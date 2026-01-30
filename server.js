const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Secure session tokens
const rateLimit = require('express-rate-limit'); // Brute force protection
const helmet = require('helmet'); // Security headers

const app = express();

// --- 1. SECURITY CONFIGURATION ---
app.use(helmet());

// JWT Secret Key (In production, use a long random string in env variables)
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-this-in-prod";

// Rate Limiter: Maximum 10 login attempts per 15 minutes per IP address
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { error: "Too many login attempts. Please try again later." }
});

// CORS: Only allow requests from your specific authorized URLs
const allowedOrigins = [
    'http://127.0.0.1:5500',                            
    'http://localhost:3000',                            
    'https://tsf-sslg-election-endpoint.onrender.com',
    'https://tsf-g-digital-election.web.app' 
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}));

app.use(express.json());

// --- 2. FIREBASE INITIALIZATION ---
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.error("ERROR: Missing FIREBASE_SERVICE_ACCOUNT environment variable.");
    process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// --- 3. SERVER-SIDE CACHING (THE QUOTA FIX) ---
// These variables store data in RAM to prevent reading from Firebase constantly.

let CACHE_CANDIDATES = null;      // Stores the list of candidates (Names, Parties, Images)
let CACHE_DASHBOARD = null;       // Stores the calculated vote tallies
let CACHE_TOTAL_VOTERS = null;    // Stores the total number of registered students
let LAST_DASHBOARD_FETCH = 0;     // Timestamp to track when we last updated the dashboard

// Helper: Clears the candidate cache so updates appear immediately
function invalidateCandidateCache() {
    CACHE_CANDIDATES = null;
    console.log("CACHE: Candidate data invalidated. Will re-fetch on next request.");
}

// --- 4. MIDDLEWARE: TOKEN AUTHENTICATION ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) return res.status(401).json({ error: "Access Denied. Missing Ballot Token." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired. Please login again." });
        req.user = user; 
        next();
    });
}

// --- 5. REGISTRAR API (Login) ---
app.post('/api/verify', loginLimiter, async (req, res) => {
    const { lvn, code } = req.body;

    try {
        // We still read from DB here for security (1 Read per Login)
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        if (!settingsSnap.exists) return res.status(500).json({ error: "System config missing." });
        
        const settings = settingsSnap.data();
        if (!settings.isLive) return res.status(403).json({ error: "Election is paused." });

        const voterRef = db.collection('voters').doc(lvn);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists || voterSnap.data().code !== code.toUpperCase()) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const voterData = voterSnap.data();
        if (voterData.hasVoted) return res.status(403).json({ error: "You have already voted." });

        if (settings.activeGrade && settings.activeGrade !== "ALL" && voterData.grade !== settings.activeGrade) {
            return res.status(403).json({ error: `Voting session is currently for Grade ${settings.activeGrade}.` });
        }

        const token = jwt.sign(
            { lvn: lvn, grade: voterData.grade }, 
            JWT_SECRET,
            { expiresIn: '20m' }
        );

        res.json({ name: voterData.name, grade: voterData.grade, token: token });

    } catch (err) {
        console.error("Registrar Error:", err);
        res.status(500).json({ error: "Registrar connection error." });
    }
});

// --- 6. TALLIER API (Voting - Atomic & Tamper Proof) ---
app.post('/api/vote', authenticateToken, async (req, res) => {
    const { lvn, grade } = req.user; 
    const { selections } = req.body; 

    if (!lvn) return res.status(400).json({ error: "Token Malformed." });
    if (!selections || !selections.president) {
        return res.status(400).json({ error: "Invalid ballot selection." });
    }

    try {
        await db.runTransaction(async (t) => {
            const voterRef = db.collection('voters').doc(lvn);
            const voterSnap = await t.get(voterRef);

            if (!voterSnap.exists) throw new Error("Voter not found.");
            if (voterSnap.data().hasVoted) throw new Error("Vote already recorded.");

            // 1. Audit Log
            const logRef = db.collection('audit_logs').doc();
            t.set(logRef, {
                lvn: lvn,
                action: "VOTE_CAST",
                grade: grade || "Unknown",
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                ip: req.ip
            });

            // 2. Mark voter as voted
            t.update(voterRef, { 
                hasVoted: true, 
                votedAt: admin.firestore.FieldValue.serverTimestamp() 
            });

            // 3. Tally Votes with Grade Breakdown
            Object.keys(selections).forEach(posKey => {
                const candidateId = selections[posKey];
                if(candidateId) {
                    const resRef = db.collection('results').doc(candidateId);
                    
                    const updateData = { votes: admin.firestore.FieldValue.increment(1) };
                    
                    // Crucial: Increment the specific grade field. This allows us to
                    // calculate grade stats later without reading the voters collection.
                    const gradeKey = grade ? `votes_${grade}` : 'votes_unknown';
                    updateData[gradeKey] = admin.firestore.FieldValue.increment(1);

                    t.set(resRef, updateData, { merge: true });
                }
            });
        });

        res.json({ success: true, hash: `TSF-${Date.now().toString(16).toUpperCase()}` });
    } catch (err) {
        console.error("Vote Transaction Error:", err);
        res.status(400).json({ error: err.message });
    }
});

// --- 7. PUBLIC API: CANDIDATES (CACHED) ---
app.get('/api/candidates', async (req, res) => {
    try {
        // Optimization: If cache exists, return it immediately (0 Database Reads)
        if (CACHE_CANDIDATES) {
            return res.json(CACHE_CANDIDATES);
        }

        // If no cache, fetch from DB (Occurs only once on server start/restart)
        const positions = [
            'president', 'vp', 'secretary', 'treasurer', 'auditor', 
            'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
        ];
        
        const data = {};
        await Promise.all(positions.map(async (pos) => {
            const snap = await db.collection('candidates').doc(pos).get();
            data[pos] = snap.exists ? snap.data().options : [];
        }));

        CACHE_CANDIDATES = data; // Save to RAM
        console.log("CACHE: Candidates loaded into memory.");
        
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: "Failed to load candidates." });
    }
});

// --- 8. DASHBOARD API (HEAVILY OPTIMIZED) ---
app.get('/api/dashboard', async (req, res) => {
    try {
        const now = Date.now();
        // Update cache only if it's older than 15 seconds
        const CACHE_DURATION = 15000; 

        if (CACHE_DASHBOARD && (now - LAST_DASHBOARD_FETCH < CACHE_DURATION)) {
            return res.json(CACHE_DASHBOARD);
        }

        // --- START REFRESHING DATA ---
        
        // 1. Check Election Status
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        const isLive = settingsSnap.exists ? settingsSnap.data().isLive : false;

        // 2. Get Total Registered Voters (Cached permanently after first fetch)
        if (CACHE_TOTAL_VOTERS === null) {
            const votersSnap = await db.collection('voters').count().get();
            CACHE_TOTAL_VOTERS = votersSnap.data().count;
            console.log(`CACHE: Total registered voters set to ${CACHE_TOTAL_VOTERS}`);
        }

        // 3. Fetch Vote Counts (~50 reads max, instead of 3000)
        const resultsSnap = await db.collection('results').get();
        const resultsData = {}; 
        resultsSnap.forEach(doc => { resultsData[doc.id] = doc.data(); });

        // 4. Ensure Candidates are loaded for mapping
        if (!CACHE_CANDIDATES) {
            // Internal fetch if candidates aren't cached yet
             await new Promise(resolve => {
                const mockRes = { json: (d) => { CACHE_CANDIDATES = d; resolve(); }};
                app.get('/api/candidates')(null, mockRes);
             });
        }

        // 5. Calculate Statistics from 'results' collection
        const stats = { total: CACHE_TOTAL_VOTERS, voted: 0, percentage: 0, grades: {} };
        const finalResults = {};
        let presidentialVotes = 0;

        const positions = Object.keys(CACHE_CANDIDATES || {});

        positions.forEach(pos => {
            const candidates = CACHE_CANDIDATES[pos].map(c => {
                const r = resultsData[c.id] || {};
                const voteCount = r.votes || 0;

                // We use Presidential votes to calculate total turnout & grade breakdown
                if (pos === 'president') {
                    presidentialVotes += voteCount;
                    
                    // Sum up grade stats from result fields (e.g. "votes_10")
                    Object.keys(r).forEach(key => {
                        if (key.startsWith('votes_')) {
                            const grade = key.replace('votes_', '');
                            if (!stats.grades[grade]) stats.grades[grade] = { total: 0, voted: 0, missed: 0 };
                            stats.grades[grade].voted += r[key];
                        }
                    });
                }

                return { ...c, votes: voteCount, breakdown: r };
            });
            
            candidates.sort((a, b) => b.votes - a.votes);
            finalResults[pos] = candidates;
        });

        // Finalize Stats
        stats.voted = presidentialVotes;
        if (stats.total > 0) stats.percentage = ((stats.voted / stats.total) * 100).toFixed(1);

        // Approximate 'Total' and 'Missed' per grade for display
        // Note: 'Missed' will be approximate since we aren't reading the full voter list
        Object.keys(stats.grades).forEach(g => {
             // For display purposes, assume total = voted + missed (we can't know true total without expensive read)
             // or just show voted count.
             // Here we just set total to voted to avoid UI errors, or you can hardcode totals if known.
             if(stats.grades[g].total === 0) stats.grades[g].total = stats.grades[g].voted; 
             stats.grades[g].missed = stats.grades[g].total - stats.grades[g].voted;
        });

        const responsePayload = {
            isLive: isLive,
            stats: stats,
            leaderboard: finalResults
        };

        // Save to Cache
        CACHE_DASHBOARD = responsePayload;
        LAST_DASHBOARD_FETCH = now;

        res.json(responsePayload);

    } catch (err) {
        console.error("Dashboard API Error:", err);
        res.status(500).json({ error: "Failed to fetch live results." });
    }
});

// --- 9. ADMIN API ---

app.post('/api/admin/add-party', async (req, res) => {
    const { candidates } = req.body; 
    if (!candidates || !Array.isArray(candidates)) return res.status(400).json({ error: "Invalid data format." });

    try {
        await db.runTransaction(async (t) => {
            const groupedData = {};
            candidates.forEach(c => {
                if (!groupedData[c.position]) groupedData[c.position] = [];
                groupedData[c.position].push({
                    id: c.id, name: c.name.toUpperCase(), party: c.party.toUpperCase(), img: c.img || "none"
                });
            });

            const uniquePositions = Object.keys(groupedData);
            const snapshotMap = {};

            for (const pos of uniquePositions) {
                const docRef = db.collection('candidates').doc(pos);
                snapshotMap[pos] = await t.get(docRef);
            }

            for (const pos of uniquePositions) {
                const docRef = db.collection('candidates').doc(pos);
                const doc = snapshotMap[pos];
                const newCandidates = groupedData[pos];

                if (!doc.exists) t.set(docRef, { options: newCandidates });
                else t.update(docRef, { options: admin.firestore.FieldValue.arrayUnion(...newCandidates) });
            }
        });

        invalidateCandidateCache(); // Clear cache so new candidates show up
        res.json({ success: true, message: "Party registered successfully." });

    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/delete', async (req, res) => {
    const { position, candidateId } = req.body;
    try {
        const docRef = db.collection('candidates').doc(position);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: "Position not found." });

        const updatedOptions = doc.data().options.filter(c => c.id.toString() !== candidateId.toString());
        await docRef.update({ options: updatedOptions });
        
        invalidateCandidateCache(); // Clear cache
        res.json({ success: true });

    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/edit', async (req, res) => {
    const { position, candidateId, newData } = req.body;
    try {
        await db.runTransaction(async (t) => {
            const docRef = db.collection('candidates').doc(position);
            const doc = await t.get(docRef);
            if (!doc.exists) throw new Error("Position missing.");

            const options = doc.data().options;
            const index = options.findIndex(c => c.id.toString() === candidateId.toString());
            if (index === -1) throw new Error("Candidate not found.");

            options[index] = { ...options[index], ...newData };
            t.update(docRef, { options: options });
        });

        invalidateCandidateCache(); // Clear cache
        res.json({ success: true });

    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

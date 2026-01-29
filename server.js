const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // NEW: For secure session tokens
const rateLimit = require('express-rate-limit'); // NEW: Brute force protection
const helmet = require('helmet'); // NEW: Security headers

const app = express();

// --- 1. SECURITY CONFIGURATION ---

// Helmet adds various HTTP headers to secure the app
app.use(helmet());

// JWT Secret Key (In production, use a long random string in env variables)
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-this-in-prod";

// Rate Limiter: Maximum 10 login attempts per 15 minutes per IP address
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { error: "Too many login attempts. Please try again later." }
});

// CORS: Only allow requests from your specific frontend URL
const allowedOrigins = [
    'http://127.0.0.1:5500',                         
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
// Uses the secret key stored in Render Environment Variables
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.error("ERROR: Missing FIREBASE_SERVICE_ACCOUNT environment variable.");
    process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// --- 3. MIDDLEWARE: TOKEN AUTHENTICATION ---
// This acts as the "Security Guard" for the voting endpoint
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <token>"

    if (!token) return res.status(401).json({ error: "Access Denied. Missing Ballot Token." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired. Please login again." });
        req.user = user; // Attach verified voter data to the request
        next();
    });
}

// --- 4. REGISTRAR API (Login) ---
// Applies Rate Limiting here
app.post('/api/verify', loginLimiter, async (req, res) => {
    const { lvn, code } = req.body;

    try {
        // Fetch current election status
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        if (!settingsSnap.exists) return res.status(500).json({ error: "System config missing." });
        
        const settings = settingsSnap.data();

        if (!settings.isLive) {
            return res.status(403).json({ error: "Election is paused. Please wait for instructions." });
        }

        // Fetch voter details
        const voterRef = db.collection('voters').doc(lvn);
        const voterSnap = await voterRef.get();

        // Security Check: Does user exist and code match?
        if (!voterSnap.exists || voterSnap.data().code !== code.toUpperCase()) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const voterData = voterSnap.data();

        // Security Check: Already voted?
        if (voterData.hasVoted) {
            return res.status(403).json({ error: "You have already voted." });
        }

        // Security Check: Grade Level Gate
        if (voterData.grade !== settings.activeGrade) {
            return res.status(403).json({ error: `Voting session is currently for Grade ${settings.activeGrade}.` });
        }

        // SUCCESS: Generate a secure Token
        // CRITICAL FIX: Use 'lvn' from request, not 'voterData.lvn' (which might be undefined)
        const token = jwt.sign(
            { lvn: lvn, grade: voterData.grade }, // <--- CHANGED THIS LINE
            JWT_SECRET,
            { expiresIn: '20m' } // Token expires in 20 minutes
        );

        res.json({ 
            name: voterData.name, 
            grade: voterData.grade,
            token: token // Send the digital "Ballot Paper" to frontend
        });

    } catch (err) {
        console.error("Registrar Error:", err);
        res.status(500).json({ error: "Registrar connection error." });
    }
});

// --- 5. TALLIER API (Voting) ---
app.post('/api/vote', authenticateToken, async (req, res) => {
    const lvn = req.user.lvn; 
    const { selections } = req.body; 

    if (!lvn) return res.status(400).json({ error: "Security Token Malformed." });

    // Validate only critical positions (Pres/VP), others can be optional if you prefer
    if (!selections || !selections.president || !selections.vp) {
        return res.status(400).json({ error: "Invalid ballot: President and VP are required." });
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
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                ip: req.ip,
                userAgent: req.headers['user-agent'] || 'Unknown'
            });

            // 2. Mark voter
            t.update(voterRef, { 
                hasVoted: true, 
                votedAt: admin.firestore.FieldValue.serverTimestamp() 
            });

            // 3. Tally Votes (Dynamic Loop for all keys)
            // This loops through every position sent (pres, vp, secretary, etc.) and updates results
            Object.keys(selections).forEach(posKey => {
                const candidateId = selections[posKey];
                if(candidateId) {
                    const resRef = db.collection('results').doc(candidateId);
                    t.set(resRef, { votes: admin.firestore.FieldValue.increment(1) }, { merge: true });
                }
            });
        });

        res.json({ success: true, hash: `TSF-${Date.now().toString(16).toUpperCase()}` });
    } catch (err) {
        console.error("Vote Transaction Error:", err);
        res.status(400).json({ error: err.message });
    }
});

// --- 6. PUBLIC API: CANDIDATES ---
app.get('/api/candidates', async (req, res) => {
    try {
        // We define the list of positions we need to fetch
        const positions = [
            'president', 'vp', 'secretary', 'treasurer', 'auditor', 
            'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
        ];
        
        const data = {};

        // Fetch all candidates in parallel for speed
        await Promise.all(positions.map(async (pos) => {
            const snap = await db.collection('candidates').doc(pos).get();
            // If document exists, use its options; otherwise return empty list
            data[pos] = snap.exists ? snap.data().options : [];
        }));

        res.json(data);
    } catch (err) {
        console.error("Candidate Fetch Error:", err);
        res.status(500).json({ error: "Failed to load candidates." });
    }
});

// --- 7. ADMIN API: MANAGE CANDIDATES ---

// A. BULK ADD PARTY (Transactional - Fixed)
app.post('/api/admin/add-party', async (req, res) => {
    const { candidates } = req.body; 

    if (!candidates || !Array.isArray(candidates)) {
        return res.status(400).json({ error: "Invalid data format." });
    }

    try {
        await db.runTransaction(async (t) => {
            // STEP 1: PREPARE DATA & READS
            // Group candidates by position first (e.g., separate all 'president' entries)
            const groupedData = {};
            candidates.forEach(c => {
                if (!groupedData[c.position]) groupedData[c.position] = [];
                groupedData[c.position].push({
                    id: c.id,
                    name: c.name.toUpperCase(),
                    party: c.party.toUpperCase(),
                    img: c.img || "none"
                });
            });

            const uniquePositions = Object.keys(groupedData);
            const snapshotMap = {};

            // READ PHASE: Fetch all necessary documents *before* writing anything
            for (const pos of uniquePositions) {
                const docRef = db.collection('candidates').doc(pos);
                const doc = await t.get(docRef);
                snapshotMap[pos] = doc; // Store snapshot in memory
            }

            // WRITE PHASE: Now safe to write
            for (const pos of uniquePositions) {
                const docRef = db.collection('candidates').doc(pos);
                const doc = snapshotMap[pos];
                const newCandidates = groupedData[pos];

                if (!doc.exists) {
                    // If position doesn't exist yet, create it with the list
                    t.set(docRef, { options: newCandidates });
                } else {
                    // If it exists, append new candidates to the array
                    // We use spread (...) to add multiple candidates at once
                    t.update(docRef, { options: admin.firestore.FieldValue.arrayUnion(...newCandidates) });
                }
            }
        });

        res.json({ success: true, message: "Party successfully registered." });
    } catch (err) {
        console.error("Admin Add Error:", err);
        res.status(500).json({ error: err.message });
    }
});

// B. DELETE CANDIDATE
app.post('/api/admin/delete', async (req, res) => {
    const { position, candidateId } = req.body;

    try {
        const docRef = db.collection('candidates').doc(position);
        const doc = await docRef.get();

        if (!doc.exists) return res.status(404).json({ error: "Position not found." });

        const options = doc.data().options;
        const updatedOptions = options.filter(c => c.id.toString() !== candidateId.toString());

        if (options.length === updatedOptions.length) {
            return res.status(404).json({ error: "Candidate ID not found." });
        }

        await docRef.update({ options: updatedOptions });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// C. EDIT CANDIDATE
app.post('/api/admin/edit', async (req, res) => {
    const { position, candidateId, newData } = req.body;

    try {
        await db.runTransaction(async (t) => {
            const docRef = db.collection('candidates').doc(position);
            const doc = await t.get(docRef);

            if (!doc.exists) throw new Error("Position document missing.");

            const options = doc.data().options;
            const index = options.findIndex(c => c.id.toString() === candidateId.toString());

            if (index === -1) throw new Error("Candidate not found.");

            // Update specific fields
            options[index] = { ...options[index], ...newData };
            
            t.update(docRef, { options: options });
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 8. LIVE DASHBOARD API ---
app.get('/api/dashboard', async (req, res) => {
    try {
        // 1. Get Voter Statistics (Count registered vs voted)
        const votersSnap = await db.collection('voters').get();
        const totalVoters = votersSnap.size;
        // fast filter to count those who voted
        const totalVoted = votersSnap.docs.filter(doc => doc.data().hasVoted).length;

        // 2. Fetch Candidates Structure
        const positions = [
            'president', 'vp', 'secretary', 'treasurer', 'auditor', 
            'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
        ];
        
        const candidateMap = {}; // Will hold raw candidates by position
        
        // Fetch candidate lists
        await Promise.all(positions.map(async (pos) => {
            const snap = await db.collection('candidates').doc(pos).get();
            candidateMap[pos] = snap.exists ? snap.data().options : [];
        }));

        // 3. Fetch Vote Counts (The Results)
        const resultsSnap = await db.collection('results').get();
        const voteCounts = {};
        
        resultsSnap.forEach(doc => {
            voteCounts[doc.id] = doc.data().votes || 0;
        });

        // 4. Merge Data & Sort for Leaderboard
        const finalResults = {};
        
        positions.forEach(pos => {
            const candidates = candidateMap[pos].map(c => ({
                ...c,
                votes: voteCounts[c.id] || 0 // Attach vote count or 0
            }));

            // Sort: Highest votes first
            candidates.sort((a, b) => b.votes - a.votes);
            
            finalResults[pos] = candidates;
        });

        // Send everything to frontend
        res.json({
            stats: {
                totalVoters,
                totalVoted,
                percentage: totalVoters > 0 ? ((totalVoted / totalVoters) * 100).toFixed(1) : 0
            },
            leaderboard: finalResults
        });

    } catch (err) {
        console.error("Dashboard API Error:", err);
        res.status(500).json({ error: "Failed to fetch live results." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

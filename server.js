const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const jwt = require('jsonwebtoken'); 
const rateLimit = require('express-rate-limit'); 
const helmet = require('helmet'); 

const app = express();

// --- 1. SECURITY CONFIGURATION ---
app.use(helmet());

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-this-in-prod";

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: { error: "Too many login attempts. Please try again later." }
});

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
            return callback(new Error('CORS Policy violation'), false);
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

// --- 3. IN-MEMORY CACHE (THE VARIABLES) ---
// This replaces direct DB reads for public endpoints
const GlobalCache = {
    candidates: {},          // Stores the list of candidates
    dashboard: {             // Stores the full results/stats object
        isLive: false,
        stats: { total: 0, voted: 0, percentage: 0, grades: {} },
        leaderboard: {}
    },
    timestamps: {            // Stores when the variables were last updated
        candidates: "Not yet loaded",
        results: "Not yet loaded"
    }
};

// --- HELPER: REFRESH CANDIDATES FROM DB ---
async function refreshLocalCandidates() {
    try {
        const positions = [
            'president', 'vp', 'secretary', 'treasurer', 'auditor', 
            'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
        ];
        
        const data = {};
        await Promise.all(positions.map(async (pos) => {
            const snap = await db.collection('candidates').doc(pos).get();
            data[pos] = snap.exists ? snap.data().options : [];
        }));

        GlobalCache.candidates = data;
        GlobalCache.timestamps.candidates = new Date().toLocaleString();
        console.log("CACHE: Candidates updated.");
        return true;
    } catch (err) {
        console.error("CACHE ERROR (Candidates):", err);
        return false;
    }
}

// --- HELPER: REFRESH RESULTS/DASHBOARD FROM DB ---
async function refreshLocalResults() {
    try {
        // 1. Get Election Status
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        const isLive = settingsSnap.exists ? settingsSnap.data().isLive : false;

        // 2. Get Voter Stats
        const votersSnap = await db.collection('voters').get();
        const stats = { total: 0, voted: 0, percentage: 0, grades: {} };

        votersSnap.forEach(doc => {
            const d = doc.data();
            const g = d.grade || "Unknown";
            if(!stats.grades[g]) stats.grades[g] = { total: 0, voted: 0, missed: 0 };
            
            stats.total++;
            stats.grades[g].total++;

            if(d.hasVoted) {
                stats.voted++;
                stats.grades[g].voted++;
            } else {
                stats.grades[g].missed++;
            }
        });

        if(stats.total > 0) stats.percentage = ((stats.voted / stats.total) * 100).toFixed(1);

        // 3. Get Votes (Leaderboard)
        // Note: We use the *Cached Candidates* to map the results
        const resultsSnap = await db.collection('results').get();
        const resultsData = {}; 
        resultsSnap.forEach(doc => { resultsData[doc.id] = doc.data(); });

        const finalResults = {};
        const positions = Object.keys(GlobalCache.candidates); // Use cached keys

        positions.forEach(pos => {
            const candidates = GlobalCache.candidates[pos].map(c => {
                const r = resultsData[c.id] || {};
                return { ...c, votes: r.votes || 0, breakdown: r };
            });
            candidates.sort((a, b) => b.votes - a.votes);
            finalResults[pos] = candidates;
        });

        // 4. Update Cache
        GlobalCache.dashboard = { isLive, stats, leaderboard: finalResults };
        GlobalCache.timestamps.results = new Date().toLocaleString();
        console.log("CACHE: Results updated.");
        return true;

    } catch (err) {
        console.error("CACHE ERROR (Results):", err);
        return false;
    }
}

// Initialize Cache on Server Start
refreshLocalCandidates().then(() => refreshLocalResults());


// --- 4. MIDDLEWARE: TOKEN AUTH ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 
    if (!token) return res.status(401).json({ error: "Access Denied." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired." });
        req.user = user; 
        next();
    });
}

// --- 5. REGISTRAR API (Login) ---
app.post('/api/verify', loginLimiter, async (req, res) => {
    const { lvn, code } = req.body;
    try {
        // Read "isLive" from Cache for speed, or DB if critical. 
        // For login, we'll keep DB read to ensure pausing is instant.
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        if (!settingsSnap.exists || !settingsSnap.data().isLive) {
            return res.status(403).json({ error: "Election is paused." });
        }
        const activeGrade = settingsSnap.data().activeGrade;

        const voterRef = db.collection('voters').doc(lvn);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists || voterSnap.data().code !== code.toUpperCase()) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const voterData = voterSnap.data();
        if (voterData.hasVoted) return res.status(403).json({ error: "You have already voted." });

        if (activeGrade && activeGrade !== "ALL" && voterData.grade !== activeGrade) {
            return res.status(403).json({ error: `Voting session is for Grade ${activeGrade} only.` });
        }

        const token = jwt.sign(
            { lvn: lvn, grade: voterData.grade }, 
            JWT_SECRET,
            { expiresIn: '20m' }
        );

        res.json({ name: voterData.name, grade: voterData.grade, token: token });

    } catch (err) {
        res.status(500).json({ error: "Registrar connection error." });
    }
});

// --- 6. TALLIER API (Voting) ---
app.post('/api/vote', authenticateToken, async (req, res) => {
    const { lvn, grade } = req.user; 
    const { selections } = req.body; 

    if (!lvn || !selections || !selections.president) {
        return res.status(400).json({ error: "Invalid ballot." });
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
                lvn, action: "VOTE_CAST", grade, timestamp: admin.firestore.FieldValue.serverTimestamp(), ip: req.ip
            });

            // 2. Mark Voted
            t.update(voterRef, { hasVoted: true, votedAt: admin.firestore.FieldValue.serverTimestamp() });

            // 3. Tally in Firestore
            Object.keys(selections).forEach(posKey => {
                const candidateId = selections[posKey];
                if(candidateId) {
                    const resRef = db.collection('results').doc(candidateId);
                    const gradeKey = grade ? `votes_${grade}` : 'votes_unknown';
                    t.set(resRef, { 
                        votes: admin.firestore.FieldValue.increment(1),
                        [gradeKey]: admin.firestore.FieldValue.increment(1)
                    }, { merge: true });
                }
            });
        });

        // 4. INSTANT LOCAL UPDATE (Keep Cache Live without DB Read)
        // This ensures the Dashboard updates immediately after a vote without waiting for Admin Refresh
        GlobalCache.dashboard.stats.voted++;
        if(GlobalCache.dashboard.stats.grades[grade]) {
            GlobalCache.dashboard.stats.grades[grade].voted++;
            GlobalCache.dashboard.stats.grades[grade].missed--;
        }
        
        Object.keys(selections).forEach(posKey => {
             const cId = selections[posKey];
             // Find candidate in dashboard leaderboard and increment
             if(GlobalCache.dashboard.leaderboard[posKey]) {
                 const cand = GlobalCache.dashboard.leaderboard[posKey].find(c => c.id == cId);
                 if(cand) {
                     cand.votes = (cand.votes || 0) + 1;
                     if(!cand.breakdown) cand.breakdown = {};
                     const gKey = `votes_${grade}`;
                     cand.breakdown[gKey] = (cand.breakdown[gKey] || 0) + 1;
                 }
                 // Re-sort that position
                 GlobalCache.dashboard.leaderboard[posKey].sort((a,b) => b.votes - a.votes);
             }
        });

        res.json({ success: true, hash: `TSF-${Date.now().toString(16).toUpperCase()}` });
    } catch (err) {
        console.error("Vote Error:", err);
        res.status(400).json({ error: err.message });
    }
});

// --- 7. PUBLIC API: CANDIDATES (Reads from Variable) ---
app.get('/api/candidates', (req, res) => {
    // Directly return the variable
    res.json(GlobalCache.candidates);
});

// --- 8. LIVE DASHBOARD (Reads from Variable) ---
app.get('/api/dashboard', (req, res) => {
    // Directly return the variable
    res.json(GlobalCache.dashboard);
});

// --- 9. ADMIN API: MANAGEMENT & REFRESH ---

// Trigger: Refresh Candidates Variable
app.post('/api/admin/refresh/candidates', async (req, res) => {
    const success = await refreshLocalCandidates();
    if(success) res.json({ success: true, timestamp: GlobalCache.timestamps.candidates });
    else res.status(500).json({ error: "Failed to refresh candidates." });
});

// Trigger: Refresh Results Variable
app.post('/api/admin/refresh/results', async (req, res) => {
    const success = await refreshLocalResults();
    if(success) res.json({ success: true, timestamp: GlobalCache.timestamps.results });
    else res.status(500).json({ error: "Failed to refresh results." });
});

// Get Cache Timestamps
app.get('/api/admin/status', (req, res) => {
    res.json(GlobalCache.timestamps);
});

// Add Party (Writes to DB -> Auto Updates Cache)
app.post('/api/admin/add-party', async (req, res) => {
    const { candidates } = req.body; 
    try {
        await db.runTransaction(async (t) => {
            const groupedData = {};
            candidates.forEach(c => {
                if (!groupedData[c.position]) groupedData[c.position] = [];
                groupedData[c.position].push({
                    id: c.id, name: c.name.toUpperCase(), party: c.party.toUpperCase(), img: c.img || "none"
                });
            });

            for (const pos of Object.keys(groupedData)) {
                const docRef = db.collection('candidates').doc(pos);
                const doc = await t.get(docRef);
                const newCandidates = groupedData[pos];
                if (!doc.exists) t.set(docRef, { options: newCandidates });
                else t.update(docRef, { options: admin.firestore.FieldValue.arrayUnion(...newCandidates) });
            }
        });
        
        // Auto-refresh cache so Admin sees it immediately
        await refreshLocalCandidates();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete Candidate (Writes to DB -> Auto Updates Cache)
app.post('/api/admin/delete', async (req, res) => {
    const { position, candidateId } = req.body;
    try {
        const docRef = db.collection('candidates').doc(position);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: "Position not found." });

        const updatedOptions = doc.data().options.filter(c => c.id.toString() !== candidateId.toString());
        await docRef.update({ options: updatedOptions });

        // Auto-refresh cache
        await refreshLocalCandidates();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

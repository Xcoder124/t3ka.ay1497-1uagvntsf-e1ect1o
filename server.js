const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const jwt = require('jsonwebtoken'); 
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); 
const crypto = require('crypto'); // NEW: For generating Receipt Hashes

const app = express();

// --- 1. STRICT SECURITY CONFIGURATION ---
app.use(helmet());
app.use(express.json()); // Ensure JSON body parsing is enabled

// CRITICAL: Fail if secrets are missing
if (!process.env.JWT_SECRET || !process.env.ADMIN_KEY) {
    console.error("FATAL ERROR: JWT Key and Admin Secret is missing.");
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY; // New master password for admin actions

// Rate Limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 3, 
    message: { error: "Too many attempts. Please try again later." }
});

// CORS
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
            return callback(new Error('CORS Policy: Origin not allowed'), false);
        }
        return callback(null, true);
    }
}));

app.use(express.json());

// --- 2. FIREBASE INITIALIZATION ---
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.error("ERROR: Missing FIREBASE SERVICE ACCOUNT.");
    process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// --- 3. IN-MEMORY CACHE ---
const GlobalCache = {
    candidates: {},          
    dashboard: {             
        isLive: false,
        stats: { total: 0, voted: 0, percentage: 0, grades: {} }, // <--- Stats live here
        leaderboard: {}
    },
    timestamps: {            
        candidates: "Not yet loaded",
        results: "Not yet loaded"
    }
};

// --- HELPER: REFRESH CANDIDATES ---
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

// --- HELPER: REFRESH RESULTS & VOTER STATS ---
async function refreshLocalResults() {
    try {
        console.log("CACHE: Starting full refresh of Results & Stats...");

        // 1. Get Election Status
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        const isLive = settingsSnap.exists ? settingsSnap.data().isLive : false;

        // 2. RE-CALCULATE VOTER STATS (The part you asked about)
        // We query the 'voters' collection to get the absolute latest counts.
        const votersSnap = await db.collection('voters').get();
        const stats = { total: 0, voted: 0, percentage: 0, grades: {} };

        votersSnap.forEach(doc => {
            const d = doc.data();
            const g = d.grade || "Unknown";
            
            // Initialize grade group if missing
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

        // Calculate Global Percentage
        if(stats.total > 0) stats.percentage = ((stats.voted / stats.total) * 100).toFixed(1);
        
        console.log(`CACHE: Stats updated. Total: ${stats.total}, Voted: ${stats.voted}`);

        // 3. Get Votes (Leaderboard)
        const resultsSnap = await db.collection('results').get();
        const resultsData = {}; 
        resultsSnap.forEach(doc => { resultsData[doc.id] = doc.data(); });

        const finalResults = {};
        const positions = Object.keys(GlobalCache.candidates); 

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
        
        console.log("CACHE: Results & Stats refresh complete.");
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

// --- AUDIT LOGGING HELPER ---
async function logAudit(action, performer, details) {
    try {
        await admin.firestore().collection('audit_logs').add({
            action: action,
            performer: performer, // IP or User ID
            details: details,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log(`[AUDIT] ${action} by ${performer}`);
    } catch (e) {
        console.error("Audit Log Failed:", e);
    }
}

// --- 6. TALLIER API (Voting) ---
app.post('/api/vote', async (req, res) => {
    // A. Validate Auth Header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Access Denied: No Token" });

    try {
        // B. Verify Token
        const user = jwt.verify(token, JWT_SECRET);
        
        // C. Input Sanitization
        const { selections } = req.body;
        if (!selections || typeof selections !== 'object') {
            return res.status(400).json({ error: "Invalid payload format." });
        }

        // D. Transaction: Check Double Vote + Save
        const db = admin.firestore();
        await db.runTransaction(async (t) => {
            const voterRef = db.collection('voters').doc(user.lrn); // Assuming LRN is ID
            const voterDoc = await t.get(voterRef);

            if (voterDoc.exists && voterDoc.data().hasVoted) {
                throw new Error("ALREADY_VOTED");
            }

            // E. Generate Receipt Hash (Integrity Check)
            const voteString = `${user.lrn}-${new Date().toISOString()}-${JSON.stringify(selections)}`;
            const receiptHash = crypto.createHash('sha256').update(voteString).digest('hex');

            // F. Save Vote & Update Voter Status
            t.set(db.collection('votes').doc(), {
                selections: selections,
                hash: receiptHash,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
            t.update(voterRef, { hasVoted: true, votedAt: admin.firestore.FieldValue.serverTimestamp() });
            
            // Log this event (Anonymized for privacy, but logged for traffic analysis)
            logAudit("VOTE_CAST", "ANONYMOUS", { hash: receiptHash });

            return receiptHash;
        }).then((hash) => {
            res.json({ success: true, hash: hash });
        });

    } catch (err) {
        if (err.message === "ALREADY_VOTED") return res.status(403).json({ error: "You have already voted." });
        return res.status(403).json({ error: "Invalid Token or Server Error" });
    }
});
        // 4. INSTANT LOCAL UPDATE
        // Updates the STATS cache immediately for the dashboard
        if (GlobalCache.dashboard.stats) {
            GlobalCache.dashboard.stats.voted++;
            // Update percentage
            if(GlobalCache.dashboard.stats.total > 0) {
                GlobalCache.dashboard.stats.percentage = 
                    ((GlobalCache.dashboard.stats.voted / GlobalCache.dashboard.stats.total) * 100).toFixed(1);
            }
            // Update Grade specific stats
            if(GlobalCache.dashboard.stats.grades[grade]) {
                GlobalCache.dashboard.stats.grades[grade].voted++;
                GlobalCache.dashboard.stats.grades[grade].missed--;
            }
        }
        
        // Updates the CANDIDATE cache immediately
        Object.keys(selections).forEach(posKey => {
             const cId = selections[posKey];
             if(GlobalCache.dashboard.leaderboard[posKey]) {
                 const cand = GlobalCache.dashboard.leaderboard[posKey].find(c => c.id == cId);
                 if(cand) {
                     cand.votes = (cand.votes || 0) + 1;
                     if(!cand.breakdown) cand.breakdown = {};
                     const gKey = `votes_${grade}`;
                     cand.breakdown[gKey] = (cand.breakdown[gKey] || 0) + 1;
                 }
                 GlobalCache.dashboard.leaderboard[posKey].sort((a,b) => b.votes - a.votes);
             }
        });

        res.json({ success: true, hash: `TSF-${Date.now().toString(16).toUpperCase()}` });
    } catch (err) {
        console.error("Vote Error:", err);
        res.status(400).json({ error: err.message });
    }
});

// --- 7. PUBLIC API: CANDIDATES ---
app.get('/api/candidates', (req, res) => {
    res.json(GlobalCache.candidates);
});

// --- 8. LIVE DASHBOARD ---
app.get('/api/dashboard', (req, res) => {
    res.json(GlobalCache.dashboard);
});

// --- 9. ADMIN API: MANAGEMENT & REFRESH ---

// Trigger: Refresh Candidates
app.post('/api/admin/refresh/candidates', async (req, res) => {
    const success = await refreshLocalCandidates();
    if(success) res.json({ success: true, timestamp: GlobalCache.timestamps.candidates });
    else res.status(500).json({ error: "Failed to refresh candidates." });
});

// Trigger: Refresh Results & Stats
app.post('/api/admin/refresh/results', async (req, res) => {
    const success = await refreshLocalResults();
    if(success) res.json({ success: true, timestamp: GlobalCache.timestamps.results });
    else res.status(500).json({ error: "Failed to refresh results." });
});

app.get('/api/admin/status', (req, res) => {
    res.json(GlobalCache.timestamps);
});

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
        await refreshLocalCandidates();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---ADMIN DELETE ---
app.post('/api/admin/delete', async (req, res) => {
    const { position, candidateId, partyName, adminKey } = req.body;

    // A. Server-Side Auth Check
    if (!adminKey || adminKey !== ADMIN_KEY) {
        logAudit("UNAUTHORIZED_DELETE_ATTEMPT", req.ip, { target: candidateId || partyName });
        return res.status(403).json({ error: "Unauthorized: Invalid Admin Key" });
    }

    const db = admin.firestore();

    const ALL_POSITIONS = [
        'president', 'vp', 'secretary', 'treasurer', 'auditor', 
        'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
    ];

    try {
        // SCENARIO 1: DELETE ENTIRE PARTYLIST
        if (partyName) {
            console.log(`[ADMIN] Starting bulk delete for party: ${partyName}`);
            
            const batch = db.batch();
            let deletedCount = 0;

            const refs = ALL_POSITIONS.map(pos => db.collection('candidates').doc(pos));
            const snapshots = await db.getAll(...refs);

            snapshots.forEach((doc, index) => {
                if (doc.exists) {
                    const currentOptions = doc.data().options || [];
                    
                    // Filter out ANYONE who belongs to this party
                    const newOptions = currentOptions.filter(c => c.party !== partyName);
                    
                    if (newOptions.length !== currentOptions.length) {
                        const removedCount = currentOptions.length - newOptions.length;
                        deletedCount += removedCount;
                        
                        // Update the document in the batch
                        batch.update(refs[index], { options: newOptions });
                    }
                }
            });
            await batch.commit();

            await logAudit("DELETE_PARTY", "ADMIN", { party: partyName, count: deletedCount });
            return res.json({ success: true, message: `Deleted ${deletedCount} candidates from party '${partyName}' across all positions.` });
        }
            // SCENARIO 2: DELETE SINGLE CANDIDATE
        else if (position && candidateId) {
            const docRef = db.collection('candidates').doc(position);
        
            await db.runTransaction(async (t) => {
                const doc = await t.get(docRef);
                if (!doc.exists) throw new Error("Position document not found");

                const currentOptions = doc.data().options || [];
                
                const exists = currentOptions.some(c => c.id === candidateId);
                if (!exists) throw new Error("Candidate ID not found in this position");

                const newOptions = currentOptions.filter(c => c.id !== candidateId);

                t.update(docRef, { options: newOptions });
            });

            await logAudit("DELETE_CANDIDATE", "ADMIN", { position, candidateId });
            return res.json({ success: true, message: "Candidate deleted successfully." });
        }

        // =========================================================
        // INVALID REQUEST
        // =========================================================
        else {
            return res.status(400).json({ error: "Missing parameters. Provide (position & candidateId) OR (partyName)." });
        }

    } catch (err) {
        console.error("Delete Error:", err);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

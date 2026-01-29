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

// --- 3. MIDDLEWARE: TOKEN AUTHENTICATION ---
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

// --- 4. REGISTRAR API (Login) ---
app.post('/api/verify', loginLimiter, async (req, res) => {
    const { lvn, code } = req.body;

    try {
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

        // --- NEW SECURITY CHECK: AUDIT LOG VERIFICATION ---
        // Even if the 'voterData.hasVoted' flag is false, we check the immutable audit logs
        // to see if this LVN has ever submitted a vote before.
        const auditCheck = await db.collection('audit_logs')
            .where('lvn', '==', lvn)
            .limit(1) // We only need to know if at least one exists
            .get();

        if (!auditCheck.empty) {
            console.warn(`SECURITY: Blocked login for ${lvn}. Audit log found despite hasVoted flag.`);
            
            // OPTIONAL: Self-healing
            // If we find an audit log but hasVoted is false, fix it now.
            if (!voterData.hasVoted) {
                 voterRef.update({ hasVoted: true });
            }

            return res.status(403).json({ error: "Security Alert: A vote trace exists for this ID." });
        }
        // --------------------------------------------------

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

// --- 5. TALLIER API (Voting - Atomic & Tamper Proof) ---
app.post('/api/vote', authenticateToken, async (req, res) => {
    const { lvn, grade } = req.user; 
    const { selections } = req.body; 

    if (!lvn) return res.status(400).json({ error: "Token Malformed." });
    if (!selections || !selections.president || !selections.vp) {
        return res.status(400).json({ error: "Invalid ballot selection." });
    }

    try {
        // --- NEW SECURITY CHECK: FINAL AUDIT VERIFICATION ---
        // Just before writing, check one last time.
        const auditCheck = await db.collection('audit_logs')
            .where('lvn', '==', lvn)
            .limit(1)
            .get();

        if (!auditCheck.empty) {
            return res.status(403).json({ error: "Vote rejected: Duplicate transaction detected." });
        }
        // ----------------------------------------------------

        await db.runTransaction(async (t) => {
            const voterRef = db.collection('voters').doc(lvn);
            const voterSnap = await t.get(voterRef);

            if (!voterSnap.exists) throw new Error("Voter not found.");
            
            if (voterSnap.data().hasVoted) throw new Error("Vote already recorded.");

            // 1. Audit Log (Permanent trail for forensic verification)
            const logRef = db.collection('audit_logs').doc();
            t.set(logRef, {
                lvn: lvn,
                action: "VOTE_CAST",
                grade: grade || "Unknown",
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                ip: req.ip,
                userAgent: req.headers['user-agent'] || 'Unknown'
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

// ... (Rest of your server.js logic for Candidates, Admin, Dashboard remains unchanged)
app.get('/api/candidates', async (req, res) => {
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

        res.json(data);
    } catch (err) {
        res.status(500).json({ error: "Failed to load candidates." });
    }
});

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
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/dashboard', async (req, res) => {
    try {
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        const isLive = settingsSnap.exists ? settingsSnap.data().isLive : false;

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

        const positions = [
            'president', 'vp', 'secretary', 'treasurer', 'auditor', 
            'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
        ];
        
        const candidateMap = {}; 
        await Promise.all(positions.map(async (pos) => {
            const snap = await db.collection('candidates').doc(pos).get();
            candidateMap[pos] = snap.exists ? snap.data().options : [];
        }));

        const resultsSnap = await db.collection('results').get();
        const resultsData = {}; 
        resultsSnap.forEach(doc => { resultsData[doc.id] = doc.data(); });

        const finalResults = {};
        positions.forEach(pos => {
            const candidates = candidateMap[pos].map(c => {
                const r = resultsData[c.id] || {};
                return { ...c, votes: r.votes || 0, breakdown: r };
            });
            candidates.sort((a, b) => b.votes - a.votes);
            finalResults[pos] = candidates;
        });

        res.json({
            isLive: isLive,
            stats: stats,
            leaderboard: finalResults
        });

    } catch (err) {
        console.error("Dashboard API Error:", err);
        res.status(500).json({ error: "Failed to fetch live results." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

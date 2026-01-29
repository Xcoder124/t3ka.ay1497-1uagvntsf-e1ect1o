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

// CORS: Allow specific origins
const allowedOrigins = [
    'http://127.0.0.1:5500',                            
    'http://localhost:3000',                            
    'https://tsf-sslg-election-endpoint.onrender.com',
    'https://tsf-g-digital-election.web.app' 
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            // Optional: For development, you can uncomment the line below to allow ALL origins temporarily
            // return callback(null, true); 
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
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer <token>"

    if (!token) return res.status(401).json({ error: "Access Denied. Missing Ballot Token." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired. Please login again." });
        req.user = user; // Contains { lvn, grade, iat, exp }
        next();
    });
}

// --- 4. REGISTRAR API (Login) ---
app.post('/api/verify', loginLimiter, async (req, res) => {
    const { lvn, code } = req.body;

    try {
        // Fetch current election status
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        if (!settingsSnap.exists) return res.status(500).json({ error: "System config missing." });
        
        const settings = settingsSnap.data();
        if (!settings.isLive) return res.status(403).json({ error: "Election is paused. Please wait for instructions." });

        // Fetch voter details
        const voterRef = db.collection('voters').doc(lvn);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists || voterSnap.data().code !== code.toUpperCase()) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const voterData = voterSnap.data();
        if (voterData.hasVoted) return res.status(403).json({ error: "You have already voted." });

        // Grade Level Gate (Optional - enables checking if current grade is allowed)
        if (settings.activeGrade && settings.activeGrade !== "ALL" && voterData.grade !== settings.activeGrade) {
            return res.status(403).json({ error: `Voting session is currently for Grade ${settings.activeGrade}.` });
        }

        // GENERATE TOKEN (Now includes GRADE)
        const token = jwt.sign(
            { lvn: lvn, grade: voterData.grade }, 
            JWT_SECRET,
            { expiresIn: '20m' }
        );

        res.json({ 
            name: voterData.name, 
            grade: voterData.grade,
            token: token 
        });

    } catch (err) {
        console.error("Registrar Error:", err);
        res.status(500).json({ error: "Registrar connection error." });
    }
});

// --- 5. TALLIER API (Voting) ---
app.post('/api/vote', authenticateToken, async (req, res) => {
    const { lvn, grade } = req.user; // Retrieved securely from Token
    const { selections } = req.body; 

    if (!lvn) return res.status(400).json({ error: "Token Malformed." });
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

            // 3. Tally Votes (With Grade Breakdown)
            Object.keys(selections).forEach(posKey => {
                const candidateId = selections[posKey];
                if(candidateId) {
                    const resRef = db.collection('results').doc(candidateId);
                    
                    // Increment Total Votes
                    const updateData = { votes: admin.firestore.FieldValue.increment(1) };
                    
                    // Increment Grade-Specific Votes (e.g., votes_12, votes_10)
                    if(grade) {
                        updateData[`votes_${grade}`] = admin.firestore.FieldValue.increment(1);
                    }

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

// --- 6. PUBLIC API: CANDIDATES ---
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
        console.error("Candidate Fetch Error:", err);
        res.status(500).json({ error: "Failed to load candidates." });
    }
});

// --- 7. ADMIN API: MANAGE CANDIDATES ---

// A. BULK ADD PARTY (Transactional - Fixed for Read/Write Order)
app.post('/api/admin/add-party', async (req, res) => {
    const { candidates } = req.body; 

    if (!candidates || !Array.isArray(candidates)) {
        return res.status(400).json({ error: "Invalid data format." });
    }

    try {
        await db.runTransaction(async (t) => {
            // Group by position
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

            // READ PHASE
            for (const pos of uniquePositions) {
                const docRef = db.collection('candidates').doc(pos);
                const doc = await t.get(docRef);
                snapshotMap[pos] = doc;
            }

            // WRITE PHASE
            for (const pos of uniquePositions) {
                const docRef = db.collection('candidates').doc(pos);
                const doc = snapshotMap[pos];
                const newCandidates = groupedData[pos];

                if (!doc.exists) {
                    t.set(docRef, { options: newCandidates });
                } else {
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
            if (!doc.exists) throw new Error("Position missing.");

            const options = doc.data().options;
            const index = options.findIndex(c => c.id.toString() === candidateId.toString());

            if (index === -1) throw new Error("Candidate not found.");

            options[index] = { ...options[index], ...newData };
            t.update(docRef, { options: options });
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 8. LIVE DASHBOARD API (With Grade Breakdown & Live Status) ---
app.get('/api/dashboard', async (req, res) => {
    try {
        // 1. Get Election Status (For "Ended" Screen)
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        const isLive = settingsSnap.exists ? settingsSnap.data().isLive : false;

        // 2. Get Voter Statistics Per Grade
        const votersSnap = await db.collection('voters').get();
        
        const stats = {
            total: 0,
            voted: 0,
            percentage: 0,
            grades: {} // Structure: { "12": { total: 10, voted: 5, missed: 5 } }
        };

        votersSnap.forEach(doc => {
            const d = doc.data();
            const g = d.grade || "Unknown";
            
            // Init grade object if missing
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

        // Calculate global percentage
        if(stats.total > 0) stats.percentage = ((stats.voted / stats.total) * 100).toFixed(1);

        // 3. Fetch Candidates
        const positions = [
            'president', 'vp', 'secretary', 'treasurer', 'auditor', 
            'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
        ];
        
        const candidateMap = {}; 
        await Promise.all(positions.map(async (pos) => {
            const snap = await db.collection('candidates').doc(pos).get();
            candidateMap[pos] = snap.exists ? snap.data().options : [];
        }));

        // 4. Fetch Detailed Results (with Grade Breakdown keys)
        const resultsSnap = await db.collection('results').get();
        const resultsData = {}; 
        
        resultsSnap.forEach(doc => {
            resultsData[doc.id] = doc.data(); 
        });

        // 5. Merge Data
        const finalResults = {};
        positions.forEach(pos => {
            const candidates = candidateMap[pos].map(c => {
                const r = resultsData[c.id] || {};
                return {
                    ...c,
                    votes: r.votes || 0,
                    breakdown: r // Pass raw breakdown (votes_12, votes_11, etc) to frontend
                };
            });
            candidates.sort((a, b) => b.votes - a.votes);
            finalResults[pos] = candidates;
        });

        res.json({
            isLive: isLive, // Sent to frontend to control End Screen
            stats: stats,
            leaderboard: finalResults
        });

    } catch (err) {
        console.error("Dashboard API Error:", err);
        res.status(500).json({ error: "Failed to fetch results." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

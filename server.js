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
// Protected by 'authenticateToken'
app.post('/api/vote', authenticateToken, async (req, res) => {
    // SECURITY: Get lvn from the secure token
    const lvn = req.user.lvn; 
    const { selections } = req.body; 

    // Diagnostic Log
    if (!lvn) {
        console.error("TOKEN ERROR: LVN is missing from token payload.", req.user);
        return res.status(400).json({ error: "Security Token Malformed. Please Login Again." });
    }

    // Input Validation
    if (!selections || !selections.president || !selections.vp) {
        return res.status(400).json({ error: "Invalid ballot: Missing selections." });
    }

    try {
        await db.runTransaction(async (t) => {
            const voterRef = db.collection('voters').doc(lvn);
            const voterSnap = await t.get(voterRef);

            if (!voterSnap.exists) throw new Error("Voter not found in registry.");
            if (voterSnap.data().hasVoted) throw new Error("Vote already recorded.");

            // 1. Audit Log (The Black Box)
            const logRef = db.collection('audit_logs').doc();
            t.set(logRef, {
                lvn: lvn,
                action: "VOTE_CAST",
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                ip: req.ip,
                userAgent: req.headers['user-agent'] || 'Unknown'
            });

            // 2. Mark voter as done
            t.update(voterRef, { 
                hasVoted: true, 
                votedAt: admin.firestore.FieldValue.serverTimestamp() 
            });

            // 3. Increment candidate counts (AUTO-CREATION FIX)
            const presRef = db.collection('results').doc(selections.president);
            const vpRef = db.collection('results').doc(selections.vp);

            // CHANGED: used 'set' with { merge: true } instead of 'update'
            // This creates the document with 1 vote if it's missing, or adds 1 if it exists.
            t.set(presRef, { votes: admin.firestore.FieldValue.increment(1) }, { merge: true });
            t.set(vpRef, { votes: admin.firestore.FieldValue.increment(1) }, { merge: true });
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
        const presSnap = await db.collection('candidates').doc('president').get();
        const vpSnap = await db.collection('candidates').doc('vp').get();

        if (!presSnap.exists || !vpSnap.exists) {
            return res.status(404).json({ error: "Candidate data not found." });
        }

        res.json({
            president: presSnap.data().options,
            vp: vpSnap.data().options
        });
    } catch (err) {
        console.error("Candidate Fetch Error:", err);
        res.status(500).json({ error: "Failed to load candidates." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

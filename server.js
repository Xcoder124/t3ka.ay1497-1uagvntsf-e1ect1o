const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

const app = express();

// 1. SECURITY: Only allow requests from your specific frontend URL
const allowedOrigins = [
    'http://127.0.0.1:5500',                            // Local testing
    'https://tsf-sslg-election-endpoint.onrender.com'      // Your actual frontend URL
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}));

app.use(express.json());

// 2. INITIALIZATION: Uses the secret key stored in Render Environment Variables
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// 3. REGISTRAR API: Verifies LRN and Grade-Level Gate
app.post('/api/verify', async (req, res) => {
    const { lrn, code } = req.body;

    try {
        // Fetch current election status (active grade)
        const settingsSnap = await db.collection('settings').doc('electionStatus').get();
        const settings = settingsSnap.data();

        if (!settings.isLive) {
            return res.status(403).json({ error: "Election is currently paused." });
        }

        // Fetch voter details
        const voterRef = db.collection('voters').doc(lrn);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists || voterSnap.data().code !== code.toUpperCase()) {
            return res.status(401).json({ error: "Invalid LRN or Security Code." });
        }

        const voterData = voterSnap.data();

        if (voterData.hasVoted) {
            return res.status(403).json({ error: "This LRN has already voted." });
        }

        // Grade Gate: Ensure only the currently supervised grade can log in
        if (voterData.grade !== settings.activeGrade) {
            return res.status(403).json({ error: `Unauthorized. Only Grade ${settings.activeGrade} is voting now.` });
        }

        res.json({ name: voterData.name, grade: voterData.grade });
    } catch (err) {
        res.status(500).json({ error: "Registrar connection error." });
    }
});

// 4. TALLIER API: Records the vote atomically
app.post('/api/vote', async (req, res) => {
    const { lrn, selections } = req.body; // selections: { president: 'id', vp: 'id' }

    try {
        await db.runTransaction(async (t) => {
            const voterRef = db.collection('voters').doc(lrn);
            const voterSnap = await t.get(voterRef);

            if (voterSnap.data().hasVoted) throw new Error("Vote already recorded.");

            // Mark voter as done
            t.update(voterRef, { 
                hasVoted: true, 
                votedAt: admin.firestore.FieldValue.serverTimestamp() 
            });

            // Increment candidate counts
            const presRef = db.collection('results').doc(selections.president);
            const vpRef = db.collection('results').doc(selections.vp);

            t.update(presRef, { votes: admin.firestore.FieldValue.increment(1) });
            t.update(vpRef, { votes: admin.firestore.FieldValue.increment(1) });
        });

        res.json({ success: true, hash: `TSF-${Date.now().toString(16).toUpperCase()}` });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// NEW ENDPOINT: Fetch Candidate Lists
app.get('/api/candidates', async (req, res) => {
    try {
        // Fetch candidate documents from Firestore
        const presSnap = await db.collection('candidates').doc('president').get();
        const vpSnap = await db.collection('candidates').doc('vp').get();

        if (!presSnap.exists || !vpSnap.exists) {
            return res.status(404).json({ error: "Candidate data not found in database." });
        }

        // Return the options arrays to the frontend
        res.json({
            president: presSnap.data().options,
            vp: vpSnap.data().options
        });
    } catch (err) {
        console.error("Error fetching candidates:", err);
        res.status(500).json({ error: "Failed to load candidates from the registrar." });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

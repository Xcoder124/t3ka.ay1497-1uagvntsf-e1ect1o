const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

const app = express();

// 1. SECURITY: Only allow requests from your specific frontend URL
app.use(cors({
    origin: 'https://your-frontend-link.onrender.com' 
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

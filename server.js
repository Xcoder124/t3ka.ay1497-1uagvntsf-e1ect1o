'use strict';

const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

// --- 1. STRICT SECURITY CONFIGURATION ---
app.use(helmet());
app.use(express.json()); // ✅ only once

// CRITICAL: Fail if secrets are missing
if (!process.env.JWT_SECRET || !process.env.ADMIN_KEY) {
  console.error("FATAL ERROR: JWT_SECRET and ADMIN_KEY are missing.");
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;

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
    // allow server-to-server / curl (no origin)
    if (!origin) return callback(null, true);

    if (!allowedOrigins.includes(origin)) {
      return callback(new Error('CORS Policy: Origin not allowed'), false);
    }
    return callback(null, true);
  }
}));

// --- 2. FIREBASE INITIALIZATION ---
if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("FATAL ERROR: Missing FIREBASE_SERVICE_ACCOUNT.");
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch (e) {
  console.error("FATAL ERROR: FIREBASE_SERVICE_ACCOUNT is not valid JSON.");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// --- 3. IN-MEMORY CACHE ---
const GlobalCache = {
  candidates: {},
  dashboard: {
    isLive: false,
    stats: { total: 0, voted: 0, percentage: 0, grades: {} },
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
      data[pos] = snap.exists ? (snap.data().options || []) : [];
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
    const isLive = settingsSnap.exists ? !!settingsSnap.data().isLive : false;

    // 2. Re-calc voter stats
    const votersSnap = await db.collection('voters').get();
    const stats = { total: 0, voted: 0, percentage: 0, grades: {} };

    votersSnap.forEach(docSnap => {
      const d = docSnap.data();
      const g = d.grade || "Unknown";

      if (!stats.grades[g]) stats.grades[g] = { total: 0, voted: 0, missed: 0 };

      stats.total++;
      stats.grades[g].total++;

      if (d.hasVoted) {
        stats.voted++;
        stats.grades[g].voted++;
      } else {
        stats.grades[g].missed++;
      }
    });

    if (stats.total > 0) stats.percentage = ((stats.voted / stats.total) * 100).toFixed(1);

    console.log(`CACHE: Stats updated. Total: ${stats.total}, Voted: ${stats.voted}`);

    // 3. Votes leaderboard
    const resultsSnap = await db.collection('results').get();
    const resultsData = {};
    resultsSnap.forEach(docSnap => { resultsData[docSnap.id] = docSnap.data(); });

    const finalResults = {};
    const positions = Object.keys(GlobalCache.candidates);

    positions.forEach(pos => {
      const candidates = (GlobalCache.candidates[pos] || []).map(c => {
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

// --- AUDIT LOGGING HELPER ---
async function logAudit(action, performer, details) {
  try {
    await admin.firestore().collection('audit_logs').add({
      action,
      performer,
      details,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`[AUDIT] ${action} by ${performer}`);
  } catch (e) {
    console.error("Audit Log Failed:", e);
  }
}

// --- 5. REGISTRAR API (Login) ---
app.post('/api/verify', loginLimiter, async (req, res) => {
  const { lvn, code } = req.body;

  if (!lvn || !code) {
    return res.status(400).json({ error: "Missing lvn or code." });
  }

  try {
    const settingsSnap = await db.collection('settings').doc('electionStatus').get();
    if (!settingsSnap.exists || !settingsSnap.data().isLive) {
      return res.status(403).json({ error: "Election is paused." });
    }
    const activeGrade = settingsSnap.data().activeGrade;

    const voterRef = db.collection('voters').doc(String(lvn));
    const voterSnap = await voterRef.get();

    const inputCode = String(code).toUpperCase().trim();

    if (!voterSnap.exists || String(voterSnap.data().code || '').toUpperCase().trim() !== inputCode) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const voterData = voterSnap.data();
    if (voterData.hasVoted) return res.status(403).json({ error: "You have already voted." });

    if (activeGrade && activeGrade !== "ALL" && voterData.grade !== activeGrade) {
      return res.status(403).json({ error: `Voting session is for Grade ${activeGrade} only.` });
    }

    // ✅ token includes lvn (consistent everywhere)
    const token = jwt.sign(
      { lvn: String(lvn), grade: voterData.grade },
      JWT_SECRET,
      { expiresIn: '20m' }
    );

    res.json({ name: voterData.name, grade: voterData.grade, token });

  } catch (err) {
    console.error("Verify Error:", err);
    res.status(500).json({ error: "Registrar connection error." });
  }
});

// --- 6. TALLIER API (Voting) ---
// ✅ use middleware instead of re-verifying manually
app.post('/api/vote', authenticateToken, async (req, res) => {
  const { selections } = req.body;

  // A. Validate payload
  if (!selections || typeof selections !== 'object' || Array.isArray(selections)) {
    return res.status(400).json({ error: "Invalid payload format." });
  }

  const lvn = req.user.lvn;     // ✅ consistent with /api/verify
  const grade = req.user.grade; // used for cache breakdown updates

  try {
    // B. Transaction: block double vote + save vote receipt + mark voter voted
    const receiptHash = await db.runTransaction(async (t) => {
      const voterRef = db.collection('voters').doc(String(lvn));
      const voterDoc = await t.get(voterRef);

      if (!voterDoc.exists) {
        throw new Error("VOTER_NOT_FOUND");
      }
      if (voterDoc.data().hasVoted) {
        throw new Error("ALREADY_VOTED");
      }

      // C. Generate Receipt Hash (Integrity Check)
      const voteString = `${String(lvn)}-${new Date().toISOString()}-${JSON.stringify(selections)}`;
      const hash = crypto.createHash('sha256').update(voteString).digest('hex');

      // D. Save vote record (anonymous)
      t.set(db.collection('votes').doc(), {
        selections,
        hash,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      // E. Update voter
      t.update(voterRef, {
        hasVoted: true,
        votedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      return hash;
    });

    // ✅ log audit outside transaction
    logAudit("VOTE_CAST", "ANONYMOUS", { hash: receiptHash }).catch(() => {});

    // ✅ 4. INSTANT LOCAL UPDATE (now properly inside the route)
    if (GlobalCache.dashboard?.stats) {
      GlobalCache.dashboard.stats.voted++;

      if (GlobalCache.dashboard.stats.total > 0) {
        GlobalCache.dashboard.stats.percentage =
          ((GlobalCache.dashboard.stats.voted / GlobalCache.dashboard.stats.total) * 100).toFixed(1);
      }

      if (grade && GlobalCache.dashboard.stats.grades?.[grade]) {
        GlobalCache.dashboard.stats.grades[grade].voted++;
        GlobalCache.dashboard.stats.grades[grade].missed =
          Math.max(0, (GlobalCache.dashboard.stats.grades[grade].missed || 0) - 1);
      }
    }

    // Update candidate cache immediately
    if (GlobalCache.dashboard?.leaderboard) {
      Object.keys(selections).forEach(posKey => {
        const cId = selections[posKey];
        const list = GlobalCache.dashboard.leaderboard[posKey];

        if (Array.isArray(list)) {
          const cand = list.find(c => String(c.id) === String(cId));
          if (cand) {
            cand.votes = (cand.votes || 0) + 1;

            if (!cand.breakdown) cand.breakdown = {};
            const gKey = `votes_${grade || 'Unknown'}`;
            cand.breakdown[gKey] = (cand.breakdown[gKey] || 0) + 1;

            list.sort((a, b) => (b.votes || 0) - (a.votes || 0));
          }
        }
      });
    }

    return res.json({ success: true, hash: receiptHash });

  } catch (err) {
    if (err.message === "ALREADY_VOTED") {
      return res.status(403).json({ error: "You have already voted." });
    }
    if (err.message === "VOTER_NOT_FOUND") {
      return res.status(404).json({ error: "Voter record not found." });
    }
    console.error("Vote Error:", err);
    return res.status(500).json({ error: "Server error while casting vote." });
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

app.post('/api/admin/refresh/candidates', async (req, res) => {
  const success = await refreshLocalCandidates();
  if (success) res.json({ success: true, timestamp: GlobalCache.timestamps.candidates });
  else res.status(500).json({ error: "Failed to refresh candidates." });
});

app.post('/api/admin/refresh/results', async (req, res) => {
  const success = await refreshLocalResults();
  if (success) res.json({ success: true, timestamp: GlobalCache.timestamps.results });
  else res.status(500).json({ error: "Failed to refresh results." });
});

app.get('/api/admin/status', (req, res) => {
  res.json(GlobalCache.timestamps);
});

app.post('/api/admin/add-party', async (req, res) => {
  const { candidates } = req.body;

  if (!Array.isArray(candidates) || candidates.length === 0) {
    return res.status(400).json({ error: "Candidates must be a non-empty array." });
  }

  try {
    await db.runTransaction(async (t) => {
      const groupedData = {};

      candidates.forEach(c => {
        if (!c.position || !c.id || !c.name || !c.party) return;

        if (!groupedData[c.position]) groupedData[c.position] = [];
        groupedData[c.position].push({
          id: String(c.id),
          name: String(c.name).toUpperCase(),
          party: String(c.party).toUpperCase(),
          img: c.img || "none"
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
  } catch (err) {
    console.error("Add-party Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---ADMIN DELETE ---
app.post('/api/admin/delete', async (req, res) => {
  const { position, candidateId, partyName, adminKey } = req.body;

  // A. Server-Side Auth Check
  if (!adminKey || adminKey !== ADMIN_KEY) {
    logAudit("UNAUTHORIZED_DELETE_ATTEMPT", req.ip, { target: candidateId || partyName }).catch(() => {});
    return res.status(403).json({ error: "Unauthorized: Invalid Admin Key" });
  }

  const ALL_POSITIONS = [
    'president', 'vp', 'secretary', 'treasurer', 'auditor',
    'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
  ];

  try {
    // SCENARIO 1: DELETE ENTIRE PARTYLIST
    if (partyName) {
      const normalizedParty = String(partyName).toUpperCase();
      console.log(`[ADMIN] Starting bulk delete for party: ${normalizedParty}`);

      const batch = db.batch();
      let deletedCount = 0;

      const refs = ALL_POSITIONS.map(pos => db.collection('candidates').doc(pos));
      const snapshots = await db.getAll(...refs);

      snapshots.forEach((docSnap, index) => {
        if (docSnap.exists) {
          const currentOptions = docSnap.data().options || [];
          const newOptions = currentOptions.filter(c => String(c.party).toUpperCase() !== normalizedParty);

          if (newOptions.length !== currentOptions.length) {
            deletedCount += (currentOptions.length - newOptions.length);
            batch.update(refs[index], { options: newOptions });
          }
        }
      });

      await batch.commit();
      await logAudit("DELETE_PARTY", "ADMIN", { party: normalizedParty, count: deletedCount });

      return res.json({
        success: true,
        message: `Deleted ${deletedCount} candidates from party '${normalizedParty}' across all positions.`
      });
    }

    // SCENARIO 2: DELETE SINGLE CANDIDATE
    if (position && candidateId) {
      const pos = String(position);
      const candId = String(candidateId);

      const docRef = db.collection('candidates').doc(pos);

      await db.runTransaction(async (t) => {
        const docSnap = await t.get(docRef);
        if (!docSnap.exists) throw new Error("Position document not found");

        const currentOptions = docSnap.data().options || [];
        const exists = currentOptions.some(c => String(c.id) === candId);
        if (!exists) throw new Error("Candidate ID not found in this position");

        const newOptions = currentOptions.filter(c => String(c.id) !== candId);
        t.update(docRef, { options: newOptions });
      });

      await logAudit("DELETE_CANDIDATE", "ADMIN", { position: pos, candidateId: candId });
      return res.json({ success: true, message: "Candidate deleted successfully." });
    }

    return res.status(400).json({
      error: "Missing parameters. Provide (position & candidateId) OR (partyName)."
    });

  } catch (err) {
    console.error("Delete Error:", err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Election Server live on port ${PORT}`));

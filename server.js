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
app.use(express.json());

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

// --- POSITIONS (single source of truth) ---
const ALL_POSITIONS = [
  'president', 'vp', 'secretary', 'treasurer', 'auditor',
  'pio', 'protocol', 'rep8', 'rep9', 'rep10', 'rep11', 'rep12'
];

// --- HELPER: REFRESH CANDIDATES ---
async function refreshLocalCandidates() {
  try {
    const data = {};
    await Promise.all(ALL_POSITIONS.map(async (pos) => {
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

    const settingsSnap = await db.collection('settings').doc('electionStatus').get();
    const isLive = settingsSnap.exists ? !!settingsSnap.data().isLive : false;

    // voter stats
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

    // leaderboard from results collection
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
      candidates.sort((a, b) => (b.votes || 0) - (a.votes || 0));
      finalResults[pos] = candidates;
    });

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

// --- HELPER: validate selections against cached candidates ---
function validateSelectionsOrThrow(selections) {
  if (!selections || typeof selections !== 'object' || Array.isArray(selections)) {
    throw new Error("INVALID_PAYLOAD");
  }

  // Must have candidates loaded
  if (!GlobalCache.candidates || Object.keys(GlobalCache.candidates).length === 0) {
    throw new Error("CANDIDATES_NOT_READY");
  }

  const validated = {};

  for (const [posKey, candidateIdRaw] of Object.entries(selections)) {
    if (!ALL_POSITIONS.includes(posKey)) {
      throw new Error(`INVALID_POSITION:${posKey}`);
    }

    const candidateId = String(candidateIdRaw);
    const list = GlobalCache.candidates[posKey] || [];

    const existsInPosition = list.some(c => String(c.id) === candidateId);
    if (!existsInPosition) {
      throw new Error(`INVALID_CANDIDATE:${posKey}`);
    }

    validated[posKey] = candidateId;
  }

  return validated;
}

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
    await db.collection('audit_logs').add({
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

// --- ADMIN KEY MIDDLEWARE (applies to ALL /api/admin/*) ---
function requireAdminKey(req, res, next) {
  const key =
    req.headers['x-admin-key'] ||
    req.body?.adminKey ||
    req.query?.adminKey;

  if (!key || String(key) !== String(ADMIN_KEY)) {
    logAudit("UNAUTHORIZED_ADMIN_ACTION", req.ip, { path: req.path }).catch(() => {});
    return res.status(403).json({ error: "Unauthorized: Invalid Admin Key" });
  }

  next();
}

// ✅ This makes every /api/admin/* require admin key
app.use('/api/admin', requireAdminKey);

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
// ✅ validates candidates + writes to results inside transaction
app.post('/api/vote', authenticateToken, async (req, res) => {
  const lvn = req.user.lvn;
  const grade = req.user.grade || "Unknown";

  let selections;
  try {
    selections = validateSelectionsOrThrow(req.body.selections);
  } catch (e) {
    const msg = String(e.message || "");
    if (msg === "INVALID_PAYLOAD") return res.status(400).json({ error: "Invalid payload format." });
    if (msg === "CANDIDATES_NOT_READY") return res.status(503).json({ error: "Candidates not ready. Try again." });
    if (msg.startsWith("INVALID_POSITION")) return res.status(400).json({ error: "Invalid position in selections." });
    if (msg.startsWith("INVALID_CANDIDATE")) return res.status(400).json({ error: "Invalid candidate selection." });
    return res.status(400).json({ error: "Invalid selections." });
  }

  try {
    const receiptHash = await db.runTransaction(async (t) => {
      // ✅ Check election status + active grade inside the transaction
      const settingsRef = db.collection('settings').doc('electionStatus');
      const settingsSnap = await t.get(settingsRef);

      if (!settingsSnap.exists || !settingsSnap.data().isLive) {
        throw new Error("ELECTION_PAUSED");
      }

      const activeGrade = settingsSnap.data().activeGrade;
      if (activeGrade && activeGrade !== "ALL" && grade !== activeGrade) {
        throw new Error("GRADE_NOT_ALLOWED");
      }

      // voter checks
      const voterRef = db.collection('voters').doc(String(lvn));
      const voterDoc = await t.get(voterRef);

      if (!voterDoc.exists) throw new Error("VOTER_NOT_FOUND");
      if (voterDoc.data().hasVoted) throw new Error("ALREADY_VOTED");

      // receipt hash
      const voteString = `${String(lvn)}-${new Date().toISOString()}-${JSON.stringify(selections)}`;
      const hash = crypto.createHash('sha256').update(voteString).digest('hex');

      // store the anonymized vote record
      t.set(db.collection('votes').doc(), {
        selections,
        hash,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });

      // ✅ REAL-TIME TALLY: update results per candidate INSIDE transaction
      // results/<candidateId> { votes: +1, votes_<grade>: +1 }
      for (const candidateId of Object.values(selections)) {
        const resultRef = db.collection('results').doc(String(candidateId));

        t.set(resultRef, {
          votes: admin.firestore.FieldValue.increment(1),
          [`votes_${grade}`]: admin.firestore.FieldValue.increment(1),
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      }

      // mark voter voted
      t.update(voterRef, {
        hasVoted: true,
        votedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      return hash;
    });

    // audit outside transaction
    logAudit("VOTE_CAST", "ANONYMOUS", { hash: receiptHash }).catch(() => {});

    // ✅ instant local cache updates (dashboard)
    if (GlobalCache.dashboard?.stats) {
      GlobalCache.dashboard.stats.voted++;

      if (GlobalCache.dashboard.stats.total > 0) {
        GlobalCache.dashboard.stats.percentage =
          ((GlobalCache.dashboard.stats.voted / GlobalCache.dashboard.stats.total) * 100).toFixed(1);
      }

      if (GlobalCache.dashboard.stats.grades?.[grade]) {
        GlobalCache.dashboard.stats.grades[grade].voted++;
        GlobalCache.dashboard.stats.grades[grade].missed =
          Math.max(0, (GlobalCache.dashboard.stats.grades[grade].missed || 0) - 1);
      }
    }

    // ✅ instant local cache updates (leaderboard)
    if (GlobalCache.dashboard?.leaderboard) {
      for (const [posKey, candidateId] of Object.entries(selections)) {
        const list = GlobalCache.dashboard.leaderboard[posKey];
        if (!Array.isArray(list)) continue;

        const cand = list.find(c => String(c.id) === String(candidateId));
        if (!cand) continue;

        cand.votes = (cand.votes || 0) + 1;

        if (!cand.breakdown) cand.breakdown = {};
        const gKey = `votes_${grade}`;
        cand.breakdown[gKey] = (cand.breakdown[gKey] || 0) + 1;

        list.sort((a, b) => (b.votes || 0) - (a.votes || 0));
      }
    }

    return res.json({ success: true, hash: receiptHash });

  } catch (err) {
    const m = String(err.message || "");
    if (m === "ALREADY_VOTED") return res.status(403).json({ error: "You have already voted." });
    if (m === "VOTER_NOT_FOUND") return res.status(404).json({ error: "Voter record not found." });
    if (m === "ELECTION_PAUSED") return res.status(403).json({ error: "Election is paused." });
    if (m === "GRADE_NOT_ALLOWED") return res.status(403).json({ error: "Not allowed in current grade session." });

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
// ✅ all routes below automatically require ADMIN_KEY due to app.use('/api/admin', requireAdminKey)

// Refresh Candidates
app.post('/api/admin/refresh/candidates', async (req, res) => {
  const success = await refreshLocalCandidates();
  if (success) res.json({ success: true, timestamp: GlobalCache.timestamps.candidates });
  else res.status(500).json({ error: "Failed to refresh candidates." });
});

// Refresh Results & Stats
app.post('/api/admin/refresh/results', async (req, res) => {
  const success = await refreshLocalResults();
  if (success) res.json({ success: true, timestamp: GlobalCache.timestamps.results });
  else res.status(500).json({ error: "Failed to refresh results." });
});

// Status (GET) - adminKey via header x-admin-key OR query ?adminKey=...
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
        const docSnap = await t.get(docRef);

        const newCandidates = groupedData[pos];
        if (!docSnap.exists) t.set(docRef, { options: newCandidates });
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
  const { position, candidateId, partyName } = req.body;

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
        if (!docSnap.exists) return;

        const currentOptions = docSnap.data().options || [];
        const newOptions = currentOptions.filter(c => String(c.party).toUpperCase() !== normalizedParty);

        if (newOptions.length !== currentOptions.length) {
          deletedCount += (currentOptions.length - newOptions.length);
          batch.update(refs[index], { options: newOptions });
        }
      });

      await batch.commit();
      await logAudit("DELETE_PARTY", "ADMIN", { party: normalizedParty, count: deletedCount });

      await refreshLocalCandidates();
      await refreshLocalResults();

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

      await refreshLocalCandidates();
      await refreshLocalResults();

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

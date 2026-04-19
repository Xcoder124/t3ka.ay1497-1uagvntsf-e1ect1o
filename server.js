const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const crypto = require("crypto");
const CANDIDATE_SECRET = process.env.CANDIDATE_SECRET;
if (!process.env.CANDIDATE_SECRET) {
    throw new Error("CANDIDATE_SECRET is required.");
}
const VOTE_SIGN_SECRET = process.env.VOTE_SIGN_SECRET;
if (!VOTE_SIGN_SECRET) {
    throw new Error("VOTE_SIGN_SECRET is required");
}

const BACKUP_SECRET = process.env.BACKUP_SECRET;
if (!BACKUP_SECRET) {
    throw new Error("BACKUP_SECRET is required");
}

const axios = require("axios");
const bcrypt = require("bcrypt");
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

// --- ADD dotenv for local developent ---
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// --- RENDER: Explicit Firebase Admin Initialization ---
const privateKey = process.env.FIREBASE_PRIVATE_KEY;
if (!privateKey) {
    console.error("ERROR: FIREBASE_PRIVATE_KEY environment variable is missing!");
    console.error("Available env vars:", Object.keys(process.env).filter(k => k.includes('FIREBASE')));
    process.exit(1);
}

try {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: privateKey.replace(/\\n/g, '\n'),
        }),
        databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}-default-rtdb.asia-southeast1.firebasedatabase.app` // Ensure this matches your RTDB URL
    });
    console.log("Firebase Admin initialized successfully");
} catch (error) {
    console.error("Firebase initialization failed:", error.message);
    process.exit(1);
}

const rtdb = admin.database();

console.log("=== SERVER STARTING ===");
console.log("NODE_ENV:", process.env.NODE_ENV);
console.log("FIREBASE_PROJECT_ID exists:", !!process.env.FIREBASE_PROJECT_ID);
console.log("FIREBASE_CLIENT_EMAIL exists:", !!process.env.FIREBASE_CLIENT_EMAIL);
console.log("FIREBASE_PRIVATE_KEY exists:", !!process.env.FIREBASE_PRIVATE_KEY);
console.log("ADMIN_KEY exists:", !!process.env.ADMIN_KEY);
console.log("GITHUB_REPO exists:", !!process.env.GITHUB_REPO);
console.log("GITHUB_TOKEN exists:", !!process.env.GITHUB_TOKEN);

const app = express();

// --- MIDDLEWARE & APP CONFIG ---
app.set('trust proxy', 1);
app.use(express.json({ limit: '110kb' }));
app.use(cookieParser());

// --- SECURITY: ENHANCED HELMET CONFIGURATION (FIXED FOR HELMET v7) ---
// ✅ FIXED CORS CONFIGURATION
const allowedOrigins = process.env.NODE_ENV === 'production'
    ? [
        "https://tsf-g-digital-election.web.app",
        "https://tanauanschooloffisheries.web.app",
        "https://adesportstorres-v2.web.app"
    ]
    : [
        "http://127.0.0.1:5500",
        "http://localhost:3000",
        "https://tsf-g-digital-election.web.app",
        "https://tanauanschooloffisheries.web.app",
        "https://adesportstorres-v2.web.app"
    ];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, curl, server-to-server)
        if (!origin) return callback(null, true);

        // Clean the origin (remove trailing spaces, normalize)
        const cleanOrigin = origin.trim();

        // Check if origin matches allowed list
        const isAllowed = allowedOrigins.some(allowed =>
            cleanOrigin === allowed || cleanOrigin.startsWith(allowed + '/')
        );

        if (isAllowed) {
            // Return the specific origin, not true (required for credentials)
            callback(null, cleanOrigin);
        } else {
            console.warn(`[CORS BLOCKED] Origin: ${cleanOrigin}`);
            callback(new Error("CORS Policy: Origin not allowed"), false);
        }
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "x-csrf-token", "X-Admin-Key", "x-ai-service-key"],
    exposedHeaders: ["set-cookie"]
}));

app.options('*', cors());

// CSP Middleware with Signed Nonce Support - HELMET v7 COMPATIBLE
app.use((req, res, next) => {
    req.cspNonce = generateNonce();

    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", `'nonce-${req.cspNonce}'`, "https://cdnjs.cloudflare.com", "https://www.gstatic.com", "https://challenges.cloudflare.com", "https://cdn.jsdelivr.net"],
            frameSrc: ["'self'", "https://challenges.cloudflare.com"],
            styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "https://identitytoolkit.googleapis.com", "https://securetoken.googleapis.com", "https://challenges.cloudflare.com", "https://tsf-sslg-election-endpoint.onrender.com", "https://tsf-g-digital-election.web.app", "https://tanauanschooloffisheries.web.app"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "blob:", "https://firebasestorage.googleapis.com", "https://ui-avatars.com"],
            frameAncestors: ["'none'"],

        },
    })(req, res, next);
});

const ALLOWED_AI_ORIGINS = [
    'https://tsf-g-digital-election.web.app/conversation',
    'https://tsf-g-digital-election.web.app/conversation.html',
    'https://tanauanschooloffisheries.web.app/conversation',
    'https://tanauanschooloffisheries.web.app/conversation.html',
    'https://tsf-g-digital-election.web.app',
    'https://tanauanschooloffisheries.web.app'
];
const AI_SERVICE_KEY = process.env.AI_SERVICE_KEY;
if (!AI_SERVICE_KEY) {
    console.warn('⚠️  AI_SERVICE_KEY not set. AI Service authentication will be disabled.');
}

const db = admin.firestore();

// GLOBAL VARIABLES
const MAX_ATTEMPTS = 3;
const LOCK_TIME = 30 * 1000; // 30 sec
const AUDIT_CHAIN_DOC = db.collection("_meta").doc("chain_head");
const MASK_SECRET = process.env.JWT_SECRET;

const VotersStaticCache = {
    data: [],
    lastUpdated: null,
    isLoading: false
};

const VoterStatusCache = {
    data: null,
    lastFetch: 0
};

async function getVoterStatusCache() {
    const now = Date.now();

    if (!VoterStatusCache.data || now - VoterStatusCache.lastFetch > 3000) {
        const snap = await rtdb.ref("voterStatus").once("value");
        VoterStatusCache.data = snap.val() || {};
        VoterStatusCache.lastFetch = now;
    }

    return VoterStatusCache.data;
}

const ACCESS_CODE_KEY = process.env.BACKUP_SECRET;

(async () => {
    try {
        await refreshLocalResults();
        console.log("Dashboard cache warmed up");
    } catch (err) {
        console.error("Initial dashboard load failed:", err);
    }
})();

(async () => {
    try {
        await loadVotersStaticCache();
    } catch (err) {
        console.error("Voters static cache warm-up failed:", err);
    }
})();

setInterval(async () => {
    try {
        await refreshLocalResults();
    } catch (err) {
        console.error("Background dashboard refresh failed:", err);
    }
}, 3 * 60 * 60 * 1000);

async function validateSelections(selections) {
    let candidateMap = GlobalCache.candidates;

    if (!candidateMap || Object.keys(candidateMap).length === 0) {
        const success = await refreshLocalCandidates();
        candidateMap = GlobalCache.candidates;

        if (!success || !candidateMap || Object.keys(candidateMap).length === 0) {
            throw new Error("Candidate cache unavailable");
        }
    }

    const validated = {};

    for (const [position, options] of Object.entries(candidateMap)) {

        if (selections[position] === undefined) continue;

        // 🔐 Ensure valid position
        if (!GlobalCache.candidateHashMap[position]) {
            throw new Error(`Invalid position ${position}`);
        }

        const selected = selections[position];

        const selectedArray = (Array.isArray(selected) ? selected : [selected])
            .map(s => String(s).trim());

        if (selectedArray.length === 0) {
            throw new Error(`No selection provided for ${position}`);
        }

        if (!MULTI_POSITIONS.includes(position) && selectedArray.length > 1) {
            throw new Error(`Multiple selections not allowed for ${position}`);
        }

        if (selectedArray.length > options.length) {
            throw new Error(`Too many selections for ${position}`);
        }

        if (new Set(selectedArray).size !== selectedArray.length) {
            throw new Error(`Duplicate selections for ${position}`);
        }

        const resolved = selectedArray.map(sel => {

            if (!/^[a-f0-9]{64}$/.test(sel)) {
                throw new Error(`Tampered selection detected for ${position}`);
            }

            const match = GlobalCache.candidateHashMap[position]?.[sel];

            if (!match) {
                throw new Error(`Invalid candidate for ${position}`);
            }

            return match;
        });

        validated[position] = MULTI_POSITIONS.includes(position)
            ? resolved
            : resolved[0];
    }

    return validated;
}

function hashCandidateId(id) {
    if (!process.env.CANDIDATE_SECRET) {
        throw new Error("A Candidate Secret is missing.");
    }

    return crypto.createHmac("sha256", process.env.CANDIDATE_SECRET)
        .update(id)
        .digest("hex");
}

function generateVoteSignature(selections, timestamp, nonce) {
    const payload = JSON.stringify({ selections, timestamp, nonce });
    return crypto.createHmac("sha256", VOTE_SIGN_SECRET)
        .update(payload)
        .digest("hex");
}

// ============================================
// 🔐 ANTI-REPLAY: FIRESTORE-BACKED NONCE STORE
// ============================================
async function consumeNonce(nonce, jti) {
    const key = crypto.createHash('sha256').update(`${nonce}:${jti}`).digest('hex');
    const ref = db.collection('used_nonces').doc(key);

    let accepted = false;
    await db.runTransaction(async (t) => {
        const doc = await t.get(ref);
        if (doc.exists) return;   // already used — abort without writing
        accepted = true;
        t.set(ref, { usedAt: admin.firestore.FieldValue.serverTimestamp() });
    });

    return accepted;
}

// Purge nonces older than 2 minutes every 60 seconds (keeps collection lean)
setInterval(async () => {
    try {
        const cutoff = admin.firestore.Timestamp.fromMillis(Date.now() - 120_000);
        const snap = await db.collection('used_nonces')
            .where('usedAt', '<', cutoff)
            .limit(200)
            .get();
        if (snap.empty) return;
        const batch = db.batch();
        snap.forEach(doc => batch.delete(doc.ref));
        await batch.commit();
        console.log(`[NONCE] Purged ${snap.size} expired nonce(s)`);
    } catch (e) {
        console.error('[NONCE CLEANUP] Error:', e);
    }
}, 60_000);

setInterval(async () => {
    try {
        const now = Date.now();
        const snapshot = await db.collection("system_alerts").where("active", "==", true).get();
        snapshot.forEach(async (doc) => {
            const data = doc.data();
            if (data.expiresAt && data.expiresAt.toMillis() < now) {
                await alertManager.expireAlert(doc.id);
            }
        });
    } catch (e) { console.error("Expiry check error:", e); }
}, 1200000);

async function joinQueue(userId, grade) {
    const gradeKey = `sessionG${grade}`;
    const queueRef = rtdb.ref(`queue/${gradeKey}`);

    await queueRef.transaction(current => {
        current = current || {
            activeCount: 0,
            maxActive: 50,  // 50 voters per grade at a time
            lastPosition: 0,
            users: {}
        };

        if (!current.users) current.users = {};

        // If user already exists and is done, don't re-add
        if (current.users[userId] && current.users[userId].status === 'done') {
            return; // abort transaction
        }

        const newPosition = current.lastPosition + 1;

        // Determine status based on position within this grade's slots
        let newStatus = 'waiting';
        let newActiveCount = current.activeCount;

        // If position is within maxActive slots for THIS GRADE, they're active immediately
        if (newPosition <= current.maxActive) {
            newStatus = 'active';
            newActiveCount++;
        }

        current.users[userId] = {
            position: newPosition,
            status: newStatus,
            joinedAt: admin.database.ServerValue.TIMESTAMP,
            grade: grade  // Store grade for reference
        };

        current.activeCount = newActiveCount;
        current.lastPosition = newPosition;

        return current;
    });
}

function calculateETA(position, currentServing, maxActive = 100, avgTime = 5) {
    // peopleAhead = how many slots are still ahead of this user's position
    const peopleAhead = Math.max(0, position - currentServing);

    if (peopleAhead <= 0) return "You're next!";

    const batches = Math.ceil(peopleAhead / maxActive);
    return `${batches * avgTime} mins`;
}

function encryptAccessCode(code) {
    if (!code) return null;
    const key = crypto.createHash('sha256').update(ACCESS_CODE_KEY).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(code.toUpperCase(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decryptAccessCode(encryptedCode) {
    if (!encryptedCode || !encryptedCode.includes(':')) return null;
    try {
        const [ivHex, encrypted] = encryptedCode.split(':');
        const key = crypto.createHash('sha256').update(ACCESS_CODE_KEY).digest();
        const iv = Buffer.from(ivHex, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error('Failed to decrypt access code:', e);
        return null;
    }
}

async function loadVotersStaticCache() {
    if (VotersStaticCache.isLoading) return;
    VotersStaticCache.isLoading = true;

    try {
        console.log('[CACHE] Loading voters static cache from Firestore...');

        // ONE full-collection read — amortised across all future admin page loads.
        // ~2700 docs × ~4 fields ≈ very cheap on Blaze.
        const snap = await db.collection("voters").get();

        const voters = [];
        snap.forEach(doc => {
            const v = doc.data();
            voters.push({
                id: doc.id,                               // hashedLVN — RTDB key
                lvn: v.lvn || null,                       // raw LVN — admin operations
                name: v.name || "",
                grade: v.grade || "",
                section: v.section || "",
                // Decrypt once at cache-load time rather than per-request
                accessCode: v.code ? (decryptAccessCode(v.codeHash) || "ERROR") : null,
                addedAt: v.addedAt ? v.addedAt.toDate().toISOString() : null,
            });
        });

        // Pre-sort by grade → name so slices come out ordered without re-sorting
        voters.sort((a, b) => {
            const gDiff = parseInt(a.grade) - parseInt(b.grade);
            if (gDiff !== 0) return gDiff;
            return (a.name || "").localeCompare(b.name || "");
        });

        VotersStaticCache.data = voters;
        VotersStaticCache.lastUpdated = new Date().toISOString();

        console.log(`[CACHE] Voters static cache loaded: ${voters.length} entries`);
    } catch (e) {
        console.error('[CACHE] Failed to load voters static cache:', e);
    } finally {
        VotersStaticCache.isLoading = false;
    }
}

// Invalidate + reload when voter records are added or deleted
async function invalidateVotersCache() {
    VotersStaticCache.data = [];
    VotersStaticCache.lastUpdated = null;
    await loadVotersStaticCache();
}

async function updateVoterStatusInRTDB(voterId, { hasVoted, isMissed, integrityStatus }) {
    await rtdb.ref(`voterStatus/${voterId}`).set({
        hasVoted: !!hasVoted,
        isMissed: !!isMissed,
        integrityStatus: integrityStatus || "PENDING",
        updatedAt: admin.database.ServerValue.TIMESTAMP
    });
    VoterStatusCache.data = null;
    VoterStatusCache.lastFetch = 0;
}

// ============================================
// AI SERVICE AUTHENTICATION - STRICT SECURITY
// ============================================

function requireAIServiceOnly(req, res, next) {
    const aiKey = req.headers['x-ai-service-key'];
    const origin = req.headers.origin || req.headers.referer;

    // Must have valid key
    if (!aiKey || !AI_SERVICE_KEY || aiKey !== AI_SERVICE_KEY) {
        return res.status(401).json({ error: "Invalid or missing AI Service key" });
    }

    // Must have valid origin
    const isAllowedOrigin = ALLOWED_AI_ORIGINS.some(allowed => {
        return origin === allowed || origin?.startsWith(allowed);
    });

    if (!isAllowedOrigin && process.env.NODE_ENV === 'production') {
        console.warn(`[AI AUTH] Blocked request from origin: ${origin}`);
        return res.status(403).json({ error: "Forbidden: Invalid origin" });
    }

    // Set AI context
    req.user = {
        uid: 'AI_SERVICE',
        role: 'admin',
        isAIService: true
    };

    next();
}

// --- CONSTANTS ---
const MULTI_POSITIONS = ["rep7", "rep8", "rep9", "rep10", "rep11", "rep12"];

// -- BACKUP
async function createElectionBackup(db) {
    const votesSnap = await db.collection("votes").get();
    const votersSnap = await db.collection("voters").get();
    const candidatesSnap = await db.collection("candidates").get();

    const backup = {
        timestamp: new Date().toISOString(),
        totalVotes: votesSnap.size,
        votes: votesSnap.docs.map(d => ({ _docId: d.id, ...d.data() })),
        voters: votersSnap.docs.map(d => ({ _docId: d.id, ...d.data() })),  // ← include doc ID
        candidates: candidatesSnap.docs.map(d => ({ _docId: d.id, ...d.data() }))
    };

    const raw = JSON.stringify(backup, null, 2);

    const key = crypto.createHash('sha256').update(process.env.BACKUP_SECRET).digest();
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(raw, "utf8", "hex");
    encrypted += cipher.final("hex");

    const json = iv.toString("hex") + ":" + encrypted;

    const hash = crypto
        .createHash("sha256")
        .update(json)
        .digest("hex");

    return { json, hash };
}

async function uploadToGitHub(json, hash) {
    try {
        const path = `archives/election-${Date.now()}.json`;
        const content = Buffer.from(json).toString("base64");

        const res = await axios.put(
            `https://api.github.com/repos/${process.env.GITHUB_REPO}/contents/${path}`,
            {
                message: `Election backup | ${new Date().toISOString()} | Hash: ${hash}`,
                content: content
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
                    "Content-Type": "application/json"
                }
            }
        );

        await alertManager.detectSystemHealth();

        return res.data.content.html_url;


    } catch (e) {
        console.error("GITHUB UPLOAD ERROR:", e.response?.data || e.message);
        throw e;
    }
}

async function restoreElectionFromBackup(jsonData, providedHash) {
    const actualHash = crypto.createHash("sha256").update(jsonData).digest("hex");
    if (!crypto.timingSafeEqual(Buffer.from(actualHash), Buffer.from(providedHash))) {
        throw new Error("BACKUP_INTEGRITY_FAIL: Hash mismatch. Restore aborted.");
    }

    const key = crypto.createHash("sha256").update(process.env.BACKUP_SECRET).digest();
    const [ivHex, encrypted] = jsonData.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    const data = JSON.parse(decrypted);

    // Helper: commit in chunks of 499
    async function commitInChunks(operations) {
        const CHUNK_SIZE = 499;
        for (let i = 0; i < operations.length; i += CHUNK_SIZE) {
            const chunk = operations.slice(i, i + CHUNK_SIZE);
            const batch = db.batch();
            chunk.forEach(({ ref, doc }) => batch.set(ref, doc));
            await batch.commit();
        }
    }

    await deleteCollectionInBatches(db.collection("votes"), 400);
    await deleteCollectionInBatches(db.collection("voters"), 400);
    await deleteCollectionInBatches(db.collection("candidates"), 400);


    await db.collection("_meta").doc("chain_head").delete();

    const voterOps = (data.voters || []).map(v => {
        const docId = v._docId;                      // ← store _docId in backup
        if (!docId) throw new Error("Voter backup is missing document ID. Restore aborted.");
        return { ref: db.collection("voters").doc(docId), doc: v };
    });


    const candidateOps = (data.candidates || []).map(c => ({
        ref: db.collection("candidates").doc(c.position),
        doc: { options: c.options || [] }
    }));
    const voteOps = (data.votes || []).map(vote => ({
        ref: db.collection("votes").doc(),
        doc: vote
    }));

    await commitInChunks(voterOps);
    await commitInChunks(candidateOps);
    await commitInChunks(voteOps);

    return {
        voters: data.voters?.length || 0,
        votes: data.votes?.length || 0,
        candidates: data.candidates?.length || 0
    };
}

app.get('/api/firebase-config', (req, res) => {
    res.json({
        databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}-default-rtdb.asia-southeast1.firebasedatabase.app`,
        projectId: process.env.FIREBASE_PROJECT_ID
    });
});

// ============================================
// COMPREHENSIVE ALERT SYSTEM
// ============================================

const ALERT_TYPES = {
    // System-level alerts
    HIGH_LOAD: { type: 'high_load', level: 'major', autoExpire: 5 * 60 * 1000 },
    BACKUP_CREATED: { type: 'backup', level: 'minor', autoExpire: 24 * 60 * 60 * 1000 },

    // Candidate-related alerts
    CANDIDATE_SYNC_NEEDED: { type: 'candidate_sync', level: 'minor', autoExpire: null },

    // Security alerts
    TAMPER_DETECTED: { type: 'tamper', level: 'critical', autoExpire: null },

    // Data integrity alerts
    VOTE_INTEGRITY: { type: 'vote_integrity', level: 'critical', autoExpire: null },

    // API/Backend errors
    DATABASE_ERROR: { type: 'database_error', level: 'critical', autoExpire: null },
    FIREBASE_ERROR: { type: 'firebase_error', level: 'critical', autoExpire: null },
    ELECTION_DATA_DELETED: { type: 'election_deleted', level: 'major', autoExpire: null },

    // Election status alerts
    SESSION_TIMEOUT: { type: 'session_timeout', level: 'minor', autoExpire: null }
};

// Fix instructions for each alert type
const ALERT_FIX_INSTRUCTIONS = {
    candidate_sync: {
        fixSteps: [
            "Navigate to Settings tab",
            "Click 'Publish Candidates' button",
            "Verify candidates appear on voting page"
        ],
        developerFix: false,
        contactMessage: null
    },
    candidate_publish_failed: {
        fixSteps: [
            "Check internet connection",
            "Try publishing again",
            "Check server logs for errors"
        ],
        developerFix: false,
        contactMessage: null
    },
    tamper: {
        fixSteps: [
            "DO NOT proceed with election",
            "Document the issue",
            "Contact developer immediately"
        ],
        developerFix: true,
        contactMessage: "CRITICAL SECURITY ALERT: Potential vote tampering detected. STOP all election activities and contact developer IMMEDIATELY."
    },
    vote_integrity: {
        fixSteps: [
            "STOP election immediately",
            "Run 'Re-Tally Votes'",
            "Contact developer if issue persists"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Vote integrity check failed. There might be some issues on votes, follow the instructions and contact developer if the issue still persist."
    },
    database_error: {
        fixSteps: [
            "Check Firebase connection",
            "Verify database permissions",
            "Restart server if needed"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Database connection failed. Contact developer immediately."
    },
    firebase_error: {
        fixSteps: [
            "Check Firebase console for outages",
            "Verify service account credentials",
            "Check Firebase project status"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Firebase service error. Contact developer immediately."
    },
    high_load: {
        fixSteps: [
            "Monitor active users in real-time",
            "If users exceed 300, prepare queue system",
            "Activate Queue System to control traffic"
        ],
        developerFix: false,
        contactMessage: null,
        action: "activate_queue"
    },
    backup: {
        fixSteps: [
            "Verify backup was created successfully",
            "Check backup archive link",
            "No action needed - informational only"
        ],
        developerFix: false,
        contactMessage: null
    },
    election_paused: {
        fixSteps: [
            "Toggle election status to LIVE when ready",
            "Verify voters can access the system"
        ],
        developerFix: false,
        contactMessage: null
    },
    session_timeout: {
        fixSteps: [
            "Login again to continue",
            "Check session timer settings"
        ],
        developerFix: false,
        contactMessage: null
    },
    election_deleted: {
        fixSteps: [
            "Access the backup archive using the provided link",
            "Navigate to System Log panel",
            "Enter restore command: /restore {archive_link}"
        ],
        developerFix: false,
        contactMessage: null
    }
};

class AlertManager {
    constructor() {
        this.activeAlerts = new Map();
        this.alertLogs = [];
        this.maxLogEntries = 100;
        this.activeTypes = new Set();
        this.lastCandidateCheck = 0;
    }

    async createAlert(type, level, title, message, meta = {}, expiresInMs = null) {
        if (!this.lastAlertTime) this.lastAlertTime = {};

        const now = Date.now();
        if (this.lastAlertTime[type] && now - this.lastAlertTime[type] < 10000) {
            return null;
        }
        this.lastAlertTime[type] = now;
        try {
            // Check if similar alert already exists (prevent duplicates)
            const alertRef = db.collection("system_alerts").doc(type);
            if (this.activeTypes.has(type)) {
                return null;
            }

            const alertData = {
                type,
                level,
                title,
                message,
                meta: meta || {},
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                active: true,
                dismissed: false,
                dismissedAt: null,
                dismissedBy: null,
                occurrenceCount: 1,
                acknowledged: false,
                fixInstructions: ALERT_FIX_INSTRUCTIONS[type] || null
            };

            if (expiresInMs) {
                alertData.expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + expiresInMs);
            }

            await alertRef.set(alertData);
            this.activeTypes.add(type);
            const docRef = alertRef;

            // Cache the alert
            this.activeAlerts.set(docRef.id, { ...alertData, id: docRef.id });

            console.log(`[ALERT] Created: ${type} - ${title}`);
            return docRef.id;
        } catch (e) {
            console.error("[ALERT ERROR] Failed to create alert:", e);
            return null;
        }
    }

    async detectSystemHealth() {
        let critical = 0;
        let warnings = 0;

        const indicators = {
            database: true,
            auth: true,
            voteChain: true,
            antiMultipleVote: true,
            tamperDetection: true,
            replayProtection: true,
            backups: true,
            anomalyDetection: true,
            tallyVerification: true,
            voteConsistency: true
        };

        try {
            // 🔍 1. DATABASE LATENCY CHECK
            const start = Date.now();
            await db.collection("settings").doc("config").get();
            const latency = Date.now() - start;

            if (latency > 1000) {
                warnings++;
                indicators.database = false;

                await this.createAlert(
                    'api_error',
                    'major',
                    'Slow Database Response',
                    `Database response time is ${latency}ms.`,
                    { latency },
                    10 * 60 * 1000
                );
            } else {
                await this.clearResolvedAlerts('api_error');
            }

            // 🔍 2. DATABASE READ TEST
            const testSnap = await db.collection("candidates").limit(1).get();
            if (testSnap.empty) {
                critical++;
                indicators.database = false;

                await this.createAlert(
                    'database_error',
                    'critical',
                    'Database Read Failure',
                    'Candidates collection is empty or inaccessible.',
                    {},
                    null
                );
            }

            // 🔍 3. ENV CHECK
            const requiredEnv = [
                'FIREBASE_PROJECT_ID',
                'FIREBASE_CLIENT_EMAIL',
                'FIREBASE_PRIVATE_KEY',
                'JWT_SECRET',
                'ADMIN_KEY'
            ];

            const missingEnv = requiredEnv.filter(key => !process.env[key]);

            if (missingEnv.length > 0) {
                critical++;
                indicators.auth = false;

                await this.createAlert(
                    'env_error',
                    'critical',
                    'Environment Configuration Error',
                    `Missing: ${missingEnv.join(', ')}`,
                    { missingEnv },
                    null
                );
            } else {
                await this.clearResolvedAlerts('env_error');
            }

            // 🔍 4. HASH CHAIN CHECK (IMPORTANT FOR PAGE 7)
            let hashStatus = "verified";
            let anomalies = 0;

            try {
                const chainDoc = await db.collection("_meta").doc("chain_head").get();

                if (!chainDoc.exists) {
                    hashStatus = "not verified";
                    anomalies++;
                    warnings++;
                    indicators.voteChain = false;
                }
            } catch (e) {
                hashStatus = "error";
                anomalies++;
                critical++;
                indicators.voteChain = false;
            }

            // 🔍 5. FINAL STATUS DECISION
            let overallStatus = "ACTIVE";
            if (critical > 0) overallStatus = "CRITICAL";
            else if (warnings > 0) overallStatus = "WARNING";

            return {
                success: true,

                // 🔥 REQUIRED FOR PDF PAGE 7
                status: overallStatus,
                trust:
                    critical > 0 ? "cannot" :
                        warnings > 0 ? "can be" : "can",

                hashStatus,
                anomalies,

                // counts
                critical,
                warnings,

                // 🔥 REQUIRED FOR LIVE UI
                indicators,

                // timestamps
                lastCheckScan: new Date().toLocaleString()
            };

        } catch (e) {
            await this.createAlert(
                'firebase_error',
                'critical',
                'Firebase Connection Failed',
                `Unable to connect: ${e.message}`,
                { error: e.message },
                null
            );

            return {
                success: false,
                status: "CRITICAL",
                trust: "cannot",
                error: e.message,
                critical: 1,
                warnings: 0,
                indicators: {},
                lastCheckScan: new Date().toLocaleString()
            };
        }
    }

    async dismissAlert(alertId, adminId = 'system') {
        try {
            const alertRef = db.collection("system_alerts").doc(alertId);
            const alertDoc = await alertRef.get();

            if (!alertDoc.exists) {
                return { success: false, error: 'Alert not found' };
            }

            const alertData = alertDoc.data();

            // Move to alert logs
            const logEntry = {
                ...alertData,
                originalAlertId: alertId,
                dismissedAt: admin.firestore.FieldValue.serverTimestamp(),
                dismissedBy: adminId,
                loggedAt: admin.firestore.FieldValue.serverTimestamp()
            };

            await db.collection("alert_logs").add(logEntry);

            // Mark as dismissed (but keep for tracking)
            await alertRef.update({
                active: false,
                dismissed: true,
                dismissedAt: admin.firestore.FieldValue.serverTimestamp(),
                dismissedBy: adminId
            });

            // Remove from cache
            this.activeAlerts.delete(alertId);

            console.log(`[ALERT] Dismissed: ${alertId} by ${adminId}`);
            this.activeTypes.delete(alertData.type);
            return { success: true };
        } catch (e) {
            console.error("[ALERT ERROR] Failed to dismiss alert:", e);
            return { success: false, error: e.message };
        }
    }

    async acknowledgeAlert(alertId) {
        try {
            await db.collection("system_alerts").doc(alertId).update({
                acknowledged: true,
                acknowledgedAt: admin.firestore.FieldValue.serverTimestamp()
            });
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    async clearResolvedAlerts(type) {
        // Clear alerts of a specific type when the issue is resolved
        try {
            const snapshot = await db.collection("system_alerts")
                .where("type", "==", type)
                .where("active", "==", true)
                .get();

            const batch = db.batch();
            snapshot.docs.forEach(doc => {
                batch.update(doc.ref, {
                    active: false,
                    resolved: true,
                    resolvedAt: admin.firestore.FieldValue.serverTimestamp(),
                    resolutionType: 'auto'
                });
            });

            if (snapshot.size > 0) {
                await batch.commit();
                this.activeTypes.delete(type);
                console.log(`[ALERT] Cleared ${snapshot.size} resolved alerts of type: ${type}`);
            }

            return { success: true, cleared: snapshot.size };
        } catch (e) {
            console.error("[ALERT ERROR] Failed to clear resolved alerts:", e);
            return { success: false, error: e.message };
        }
    }

    async getActiveAlerts() {
        try {
            const now = admin.firestore.Timestamp.now();
            const snapshot = await db.collection("system_alerts")
                .where("active", "==", true)
                .orderBy("createdAt", "desc")
                .get();

            const alerts = [];
            if (alerts.length > 20) {
                return alerts.slice(0, 20);
            }
            snapshot.forEach(doc => {
                const data = doc.data();
                alerts.push({ id: doc.id, ...data });
            });

            const priority = {
                critical: 4,
                major: 3,
                minor: 2,
                normal: 1
            };

            alerts.sort((a, b) => {
                if (priority[b.level] !== priority[a.level]) {
                    return priority[b.level] - priority[a.level];
                }
                return (b.createdAt?.toMillis?.() || 0) - (a.createdAt?.toMillis?.() || 0);
            });

            return alerts;
        } catch (e) {
            console.error("[ALERT ERROR] Failed to get active alerts:", e);
            return [];
        }
    }

    async getAlertLogs(limit = 50) {
        try {
            const snapshot = await db.collection("alert_logs")
                .orderBy("loggedAt", "desc")
                .limit(limit)
                .get();

            return snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        } catch (e) {
            console.error("[ALERT ERROR] Failed to get alert logs:", e);
            return [];
        }
    }

    async expireAlert(alertId) {
        try {
            await db.collection("system_alerts").doc(alertId).update({
                active: false,
                expired: true,
                expiredAt: admin.firestore.FieldValue.serverTimestamp()
            });
            this.activeAlerts.delete(alertId);
        } catch (e) {
            console.error("[ALERT ERROR] Failed to expire alert:", e);
        }
    }

    // Comprehensive error detection methods
    async detectCandidatesStatus() {
        if (this.lastCandidateCheck && Date.now() - this.lastCandidateCheck < 60000) {
            return;
        }
        this.lastCandidateCheck = Date.now();
        try {
            const candidatesSnap = await db.collection("candidates").get();
            let totalCandidates = 0;
            candidatesSnap.forEach(doc => {
                const opts = doc.data().options || [];
                totalCandidates += opts.length;
            });

            // Check if candidates need publishing
            const staticDoc = await db.collection("app_config").doc("candidates_static").get();
            if (staticDoc.exists) {
                const staticData = staticDoc.data();
                const lastUpdated = staticData.lastUpdated;

                // Check if source candidates were updated after last publish
                let sourceUpdated = false;

                candidatesSnap.forEach(doc => {
                    const rawOptions = doc.data().options;
                    const opts = Array.isArray(rawOptions) ? rawOptions : [];

                    opts.forEach(c => {
                        if (!lastUpdated) {
                            sourceUpdated = true;
                            return;
                        }

                        if (c.addedAt) {
                            const addedTime = c.addedAt.toMillis
                                ? c.addedAt.toMillis()
                                : new Date(c.addedAt).getTime();

                            const publishTime = lastUpdated.toMillis
                                ? lastUpdated.toMillis()
                                : new Date(lastUpdated).getTime();

                            if (addedTime > publishTime) {
                                sourceUpdated = true;
                            }
                        } else {
                            sourceUpdated = true;
                        }
                    });
                });

                if (sourceUpdated) {
                    const existing = await db.collection("system_alerts").doc("candidate_sync").get();

                    if (!existing.exists || !existing.data().active) {
                        await this.createAlert(
                            'candidate_sync',
                            'minor',
                            'Candidates Update Needed',
                            'New candidates have been added but not yet published to the voting system.',
                            {},
                            null
                        );
                    }
                } else {
                    // Clear the sync needed alert if candidates are now synced
                    await this.clearResolvedAlerts('candidate_sync');
                }
            }

            console.log("Running candidate detection...");

            return { success: true, totalCandidates };
        } catch (e) {
            console.error("[ALERT] Candidate detection error:", e);
            await this.createAlert(
                'database_error',
                'critical',
                'Database Error',
                `Failed to check candidates status: ${e.message}`,
                { error: e.message },
                null
            );
            return { success: false, error: e.message };
        }
    }

    async detectVoteIntegrity() {
        try {
            // ✅ Cooldown (prevent spam execution)
            if (this.lastIntegrityCheck && Date.now() - this.lastIntegrityCheck < 90000) {
                return { skipped: true, reason: "Cooldown active" };
            }
            this.lastIntegrityCheck = Date.now();

            // ✅ Fetch votes ONCE (reuse everywhere)
            const votesSnap = await db.collection("votes")
                .orderBy("createdAt", "asc")
                .get();

            // 🔴 No votes check
            if (votesSnap.empty) {
                await this.createAlert(
                    'vote_integrity',
                    'major',
                    'No Votes Found',
                    'No votes recorded in the system.',
                    {},
                    null
                );
            }

            // ✅ Reuse snapshot (NO second read)
            const chainInfo = await verifyHashChain(votesSnap);

            if (!chainInfo.valid) {
                await this.createAlert(
                    'vote_integrity',
                    'critical',
                    'Vote Integrity Compromised',
                    `Hash chain verification failed. ${chainInfo.invalidCount} invalid vote(s) detected.`,
                    chainInfo,
                    null
                );
            } else {
                await this.clearResolvedAlerts('vote_integrity');
            }

            // =========================================
            // ✅ COUNT() instead of full voters scan
            // =========================================
            const [voteCountSnap, voterCountSnap] = await Promise.all([
                db.collection("votes").count().get(),
                db.collection("voters").where("hasVoted", "==", true).count().get()
            ]);

            const totalVotes = voteCountSnap.data().count;
            const totalVoters = voterCountSnap.data().count;

            // =========================================
            // ⚠️ Orphan check (still needs receipts)
            // =========================================
            // NOTE: This is the ONLY remaining heavy read (can be optimized later)
            const votersSnap = await db.collection("voters")
                .where("hasVoted", "==", true)
                .get();

            const validReceipts = new Set();
            votersSnap.forEach(doc => {
                const v = doc.data();
                if (v.receipt) validReceipts.add(v.receipt);
            });

            let orphanedCount = 0;

            for (const doc of votesSnap.docs) {
                const vote = doc.data();

                if (!vote.receipt || !validReceipts.has(vote.receipt)) {
                    orphanedCount++;
                }
            }

            // =========================================
            // ✅ Count-based mismatch check (CHEAP)
            // =========================================
            if (totalVotes > totalVoters) {
                await this.createAlert(
                    'vote_integrity',
                    'critical',
                    'Vote Count Mismatch',
                    'Votes exceed number of voters. Consider re-tallying the election results.',
                    {
                        votes: totalVotes,
                        voters: totalVoters
                    },
                    null
                );
            } else {
                await this.clearResolvedAlerts('vote_integrity');
            }

            console.log("Integrity check completed");

            return {
                success: true,
                chainValid: chainInfo.valid,
                orphanedCount,
                totalVotes,
                totalVoters
            };

        } catch (e) {
            console.error("[ALERT] Vote integrity detection error:", e);
            return { success: false, error: e.message };
        }
    }
}

const alertManager = new AlertManager();

// Legacy function for backward compatibility
async function createAlert(type, level, title, message, meta = {}, expiresInMs = null) {
    return alertManager.createAlert(type, level, title, message, meta, expiresInMs);
}

async function getActiveSessionCount() {
    const snap = await rtdb.ref("activeSessions").once("value");
    return snap.numChildren();
}

let lastLoadState = null;

setInterval(async () => {
    try {
        const count = await getActiveSessionCount();

        let currentState = "normal";

        if (count >= 800) {
            currentState = "degraded";

            await rtdb.ref("system/queueEnabled").set(true);

            if (lastLoadState !== currentState) {
                await alertManager.createAlert(
                    "high_load",
                    "critical",
                    "Degraded performance",
                    `The system has exceeded the defined threshold of ${count} concurrent active sessions, resulting in degraded application performance. To ensure stability and recover latency, the automated request queue system has been enabled. System traffic is being managed to return to operational parameters. No immediate action required; monitoring.`,
                    { count }
                );
            }

        } else if (count >= 500) {
            currentState = "critical";

            if (lastLoadState !== currentState) {
                await alertManager.createAlert(
                    "high_load",
                    "critical",
                    "Critical Load",
                    `Active sessions have reached critically ${count} users. Current load levels may lead to degraded latency and performance.`,
                    { count }
                );
            }

        } else if (count >= 300) {
            currentState = "high";

            if (lastLoadState !== currentState) {
                await alertManager.createAlert(
                    "high_load",
                    "major",
                    "High Load",
                    `Active sessions have reached ${count}. Current load levels may lead to degraded latency and performance.`,
                    { count }
                );
            }

        } else {
            currentState = "normal";

            await rtdb.ref("system/queueEnabled").set(false);

            if (lastLoadState !== currentState) {
                await alertManager.clearResolvedAlerts("high_load");
            }
        }

        lastLoadState = currentState;

    } catch (e) {
        console.error("Active session monitor error:", e);
    }
}, 15000);

// Initial system health check
setTimeout(async () => {
    await alertManager.detectSystemHealth();
}, 5000);

// --- SECURITY: JWT SECRET ---
const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
    throw new Error("JWT_SECRET environment variable is required");
}

// --- SECURITY: ADMIN KEY ---
const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY) {
    throw new Error("ADMIN_KEY environment variable is required");
}

// --- SECURITY: NONCE GENERATOR FOR CSP ---
function generateNonce() {
    const raw = crypto.randomBytes(16).toString('base64');
    const window = Math.floor(Date.now() / (5 * 60 * 1000));
    const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'fallback')
        .update(`${raw}:${window}`)
        .digest('base64url');
    return `${raw}.${sig}`;
}

function verifyNonce(nonce) {
    if (!nonce || !nonce.includes('.')) return false;
    const [raw, sig] = nonce.split('.');
    const now = Math.floor(Date.now() / (5 * 60 * 1000));
    for (const w of [now, now - 1]) {
        const expected = crypto.createHmac('sha256', process.env.JWT_SECRET || 'fallback')
            .update(`${raw}:${w}`)
            .digest('base64url');
        try {
            if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return true;
        } catch { }
    }
    return false;
}

// --- SECURITY: ENHANCED INPUT SANITIZATION ---
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitizeHtml(input) {
    if (typeof input !== 'string') return '';
    return DOMPurify.sanitize(input, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true
    });
}

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    let cleaned = sanitizeHtml(input);
    cleaned = cleaned
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .replace(/data:/gi, '')
        .replace(/vbscript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .replace(/&#x0*[0-9a-f]+;/gi, '')
        .replace(/&#0*[0-9]+;/g, '')
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
        .trim();
    return cleaned;
}

function sanitizeObjectEnhanced(obj) {
    if (typeof obj === 'string') return sanitizeInput(obj);
    if (Array.isArray(obj)) return obj.map(sanitizeObjectEnhanced);
    if (obj && typeof obj === 'object') {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            const safeKey = sanitizeInput(key).replace(/__proto__|constructor|prototype/g, '');
            sanitized[safeKey] = sanitizeObjectEnhanced(value);
        }
        return sanitized;
    }
    return obj;
}

// --- SECURITY: PER-USER (LVN) BRUTE FORCE PROTECTION ---
const USER_LOCK_ATTEMPTS = 5;
const USER_LOCK_DURATION_MS = 30 * 60 * 1000;

// --- SECURITY: HASH FUNCTION FOR LVN ENCRYPTION ---
const LVN_SECRET = process.env.LVN_SECRET;
if (!LVN_SECRET) throw new Error("LVN_SECRET environment variable is required");

function hashLVN(lvn) {
    return crypto.createHmac("sha256", LVN_SECRET)
        .update(String(lvn).trim().toUpperCase())
        .digest("hex");
}

// --- GRADE-LEVEL REP VOTING RULE ---
function getAllowedRepPositionForGrade(grade) {
    const g = parseInt(String(grade), 10);
    if (!Number.isFinite(g)) return null;
    if (g >= 7 && g <= 11) return `rep${g + 1}`;
    return null;
}

function buildAllowedPositionsForGrade(grade) {
    const allowedRep = getAllowedRepPositionForGrade(grade);
    return { allowedRep, isAllowed: (pos) => (!MULTI_POSITIONS.includes(pos) || (allowedRep && pos === allowedRep)) };
}

// --- SECURITY: MOBILE DEVICE ENFORCEMENT ---
function isMobileDevice(req) {
    const userAgent = req.headers['user-agent'] || '';
    const mobileRegex = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|mobile|CriOS/i;
    return mobileRegex.test(userAgent);
}

function requireMobile(req, res, next) {
    const isDev = req.headers['x-dev-mode'] === 'true' && process.env.NODE_ENV === 'development';
    if (isDev) return next();

    if (!isMobileDevice(req)) {
        logSecurityEvent("DESKTOP_ACCESS_BLOCKED", req, { userAgent: req.headers['user-agent'] });
        return res.status(403).json({
            error: "Access Denied: This endpoint is only accessible from mobile devices."
        });
    }
    next();
}

// --- RATE LIMITERS ---
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: "Too many attempts. Please try again later." },
});

const voteLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: "Too many vote attempts. Please try again later." },
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: "Too many admin requests. Please try again later." },
});

const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: "Too many login attempts. Please try again later." },
});

const submitReviewLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Too many submission attempts. Please wait." },
});

const submissionLimiter = rateLimit({
    windowMs: 48 * 60 * 60 * 1000,
    max: 1,
    message: { error: "Limit reached... if you have something to change, please contact an administrator." },
    standardHeaders: true,
    legacyHeaders: false,
});

// --- HELPERS ---
async function deleteCollectionInBatches(collectionRef, batchSize = 500) {
    while (true) {
        const snapshot = await collectionRef.limit(batchSize).get();
        if (snapshot.empty) break;
        const batch = db.batch();
        snapshot.docs.forEach((doc) => batch.delete(doc.ref));
        await batch.commit();
    }
}

const GlobalCache = {
    candidates: {},
    dashboard: {
        isLive: false,
        stats: { total: 0, voted: 0, percentage: 0, grades: {} },
        leaderboard: {},
    },
    timestamps: {
        candidates: "Not yet loaded",
        results: "Not yet loaded",
    },
};

const ALL_POSITIONS = [
    "president", "vp", "secretary", "treasurer", "auditor",
    "pio", "protocol", "rep7", "rep8", "rep9", "rep10", "rep11", "rep12",
];

// --- SECURITY LOGGING ---
async function logSecurityEvent(type, req, meta = {}) {
    try {
        await db.collection("security_logs").add({
            type: type,
            ip: req.ip || "Unknown",
            userAgent: req.headers["user-agent"] || "Unknown",
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            meta: meta && typeof meta === "object" ? meta : { value: meta },
        });
    } catch (e) { }
}


async function checkAbuse(ip) {
    try {
        const logs = await db.collection("security_logs")
            .where("ip", "==", ip)
            .where("timestamp", ">", admin.firestore.Timestamp.fromMillis(Date.now() - 60000))
            .get();

        if (logs.size > 10) {
            await db.collection("security_logs").add({
                type: "POTENTIAL_ABUSE",
                ip: ip,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                eventCount: logs.size
            });
            return true;
        }
        return false;
    } catch (e) {
        return false;
    }
}

async function logAdminAction(req, action, meta = {}) {
    try {
        const u = req.user || {};
        await db.collection("admin_audit").add({
            action: String(action || "UNKNOWN"),
            adminId: u.uid || null,
            adminEmail: u.email || null,
            path: req.originalUrl || null,
            method: req.method || null,
            ip: req.ip || null,
            userAgent: req.headers["user-agent"] || null,
            meta: meta && typeof meta === "object" ? meta : { value: meta },
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
    } catch (e) { }
}


// 1. Log every admin data mutation with before/after state
async function logDataMutation(req, collection, docId, before, after) {
    await db.collection("admin_audit").add({
        action: "DATA_MUTATION",
        collection, docId,
        before: JSON.stringify(before),
        after: JSON.stringify(after),
        adminEmail: req.user?.email,
        ip: req.ip,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

// --- CANDIDATE & RESULTS FUNCTIONS ---
async function getOrGenerateCode(type, key) {
    const registryRef = db.collection("settings").doc("meta_registry");
    return await db.runTransaction(async (t) => {
        const doc = await t.get(registryRef);
        let data = doc.exists ? doc.data() : {};
        if (!data.grades) data.grades = {};
        if (!data.sections) data.sections = {};
        let returnValue;
        if (type === 'grade_prefix') {
            if (data.grades[key]) {
                returnValue = data.grades[key];
            } else {
                returnValue = Math.floor(100 + Math.random() * 900).toString();
                t.set(registryRef, { grades: { [key]: returnValue } }, { merge: true });
            }
        }
        else if (type === 'section_data') {
            if (data.sections[key]) {
                returnValue = data.sections[key];
            } else {
                const secPrefix = Math.floor(100 + Math.random() * 900).toString();
                const sectionName = key.split('_')[1] || "A";
                const letter = sectionName.charAt(0).toUpperCase();
                const nums = Math.floor(10000 + Math.random() * 90000);
                const accessCode = `${letter}-${nums}`;
                returnValue = { prefix: secPrefix, access_code: accessCode };
                t.set(registryRef, { sections: { [key]: returnValue } }, { merge: true });
            }
        }
        return returnValue;
    });
}

async function fetchRawCandidatesFromSource() {
    try {
        const data = {};
        const refs = ALL_POSITIONS.map((pos) => db.collection("candidates").doc(pos));
        const snapshots = await db.getAll(...refs);
        snapshots.forEach((snap, index) => {
            data[ALL_POSITIONS[index]] = snap.exists ? (snap.data().options || []) : [];
        });
        return data;
    } catch (err) {
        return null;
    }
}

async function refreshLocalCandidates() {
    try {
        const docRef = db.collection("app_config").doc("candidates_static");
        const doc = await docRef.get();

        if (!doc.exists) {
            GlobalCache.candidates = Object.freeze({});
            GlobalCache.candidateHashMap = Object.freeze({});
            return false;
        }

        const data = doc.data();
        const newCandidates = data.payload || {};

        // ✅ Build hash map (FAST lookup)
        const candidateHashMap = {};

        for (const [position, options] of Object.entries(newCandidates)) {
            candidateHashMap[position] = {};

            for (const c of options) {
                if (c?.id) {
                    const hash = hashCandidateId(c.id);

                    // ⚠️ Safety: detect accidental hash collisions
                    if (candidateHashMap[position][hash]) {
                        console.warn(`Hash collision detected at ${position}`, c.id);
                    }

                    candidateHashMap[position][hash] = c.id;
                }
            }
        }

        // ✅ Replace cache atomically
        GlobalCache.candidates = Object.freeze({ ...newCandidates });
        GlobalCache.candidateHashMap = Object.freeze(candidateHashMap);

        // ✅ Timestamp handling (keep yours)
        const ts = data.lastUpdated;
        GlobalCache.timestamps.candidates = ts && ts.toDate
            ? ts.toDate().toISOString()
            : (ts || new Date().toISOString());

        return true;

    } catch (err) {
        console.error("Candidate refresh failed:", err);
        return false;
    }
}

async function refreshLocalResults() {
    try {
        if (Object.keys(GlobalCache.candidates).length === 0) await refreshLocalCandidates();
        const settingsSnap = await db.collection("settings").doc("electionStatus").get();
        const isLive = settingsSnap.exists ? !!settingsSnap.data().isLive : false;
        const votersSnap = await db.collection("voters").get();
        const stats = { total: 0, voted: 0, percentage: 0, grades: {} };
        votersSnap.forEach((doc) => {
            const v = doc.data() || {};
            const grade = String(v.grade || "Unknown");
            if (!stats.grades[grade]) stats.grades[grade] = { total: 0, voted: 0, missed: 0 };
            stats.total += 1;
            stats.grades[grade].total += 1;
            if (v.isMissed) {
                stats.grades[grade].missed += 1;
            }
            if (v.hasVoted) {
                stats.voted += 1;
                stats.grades[grade].voted += 1;
            }
        });
        if (stats.total > 0) stats.percentage = ((stats.voted / stats.total) * 100).toFixed(1);
        const votesSnap = await db.collection("votes").get();
        const tallies = {};
        for (const pos of Object.keys(GlobalCache.candidates)) {
            tallies[pos] = {};
            for (const c of (GlobalCache.candidates[pos] || [])) {
                tallies[pos][String(c.id)] = { votes: 0, breakdown: {} };
            }
        }
        votesSnap.forEach((doc) => {
            const v = doc.data() || {};
            const grade = String(v.grade || "Unknown");
            const selections = v.selections || {};
            for (const pos of Object.keys(tallies)) {
                const rawSel = selections[pos];
                if (!rawSel) continue;
                const selectedIds = Array.isArray(rawSel) ? rawSel : [rawSel];
                for (const cid of selectedIds) {
                    const cidStr = String(cid);
                    if (!tallies[pos][cidStr]) {
                        tallies[pos][cidStr] = { votes: 0, breakdown: {} };
                    }
                    tallies[pos][cidStr].votes += 1;
                    const key = `votes_${grade}`;
                    tallies[pos][cidStr].breakdown[key] = (tallies[pos][cidStr].breakdown[key] || 0) + 1;
                }
            }
        });
        const finalResults = {};
        for (const pos of Object.keys(GlobalCache.candidates)) {
            const list = [];
            for (const c of (GlobalCache.candidates[pos] || [])) {
                const cidStr = String(c.id);
                const t = tallies[pos][cidStr] || { votes: 0, breakdown: {} };
                list.push({
                    name: c.name,
                    party: c.party,
                    hash: c.hash,
                    votes: t.votes,
                    breakdown: t.breakdown
                });
            }
            list.sort((a, b) => (b.votes || 0) - (a.votes || 0));
            finalResults[pos] = list;
        }
        GlobalCache.dashboard = { isLive, stats, leaderboard: finalResults };
        GlobalCache.timestamps.results = new Date().toISOString();
        return true;
    } catch (err) {
        return false;
    }
}



function generateSubmitToken(jti) {
    if (!jti) throw new Error("jti required for submit token");
    const window = Math.floor(Date.now() / (10 * 60 * 1000));
    return crypto.createHmac("sha256", SECRET).update(`${jti}:${window}`).digest("hex");
}

app.get("/voter/submit-token", requireAuth, requireRole("voter"), (req, res) => {
    res.json({ submitToken: generateSubmitToken(req.user.jti) });
});

function verifySubmitToken(token, jti) {
    if (!token || !jti) return false;
    const now = Math.floor(Date.now() / (10 * 60 * 1000));
    // Check current window and previous (handles clock edge cases)
    for (const w of [now, now - 1]) {
        const expected = crypto.createHmac("sha256", SECRET)
            .update(`${jti}:${w}`)
            .digest("hex");
        try {
            if (Buffer.from(token).length === Buffer.from(expected).length &&
                crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) {
                return true;
            }
        } catch { }
    }
    return false;
}

// --- AUTH MIDDLEWARE ---
function verifyCSRF(req, res, next) {
    const csrfHeader = req.headers["x-csrf-token"];
    if (!csrfHeader || !req.user?.csrfToken) return res.status(403).json({ error: "Missing CSRF token" });

    try {
        const a = Buffer.from(csrfHeader);
        const b = Buffer.from(req.user.csrfToken);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            return res.status(403).json({ error: "Invalid CSRF token" });
        }
    } catch {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    next();
}

async function revokeJti(jti) {
    if (!jti) return;
    await db.collection("revoked_jtis").doc(jti).set({
        revokedAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

async function isJtiRevoked(jti) {
    if (!jti) return false;
    const doc = await db.collection("revoked_jtis").doc(jti).get();
    return doc.exists;
}

// Make requireAuth async and use await properly:
async function requireAuth(req, res, next) {
    try {
        let token = req.cookies.__session;
        if (!token && req.headers.authorization?.startsWith("Bearer "))
            token = req.headers.authorization.split(" ")[1];
        if (!token) return res.status(401).end();

        const decoded = jwt.verify(token, SECRET);
        if (!decoded.jti) {
            return res.status(401).json({ error: "Invalid token structure." });
        }
        const revoked = await isJtiRevoked(decoded.jti);
        if (revoked) return res.status(401).json({ error: "Session revoked." });

        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).end();
    }
}

function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            logSecurityEvent("UNAUTHORIZED_ACCESS", req, { requiredRole: role, userRole: req.user?.role });
            return res.status(403).json({ error: "Forbidden" });
        }
        next();
    };
}

function requireRoles(roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            logSecurityEvent("UNAUTHORIZED_ACCESS", req, { requiredRoles: roles, userRole: req.user?.role });
            return res.status(403).json({ error: "Forbidden: Insufficient privileges" });
        }
        next();
    };
}

/**
 * @deprecated NOT used on any route. Do NOT add to any endpoint.
 * Use requireAuth (async, checks JTI revocation list) for all authenticated routes.
 * This function is kept only to avoid a reference error if old admin scripts call it,
 * and will throw immediately in production to surface accidental use.
 */
const verifySecureSession = (req, res, next) => {
    if (process.env.NODE_ENV === 'production') {
        console.error('[SECURITY] verifySecureSession called in production — use requireAuth instead');
        return res.status(500).json({ error: "Internal configuration error." });
    }
    let token = req.cookies['__session'];
    if (!token && req.headers.authorization?.startsWith("Bearer ")) {
        token = req.headers.authorization.split(" ")[1];
    }
    if (!token) {
        logSecurityEvent("INVALID_TOKEN", req, { reason: "Missing token" });
        return res.status(401).json({ error: "Access Denied. No secure session. (Missing __session cookie or Bearer token)" });
    }
    jwt.verify(token, SECRET, (err, user) => {
        if (err) {
            logSecurityEvent("INVALID_TOKEN", req, { reason: err.message });
            return res.status(403).json({ error: "Your session is invalid or expired. Please log in again." });
        }
        req.user = user;
        next();
    });
};

async function verifyFirebaseAdmin(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Unauthorized: No token provided" });
    }
    const token = authHeader.split(" ")[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        const allowedAdminEmail = process.env.ADMIN_EMAIL;
        if (!allowedAdminEmail) throw new Error("ADMIN_EMAIL environment variable is required");
        if (decodedToken.email !== allowedAdminEmail) {
            logSecurityEvent("UNAUTHORIZED_ADMIN", req, { email: decodedToken.email });
            return res.status(403).json({ error: "Unauthorized: Email not recognized as admin" });
        }
        decodedToken.role = "admin";
        req.user = decodedToken;
        next();
    } catch (error) {
        logSecurityEvent("INVALID_ADMIN_TOKEN", req, { error: error.message });
        return res.status(403).json({ error: "Unauthorized: Invalid Token" });
    }
}

function requireAdminKey(req, res, next) {
    const adminKey = req.headers["x-admin-key"];
    if (!adminKey || adminKey !== ADMIN_KEY) {
        logSecurityEvent("ADMIN_KEY_FAILED", req, { hasKey: !!adminKey, path: req.originalUrl });
        return res.status(403).json({ error: "Forbidden: Invalid admin key" });
    }
    next();
}

// --- PURGE FUNCTION ---
async function purgeElectionData() {
    const votersRef = db.collection("voters");
    const votesRef = db.collection("votes");
    const resultsRef = db.collection("results");
    const securityLogsRef = db.collection("security_logs");
    await deleteCollectionInBatches(votersRef);
    await deleteCollectionInBatches(votesRef);
    await deleteCollectionInBatches(resultsRef);
    await deleteCollectionInBatches(securityLogsRef);
}

// --- CACHE INIT MIDDLEWARE ---
app.use(async (req, res, next) => {
    if (Object.keys(GlobalCache.candidates).length === 0) {
        await refreshLocalCandidates();
        await refreshLocalResults();
    }
    next();
});

// --- ROUTES ---

// -- VERIFY CLOUDFLARE
async function verifyCaptcha(token) {
    const res = await axios.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        new URLSearchParams({
            secret: process.env.TURNSTILE_SECRET,
            response: token
        })
    );
    return res.data.success;
}

// -- ALERTS

app.get("/admin/alerts", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const alerts = await alertManager.getActiveAlerts();
        res.json(alerts);
    } catch (e) {
        console.error("[ALERT API] Failed to fetch alerts:", e);
        res.status(500).json({ error: "Failed to fetch alerts" });
    }
});

app.get("/admin/test-alert", requireAuth, requireRole("admin"), async (req, res) => {
    await alertManager.createAlert(
        'api_error',
        'major',
        'Test Alert',
        'If you see this, alerts are working.',
        {},
        null
    );

    res.json({ ok: true });
});

app.post("/admin/alerts/:id/dismiss", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const alertId = req.params.id;
        const adminId = req.user?.uid || req.user?.email || 'unknown';
        const result = await alertManager.dismissAlert(alertId, adminId);
        if (result.success) {
            res.json({ success: true, message: "Alert dismissed and logged" });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (e) {
        console.error("[ALERT API] Failed to dismiss alert:", e);
        res.status(500).json({ error: "Failed to dismiss alert" });
    }
});

app.post("/admin/alerts/:id/acknowledge", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const alertId = req.params.id;
        const result = await alertManager.acknowledgeAlert(alertId);
        if (result.success) {
            res.json({ success: true, message: "Alert acknowledged" });
        } else {
            res.status(400).json({ error: result.error });
        }
    } catch (e) {
        console.error("[ALERT API] Failed to acknowledge alert:", e);
        res.status(500).json({ error: "Failed to acknowledge alert" });
    }
});

app.get("/admin/alerts/logs", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const logs = await alertManager.getAlertLogs(limit);
        res.json(logs);
    } catch (e) {
        console.error("[ALERT API] Failed to fetch alert logs:", e);
        res.status(500).json({ error: "Failed to fetch alert logs" });
    }
});

app.get("/admin/alerts/status", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const activeAlerts = await alertManager.getActiveAlerts();
        const hasCritical = activeAlerts.some(a => a.level === 'critical');
        const hasMajor = activeAlerts.some(a => a.level === 'major');
        const hasUnacknowledged = activeAlerts.some(a => !a.acknowledged);

        res.json({
            totalActive: activeAlerts.length,
            hasCritical,
            hasMajor,
            hasUnacknowledged,
            alertsByLevel: {
                critical: activeAlerts.filter(a => a.level === 'critical').length,
                major: activeAlerts.filter(a => a.level === 'major').length,
                minor: activeAlerts.filter(a => a.level === 'minor').length,
                normal: activeAlerts.filter(a => a.level === 'normal').length
            }
        });
    } catch (e) {
        console.error("[ALERT API] Failed to fetch alert status:", e);
        res.status(500).json({ error: "Failed to fetch alert status" });
    }
});

app.post("/admin/system/status", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const { isLive, isQueue } = req.body;

        // Validate inputs
        if (typeof isLive !== "boolean" && typeof isQueue !== "boolean") {
            return res.status(400).json({ error: "Invalid status values" });
        }

        const updates = {};

        if (typeof isLive === "boolean") updates["status/isLive"] = isLive;
        if (typeof isQueue === "boolean") updates["status/isQueue"] = isQueue;

        await rtdb.ref("/").update(updates);

        await logAdminAction(req, "UPDATE_SYSTEM_STATUS", {
            isLive,
            isQueue
        });

        res.json({
            success: true,
            message: "System status updated",
            updates
        });

    } catch (e) {
        console.error("Update status error:", e);
        res.status(500).json({ error: "Failed to update system status" });
    }
});

async function detectVotingAnomalies(req, voterId) {
    try {
        const recentVotes = await db.collection("votes")
            .where("ip", "==", req.ip)
            .where("createdAt", ">", admin.firestore.Timestamp.fromMillis(Date.now() - 60000))
            .get();

        // 🚨 Too many votes from same IP
        if (recentVotes.size > 10) {
            await createAlert(
                "tamper",
                "major",
                "⚠️ Suspicious Voting Pattern",
                "Multiple votes from same IP in short time. If the voting session was done in school, kindly dismiss this alert.",
                { ip: req.ip, count: recentVotes.size }
            );
        }

        const deviceId = req.headers["user-agent"] || "unknown";
        const deviceVotes = await db.collection("votes")
            .where("device", "==", deviceId)
            .get();

        const uniqueVoters = new Set();
        deviceVotes.forEach(doc => uniqueVoters.add(doc.data().voterId));

        if (uniqueVoters.size > 5) {
            await createAlert(
                "tamper",
                "major",
                "⚠️ Device Abuse Detected",
                "Too many voters using same device",
                { deviceId, voters: uniqueVoters.size }
            );
        }

    } catch (e) {
        console.error("Anomaly detection error:", e);
    }
}

// Client-side error reporting endpoint
app.post("/client-error-report", requireAuth, requireRole("admin"), async (req, res) => {
    res.sendStatus(200);
    try {
        const { type, message, stack, url, line, column, userAgent } = req.body;

        // Determine alert level based on error type
        let level = 'minor';
        let alertType = 'script_error';

        if (type === 'API_ERROR' || message?.includes('fetch') || message?.includes('network')) {
            level = 'major';
            alertType = 'client_api_error';
        } else if (type === 'RENDER_ERROR' || message?.includes('render') || message?.includes('React')) {
            level = 'major';
            alertType = 'render_error';
        }

        await alertManager.createAlert(
            alertType,
            level,
            `Client ${type || 'Error'}`,
            message || 'Unknown client-side error',
            {
                stack: stack?.substring(0, 1000),
                url,
                line,
                column,
                userAgent: userAgent?.substring(0, 500),
                ip: req.ip
            },
            60 * 60 * 1000 // 1 hour expiration
        );

        res.json({ success: true });
    } catch (e) {
        console.error("[CLIENT ERROR REPORT] Failed to process:", e);
        res.status(500).json({ error: "Failed to process error report" });
    }
});

// --- ADMIN AUTH ROUTES ---
app.post("/admin/login", adminLoginLimiter, async (req, res) => {
    const username = sanitizeInput(req.body.username || '');
    const password = req.body.password || '';
    const captchaToken = req.body.captchaToken;

    if (!req.headers["user-agent"]) {
        return res.status(403).end();
    }

    if (!captchaToken) {
        return res.status(400).json({
            error: "Complete Captcha Verification First"
        });
    }

    if (!(await verifyCaptcha(captchaToken))) {
        return res.status(403).json({ error: "Captcha verification failed" });
    }

    const isValidUser = username === process.env.ADMIN_USER;
    let isValidPass = false;

    if (isValidUser && process.env.ADMIN_HASH) {
        isValidPass = await bcrypt.compare(password, process.env.ADMIN_HASH);
    }

    // ✅ GATE: reject before any token is issued
    if (!isValidUser || !isValidPass) {
        await logSecurityEvent("ADMIN_LOGIN_FAILED", req, { username });
        // Constant-time delay prevents timing oracle on username enumeration
        await new Promise(r => setTimeout(r, 400));
        return res.status(401).json({ error: "Invalid credentials." });
    }

    const adminJti = crypto.randomBytes(16).toString("hex");
    const token = jwt.sign({
        uid: process.env.ADMIN_USER,
        role: "admin",
        jti: adminJti,
        iat: Math.floor(Date.now() / 1000)
    }, SECRET, { expiresIn: "1h" });

    res.cookie("__session", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/",
        maxAge: 2 * 60 * 60 * 1000
    });

    await logSecurityEvent("ADMIN_LOGIN_SUCCESS", req, { uid: "admin" });

    res.json({ success: true });
});

app.post("/admin/logout", async (req, res) => {
    try {
        if (req.user?.jti) {
            await revokeJti(req.user.jti);
        }

        res.clearCookie("__session", {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            path: "/"
        });

        res.json({ success: true });

    } catch (err) {
        console.error("Logout error:", err);
        res.status(500).json({ error: "Logout failed" });
    }
});

app.get("/admin/verify", requireAuth, requireRole("admin"), (req, res) => {
    res.json({ success: true });
});

// --- PUBLIC ROUTES ---
app.get("/settings", async (req, res) => {
    try {
        // Fetch Firestore config docs and RTDB status in parallel
        const [configDoc, statusDoc, rtdbStatusSnap] = await Promise.all([
            db.collection("settings").doc("config").get(),
            db.collection("settings").doc("electionStatus").get(),
            rtdb.ref("status").once("value")
        ]);

        // ✅ isLive and isQueue come exclusively from RTDB
        const rtdbStatus = rtdbStatusSnap.val() || {};
        const isLive = rtdbStatus.isLive === true;
        const isQueue = rtdbStatus.isQueue === true;

        // All other fields (activeGrade, sessionTimer, endTime, etc.) still come from Firestore
        const statusData = statusDoc.exists ? statusDoc.data() : {};
        const config = configDoc.exists ? configDoc.data() : { voterTimeoutMinutes: 60 };

        // Spread Firestore data first, then override the two status fields with RTDB values
        res.json({ ...config, ...statusData, isLive, isQueue });
    } catch (e) {
        res.status(500).json({ error: "Settings Error" });
    }
});

function normalizeName(name) {
    return String(name)
        .trim()
        .toUpperCase()
        .replace(/\s+/g, " ");
}

app.get("/candidates", async (req, res) => {
    try {
        let candidateMap = GlobalCache.candidates;

        if (!candidateMap || Object.keys(candidateMap).length === 0) {
            const success = await refreshLocalCandidates();
            candidateMap = GlobalCache.candidates;

            if (!success || !candidateMap || Object.keys(candidateMap).length === 0) {
                return res.status(503).json({ error: "Candidate data unavailable" });
            }
        }

        const safeCandidates = Object.entries(candidateMap).map(([position, options]) => ({
            position,
            options: (options || []).map(c => ({
                name: c.name || "",
                party: c.party || "",
                image: c.img || "",
                hash: c.hash || hashCandidateId(c.id) // fallback if not precomputed
            }))
        }));

        res.set("Cache-Control", "no-store");

        return res.json(safeCandidates);

    } catch (err) {
        console.error("Candidates route error:", err);
        return res.status(500).json({ error: "Failed to load candidates" });
    }
});

app.get("/dashboard", (req, res) => {
    try {
        const dashboard = GlobalCache.dashboard;

        if (!dashboard || Object.keys(dashboard).length === 0) {
            return res.status(503).json({
                error: "Dashboard data not ready",
                lastUpdated: GlobalCache.timestamps.results || null
            });
        }

        res.set("Cache-Control", "no-store");

        return res.json({
            ...dashboard,
            lastUpdated: GlobalCache.timestamps.results || null
        });

    } catch (err) {
        console.error("Dashboard route error:", err);
        return res.status(500).json({ error: "Failed to load dashboard" });
    }
});

// --- VERIFIABLE VOTING: PUBLIC BULLETIN BOARD ---
app.get("/public-receipts", async (req, res) => {
    try {
        // Pagination controls (safe limits)
        const limit = Math.min(parseInt(req.query.limit) || 100, 500);
        const cursor = req.query.cursor || null;

        let query = db.collection("votes")
            .orderBy("createdAt", "asc")
            .limit(limit);

        if (cursor) {
            query = query.startAfter(new Date(cursor));
        }

        const votesSnap = await query.get();

        const receipts = [];
        let lastTimestamp = null;

        for (const doc of votesSnap.docs) {
            const data = doc.data();
            const ts = data.createdAt ? data.createdAt.toDate().toISOString() : null;
            if (ts) lastTimestamp = ts;

            // CRITICAL: Never expose raw receipt, only masked version
            const masked = maskReceipt(data.receipt);

            receipts.push({
                receiptMask: masked.mask,
                receiptHash: masked.hash,
                timestamp: ts,
                blockHash: data.hash,
                prevBlockHash: data.prevHash,
                sequence: data.sequence
            });
        }

        // Only verify chain on FIRST page (avoid repeated heavy checks)
        let chainInfo = null;
        if (!cursor) {
            chainInfo = await verifyHashChain(votesSnap);
        }

        res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
        res.set("Pragma", "no-cache");
        res.set("Expires", "0");

        return res.json({
            receipts,
            pageSize: receipts.length,
            nextCursor: lastTimestamp,
            chainValid: chainInfo ? chainInfo.valid : undefined,
            totalVerified: chainInfo ? chainInfo.totalVotes : undefined,
            pageIntegrity: crypto.createHash('sha256')
                .update(JSON.stringify(receipts.map(r => r.blockHash)))
                .digest('hex')
        });

    } catch (e) {
        console.error("Public receipts error:", e);
        return res.status(500).json({
            error: "Failed to retrieve public receipts"
        });
    }
});

app.post("/verify-receipt", rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { error: "Too many verification attempts" }
}), async (req, res) => {
    try {
        // Accept receipt in POST body instead of URL parameter
        const { receipt } = req.body;

        if (!receipt || typeof receipt !== 'string' || receipt.length !== 64) {
            return res.status(400).json({ error: "Invalid receipt format" });
        }

        // Sanitize input
        const sanitizedReceipt = receipt.replace(/[^a-f0-9]/g, '');
        if (sanitizedReceipt.length !== 64) {
            return res.status(400).json({ error: "Invalid receipt characters" });
        }

        const votesSnap = await db.collection("votes")
            .where("receipt", "==", sanitizedReceipt)
            .limit(1)
            .get();

        if (votesSnap.empty) {
            return res.json({
                found: false,
                message: "Receipt not found in public ledger"
            });
        }

        const voteData = votesSnap.docs[0].data();
        const masked = maskReceipt(voteData.receipt);

        // Return verification without exposing raw receipt
        res.json({
            found: true,
            verified: true,
            message: "Vote is recorded and included in the blockchain",
            receiptMask: masked.mask,  // User can confirm first/last chars match their copy
            timestamp: voteData.createdAt ? voteData.createdAt.toDate().toISOString() : null,
            blockHash: voteData.hash,
            prevBlockHash: voteData.prevHash,
            sequence: voteData.sequence,
            // Verification proof (hash of receipt + block hash)
            inclusionProof: crypto.createHash('sha256')
                .update(sanitizedReceipt + voteData.hash)
                .digest('hex')
        });
    } catch (e) {
        console.error("Verify receipt error:", e);
        res.status(500).json({ error: "Verification failed" });
    }
});

// --- VERIFIABLE VOTING: HASH CHAIN VERIFICATION ---
async function verifyHashChain(votesSnapParam = null) {
    try {
        // ✅ Use provided snapshot OR fetch only if needed
        const votesSnap = votesSnapParam || await db.collection("votes")
            .orderBy("createdAt", "asc")
            .get();

        if (!votesSnap || votesSnap.empty) {
            return {
                valid: true,
                message: "No votes to verify",
                totalVotes: 0,
                invalidCount: 0,
                firstInvalidIndex: -1
            };
        }

        let prevHash = "GENESIS";
        let index = 0;
        let invalidCount = 0;
        let firstInvalidIndex = -1;

        // ✅ Iterate directly (no array allocation → better memory)
        for (const doc of votesSnap.docs) {
            const vote = doc.data();

            // 🔐 Check previous hash linkage
            if (vote.prevHash !== prevHash) {
                invalidCount++;
                if (firstInvalidIndex === -1) firstInvalidIndex = index;
            } else {
                // 🔐 Verify current hash only if prevHash is valid
                const expectedHash = crypto.createHash("sha256")
                    .update(vote.receipt + vote.prevHash)
                    .digest("hex");

                if (vote.hash !== expectedHash) {
                    invalidCount++;
                    if (firstInvalidIndex === -1) firstInvalidIndex = index;
                }
            }

            // Move chain forward regardless (so we detect cascading issues)
            prevHash = vote.hash;
            index++;
        }

        return {
            valid: invalidCount === 0,
            totalVotes: index,
            invalidCount,
            firstInvalidIndex,
            message: invalidCount === 0
                ? "Hash chain integrity verified"
                : `Hash chain broken at ${invalidCount} position(s)`
        };

    } catch (e) {
        console.error("Hash chain verification error:", e);
        return {
            valid: false,
            message: "Verification error: " + e.message,
            totalVotes: 0,
            invalidCount: 0,
            firstInvalidIndex: -1
        };
    }
}

async function monitorIntegrity() {
    const result = await verifyHashChain();

    if (!result.valid) {
        await createAlert(
            "tamper",
            "critical",
            "🚨 Tamper Detected",
            "Vote hash chain is broken.",
            result
        );
    }
}
setInterval(monitorIntegrity, 5 * 60 * 1000);

app.get("/admin/verify-chain", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const chainInfo = await verifyHashChain();
        res.json(chainInfo);
    } catch (e) {
        res.status(500).json({ error: "Chain verification failed" });
    }
});

app.post("/verify", loginLimiter, async (req, res) => {
    if (!(await verifyCaptcha(req.body.captchaToken))) {
        return res.status(403).json({ error: "Captcha verification failed" });
    }

    try {
        const lvn = sanitizeInput(req.body.lvn || '');
        const code = sanitizeInput(req.body.code || '');

        if (!lvn || !code) {
            return res.status(400).json({ error: "Missing credentials." });
        }

        const hashedLVN = hashLVN(lvn);

        const ua = (req.headers["user-agent"] || "").replace(/\s+/g, " ").trim().toLowerCase();

        const deviceFingerprint = crypto.createHash("sha256")
            .update(`${ua}|${req.headers['sec-ch-ua'] || ''}`)
            .digest("hex");

        const deviceRef = db.collection("device_tracking").doc(deviceFingerprint);
        const deviceSnap = await deviceRef.get();

        if (deviceSnap.exists) {
            const usedLvns = deviceSnap.data().lvns || [];

            if (!usedLvns.includes(hashedLVN)) {
                if (usedLvns.length >= 10) {
                    return res.status(403).json({
                        error: "Device Limit Reached: Maximum 10 voters allowed per device."
                    });
                }
            }
        }

        // ✅ Fetch Firestore config (activeGrade, endTime, etc.) and RTDB status in parallel
        const [settingsSnap, rtdbStatusSnap] = await Promise.all([
            db.collection("settings").doc("electionStatus").get(),
            rtdb.ref("status").once("value")
        ]);
        const settingsData = settingsSnap.data() || {};

        // ✅ isLive and isQueue are authoritative from RTDB only
        const rtdbStatus = rtdbStatusSnap.val() || {};
        const isLive = rtdbStatus.isLive === true;
        const isQueue = rtdbStatus.isQueue === true;

        const voterRef = db.collection("voters").doc(hashedLVN);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists) {
            return res.status(401).json({ error: "Invalid Credentials." });
        }

        const d = voterSnap.data();
        const inputCode = code.toUpperCase();

        const isCodeValid = await bcrypt.compare(inputCode, d.code);

        if (!isCodeValid) {
            await logSecurityEvent("FAILED_LOGIN", req, { reason: "Invalid code" });
            return res.status(401).json({ error: "Invalid Credentials." });
        }

        if (d.isMissed === true) {
            return res.status(403).json({
                error: "Voting Session Expired: You missed the cutoff time."
            });
        }

        if (d.isTrap === true) {
            await db.collection("security_logs").add({
                event: "HONEYTOKEN_USED",
                ip: req.ip || "Unknown",
                userAgent: req.headers["user-agent"] || "Unknown",
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                method: "LOGIN_ATTEMPT"
            });

            const fakeToken = jwt.sign(
                { uid: hashedLVN, grade: "12", role: "shadow_realm" },
                SECRET,
                { expiresIn: "60m" }
            );

            return res.json({
                name: "JOHN DOE (TEST)",
                grade: "12",
                token: fakeToken,
                csrfToken: ""
            });
        }

        if (!isLive) {
            return res.status(403).json({ error: "Election PAUSED." });
        }

        if (d.hasVoted) {
            if (isQueue) {
                setImmediate(async () => {
                    try {
                        // ✅ Use the per-grade path — root 'queue' has no flat users map
                        const userGrade = d.grade || settingsData.activeGrade;
                        if (userGrade) {
                            await rtdb.ref(`queue/sessionG${userGrade}/users/${hashedLVN}`).remove();
                        }
                    } catch (err) {
                        console.error("Failed to cleanup voted user from queue:", err);
                    }
                });
            }

            await logSecurityEvent("DUPLICATE_VOTE_ATTEMPT", req, { hashedLVN });
            return res.status(403).json({ error: "Already Voted." });
        }

        const activeGrade = settingsData.activeGrade;

        if (activeGrade && String(activeGrade) !== "ALL" && String(activeGrade) !== "0") {
            if (String(d.grade) !== String(activeGrade)) {
                return res.status(403).json({ error: `Grade ${activeGrade} Only.` });
            }
        }

        // isQueue already derived from RTDB above
        if (isQueue) {
            await joinQueue(hashedLVN, d.grade || activeGrade);
        }

        await deviceRef.set({
            lvns: admin.firestore.FieldValue.arrayUnion(hashedLVN),
            lastLogin: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        // 🔥 ✅ ACTIVE SESSION SET (CORRECT PLACE)
        const userRef = rtdb.ref(`activeSessions/${hashedLVN}`);
        await userRef.set({
            startedAt: Date.now()
        });
        userRef.onDisconnect().remove();

        const csrfToken = crypto.randomBytes(32).toString('hex');
        const jti = crypto.randomBytes(16).toString("hex");

        const sessionToken = jwt.sign(
            { uid: hashedLVN, grade: d.grade, role: "voter", csrfToken, jti },
            SECRET,
            { expiresIn: "60m" }
        );

        res.cookie("__session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            path: "/",
            maxAge: 60 * 60 * 1000
        });

        return res.json({
            success: true,
            name: d.name,
            grade: d.grade,
            token: sessionToken,
            csrfToken,
            isQueue,
            ...(isQueue && { queueKey: hashedLVN })
        });

    } catch (e) {
        console.error("ERROR:", e);
        return res.status(500).json({ error: "Server error during verification." });
    }
});

setInterval(async () => {
    const grades = ['G7', 'G8', 'G9', 'G10', 'G11', 'G12'];

    for (const grade of grades) {
        const gradeKey = `session${grade}`;
        const usersRef = rtdb.ref(`queue/${gradeKey}/users`);
        const queueRef = rtdb.ref(`queue/${gradeKey}`);

        try {
            const snapshot = await usersRef.once('value');
            const users = snapshot.val() || {};

            let cleanedCount = 0;
            let needsRecalc = false;

            for (const [userId, userData] of Object.entries(users)) {
                // ✅ Just check RTDB status - no Firestore call!
                if (userData.status === 'done') {
                    await usersRef.child(userId).remove();
                    cleanedCount++;
                    needsRecalc = true;
                }
            }

            if (cleanedCount > 0) {
                console.log(`🧹 Cleaned up ${cleanedCount} 'done' entries from ${gradeKey}`);

                if (needsRecalc) {
                    // Recalculate activeCount from remaining users
                    const remainingSnapshot = await usersRef.once('value');
                    const remainingUsers = remainingSnapshot.val() || {};

                    let newActiveCount = 0;
                    for (const [_, data] of Object.entries(remainingUsers)) {
                        if (data.status === 'active') {
                            newActiveCount++;
                        }
                    }

                    await queueRef.update({ activeCount: newActiveCount });
                    console.log(`📊 ${gradeKey} activeCount recalculated: ${newActiveCount}`);
                }
            }

        } catch (err) {
            console.error(`Queue cleanup error for ${gradeKey}:`, err);
        }
    }
}, 10 * 60 * 1000);

function maskReceipt(receipt) {
    if (!receipt || typeof receipt !== 'string') return { mask: '***', hash: null };
    if (receipt.length < 16) return { mask: '***', hash: null };

    const mask = receipt.substring(0, 4) + '⋯' + receipt.substring(receipt.length - 4);

    const hash = crypto.createHmac('sha256', MASK_SECRET)
        .update(receipt)
        .digest('hex')
        .substring(0, 16);

    return { mask, hash };
}

function maskLVN(lvn) {
    if (!lvn || typeof lvn !== 'string') return '***';
    if (lvn.length < 8) return '***';
    // Show only last 3 digits
    return '***' + lvn.slice(-3);
}

function sanitizeVoterData(voter) {
    const sanitized = { ...voter };

    // Never expose these fields
    delete sanitized.code;
    delete sanitized.lvn;
    delete sanitized.receipt;
    delete sanitized._deviceFingerprint;

    if (voter.lvn) {
        sanitized.lvnMask = maskLVN(voter.lvn);
    }
    if (voter.receipt) {
        const masked = maskReceipt(voter.receipt);
        sanitized.receiptMask = masked.mask;
        sanitized.receiptHash = masked.hash;
    }

    return sanitized;
}

function sanitizePublicVote(voteData) {
    const { receipt, salt, ...safeData } = voteData;

    delete safeData.voterId; // If exists
    delete safeData.ip;      // If exists

    if (receipt) {
        const masked = maskReceipt(receipt);
        safeData.receiptMask = masked.mask;
        safeData.receiptVerifyHash = masked.hash;
    }

    return safeData;
}

app.post("/verify-vote", rateLimit({
    windowMs: 60 * 1000,
    max: 20
}), async (req, res) => {
    const { receipt, verificationCode } = req.body;

    if (!receipt || !verificationCode) {
        return res.status(400).json({ error: "Missing data" });
    }

    const voteSnap = await db.collection("votes")
        .where("receipt", "==", receipt)
        .limit(1)
        .get();

    if (voteSnap.empty) {
        return res.json({ found: false });
    }

    const vote = voteSnap.docs[0].data();

    const expectedCode = crypto.createHash("sha256")
        .update(receipt + stableStringify(vote.selections))
        .digest("hex")
        .substring(0, 12);

    if (verificationCode.length !== expectedCode.length) {
        return res.json({ found: true, contentMatches: false });
    }

    const cleanCode = verificationCode.trim().toLowerCase();

    const contentMatches = crypto.timingSafeEqual(
        Buffer.from(expectedCode),
        Buffer.from(cleanCode)
    );

    res.json({
        found: true,
        contentMatches
    });
});

function stableStringify(obj) {
    if (obj === null || typeof obj !== "object") {
        return JSON.stringify(obj);
    }

    if (Array.isArray(obj)) {
        return "[" + obj.map(stableStringify).join(",") + "]";
    }

    const keys = Object.keys(obj).sort();
    return "{" + keys.map(key => {
        return JSON.stringify(key) + ":" + stableStringify(obj[key]);
    }).join(",") + "}";
}

app.post("/vote", voteLimiter, requireAuth, requireRole("voter"), verifyCSRF, async (req, res) => {
    try {
        const hashedLVN = req.user.uid;
        const grade = req.user.grade;

        const { selections, timestamp, nonce } = req.body;

        // 🔍 Basic validation
        if (!selections || typeof selections !== "object") {
            return res.status(400).json({ error: "Invalid ballot format." });
        }

        if (typeof timestamp !== "number") {
            return res.status(400).json({ error: "Invalid timestamp" });
        }

        if (!nonce || typeof nonce !== "string" || nonce.length < 20) {
            return res.status(400).json({ error: "Invalid nonce" });
        }

        const now = Date.now();
        if (Math.abs(now - timestamp) > 60000) {
            return res.status(400).json({ error: "Request expired" });
        }

        // 🔐 Anti-replay (nonce)
        const nonceAccepted = await consumeNonce(nonce, hashedLVN); // 🔥 tied to user
        if (!nonceAccepted) {
            await logSecurityEvent("REPLAY_ATTACK", req, { hashedLVN, nonce });
            return res.status(409).json({ error: "Duplicate request detected." });
        }

        // 🔍 Validate selections
        let validatedSelections;
        try {
            validatedSelections = await validateSelections(selections);
        } catch (e) {
            await createAlert("tamper", "critical", "Tampered Vote", e.message, { selections });
            return res.status(400).json({ error: e.message });
        }

        // ⚙️ Get system state
        const [settings, rtdbStatusSnap] = await Promise.all([
            db.collection("settings").doc("electionStatus").get(),
            rtdb.ref("status").once("value")
        ]);

        const rtdbStatus = rtdbStatusSnap.val() || {};
        const isLive = rtdbStatus.isLive === true;
        const isQueue = rtdbStatus.isQueue === true;

        if (!isLive) {
            return res.status(403).json({ error: "Election closed." });
        }

        const electionData = settings.exists ? settings.data() : {};

        // ⏱ End time check
        if (electionData.endTime && Date.now() > electionData.endTime.toMillis()) {
            return res.status(403).json({ error: "Voting period ended." });
        }

        // 👤 Voter validation
        const voterRef = db.collection("voters").doc(hashedLVN);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists) {
            return res.status(403).json({ error: "Voter not found." });
        }

        if (voterSnap.data().hasVoted) {
            return res.status(403).json({ error: "Already voted." });
        }

        // 🔁 Queue validation (FIRST PASS)
        if (isQueue) {
            const userSnap = await rtdb.ref(`queue/sessionG${grade}/users/${hashedLVN}`).once('value');

            if (!userSnap.exists()) {
                return res.status(403).json({ error: "You are not in the queue." });
            }

            if (userSnap.val().status !== 'active') {
                return res.status(403).json({ error: "Please wait for your turn." });
            }
        }

        // 🔗 Refs
        const CHAIN_DOC = db.collection("_meta").doc("chain_head");
        const AGG_REF = db.collection("aggregates").doc("dashboard");

        const voteResult = await db.runTransaction(async (t) => {
            const voterDoc = await t.get(voterRef);
            if (!voterDoc.exists) throw new Error("VOTER_NOT_FOUND");
            if (voterDoc.data().hasVoted) throw new Error("ALREADY_VOTED");

            const chainDoc = await t.get(CHAIN_DOC);
            const aggDoc = await t.get(AGG_REF);

            const prevHash = chainDoc.exists ? chainDoc.data().hash : "GENESIS";
            const prevCount = chainDoc.exists ? (chainDoc.data().count || 0) : 0;

            // 🔥 HASH CHAIN VALIDATION
            if (chainDoc.exists) {
                const expectedPrevHash = chainDoc.data().hash;
                const expectedSequence = (chainDoc.data().count || 0) + 1;

                if (prevHash !== expectedPrevHash) {
                    throw new Error("CHAIN_MISMATCH");
                }

                if (prevCount + 1 !== expectedSequence) {
                    throw new Error("INVALID_SEQUENCE");
                }
            }

            // 🔁 Queue validation (SECOND PASS inside critical section)
            if (isQueue) {
                const queueSnap = await rtdb.ref(`queue/sessionG${grade}/users/${hashedLVN}`).once('value');

                if (!queueSnap.exists() || queueSnap.val().status !== 'active') {
                    throw new Error("QUEUE_NOT_ACTIVE");
                }
            }

            const randomSalt = crypto.randomBytes(32).toString("hex");

            const payload = JSON.stringify({
                voter_hash: hashedLVN,
                selections: validatedSelections,
                timestamp: Date.now()
            });

            const receipt = crypto.createHash("sha256")
                .update(payload + randomSalt)
                .digest("hex");

            // 🔒 Receipt uniqueness
            const receiptCheck = await db.collection("votes")
                .where("receipt", "==", receipt)
                .limit(1)
                .get();

            if (!receiptCheck.empty) {
                throw new Error("DUPLICATE_RECEIPT");
            }

            const verificationCode = crypto.createHash("sha256")
                .update(receipt + stableStringify(validatedSelections))
                .digest("hex")
                .substring(0, 12);

            const currentHash = crypto.createHash("sha256")
                .update(receipt + prevHash + stableStringify(validatedSelections))
                .digest("hex");

            const voteRef = db.collection("votes").doc();

            // 🗳️ Save vote
            t.set(voteRef, {
                selections: validatedSelections,
                grade: String(grade),
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                receipt,
                hash: currentHash,
                prevHash,
                salt: randomSalt,
                sequence: prevCount + 1
            });

            // 👤 Update voter
            t.update(voterRef, {
                hasVoted: true,
                votedAt: admin.firestore.FieldValue.serverTimestamp(),
                receipt
            });

            // 🔗 Update chain
            t.set(CHAIN_DOC, {
                hash: currentHash,
                count: prevCount + 1
            });

            // ⚡ Aggregates
            const agg = aggDoc.exists ? aggDoc.data() : {
                stats: { total: 0, voted: 0, grades: {} },
                leaderboard: {}
            };

            const g = String(grade);
            agg.stats.voted = (agg.stats.voted || 0) + 1;

            if (!agg.stats.grades[g]) {
                agg.stats.grades[g] = { total: 0, voted: 0, missed: 0 };
            }

            agg.stats.grades[g].voted++;

            for (const pos in validatedSelections) {
                const selected = Array.isArray(validatedSelections[pos])
                    ? validatedSelections[pos]
                    : [validatedSelections[pos]];

                if (!agg.leaderboard[pos]) {
                    agg.leaderboard[pos] = {};
                }

                selected.forEach(cid => {
                    agg.leaderboard[pos][cid] =
                        (agg.leaderboard[pos][cid] || 0) + 1;
                });
            }

            if (agg.stats.total > 0) {
                agg.stats.percentage =
                    ((agg.stats.voted / agg.stats.total) * 100).toFixed(1);
            }

            agg.lastUpdated = admin.firestore.FieldValue.serverTimestamp();
            t.set(AGG_REF, agg, { merge: true });

            return { receipt, currentHash, prevHash, verificationCode };
        });

        // ✅ Respond
        res.json({
            success: true,
            receipt: voteResult.receipt,
            verificationCode: voteResult.verificationCode,
            hash: voteResult.currentHash,
            prevHash: voteResult.prevHash
        });

        // 🔄 Queue advancement (async)
        if (isQueue) {
            setImmediate(async () => {
                try {
                    const gradeKey = `sessionG${grade}`;
                    const queueRef = rtdb.ref(`queue/${gradeKey}`);

                    await queueRef.transaction(current => {
                        if (!current || !current.users) return current;

                        delete current.users[hashedLVN];

                        let newActiveCount = 0;
                        let nextUserId = null;
                        let lowestPosition = Infinity;

                        for (const [uid, data] of Object.entries(current.users)) {
                            if (data.status === 'active') {
                                newActiveCount++;
                            } else if (data.status === 'waiting' && data.position < lowestPosition) {
                                nextUserId = uid;
                                lowestPosition = data.position;
                            }
                        }

                        if (nextUserId && newActiveCount < current.maxActive) {
                            current.users[nextUserId].status = 'active';
                            newActiveCount++;
                        }

                        current.activeCount = newActiveCount;

                        return current;
                    });

                } catch (err) {
                    console.error("Queue cleanup failed:", err);
                }
            });
        }

    } catch (e) {
        console.error("Vote error:", e);

        if (e.message === "CHAIN_MISMATCH" || e.message === "INVALID_SEQUENCE") {
            return res.status(500).json({ error: "Vote chain integrity error." });
        }

        if (e.message === "QUEUE_NOT_ACTIVE") {
            return res.status(403).json({ error: "Queue status changed. Try again." });
        }

        if (e.message === "DUPLICATE_RECEIPT") {
            return res.status(409).json({ error: "Duplicate vote detected." });
        }

        res.status(500).json({
            error: "System failed to record vote. Please notify a facilitator."
        });
    }
});

async function verifyAggregateConsistency() {
    try {
        // 🔢 Get real counts
        const [voteCountSnap, votedSnap] = await Promise.all([
            db.collection("votes").count().get(),
            db.collection("voters").where("hasVoted", "==", true).count().get()
        ]);

        const realVotes = voteCountSnap.data().count;
        const realVoted = votedSnap.data().count;

        // 📊 Get aggregate
        const aggSnap = await db.collection("aggregates").doc("dashboard").get();

        if (!aggSnap.exists) {
            throw new Error("Aggregate missing");
        }

        const agg = aggSnap.data();

        const aggVotes = agg.stats?.voted || 0;

        // 🚨 MISMATCH DETECTED
        if (aggVotes !== realVotes || aggVotes !== realVoted) {
            await createAlert(
                "vote_integrity",
                "critical",
                "Aggregate Mismatch Detected",
                "Dashboard data does not match actual votes.",
                {
                    aggregateVotes: aggVotes,
                    actualVotes: realVotes,
                    actualVoters: realVoted
                }
            );

            return {
                valid: false,
                aggVotes,
                realVotes
            };
        }

        return { valid: true };

    } catch (e) {
        console.error("Aggregate verification failed:", e);
        return { valid: false, error: e.message };
    }
}

async function rebuildAggregates() {
    console.log("🔧 Rebuilding aggregates...");

    const votesSnap = await db.collection("votes").get();

    const agg = {
        stats: { total: 0, voted: 0, grades: {} },
        leaderboard: {}
    };

    votesSnap.forEach(doc => {
        const v = doc.data();
        const grade = String(v.grade || "Unknown");

        agg.stats.voted++;

        if (!agg.stats.grades[grade]) {
            agg.stats.grades[grade] = { total: 0, voted: 0, missed: 0 };
        }
        agg.stats.grades[grade].voted++;

        for (const pos in v.selections || {}) {
            const selected = Array.isArray(v.selections[pos])
                ? v.selections[pos]
                : [v.selections[pos]];

            if (!agg.leaderboard[pos]) agg.leaderboard[pos] = {};

            selected.forEach(cid => {
                agg.leaderboard[pos][cid] =
                    (agg.leaderboard[pos][cid] || 0) + 1;
            });
        }
    });

    await db.collection("aggregates").doc("dashboard").set(agg);
}

setInterval(async () => {
    const result = await verifyAggregateConsistency();

    if (!result.valid) {
        await rebuildAggregates();
    }
}, 60000);

app.post("/submit-review", submitReviewLimiter, submissionLimiter, requireAuth, async (req, res) => {
    const submitToken = req.headers["x-submit-token"] || req.body._submitToken;
    if (!verifySubmitToken(submitToken, req.user.jti)) {
        return res.status(403).json({ error: "Unauthorized: Invalid session token." });
    }
    const grade = sanitizeInput(req.body.grade || '');
    const section = sanitizeInput(req.body.section || '');
    const encoder = sanitizeInput(req.body.encoder || '');
    const names = Array.isArray(req.body.names) ? req.body.names.map(n => sanitizeInput(n)) : [];
    if (!grade || isNaN(parseInt(grade))) {
        return res.status(400).json({ error: "Invalid grade value." });
    }
    if (!section || !section.trim()) {
        return res.status(400).json({ error: "Section is required." });
    }
    if (!encoder || !encoder.trim()) {
        return res.status(400).json({ error: "Encoder name is required." });
    }
    if (!names || !Array.isArray(names)) {
        return res.status(400).json({ error: "Invalid input format" });
    }
    try {
        const settingsSnap = await db.collection("settings").doc("electionStatus").get();
        if (settingsSnap.exists) {
            const data = settingsSnap.data();
            if (data.submissionTimer) {
                const now = new Date();
                let deadline;
                if (data.submissionTimer._seconds) {
                    deadline = new Date(data.submissionTimer._seconds * 1000);
                } else {
                    deadline = new Date(data.submissionTimer);
                }
                if (now > deadline) {
                    return res.status(403).json({ error: "SESSION_EXPIRED", message: "The submission deadline has passed." });
                }
            }
        }
        const now = new Date();
        const currentYear = now.getFullYear();
        const startYear = now.getMonth() < 5 ? currentYear - 1 : currentYear;
        const sy = `${startYear}-${startYear + 1}`;
        const cleanSection = section.toUpperCase();
        const submissionPayload = {
            grade: String(grade),
            section: cleanSection,
            encoder: encoder,
            names: names.map(n => n.toUpperCase()),
            status: "PENDING",
            submittedAt: admin.firestore.FieldValue.serverTimestamp(),
            schoolYear: sy
        };
        await db.collection("forms").doc(sy).collection("submissions").add(submissionPayload);
        res.json({ success: true, message: `List for Grade ${grade} - ${cleanSection} (S.Y. ${sy}) submitted for verification.` });
    } catch (e) {
        res.status(500).json({ error: "Failed to submit list for review." });
    }
});

// --- ADMIN ROUTES ---
app.use("/admin", requireAuth, requireRole("admin"), adminLimiter);

app.get("/admin/voters", async (req, res) => {
    try {
        if (VotersStaticCache.data.length === 0) {
            while (VotersStaticCache.isLoading) {
                await new Promise(r => setTimeout(r, 50));
            }
            if (VotersStaticCache.data.length === 0) {
                await loadVotersStaticCache();
            }
        }

        // ── 1. Parse query parameters ─────────────────────────────────────────
        const page = Math.max(1, parseInt(req.query.page || "1", 10));
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || "50", 10)));
        const gradeFilter = sanitizeInput(req.query.grade || "ALL");
        const searchQuery = sanitizeInput((req.query.search || "").toLowerCase().trim());

        // ── 2. Filter on static cache (O(n) over in-memory array, no I/O) ────
        let filtered = VotersStaticCache.data;

        if (gradeFilter && gradeFilter !== "ALL") {
            filtered = filtered.filter(v => String(v.grade).trim() === String(gradeFilter).trim());
        }

        if (searchQuery) {
            filtered = filtered.filter(v =>
                (v.name || "").toLowerCase().includes(searchQuery) ||
                (v.lvn || "").toLowerCase().includes(searchQuery) ||
                (v.section || "").toLowerCase().includes(searchQuery)
            );
        }

        const total = filtered.length;
        const totalPages = Math.ceil(total / limit) || 1;
        const safePage = Math.min(page, totalPages);
        const start = (safePage - 1) * limit;
        const pageSlice = filtered.slice(start, start + limit);

        const statusSnap = await rtdb.ref("voterStatus").once("value");
        const statusMap = await getVoterStatusCache();

        // ── 4. Merge static + dynamic data ────────────────────────────────────
        const voters = pageSlice.map(voter => {
            const s = statusMap[voter.id] || {};
            return {
                id: voter.id,
                lvn: voter.lvn,
                name: voter.name,
                grade: voter.grade,
                section: voter.section,
                code: voter.accessCode,
                hasVoted: s.hasVoted ?? false,
                isMissed: s.isMissed ?? false,
                integrityStatus: s.integrityStatus ?? "PENDING",
                addedAt: voter.addedAt,
            };
        });

        res.json({
            voters,
            pagination: {
                page: safePage,
                limit,
                total,
                totalPages,
                hasNext: safePage < totalPages,
                hasPrev: safePage > 1,
            },
            cacheAge: VotersStaticCache.lastUpdated,
        });

    } catch (e) {
        console.error("GET /admin/voters error:", e);
        res.status(500).json({ error: "Failed to fetch voters" });
    }
});

app.post("/admin/voters/cache-refresh", async (req, res) => {
    try {
        await invalidateVotersCache();
        await logAdminAction(req, "VOTER_CACHE_REFRESH", { count: VotersStaticCache.data.length });
        res.json({ success: true, count: VotersStaticCache.data.length, cachedAt: VotersStaticCache.lastUpdated });
    } catch (e) {
        res.status(500).json({ error: "Cache refresh failed" });
    }
});

app.post("/admin/voters/add", async (req, res) => {
    const grade = sanitizeInput(req.body.grade || '');
    const section = sanitizeInput(req.body.section || '');
    const names = Array.isArray(req.body.names) ? req.body.names.map(n => sanitizeInput(n)) : [];
    if (!grade || isNaN(parseInt(grade))) {
        return res.status(400).json({ error: "Invalid grade value." });
    }
    if (!section || !section.trim()) {
        return res.status(400).json({ error: "Section is required." });
    }
    if (!names || !Array.isArray(names)) {
        return res.status(400).json({ error: "Invalid input format" });
    }
    try {
        const targetGrade = String(grade).trim();
        const prevGrade = String(parseInt(targetGrade) - 1);
        const sectionKey = `${targetGrade}_${section.toUpperCase()}`;
        const sectionData = await getOrGenerateCode('section_data', sectionKey);
        const gradePrefix = await getOrGenerateCode('grade_prefix', targetGrade);
        const accessCode = sectionData.access_code;
        const sectionPrefix = sectionData.prefix;
        const batch = db.batch();
        let addedCount = 0;
        let updatedCount = 0;
        const searchGrades = [targetGrade];
        if (targetGrade !== "7" && parseInt(targetGrade) > 0) {
            searchGrades.push(prevGrade);
        }
        const existingSnap = await db.collection("voters")
            .where("grade", "in", searchGrades)
            .get();
        const existingMap = {};
        existingSnap.forEach(doc => {
            const data = doc.data();
            if (data.name) existingMap[data.name.toUpperCase().trim()] = doc.ref;
        });
        for (const name of names) {
            if (!name || !name.trim()) continue;
            const cleanName = name.toUpperCase().trim();
            const codeHashForUpdate = encryptAccessCode(accessCode);
            const code = await bcrypt.hash(accessCode.toUpperCase(), 10);
            if (existingMap[cleanName]) {
                batch.update(existingMap[cleanName], {
                    grade: targetGrade,
                    section: section.toUpperCase(),
                    code: code,
                    codeHash: codeHashForUpdate,
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                updatedCount++;
            } else {
                const randomSuffix = Math.floor(1000000 + Math.random() * 9000000).toString();
                const lvn = `${gradePrefix}${sectionPrefix}${randomSuffix}`;
                const hashedLVN = hashLVN(lvn);
                const encryptedCode = encryptAccessCode(accessCode);
                const codeForNewSet = await bcrypt.hash(accessCode.toUpperCase(), 10);
                const existingLvnSnap = await db.collection("voters").doc(hashedLVN).get();
                const voterRef = db.collection("voters").doc(hashedLVN);
                batch.set(voterRef, {
                    lvn: lvn,
                    name: cleanName,
                    grade: targetGrade,
                    section: section.toUpperCase(),
                    code: codeForNewSet,
                    codeHash: encryptedCode,
                    hasVoted: false,
                    addedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                addedCount++;
            }
        }
        await batch.commit();
        // Invalidate static cache so new voters appear on next admin load
        setImmediate(() => invalidateVotersCache().catch(e =>
            console.error("[CACHE] invalidateVotersCache after add failed:", e)
        ));
        await logAdminAction(req, "VOTERS_UPSERT", {
            grade: targetGrade,
            section: section.toUpperCase(),
            totalProvided: names.length,
            updated: updatedCount,
            added: addedCount,
        });
        res.json({ success: true, message: `Processed ${names.length}. Promoted/Updated: ${updatedCount}, New: ${addedCount}`, accessCode: accessCode });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/ai/voters/add", requireAIServiceOnly, async (req, res) => {
    const grade = sanitizeInput(req.body.grade || '');
    const section = sanitizeInput(req.body.section || '');
    const names = Array.isArray(req.body.names)
        ? req.body.names.map(n => sanitizeInput(n))
        : [];

    if (!grade || isNaN(parseInt(grade))) {
        return res.status(400).json({ error: "Invalid grade value." });
    }

    if (!section.trim()) {
        return res.status(400).json({ error: "Section is required." });
    }

    if (!Array.isArray(names) || names.length === 0) {
        return res.status(400).json({ error: "At least one name is required." });
    }

    if (names.length > 10) {
        return res.status(400).json({ error: "Maximum 10 names per request." });
    }

    try {
        const targetGrade = String(parseInt(grade));
        const upperSection = section.toUpperCase();

        // ==================================================
        // LOW COST DUPLICATE CHECK
        // Stops immediately if one name already exists
        // ==================================================
        for (const rawName of names) {
            if (!rawName || !rawName.trim()) continue;

            const cleanName = rawName.toUpperCase().trim();

            const existSnap = await db.collection("voters")
                .where("nameKey", "==", cleanName)
                .limit(1)
                .get();

            if (!existSnap.empty) {
                return res.json({
                    status: "exist"
                });
            }
        }

        // ==================================================
        // CONTINUE ONLY IF NO DUPLICATES
        // ==================================================
        const sectionKey = `${targetGrade}_${upperSection}`;
        const sectionData = await getOrGenerateCode("section_data", sectionKey);
        const gradePrefix = await getOrGenerateCode("grade_prefix", targetGrade);

        const accessCode = sectionData.access_code;
        const sectionPrefix = sectionData.prefix;

        const batch = db.batch();

        const addedLVNs = [];
        let addedCount = 0;

        for (const rawName of names) {
            if (!rawName || !rawName.trim()) continue;

            const cleanName = rawName.toUpperCase().trim();

            const randomSuffix = Math.floor(
                1000000 + Math.random() * 9000000
            ).toString();

            const lvn = `${gradePrefix}${sectionPrefix}${randomSuffix}`;
            const hashedLVN = hashLVN(lvn);

            const voterRef = db.collection("voters").doc(hashedLVN);

            const encryptedCode = encryptAccessCode(accessCode);
            const bcryptCode = await bcrypt.hash(accessCode.toUpperCase(), 10);

            batch.set(voterRef, {
                lvn: lvn,
                name: cleanName,
                nameKey: cleanName,
                grade: targetGrade,
                section: upperSection,
                code: bcryptCode,
                codeHash: encryptedCode,
                hasVoted: false,
                addedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            addedLVNs.push(lvn);
            addedCount++;
        }

        await batch.commit();

        setImmediate(() =>
            invalidateVotersCache().catch(err =>
                console.error("[CACHE ERROR]", err)
            )
        );

        await logSecurityEvent("AI_SERVICE_ADD_VOTERS", req, {
            grade: targetGrade,
            section: upperSection,
            count: addedCount
        });

        return res.json({
            success: true,
            status: "added",
            count: addedCount,
            accessCode: accessCode,
            lvns: addedLVNs
        });

    } catch (error) {
        console.error("AI Service error:", error);

        return res.status(500).json({
            error: "Failed to process voters."
        });
    }
});

app.post("/admin/voters/delete", async (req, res) => {
    try {
        const lvn = sanitizeInput(req.body.lvn || '');

        if (!lvn) {
            return res.status(400).json({
                error: "LVN required"
            });
        }

        const hashedLVN = hashLVN(lvn);

        const voterRef = db.collection("voters").doc(hashedLVN);
        const statusRef = rtdb.ref(`voterStatus/${hashedLVN}`);

        const voterSnap = await voterRef.get();

        if (!voterSnap.exists) {
            return res.status(404).json({
                error: "Voter not found."
            });
        }

        const voterData = voterSnap.data() || {};

        // 🔥 Check both Firestore + RTDB live status
        const liveSnap = await statusRef.once("value");
        const liveStatus = liveSnap.val() || {};

        const alreadyVoted =
            voterData.hasVoted === true ||
            liveStatus.hasVoted === true;

        // 🚫 Block deletion if already voted
        if (alreadyVoted) {
            return res.status(409).json({
                error:
                    "Cannot remove a voter that has already been voted. " +
                    "If you want to change details proceed on " +
                    "https://currentLinktheUserwason/tools/system/admin/utilities/changeDetails.html"
            });
        }

        // ✅ Safe delete (not voted)
        await voterRef.delete();

        // Remove RTDB live status if exists
        await statusRef.remove();

        // Refresh static cache
        await invalidateVotersCache();

        await logAdminAction(req, "VOTER_DELETE", {
            lvn: "***"
        });

        return res.json({
            success: true
        });

    } catch (e) {
        console.error("Delete voter failed:", e);

        return res.status(500).json({
            error: "Delete failed"
        });
    }
});

app.post("/admin/voters/reset", async (req, res) => {
    try {
        const lvn = sanitizeInput(req.body.lvn || '');
        if (!lvn) return res.status(400).json({ error: "LVN required" });
        const hashedLVN = hashLVN(lvn);

        await db.runTransaction(async (t) => {
            const voterRef = db.collection("voters").doc(hashedLVN);
            const voterSnap = await t.get(voterRef);
            if (!voterSnap.exists) throw new Error("VOTER_NOT_FOUND");

            const voterData = voterSnap.data();
            const receipt = voterData.receipt;

            if (receipt) {
                const voteSnap = await db.collection("votes")
                    .where("receipt", "==", receipt).limit(1).get();

                // Step 2 — delete it inside the transaction using the known ref
                if (!voteSnap.empty) {
                    t.delete(voteSnap.docs[0].ref);
                }
            }

            t.update(voterRef, {
                hasVoted: false,
                receipt: admin.firestore.FieldValue.delete(),
                votedAt: admin.firestore.FieldValue.delete()
            });
        });

        await logAdminAction(req, "VOTER_RESET", { lvn: "***" });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Reset failed" });
    }
});



app.post("/admin/purge", async (req, res) => {
    try {
        await logAdminAction(req, "PURGE_ELECTION_DATA", { initiated: true });
        const { json, hash } = await createElectionBackup(db);
        const url = await uploadToGitHub(json, hash);

        await alertManager.createAlert(
            'backup',
            'minor',
            '💾 Archived Created',
            'Election backup saved. Click the archive link below to view all archived election results.',
            {
                archiveUrl: url
            },
            24 * 60 * 60 * 1000
        );

        if (!hash || !url) {
            throw new Error("Backup failed. Purge aborted.");
        }

        await purgeElectionData();

        await alertManager.detectSystemHealth();

        await alertManager.createAlert(
            'election_deleted',
            'major',
            'Election Data Deleted',
            'All election data has been cleared.',
            {},
            null
        );

        res.json({
            success: true,
            message: "Election purged with backup 🔥",
            backupHash: hash,
            backupUrl: url
        });

    } catch (e) {
        console.error("PURGE ERROR:", e);
        res.status(500).json({ error: "Purge failed: " + e.message });
    }
});

app.post("/admin/restore", async (req, res) => {
    try {
        const { backupUrl, backupHash } = req.body;

        if (!backupUrl || !backupHash) {
            return res.status(400).json({ error: "Backup URL and hash required" });
        }

        if (!/^https:\/\/raw\.githubusercontent\.com\//.test(backupUrl) &&
            !/^https:\/\/api\.github\.com\/repos\//.test(backupUrl)) {
            return res.status(400).json({ error: "Untrusted backup URL" });
        }

        const response = await axios.get(backupUrl, { responseType: 'text' });
        const jsonData = response.data;

        const result = await restoreElectionFromBackup(jsonData, backupHash);

        await alertManager.detectSystemHealth();

        res.json({
            success: true,
            restored: result
        });

    } catch (e) {
        console.error("RESTORE ERROR:", e);
        res.status(500).json({ error: e.message });
    }
});

app.post("/admin/retally", async (req, res) => {
    try {
        const candidatesSnap = await db.collection("candidates").get();
        const votesSnap = await db.collection("votes").get();
        const votersSnap = await db.collection("voters").where("hasVoted", "==", true).get();
        const validReceipts = {};
        votersSnap.forEach(doc => {
            const v = doc.data();
            if (v.receipt) validReceipts[v.receipt] = v.grade || "Unknown";
        });
        const newResults = {};
        candidatesSnap.forEach(doc => {
            const options = doc.data().options || [];
            options.forEach(c => {
                newResults[String(c.id)] = { votes: 0 };
            });
        });
        let validVotesCount = 0;
        let orphanedVotesCount = 0;
        votesSnap.forEach(doc => {
            const ballot = doc.data();
            const receipt = ballot.receipt;
            if (!validReceipts.hasOwnProperty(receipt)) {
                orphanedVotesCount++;
                return;
            }
            validVotesCount++;
            const voterGrade = validReceipts[receipt];
            const selections = ballot.selections || {};
            Object.values(selections).forEach((candidateIdOrArray) => {
                if (!candidateIdOrArray) return;
                const ids = Array.isArray(candidateIdOrArray) ? candidateIdOrArray : [candidateIdOrArray];
                ids.forEach((candidateId) => {
                    if (!candidateId) return;
                    const cid = String(candidateId);
                    if (!newResults[cid]) newResults[cid] = { votes: 0 };
                    newResults[cid].votes++;
                    if (voterGrade !== "Unknown") {
                        const gradeKey = `votes_${voterGrade}`;
                        if (!newResults[cid][gradeKey]) newResults[cid][gradeKey] = 0;
                        newResults[cid][gradeKey]++;
                    }
                });
            });
        });
        const batch = db.batch();
        for (const [cid, data] of Object.entries(newResults)) {
            const docRef = db.collection("results").doc(cid);
            batch.set(docRef, { ...data, updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        }
        await batch.commit();
        await refreshLocalResults();
        res.json({ success: true, message: `Re-tally complete. Database updated. Valid Votes: ${validVotesCount}, Invalid Votes: ${orphanedVotesCount}.` });
        await alertManager.clearResolvedAlerts('vote_integrity');
    } catch (e) {
        res.status(500).json({ error: "Re-tally failed." });
    }
});

app.post("/admin/publish/candidates", async (req, res) => {
    try {
        const freshData = await fetchRawCandidatesFromSource();
        if (freshData) {
            await db.collection("app_config").doc("candidates_static").set({
                payload: freshData,
                lastUpdated: admin.firestore.FieldValue.serverTimestamp()
            });
            GlobalCache.candidates = freshData;
            Object.freeze(GlobalCache.candidates);
            GlobalCache.timestamps.candidates = new Date().toISOString();
            await logAdminAction(req, "PUBLISH_CANDIDATES", { success: true });
            await alertManager.createAlert(
                'candidate_sync',
                'minor',
                'Candidates Published',
                'Candidates successfully synced.',
                {},
                10 * 60 * 1000
            );


            await alertManager.detectSystemHealth();
            res.json({ success: true, message: "Candidates published successfully." });
            await alertManager.clearResolvedAlerts('candidate_sync');
        } else {
            throw new Error("No data returned from source collections.");
        }
    } catch (e) {
        res.status(500).json({ error: "Update Failed: " + e.message });
    }
});

app.post("/admin/publish/results", async (req, res) => {
    const success = await refreshLocalResults();
    if (success) {
        await db.collection("app_config").doc("results_public").set({
            ...GlobalCache.dashboard,
            lastUpdated: new Date().toISOString()
        });
        await logAdminAction(req, "RETALLY", { ok: true });
        res.json({ success: true });
    } else {
        res.status(500).json({ error: "Update Failed" });
    }
});

app.get("/admin/status", (req, res) => {
    res.json(GlobalCache.timestamps);
});

app.post("/admin/add-party", async (req, res) => {
    const rawCandidates = req.body.candidates || [];
    const candidates = rawCandidates.map(c => ({
        position: sanitizeInput(c.position || ''),
        id: sanitizeInput(c.id || ''),
        name: sanitizeInput(c.name || ''),
        party: sanitizeInput(c.party || ''),
        img: c.img || "none"
    }));
    try {
        await db.runTransaction(async (t) => {
            const allRefs = ALL_POSITIONS.map(pos => db.collection("candidates").doc(pos));
            const allSnaps = await t.getAll(...allRefs);
            const globalNames = new Set();
            const partyCounts = {};
            const idByPosition = {};
            ALL_POSITIONS.forEach(pos => {
                partyCounts[pos] = {};
                idByPosition[pos] = new Set();
            });
            allSnaps.forEach((snap, idx) => {
                const posId = ALL_POSITIONS[idx];
                if (!snap.exists) return;
                const list = snap.data().options || [];
                list.forEach(c => {
                    const name = c && c.name ? String(c.name).toUpperCase().trim() : "";
                    const party = c && c.party ? String(c.party).toUpperCase().trim() : "";
                    const id = c && c.id ? String(c.id) : "";
                    if (name) globalNames.add(name);
                    if (party) partyCounts[posId][party] = (partyCounts[posId][party] || 0) + 1;
                    if (id) idByPosition[posId].add(id);
                });
            });
            const groupedData = {};
            for (const c of candidates) {
                if (!c || !c.position || !c.id || !c.name) continue;
                const pos = String(c.position).trim();
                const idStr = String(c.id).trim();
                const nameUpper = String(c.name).toUpperCase().trim();
                const partyUpper = String(c.party || "").toUpperCase().trim();
                if (!ALL_POSITIONS.includes(pos)) throw new Error(`Invalid position '${pos}'.`);
                if (!partyUpper) throw new Error(`Missing party name for ${pos}.`);
                if (idByPosition[pos].has(idStr)) throw new Error(`Candidate ID '${idStr}' already exists for ${pos}.`);
                if (globalNames.has(nameUpper)) throw new Error(`ERROR: '${c.name}' is already a candidate.`);
                const limitPerParty = MULTI_POSITIONS.includes(pos) ? 2 : 1;
                const currentCount = partyCounts[pos][partyUpper] || 0;
                if (currentCount >= limitPerParty) throw new Error(`Party '${c.party}' already has ${limitPerParty} candidate(s) for ${pos}.`);
                globalNames.add(nameUpper);
                partyCounts[pos][partyUpper] = currentCount + 1;
                idByPosition[pos].add(idStr);
                if (!groupedData[pos]) groupedData[pos] = [];
                groupedData[pos].push({
                    id: idStr,
                    name: nameUpper,
                    party: partyUpper,
                    img: c.img || "none",
                });
            }
            const positionsToUpdate = Object.keys(groupedData);
            positionsToUpdate.forEach(pos => {
                const newCands = groupedData[pos];
                const ref = db.collection("candidates").doc(pos);
                t.set(ref, { options: admin.firestore.FieldValue.arrayUnion(...newCands) }, { merge: true });
            });
        });
        await refreshLocalCandidates();
        await logAdminAction(req, "ADD_PARTY", { success: true });
        res.json({ success: true });
        await createAlert(
            "candidate_sync",
            "minor",
            "📢 Candidate Update Needed",
            "New candidates added but not published.",
            {},
            24 * 60 * 60 * 1000
        );

    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.post("/admin/delete", async (req, res) => {
    const position = sanitizeInput(req.body.position || '');
    const candidateId = sanitizeInput(req.body.candidateId || '');
    const partyName = sanitizeInput(req.body.partyName || '');
    try {
        if (partyName) {
            const normParty = partyName.toUpperCase();
            const batch = db.batch();
            const refs = ALL_POSITIONS.map(pos => db.collection("candidates").doc(pos));
            const snaps = await db.getAll(...refs);
            snaps.forEach((s, i) => {
                if (!s.exists) return;
                const opts = s.data().options || [];
                const newOpts = opts.filter(c => String(c.party).toUpperCase() !== normParty);
                if (newOpts.length !== opts.length) batch.update(refs[i], { options: newOpts });
            });
            await batch.commit();
            await refreshLocalCandidates();
            await logAdminAction(req, "DELETE_PARTY", { partyName });

            return res.json({ success: true });
        }
        if (position && candidateId) {
            const docRef = db.collection("candidates").doc(position);
            await db.runTransaction(async t => {
                const s = await t.get(docRef);
                if (!s.exists) throw new Error("No doc");
                const opts = s.data().options || [];
                const newOpts = opts.filter(c => String(c.id) !== String(candidateId));
                t.update(docRef, { options: newOpts });
            });
            await refreshLocalCandidates();
            await logAdminAction(req, "DELETE_CANDIDATE", { position, candidateId });
            return res.json({ success: true });
        }

        await alertManager.detectSystemHealth();
        res.status(400).json({ error: "Bad Params" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/admin/election/reset", async (req, res) => {
    const confirmation = sanitizeInput(req.body.confirmation || '');
    if (confirmation !== "DELETE ELECTION DATA") return res.status(403).json({ error: "Security Mismatch." });
    try {
        await db.collection("immutable_audit").add({
            event: "ELECTION_RESET",
            adminEmail: req.user?.email || "unknown",
            ip: req.ip,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        const batchLimit = 400;
        const votersRef = db.collection("voters").where("hasVoted", "==", true);
        const votersSnapshot = await votersRef.get();
        const chunks = [];
        let currentBatch = db.batch();
        let counter = 0;
        votersSnapshot.docs.forEach((doc) => {
            currentBatch.update(doc.ref, {
                hasVoted: false,
                votedAt: admin.firestore.FieldValue.delete(),
                receipt: admin.firestore.FieldValue.delete()
            });
            counter++;
            if (counter >= batchLimit) {
                chunks.push(currentBatch.commit());
                currentBatch = db.batch();
                counter = 0;
            }
        });
        if (counter > 0) chunks.push(currentBatch.commit());
        await deleteCollectionInBatches(db.collection("votes"), 500);
        await deleteCollectionInBatches(db.collection("results"), 500);
        await Promise.all(chunks);
        GlobalCache.dashboard.stats = { total: 0, voted: 0, percentage: 0, grades: {} };
        GlobalCache.dashboard.leaderboard = {};
        await refreshLocalResults();
        await logAdminAction(req, "ELECTION_RESET", { success: true });
        res.json({ success: true, message: "Election system successfully reset." });
    } catch (e) {
        res.status(500).json({ error: "Reset failed partially. Check logs." });
    }
});

app.post("/admin/settings/session", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const voterTime = req.body.voterTime;
        const activeGrade = req.body.activeGrade;
        const isLive = req.body.isLive;
        const isQueue = req.body.isQueue;

        const firestoreUpdate = {};
        const rtdbUpdates = {};

        // =========================
        // 🔥 RTDB (ONLY REALTIME FLAGS)
        // =========================
        if (typeof isLive === 'boolean') {
            rtdbUpdates["status/isLive"] = isLive;
        }

        if (typeof isQueue === 'boolean') {
            rtdbUpdates["status/isQueue"] = isQueue;
        }

        // =========================
        // 🔥 FIRESTORE (GRADE + TIMER)
        // =========================
        if (activeGrade !== undefined) {
            firestoreUpdate.activeGrade =
                (activeGrade === "ALL") ? "ALL" : Number(activeGrade);
        }

        if (voterTime && !isNaN(voterTime) && Number(voterTime) > 0) {
            const minutes = Number(voterTime);
            const futureDate = new Date(Date.now() + (minutes * 60 * 1000));

            firestoreUpdate.sessionTimer = futureDate.toISOString();
        } else if (voterTime == 0) {
            firestoreUpdate.sessionTimer = admin.firestore.FieldValue.delete();
        }

        // =========================
        // 🔥 WRITE UPDATES
        // =========================
        if (Object.keys(rtdbUpdates).length > 0) {
            await rtdb.ref("/").update(rtdbUpdates);
        }

        if (Object.keys(firestoreUpdate).length > 0) {
            await db.collection("settings").doc("electionStatus")
                .set(firestoreUpdate, { merge: true });
        }

        // =========================
        // 🔥 CACHE
        // =========================
        if (typeof isLive === 'boolean') {
            GlobalCache.dashboard.isLive = isLive;
        }

        if (typeof isQueue === 'boolean') {
            GlobalCache.dashboard.isQueue = isQueue;
        }

        if (activeGrade !== undefined) {
            GlobalCache.dashboard.activeGrade = activeGrade;
        }

        // =========================
        // 🔥 LOGS
        // =========================
        await logAdminAction(req, "SET_ELECTION_SESSION", {
            isLive,
            isQueue,
            activeGrade,
            voterTime
        });

        res.json({
            success: true,
            isLive,
            isQueue,
            activeGrade
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Failed to update election status" });
    }
});

app.post("/admin/session/end", async (req, res) => {
    try {
        const settingsSnap = await db.collection("settings").doc("electionStatus").get();
        const activeGrade = settingsSnap.exists ? settingsSnap.data().activeGrade : "ALL";
        let query = db.collection("voters").where("hasVoted", "==", false);
        if (activeGrade && activeGrade !== "ALL" && activeGrade !== 0) {
            query = query.where("grade", "==", String(activeGrade));
        }
        const snapshot = await query.get();
        const BATCH_LIMIT = 400;
        let currentBatch = db.batch();
        let count = 0;
        const commits = [];

        snapshot.forEach(doc => {
            if (!doc.data().isMissed) {
                currentBatch.update(doc.ref, {
                    isMissed: true,
                    missedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                count++;
                if (count % BATCH_LIMIT === 0) {
                    commits.push(currentBatch.commit());
                    currentBatch = db.batch();
                }
            }
        });

        if (count % BATCH_LIMIT !== 0) commits.push(currentBatch.commit());
        await Promise.all(commits);

        await logAdminAction(req, "SESSION_END", { count });
        res.json({ success: true, count });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/admin/voters/reset-missed", async (req, res) => {
    try {
        const lvn = sanitizeInput(req.body.lvn || '');
        if (!lvn) return res.status(400).json({ error: "LVN required" });
        const hashedLVN = hashLVN(lvn);
        await db.collection("voters").doc(hashedLVN).update({
            isMissed: false,
            missedAt: admin.firestore.FieldValue.delete()
        });
        await logAdminAction(req, "RESET_MISSED", { lvn: "***" });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Reset failed" });
    }
});

app.get("/admin/forms/submissions", async (req, res) => {
    try {
        const now = new Date();
        const currentYear = now.getFullYear();
        const startYear = now.getMonth() < 5 ? currentYear - 1 : currentYear;
        const sy = `${startYear}-${startYear + 1}`;
        const snapshot = await db.collection("forms").doc(sy)
            .collection("submissions")
            .orderBy("submittedAt", "desc")
            .limit(50)
            .get();
        const submissions = [];
        let lastUpdated = null;
        snapshot.forEach(doc => {
            const data = doc.data();
            const submittedAt = data.submittedAt ? data.submittedAt.toDate().toISOString() : null;
            if (!lastUpdated) lastUpdated = submittedAt;
            submissions.push({
                id: doc.id,
                grade: data.grade,
                section: data.section,
                count: data.names ? data.names.length : 0,
                submittedAt: submittedAt,
                encoder: data.encoder
            });
        });
        res.json({ sy: sy, lastUpdated: lastUpdated, submissions: submissions });
    } catch (e) {
        res.status(500).json({ error: "Failed to load submissions." });
    }
});

app.get("/api/admin/report-data", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const votersSnap = await db.collection("voters").get();
        const votesSnap = await db.collection("votes").get();

        const totalRegistered = votersSnap.size;
        const totalVotes = votesSnap.size;

        const turnoutRate = totalRegistered === 0
            ? 0
            : ((totalVotes / totalRegistered) * 100);

        const remainingVotes = totalRegistered - totalVotes;

        const gradeStats = {};

        votersSnap.forEach(doc => {
            const g = doc.data().grade;
            if (!gradeStats[g]) {
                gradeStats[g] = { total: 0, voted: 0 };
            }
            gradeStats[g].total++;
        });

        votesSnap.forEach(doc => {
            const g = doc.data().grade;
            if (gradeStats[g]) {
                gradeStats[g].voted++;
            }
        });

        Object.keys(gradeStats).forEach(g => {
            const s = gradeStats[g];
            s.turnout = s.total === 0 ? 0 : ((s.voted / s.total) * 100);
        });

        // ✅ FIXED HERE
        const systemHealth = await alertManager.detectSystemHealth();

        res.json({
            REG_USR: totalRegistered,
            VT_CST: totalVotes,
            TN_RT: turnoutRate.toFixed(2) + "%",
            RG_VT: remainingVotes,
            CURRENTDATEANDTIME: new Date().toLocaleString(),

            gradeStats,
            systemHealth
        });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "Failed to generate report data" });
    }
});

app.get("/api/system/health", async (req, res) => {
    const health = await alertManager.detectSystemHealth();
    res.json(health);
});

// ============================================
// AI INTEGRATION FOR NAME VALIDATION
// ============================================
// ============================================
// NVIDIA API + KIMI K2.5 INTEGRATION
// ============================================
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NVIDIA_BASE_URL = 'https://integrate.api.nvidia.com/v1';

if (!NVIDIA_API_KEY) {
    console.warn('⚠️ NVIDIA_API_KEY not set. AI name validation will be disabled.');
}

// ============================================
// DEVICE-BASED RATE LIMITING (2 ATTEMPTS PER DEVICE)
// ============================================
const deviceValidationStore = new Map();

setInterval(() => {
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);

    for (const [deviceId, data] of deviceValidationStore.entries()) {
        if (data.lastAttempt < oneHourAgo) {
            deviceValidationStore.delete(deviceId);
        }
    }
}, 30 * 60 * 1000);

function getDeviceFingerprint(req) {
    const ip = req.ip || req.connection.remoteAddress || '';
    const ua = req.headers['user-agent'] || '';
    return crypto.createHash('sha256').update(`${ip}:${ua}`).digest('hex').substring(0, 16);
}

function checkDeviceLimit(req) {
    const deviceId = getDeviceFingerprint(req);
    const now = Date.now();
    const oneHourAgo = now - (60 * 60 * 1000);

    let record = deviceValidationStore.get(deviceId);

    if (record && record.lastAttempt < oneHourAgo) {
        deviceValidationStore.delete(deviceId);
        record = null;
    }

    if (!record) {
        return { deviceId, attempts: 0, remaining: 2, limit: 2, limited: false };
    }

    return { deviceId, attempts: record.count, remaining: Math.max(0, 2 - record.count), limit: 2, limited: record.count >= 2 };
}

function trackDeviceAttempt(req) {
    const deviceId = getDeviceFingerprint(req);
    const now = Date.now();

    let record = deviceValidationStore.get(deviceId);
    if (!record) record = { count: 0, firstAttempt: now };

    record.count++;
    record.lastAttempt = now;
    deviceValidationStore.set(deviceId, record);

    return { attempts: record.count, remaining: Math.max(0, 2 - record.count), limited: record.count >= 2 };
}

/**
 * Validates a name using AI - NO FALLBACK
 * @returns {Promise<Object>} Validation result or throws error
 */
// ============================================
// VALIDATE NAME WITH KIMI K2.5 (NVIDIA)
// ============================================
async function validateNameWithKimi(name) {
    if (!NVIDIA_API_KEY) {
        throw new Error('NVIDIA_API_KEY not configured');
    }

    const cleanName = sanitizeInput(name).trim();

    const prompt = `Role: Act as an expert in Global Onomastics (the study of names) and Forensic Linguistics.
Task: Analyze the provided "${cleanName}" to determine the likelihood that it is a legitimate human name versus a fake, bot-generated, or "keyboard-mash" string.

Evaluation Criteria:
- Cultural Plausibility: Determine if the name follows phonetic and structural patterns of any known global culture (Filipino, English, Spanish, Chinese, etc.)
- Entropy Analysis: Analyze the character distribution - real names have natural letter patterns
- Length vs. Structure: Assess if the name length is justified by cultural standards (Filipino names often have 2-3 parts: First, Middle, Last)
- Forbidden Patterns: Flag names that are placeholder text (e.g., "asdf", "test"), repeated characters (e.g., "aaaa"), or offensive content

Scoring: The score is linked if the name was real. Therefore, scoring is based on realness of the name.

Input String to Analyze: "${cleanName}"

Response Format (JSON only - no markdown, no extra text):
{
 "confidence_score": (Integer 1-100),
 "classification": "Real" | "Suspicious" | "Gibberish",
 "reasoning": "Short 1-sentence explanation of why the score was given.",
 "is_culturally_valid": (Boolean)
}

NOTE: FILTER BAD WORDS, SLANG AND OTHER INAPPROPRIATE NAMES AND SURNAMES. DECLINE NICKNAMES AND USERNAMES.`;

    try {
        const response = await axios.post(
            `${NVIDIA_BASE_URL}/chat/completions`,
            {
                model: "moonshotai/kimi-k2.5",
                messages: [
                    {
                        role: "system",
                        content: "You are an expert in Global Onomastics and Forensic Linguistics. Analyze names for legitimacy and respond only in the requested JSON format."
                    },
                    {
                        role: "user",
                        content: prompt
                    }
                ],
                max_tokens: 512,
                temperature: 0.1,
                top_p: 0.8,
                stream: false,
                chat_template_kwargs: { thinking: false }
            },
            {
                headers: {
                    'Authorization': `Bearer ${NVIDIA_API_KEY}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                timeout: 15000
            }
        );

        const textResponse = response.data?.choices?.[0]?.message?.content;
        
        if (!textResponse) {
            const rawResponse = JSON.stringify(response.data);
            throw new Error(`Empty response from Kimi. Raw response: "${rawResponse.substring(0, 500)}"`);
        }

        // Clean JSON safely
        let cleanJson = textResponse
            .replace(/```json\s*/gi, '')
            .replace(/```\s*/g, '')
            .trim();

        const jsonMatch = cleanJson.match(/\{[\s\S]*\}/);
        if (!jsonMatch) {
            throw new Error(`No JSON found in response. AI responded: "${textResponse.substring(0, 500)}"`);
        }

        let result;
        try {
            result = JSON.parse(jsonMatch[0]);
        } catch (parseError) {
            throw new Error(`Failed to parse JSON. AI responded: "${textResponse.substring(0, 500)}"`);
        }

        if (
            typeof result.confidence_score !== 'number' ||
            !result.classification ||
            !result.reasoning
        ) {
            throw new Error(`Invalid response structure from Kimi. AI responded: "${textResponse.substring(0, 500)}"`);
        }

        result.confidence_score = Math.max(1, Math.min(100, result.confidence_score));

        console.log(`[KIMI-NVIDIA] "${cleanName.substring(0, 2)}***" -> ${result.confidence_score}% (${result.classification})`);

        return {
            success: true,
            confidence_score: result.confidence_score,
            classification: result.classification,
            reasoning: result.reasoning,
            is_culturally_valid: result.is_culturally_valid ?? result.confidence_score >= 70,
            name: cleanName,
            source: 'kimi-nvidia'
        };

    } catch (error) {
        // If it's already a custom error with AI response included, re-throw it
        if (error.message && error.message.includes('AI responded:')) {
            throw error;
        }

        // Extract AI response text from various error shapes
        let aiResponseText = 'No response text available';
        
        if (error.response?.data?.choices?.[0]?.message?.content) {
            aiResponseText = error.response.data.choices[0].message.content;
        } else if (error.response?.data?.error?.message) {
            aiResponseText = error.response.data.error.message;
        } else if (error.response?.data) {
            aiResponseText = JSON.stringify(error.response.data);
        }

        console.error('[KIMI-NVIDIA ERROR]', error.response?.data || error.message);
        throw new Error(`Kimi validation failed. AI responded: "${aiResponseText.substring(0, 500)}"`);
    }
}

// ============================================
// AI NAME VALIDATION ENDPOINT (2 ATTEMPTS PER DEVICE)
// ============================================
app.post("/ai/validate-name", requireAIServiceOnly, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name || typeof name !== 'string') {
            return res.status(400).json({
                error: "Name is required",
                requires_facilitator: true,
                facilitator_message: "No name provided. Please try again or request manual verification."
            });
        }

        const limitCheck = checkDeviceLimit(req);

        if (limitCheck.limited) {
            return res.status(429).json({
                error: "Validation limit reached",
                requires_facilitator: true,
                attempts_used: limitCheck.attempts,
                facilitator_message: "You've used both validation attempts on this device. Your request will be forwarded to a technical facilitator for manual verification."
            });
        }

        trackDeviceAttempt(req);

        try {
            const validation = await validateNameWithKimi(name);
            const requiresFacilitator = validation.confidence_score < 85;

            console.log(`[AI] Device ${limitCheck.deviceId} - Attempt ${limitCheck.attempts + 1}/2 - Score: ${validation.confidence_score}%`);

            res.json({
                success: true,
                validation: {
                    ...validation,
                    requires_facilitator: requiresFacilitator,
                    attempts_used: limitCheck.attempts + 1,
                    attempts_remaining: Math.max(0, 1 - limitCheck.attempts),
                    facilitator_message: requiresFacilitator
                        ? `Since the likelihood of your name being legitimate is ${validation.confidence_score}% because ${validation.reasoning.toLowerCase()} I have to direct the verification to a technical facilitator.`
                        : `Following a successful validation with a ${validation.confidence_score}% match probability regarding ${validation.reasoning.toLowerCase()} your profile has been formally registered in the system.`
                }
            });
        } catch (geminiError) {
            console.error('[AI] Failed, directing to facilitator:', geminiError.message);

            res.status(503).json({
                error: "Validation service unavailable",
                requires_facilitator: true,
                attempts_used: limitCheck.attempts + 1,
                attempts_remaining: Math.max(0, 1 - limitCheck.attempts),
                facilitator_message: "The AI validation service is currently unavailable. Your request will be forwarded to a technical facilitator for manual verification.",
                gemini_error: process.env.NODE_ENV === 'development' ? geminiError.message : undefined
            });
        }

    } catch (error) {
        console.error('[AI VALIDATION] Error:', error);

        if (res.headersSent) return;

        res.status(500).json({
            error: "Validation failed",
            requires_facilitator: true,
            facilitator_message: "An unexpected error occurred. Your request will be forwarded to a technical facilitator for manual verification."
        });
    }
});

// ============================================
// GET DEVICE VALIDATION STATUS
// ============================================
app.get("/ai/validation-status", requireAIServiceOnly, (req, res) => {
    const status = checkDeviceLimit(req);

    res.json({
        success: true,
        attempts_used: status.attempts,
        attempts_remaining: status.remaining,
        limit: 2,
        can_validate: !status.limited,
        message: status.limited
            ? "You have used both validation attempts. Manual verification required."
            : `You have ${status.remaining} validation ${status.remaining === 1 ? 'attempt' : 'attempts'} remaining.`
    });
});

// ============================================
// MANUAL VERIFICATION SUBMISSION
// ============================================
app.post("/ai/manual-verification", requireAIServiceOnly, async (req, res) => {
    try {
        const { name, grade, section, reason, validationScore, geminiReasoning } = req.body;

        if (!name || !grade || !section) {
            return res.status(400).json({ error: "Name, grade, and section are required" });
        }

        const verificationRef = await db.collection("manual_verifications").add({
            name: sanitizeInput(name),
            grade: sanitizeInput(grade),
            section: sanitizeInput(section),
            reason: sanitizeInput(reason || 'AI flagged for manual review'),
            validationScore: validationScore || null,
            geminiReasoning: geminiReasoning || null,
            status: 'PENDING',
            submittedAt: admin.firestore.FieldValue.serverTimestamp(),
            source: 'AI_ASSISTANT'
        });

        await alertManager.createAlert(
            'script_error',
            'minor',
            '📋 Manual Verification Requested',
            `${name} (Grade ${grade}-${section}) requires manual verification.`,
            { verificationId: verificationRef.id, reason: reason || 'AI flagged', validationScore },
            24 * 60 * 60 * 1000
        );

        res.json({
            success: true,
            message: "Your request has been forwarded to a technical facilitator for manual verification.",
            verificationId: verificationRef.id
        });

    } catch (error) {
        console.error('[MANUAL VERIFICATION] Error:', error);
        res.status(500).json({ error: "Failed to submit manual verification request" });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});

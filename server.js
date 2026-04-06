const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

// --- ADD dotenv for local development ---
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// --- RENDER: Explicit Firebase Admin Initialization ---
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  })
});

const app = express();
const db = admin.firestore();

// --- CONSTANTS ---
const MULTI_POSITIONS = ["rep7", "rep8", "rep9", "rep10", "rep11", "rep12"];

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

function sanitizeString(input) {
    return sanitizeInput(input);
}

function sanitizeObject(obj) {
    return sanitizeObjectEnhanced(obj);
}

// --- SECURITY: TIMING ATTACK MITIGATION ---
async function randomDelay(minMs = 800, maxMs = 1200) {
    const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
}

// --- SECURITY: FIRESTORE-BACKED BRUTE FORCE TRACKING ---
const BRUTE_FORCE_WINDOW_MS = 15 * 60 * 1000;
const BRUTE_FORCE_MAX = 5;

async function getBruteForceDoc(ip) {
    return db.collection("brute_force").doc(ip.replace(/[:.]/g, "_"));
}

async function isIPLocked(ip) {
    try {
        const ref = await getBruteForceDoc(ip);
        const snap = await ref.get();
        if (!snap.exists) return false;
        const d = snap.data();
        const windowStart = Date.now() - BRUTE_FORCE_WINDOW_MS;
        if (d.windowStart && d.windowStart.toMillis() < windowStart) {
            await ref.delete();
            return false;
        }
        return (d.count || 0) >= BRUTE_FORCE_MAX;
    } catch { return false; }
}

async function recordFailedAttempt(ip) {
    try {
        const ref = await getBruteForceDoc(ip);
        const snap = await ref.get();
        const windowStart = Date.now() - BRUTE_FORCE_WINDOW_MS;
        if (!snap.exists || (snap.data().windowStart && snap.data().windowStart.toMillis() < windowStart)) {
            await ref.set({ count: 1, windowStart: admin.firestore.FieldValue.serverTimestamp() });
        } else {
            await ref.update({ count: admin.firestore.FieldValue.increment(1) });
        }
    } catch { }
}

async function clearBruteForce(ip) {
    try {
        const ref = await getBruteForceDoc(ip);
        await ref.delete();
    } catch { }
}

// --- SECURITY: PER-USER (LVN) BRUTE FORCE PROTECTION ---
const USER_LOCK_ATTEMPTS = 5;
const USER_LOCK_DURATION_MS = 30 * 60 * 1000;

async function getVoterBruteForceDoc(hashedLVN) {
    return db.collection("voter_brute_force").doc(hashedLVN);
}

async function isVoterLocked(hashedLVN) {
    try {
        const ref = await getVoterBruteForceDoc(hashedLVN);
        const snap = await ref.get();
        if (!snap.exists) return false;
        const d = snap.data();
        if (d.lockUntil && d.lockUntil.toMillis() > Date.now()) {
            return true;
        }
        if (d.lockUntil && d.lockUntil.toMillis() <= Date.now()) {
            await ref.delete();
            return false;
        }
        return false;
    } catch { return false; }
}

async function recordVoterFailedAttempt(hashedLVN) {
    try {
        const ref = await getVoterBruteForceDoc(hashedLVN);
        const snap = await ref.get();
        if (!snap.exists) {
            await ref.set({ 
                failedAttempts: 1, 
                lastAttempt: admin.firestore.FieldValue.serverTimestamp() 
            });
        } else {
            const d = snap.data();
            const newAttempts = (d.failedAttempts || 0) + 1;
            if (newAttempts >= USER_LOCK_ATTEMPTS) {
                const lockUntil = new Date(Date.now() + USER_LOCK_DURATION_MS);
                await ref.update({ 
                    failedAttempts: newAttempts,
                    lockUntil: admin.firestore.Timestamp.fromDate(lockUntil),
                    lastAttempt: admin.firestore.FieldValue.serverTimestamp()
                });
            } else {
                await ref.update({ 
                    failedAttempts: newAttempts,
                    lastAttempt: admin.firestore.FieldValue.serverTimestamp()
                });
            }
        }
    } catch { }
}

async function clearVoterBruteForce(hashedLVN) {
    try {
        const ref = await getVoterBruteForceDoc(hashedLVN);
        await ref.delete();
    } catch { }
}

// --- SECURITY: HASH FUNCTION FOR LVN ENCRYPTION ---
function hashLVN(lvn) {
    return crypto.createHash("sha256").update(String(lvn)).digest("hex");
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

// --- MIDDLEWARE & APP CONFIG ---
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// --- SECURITY: ENHANCED HELMET CONFIGURATION (FIXED FOR HELMET v7) ---
// Single helmet() call with all security headers
app.use(helmet({
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    contentSecurityPolicy: false // Disable default CSP, we'll set it manually below
}));

// CSP Middleware with Signed Nonce Support - HELMET v7 COMPATIBLE
app.use((req, res, next) => {
    req.cspNonce = generateNonce();
    
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", `'nonce-${req.cspNonce}'`, "https://cdnjs.cloudflare.com", "https://www.gstatic.com"],
            styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "https://identitytoolkit.googleapis.com", "https://securetoken.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "blob:", "https://firebasestorage.googleapis.com"],
            frameAncestors: ["'none'"],
            // FIX: Remove empty upgradeInsecureRequests or set to null
        },
    })(req, res, next);
});

// REMOVE THESE DUPLICATE CALLS (they were causing issues):
// app.use(helmet.referrerPolicy({ policy: 'no-referrer' }));
// app.use(helmet.crossOriginOpenerPolicy({ policy: 'same-origin' }));
// app.use(helmet.hsts({...}));

const allowedOrigins = [
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "https://tsf-sslg-election-endpoint.onrender.com",
    "https://tsf-g-digital-election.web.app",
    "https://tanauanschooloffisheries.web.app"
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("CORS Policy: Origin not allowed"), false);
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "x-csrf-token", "X-Admin-Key"],
    exposedHeaders: ["set-cookie"]
}));
app.options('/*splat', cors());

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

Object.freeze(GlobalCache.candidates);

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

async function logSuccessEvent(type, req, meta = {}) {
    try {
        await db.collection("security_logs").add({
            type: type,
            ip: req.ip || "Unknown",
            userAgent: req.headers["user-agent"] || "Unknown",
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            meta: {
                ...meta,
                role: req.user?.role || 'anonymous',
                userId: req.user?.uid || null
            },
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
        if (doc.exists) {
            const data = doc.data();
            const newCandidates = data.payload || {};
            Object.assign(GlobalCache.candidates, newCandidates);
            Object.freeze(GlobalCache.candidates);
            const ts = data.lastUpdated;
            GlobalCache.timestamps.candidates = ts && ts.toDate
                ? ts.toDate().toISOString()
                : (ts || new Date().toISOString());
            return true;
        } else {
            Object.assign(GlobalCache.candidates, {});
            Object.freeze(GlobalCache.candidates);
            return false;
        }
    } catch (err) {
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
                list.push({ ...c, votes: t.votes, breakdown: t.breakdown });
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

function generateSubmitToken() {
    const payload = `submitreview:${Math.floor(Date.now() / (10 * 60 * 1000))}`;
    return crypto.createHmac("sha256", SECRET).update(payload).digest("hex");
}

function verifySubmitToken(token) {
    if (!token) return false;
    const now = Math.floor(Date.now() / (10 * 60 * 1000));
    const payloadCurrent = `submitreview:${now}`;
    const payloadPrev = `submitreview:${now - 1}`;
    const expected1 = crypto.createHmac("sha256", SECRET).update(payloadCurrent).digest("hex");
    const expected2 = crypto.createHmac("sha256", SECRET).update(payloadPrev).digest("hex");
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected1)) ||
           crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected2));
}

// --- AUTH MIDDLEWARE ---
function verifyCSRF(req, res, next) {
    const csrfCookie = req.cookies.csrfToken;
    const csrfHeader = req.headers["x-csrf-token"] || req.headers["X-CSRF-Token"];
    if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
        logSecurityEvent("CSRF_FAILED", req, { cookie: !!csrfCookie, header: !!csrfHeader });
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    next();
}

function requireAuth(req, res, next) {
    try {
        let token = req.cookies.__session;
        if (!token && req.headers.authorization?.startsWith("Bearer ")) {
            token = req.headers.authorization.split(" ")[1];
        }
        if (!token) return res.status(401).end();
        const decoded = jwt.verify(token, SECRET);
        req.user = decoded;
        next();
    } catch {
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

const verifySecureSession = (req, res, next) => {
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
            return res.status(403).json({ error: "Session expired." });
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
        const allowedAdminEmail = process.env.ADMIN_EMAIL || "admin@tanauanschooloffisheries.web.app";
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

// --- ADMIN AUTH ROUTES ---
app.post("/admin/login", adminLoginLimiter, async (req, res) => {
    const username = sanitizeString(req.body.username || '');
    const password = req.body.password || '';
    const ip = req.ip;
    await randomDelay(800, 1200);
    if (!req.headers["user-agent"]) {
        return res.status(403).end();
    }
    if (await isIPLocked(ip)) {
        return res.status(403).json({ error: "Locked" });
    }
    const isValidUser = username === process.env.ADMIN_USER;
    let isValidPass = false;
    if (isValidUser && process.env.ADMIN_HASH) {
        isValidPass = await bcrypt.compare(password, process.env.ADMIN_HASH);
    }
    if (!isValidUser || !isValidPass) {
        await recordFailedAttempt(ip);
        await logSecurityEvent("ADMIN_LOGIN_FAILED", req, { username: username ? "***" : null, reason: "Invalid credentials" });
        return res.status(401).json({ error: "Invalid credentials" });
    }
    await clearBruteForce(ip);
    const token = jwt.sign({
        uid: "admin",
        role: "admin",
        iat: Math.floor(Date.now() / 1000)
    }, SECRET, { expiresIn: "1h" });
    res.cookie("__session", token, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/",
        maxAge: 60 * 60 * 1000
    });
    await logSecurityEvent("ADMIN_LOGIN_SUCCESS", req, { uid: "admin" });
    res.json({ success: true });
});

app.get("/admin/verify", requireAuth, requireRole("admin"), (req, res) => {
    res.json({ success: true });
});

// --- PUBLIC ROUTES ---
app.get("/settings", async (req, res) => {
    try {
        const doc = await db.collection("settings").doc("config").get();
        const statusDoc = await db.collection("settings").doc("electionStatus").get();
        const isLive = statusDoc.exists ? statusDoc.data().isLive : false;
        const statusData = statusDoc.exists ? statusDoc.data() : {};
        const config = doc.exists ? doc.data() : { voterTimeoutMinutes: 60 };
        res.json({ ...config, ...statusData, isLive, submitToken: generateSubmitToken() });
    } catch (e) {
        res.status(500).json({ error: "Settings Error" });
    }
});

app.get("/candidates", (req, res) => res.json(GlobalCache.candidates));

app.get("/dashboard", async (req, res) => {
    await refreshLocalResults();
    res.json({ ...GlobalCache.dashboard, lastUpdated: GlobalCache.timestamps.results });
});

// --- VERIFIABLE VOTING: PUBLIC BULLETIN BOARD ---
app.get("/public-receipts", async (req, res) => {
    try {
        const votesSnap = await db.collection("votes")
            .orderBy("createdAt", "asc")
            .get();
        const receipts = [];
        votesSnap.forEach((doc) => {
            const data = doc.data();
            receipts.push({
                receipt: data.receipt,
                timestamp: data.createdAt ? data.createdAt.toDate().toISOString() : null,
                hash: data.hash,
                prevHash: data.prevHash
            });
        });
        const chainInfo = await verifyHashChain();
        res.json({
            receipts: receipts,
            totalCount: receipts.length,
            chainValid: chainInfo.valid,
            chainInfo: chainInfo
        });
    } catch (e) {
        console.error("Public receipts error:", e);
        res.status(500).json({ error: "Failed to retrieve public receipts" });
    }
});

app.get("/verify-receipt/:receipt", async (req, res) => {
    try {
        const receipt = sanitizeString(req.params.receipt || '');
        if (!receipt || receipt.length !== 64) {
            return res.status(400).json({ error: "Invalid receipt format" });
        }
        const votesSnap = await db.collection("votes")
            .where("receipt", "==", receipt)
            .limit(1)
            .get();
        if (votesSnap.empty) {
            return res.json({ found: false, message: "Receipt not found" });
        }
        const voteData = votesSnap.docs[0].data();
        res.json({
            found: true,
            message: "Vote is recorded and included",
            timestamp: voteData.createdAt ? voteData.createdAt.toDate().toISOString() : null,
            hash: voteData.hash,
            prevHash: voteData.prevHash
        });
    } catch (e) {
        console.error("Verify receipt error:", e);
        res.status(500).json({ error: "Verification failed" });
    }
});

// --- VERIFIABLE VOTING: HASH CHAIN VERIFICATION ---
async function verifyHashChain() {
    try {
        const votesSnap = await db.collection("votes")
            .orderBy("createdAt", "asc")
            .get();
        const votes = [];
        votesSnap.forEach((doc) => {
            votes.push({ id: doc.id, ...doc.data() });
        });
        if (votes.length === 0) {
            return { valid: true, message: "No votes to verify", totalVotes: 0 };
        }
        let invalidCount = 0;
        let firstInvalidIndex = -1;
        for (let i = 0; i < votes.length; i++) {
            const vote = votes[i];
            const expectedPrevHash = i === 0 ? "GENESIS" : votes[i - 1].hash;
            if (vote.prevHash !== expectedPrevHash) {
                invalidCount++;
                if (firstInvalidIndex === -1) firstInvalidIndex = i;
                continue;
            }
            const expectedHash = crypto.createHash("sha256")
                .update(vote.receipt + vote.prevHash)
                .digest("hex");
            if (vote.hash !== expectedHash) {
                invalidCount++;
                if (firstInvalidIndex === -1) firstInvalidIndex = i;
            }
        }
        return {
            valid: invalidCount === 0,
            totalVotes: votes.length,
            invalidCount: invalidCount,
            firstInvalidIndex: firstInvalidIndex,
            message: invalidCount === 0 ? "Hash chain integrity verified" : `Hash chain broken at ${invalidCount} position(s)`
        };
    } catch (e) {
        return { valid: false, message: "Verification error: " + e.message };
    }
}

app.get("/admin/verify-chain", requireAuth, requireRole("admin"), async (req, res) => {
    try {
        const chainInfo = await verifyHashChain();
        await logSuccessEvent("ADMIN_VERIFY_CHAIN", req, chainInfo);
        res.json(chainInfo);
    } catch (e) {
        res.status(500).json({ error: "Chain verification failed" });
    }
});

app.post("/verify", loginLimiter, async (req, res) => {
    try {
        const lvn = sanitizeString(req.body.lvn || '');
        const code = sanitizeString(req.body.code || '');
        if (!lvn || !code) return res.status(400).json({ error: "Missing credentials." });
        const hashedLVN = hashLVN(lvn);
        if (await isVoterLocked(hashedLVN)) {
            return res.status(403).json({ error: "Account temporarily locked due to multiple failed attempts. Please try again later." });
        }
        const ua = (req.headers["user-agent"] || "").replace(/\s+/g, " ").trim().toLowerCase();
        const deviceFingerprint = crypto.createHash("sha256")
            .update(`${req.ip}|${ua}`)
            .digest("hex");
        const deviceRef = db.collection("device_tracking").doc(deviceFingerprint);
        const deviceSnap = await deviceRef.get();
        if (deviceSnap.exists) {
            const usedLvns = deviceSnap.data().lvns || [];
            if (!usedLvns.includes(hashedLVN)) {
                if (usedLvns.length >= 3) { 
                    return res.status(403).json({ error: "Device Limit Reached: Maximum 3 voters allowed per device." });
                }
            }
        }
        const settingsSnap = await db.collection("settings").doc("electionStatus").get();
        const voterRef = db.collection("voters").doc(hashedLVN);
        const voterSnap = await voterRef.get();
        if (!voterSnap.exists) {
            await recordVoterFailedAttempt(hashedLVN);
            await logSecurityEvent("FAILED_LOGIN", req, { reason: "Invalid LVN" });
            await checkAbuse(req.ip);
            return res.status(401).json({ error: "Invalid Credentials." });
        }
        const d = voterSnap.data();
        const inputCode = code.toUpperCase();
        const storedCode = String(d.code || "").toUpperCase().trim();
        if (storedCode !== inputCode) {
            await recordVoterFailedAttempt(hashedLVN);
            await logSecurityEvent("FAILED_LOGIN", req, { reason: "Invalid code" });
            await checkAbuse(req.ip);
            return res.status(401).json({ error: "Invalid Credentials." });
        }
        if (d.isMissed === true) {
            return res.status(403).json({ error: "Voting Session Expired: You missed the cutoff time." });
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
            return res.json({ name: "JOHN DOE (TEST)", grade: "12", token: fakeToken, csrfToken: "" });
        }
        if (!settingsSnap.exists || !settingsSnap.data().isLive) {
            return res.status(403).json({ error: "Election PAUSED." });
        }
        if (d.hasVoted) {
            await logSecurityEvent("DUPLICATE_VOTE_ATTEMPT", req, { hashedLVN });
            return res.status(403).json({ error: "Already Voted." });
        }
        const activeGrade = settingsSnap.data().activeGrade;
        if (activeGrade && String(activeGrade) !== "ALL" && String(activeGrade) !== "0") {
            if (String(d.grade) !== String(activeGrade)) {
                return res.status(403).json({ error: `Grade ${activeGrade} Only.` });
            }
        }
        await deviceRef.set({
            lvns: admin.firestore.FieldValue.arrayUnion(hashedLVN),
            lastLogin: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        res.cookie("__device_id", deviceFingerprint, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            path: "/",
            maxAge: 365 * 24 * 60 * 60 * 1000
        });
        await clearVoterBruteForce(hashedLVN);
        const sessionToken = jwt.sign(
            { uid: hashedLVN, grade: d.grade, role: "voter", iat: Math.floor(Date.now() / 1000) },
            SECRET,
            { expiresIn: "60m" }
        );
        res.cookie("__session", sessionToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            path: "/",
            maxAge: 60 * 60 * 1000
        });
        const csrfToken = crypto.randomBytes(32).toString('hex');
        res.cookie("csrfToken", csrfToken, {
            httpOnly: false,
            secure: true,
            sameSite: "strict",
            path: "/"
        });
        return res.json({ success: true, name: d.name, grade: d.grade, token: sessionToken, csrfToken });
    } catch (e) {
        return res.status(500).json({ error: "Server error during verification." });
    }
});

// --- VOTE ROUTE ---
app.post("/vote", voteLimiter, verifyCSRF, requireAuth, requireRole("voter"), async (req, res) => {
    const hashedLVN = req.user.uid;
    const grade = req.user.grade;
    const { selections } = req.body;
    if (!selections || typeof selections !== 'object') {
        return res.status(400).json({ error: "Invalid ballot format." });
    }
    try {
        const settings = await db.collection("settings").doc("electionStatus").get();
        if (!settings.exists || !settings.data().isLive) {
            return res.status(403).json({ error: "Election closed." });
        }
        if (settings.data().endTime && Date.now() > settings.data().endTime.toMillis()) {
            return res.status(403).json({ error: "Voting period ended." });
        }
        const voterRef = db.collection("voters").doc(hashedLVN);
        const voterSnap = await voterRef.get();
        if (!voterSnap.exists) {
            return res.status(403).json({ error: "Voter not found." });
        }
        const voter = voterSnap.data();
        if (voter.hasVoted) {
            await logSecurityEvent("DUPLICATE_VOTE_ATTEMPT", req, { hashedLVN });
            return res.status(403).json({ error: "Already voted." });
        }
        if (Object.keys(GlobalCache.candidates).length === 0) await refreshLocalCandidates();
        const validSelections = {};
        const { allowedRep, isAllowed } = buildAllowedPositionsForGrade(grade);
        const allowedPositions = Object.keys(GlobalCache.candidates).filter(isAllowed);
        const repLabel = allowedRep ? `Grade ${String(allowedRep).replace('rep', '')} Representative` : "no grade-level representatives";
        for (const repId of MULTI_POSITIONS) {
            if (!allowedRep || repId !== allowedRep) {
                if (Object.prototype.hasOwnProperty.call(selections, repId)) {
                    return res.status(403).json({ error: `Not allowed: Your grade can only vote for ${repLabel}.` });
                }
            }
        }
        for (const position of allowedPositions) {
            let userSelection = selections[position];
            const availableCandidates = GlobalCache.candidates[position] || [];
            const availCount = availableCandidates.length;
            if (availCount === 0) continue;
            if (MULTI_POSITIONS.includes(position)) {
                if (!Array.isArray(userSelection)) {
                    userSelection = userSelection ? [userSelection] : [];
                }
                for (const selId of userSelection) {
                    const exists = availableCandidates.some(c => String(c.id) === String(selId));
                    if (!exists) return res.status(400).json({ error: `Invalid candidate selected for ${position}.` });
                }
                if (availCount >= 2) {
                    if (userSelection.length !== 2) {
                        return res.status(400).json({ error: `${position}: You must select exactly 2 candidates.` });
                    }
                } else if (availCount === 1) {
                    if (userSelection.length !== 1) {
                        return res.status(400).json({ error: `${position}: You must select the candidate.` });
                    }
                }
                validSelections[position] = userSelection;
            } else {
                if (Array.isArray(userSelection)) return res.status(400).json({ error: `Multiple selections not allowed for ${position}.` });
                if (!userSelection) return res.status(400).json({ error: `Missing selection for ${position}.` });
                const candidateExists = availableCandidates.some(c => String(c.id) === String(userSelection));
                if (!candidateExists) {
                    return res.status(400).json({ error: `Invalid candidate selected for ${position}.` });
                }
                validSelections[position] = String(userSelection);
            }
        }
        if (Object.keys(validSelections).length === 0) {
            return res.status(400).json({ error: "No valid selections provided." });
        }
        const voteResult = await db.runTransaction(async (t) => {
            const settingsRef = db.collection("settings").doc("electionStatus");
            const settingsSnap = await t.get(settingsRef);
            if (!settingsSnap.exists || !settingsSnap.data().isLive) throw new Error("PAUSED");
            const voterRef = db.collection("voters").doc(hashedLVN);
            const voterDoc = await t.get(voterRef);
            if (!voterDoc.exists) throw new Error("VOTER_NOT_FOUND");
            if (voterDoc.data().hasVoted) throw new Error("ALREADY_VOTED");
            const latestVoteQuery = await db.collection("votes")
                .orderBy("createdAt", "desc")
                .limit(1)
                .get();
            const prevHash = latestVoteQuery.empty ? "GENESIS" : latestVoteQuery.docs[0].data().hash;
            const randomSalt = crypto.randomBytes(32).toString('hex');
            const serverTimestamp = admin.firestore.FieldValue.serverTimestamp();
            const timestampMs = Date.now();
            const payload = JSON.stringify({
                voter_hash: hashedLVN,
                selected_candidates: validSelections,
                timestamp: timestampMs
            });
            const receipt = crypto.createHash("sha256")
                .update(payload + randomSalt)
                .digest("hex");
            const currentHash = crypto.createHash("sha256")
                .update(receipt + prevHash)
                .digest("hex");
            const voteRef = db.collection("votes").doc();
            t.set(voteRef, {
                selections: validSelections,
                grade: String(grade),
                createdAt: serverTimestamp,
                receipt: receipt,
                hash: currentHash,
                prevHash: prevHash,
                salt: randomSalt
            });
            t.update(voterRef, {
                hasVoted: true,
                votedAt: serverTimestamp,
                receipt: receipt
            });
            return { receipt, currentHash, prevHash, timestamp: timestampMs };
        });
        await logSuccessEvent("VOTE_CAST", req, { receipt: voteResult.receipt.substring(0, 16) + '...', grade: grade });
        res.json({ success: true, receipt: voteResult.receipt, hash: voteResult.currentHash, prevHash: voteResult.prevHash });
    } catch (e) {
        if (e.message === "ALREADY_VOTED") return res.status(403).json({ error: "Our records show you have already cast your vote." });
        if (e.message === "PAUSED") return res.status(403).json({ error: "The election is currently paused by the administrator." });
        console.error("Vote error:", e);
        res.status(500).json({ error: "System failed to record vote. Please notify a facilitator." });
    }
});

app.post("/submit-review", submitReviewLimiter, submissionLimiter, async (req, res) => {
    const submitToken = req.headers["x-submit-token"] || req.body._submitToken;
    if (!verifySubmitToken(submitToken)) {
        await logSecurityEvent("SUBMIT_REVIEW_UNAUTHORIZED", req, { reason: "Missing or invalid submit token" });
        return res.status(403).json({ error: "Unauthorized: Invalid session token." });
    }
    const grade = sanitizeString(req.body.grade || '');
    const section = sanitizeString(req.body.section || '');
    const encoder = sanitizeString(req.body.encoder || '');
    const names = Array.isArray(req.body.names) ? req.body.names.map(n => sanitizeString(n)) : [];
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
        const [votersSnap, votesSnap] = await Promise.all([
            db.collection("voters").get(),
            db.collection("votes").select("receipt").get()
        ]);
        const validReceipts = new Set();
        votesSnap.forEach(doc => {
            const d = doc.data();
            if (d.receipt) validReceipts.add(d.receipt);
        });
        const voters = [];
        votersSnap.forEach(doc => {
            const v = doc.data();
            let integrityStatus = "PENDING";
            if (v.isMissed) {
                integrityStatus = "MISSED";
            } else if (v.hasVoted) {
                if (!v.receipt || !validReceipts.has(v.receipt)) {
                    integrityStatus = "INVALID";
                } else {
                    integrityStatus = "VOTED";
                }
            }
            voters.push({ 
                lvn: v.lvn || "***",
                name: v.name,
                grade: v.grade,
                section: v.section,
                hasVoted: v.hasVoted,
                isMissed: v.isMissed,
                integrityStatus 
            });
        });
        await logSuccessEvent("ADMIN_VIEW_VOTERS", req, { count: voters.length });
        res.json(voters);
    } catch (e) {
        res.status(500).json({ error: "Failed to fetch voters" });
    }
});

app.post("/admin/voters/add", async (req, res) => {
    const grade = sanitizeString(req.body.grade || '');
    const section = sanitizeString(req.body.section || '');
    const names = Array.isArray(req.body.names) ? req.body.names.map(n => sanitizeString(n)) : [];
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
            if (existingMap[cleanName]) {
                batch.update(existingMap[cleanName], {
                    grade: targetGrade,
                    section: section.toUpperCase(),
                    code: accessCode,
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                updatedCount++;
            } else {
                const randomSuffix = Math.floor(1000000 + Math.random() * 9000000).toString();
                const lvn = `${gradePrefix}${sectionPrefix}${randomSuffix}`;
                const hashedLVN = hashLVN(lvn);
                const existingLvnSnap = await db.collection("voters").doc(hashedLVN).get();
                if (existingLvnSnap.exists) continue;
                const voterRef = db.collection("voters").doc(hashedLVN);
                batch.set(voterRef, {
                    lvn: lvn,
                    name: cleanName,
                    grade: targetGrade,
                    section: section.toUpperCase(),
                    code: accessCode,
                    hasVoted: false,
                    addedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                addedCount++;
            }
        }
        await batch.commit();
        await logAdminAction(req, "VOTERS_UPSERT", {
            grade: targetGrade,
            section: section.toUpperCase(),
            totalProvided: names.length,
            updated: updatedCount,
            added: addedCount,
            accessCode: accessCode,
        });
        await logSuccessEvent("ADMIN_ADD_VOTERS", req, { grade: targetGrade, added: addedCount, updated: updatedCount });
        res.json({ success: true, message: `Processed ${names.length}. Promoted/Updated: ${updatedCount}, New: ${addedCount}`, accessCode: accessCode });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/admin/voters/delete", async (req, res) => {
    try {
        const lvn = sanitizeString(req.body.lvn || '');
        if (!lvn) return res.status(400).json({ error: "LVN required" });
        const hashedLVN = hashLVN(lvn);
        const voterRef = db.collection("voters").doc(hashedLVN);
        const voterSnap = await voterRef.get();
        if (!voterSnap.exists) return res.status(404).json({ error: "Voter not found." });
        const voterData = voterSnap.data();
        if (voterData.hasVoted) {
            await voterRef.update({
                _deleted: true,
                _deletedAt: admin.firestore.FieldValue.serverTimestamp(),
                name: "[REMOVED]",
                lvn: admin.firestore.FieldValue.delete(),
                code: admin.firestore.FieldValue.delete(),
            });
            await logAdminAction(req, "VOTER_SOFT_DELETE", { lvn: "***", reason: "Has voted — receipt preserved" });
            await logSuccessEvent("ADMIN_DELETE_VOTER", req, { lvn: "***", method: "soft" });
            return res.json({ success: true, note: "Voter soft-deleted. Vote record remains intact for integrity." });
        }
        await voterRef.delete();
        await logAdminAction(req, "VOTER_DELETE", { lvn: "***" });
        await logSuccessEvent("ADMIN_DELETE_VOTER", req, { lvn: "***", method: "hard" });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Delete failed" });
    }
});

app.post("/admin/voters/reset", async (req, res) => {
    try {
        const lvn = sanitizeString(req.body.lvn || '');
        if (!lvn) return res.status(400).json({ error: "LVN required" });
        const hashedLVN = hashLVN(lvn);
        await db.collection("voters").doc(hashedLVN).update({
            hasVoted: false,
            receipt: admin.firestore.FieldValue.delete(),
            votedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        await logAdminAction(req, "VOTER_RESET", { lvn: "***" });
        await logSuccessEvent("ADMIN_RESET_VOTER", req, { lvn: "***" });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Reset failed" });
    }
});

app.post("/admin/settings/session", async (req, res) => {
    try {
        const voterTime = req.body.voterTime;
        const activeGrade = req.body.activeGrade;
        const isLive = req.body.isLive;
        const statusUpdate = {};
        if (typeof isLive === 'boolean') statusUpdate.isLive = isLive;
        if (activeGrade !== undefined) {
            statusUpdate.activeGrade = (activeGrade === "ALL") ? "ALL" : Number(activeGrade);
        }
        if (voterTime && !isNaN(voterTime) && Number(voterTime) > 0) {
            const minutes = Number(voterTime);
            const futureDate = new Date(Date.now() + (minutes * 60 * 1000));
            statusUpdate.sessionTimer = admin.firestore.Timestamp.fromDate(futureDate);
        } else if (voterTime == 0) {
            statusUpdate.sessionTimer = admin.firestore.FieldValue.delete();
        }
        await db.collection("settings").doc("electionStatus").set(statusUpdate, { merge: true });
        const now = admin.firestore.FieldValue.serverTimestamp();
        await db.collection("app_config").doc("candidates_static").set({ lastUpdated: now }, { merge: true });
        const resultsConfig = { lastUpdated: now };
        if (typeof isLive === 'boolean') resultsConfig.isLive = isLive;
        await db.collection("app_config").doc("results_public").set(resultsConfig, { merge: true });
        if (typeof isLive === 'boolean') GlobalCache.dashboard.isLive = isLive;
        await logAdminAction(req, "SET_ELECTION_SESSION", {
            isLive: typeof isLive === 'boolean' ? isLive : null,
            activeGrade: activeGrade !== undefined ? activeGrade : null,
            voterTime: voterTime !== undefined ? voterTime : null,
        });
        await logSuccessEvent("ADMIN_SET_SESSION", req, { isLive: typeof isLive === 'boolean' ? isLive : null, activeGrade: activeGrade !== undefined ? activeGrade : null });
        res.json({ success: true, isLive, activeGrade });
    } catch (e) {
        res.status(500).json({ error: "Failed to update election status" });
    }
});

app.post("/admin/settings/timers", async (req, res) => {
    const voterTime = req.body.voterTime;
    try {
        await db.collection("settings").doc("config").set({
            voterTimeoutMinutes: parseInt(voterTime) || 60,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        await logAdminAction(req, "SET_VOTER_TIMEOUT", { voterTimeoutMinutes: parseInt(voterTime) || 60 });
        await logSuccessEvent("ADMIN_SET_TIMERS", req, { voterTimeoutMinutes: parseInt(voterTime) || 60 });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Failed to save timer settings" });
    }
});

app.post("/admin/purge", async (req, res) => {
    try {
        await logAdminAction(req, "PURGE_ELECTION_DATA", { initiated: true });
        await purgeElectionData();
        await logSuccessEvent("ADMIN_PURGE_DATA", req, { success: true });
        res.json({ success: true, message: "Election data purged successfully." });
    } catch (e) {
        res.status(500).json({ error: "Purge failed: " + e.message });
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
        await logSuccessEvent("ADMIN_RETALLY", req, { validVotes: validVotesCount, orphanedVotes: orphanedVotesCount });
        res.json({ success: true, message: `Re-tally complete. Database updated. Valid Votes: ${validVotesCount}, Invalid Votes: ${orphanedVotesCount}.` });
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
            await logSuccessEvent("ADMIN_PUBLISH_CANDIDATES", req, { success: true });
            res.json({ success: true, message: "Candidates published successfully." });
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
        await logSuccessEvent("ADMIN_PUBLISH_RESULTS", req, { success: true });
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
        position: sanitizeString(c.position || ''),
        id: sanitizeString(c.id || ''),
        name: sanitizeString(c.name || ''),
        party: sanitizeString(c.party || ''),
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
        await logSuccessEvent("ADMIN_ADD_PARTY", req, { success: true });
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.post("/admin/delete", async (req, res) => {
    const position = sanitizeString(req.body.position || '');
    const candidateId = sanitizeString(req.body.candidateId || '');
    const partyName = sanitizeString(req.body.partyName || '');
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
            await logSuccessEvent("ADMIN_DELETE_PARTY", req, { partyName });
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
            await logSuccessEvent("ADMIN_DELETE_CANDIDATE", req, { position, candidateId });
            return res.json({ success: true });
        }
        res.status(400).json({ error: "Bad Params" });
    } catch (e) { 
        res.status(500).json({ error: e.message }); 
    }
});

app.post("/admin/election/reset", async (req, res) => {
    const confirmation = sanitizeString(req.body.confirmation || '');
    if (confirmation !== "DELETE ELECTION DATA") return res.status(403).json({ error: "Security Mismatch." });
    try {
        await db.collection("security_logs").add({
            event: "ELECTION_RESET",
            admin_email: req.user.email,
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
        await logSuccessEvent("ADMIN_ELECTION_RESET", req, { success: true });
        res.json({ success: true, message: "Election system successfully reset." });
    } catch (e) {
        res.status(500).json({ error: "Reset failed partially. Check logs." });
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
        const batch = db.batch();
        let count = 0;
        snapshot.forEach(doc => {
            if (!doc.data().isMissed) {
                batch.update(doc.ref, {
                    isMissed: true,
                    missedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                count++;
            }
        });
        if (count > 0) await batch.commit();
        await logAdminAction(req, "SESSION_END", { count });
        await logSuccessEvent("ADMIN_SESSION_END", req, { count });
        res.json({ success: true, count });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/admin/voters/reset-missed", async (req, res) => {
    try {
        const lvn = sanitizeString(req.body.lvn || '');
        if (!lvn) return res.status(400).json({ error: "LVN required" });
        const hashedLVN = hashLVN(lvn);
        await db.collection("voters").doc(hashedLVN).update({
            isMissed: false,
            missedAt: admin.firestore.FieldValue.delete()
        });
        await logAdminAction(req, "RESET_MISSED", { lvn: "***" });
        await logSuccessEvent("ADMIN_RESET_MISSED", req, { lvn: "***" });
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
        await logSuccessEvent("ADMIN_VIEW_SUBMISSIONS", req, { count: submissions.length });
        res.json({ sy: sy, lastUpdated: lastUpdated, submissions: submissions });
    } catch (e) {
        res.status(500).json({ error: "Failed to load submissions." });
    }
});

// --- RENDER SERVERLESS EXPORT ---
module.exports = app;

// --- LOCAL DEVELOPMENT FALLBACK ---
// Only start server if running locally (not on Render)
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

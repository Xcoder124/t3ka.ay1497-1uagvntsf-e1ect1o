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
console.log("JWT_SECRET exists:", !!process.env.JWT_SECRET);
console.log("ADMIN_KEY exists:", !!process.env.ADMIN_KEY);
console.log("GITHUB_REPO exists:", !!process.env.GITHUB_REPO);
console.log("GITHUB_TOKEN exists:", !!process.env.GITHUB_TOKEN);

const app = express();
let activeUsers = 0;

app.use((req, res, next) => {
    activeUsers++;
    const decrement = () => { activeUsers = Math.max(0, activeUsers - 1); };
    res.on("finish", decrement);
    res.on("close", decrement);
    res.on("error", decrement);
    next();
});

const db = admin.firestore();

// GLOBAL VARIABLES
const MAX_ATTEMPTS = 3;
const LOCK_TIME = 30 * 1000; // 30 sec
const AUDIT_CHAIN_DOC = db.collection("_meta").doc("chain_head");

(async () => {
    try {
        await refreshLocalResults();
        console.log("Dashboard cache warmed up");
    } catch (err) {
        console.error("Initial dashboard load failed:", err);
    }
})();

setInterval(async () => {
    try {
        await refreshLocalResults();
    } catch (err) {
        console.error("Background dashboard refresh failed:", err);
    }
}, 2 * 60 * 1000);

async function checkLoginAttempts(deviceId) {
    const ref = db.collection("login_attempts").doc(deviceId);
    const snap = await ref.get();

    if (!snap.exists) return { allowed: true };

    const data = snap.data();

    if (data.lockUntil && data.lockUntil.toMillis() > Date.now()) {
        return {
            allowed: false,
            message: "Too many attempts. Try again in 30 seconds."
        };
    }

    return { allowed: true, attempts: data.attempts || 0 };
}

async function recordLoginAttempt(deviceId, success) {
    const ref = db.collection("login_attempts").doc(deviceId);
    const snap = await ref.get();

    if (success) {
        await ref.delete();
        return;
    }

    let attempts = 1;

    if (snap.exists) {
        attempts = (snap.data().attempts || 0) + 1;
    }

    const data = {
        attempts,
        lastAttempt: admin.firestore.FieldValue.serverTimestamp()
    };

    if (attempts >= MAX_ATTEMPTS) {
        data.lockUntil = admin.firestore.Timestamp.fromMillis(Date.now() + LOCK_TIME);
    }

    await ref.set(data, { merge: true });
}

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

async function isNonceUsed(nonce) {
    const doc = await db.collection("used_nonces").doc(nonce).get();
    return doc.exists;
}

async function markNonceUsed(nonce) {
    await db.collection("used_nonces").doc(nonce).set({
        usedAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

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
}, 30000);

async function joinQueue(userId) {
    const queueRef = rtdb.ref('queue');

    await queueRef.transaction(current => {
        // Initialise if empty
        current = current || {
            activeCount: 0,
            maxActive: 50,
            lastPosition: 0,
            users: {}
        };

        // If user already exists and status is 'done', do nothing
        if (current.users[userId] && current.users[userId].status === 'done') {
            return; // abort transaction
        }

        // Assign new position
        const newPosition = current.lastPosition + 1;

        // Determine status based on available slots
        let newStatus = 'waiting';
        let newActiveCount = current.activeCount;
        if (current.activeCount < current.maxActive) {
            newStatus = 'active';
            newActiveCount++;
        }

        // Update user record
        current.users[userId] = {
            position: newPosition,
            status: newStatus,
            joinedAt: admin.database.ServerValue.TIMESTAMP
        };

        // Update global counters
        current.activeCount = newActiveCount;
        current.lastPosition = newPosition;

        return current;
    });
}

function calculateETA(position, currentServing, maxActive = 50, avgTime = 2) {
    const peopleAhead = position - (currentServing + maxActive);

    if (peopleAhead <= 0) return "You're next!";

    const batches = Math.ceil(peopleAhead / maxActive);
    return `${batches * avgTime} mins`;
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
        await alertManager.detectCandidatesStatus();
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
    CANDIDATES_EMPTY: { type: 'candidates_empty', level: 'critical', autoExpire: null },
    CANDIDATE_PUBLISH_FAILED: { type: 'candidate_publish_failed', level: 'major', autoExpire: null },

    // Security alerts
    BRUTE_FORCE: { type: 'bruteforce', level: 'major', autoExpire: null },
    TAMPER_DETECTED: { type: 'tamper', level: 'critical', autoExpire: null },
    UNAUTHORIZED_ACCESS: { type: 'unauthorized', level: 'major', autoExpire: null },

    // Data integrity alerts
    HASH_CHAIN_BROKEN: { type: 'hash_chain', level: 'critical', autoExpire: null },
    INVALID_VOTES_DETECTED: { type: 'invalid_votes', level: 'major', autoExpire: null },
    VOTE_INTEGRITY_FAIL: { type: 'vote_integrity', level: 'critical', autoExpire: null },

    // API/Backend errors
    API_ERROR: { type: 'api_error', level: 'major', autoExpire: 30 * 60 * 1000 },
    DATABASE_ERROR: { type: 'database_error', level: 'critical', autoExpire: null },
    FIREBASE_ERROR: { type: 'firebase_error', level: 'critical', autoExpire: null },
    ELECTION_DATA_DELETED: { type: 'election_deleted', level: 'major', autoExpire: null },

    // Frontend/Script errors (reported from client)
    SCRIPT_ERROR: { type: 'script_error', level: 'major', autoExpire: 60 * 60 * 1000 },
    CLIENT_API_ERROR: { type: 'client_api_error', level: 'minor', autoExpire: 30 * 60 * 1000 },
    RENDER_ERROR: { type: 'render_error', level: 'major', autoExpire: null },

    // Configuration alerts
    CONFIG_MISSING: { type: 'config_missing', level: 'critical', autoExpire: null },
    ENV_ERROR: { type: 'env_error', level: 'critical', autoExpire: null },

    // Election status alerts
    ELECTION_PAUSED: { type: 'election_paused', level: 'normal', autoExpire: null },
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
    candidates_empty: {
        fixSteps: [
            "Add candidates through Candidates Entry tab",
            "Ensure all positions have at least one candidate",
            "Publish candidates after adding"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: No candidates available for voting. Contact developer immediately if candidates were previously added."
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
    bruteforce: {
        fixSteps: [
            "Verify if authorized user is having login issues",
            "Check security logs for IP address",
            "Consider blocking suspicious IPs"
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
    hash_chain: {
        fixSteps: [
            "Run 'Re-Tally Votes' from Settings",
            "Verify vote integrity",
            "Contact developer if issue persists"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Vote hash chain integrity compromised. Contact developer immediately before proceeding."
    },
    invalid_votes: {
        fixSteps: [
            "Run 'Re-Tally Votes' from Settings",
            "Review invalid voter records",
            "Reset invalid voters if needed"
        ],
        developerFix: false,
        contactMessage: null
    },
    vote_integrity: {
        fixSteps: [
            "STOP election immediately",
            "Run 'Re-Tally Votes'",
            "Contact developer if issue persists"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Vote integrity check failed. Contact developer immediately."
    },
    api_error: {
        fixSteps: [
            "Check server status",
            "Verify network connectivity",
            "Check API endpoint configuration"
        ],
        developerFix: false,
        contactMessage: null
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
    script_error: {
        fixSteps: [
            "Refresh the page",
            "Clear browser cache",
            "Try a different browser"
        ],
        developerFix: false,
        contactMessage: null
    },
    client_api_error: {
        fixSteps: [
            "Check internet connection",
            "Refresh the page",
            "Try again in a few minutes"
        ],
        developerFix: false,
        contactMessage: null
    },
    render_error: {
        fixSteps: [
            "Refresh the page",
            "Check browser console for errors",
            "Clear browser cache"
        ],
        developerFix: true,
        contactMessage: "Frontend rendering error detected. Contact developer if issue persists."
    },
    config_missing: {
        fixSteps: [
            "Check environment variables",
            "Verify configuration files",
            "Restart server after fixing"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Required configuration missing. Contact developer immediately."
    },
    env_error: {
        fixSteps: [
            "Check .env file or environment variables",
            "Verify all required variables are set",
            "Restart server after fixing"
        ],
        developerFix: true,
        contactMessage: "CRITICAL: Environment configuration error. Contact developer immediately."
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
    unauthorized: {
        fixSteps: [
            "Verify user permissions",
            "Check admin credentials",
            "Review access logs"
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

    async findSimilarAlert(type, message) {
        try {
            const fiveMinutesAgo = admin.firestore.Timestamp.fromMillis(Date.now() - 5 * 60 * 1000);
            const snapshot = await db.collection("system_alerts")
                .where("type", "==", type)
                .where("active", "==", true)
                .where("createdAt", ">", fiveMinutesAgo)
                .limit(1)
                .get();

            if (!snapshot.empty) {
                return { id: snapshot.docs[0].id, ...snapshot.docs[0].data() };
            }
            return null;
        } catch (e) {
            return null;
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

    async hasUnacknowledgedIgnoredAlerts() {
        // Check if there are alerts that were dismissed but not fixed
        try {
            const snapshot = await db.collection("alert_logs")
                .where("fixInstructions.developerFix", "==", true)
                .where("fixInstructions.contacted", "!=", true)
                .limit(1)
                .get();

            return !snapshot.empty;
        } catch (e) {
            return false;
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

            if (totalCandidates === 0) {
                await this.createAlert(
                    'candidates_empty',
                    'critical',
                    'No Candidates Found',
                    'The candidates database is empty. Voting cannot proceed.',
                    { totalCandidates },
                    null
                );
            }

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
                    'hash_chain',
                    'critical',
                    'Vote Integrity Compromised',
                    `Hash chain verification failed. ${chainInfo.invalidCount} invalid vote(s) detected.`,
                    chainInfo,
                    null
                );
            } else {
                await this.clearResolvedAlerts('hash_chain');
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

            if (orphanedCount > 0) {
                await this.createAlert(
                    'invalid_votes',
                    'major',
                    'Invalid Votes Detected',
                    `${orphanedCount} vote(s) without valid voter.`,
                    { orphanedCount },
                    null
                );
            } else {
                await this.clearResolvedAlerts('invalid_votes');
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

    async detectSystemHealth() {
        try {
            const start = Date.now();
            await db.collection("settings").doc("config").get();
            const latency = Date.now() - start;

            if (latency > 1000) {
                await this.createAlert(
                    'api_error',
                    'major',
                    'Slow Database Response',
                    `Database response time is ${latency}ms... This might be a cause of too much requests due to large amount of students accessing the site at the same time.`,
                    { latency },
                    10 * 60 * 1000
                );
            } else {
                await this.clearResolvedAlerts('api_error');
            }

            const testSnap = await db.collection("candidates").limit(1).get();

            if (testSnap.empty) {
                await this.createAlert(
                    'database_error',
                    'critical',
                    'Database Read Failure',
                    'Unable to read from candidates collection. Contact the developer to fix this issue.',
                    {},
                    null
                );
            }

            const requiredEnv = [
                'FIREBASE_PROJECT_ID',
                'FIREBASE_CLIENT_EMAIL',
                'FIREBASE_PRIVATE_KEY',
                'JWT_SECRET',
                'ADMIN_KEY'
            ];

            const missingEnv = requiredEnv.filter(key => !process.env[key]);
            if (missingEnv.length > 0) {
                await this.createAlert(
                    'env_error',
                    'critical',
                    'Environment Configuration Error',
                    `Missing: ${missingEnv.join(', ')} contact the developer for re-check of environment rules.`,
                    { missingEnv },
                    null
                );
            } else {
                await this.clearResolvedAlerts('env_error');
            }

            await this.clearResolvedAlerts('firebase_error');
            await this.clearResolvedAlerts('database_error');

            return { success: true };
        } catch (e) {
            await this.createAlert(
                'firebase_error',
                'critical',
                'Firebase Connection Failed',
                `Unable to connect to Firebase: ${e.message}`,
                { error: e.message },
                null
            );
            return { success: false, error: e.message };
        }
    }
}

const alertManager = new AlertManager();

// Legacy function for backward compatibility
async function createAlert(type, level, title, message, meta = {}, expiresInMs = null) {
    return alertManager.createAlert(type, level, title, message, meta, expiresInMs);
}

// Scheduled monitoring
setInterval(async () => {
    if (activeUsers >= 2) { // TESTING
        await alertManager.createAlert(
            "high_load",
            "critical",
            "Voting Session Critical Load",
            `Total of ${activeUsers} students are currently voting. System is under heavy stress and may slow down.`,
            { activeUsers },
            5 * 60 * 1000
        );
    }
    else if (activeUsers >= 1) {
        await alertManager.createAlert(
            'high_load',
            'major',
            'Voting Session High Traffic',
            `Total of ${activeUsers} students are on voting session. Exceeding 500 may affect connectivity. Consider activating Queue System.`,
            { activeUsers },
            5 * 60 * 1000
        );
    }

    else {
        await alertManager.clearResolvedAlerts('high_load');
    }

}, 30000);

// Run comprehensive checks every 30 seconds
setInterval(async () => {
    await alertManager.detectCandidatesStatus();
    await alertManager.detectVoteIntegrity();
}, 120000);

// Initial system health check
setTimeout(async () => {
    await alertManager.detectSystemHealth();
    await alertManager.detectCandidatesStatus();
    await alertManager.detectVoteIntegrity();
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

function getDeviceBruteForceDoc(deviceId) {
    return db.collection("device_brute_force").doc(deviceId);
}

async function recordDeviceAttempt(deviceId) {
    const ref = getDeviceBruteForceDoc(deviceId);
    const snap = await ref.get();

    if (!snap.exists) {
        await ref.set({
            attempts: 1,
            lastAttempt: admin.firestore.FieldValue.serverTimestamp()
        });
    } else {
        const attempts = (snap.data().attempts || 0) + 1;

        if (attempts >= 5) {
            await ref.update({
                attempts,
                lockUntil: admin.firestore.Timestamp.fromMillis(Date.now() + 30 * 60 * 1000)
            });
        } else {
            await ref.update({ attempts });
        }
    }
}

async function isDeviceLocked(deviceId) {
    const ref = getDeviceBruteForceDoc(deviceId);
    const snap = await ref.get();

    if (!snap.exists) return false;

    const data = snap.data();

    if (data.lockUntil && data.lockUntil.toMillis() > Date.now()) {
        return true;
    }

    return false;
}

async function clearBruteForce(deviceId) {
    try {
        const ref = await getDeviceBruteForceDoc(deviceId);
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

// --- MIDDLEWARE & APP CONFIG ---
app.set('trust proxy', 1);
app.use(express.json({ limit: '110kb' }));
app.use(cookieParser());

// --- SECURITY: ENHANCED HELMET CONFIGURATION (FIXED FOR HELMET v7) ---
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
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("CORS Policy: Origin not allowed"), false);
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token", "x-csrf-token", "X-Admin-Key"],
    exposedHeaders: ["set-cookie"]
}));

// CSP Middleware with Signed Nonce Support - HELMET v7 COMPATIBLE
app.use((req, res, next) => {
    req.cspNonce = generateNonce();

    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", `'nonce-${req.cspNonce}'`, "https://cdnjs.cloudflare.com", "https://www.gstatic.com", "https://challenges.cloudflare.com", "https://cdn.jsdelivr.net", "https://www.gstatic.com"],
            frameSrc: ["'self'", "https://challenges.cloudflare.com"],
            styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'", "https://identitytoolkit.googleapis.com", "https://securetoken.googleapis.com", "https://challenges.cloudflare.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "blob:", "https://firebasestorage.googleapis.com", "https://ui-avatars.com"],
            frameAncestors: ["'none'"],

        },
    })(req, res, next);
});

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

async function getLatestAuditHash() {
    const doc = await AUDIT_CHAIN_DOC.get();
    return doc.exists ? doc.data().hash : "GENESIS";
}

async function logImmutableAction(action, data, user) {
    try {
        const safeData = JSON.parse(JSON.stringify(data || {}));

        const safeUser = {
            id: user?.uid || null,
            email: user?.email || null
        };

        await db.runTransaction(async (t) => {
            const chainDoc = await t.get(AUDIT_CHAIN_DOC);
            const previousHash = chainDoc.exists ? chainDoc.data().hash : "GENESIS";

            const logEntry = {
                action,
                data: safeData,
                user: safeUser,
                timestamp: Date.now(),
                previousHash
            };

            const hash = crypto.createHash("sha256")
                .update(JSON.stringify(logEntry))
                .digest("hex");

            logEntry.hash = hash;

            const logRef = db.collection("audit_trail").doc();

            t.set(logRef, logEntry);
            t.set(AUDIT_CHAIN_DOC, {
                hash,
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            });
        });

    } catch (e) {
        console.error("🔥 AUDIT FAILED (IGNORED):", e.message);
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

app.get("/verify-audit-chain", async (req, res) => {
    const logs = await db.collection("audit_trail")
        .orderBy("timestamp")
        .get();

    let prevHash = "GENESIS";

    for (const doc of logs.docs) {
        const entry = doc.data();

        const recalculated = crypto.createHash("sha256")
            .update(JSON.stringify({
                action: entry.action,
                data: entry.data,
                user: entry.user,
                timestamp: entry.timestamp,
                previousHash: prevHash
            }))
            .digest("hex");

        if (recalculated !== entry.hash) {
            return res.json({ valid: false });
        }

        prevHash = entry.hash;
    }

    res.json({ valid: true });
});

// 1. Log every admin data mutation with before/after state
async function logDataMutation(req, collection, docId, before, after) {
    await db.collection("admin_audit").add({
        action: "DATA_MUTATION",
        collection, docId,
        before: JSON.stringify(before),   // snapshot before change
        after: JSON.stringify(after),
        adminEmail: req.user?.email,
        ip: req.ip,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
}

// 2. Periodic audit: vote count must equal voter.hasVoted count
setInterval(async () => {
    const [voteSnap, voterSnap] = await Promise.all([
        db.collection("votes").count().get(),
        db.collection("voters").where("hasVoted", "==", true).count().get()
    ]);
    const votes = voteSnap.data().count;
    const voters = voterSnap.data().count;
    if (votes !== voters) {
        await createAlert("vote_integrity", "critical",
            "Count mismatch", `votes=${votes} vs hasVoted=${voters}`);
    }
}, 60000);

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
    const username = sanitizeString(req.body.username || '');
    const password = req.body.password || '';
    const captchaToken = req.body.captchaToken;
    const deviceId = req.cookies.__device_id || req.ip;

    await randomDelay(800, 1200);

    if (!req.headers["user-agent"]) {
        return res.status(403).end();
    }

    if (!captchaToken) {
        return res.status(400).json({
            error: "Complete Captcha Verification First"
        });
    }

    const check = await checkLoginAttempts(deviceId);
    if (!check.allowed) {
        return res.status(429).json({ error: check.message });
    }

    if (!(await verifyCaptcha(captchaToken))) {
        return res.status(403).json({ error: "Captcha verification failed" });
    }

    if (await isDeviceLocked(deviceId)) {
        return res.status(403).json({ error: "Locked" });
    }

    const isValidUser = username === process.env.ADMIN_USER;
    let isValidPass = false;

    if (isValidUser && process.env.ADMIN_HASH) {
        isValidPass = await bcrypt.compare(password, process.env.ADMIN_HASH);
    }

    if (!isValidUser || !isValidPass) {
        await recordDeviceAttempt(deviceId);
        const ip = req.ip;
        await createAlert(
            "bruteforce",
            "major",
            "⚠️ Brute Force Detected",
            "Multiple failed admin login attempts detected.",
            { ip }
        );

        await logSecurityEvent("ADMIN_LOGIN_FAILED", req, {
            username: username ? "***" : null
        });
        await recordLoginAttempt(deviceId, isValidPass);

        return res.status(401).json({ error: "Invalid credentials" });
    }

    await clearBruteForce(deviceId);

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
    await recordLoginAttempt(deviceId, isValidPass);

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
        const doc = await db.collection("settings").doc("config").get();
        const statusDoc = await db.collection("settings").doc("electionStatus").get();
        const isLive = statusDoc.exists ? statusDoc.data().isLive : false;
        const statusData = statusDoc.exists ? statusDoc.data() : {};
        const config = doc.exists ? doc.data() : { voterTimeoutMinutes: 60 };
        res.json({ ...config, ...statusData, isLive });
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
        // ✅ Pagination controls (safe limits)
        const limit = Math.min(parseInt(req.query.limit) || 100, 500);
        const cursor = req.query.cursor || null;

        let query = db.collection("votes")
            .orderBy("createdAt", "asc")
            .limit(limit);

        // ✅ Cursor support (ISO string → Date)
        if (cursor) {
            query = query.startAfter(new Date(cursor));
        }

        const votesSnap = await query.get();

        const receipts = [];
        let lastTimestamp = null;

        for (const doc of votesSnap.docs) {
            const data = doc.data();

            const ts = data.createdAt
                ? data.createdAt.toDate().toISOString()
                : null;

            if (ts) lastTimestamp = ts;

            receipts.push({
                receipt: data.receipt,
                timestamp: ts,
                hash: data.hash,
                prevHash: data.prevHash
            });
        }

        // ✅ Only verify chain on FIRST page (avoid repeated heavy checks)
        let chainInfo = null;
        if (!cursor) {
            chainInfo = await verifyHashChain(votesSnap); // reuse snapshot
        }

        res.set("Cache-Control", "no-store");

        return res.json({
            receipts,
            pageSize: receipts.length,
            nextCursor: lastTimestamp, // client uses this for next page
            chainValid: chainInfo ? chainInfo.valid : undefined,
            chainInfo: chainInfo || undefined
        });

    } catch (e) {
        console.error("Public receipts error:", e);
        return res.status(500).json({
            error: "Failed to retrieve public receipts"
        });
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
        await logSuccessEvent("ADMIN_VERIFY_CHAIN", req, chainInfo);
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
        const lvn = sanitizeString(req.body.lvn || '');
        const code = sanitizeString(req.body.code || '');

        if (!lvn || !code) {
            return res.status(400).json({ error: "Missing credentials." });
        }

        const hashedLVN = hashLVN(lvn);

        if (await isVoterLocked(hashedLVN)) {
            return res.status(403).json({
                error: "Account temporarily locked due to multiple failed attempts. Please try again later."
            });
        }

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

        const settingsSnap = await db.collection("settings").doc("electionStatus").get();
        const settingsData = settingsSnap.data() || {};

        const voterRef = db.collection("voters").doc(hashedLVN);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists) {
            await recordVoterFailedAttempt(hashedLVN);
            return res.status(401).json({ error: "Invalid Credentials." });
        }

        const d = voterSnap.data();
        const inputCode = code.toUpperCase();

        const isCodeValid = await bcrypt.compare(inputCode, d.code);

        if (!isCodeValid) {
            await recordVoterFailedAttempt(hashedLVN);
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

        if (!settingsSnap.exists || !settingsData.isLive) {
            return res.status(403).json({ error: "Election PAUSED." });
        }

        if (d.hasVoted) {
            await logSecurityEvent("DUPLICATE_VOTE_ATTEMPT", req, { hashedLVN });
            return res.status(403).json({ error: "Already Voted." });
        }

        const activeGrade = settingsData.activeGrade;

        if (activeGrade && String(activeGrade) !== "ALL" && String(activeGrade) !== "0") {
            if (String(d.grade) !== String(activeGrade)) {
                return res.status(403).json({ error: `Grade ${activeGrade} Only.` });
            }
        }

        // 🔥 QUEUE CHECK + JOIN
        const isQueue = settingsData.isQueue === true;

        if (isQueue) {
            await joinQueue(hashedLVN); // ✅ SAFE + CONSISTENT
        }

        await deviceRef.set({
            lvns: admin.firestore.FieldValue.arrayUnion(hashedLVN),
            lastLogin: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        res.cookie("__device_id", deviceFingerprint, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            path: "/",
            maxAge: 365 * 24 * 60 * 60 * 1000
        });

        await clearVoterBruteForce(hashedLVN);

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
            isQueue // ✅ FRONTEND USES THIS
        });

    } catch (e) {
        return res.status(500).json({ error: "Server error during verification." });
    }
});

async function useNonce(nonce) {
    const ref = db.collection("used_nonces").doc(nonce);

    return db.runTransaction(async (tx) => {
        const doc = await tx.get(ref);

        if (doc.exists) {
            return false;
        }

        tx.set(ref, {
            usedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return true;
    });
}

function stableStringify(obj) {
    return JSON.stringify(Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = obj[key];
        return acc;
    }, {}));
}

app.post('/authenticate', async (req, res) => {
    const { lvn, turnstileToken } = req.body;
    console.log("🔵 AUTH: Request received for LVN hash:", hashLVN(lvn).substring(0, 8));

    try {
        const voterHash = hashLVN(lvn);
        const voterRef = db.collection("voters").doc(voterHash);
        const voterSnap = await voterRef.get();

        if (!voterSnap.exists) {
            console.log("🔴 AUTH: Voter not found");
            return res.status(403).json({ error: "Voter not found" });
        }

        const voterData = voterSnap.data();
        const sessionId = crypto.randomBytes(32).toString("hex");
        const jti = crypto.randomBytes(16).toString("hex");
        console.log("🟢 AUTH: SessionID generated:", sessionId.substring(0, 16));

        const token = jwt.sign({
            uid: voterHash,
            grade: voterData.grade,
            sessionId,
            jti,
            role: "voter"
        }, SECRET, { expiresIn: "30m" });

        console.log("🟡 AUTH: JWT signed.");

        res.json({ token, voterData });

    } catch (e) {
        console.error("❌ AUTH ERROR:", {
            message: e.message,
            stack: e.stack,
            code: e.code
        });
        res.status(500).json({ error: "Authentication failed" });
    }
});

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

        // 🔒 Anti-replay (nonce)
        const nonceRef = db.collection("used_nonces").doc(nonce);

        const nonceUsed = await db.runTransaction(async (tx) => {
            const doc = await tx.get(nonceRef);

            if (doc.exists) return true;

            tx.set(nonceRef, {
                usedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            return false;
        });

        if (nonceUsed) {
            await createAlert("tamper", "critical", "Replay Attack", "Duplicate vote", { nonce });
            return res.status(400).json({ error: "Duplicate request detected" });
        }

        // 🔍 Validate selections
        let validatedSelections;
        try {
            validatedSelections = await validateSelections(selections);
        } catch (e) {
            await createAlert("tamper", "critical", "Tampered Vote", e.message, { selections });
            return res.status(400).json({ error: e.message });
        }

        // ⚙️ Election settings
        const settings = await db.collection("settings").doc("electionStatus").get();

        if (!settings.exists || !settings.data().isLive) {
            return res.status(403).json({ error: "Election closed." });
        }

        const electionData = settings.data();

        if (electionData.isQueue) {
            const userSnap = await rtdb.ref(`queue/users/${hashedLVN}`).once('value');
            if (!userSnap.exists()) {
                return res.status(403).json({ error: "You are not in the queue." });
            }
            const queueData = userSnap.val();
            if (queueData.status !== 'active') {
                return res.status(403).json({ error: "Please wait for your turn." });
            }
        }

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

        // 🔗 Blockchain chain head
        const CHAIN_DOC = db.collection("_meta").doc("chain_head");

        const voteResult = await db.runTransaction(async (t) => {
            const voterDoc = await t.get(voterRef);
            if (!voterDoc.exists) throw new Error("VOTER_NOT_FOUND");
            if (voterDoc.data().hasVoted) throw new Error("ALREADY_VOTED");

            const chainDoc = await t.get(CHAIN_DOC);
            const prevHash = chainDoc.exists ? chainDoc.data().hash : "GENESIS";
            const prevCount = chainDoc.exists ? (chainDoc.data().count || 0) : 0;

            const randomSalt = crypto.randomBytes(32).toString("hex");

            const payload = JSON.stringify({
                voter_hash: hashedLVN,
                selections: validatedSelections,
                timestamp: Date.now()
            });

            const receipt = crypto.createHash("sha256")
                .update(payload + randomSalt)
                .digest("hex");

            const verificationCode = crypto.createHash("sha256")
                .update(receipt + stableStringify(validatedSelections))
                .digest("hex")
                .substring(0, 12);

            const currentHash = crypto.createHash("sha256")
                .update(receipt + prevHash + stableStringify(validatedSelections))
                .digest("hex");

            const voteRef = db.collection("votes").doc();

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

            t.update(voterRef, {
                hasVoted: true,
                votedAt: admin.firestore.FieldValue.serverTimestamp(),
                receipt
            });

            t.set(CHAIN_DOC, {
                hash: currentHash,
                count: prevCount + 1
            });

            return { receipt, currentHash, prevHash, verificationCode };
        });

        // ✅ Respond immediately
        res.json({
            success: true,
            receipt: voteResult.receipt,
            verificationCode: voteResult.verificationCode,
            hash: voteResult.currentHash,
            prevHash: voteResult.prevHash
        });

        if (electionData.isQueue) {
            setImmediate(async () => {
                const queueRef = rtdb.ref('queue');
                await queueRef.transaction(current => {
                    if (!current) return current;
                    const user = current.users[hashedLVN];
                    if (!user) return current;

                    // Mark this user as done
                    user.status = 'done';
                    // Free one active slot
                    let newActiveCount = Math.max(0, (current.activeCount || 0) - 1);

                    // Find next waiting user (FIFO by position)
                    let nextUserId = null;
                    let lowestPosition = Infinity;
                    for (const [uid, data] of Object.entries(current.users)) {
                        if (data.status === 'waiting' && data.position < lowestPosition) {
                            nextUserId = uid;
                            lowestPosition = data.position;
                        }
                    }

                    if (nextUserId) {
                        current.users[nextUserId].status = 'active';
                        newActiveCount++;
                    }

                    current.activeCount = newActiveCount;
                    return current;
                });
            });
        }

        await refreshLocalResults();

    } catch (e) {
        console.log("REQ.USER:", req.user);
        console.error("Vote error:", e);
        res.status(500).json({
            error: "System failed to record vote. Please notify a facilitator."
        });
    }
});

async function completeVoting(userId) {
    const userRef = db.collection("queue_users").doc(userId);
    const queueRef = db.collection("queue").doc("active");

    await db.runTransaction(async (t) => {
        const queueDoc = await t.get(queueRef);
        const data = queueDoc.data();

        let currentServing = data.currentServing || 0;

        // mark user done
        t.update(userRef, {
            status: "done"
        });

        // move queue forward
        currentServing++;

        t.update(queueRef, {
            currentServing
        });

        // 🔥 Activate next user
        const nextUserSnap = await db.collection("queue_users")
            .where("position", "==", currentServing + data.maxActive)
            .limit(1)
            .get();

        if (!nextUserSnap.empty) {
            t.update(nextUserSnap.docs[0].ref, {
                status: "active"
            });
        }
    });
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

app.post("/submit-review", submitReviewLimiter, submissionLimiter, requireAuth, async (req, res) => {
    const submitToken = req.headers["x-submit-token"] || req.body._submitToken;
    if (!verifySubmitToken(submitToken, req.user.jti)) {
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
            const codeHashForUpdate = await bcrypt.hash(accessCode.toUpperCase(), 10);
            if (existingMap[cleanName]) {
                batch.update(existingMap[cleanName], {
                    grade: targetGrade,
                    section: section.toUpperCase(),
                    code: codeHashForUpdate,
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                updatedCount++;
            } else {
                const randomSuffix = Math.floor(1000000 + Math.random() * 9000000).toString();
                const lvn = `${gradePrefix}${sectionPrefix}${randomSuffix}`;
                const hashedLVN = hashLVN(lvn);
                const codeHash = await bcrypt.hash(accessCode.toUpperCase(), 10);
                const existingLvnSnap = await db.collection("voters").doc(hashedLVN).get();
                if (existingLvnSnap.exists) continue;
                const voterRef = db.collection("voters").doc(hashedLVN);
                batch.set(voterRef, {
                    lvn: lvn,
                    name: cleanName,
                    grade: targetGrade,
                    section: section.toUpperCase(),
                    code: codeHash,
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
        });
        await logImmutableAction(req, "VOTERS_UPSERT", {
            grade: targetGrade,
            section: section.toUpperCase(),
            totalProvided: names.length,
            updated: updatedCount,
            added: addedCount,
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
            await logImmutableAction(req, "VOTER_SOFT_DELETE", { lvn: "***", reason: "Has voted — receipt preserved" });
            await logSuccessEvent("ADMIN_DELETE_VOTER", req, { lvn: "***", method: "soft" });
            return res.json({ success: true, note: "Voter soft-deleted. Vote record remains intact for integrity." });
        }
        await voterRef.delete();
        await logAdminAction(req, "VOTER_DELETE", { lvn: "***" });
        await logImmutableAction(req, "VOTER_DELETE", { lvn: "***" });
        await logSuccessEvent("ADMIN_DELETE_VOTER", req, { lvn: "***", method: "hard" });
        await alertManager.detectCandidatesStatus();
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
        await logImmutableAction(req, "VOTER_RESET", { lvn: "***" });
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
        const isQueue = req.body.isQueue;

        const statusUpdate = {};

        if (typeof isLive === 'boolean') {
            statusUpdate.isLive = isLive;
        }

        if (typeof isQueue === 'boolean') {
            statusUpdate.isQueue = isQueue;
        }

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

        await db.collection("app_config").doc("candidates_static").set({
            lastUpdated: now
        }, { merge: true });

        const resultsConfig = { lastUpdated: now };

        if (typeof isLive === 'boolean') {
            resultsConfig.isLive = isLive;
        }

        if (typeof isQueue === 'boolean') {
            resultsConfig.isQueue = isQueue;
        }

        await db.collection("app_config").doc("results_public").set(resultsConfig, { merge: true });

        if (typeof isLive === 'boolean') {
            GlobalCache.dashboard.isLive = isLive;
        }

        if (typeof isQueue === 'boolean') {
            GlobalCache.dashboard.isQueue = isQueue;
        }

        await logAdminAction(req, "SET_ELECTION_SESSION", {
            isLive: typeof isLive === 'boolean' ? isLive : null,
            isQueue: typeof isQueue === 'boolean' ? isQueue : null,
            activeGrade: activeGrade !== undefined ? activeGrade : null,
            voterTime: voterTime !== undefined ? voterTime : null,
        });

        await logSuccessEvent("ADMIN_SET_SESSION", req, {
            isLive: typeof isLive === 'boolean' ? isLive : null,
            isQueue: typeof isQueue === 'boolean' ? isQueue : null,
            activeGrade: activeGrade !== undefined ? activeGrade : null
        });

        await alertManager.detectCandidatesStatus();
        await alertManager.detectSystemHealth();

        res.json({
            success: true,
            isLive,
            isQueue,
            activeGrade
        });

    } catch (e) {
        res.status(500).json({ error: "Failed to update election status" });
    }
});

app.post("/admin/purge", async (req, res) => {
    try {
        await logAdminAction(req, "PURGE_ELECTION_DATA", { initiated: true });
        await logImmutableAction(req, "PURGE_ELECTION_DATA", { initiated: true });
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
        await alertManager.detectCandidatesStatus();
        await alertManager.detectSystemHealth();

        await alertManager.createAlert(
            'election_deleted',
            'major',
            'Election Data Deleted',
            'All election data has been cleared.',
            {},
            null
        );

        await logSuccessEvent("ADMIN_PURGE_DATA", req, {
            success: true,
            backupHash: hash,
            backupUrl: url
        });

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
        await alertManager.detectCandidatesStatus();
        await alertManager.detectVoteIntegrity();
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
        await logSuccessEvent("ADMIN_RETALLY", req, { validVotes: validVotesCount, orphanedVotes: orphanedVotesCount });
        res.json({ success: true, message: `Re-tally complete. Database updated. Valid Votes: ${validVotesCount}, Invalid Votes: ${orphanedVotesCount}.` });
        await alertManager.clearResolvedAlerts('invalid_votes');
        await alertManager.clearResolvedAlerts('vote_integrity');
        await alertManager.clearResolvedAlerts('hash_chain');
    } catch (e) {
        res.status(500).json({ error: "Re-tally failed." });
    }
});

(async () => {
    const result = await alertManager.detectVoteIntegrity();
    if (result.chainValid && result.orphanedCount === 0) {
        await alertManager.clearResolvedAlerts('invalid_votes');
    }
})();

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
            await alertManager.createAlert(
                'candidate_sync',
                'minor',
                'Candidates Published',
                'Candidates successfully synced.',
                {},
                10 * 60 * 1000
            );

            await alertManager.detectCandidatesStatus();
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
        await logImmutableAction(req, "RETALLY", { ok: true });
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
        await createAlert(
            "candidate_sync",
            "minor",
            "📢 Candidate Update Needed",
            "New candidates added but not published.",
            {},
            24 * 60 * 60 * 1000
        );
        await alertManager.detectCandidatesStatus();
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
            await logImmutableAction(req, "DELETE_PARTY", { partyName });
            await logSuccessEvent("ADMIN_DELETE_PARTY", req, { partyName });
            await alertManager.detectCandidatesStatus();
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
            await logImmutableAction(req, "DELETE_CANDIDATE", { position, candidateId });

            await logSuccessEvent("ADMIN_DELETE_CANDIDATE", req, { position, candidateId });
            return res.json({ success: true });
        }
        await alertManager.detectCandidatesStatus();
        await alertManager.detectSystemHealth();
        res.status(400).json({ error: "Bad Params" });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post("/admin/election/reset", async (req, res) => {
    const confirmation = sanitizeString(req.body.confirmation || '');
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
        await logImmutableAction(req, "ELECTION_RESET", { success: true });

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
        await logImmutableAction(req, "RESET_MISSED", { lvn: "***" });

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

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});

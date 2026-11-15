/**
 * E-BOTO QR Recovery System — server module (spec v3)
 * ---------------------------------------------------------------------------
 * Single authority for: the QR package wire format, credential issuance, key
 * management (Ed25519 signing + P-256 ECDH envelope keys, versioned by `kid`),
 * package verification, structured rejection reasons and idempotent processing.
 *
 * Crypto primitives (all from Node's built-in OpenSSL-backed `crypto`; nothing custom):
 *   - Ed25519            : server signs recovery credentials (private key never leaves server/vault)
 *   - ECDH P-256 + HKDF  : student device encrypts the ballot to the server's envelope key
 *   - AES-256-GCM        : authenticated encryption of the ballot (header bound as AAD)
 *   - ECDSA P-256        : device-binding signature made with a non-extractable device key
 *
 * Wire format (big-endian). text = "EBOTO-RECOVERY:3." + base64url(bytes)
 *   [0]      0xEB magic
 *   [1]      0x03 schema version
 *   CREDENTIAL (54 B, signed by server):
 *     credVer(1)=1 | kid(4) | eid(8) | cid(16) | devh(16) | credIat(4) | credExp(4) | flags(1)
 *   credSig (64 B Ed25519 over "EBOTO-QR-CRED-v1\0" || credential)
 *   txId(16) | pkgIat(4) | pkgExp(4) | ephPub(33, compressed P-256) | iv(12) | ctLen(2) | ct||tag
 *   devSig (64 B ECDSA-P256-SHA256, IEEE-P1363) over every byte before it
 * AES-GCM AAD = every byte from offset 0 up to and including ctLen.
 * Plaintext ballot = ver(1)=1 | n(1) | n * [posCode(1) | candidateHashPrefix(8)]
 *
 * Nothing in the QR contains a name, LRN/LVN, token or plaintext selection.
 */
'use strict';

const crypto = require('crypto');

/* ------------------------------------------------------------------ constants */
const SCHEMA_VERSION = 3;
const PREFIX = 'EBOTO-RECOVERY:';
const MAGIC = 0xEB;
const CRED_VER = 1;
const CRED_LEN = 54;
const SIG_LEN = 64;
const CRED_DOMAIN = Buffer.from('EBOTO-QR-CRED-v1\0', 'latin1');
const HKDF_SALT = crypto.createHash('sha256').update('EBOTO-QR-v3').digest();
const MAX_TEXT_LEN = 1500;
const MIN_PKG_LEN = 2 + CRED_LEN + SIG_LEN + 16 + 4 + 4 + 33 + 12 + 2 + 16 + 64;
const MAX_PKG_LEN = 700;
const POS_ORDER = ['president', 'vp', 'secretary', 'treasurer', 'auditor', 'pio', 'protocol'];
const REP_BASE = 0x10; // posCode = 0x10 + grade for grade-representative slots

const DEFAULT_SETTINGS = Object.freeze({
    rotationEnabled: true,
    rotationIntervalMonths: 12,
    strictRejection: true,
    gracePeriodMinutes: 360,       // how long a retired key keeps verifying pending recoveries
    credentialTtlMinutes: 360,     // validity of an offline recovery credential
    packageTtlMinutes: 15,         // validity of a generated QR package
    maxClockSkewSec: 180,
    assistedReceiptTtlMinutes: 120
});

/* ------------------------------------------------------------ error catalogue */
const ERRORS = {
    INVALID_FORMAT: { title: 'Invalid QR format', message: 'This QR code is not a correctly structured E-Boto recovery package.', retryable: false, action: 'Ask the student to open the recovery screen and show a freshly generated recovery QR code.' },
    UNSUPPORTED_VERSION: { title: 'Unsupported package version', message: 'This recovery package was created by an older or newer version of E-Boto than this server accepts.', retryable: false, action: 'Ask the student to reload E-Boto and generate a new recovery package.' },
    INVALID_SIGNATURE: { title: 'Signature verification failed', message: 'The cryptographic signature on this package could not be verified. It may have been altered or forged.', retryable: false, action: 'Do not accept this package. Ask the student to generate a new one; report repeated failures to the election committee.' },
    UNKNOWN_KEY_ID: { title: 'Unknown signing key', message: 'The signing key identifier in this package is not recognized by this election server.', retryable: false, action: 'Ask the student to reload E-Boto (to obtain current recovery authorization) and generate a new package.' },
    EXPIRED_KEY: { title: 'Expired signing key', message: 'This recovery package was generated using a signing key that is no longer accepted by the current election security configuration.', retryable: false, action: 'Generate a new recovery package using the current authorized recovery process.' },
    REVOKED_KEY: { title: 'Revoked signing key', message: 'The signing key for this package was revoked by an administrator and can no longer be trusted.', retryable: false, action: 'Ask the student to reload E-Boto and generate a new package. Notify the election committee.' },
    EXPIRED_PACKAGE: { title: 'Recovery package expired', message: 'This recovery package or its recovery authorization is past its validity window.', retryable: false, action: 'Ask the student to open the recovery screen and generate a new QR code, then scan again.' },
    INVALID_TIMESTAMP: { title: 'Invalid timestamp', message: 'The package timestamps are invalid or outside the allowed limits (the student device clock may be wrong).', retryable: false, action: 'Ask the student to correct their device date and time, then generate a new package.' },
    INTEGRITY_FAILURE: { title: 'Package integrity check failed', message: 'The package contents failed authenticated-encryption or device-binding verification and may have been modified.', retryable: false, action: 'Do not accept this package. Ask the student to generate a new one.' },
    INVALID_ELECTION: { title: 'Wrong election', message: 'This package belongs to a different election or election mode (practice vs. live) than the one currently running.', retryable: false, action: 'Ask the student to sign in again for the current election and generate a new package.' },
    ELECTION_CLOSED: { title: 'Election not accepting recoveries', message: 'The election is closed or paused, so recovery submissions cannot be processed right now.', retryable: true, action: 'Wait until the election is open (or within its grace period), then scan again.' },
    DUPLICATE_TRANSACTION: { title: 'Already processed', message: 'A ballot for this recovery authorization was already processed. No second ballot was recorded.', retryable: false, action: 'No action is needed. Do not scan this student again; the first result stands.' },
    UNAUTHORIZED_ADVISER: { title: 'Not authorized to scan', message: 'This account is not permitted to process recovery packages.', retryable: false, action: 'Sign in with an account assigned to the QR Ballot Recovery Scanner or contact a Super Admin.' },
    INVALID_CREDENTIAL: { title: 'Invalid recovery authorization', message: 'The recovery authorization inside this package is unknown, superseded, or does not match the student device.', retryable: false, action: 'Ask the student to sign in again so a new recovery authorization is issued, then generate a new package.' },
    SERVER_UNAVAILABLE: { title: 'Server temporarily unavailable', message: 'The election server could not process this request right now.', retryable: true, action: 'The package is saved on this device. It will be retried automatically; you may also retry manually.' },
    STORAGE_FAILURE: { title: 'Storage operation failed', message: 'A required storage operation failed before the result could be confirmed.', retryable: true, action: 'Retry in a moment. The server checks the transaction status first, so no duplicate ballot can result.' },
    REVIEW_REQUIRED: { title: 'Needs committee review', message: 'The package is authentic but its ballot could not be fully reconciled with the candidate list.', retryable: false, action: 'The package was logged for committee review. The student may generate a new package.' }
};

function errorBody(code, extra = {}) {
    const e = ERRORS[code] || ERRORS.SERVER_UNAVAILABLE;
    return Object.assign({
        success: false,
        ok: false,
        outcome: 'rejected',
        state: 'REJECTED',
        errorCode: code,
        title: 'Package rejected — ' + e.title,
        message: e.message,
        retryable: !!e.retryable,
        recommendedAction: e.action,
        reference: null
    }, extra);
}

class QrError extends Error {
    constructor(code, extra) { super(code); this.code = code; this.extra = extra || {}; }
}

/* ------------------------------------------------------------------- helpers */
const b64u = (buf) => Buffer.from(buf).toString('base64url');
function b64uStrict(s) {
    if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) return null;
    const buf = Buffer.from(s, 'base64url');
    return buf.toString('base64url') === s ? buf : null;
}
const hex = (buf) => Buffer.from(buf).toString('hex');
const sec = (ms) => Math.floor(ms / 1000);
const kidToHex = (kidBuf) => Buffer.from(kidBuf).toString('hex');
const kidLabel = (kidHex) => 'qk-' + kidHex;
function eidFor(electionId) {
    return crypto.createHash('sha256').update('eboto-election:' + String(electionId)).digest().subarray(0, 8);
}
function addMonths(ms, months) {
    const d = new Date(ms);
    d.setUTCMonth(d.getUTCMonth() + months);
    return d.getTime();
}
function coarse(ms, bucket = 15 * 60 * 1000) { return Math.floor(ms / bucket) * bucket; }

function p256JwkFromRaw(raw) {
    return { kty: 'EC', crv: 'P-256', x: b64u(raw.subarray(1, 33)), y: b64u(raw.subarray(33, 65)) };
}
function validateRawP256(raw) {
    if (!Buffer.isBuffer(raw) || raw.length !== 65 || raw[0] !== 0x04) return false;
    try { const e = crypto.createECDH('prime256v1'); e.generateKeys(); e.computeSecret(raw); return true; } catch (_) { return false; }
}

/* ---------------------------------------------------------------- key vaults */
class MemoryVault {
    constructor() { this.name = 'memory'; this.m = new Map(); }
    async put(kidHex, secret) { if (this.m.has(kidHex)) throw new Error('VAULT_EXISTS'); this.m.set(kidHex, JSON.stringify(secret)); }
    async get(kidHex) { const v = this.m.get(kidHex); return v ? JSON.parse(v) : null; }
}

/** Private halves wrapped with AES-256-GCM under a key derived from QR_KEY_WRAP_SECRET (server env only). */
class EncryptedFirestoreVault {
    constructor({ db, wrapSecret, collection = 'qr_keyvault' }) {
        if (!wrapSecret || String(wrapSecret).length < 32) throw new Error('QR_KEY_WRAP_SECRET must be at least 32 characters');
        this.name = 'firestore-wrapped';
        this.db = db; this.col = collection;
        this.key = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(wrapSecret)), Buffer.from('e-boto-qr-vault/v1'), Buffer.from('wrap-aes-256-gcm'), 32));
    }
    async put(kidHex, secret) {
        const iv = crypto.randomBytes(12);
        const c = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        c.setAAD(Buffer.from('qrvault:' + kidHex));
        const ct = Buffer.concat([c.update(JSON.stringify(secret), 'utf8'), c.final()]);
        const ref = this.db.collection(this.col).doc(kidHex);
        await this.db.runTransaction(async (t) => {
            const s = await t.get(ref);
            if (s.exists) throw new Error('VAULT_EXISTS'); // never silently overwrite a private key
            t.set(ref, { alg: 'A256GCM', iv: hex(iv), tag: hex(c.getAuthTag()), ct: hex(ct), createdAtMs: Date.now() });
        });
    }
    async get(kidHex) {
        const s = await this.db.collection(this.col).doc(kidHex).get();
        if (!s.exists) return null;
        const d = s.data();
        const dec = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(d.iv, 'hex'));
        dec.setAAD(Buffer.from('qrvault:' + kidHex));
        dec.setAuthTag(Buffer.from(d.tag, 'hex'));
        return JSON.parse(Buffer.concat([dec.update(Buffer.from(d.ct, 'hex')), dec.final()]).toString('utf8'));
    }
}

/** Google Cloud Secret Manager (recommended). Requires `npm i @google-cloud/secret-manager`. */
class GcpSecretManagerVault {
    constructor({ projectId, client }) {
        this.name = 'gcp-secret-manager';
        this.projectId = projectId;
        if (client) this.client = client;
        else {
            const { SecretManagerServiceClient } = require('@google-cloud/secret-manager'); // lazy, optional dependency
            this.client = new SecretManagerServiceClient();
        }
    }
    _id(kidHex) { return 'eboto-qr-key-' + kidHex; }
    async put(kidHex, secret) {
        const parent = `projects/${this.projectId}`;
        await this.client.createSecret({ parent, secretId: this._id(kidHex), secret: { replication: { automatic: {} } } }); // throws if it exists
        await this.client.addSecretVersion({ parent: `${parent}/secrets/${this._id(kidHex)}`, payload: { data: Buffer.from(JSON.stringify(secret)) } });
    }
    async get(kidHex) {
        try {
            const [v] = await this.client.accessSecretVersion({ name: `projects/${this.projectId}/secrets/${this._id(kidHex)}/versions/latest` });
            return JSON.parse(v.payload.data.toString('utf8'));
        } catch (e) { if (e && (e.code === 5 || e.code === 'NOT_FOUND')) return null; throw e; }
    }
}

function createVaultFromEnv({ db, env = process.env }) {
    if (env.QR_KEY_VAULT === 'gcp-secret-manager') {
        const projectId = env.GCP_PROJECT_ID || env.GOOGLE_CLOUD_PROJECT;
        if (!projectId) throw new Error('GCP_PROJECT_ID is required for the Secret Manager vault');
        return new GcpSecretManagerVault({ projectId });
    }
    if (!env.QR_KEY_WRAP_SECRET && env.NODE_ENV === 'production') {
        throw new Error('QR key vault not configured: set QR_KEY_VAULT=gcp-secret-manager or QR_KEY_WRAP_SECRET (>=32 chars, dedicated to this purpose).');
    }
    if (!env.QR_KEY_WRAP_SECRET) {
        console.warn('[QR] QR_KEY_WRAP_SECRET not set — using an ephemeral in-memory vault (development only; keys are lost on restart).');
        return new MemoryVault();
    }
    return new EncryptedFirestoreVault({ db, wrapSecret: env.QR_KEY_WRAP_SECRET });
}

/* ------------------------------------------------------------------- keyring */
class QrKeyring {
    constructor({ db, vault, now = () => Date.now(), audit = async () => {} }) {
        this.db = db; this.vault = vault; this.now = now; this.audit = audit;
        this.priv = new Map(); // kidHex -> { sigKey, encEcdh, at }
        this.PRIV_TTL = 5 * 60 * 1000;
    }
    get settingsRef() { return this.db.collection('settings').doc('qrSecurity'); }
    keyRef(kidHex) { return this.db.collection('qr_keys').doc(kidHex); }

    async getSettings() {
        const s = await this.settingsRef.get();
        return Object.assign({}, DEFAULT_SETTINGS, s.exists ? s.data() : {});
    }
    async getKey(kidHex) {
        if (!/^[0-9a-f]{8}$/.test(kidHex)) return null;
        const s = await this.keyRef(kidHex).get(); // always fresh: revocation takes effect immediately
        return s.exists ? s.data() : null;
    }
    async listKeys() {
        const snap = await this.db.collection('qr_keys').get();
        const out = []; snap.forEach((d) => out.push(d.data()));
        return out.sort((a, b) => (a.version || 0) - (b.version || 0));
    }
    async listEvents(limit = 50) {
        const snap = await this.db.collection('qr_key_events').get();
        const out = []; snap.forEach((d) => out.push(d.data()));
        return out.sort((a, b) => b.atMs - a.atMs).slice(0, limit);
    }
    async _event(type, actor, details) {
        const atMs = this.now();
        const id = `${atMs}-${crypto.randomBytes(4).toString('hex')}`;
        await this.db.collection('qr_key_events').doc(id).set({ id, type, actor: actor || 'system', atMs, details: details || {} });
        try { await this.audit(type, Object.assign({ actor: actor || 'system' }, details || {})); } catch (_) {}
    }

    /** Create settings + a first ACTIVE key if none exist. Idempotent. */
    async ensureInitialized(actor = 'system') {
        let s = await this.settingsRef.get();
        if (!s.exists) {
            const now = this.now();
            const init = Object.assign({}, DEFAULT_SETTINGS, {
                electionId: 'el-' + crypto.randomBytes(8).toString('hex'),
                activeKid: null, lastRotationAtMs: null,
                nextRotationAtMs: addMonths(now, DEFAULT_SETTINGS.rotationIntervalMonths),
                createdAtMs: now, updatedAtMs: now
            });
            await this.db.runTransaction(async (t) => {
                const cur = await t.get(this.settingsRef);
                if (!cur.exists) t.set(this.settingsRef, init);
            });
        }
        const settings = await this.getSettings();
        if (!settings.activeKid) {
            const meta = await this.generateKey({ actor, reason: 'initial key' });
            await this.activate(meta.kid, { actor });
        }
        return this.getSettings();
    }

    async generateKey({ actor = 'system', activatesAtMs = null, reason = '' } = {}) {
        const keys = await this.listKeys();
        let kidHexVal;
        for (let i = 0; i < 8; i++) {
            const k = crypto.randomBytes(4);
            if (k.readUInt32BE(0) === 0) continue;
            const h = kidToHex(k);
            if (!keys.some((x) => x.kid === h)) { kidHexVal = h; break; }
        }
        if (!kidHexVal) throw new Error('KID_ALLOCATION_FAILED');
        const sig = crypto.generateKeyPairSync('ed25519');
        const ecdh = crypto.createECDH('prime256v1'); ecdh.generateKeys();
        await this.vault.put(kidHexVal, {
            v: 1,
            sigPkcs8: sig.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
            encPriv: ecdh.getPrivateKey('hex')
        });
        const meta = {
            kid: kidHexVal, label: kidLabel(kidHexVal),
            version: keys.reduce((m, k) => Math.max(m, k.version || 0), 0) + 1,
            alg: { sig: 'Ed25519', enc: 'ECDH-P256+HKDF-SHA256+AES-256-GCM' },
            sigPub: sig.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
            encPub: ecdh.getPublicKey('hex', 'uncompressed'),
            status: 'PENDING',
            createdAtMs: this.now(), activatesAtMs: activatesAtMs || null, activatedAtMs: null,
            retiredAtMs: null, retireCutoffMs: null, revokedAtMs: null, revokedReason: null,
            vault: this.vault.name, createdBy: actor
        };
        await this.db.runTransaction(async (t) => {
            const cur = await t.get(this.keyRef(kidHexVal));
            if (cur.exists) throw new Error('KEY_EXISTS'); // never overwrite existing key metadata
            t.set(this.keyRef(kidHexVal), meta);
        });
        await this._event('QR_KEY_GENERATED', actor, { kid: kidHexVal, version: meta.version, activatesAtMs, reason });
        return meta;
    }

    async schedule(kidHexVal, activatesAtMs, actor) {
        const k = await this.getKey(kidHexVal);
        if (!k) throw new QrError('UNKNOWN_KEY_ID');
        if (k.status !== 'PENDING') throw new Error('ONLY_PENDING_KEYS_CAN_BE_SCHEDULED');
        if (!Number.isFinite(activatesAtMs) || activatesAtMs < this.now() - 1000) throw new Error('ACTIVATION_MUST_BE_IN_FUTURE');
        await this.keyRef(kidHexVal).update({ activatesAtMs });
        await this._event('QR_KEY_ACTIVATION_SCHEDULED', actor, { kid: kidHexVal, activatesAtMs });
    }

    /** Make a PENDING key the single ACTIVE key; retire the previous one with an explicit, auditable cutoff. */
    async activate(kidHexVal, { actor = 'system' } = {}) {
        const now = this.now();
        let retired = null, cutoff = null;
        await this.db.runTransaction(async (t) => {
            const [sSnap, kSnap] = await Promise.all([t.get(this.settingsRef), t.get(this.keyRef(kidHexVal))]);
            if (!kSnap.exists) throw new QrError('UNKNOWN_KEY_ID');
            const k = kSnap.data(); const s = Object.assign({}, DEFAULT_SETTINGS, sSnap.exists ? sSnap.data() : {});
            if (k.status !== 'PENDING') throw new Error('ONLY_PENDING_KEYS_CAN_BE_ACTIVATED');
            let prev = null;
            if (s.activeKid && s.activeKid !== kidHexVal) { const p = await t.get(this.keyRef(s.activeKid)); if (p.exists) prev = p.data(); }
            if (prev && prev.status === 'ACTIVE') {
                cutoff = now + s.gracePeriodMinutes * 60000; retired = prev.kid;
                t.update(this.keyRef(prev.kid), { status: 'RETIRED', retiredAtMs: now, retireCutoffMs: cutoff });
            }
            t.update(this.keyRef(kidHexVal), { status: 'ACTIVE', activatedAtMs: now, activatesAtMs: k.activatesAtMs || now });
            t.set(this.settingsRef, Object.assign({}, s, {
                activeKid: kidHexVal, lastRotationAtMs: now,
                nextRotationAtMs: addMonths(now, s.rotationIntervalMonths), updatedAtMs: now
            }));
        });
        await this._event(retired ? 'QR_KEY_ROTATED' : 'QR_KEY_ACTIVATED', actor, { kid: kidHexVal, retiredKid: retired, retireCutoffMs: cutoff });
        return { kid: kidHexVal, retiredKid: retired, retireCutoffMs: cutoff };
    }

    async rotate({ actor = 'system', reason = 'manual rotation' } = {}) {
        const meta = await this.generateKey({ actor, reason });
        return this.activate(meta.kid, { actor });
    }

    /** Emergency revocation: effective immediately; a compromised ACTIVE key is auto-replaced so issuance continues. */
    async revoke(kidHexVal, { actor = 'system', reason = '', autoReplace = true } = {}) {
        const now = this.now(); let wasActive = false;
        await this.db.runTransaction(async (t) => {
            const [sSnap, kSnap] = await Promise.all([t.get(this.settingsRef), t.get(this.keyRef(kidHexVal))]);
            if (!kSnap.exists) throw new QrError('UNKNOWN_KEY_ID');
            const k = kSnap.data(); if (k.status === 'REVOKED') throw new Error('ALREADY_REVOKED');
            const s = Object.assign({}, DEFAULT_SETTINGS, sSnap.exists ? sSnap.data() : {});
            wasActive = s.activeKid === kidHexVal;
            t.update(this.keyRef(kidHexVal), { status: 'REVOKED', revokedAtMs: now, revokedReason: String(reason).slice(0, 300) });
            if (wasActive) t.set(this.settingsRef, Object.assign({}, s, { activeKid: null, updatedAtMs: now }));
        });
        this.priv.delete(kidHexVal);
        await this._event('QR_KEY_REVOKED', actor, { kid: kidHexVal, reason: String(reason).slice(0, 300), wasActive });
        let replacement = null;
        if (wasActive && autoReplace) replacement = await this.rotate({ actor, reason: 'emergency replacement for revoked ' + kidHexVal });
        return { kid: kidHexVal, wasActive, replacement };
    }

    /** Called when election data is purged/reset: new election id => every old credential/package is INVALID_ELECTION. */
    async newElection(actor = 'system') {
        const before = await this.getSettings();
        const electionId = 'el-' + crypto.randomBytes(8).toString('hex');
        await this.settingsRef.set(Object.assign({}, before, { electionId, updatedAtMs: this.now() }));
        await this._event('QR_ELECTION_ID_CHANGED', actor, { note: 'election id regenerated; outstanding recovery credentials are no longer valid' });
        return electionId;
    }

    async updateSettings(patch, actor) {
        const allowed = ['rotationEnabled', 'rotationIntervalMonths', 'strictRejection', 'gracePeriodMinutes', 'nextRotationAtMs', 'credentialTtlMinutes', 'packageTtlMinutes'];
        const clean = {};
        for (const k of allowed) if (patch[k] !== undefined) clean[k] = patch[k];
        if ('rotationEnabled' in clean) clean.rotationEnabled = !!clean.rotationEnabled;
        if ('strictRejection' in clean) clean.strictRejection = !!clean.strictRejection;
        const rng = { rotationIntervalMonths: [1, 36], gracePeriodMinutes: [0, 10080], credentialTtlMinutes: [10, 1440], packageTtlMinutes: [1, 60] };
        for (const [k, [lo, hi]] of Object.entries(rng)) if (k in clean) {
            const n = Number(clean[k]); if (!Number.isInteger(n) || n < lo || n > hi) throw new Error(`INVALID_SETTING_${k}`);
            clean[k] = n;
        }
        if ('nextRotationAtMs' in clean) { clean.nextRotationAtMs = Number(clean.nextRotationAtMs); if (!Number.isFinite(clean.nextRotationAtMs)) throw new Error('INVALID_SETTING_nextRotationAtMs'); }
        const before = await this.getSettings();
        if (!('nextRotationAtMs' in clean) && clean.rotationIntervalMonths && before.lastRotationAtMs) clean.nextRotationAtMs = addMonths(before.lastRotationAtMs, clean.rotationIntervalMonths);
        clean.updatedAtMs = this.now();
        await this.settingsRef.set(Object.assign({}, before, clean));
        await this._event('QR_KEY_SETTINGS_CHANGED', actor, { before: pick(before, Object.keys(clean)), after: clean });
        return this.getSettings();
    }

    /** Scheduler step (safe to call on every instance; state changes are transactional). */
    async tick() {
        const now = this.now(); const out = [];
        const settings = await this.getSettings();
        if (!settings.activeKid) return out;
        const keys = await this.listKeys();
        for (const k of keys) if (k.status === 'PENDING' && k.activatesAtMs && k.activatesAtMs <= now) {
            try { out.push(await this.activate(k.kid, { actor: 'system:scheduler' })); } catch (_) { /* another instance won */ }
        }
        const fresh = await this.getSettings();
        if (fresh.rotationEnabled && fresh.nextRotationAtMs && fresh.nextRotationAtMs <= now) {
            try { out.push(await this.rotate({ actor: 'system:scheduler', reason: 'annual rotation' })); } catch (_) {}
        }
        return out;
    }

    async _privateFor(kidHexVal) {
        const hit = this.priv.get(kidHexVal);
        if (hit && this.now() - hit.at < this.PRIV_TTL) return hit;
        const secret = await this.vault.get(kidHexVal);
        if (!secret) throw new QrError('UNKNOWN_KEY_ID');
        const ecdh = crypto.createECDH('prime256v1'); ecdh.setPrivateKey(Buffer.from(secret.encPriv, 'hex'));
        const entry = { sigKey: crypto.createPrivateKey({ key: Buffer.from(secret.sigPkcs8, 'base64'), format: 'der', type: 'pkcs8' }), ecdh, at: this.now() };
        this.priv.set(kidHexVal, entry);
        return entry;
    }
    async sign(kidHexVal, message) { return crypto.sign(null, message, (await this._privateFor(kidHexVal)).sigKey); }
    async ecdhSecret(kidHexVal, peerPub) { return (await this._privateFor(kidHexVal)).ecdh.computeSecret(peerPub); }
}

function pick(o, keys) { const r = {}; for (const k of keys) r[k] = o[k]; return r; }

/** Which error (if any) prevents this key from verifying packages right now? Pure function. */
function keyVerificationError(meta, settings, nowMs) {
    if (!meta) return 'UNKNOWN_KEY_ID';
    switch (meta.status) {
        case 'REVOKED': return 'REVOKED_KEY';
        case 'ACTIVE': return null;
        case 'RETIRED':
            if (settings.strictRejection && nowMs > (meta.retireCutoffMs || 0)) return 'EXPIRED_KEY';
            return null;
        default: return 'UNKNOWN_KEY_ID'; // PENDING keys never signed anything
    }
}

/* ------------------------------------------------------------- package parse */
function parsePackage(text) {
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_TEXT_LEN) return { err: 'INVALID_FORMAT' };
    const t = text.trim();
    if (!t.startsWith(PREFIX)) return { err: 'INVALID_FORMAT' };
    const rest = t.slice(PREFIX.length);
    if (/^[A-Za-z0-9_-]{140,170}$/.test(rest)) return { err: 'UNSUPPORTED_VERSION', detail: 'legacy-v2' };
    const m = /^(\d{1,3})\.([A-Za-z0-9_-]+)$/.exec(rest);
    if (!m) return { err: 'INVALID_FORMAT' };
    if (Number(m[1]) !== SCHEMA_VERSION) return { err: 'UNSUPPORTED_VERSION', detail: 'v' + m[1] };
    const buf = b64uStrict(m[2]);
    if (!buf || buf.length < MIN_PKG_LEN || buf.length > MAX_PKG_LEN) return { err: 'INVALID_FORMAT' };
    if (buf[0] !== MAGIC) return { err: 'INVALID_FORMAT' };
    if (buf[1] !== SCHEMA_VERSION) return { err: 'UNSUPPORTED_VERSION', detail: 'inner' };
    let o = 2;
    const cred = buf.subarray(o, o + CRED_LEN); o += CRED_LEN;
    if (cred[0] !== CRED_VER) return { err: 'UNSUPPORTED_VERSION', detail: 'cred' };
    const credSig = buf.subarray(o, o + SIG_LEN); o += SIG_LEN;
    const txId = buf.subarray(o, o + 16); o += 16;
    const pkgIat = buf.readUInt32BE(o); o += 4;
    const pkgExp = buf.readUInt32BE(o); o += 4;
    const eph = buf.subarray(o, o + 33); o += 33;
    const iv = buf.subarray(o, o + 12); o += 12;
    const ctLen = buf.readUInt16BE(o); o += 2;
    const aadEnd = o;
    if (ctLen < 16 + 2 || ctLen > 16 + 2 + 9 * 9 + 8 || o + ctLen + SIG_LEN !== buf.length) return { err: 'INVALID_FORMAT' };
    const ct = buf.subarray(o, o + ctLen); o += ctLen;
    const devSig = buf.subarray(o, o + SIG_LEN);
    if (eph[0] !== 0x02 && eph[0] !== 0x03) return { err: 'INVALID_FORMAT' };
    return {
        bytes: buf, cred, credSig, txId, pkgIat, pkgExp, eph, iv, ct, devSig, aadEnd,
        f: {
            kid: kidToHex(cred.subarray(1, 5)), eid: hex(cred.subarray(5, 13)), cid: hex(cred.subarray(13, 29)),
            devh: hex(cred.subarray(29, 45)), credIat: cred.readUInt32BE(45), credExp: cred.readUInt32BE(49), flags: cred[53],
            txIdHex: hex(txId)
        }
    };
}

function deriveAesKey(sharedSecret, kidBuf, txId) {
    return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, HKDF_SALT, Buffer.concat([Buffer.from('aes-256-gcm|'), kidBuf, txId]), 32));
}

function parseBallotPlaintext(pt) {
    if (pt.length < 2 || pt[0] !== 1) return null;
    const n = pt[1];
    if (n > 9 || pt.length !== 2 + n * 9) return null;
    const entries = []; const seen = new Set();
    for (let i = 0; i < n; i++) {
        const code = pt[2 + i * 9];
        const h = hex(pt.subarray(3 + i * 9, 11 + i * 9));
        let pos;
        if (code < POS_ORDER.length) pos = POS_ORDER[code];
        else if (code >= REP_BASE + 7 && code <= REP_BASE + 12) pos = 'rep' + (code - REP_BASE);
        else return null;
        entries.push({ pos, hash8: h });
    }
    return entries;
}

/** Map decrypted slot entries onto the live candidate list. Pure; used by inspect and process. */
function resolveBallot(entries, { candidateMap, candidateHashMap, grade, allowedRepPos, titleOf = (p) => p }) {
    const issues = [], anomalies = []; const selections = {};
    const byPos = {};
    for (const e of entries) (byPos[e.pos] = byPos[e.pos] || []).push(e);
    const find = (pos, h8) => {
        const keys = Object.keys((candidateHashMap && candidateHashMap[pos]) || {}).filter((k) => k.startsWith(h8));
        return keys.length === 1 ? candidateHashMap[pos][keys[0]] : null;
    };
    for (const pos of POS_ORDER) {
        const opts = Array.isArray(candidateMap[pos]) ? candidateMap[pos] : [];
        if (!opts.length) { if (byPos[pos]) anomalies.push(`Selection for ${titleOf(pos)} but no candidates are registered.`); continue; }
        const e = byPos[pos];
        if (!e || e.length !== 1) { issues.push(`Missing or duplicate selection for ${titleOf(pos)}.`); continue; }
        const id = find(pos, e[0].hash8);
        if (!id) anomalies.push(`Unrecognized candidate for ${titleOf(pos)}.`); else selections[pos] = id;
    }
    for (const pos of Object.keys(byPos)) if (/^rep\d+$/.test(pos) && pos !== allowedRepPos) anomalies.push(`Selection for ${titleOf(pos)} is not allowed for this voter's grade.`);
    if (allowedRepPos) {
        const opts = Array.isArray(candidateMap[allowedRepPos]) ? candidateMap[allowedRepPos] : [];
        if (opts.length) {
            const need = opts.length >= 2 ? 2 : 1; const e = byPos[allowedRepPos] || [];
            if (e.length !== need) issues.push(`Expected ${need} selection(s) for ${titleOf(allowedRepPos)}, found ${e.length}.`);
            else {
                const ids = e.map((x) => find(allowedRepPos, x.hash8));
                if (ids.some((x) => !x)) anomalies.push(`Unrecognized candidate for ${titleOf(allowedRepPos)}.`);
                else if (new Set(ids).size !== ids.length) anomalies.push(`Duplicate candidate for ${titleOf(allowedRepPos)}.`);
                else selections[allowedRepPos] = ids;
            }
        }
    }
    return { selections, issues, anomalies };
}

/* -------------------------------------------------------------------- service */
class QrRecoveryService {
    /**
     * deps: { db, keyring, getElectionStatus(): {isLive,isMock,endTimeMs,graceMs},
     *         getCandidates(): Promise<{candidateMap,candidateHashMap}>, getAllowedRepPos(grade), titleOf(pos),
     *         ledgerWrite(t, {voterId, grade, selections, mock}): Promise<{receipt,hash,shardId,masked}>,
     *         sealReceipt(obj): string, now(): ms }
     */
    constructor(deps) { this.d = deps; this.now = deps.now || (() => Date.now()); }
    get db() { return this.d.db; }

    /* ---- credential issuance (online, voter-authenticated, BEFORE going offline) ---- */
    async issueCredential({ voterId, devicePubB64u, isMock }) {
        const raw = b64uStrict(devicePubB64u);
        if (!validateRawP256(raw)) throw new QrError('INVALID_CREDENTIAL', { message: 'Device key is invalid.' });
        const settings = await this.d.keyring.getSettings();
        if (!settings.activeKid) throw new QrError('SERVER_UNAVAILABLE');
        const meta = await this.d.keyring.getKey(settings.activeKid);
        if (!meta || meta.status !== 'ACTIVE') throw new QrError('SERVER_UNAVAILABLE');
        const now = this.now();
        const devh = crypto.createHash('sha256').update(raw).digest().subarray(0, 16);
        const byVoterRef = this.db.collection('qr_cred_by_voter').doc(voterId);
        const existing = await byVoterRef.get();
        if (existing.exists) {
            const cur = await this.db.collection('qr_credentials').doc(existing.data().cid).get();
            if (cur.exists) {
                const c = cur.data();
                if (c.status === 'ISSUED' && c.devh === hex(devh) && c.kid === meta.kid && c.expMs > now + 60000 && !!c.isMock === !!isMock) return this._credResponse(c, meta, settings);
            }
        }
        const cid = crypto.randomBytes(16);
        const credIat = sec(now), credExp = sec(now + settings.credentialTtlMinutes * 60000);
        const cred = Buffer.alloc(CRED_LEN);
        cred[0] = CRED_VER; Buffer.from(meta.kid, 'hex').copy(cred, 1); eidFor(settings.electionId).copy(cred, 5);
        cid.copy(cred, 13); devh.copy(cred, 29); cred.writeUInt32BE(credIat, 45); cred.writeUInt32BE(credExp, 49); cred[53] = isMock ? 1 : 0;
        const sig = await this.d.keyring.sign(meta.kid, Buffer.concat([CRED_DOMAIN, cred]));
        const rec = {
            cid: hex(cid), kid: meta.kid, devPub: b64u(raw), devh: hex(devh), iatMs: credIat * 1000, expMs: credExp * 1000,
            status: 'ISSUED', isMock: !!isMock, credential: b64u(Buffer.concat([cred, sig])), voterId
        };
        await this.db.runTransaction(async (t) => {
            const cur = await t.get(byVoterRef);
            if (cur.exists) { const oldRef = this.db.collection('qr_credentials').doc(cur.data().cid); const old = await t.get(oldRef); if (old.exists && old.data().status === 'ISSUED') t.update(oldRef, { status: 'SUPERSEDED' }); }
            t.set(this.db.collection('qr_credentials').doc(rec.cid), rec);
            t.set(byVoterRef, { cid: rec.cid, updatedAtMs: now });
        });
        return this._credResponse(rec, meta, settings);
    }
    _credResponse(rec, meta, settings) {
        return {
            credential: rec.credential, kid: meta.kid, encPub: meta.encPub, eid: hex(eidFor(settings.electionId)),
            expiresAtMs: rec.expMs, packageTtlMs: settings.packageTtlMinutes * 60000, serverTimeMs: this.now(), schema: SCHEMA_VERSION
        };
    }

    /* ---- verification (steps 1-10). Pure w.r.t. the ledger: reads only. ---- */
    async verify(text) {
        const now = this.now(); const nowSec = sec(now);
        const checks = { format: 'pend', signature: 'pend', key: 'pend', timing: 'pend', election: 'pend', integrity: 'pend', duplicate: 'pend' };
        const fail = (code, extra) => ({ ok: false, code, checks: Object.assign({}, checks), extra: extra || {} });

        const P = parsePackage(text);                                         // 1-3
        if (P.err) { checks.format = 'bad'; return fail(P.err); }
        checks.format = 'ok';
        const F = P.f;
        const settings = await this.d.keyring.getSettings();
        const meta = await this.d.keyring.getKey(F.kid);                      // 4-5
        if (!meta || meta.status === 'PENDING') { checks.key = 'bad'; return fail('UNKNOWN_KEY_ID'); }
        let sigOk = false;
        try {
            const pub = crypto.createPublicKey({ key: Buffer.from(meta.sigPub, 'base64'), format: 'der', type: 'spki' });
            sigOk = crypto.verify(null, Buffer.concat([CRED_DOMAIN, P.cred]), pub, P.credSig);   // 6
        } catch (_) { sigOk = false; }
        if (!sigOk) { checks.signature = 'bad'; return fail('INVALID_SIGNATURE'); }
        checks.signature = 'ok';
        const ke = keyVerificationError(meta, settings, now);
        if (ke) { checks.key = 'bad'; return fail(ke, { reference: F.txIdHex.slice(0, 8).toUpperCase() }); }
        checks.key = 'ok';
        const ref = F.txIdHex.slice(0, 8).toUpperCase();

        const skew = settings.maxClockSkewSec;                                // 7
        if (F.credExp <= F.credIat || P.pkgExp <= P.pkgIat) { checks.timing = 'bad'; return fail('INVALID_TIMESTAMP', { reference: ref }); }
        if (P.pkgIat > nowSec + skew || F.credIat > nowSec + skew) { checks.timing = 'bad'; return fail('INVALID_TIMESTAMP', { reference: ref }); }
        if (P.pkgExp - P.pkgIat > settings.packageTtlMinutes * 60 + skew) { checks.timing = 'bad'; return fail('INVALID_TIMESTAMP', { reference: ref }); }
        if (P.pkgIat + skew < F.credIat || P.pkgIat > F.credExp) { checks.timing = 'bad'; return fail('INVALID_TIMESTAMP', { reference: ref }); }
        if (nowSec > P.pkgExp || nowSec > F.credExp) { checks.timing = 'bad'; return fail('EXPIRED_PACKAGE', { reference: ref }); }
        checks.timing = 'ok';

        const st = this.d.getElectionStatus();                                // 8
        if (F.eid !== hex(eidFor(settings.electionId)) || !!(F.flags & 1) !== !!st.isMock) { checks.election = 'bad'; return fail('INVALID_ELECTION', { reference: ref }); }
        const open = st.isMock || st.isLive === true && !(st.endTimeMs && now > st.endTimeMs + (st.graceMs || 0));
        if (!open) { checks.election = 'bad'; return fail('ELECTION_CLOSED', { reference: ref }); }
        checks.election = 'ok';

        const credSnap = await this.db.collection('qr_credentials').doc(F.cid).get();   // credential + device binding
        if (!credSnap.exists) { checks.integrity = 'bad'; return fail('INVALID_CREDENTIAL', { reference: ref }); }
        const credRec = credSnap.data();
        if (credRec.status === 'REDEEMED') {   // voter link + device key were deliberately erased at redemption
            const prior = await this.db.collection('qr_recoveries').doc(F.txIdHex).get();
            checks.duplicate = 'bad';
            const replay = prior.exists && prior.data().outcome === 'confirmed';
            return { ok: false, code: 'DUPLICATE_TRANSACTION', checks, extra: Object.assign({ reference: ref }, replay ? { replay: true, previousOutcome: 'confirmed', processedAtMs: prior.data().processedAtMs } : {}) };
        }
        if (credRec.kid !== F.kid || credRec.devh !== F.devh || credRec.expMs !== F.credExp * 1000) { checks.integrity = 'bad'; return fail('INVALID_CREDENTIAL', { reference: ref }); }
        let devOk = false;
        try {
            const pk = crypto.createPublicKey({ key: p256JwkFromRaw(Buffer.from(credRec.devPub, 'base64url')), format: 'jwk' });
            devOk = crypto.verify('sha256', P.bytes.subarray(0, P.bytes.length - SIG_LEN), { key: pk, dsaEncoding: 'ieee-p1363' }, P.devSig);
        } catch (_) { devOk = false; }
        if (!devOk) { checks.integrity = 'bad'; return fail('INTEGRITY_FAILURE', { reference: ref }); }   // 9
        let pt;
        try {
            const shared = await this.d.keyring.ecdhSecret(F.kid, P.eph);
            const key = deriveAesKey(shared, Buffer.from(F.kid, 'hex'), P.txId);
            const d = crypto.createDecipheriv('aes-256-gcm', key, P.iv);
            d.setAAD(P.bytes.subarray(0, P.aadEnd)); d.setAuthTag(P.ct.subarray(P.ct.length - 16));
            pt = Buffer.concat([d.update(P.ct.subarray(0, P.ct.length - 16)), d.final()]);
        } catch (e) { if (e instanceof QrError) throw e; checks.integrity = 'bad'; return fail('INTEGRITY_FAILURE', { reference: ref }); }
        const entries = parseBallotPlaintext(pt);
        if (!entries) { checks.integrity = 'bad'; return fail('INTEGRITY_FAILURE', { reference: ref }); }
        checks.integrity = 'ok';

        const txSnap = await this.db.collection('qr_recoveries').doc(F.txIdHex).get();  // 10
        if (txSnap.exists) {
            const tx = txSnap.data();
            checks.duplicate = tx.outcome === 'confirmed' ? 'bad' : 'pend';
            if (tx.outcome === 'confirmed') return { ok: false, code: 'DUPLICATE_TRANSACTION', checks, extra: { reference: ref, replay: true, previousOutcome: 'confirmed', processedAtMs: tx.processedAtMs } };
        }
        if (credRec.status === 'REDEEMED') { checks.duplicate = 'bad'; return fail('DUPLICATE_TRANSACTION', { reference: ref }); }
        if (credRec.status !== 'ISSUED') { checks.integrity = 'bad'; return fail('INVALID_CREDENTIAL', { reference: ref }); }
        checks.duplicate = 'ok';
        return { ok: true, checks, ctx: { P, F, entries, credRec, ref, settings, isMock: !!(F.flags & 1) } };
    }

    /** Resolve ballot against the live candidate list (no writes). */
    async reconcile(ctx) {
        const voterSnap = await this.db.collection('voters').doc(ctx.credRec.voterId).get();
        if (!voterSnap.exists) return { decision: 'REJECT', code: 'INVALID_CREDENTIAL' };
        const v = voterSnap.data();
        if (v.hasVoted === true) return { decision: 'REJECT', code: 'DUPLICATE_TRANSACTION' };
        const { candidateMap, candidateHashMap } = await this.d.getCandidates();
        const r = resolveBallot(ctx.entries, { candidateMap, candidateHashMap, grade: v.grade, allowedRepPos: this.d.getAllowedRepPos(v.grade), titleOf: this.d.titleOf });
        const problems = [...r.issues, ...r.anomalies];
        if (v.isTrap === true) problems.push('Voter account flagged for committee attention.');
        if (problems.length) return { decision: 'REVIEW', issues: r.issues, anomalies: r.anomalies, reasons: problems };
        return { decision: 'CONFIRM_READY', selections: r.selections, grade: String(v.grade) };
    }

    /** Dry-run for the adviser UI. Never reveals who the voter is or what was selected. */
    async inspect(text) {
        const v = await this.verify(text);
        if (!v.ok) return this._rejection(v);
        const rc = await this.reconcile(v.ctx);
        if (rc.decision === 'REJECT') return this._rejection({ code: rc.code, checks: v.checks, extra: { reference: v.ctx.ref } });
        const base = { success: true, ok: true, valid: rc.decision === 'CONFIRM_READY', decision: rc.decision === 'REVIEW' ? 'REQUIRES_REVIEW' : rc.decision, reference: v.ctx.ref, txRef: v.ctx.ref, mode: v.ctx.isMock ? 'MOCK' : 'LIVE', checks: v.checks };
        if (rc.decision === 'REVIEW') return Object.assign(base, { outcome: 'review', state: 'REJECTED', title: 'Package needs committee review', message: 'The package is authentic, but its ballot could not be fully reconciled with the candidate list.', retryable: false, recommendedAction: ERRORS.REVIEW_REQUIRED.action, reasons: rc.reasons });
        return Object.assign(base, { outcome: 'confirm_ready', state: 'VERIFYING', title: 'Verified eligible voter', message: 'Package authenticated. Ready to record the ballot.' });
    }

    _rejection(v) {
        const body = errorBody(v.code, Object.assign({ checks: v.checks, reference: (v.extra && v.extra.reference) || null }, v.extra || {}));
        if (v.code === 'DUPLICATE_TRANSACTION' && v.extra && v.extra.replay) { body.state = 'SUCCESSFULLY_SUBMITTED'; body.message = 'This exact package was already recorded earlier. No second ballot was created.'; }
        return body;
    }

    /** Authoritative, idempotent, atomic processing. Re-verifies everything; trusts nothing from inspect(). */
    async process(text, { adviserUid, adviserRole } = {}) {
        const v = await this.verify(text);
        if (!v.ok) return this._rejection(v);
        const ctx = v.ctx; const { F } = ctx;
        const rc = await this.reconcile(ctx);
        const txRef = this.db.collection('qr_recoveries').doc(F.txIdHex);
        const processedAtMs = coarse(this.now());
        if (rc.decision === 'REJECT') return this._rejection({ code: rc.code, checks: v.checks, extra: { reference: ctx.ref } });
        if (rc.decision === 'REVIEW') {
            await txRef.set({ txId: F.txIdHex, outcome: 'review', kid: F.kid, reasons: rc.reasons.slice(0, 10), adviserUid: adviserUid || null, processedAtMs });
            return Object.assign(errorBody('REVIEW_REQUIRED', { outcome: 'review', state: 'REJECTED', reference: ctx.ref, reasons: rc.reasons, title: 'Package needs committee review', checks: v.checks }));
        }
        const credRef = this.db.collection('qr_credentials').doc(F.cid);
        const byVoterRef = this.db.collection('qr_cred_by_voter').doc(ctx.credRec.voterId);
        const receiptRef = this.db.collection('receipt_recovery').doc(ctx.credRec.voterId);
        let result;
        try {
            result = await this.db.runTransaction(async (t) => {
                const [txSnap, credSnap, voterSnap] = await Promise.all([t.get(txRef), t.get(credRef), t.get(this.db.collection('voters').doc(ctx.credRec.voterId))]);
                if (txSnap.exists && txSnap.data().outcome === 'confirmed') return { replay: true };
                if (!credSnap.exists || credSnap.data().status !== 'ISSUED') return { dup: true };
                if (!voterSnap.exists) return { bad: 'INVALID_CREDENTIAL' };
                if (voterSnap.data().hasVoted === true) return { dup: true };
                const led = await this.d.ledgerWrite(t, { voterId: ctx.credRec.voterId, grade: rc.grade, selections: rc.selections, mock: ctx.isMock });
                // Unlink voter <-> credential: the redeemed credential keeps no voter reference (ballot secrecy).
                t.set(credRef, { cid: F.cid, kid: F.kid, status: 'REDEEMED', redeemedAtMs: processedAtMs });
                t.delete(byVoterRef);
                t.set(txRef, { txId: F.txIdHex, outcome: 'confirmed', kid: F.kid, adviserUid: adviserUid || null, adviserRole: adviserRole || null, processedAtMs });
                t.set(receiptRef, { ballotKey: 'assisted:' + F.txIdHex, sealed: this.d.sealReceipt({ receipt: led.receipt, hash: led.hash, shardId: led.shardId }), expiresAt: this.d.receiptExpiry(this.now() + ctx.settings.assistedReceiptTtlMinutes * 60000) });
                return { led, voterId: ctx.credRec.voterId, grade: rc.grade, selections: rc.selections };
            });
        } catch (e) {
            const code = /unavailable|deadline|aborted|contention/i.test(String(e && (e.message || e.code))) ? 'SERVER_UNAVAILABLE' : 'STORAGE_FAILURE';
            return errorBody(code, { reference: ctx.ref });
        }
        if (result.replay) return { success: true, ok: true, outcome: 'confirmed', state: 'SUCCESSFULLY_SUBMITTED', duplicate: true, idempotentReplay: true, reference: ctx.ref, title: 'Already recorded', message: 'This package was already recorded. No second ballot was created.', checks: v.checks };
        if (result.dup) return errorBody('DUPLICATE_TRANSACTION', { reference: ctx.ref, checks: v.checks });
        if (result.bad) return errorBody(result.bad, { reference: ctx.ref, checks: v.checks });
        if (this.d.afterCommit) { try { await this.d.afterCommit(result); } catch (_) {} }
        return { success: true, ok: true, outcome: 'confirmed', state: 'SUCCESSFULLY_SUBMITTED', reference: ctx.ref, title: 'Ballot recorded', message: 'The election server verified and recorded this ballot. The voter will be notified automatically.', receiptMask: result.led.masked && result.led.masked.mask, checks: v.checks };
    }

    /** Adviser retry helper: has this transaction already been processed? (no package needed) */
    async txStatus(txIdHex) {
        if (!/^[0-9a-f]{32}$/.test(txIdHex || '')) return { found: false };
        const s = await this.db.collection('qr_recoveries').doc(txIdHex).get();
        if (!s.exists) return { found: false };
        const d = s.data();
        return { found: true, outcome: d.outcome, processedAtMs: d.processedAtMs, state: d.outcome === 'confirmed' ? 'SUCCESSFULLY_SUBMITTED' : 'REJECTED', reference: txIdHex.slice(0, 8).toUpperCase() };
    }

    /** Student-side authoritative status (voter authenticated). Receipt is only released from the voter's own sealed record. */
    async studentStatus(voterId, txIdHex, openSealed) {
        const t = await this.txStatus(txIdHex);
        if (!t.found) return { status: 'NONE' };
        if (t.outcome === 'review') return { status: 'REVIEW' };
        if (t.outcome !== 'confirmed') return { status: 'REJECTED' };
        const r = await this.db.collection('receipt_recovery').doc(voterId).get();
        if (!r.exists || r.data().ballotKey !== 'assisted:' + txIdHex) return { status: 'CONFIRMED' };
        const saved = openSealed(r.data().sealed);
        return saved ? { status: 'CONFIRMED', receipt: saved.receipt, hash: saved.hash, votingStatus: 'ASSISTED VOTED' } : { status: 'CONFIRMED' };
    }
}

/* --------------------------------------------------------------------- routes */
/**
 * deps: { app, service, keyring, requireAuth, requireRole, requireQrRecoveryRole, requireSuperAdmin, verifyCSRF,
 *         limiter, logAdminAction, logSecurityEvent, isMock(): bool, canIssue(req): Promise<{ok,reason}>, openSealed }
 */
function registerRoutes(deps) {
    const { app, service, keyring } = deps;
    const noStore = (res) => res.set('Cache-Control', 'no-store');
    const safeAudit = async (req, action, meta) => { try { await deps.logAdminAction(req, action, meta); } catch (_) {} };
    const unavailable = (res, e) => { console.error('[QR]', e && e.message); return res.status(503).json(errorBody('SERVER_UNAVAILABLE')); };
    const hexTx = (s) => /^[0-9a-f]{32}$/.test(String(s || '')) ? String(s) : null;

    // Public, non-secret: key metadata the student device needs (public encryption key only).
    app.post('/recovery/credential', deps.requireAuth, deps.requireRole('voter'), deps.limiter, deps.verifyCSRF, async (req, res) => {
        noStore(res);
        try {
            const gate = await deps.canIssue(req);
            if (!gate.ok) return res.status(409).json({ success: false, error: gate.reason });
            const out = await service.issueCredential({ voterId: req.user.uid, devicePubB64u: req.body && req.body.devicePub, isMock: deps.isMock() });
            return res.json(Object.assign({ success: true }, out));
        } catch (e) {
            if (e instanceof QrError) return res.status(e.code === 'SERVER_UNAVAILABLE' ? 503 : 400).json(errorBody(e.code));
            return unavailable(res, e);
        }
    });

    app.post('/recovery/status', deps.requireAuth, deps.requireRole('voter'), deps.limiter, deps.verifyCSRF, async (req, res) => {
        noStore(res);
        try {
            const tx = hexTx(req.body && req.body.txId);
            if (!tx) return res.status(400).json({ status: 'NONE' });
            return res.json(await service.studentStatus(req.user.uid, tx, deps.openSealed));
        } catch (e) { return unavailable(res, e); }
    });

    const adviserGate = [deps.requireAuth, deps.requireQrRecoveryRole, deps.verifyCSRF];
    app.post('/admin/recovery/inspect', ...adviserGate, async (req, res) => {
        noStore(res);
        try {
            const out = await service.inspect(String((req.body && req.body.qrPayload) || ''));
            await safeAudit(req, 'QR_RECOVERY_INSPECT', { decision: out.decision || out.outcome, errorCode: out.errorCode || null, reference: out.reference || null });
            return res.json(out);
        } catch (e) { return unavailable(res, e); }
    });
    app.post('/admin/recovery/process', ...adviserGate, async (req, res) => {
        noStore(res);
        try {
            const out = await service.process(String((req.body && req.body.qrPayload) || ''), { adviserUid: req.user && req.user.uid, adviserRole: req.user && req.user.role });
            await safeAudit(req, 'QR_RECOVERY_PROCESS', { outcome: out.outcome, errorCode: out.errorCode || null, reference: out.reference || null, duplicate: !!out.duplicate });
            return res.status(out.errorCode === 'SERVER_UNAVAILABLE' || out.errorCode === 'STORAGE_FAILURE' ? 503 : 200).json(out);
        } catch (e) { return unavailable(res, e); }
    });
    app.post('/admin/recovery/tx-status', ...adviserGate, async (req, res) => {
        noStore(res);
        try {
            const tx = hexTx(req.body && req.body.txId);
            if (!tx) return res.status(400).json(errorBody('INVALID_FORMAT'));
            return res.json(Object.assign({ success: true }, await service.txStatus(tx)));
        } catch (e) { return unavailable(res, e); }
    });

    /* -------- key management (Super Admin only; metadata only, never private material) -------- */
    const superOnly = [deps.requireAuth, deps.requireSuperAdmin, deps.verifyCSRF];
    const publicMeta = (k) => ({ kid: k.kid, label: k.label, version: k.version, status: k.status, alg: k.alg, sigPub: k.sigPub, encPub: k.encPub, createdAtMs: k.createdAtMs, activatesAtMs: k.activatesAtMs, activatedAtMs: k.activatedAtMs, retiredAtMs: k.retiredAtMs, retireCutoffMs: k.retireCutoffMs, revokedAtMs: k.revokedAtMs, revokedReason: k.revokedReason, vault: k.vault, createdBy: k.createdBy });
    const actor = (req) => (req.user && (req.user.email || req.user.uid)) || 'unknown';
    const fail = (res, e) => {
        const m = String((e && e.message) || e);
        if (e instanceof QrError || /^(ONLY_|ACTIVATION_|ALREADY_|INVALID_SETTING|UNKNOWN_KEY)/.test(m)) return res.status(400).json({ success: false, error: m });
        return unavailable(res, e);
    };

    app.get('/admin/qr-keys', deps.requireAuth, deps.requireSuperAdmin, async (req, res) => {
        noStore(res);
        try {
            const [settings, keys, events] = await Promise.all([keyring.getSettings(), keyring.listKeys(), keyring.listEvents(50)]);
            const active = keys.find((k) => k.kid === settings.activeKid) || null;
            const prev = keys.filter((k) => k.status === 'RETIRED').sort((a, b) => b.retiredAtMs - a.retiredAtMs)[0] || null;
            res.json({ success: true, settings: pick(settings, ['electionId', 'rotationEnabled', 'rotationIntervalMonths', 'strictRejection', 'gracePeriodMinutes', 'credentialTtlMinutes', 'packageTtlMinutes', 'activeKid', 'lastRotationAtMs', 'nextRotationAtMs']), active: active && publicMeta(active), previous: prev && publicMeta(prev), keys: keys.map(publicMeta), events, vault: keyring.vault.name, serverTimeMs: Date.now() });
        } catch (e) { return unavailable(res, e); }
    });
    app.post('/admin/qr-keys/generate', ...superOnly, async (req, res) => {
        try { const m = await keyring.generateKey({ actor: actor(req), activatesAtMs: Number(req.body && req.body.activatesAtMs) || null, reason: String((req.body && req.body.reason) || '') }); res.json({ success: true, key: publicMeta(m) }); } catch (e) { fail(res, e); }
    });
    app.post('/admin/qr-keys/schedule', ...superOnly, async (req, res) => {
        try { await keyring.schedule(String(req.body.kid), Number(req.body.activatesAtMs), actor(req)); res.json({ success: true }); } catch (e) { fail(res, e); }
    });
    app.post('/admin/qr-keys/rotate', ...superOnly, async (req, res) => {
        try {
            if (String(req.body && req.body.confirm) !== 'ROTATE') return res.status(400).json({ success: false, error: 'Type ROTATE to confirm.' });
            const kid = req.body.kid ? String(req.body.kid) : null;
            const out = kid ? await keyring.activate(kid, { actor: actor(req) }) : await keyring.rotate({ actor: actor(req), reason: String(req.body.reason || 'manual rotation') });
            res.json({ success: true, result: out });
        } catch (e) { fail(res, e); }
    });
    app.post('/admin/qr-keys/revoke', ...superOnly, async (req, res) => {
        try {
            const kid = String((req.body && req.body.kid) || '');
            if (String(req.body && req.body.confirm) !== 'REVOKE ' + kid) return res.status(400).json({ success: false, error: `Type "REVOKE ${kid}" to confirm.` });
            const reason = String(req.body.reason || '').trim(); if (reason.length < 5) return res.status(400).json({ success: false, error: 'A revocation reason (min 5 chars) is required.' });
            res.json({ success: true, result: await keyring.revoke(kid, { actor: actor(req), reason, autoReplace: req.body.autoReplace !== false }) });
        } catch (e) { fail(res, e); }
    });
    app.post('/admin/qr-keys/settings', ...superOnly, async (req, res) => {
        try { res.json({ success: true, settings: await keyring.updateSettings(req.body || {}, actor(req)) }); } catch (e) { fail(res, e); }
    });
}

module.exports = {
    SCHEMA_VERSION, PREFIX, DEFAULT_SETTINGS, ERRORS, POS_ORDER, REP_BASE, CRED_DOMAIN, HKDF_SALT,
    QrError, errorBody, MemoryVault, EncryptedFirestoreVault, GcpSecretManagerVault, createVaultFromEnv,
    QrKeyring, QrRecoveryService, keyVerificationError, parsePackage, parseBallotPlaintext, resolveBallot, deriveAesKey,
    registerRoutes, eidFor, addMonths
};

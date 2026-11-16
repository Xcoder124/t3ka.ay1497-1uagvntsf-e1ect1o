"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
    LIFECYCLE_STATES,
    parseManilaDateTimeToUtcMs,
    formatUtcMsToManila,
    migrateLegacyConfig,
    deriveElectionLifecycle,
    authorizeBallotSubmission,
    authorizeVoterLogin,
    authorizeRegistrationAction,
    validateScheduleUpdate,
    validateOperationalUpdate
} = require("./election-management");

function buildBaseConfig(overrides = {}) {
    const reg = parseManilaDateTimeToUtcMs("2026-11-18", "17:00");
    const open = parseManilaDateTimeToUtcMs("2026-11-20", "08:00");
    const close = parseManilaDateTimeToUtcMs("2026-11-20", "16:00");
    return {
        configVersion: 1,
        electionId: "sslg-2027",
        timezone: "Asia/Manila",
        operational: {
            isLive: true,
            isPaused: false,
            isQueue: false,
            isMockElection: false,
            gradeSessions: { "7": false, "8": false, "9": false, "10": false, "11": true, "12": false },
            activeGrade: 11,
            votingTimeLimitMinutes: 15,
            ...(overrides.operational || {})
        },
        schedule: {
            timezone: "Asia/Manila",
            registration: {
                deadlineDate: "2026-11-18",
                deadlineTime: "17:00",
                deadlineMs: reg.utcMs,
                overrideActive: false,
                overrideExpiresAtMs: null,
                overrideReason: null,
                overrideBy: null,
                ...(overrides.registration || {})
            },
            voting: {
                date: "2026-11-20",
                opensAt: "08:00",
                closesAt: "16:00",
                opensAtMs: open.utcMs,
                closesAtMs: close.utcMs,
                formallyClosed: false,
                closedAtMs: null,
                ...(overrides.voting || {})
            }
        }
    };
}

const VALID_VOTER = { exists: true, grade: "11", hasVoted: false, isTrap: false, isMissed: false };

// ==========================================
// 1. SCHEDULE & TIMEZONE TESTS
// ==========================================

test("Timezone: Asia/Manila converts accurately to UTC and back", () => {
    const parsed = parseManilaDateTimeToUtcMs("2026-11-20", "08:00");
    assert.equal(parsed.ok, true);
    assert.equal(parsed.isoUtc, "2026-11-20T00:00:00.000Z"); // 08:00+08:00 = 00:00Z
    const back = formatUtcMsToManila(parsed.utcMs);
    assert.equal(back.date, "2026-11-20");
    assert.equal(back.time, "08:00");
});

test("Schedule: Rejects invalid calendar dates and closing <= opening", () => {
    const badDate = parseManilaDateTimeToUtcMs("2026-02-30", "08:00");
    assert.equal(badDate.ok, false);

    const cfg = buildBaseConfig();
    const badSched = validateScheduleUpdate(cfg, {
        voting: { date: "2026-11-20", opensAt: "16:00", closesAt: "08:00", confirmActiveChange: true }
    }, cfg.schedule.registration.deadlineMs - 1000);
    assert.equal(badSched.ok, false);
    assert.match(badSched.errors.voting, /later than opening time/i);
});

test("Schedule: Registration before, at, and after deadline + override", () => {
    const cfg = buildBaseConfig();
    const dl = cfg.schedule.registration.deadlineMs;

    assert.equal(authorizeRegistrationAction({ config: cfg, nowMs: dl - 1 }).allowed, true);
    assert.equal(authorizeRegistrationAction({ config: cfg, nowMs: dl }).allowed, false);
    assert.equal(authorizeRegistrationAction({ config: cfg, nowMs: dl + 1000 }).allowed, false);

    // Override without justification fails
    const noReason = authorizeRegistrationAction({ config: cfg, adminOverride: true, overrideReason: "ok", nowMs: dl + 1000 });
    assert.equal(noReason.allowed, false);

    // Override with valid justification succeeds
    const withReason = authorizeRegistrationAction({ config: cfg, adminOverride: true, overrideReason: "Late transferee approved by principal", nowMs: dl + 1000 });
    assert.equal(withReason.allowed, true);
    assert.equal(withReason.overridden, true);
});

test("Schedule: Voting before open, at open, during, at close, and after close", () => {
    const cfg = buildBaseConfig();
    const open = cfg.schedule.voting.opensAtMs;
    const close = cfg.schedule.voting.closesAtMs;

    // Before open
    const before = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: open + 60000 }, nowMs: open - 1 });
    assert.equal(before.allowed, false);
    assert.equal(before.code, "VOTING_NOT_OPEN_YET");

    // Exactly at open
    const atOpen = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: open + 60000 }, nowMs: open });
    assert.equal(atOpen.allowed, true);

    // During voting
    const during = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: open + 3600000 }, nowMs: open + 1800000 });
    assert.equal(during.allowed, true);

    // Exactly at closing time -> rejected & lifecycle VOTING_CLOSED
    const atClose = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: close + 60000 }, nowMs: close });
    assert.equal(atClose.allowed, false);
    assert.equal(atClose.code, "VOTING_CLOSED");
    assert.equal(deriveElectionLifecycle(cfg, close).state, LIFECYCLE_STATES.VOTING_CLOSED);

    // After closing time -> cannot auto-reopen
    const reopen = validateOperationalUpdate(cfg, { isLive: true }, { nowMs: close + 5000 });
    assert.equal(reopen.ok, false);
});

// ==========================================
// 2. OPERATIONAL & LIFECYCLE TESTS
// ==========================================

test("Operational: Inactive election blocks voting even when schedule is open", () => {
    const cfg = buildBaseConfig({ operational: { isLive: false } });
    const now = cfg.schedule.voting.opensAtMs + 60000;
    assert.equal(deriveElectionLifecycle(cfg, now).state, LIFECYCLE_STATES.VOTING_SCHEDULED);

    const res = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: now + 60000 }, nowMs: now });
    assert.equal(res.allowed, false);
    assert.equal(res.code, "ELECTION_INACTIVE");
});

test("Operational: Manual pause blocks new submissions without altering schedule", () => {
    const cfg = buildBaseConfig({ operational: { isLive: true, isPaused: true } });
    const now = cfg.schedule.voting.opensAtMs + 60000;
    assert.equal(deriveElectionLifecycle(cfg, now).state, LIFECYCLE_STATES.VOTING_PAUSED);

    const res = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: now + 60000 }, nowMs: now });
    assert.equal(res.allowed, false);
    assert.equal(res.code, "ELECTION_PAUSED");
    assert.equal(cfg.schedule.voting.closesAt, "16:00");
});

test("Operational: Mock mode isolates official ballots and blocks unsafe switching with active sessions", () => {
    const cfg = buildBaseConfig({ operational: { isMockElection: true } });
    const now = cfg.schedule.voting.opensAtMs + 60000;

    const officialVote = authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: now + 60000 }, nowMs: now });
    assert.equal(officialVote.allowed, false);
    assert.equal(officialVote.code, "MOCK_MODE_ACTIVE");

    const unsafeSwitch = validateOperationalUpdate(cfg, { isMockElection: false }, { activeSessionCount: 3, nowMs: now });
    assert.equal(unsafeSwitch.ok, false);
    assert.match(unsafeSwitch.errors.isMockElection, /3 voting session/);
});

test("Operational: Activating Grade 11 does not activate other grade levels", () => {
    const cfg = buildBaseConfig({ operational: { gradeSessions: { "7": false, "8": false, "9": false, "10": false, "11": false, "12": false } } });
    const upd = validateOperationalUpdate(cfg, { gradeSessions: { "11": true } });
    assert.equal(upd.ok, true);
    assert.equal(upd.nextOperational.gradeSessions["11"], true);
    assert.equal(upd.nextOperational.gradeSessions["7"], false);
    assert.equal(upd.nextOperational.gradeSessions["12"], false);
});

// ==========================================
// 3. SECURITY & CONCURRENCY TESTS
// ==========================================

test("Security: Rejects unregistered, wrong grade, duplicate vote, and expired individual session", () => {
    const cfg = buildBaseConfig();
    const now = cfg.schedule.voting.opensAtMs + 60000;
    const validSess = { expiresAtMs: now + 60000 };

    assert.equal(authorizeBallotSubmission({ config: cfg, voter: { exists: false }, session: validSess, nowMs: now }).code, "VOTER_UNREGISTERED");
    assert.equal(authorizeBallotSubmission({ config: cfg, voter: { ...VALID_VOTER, grade: "7" }, session: validSess, nowMs: now }).code, "GRADE_SESSION_INACTIVE");
    assert.equal(authorizeBallotSubmission({ config: cfg, voter: { ...VALID_VOTER, hasVoted: true }, session: validSess, nowMs: now }).code, "ALREADY_VOTED");
    assert.equal(authorizeBallotSubmission({ config: cfg, voter: VALID_VOTER, session: { expiresAtMs: now - 1 }, nowMs: now }).code, "SESSION_EXPIRED");
});

test("Security: Rejects zero, negative, or oversized voting time limits", () => {
    const cfg = buildBaseConfig();
    assert.equal(validateOperationalUpdate(cfg, { votingTimeLimitMinutes: 0 }).ok, false);
    assert.equal(validateOperationalUpdate(cfg, { votingTimeLimitMinutes: -5 }).ok, false);
    assert.equal(validateOperationalUpdate(cfg, { votingTimeLimitMinutes: 181 }).ok, false);
    assert.equal(validateOperationalUpdate(cfg, { votingTimeLimitMinutes: 15.5 }).ok, false);
    assert.equal(validateOperationalUpdate(cfg, { votingTimeLimitMinutes: 20 }).ok, true);
});

test("Migration: Preserves legacy activeGrade and never silently activates election", () => {
    const migrated = migrateLegacyConfig({
        electionStatusDoc: { activeGrade: 11 },
        configDoc: { voterTimeoutMinutes: 25 },
        rtdbStatus: { isLive: false, isQueue: true, isMockElection: false }
    });
    assert.equal(migrated.operational.isLive, false);
    assert.equal(migrated.operational.isQueue, true);
    assert.equal(migrated.operational.gradeSessions["11"], true);
    assert.equal(migrated.operational.gradeSessions["10"], false);
    assert.equal(migrated.operational.votingTimeLimitMinutes, 25);
});

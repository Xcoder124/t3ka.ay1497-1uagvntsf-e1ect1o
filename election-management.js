"use strict";

/**
 * E-Boto Election Status, Schedule, Lifecycle & Authorization Engine
 * ------------------------------------------------------------------
 * Single authoritative source of truth for:
 *  1. Election Live Management (operational controls: status, pause, mock mode, grade sessions, per-student time limit)
 *  2. Election Schedule Settings (time-based configuration in Asia/Manila stored as UTC ms)
 *  3. Derived Election Lifecycle State (7-state deterministic state machine)
 *  4. Unified Election Authorization Logic (voter login, ballot submission, registration & overrides)
 *  5. Configuration Validation, Optimistic Concurrency & Backward-Compatible Migration
 */

const ELECTION_TIMEZONE = "Asia/Manila";
const MANILA_OFFSET_MS = 8 * 60 * 60 * 1000; // UTC+08:00 (Philippines has no DST)

const SUPPORTED_GRADES = ["7", "8", "9", "10", "11", "12"];
const MIN_VOTING_TIME_LIMIT_MINUTES = 1;
const MAX_VOTING_TIME_LIMIT_MINUTES = 180;
const DEFAULT_VOTING_TIME_LIMIT_MINUTES = 15;

const LIFECYCLE_STATES = Object.freeze({
    PREPARATION: "PREPARATION",
    REGISTRATION_OPEN: "REGISTRATION_OPEN",
    REGISTRATION_CLOSED: "REGISTRATION_CLOSED",
    VOTING_SCHEDULED: "VOTING_SCHEDULED",
    VOTING_OPEN: "VOTING_OPEN",
    VOTING_PAUSED: "VOTING_PAUSED",
    VOTING_CLOSED: "VOTING_CLOSED"
});

/**
 * Parse YYYY-MM-DD and HH:mm in Asia/Manila into authoritative UTC epoch milliseconds.
 * Rejects impossible calendar dates (e.g., 2026-02-30) and invalid times.
 */
function parseManilaDateTimeToUtcMs(dateStr, timeStr) {
    if (typeof dateStr !== "string" || typeof timeStr !== "string") {
        return { ok: false, error: "Date and time must be strings." };
    }
    const dMatch = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr.trim());
    const tMatch = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(timeStr.trim());
    if (!dMatch) {
        return { ok: false, error: "Invalid date format. Expected YYYY-MM-DD." };
    }
    if (!tMatch) {
        return { ok: false, error: "Invalid time format. Expected HH:MM (24-hour)." };
    }

    const year = Number(dMatch[1]);
    const month = Number(dMatch[2]);
    const day = Number(dMatch[3]);
    const hour = Number(tMatch[1]);
    const minute = Number(tMatch[2]);

    if (month < 1 || month > 12 || day < 1 || day > 31) {
        return { ok: false, error: "Invalid calendar month or day." };
    }

    // Validate actual calendar date in UTC (no rollover like Feb 30 -> Mar 2)
    const checkDate = new Date(Date.UTC(year, month - 1, day, 0, 0, 0, 0));
    if (
        checkDate.getUTCFullYear() !== year ||
        checkDate.getUTCMonth() !== month - 1 ||
        checkDate.getUTCDate() !== day
    ) {
        return { ok: false, error: `Invalid calendar date: ${dateStr}.` };
    }

    const manilaAsUtcMs = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
    const utcMs = manilaAsUtcMs - MANILA_OFFSET_MS;
    return {
        ok: true,
        utcMs,
        isoUtc: new Date(utcMs).toISOString(),
        date: dateStr.trim(),
        time: timeStr.trim()
    };
}

/**
 * Convert UTC epoch milliseconds to Asia/Manila date/time parts.
 */
function formatUtcMsToManila(utcMs) {
    if (utcMs == null || !Number.isFinite(Number(utcMs))) return null;
    const shifted = new Date(Number(utcMs) + MANILA_OFFSET_MS);
    const year = shifted.getUTCFullYear();
    const month = String(shifted.getUTCMonth() + 1).padStart(2, "0");
    const day = String(shifted.getUTCDate()).padStart(2, "0");
    const hour = String(shifted.getUTCHours()).padStart(2, "0");
    const minute = String(shifted.getUTCMinutes()).padStart(2, "0");
    return {
        date: `${year}-${month}-${day}`,
        time: `${hour}:${minute}`,
        utcMs: Number(utcMs),
        isoUtc: new Date(Number(utcMs)).toISOString(),
        display: `${year}-${month}-${day} ${hour}:${minute} (Asia/Manila)`
    };
}

function createEmptyGradeSessions(defaultVal = false) {
    const map = {};
    for (const g of SUPPORTED_GRADES) {
        map[g] = Boolean(defaultVal);
    }
    return map;
}

function normalizeGradeSessions(rawSessions, legacyActiveGrade) {
    if (rawSessions && typeof rawSessions === "object") {
        const out = createEmptyGradeSessions(false);
        for (const g of SUPPORTED_GRADES) {
            out[g] = rawSessions[g] === true;
        }
        return out;
    }
    if (legacyActiveGrade === "ALL" || legacyActiveGrade === 0 || legacyActiveGrade === "0") {
        return createEmptyGradeSessions(true);
    }
    const gStr = String(legacyActiveGrade || "").trim();
    const out = createEmptyGradeSessions(false);
    if (SUPPORTED_GRADES.includes(gStr)) {
        out[gStr] = true;
    }
    return out;
}

function deriveLegacyActiveGrade(gradeSessions) {
    const active = SUPPORTED_GRADES.filter((g) => gradeSessions[g] === true);
    if (active.length === SUPPORTED_GRADES.length) return "ALL";
    if (active.length === 1) return Number(active[0]);
    if (active.length === 0) return "NONE";
    return active.join(",");
}

/**
 * Backward-compatible migration from legacy Firestore + RTDB documents
 * into the unified election configuration model.
 * Never silently activates or deactivates an existing election.
 */
function migrateLegacyConfig({ electionStatusDoc = {}, configDoc = {}, rtdbStatus = {} } = {}) {
    const configVersion = Number.isInteger(electionStatusDoc.configVersion) && electionStatusDoc.configVersion >= 1
        ? electionStatusDoc.configVersion
        : 1;

    const isLive = rtdbStatus.isLive === true;
    const isPaused = electionStatusDoc.isPaused === true || rtdbStatus.isPaused === true;
    const isQueue = rtdbStatus.isQueue === true;
    const isMockElection = rtdbStatus.isMockElection === true;

    const gradeSessions = normalizeGradeSessions(
        electionStatusDoc.gradeSessions,
        electionStatusDoc.activeGrade
    );

    // Map per-student voting time limit (distinct from legacy election-wide endTime)
    let votingTimeLimitMinutes = DEFAULT_VOTING_TIME_LIMIT_MINUTES;
    if (Number.isInteger(electionStatusDoc.votingTimeLimitMinutes) &&
        electionStatusDoc.votingTimeLimitMinutes >= MIN_VOTING_TIME_LIMIT_MINUTES &&
        electionStatusDoc.votingTimeLimitMinutes <= MAX_VOTING_TIME_LIMIT_MINUTES) {
        votingTimeLimitMinutes = electionStatusDoc.votingTimeLimitMinutes;
    } else if (Number.isInteger(configDoc.voterTimeoutMinutes) &&
        configDoc.voterTimeoutMinutes >= MIN_VOTING_TIME_LIMIT_MINUTES &&
        configDoc.voterTimeoutMinutes <= MAX_VOTING_TIME_LIMIT_MINUTES) {
        votingTimeLimitMinutes = configDoc.voterTimeoutMinutes;
    }

    const toFiniteMs = (v) => {
        if (v === null || v === undefined || v === "") return null;
        if (typeof v === "object" && typeof v.toMillis === "function") return v.toMillis();
        const n = Number(v);
        return Number.isFinite(n) && n > 0 ? n : null;
    };

    const reg = electionStatusDoc.schedule?.registration || {};
    const regDeadlineMs = toFiniteMs(reg.deadlineMs);
    const regManila = regDeadlineMs ? formatUtcMsToManila(regDeadlineMs) : null;

    const vot = electionStatusDoc.schedule?.voting || {};
    const opensAtMs = toFiniteMs(vot.opensAtMs);
    const closesAtMs = toFiniteMs(vot.closesAtMs);
    const opensManila = opensAtMs ? formatUtcMsToManila(opensAtMs) : null;
    const closesManila = closesAtMs ? formatUtcMsToManila(closesAtMs) : null;

    return {
        configVersion,
        electionId: String(electionStatusDoc.electionId || "sslg-2027"),
        timezone: ELECTION_TIMEZONE,
        operational: {
            isLive,
            isPaused: isLive ? isPaused : false,
            isQueue,
            isMockElection,
            gradeSessions,
            activeGrade: deriveLegacyActiveGrade(gradeSessions),
            votingTimeLimitMinutes
        },
        schedule: {
            timezone: ELECTION_TIMEZONE,
            registration: {
                deadlineDate: reg.deadlineDate || (regManila ? regManila.date : null),
                deadlineTime: reg.deadlineTime || (regManila ? regManila.time : null),
                deadlineMs: regDeadlineMs,
                overrideActive: reg.overrideActive === true,
                overrideExpiresAtMs: toFiniteMs(reg.overrideExpiresAtMs),
                overrideReason: reg.overrideReason || null,
                overrideBy: reg.overrideBy || null
            },
            voting: {
                date: vot.date || (opensManila ? opensManila.date : null),
                opensAt: vot.opensAt || (opensManila ? opensManila.time : null),
                closesAt: vot.closesAt || (closesManila ? closesManila.time : null),
                opensAtMs,
                closesAtMs,
                formallyClosed: vot.formallyClosed === true,
                closedAtMs: toFiniteMs(vot.closedAtMs)
            }
        }
    };
}

/**
 * Derives the authoritative election lifecycle state from persisted config + server time.
 */
function deriveElectionLifecycle(config, nowMs = Date.now()) {
    const op = config?.operational || {};
    const reg = config?.schedule?.registration || {};
    const vot = config?.schedule?.voting || {};

    const hasReg = Number.isFinite(reg.deadlineMs);
    const hasVoting = Number.isFinite(vot.opensAtMs) && Number.isFinite(vot.closesAtMs);

    const regOverrideValid = reg.overrideActive === true &&
        (!Number.isFinite(reg.overrideExpiresAtMs) || nowMs < reg.overrideExpiresAtMs);
    const regOpen = hasReg && (nowMs < reg.deadlineMs || regOverrideValid);
    const regClosed = hasReg && nowMs >= reg.deadlineMs && !regOverrideValid;

    // 1. Formal closure or voting closing time reached -> VOTING_CLOSED (cannot auto-reopen)
    if (vot.formallyClosed === true || (hasVoting && nowMs >= vot.closesAtMs)) {
        return {
            state: LIFECYCLE_STATES.VOTING_CLOSED,
            registrationStatus: regOpen ? (regOverrideValid && nowMs >= reg.deadlineMs ? "OVERRIDE" : "OPEN") : (regClosed ? "CLOSED" : "UNCONFIGURED"),
            scheduleStatus: "CLOSED",
            canVoteNow: false,
            canRegisterNow: regOpen
        };
    }

    // 2. Inside official voting window
    if (hasVoting && nowMs >= vot.opensAtMs && nowMs < vot.closesAtMs) {
        if (op.isLive === true && op.isPaused === true) {
            return {
                state: LIFECYCLE_STATES.VOTING_PAUSED,
                registrationStatus: regOpen ? (regOverrideValid && nowMs >= reg.deadlineMs ? "OVERRIDE" : "OPEN") : (regClosed ? "CLOSED" : "UNCONFIGURED"),
                scheduleStatus: "OPEN",
                canVoteNow: false,
                canRegisterNow: regOpen
            };
        }
        if (op.isLive === true) {
            return {
                state: LIFECYCLE_STATES.VOTING_OPEN,
                registrationStatus: regOpen ? (regOverrideValid && nowMs >= reg.deadlineMs ? "OVERRIDE" : "OPEN") : (regClosed ? "CLOSED" : "UNCONFIGURED"),
                scheduleStatus: "OPEN",
                canVoteNow: true,
                canRegisterNow: regOpen
            };
        }
        // Official window is open, but admin has not manually activated election
        return {
            state: LIFECYCLE_STATES.VOTING_SCHEDULED,
            registrationStatus: regOpen ? (regOverrideValid && nowMs >= reg.deadlineMs ? "OVERRIDE" : "OPEN") : (regClosed ? "CLOSED" : "UNCONFIGURED"),
            scheduleStatus: "OPEN_AWAITING_ACTIVATION",
            canVoteNow: false,
            canRegisterNow: regOpen
        };
    }

    // 3. Before voting opens
    if (hasVoting && nowMs < vot.opensAtMs) {
        if (regOpen) {
            return {
                state: LIFECYCLE_STATES.REGISTRATION_OPEN,
                registrationStatus: regOverrideValid && nowMs >= reg.deadlineMs ? "OVERRIDE" : "OPEN",
                scheduleStatus: "SCHEDULED",
                canVoteNow: false,
                canRegisterNow: true
            };
        }
        return {
            state: LIFECYCLE_STATES.VOTING_SCHEDULED,
            registrationStatus: regClosed ? "CLOSED" : "UNCONFIGURED",
            scheduleStatus: "SCHEDULED",
            canVoteNow: false,
            canRegisterNow: false
        };
    }

    // 4. No voting schedule configured yet
    if (regOpen) {
        return {
            state: LIFECYCLE_STATES.REGISTRATION_OPEN,
            registrationStatus: regOverrideValid && nowMs >= reg.deadlineMs ? "OVERRIDE" : "OPEN",
            scheduleStatus: "UNCONFIGURED",
            canVoteNow: false,
            canRegisterNow: true
        };
    }
    if (regClosed) {
        return {
            state: LIFECYCLE_STATES.REGISTRATION_CLOSED,
            registrationStatus: "CLOSED",
            scheduleStatus: "UNCONFIGURED",
            canVoteNow: false,
            canRegisterNow: false
        };
    }

    return {
        state: LIFECYCLE_STATES.PREPARATION,
        registrationStatus: "UNCONFIGURED",
        scheduleStatus: "UNCONFIGURED",
        canVoteNow: false,
        canRegisterNow: true // Before a registration deadline is set, preparation/registration is permitted unless locked
    };
}

/**
 * Authoritative 8-condition backend ballot submission authorization.
 * Also used (with session check adapted) for voter login eligibility.
 */
function authorizeBallotSubmission({
    config,
    voter,
    session,
    submissionMode = "OFFICIAL",
    nowMs = Date.now()
}) {
    const op = config?.operational || {};
    const vot = config?.schedule?.voting || {};
    const lifecycle = deriveElectionLifecycle(config, nowMs);

    // Condition 7: Election mode isolation
    if (op.isMockElection === true || submissionMode === "MOCK" || session?.isMockElection === true) {
        return { allowed: false, code: "MOCK_MODE_ACTIVE", status: 403, error: "Live ballot submission is disabled during Mock Election Mode." };
    }

    // Condition 8: No formal closure or administrative suspension
    if (vot.formallyClosed === true || lifecycle.state === LIFECYCLE_STATES.VOTING_CLOSED) {
        return { allowed: false, code: "VOTING_CLOSED", status: 403, error: "Voting schedule has closed. New ballot submissions are prohibited." };
    }

    // Condition 1: Election is manually activated and not paused
    if (op.isLive !== true) {
        return { allowed: false, code: "ELECTION_INACTIVE", status: 403, error: "Election is currently inactive." };
    }
    if (op.isPaused === true) {
        return { allowed: false, code: "ELECTION_PAUSED", status: 403, error: "Voting is currently paused by an administrator." };
    }

    // Condition 2: Authoritative server time is within official voting schedule
    if (!Number.isFinite(vot.opensAtMs) || !Number.isFinite(vot.closesAtMs)) {
        return { allowed: false, code: "VOTING_NOT_SCHEDULED", status: 403, error: "Official voting schedule is not configured." };
    }
    if (nowMs < vot.opensAtMs) {
        return { allowed: false, code: "VOTING_NOT_OPEN_YET", status: 403, error: "Official voting schedule has not opened yet." };
    }
    if (nowMs >= vot.closesAtMs) {
        return { allowed: false, code: "VOTING_CLOSED", status: 403, error: "Official voting schedule has closed." };
    }

    // Condition 4: Student is registered and eligible
    if (!voter || voter.exists === false) {
        return { allowed: false, code: "VOTER_UNREGISTERED", status: 403, error: "Voter is not registered." };
    }
    if (voter.isTrap === true) {
        return { allowed: false, code: "VOTER_INELIGIBLE", status: 403, error: "Voter account is not eligible for official voting." };
    }
    if (voter.isMissed === true) {
        return { allowed: false, code: "VOTER_MISSED", status: 403, error: "Voting session missed cutoff." };
    }

    // Condition 3: Student's grade-level session is active
    const grade = String(voter.grade || "").trim();
    if (!SUPPORTED_GRADES.includes(grade) || op.gradeSessions?.[grade] !== true) {
        return { allowed: false, code: "GRADE_SESSION_INACTIVE", status: 403, error: `Voting session for Grade ${grade || "Unknown"} is currently inactive.` };
    }

    // Condition 5: Student has not already submitted a ballot
    if (voter.hasVoted === true) {
        return { allowed: false, code: "ALREADY_VOTED", status: 403, error: "Already voted." };
    }

    // Condition 6: Individual voting session is valid and has not expired
    if (!session || !Number.isFinite(session.expiresAtMs)) {
        return { allowed: false, code: "INVALID_SESSION", status: 401, error: "Individual voting session is missing or invalid." };
    }
    if (nowMs > session.expiresAtMs) {
        return { allowed: false, code: "SESSION_EXPIRED", status: 403, error: "Your individual voting session time limit has expired." };
    }

    return { allowed: true, code: "AUTHORIZED", status: 200, lifecycleState: lifecycle.state };
}

/**
 * Authorizes voter login (Checks Conditions 1, 2, 3, 4, 5, 7, 8 — Condition 6 is created upon login).
 */
function authorizeVoterLogin({ config, voter, nowMs = Date.now() }) {
    const op = config?.operational || {};
    const vot = config?.schedule?.voting || {};

    if (!voter || voter.exists === false) {
        return { allowed: false, code: "VOTER_UNREGISTERED", status: 401, error: "Invalid Credentials." };
    }

    // Mock mode handles trap/demo accounts separately
    if (op.isMockElection === true && voter.isTrap === true) {
        return { allowed: true, code: "MOCK_AUTHORIZED", status: 200, isMock: true };
    }
    if (op.isMockElection === true) {
        return { allowed: false, code: "MOCK_MODE_ACTIVE", status: 403, error: "Mock Election Mode is active. Official voter login is disabled." };
    }

    if (vot.formallyClosed === true || (Number.isFinite(vot.closesAtMs) && nowMs >= vot.closesAtMs)) {
        return { allowed: false, code: "VOTING_CLOSED", status: 403, error: "Official voting schedule has closed." };
    }
    if (op.isLive !== true) {
        return { allowed: false, code: "ELECTION_INACTIVE", status: 403, error: "Election PAUSED." };
    }
    if (op.isPaused === true) {
        return { allowed: false, code: "ELECTION_PAUSED", status: 403, error: "Election PAUSED by administrator." };
    }
    if (!Number.isFinite(vot.opensAtMs) || !Number.isFinite(vot.closesAtMs)) {
        return { allowed: false, code: "VOTING_NOT_SCHEDULED", status: 403, error: "Voting schedule is not configured." };
    }
    if (nowMs < vot.opensAtMs) {
        return { allowed: false, code: "VOTING_NOT_OPEN_YET", status: 403, error: "Voting has not opened yet." };
    }

    if (voter.isMissed === true) {
        return { allowed: false, code: "VOTER_MISSED", status: 403, error: "Voting Session Expired: You missed the cutoff time." };
    }
    if (voter.hasVoted === true) {
        return { allowed: false, code: "ALREADY_VOTED", status: 403, error: "Already Voted." };
    }

    const grade = String(voter.grade || "").trim();
    if (!SUPPORTED_GRADES.includes(grade) || op.gradeSessions?.[grade] !== true) {
        return { allowed: false, code: "GRADE_SESSION_INACTIVE", status: 403, error: `Grade ${grade || "Unknown"} voting session is currently inactive.` };
    }

    return { allowed: true, code: "AUTHORIZED", status: 200, isMock: false };
}

/**
 * Authorizes registration or authorized voter record corrections against the Registration Period.
 */
function authorizeRegistrationAction({ config, adminOverride = false, overrideReason = "", nowMs = Date.now() }) {
    const reg = config?.schedule?.registration || {};
    if (!Number.isFinite(reg.deadlineMs)) {
        return { allowed: true, code: "NO_DEADLINE_SET", status: 200 };
    }
    if (nowMs < reg.deadlineMs) {
        return { allowed: true, code: "BEFORE_DEADLINE", status: 200 };
    }
    // Check active temporary override
    if (reg.overrideActive === true && (!Number.isFinite(reg.overrideExpiresAtMs) || nowMs < reg.overrideExpiresAtMs)) {
        return { allowed: true, code: "OVERRIDE_WINDOW_ACTIVE", status: 200, overridden: true };
    }
    // Explicit per-request admin override
    if (adminOverride === true) {
        if (!overrideReason || String(overrideReason).trim().length < 5) {
            return { allowed: false, code: "OVERRIDE_REASON_REQUIRED", status: 400, error: "An override justification (at least 5 characters) is required." };
        }
        return { allowed: true, code: "ADMIN_OVERRIDE", status: 200, overridden: true };
    }
    return {
        allowed: false,
        code: "REGISTRATION_CLOSED",
        status: 403,
        error: "Registration and corrections are locked because the registration deadline has passed."
    };
}

/**
 * Validates and builds an updated Schedule configuration.
 */
function validateScheduleUpdate(currentConfig, payload, nowMs = Date.now()) {
    const lifecycle = deriveElectionLifecycle(currentConfig, nowMs);
    const errors = {};
    const nextSchedule = JSON.parse(JSON.stringify(currentConfig.schedule));

    if (payload.registration) {
        const { deadlineDate, deadlineTime, overrideActive, overrideMinutes, overrideReason, confirmPostDeadlineEdit } = payload.registration;
        const regClosed = Number.isFinite(currentConfig.schedule.registration.deadlineMs) &&
            nowMs >= currentConfig.schedule.registration.deadlineMs;

        if (deadlineDate !== undefined || deadlineTime !== undefined) {
            if (regClosed && confirmPostDeadlineEdit !== true) {
                errors.registration = "Registration is already closed. Confirm an authorized override with justification to modify the deadline.";
            } else if (deadlineDate === null && deadlineTime === null) {
                nextSchedule.registration.deadlineDate = null;
                nextSchedule.registration.deadlineTime = null;
                nextSchedule.registration.deadlineMs = null;
            } else {
                const parsed = parseManilaDateTimeToUtcMs(deadlineDate, deadlineTime);
                if (!parsed.ok) {
                    errors.registration = parsed.error;
                } else {
                    nextSchedule.registration.deadlineDate = parsed.date;
                    nextSchedule.registration.deadlineTime = parsed.time;
                    nextSchedule.registration.deadlineMs = parsed.utcMs;
                }
            }
        }

        if (typeof overrideActive === "boolean") {
            if (overrideActive === true) {
                if (!overrideReason || String(overrideReason).trim().length < 5) {
                    errors.registrationOverride = "A reason (at least 5 characters) is required to activate a registration override.";
                } else {
                    const mins = Number(overrideMinutes) || 30;
                    if (!Number.isFinite(mins) || mins < 1 || mins > 1440) {
                        errors.registrationOverride = "Override duration must be between 1 and 1440 minutes.";
                    } else {
                        nextSchedule.registration.overrideActive = true;
                        nextSchedule.registration.overrideExpiresAtMs = nowMs + mins * 60 * 1000;
                        nextSchedule.registration.overrideReason = String(overrideReason).trim();
                    }
                }
            } else {
                nextSchedule.registration.overrideActive = false;
                nextSchedule.registration.overrideExpiresAtMs = null;
                nextSchedule.registration.overrideReason = null;
            }
        }
    }

    if (payload.voting) {
        const { date, opensAt, closesAt, confirmActiveChange } = payload.voting;
        const isActivelyVoting = lifecycle.state === LIFECYCLE_STATES.VOTING_OPEN || lifecycle.state === LIFECYCLE_STATES.VOTING_PAUSED;

        if (isActivelyVoting && confirmActiveChange !== true) {
            errors.voting = "Voting is currently in progress. Explicit confirmation is required to modify the voting schedule.";
        } else {
            const parsedOpen = parseManilaDateTimeToUtcMs(date, opensAt);
            const parsedClose = parseManilaDateTimeToUtcMs(date, closesAt);
            if (!parsedOpen.ok) {
                errors.voting = `Opening time error: ${parsedOpen.error}`;
            } else if (!parsedClose.ok) {
                errors.voting = `Closing time error: ${parsedClose.error}`;
            } else if (parsedClose.utcMs <= parsedOpen.utcMs) {
                errors.voting = "Closing time must be later than opening time.";
            } else {
                nextSchedule.voting.date = parsedOpen.date;
                nextSchedule.voting.opensAt = parsedOpen.time;
                nextSchedule.voting.closesAt = parsedClose.time;
                nextSchedule.voting.opensAtMs = parsedOpen.utcMs;
                nextSchedule.voting.closesAtMs = parsedClose.utcMs;
                // Reconfiguring a future voting window clears prior formal closure
                if (parsedClose.utcMs > nowMs) {
                    nextSchedule.voting.formallyClosed = false;
                    nextSchedule.voting.closedAtMs = null;
                }
            }
        }
    }

    if (Object.keys(errors).length > 0) {
        return { ok: false, errors };
    }
    return { ok: true, nextSchedule };
}

/**
 * Validates and builds an updated Operational (Election Live Management) configuration.
 */
function validateOperationalUpdate(currentConfig, payload, { activeSessionCount = 0, nowMs = Date.now() } = {}) {
    const errors = {};
    const nextOp = JSON.parse(JSON.stringify(currentConfig.operational));
    const lifecycle = deriveElectionLifecycle(currentConfig, nowMs);

    if (typeof payload.isLive === "boolean") {
        if (payload.isLive === true && lifecycle.state === LIFECYCLE_STATES.VOTING_CLOSED && payload.isMockElection !== true) {
            errors.isLive = "Cannot activate election after the official voting schedule has closed. Configure a new voting schedule first.";
        } else {
            nextOp.isLive = payload.isLive;
            if (!payload.isLive) {
                nextOp.isPaused = false;
            }
        }
    }

    if (typeof payload.isPaused === "boolean") {
        if (payload.isPaused === true && nextOp.isLive !== true) {
            errors.isPaused = "Cannot pause an inactive election.";
        } else {
            nextOp.isPaused = payload.isPaused;
        }
    }

    if (typeof payload.isQueue === "boolean") {
        nextOp.isQueue = payload.isQueue;
    }

    if (typeof payload.isMockElection === "boolean") {
        if (payload.isMockElection !== currentConfig.operational.isMockElection && activeSessionCount > 0) {
            errors.isMockElection = `Cannot switch Mock Election Mode while ${activeSessionCount} voting session(s) are in progress.`;
        } else {
            nextOp.isMockElection = payload.isMockElection;
        }
    }

    if (payload.gradeSessions && typeof payload.gradeSessions === "object") {
        for (const [k, v] of Object.entries(payload.gradeSessions)) {
            if (!SUPPORTED_GRADES.includes(String(k))) {
                errors.gradeSessions = `Unsupported grade level: ${k}.`;
                break;
            }
            if (typeof v !== "boolean") {
                errors.gradeSessions = `Grade ${k} session state must be a boolean.`;
                break;
            }
            nextOp.gradeSessions[String(k)] = v;
        }
        nextOp.activeGrade = deriveLegacyActiveGrade(nextOp.gradeSessions);
    } else if (payload.activeGrade !== undefined) {
        nextOp.gradeSessions = normalizeGradeSessions(null, payload.activeGrade);
        nextOp.activeGrade = deriveLegacyActiveGrade(nextOp.gradeSessions);
    }

    if (payload.votingTimeLimitMinutes !== undefined) {
        const mins = Number(payload.votingTimeLimitMinutes);
        if (!Number.isInteger(mins) || mins < MIN_VOTING_TIME_LIMIT_MINUTES || mins > MAX_VOTING_TIME_LIMIT_MINUTES) {
            errors.votingTimeLimitMinutes = `Voting time limit must be a whole number between ${MIN_VOTING_TIME_LIMIT_MINUTES} and ${MAX_VOTING_TIME_LIMIT_MINUTES} minutes.`;
        } else {
            nextOp.votingTimeLimitMinutes = mins;
        }
    }

    if (Object.keys(errors).length > 0) {
        return { ok: false, errors };
    }
    return { ok: true, nextOperational: nextOp };
}

module.exports = {
    ELECTION_TIMEZONE,
    SUPPORTED_GRADES,
    MIN_VOTING_TIME_LIMIT_MINUTES,
    MAX_VOTING_TIME_LIMIT_MINUTES,
    DEFAULT_VOTING_TIME_LIMIT_MINUTES,
    LIFECYCLE_STATES,
    parseManilaDateTimeToUtcMs,
    formatUtcMsToManila,
    createEmptyGradeSessions,
    normalizeGradeSessions,
    deriveLegacyActiveGrade,
    migrateLegacyConfig,
    deriveElectionLifecycle,
    authorizeBallotSubmission,
    authorizeVoterLogin,
    authorizeRegistrationAction,
    validateScheduleUpdate,
    validateOperationalUpdate
};

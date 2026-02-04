-- ═══════════════════════════════════════════════════════════════
-- Security Watchdog — Registry Database Schema
--
-- Document ID:  SWDOG-DATA-003
-- Version:      1.0 DRAFT
-- Database:     SQLite 3.x via better-sqlite3 (Node.js)
-- Location:     ~/.openclaw/security/registry.db
-- Permissions:  600 (owner read/write only)
--
-- This file is the authoritative schema definition.
-- Run this file to create a fresh database.
-- For migrations from prior versions, see the migrations/ directory.
-- ═══════════════════════════════════════════════════════════════

-- ─── PRAGMAS (set on every connection open) ──────────────────
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -8000;       -- 8MB cache
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;    -- 256MB memory-mapped I/O

-- ─── SCHEMA MIGRATIONS TRACKING ──────────────────────────────

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    checksum    TEXT    NOT NULL
);

INSERT INTO schema_migrations (version, name, checksum)
VALUES (1, 'initial_schema', 'sha256:pending');


-- ═══════════════════════════════════════════════════════════════
-- LAYER 0: SENSITIVE DATA REGISTRY
-- ═══════════════════════════════════════════════════════════════

-- ─── LOCALES ─────────────────────────────────────────────────
-- Registered locale plugins. Each maps to a directory under
-- ~/.openclaw/security/locales/<locale_id>/

CREATE TABLE locales (
    locale_id       TEXT    PRIMARY KEY,                 -- e.g. "us-ga", "gb", "ch"
    display_name    TEXT    NOT NULL,                    -- e.g. "United States — Georgia"
    description     TEXT,                                -- Free-text description
    is_active       INTEGER NOT NULL DEFAULT 1,          -- 0 = disabled, 1 = active
    priority        INTEGER NOT NULL DEFAULT 100,        -- Lower = higher priority (for conflict resolution)
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─── PATTERN DEFINITIONS ─────────────────────────────────────
-- PII detection patterns, organized by locale. Each pattern maps
-- to a Presidio recognizer, a regex, or both.

CREATE TABLE patterns (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    locale_id               TEXT    NOT NULL REFERENCES locales(locale_id) ON DELETE CASCADE,
    category                TEXT    NOT NULL,            -- e.g. "government_id", "financial", "contact", "health"
    pattern_type            TEXT    NOT NULL,            -- e.g. "ssn", "credit_card_visa", "email"
    display_name            TEXT    NOT NULL,            -- Human-readable: "US Social Security Number"
    presidio_recognizer     TEXT,                        -- Presidio recognizer class name, if applicable
    regex_pattern           TEXT,                        -- Regex string for detect-secrets or custom matching
    regex_flags             TEXT    DEFAULT 'i',         -- Regex flags (i = case-insensitive)
    validation_function     TEXT,                        -- Optional JS function name for validation (e.g., "luhnCheck")
    default_classification  TEXT    NOT NULL DEFAULT 'NEVER_SHARE'
        CHECK (default_classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
    false_positive_hints    TEXT,                        -- JSON array of known false positive patterns
    example_values          TEXT,                        -- JSON array of example matches (for testing)
    is_active               INTEGER NOT NULL DEFAULT 1,
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE(locale_id, category, pattern_type)
);

-- ─── USER-DEFINED ENTRIES ────────────────────────────────────
-- Sensitive data items defined by the user. These are the entries
-- matched by fuse.js fuzzy search in the Pattern Scanner.

CREATE TABLE user_entries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    label               TEXT    NOT NULL UNIQUE,         -- Machine-readable label: "family_count"
    display_name        TEXT    NOT NULL,                -- Human-readable: "Number of Children"
    primary_value       TEXT    NOT NULL,                -- Primary text to match: "6 children"
    classification      TEXT    NOT NULL DEFAULT 'ASK_FIRST'
        CHECK (classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
    category            TEXT    NOT NULL DEFAULT 'general', -- Grouping: "family", "technology", "financial"
    notes               TEXT,                            -- Free-text notes for the user
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─── ENTRY VARIANTS ──────────────────────────────────────────
-- Synonyms and alternative phrasings for user-defined entries.
-- These expand the fuzzy matching surface.

CREATE TABLE entry_variants (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id        INTEGER NOT NULL REFERENCES user_entries(id) ON DELETE CASCADE,
    variant_text    TEXT    NOT NULL,                    -- e.g. "six kids", "6 kids", "half dozen children"
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE(entry_id, variant_text)
);

-- ─── DESTINATION RULES ───────────────────────────────────────
-- Per-destination classification overrides for user entries.
-- Example: family_count is ASK_FIRST globally but NEVER_SHARE
-- for PUBLIC_PLATFORM destinations.

CREATE TABLE destination_rules (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id                INTEGER NOT NULL REFERENCES user_entries(id) ON DELETE CASCADE,
    destination_type        TEXT    NOT NULL
        CHECK (destination_type IN ('PUBLIC_PLATFORM', 'PRIVATE_CHANNEL', 'LOCAL_FILE', 'OWNER_ONLY', 'API_CALL', 'UNKNOWN')),
    target_pattern          TEXT,                        -- Regex for specific targets (e.g., "moltbook\\.com")
    override_classification TEXT    NOT NULL
        CHECK (override_classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
    created_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE(entry_id, destination_type, target_pattern)
);

-- ─── DESTINATION REGISTRY ────────────────────────────────────
-- Known destinations with their default classification.
-- Used by the Destination Classifier sub-module.

CREATE TABLE destinations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_type    TEXT    NOT NULL
        CHECK (destination_type IN ('PUBLIC_PLATFORM', 'PRIVATE_CHANNEL', 'LOCAL_FILE', 'OWNER_ONLY', 'API_CALL', 'UNKNOWN')),
    target_pattern      TEXT    NOT NULL,                -- Regex or exact match for the target URL/path
    label               TEXT    NOT NULL,                -- Human-readable: "Moltbook", "WhatsApp DM"
    is_public           INTEGER NOT NULL DEFAULT 0,      -- 1 = publicly visible
    notes               TEXT,
    is_active           INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    UNIQUE(destination_type, target_pattern)
);


-- ═══════════════════════════════════════════════════════════════
-- LIVE INVENTORY
-- ═══════════════════════════════════════════════════════════════
-- Tracks all sensitive data currently known to exist within
-- the agent's accessible storage. Updated by inbound inspection,
-- outbound scanning, and periodic workspace scans.

CREATE TABLE inventory (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    registry_ref_type       TEXT    NOT NULL CHECK (registry_ref_type IN ('pattern', 'user_entry')),
    registry_ref_id         INTEGER NOT NULL,            -- FK to patterns.id or user_entries.id
    registry_ref_label      TEXT    NOT NULL,            -- Denormalized label for display
    storage_location        TEXT    NOT NULL,            -- File path, session ID, memory key
    storage_type            TEXT    NOT NULL
        CHECK (storage_type IN ('file', 'session', 'memory', 'context')),
    data_form               TEXT    NOT NULL DEFAULT 'VERBATIM'
        CHECK (data_form IN ('VERBATIM', 'PARAPHRASED', 'DERIVED')),
    detected_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    detected_by             TEXT    NOT NULL,            -- scan request ID that detected it
    current_classification  TEXT    NOT NULL
        CHECK (current_classification IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
    is_active               INTEGER NOT NULL DEFAULT 1,  -- 0 = no longer present at location
    last_verified_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deactivated_at          TEXT,                        -- When marked inactive
    deactivated_by          TEXT,                        -- What scan/process deactivated it

    UNIQUE(registry_ref_type, registry_ref_id, storage_location, storage_type)
);


-- ═══════════════════════════════════════════════════════════════
-- SCAN OPERATIONS & AUDIT LOG
-- ═══════════════════════════════════════════════════════════════

-- ─── SCAN DECISIONS ──────────────────────────────────────────
-- Complete audit trail of every scan performed. This is the
-- primary audit log for compliance and debugging.

CREATE TABLE scan_decisions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id          TEXT    NOT NULL UNIQUE,         -- UUIDv4 from the scan request
    timestamp           TEXT    NOT NULL,                -- ISO 8601 of scan initiation
    direction           TEXT    NOT NULL CHECK (direction IN ('OUTBOUND', 'INBOUND')),
    session_id          TEXT    NOT NULL,                -- OpenClaw session
    agent_id            TEXT    NOT NULL,                -- OpenClaw agent
    tool_name           TEXT,                            -- Tool being called (outbound only)
    content_hash        TEXT    NOT NULL,                -- SHA-256 of scanned content (never store raw content)
    content_length      INTEGER NOT NULL,                -- Character count of scanned content

    -- Destination (outbound only)
    destination_type    TEXT,
    destination_target  TEXT,
    destination_label   TEXT,
    destination_public  INTEGER,                         -- 1 = public, 0 = private, NULL = inbound

    -- Source (inbound only)
    source_channel      TEXT,
    source_id           TEXT,

    -- Posture at time of scan
    posture_level       TEXT    NOT NULL
        CHECK (posture_level IN ('GREEN', 'YELLOW', 'RED', 'BLACK')),

    -- Scanner results
    scanner_verdict     TEXT    NOT NULL CHECK (scanner_verdict IN ('CLEAN', 'FLAGGED')),
    scanner_duration_ms INTEGER NOT NULL,
    flag_count          INTEGER NOT NULL DEFAULT 0,
    flag_summary        TEXT,                            -- JSON summary of flags for display
    stages_executed     TEXT,                            -- JSON array of ScanStage records
    quarantine_id       TEXT    UNIQUE,                  -- Non-null if FLAGGED

    -- Security Agent results (null if scanner verdict was CLEAN)
    agent_decision      TEXT    CHECK (agent_decision IN ('FALSE_POSITIVE', 'BLOCK', 'ESCALATE')),
    agent_reasoning     TEXT,
    agent_confidence    REAL,
    agent_duration_ms   INTEGER,
    agent_model         TEXT,

    -- Escalation results (null if no escalation)
    escalation_id       TEXT    UNIQUE,
    escalation_response TEXT    CHECK (escalation_response IN ('APPROVE', 'DENY', 'DENY_AND_ADD', 'TIMEOUT')),
    escalation_responded_at TEXT,

    -- Final outcome
    final_outcome       TEXT    NOT NULL
        CHECK (final_outcome IN (
            'transmitted',          -- CLEAN or FALSE_POSITIVE: payload sent
            'blocked',              -- BLOCK: payload rejected
            'approved_by_user',     -- ESCALATE → APPROVE: user approved
            'denied_by_user',       -- ESCALATE → DENY: user denied
            'denied_and_added',     -- ESCALATE → DENY_AND_ADD: denied + added to registry
            'denied_by_timeout',    -- ESCALATE → TIMEOUT: no response, treated as deny
            'inventoried',          -- INBOUND: content passed through, sensitive data logged
            'inspected_clean'       -- INBOUND: no sensitive data found
        )),

    -- Timing
    total_duration_ms   INTEGER NOT NULL,

    -- Approval token (outbound only, for transmitted payloads)
    approval_token      TEXT,

    completed_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- ─── SCAN FLAGS ──────────────────────────────────────────────
-- Individual flags raised during scanning. Child records of
-- scan_decisions. Stored separately for queryability.

CREATE TABLE scan_flags (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id             INTEGER NOT NULL REFERENCES scan_decisions(id) ON DELETE CASCADE,
    flag_id                 TEXT    NOT NULL,            -- UUIDv4 for this flag
    source                  TEXT    NOT NULL
        CHECK (source IN ('STRUCTURAL', 'EXACT_MATCH', 'FUZZY_MATCH', 'CREDENTIAL')),
    entity_type             TEXT    NOT NULL,            -- e.g. "US_SSN", "user:family_count"
    matched_text_hash       TEXT    NOT NULL,            -- SHA-256 of matched text (never store raw)
    matched_text_length     INTEGER NOT NULL,            -- Character count
    confidence              REAL    NOT NULL,            -- 0.0–1.0
    offset_start            INTEGER NOT NULL,
    offset_end              INTEGER NOT NULL,
    classification_level    TEXT
        CHECK (classification_level IN ('NEVER_SHARE', 'ASK_FIRST', 'INTERNAL_ONLY', 'PUBLIC')),
    registry_entry_id       INTEGER,                     -- FK to user_entries.id if fuzzy/exact match

    -- Per-flag Security Agent decision (if agent was invoked)
    agent_flag_decision     TEXT    CHECK (agent_flag_decision IN ('FALSE_POSITIVE', 'BLOCK', 'ESCALATE')),
    agent_flag_reasoning    TEXT,

    UNIQUE(decision_id, flag_id)
);


-- ═══════════════════════════════════════════════════════════════
-- ESCALATION LIFECYCLE
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE escalations (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    escalation_id       TEXT    NOT NULL UNIQUE,         -- UUIDv4
    quarantine_id       TEXT    NOT NULL,                -- From scanner
    request_id          TEXT    NOT NULL REFERENCES scan_decisions(request_id),
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at          TEXT    NOT NULL,                -- created_at + timeout
    timeout_seconds     INTEGER NOT NULL DEFAULT 900,

    -- Message delivery
    preferred_channel   TEXT    NOT NULL,
    peer_id             TEXT    NOT NULL,
    message_sent        INTEGER NOT NULL DEFAULT 0,      -- 1 = message delivered to channel
    message_sent_at     TEXT,
    reminder_sent       INTEGER NOT NULL DEFAULT 0,
    reminder_sent_at    TEXT,

    -- Content summary (human-readable, no raw sensitive data)
    summary             TEXT    NOT NULL,
    destination_label   TEXT    NOT NULL,
    flag_summary        TEXT    NOT NULL,                -- Human-readable flag summary
    agent_reasoning     TEXT,

    -- Resolution
    state               TEXT    NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'denied', 'denied_and_added', 'timed_out', 'cancelled')),
    response            TEXT    CHECK (response IN ('APPROVE', 'DENY', 'DENY_AND_ADD', 'TIMEOUT')),
    responded_at        TEXT,
    response_channel    TEXT,                            -- Channel the reply came from
    raw_response_text   TEXT                             -- The raw text of the user's reply
);


-- ═══════════════════════════════════════════════════════════════
-- POSTURE & SYSTEM STATE
-- ═══════════════════════════════════════════════════════════════

-- ─── POSTURE HISTORY ─────────────────────────────────────────
-- Tracks posture level changes over time for audit and dashboard.

CREATE TABLE posture_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    previous_level  TEXT    NOT NULL CHECK (previous_level IN ('GREEN', 'YELLOW', 'RED', 'BLACK')),
    new_level       TEXT    NOT NULL CHECK (new_level IN ('GREEN', 'YELLOW', 'RED', 'BLACK')),
    trigger_type    TEXT    NOT NULL
        CHECK (trigger_type IN ('inventory_change', 'manual_override', 'recovery', 'escalation', 'startup')),
    trigger_detail  TEXT,                                -- Human-readable reason for change
    inventory_snapshot TEXT                              -- JSON snapshot of inventory counts at time of change
);

-- ─── CURRENT POSTURE (singleton) ─────────────────────────────
-- Single-row table holding the current posture state.

CREATE TABLE posture_current (
    id              INTEGER PRIMARY KEY CHECK (id = 1),  -- Enforce single row
    level           TEXT    NOT NULL DEFAULT 'GREEN'
        CHECK (level IN ('GREEN', 'YELLOW', 'RED', 'BLACK')),
    manual_override INTEGER NOT NULL DEFAULT 0,          -- 1 = manually set, ignores auto-calculation
    last_calculated TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    inventory_never_share   INTEGER NOT NULL DEFAULT 0,  -- Cached count
    inventory_ask_first     INTEGER NOT NULL DEFAULT 0,
    inventory_internal_only INTEGER NOT NULL DEFAULT 0
);

INSERT INTO posture_current (id, level) VALUES (1, 'GREEN');


-- ═══════════════════════════════════════════════════════════════
-- HEALTH & MONITORING
-- ═══════════════════════════════════════════════════════════════

-- ─── HEALTH CHECK LOG ────────────────────────────────────────
-- Recent health check results per component. Pruned by the
-- Auditor to retain only the last N checks per component.

CREATE TABLE health_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    component       TEXT    NOT NULL,                    -- e.g. "pattern-scanner", "security-agent", "presidio", "ollama"
    status          TEXT    NOT NULL
        CHECK (status IN ('HEALTHY', 'DEGRADED', 'UNHEALTHY', 'UNREACHABLE')),
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    uptime_seconds  INTEGER,
    version         TEXT,
    details         TEXT,                                -- JSON component-specific details
    error_message   TEXT,
    response_time_ms INTEGER
);

-- ─── SYSTEM MODE (singleton) ─────────────────────────────────

CREATE TABLE system_mode (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    mode            TEXT    NOT NULL DEFAULT 'NORMAL'
        CHECK (mode IN ('NORMAL', 'ISOLATION', 'LOCKDOWN')),
    entered_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reason          TEXT,
    triggered_by    TEXT                                 -- Component or user that triggered mode change
);

INSERT INTO system_mode (id, mode, reason) VALUES (1, 'NORMAL', 'Initial startup');


-- ═══════════════════════════════════════════════════════════════
-- METRICS & AGGREGATION
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE daily_metrics (
    date                    TEXT    PRIMARY KEY,         -- YYYY-MM-DD
    outbound_scans          INTEGER NOT NULL DEFAULT 0,
    inbound_inspections     INTEGER NOT NULL DEFAULT 0,
    total_flags             INTEGER NOT NULL DEFAULT 0,
    blocked_count           INTEGER NOT NULL DEFAULT 0,
    approved_by_human       INTEGER NOT NULL DEFAULT 0,
    denied_by_human         INTEGER NOT NULL DEFAULT 0,
    timeout_count           INTEGER NOT NULL DEFAULT 0,
    false_positive_count    INTEGER NOT NULL DEFAULT 0,
    clean_pass_count        INTEGER NOT NULL DEFAULT 0,
    avg_scan_latency_ms     REAL    NOT NULL DEFAULT 0,
    p95_scan_latency_ms     REAL    NOT NULL DEFAULT 0,
    avg_agent_latency_ms    REAL    NOT NULL DEFAULT 0,
    new_inventory_items     INTEGER NOT NULL DEFAULT 0,
    inventory_verified      INTEGER NOT NULL DEFAULT 0,
    inventory_expired       INTEGER NOT NULL DEFAULT 0,
    computed_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);


-- ═══════════════════════════════════════════════════════════════
-- QUARANTINE QUEUE
-- ═══════════════════════════════════════════════════════════════
-- Holds outbound payloads waiting for classification or
-- escalation resolution. Also used during ISOLATION mode
-- to queue all outbound traffic.

CREATE TABLE quarantine_queue (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantine_id       TEXT    NOT NULL UNIQUE,         -- UUIDv4
    request_id          TEXT    NOT NULL,                -- Original scan request ID
    created_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    -- Original tool call (encrypted at rest)
    tool_name           TEXT    NOT NULL,
    tool_args_encrypted TEXT    NOT NULL,                -- AES-256-GCM encrypted JSON of tool args
    content_hash        TEXT    NOT NULL,                -- SHA-256 of original content

    -- Destination
    destination_type    TEXT    NOT NULL,
    destination_target  TEXT    NOT NULL,
    destination_label   TEXT    NOT NULL,
    destination_public  INTEGER NOT NULL,

    -- State
    state               TEXT    NOT NULL DEFAULT 'pending'
        CHECK (state IN (
            'pending',              -- Awaiting Security Agent classification
            'classifying',          -- Security Agent is processing
            'escalating',           -- Awaiting human approval
            'approved',             -- Ready to transmit
            'blocked',              -- Rejected, will not transmit
            'transmitted',          -- Successfully transmitted
            'expired',              -- Timed out without resolution
            'isolation_queued'      -- Queued during ISOLATION mode
        )),
    state_updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    -- Resolution
    resolved_by         TEXT,                            -- "scanner", "agent", "user", "timeout", "system"
    approval_token      TEXT,                            -- Set when approved
    transmitted_at      TEXT                             -- When actually sent to external service
);


-- ═══════════════════════════════════════════════════════════════
-- CONFIGURATION METADATA
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE config_meta (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL,
    description     TEXT,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Default configuration entries
INSERT INTO config_meta (key, value, description) VALUES
    ('hmac_key_hash',       '',     'SHA-256 hash of the HMAC signing key (key stored in config.json)'),
    ('db_created_at',       strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'Database creation timestamp'),
    ('schema_version',      '1',    'Current schema version number'),
    ('last_workspace_scan', '',     'ISO 8601 timestamp of last workspace scan'),
    ('metrics_retention_days', '90', 'Number of days to retain daily metrics');


-- ═══════════════════════════════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════════════════════════════

-- Patterns: locale lookup (Scanner loads patterns by locale on startup)
CREATE INDEX idx_patterns_locale_active
    ON patterns(locale_id, is_active);

-- Patterns: category browsing
CREATE INDEX idx_patterns_category
    ON patterns(category, pattern_type);

-- User entries: active entries for fuzzy matching (Scanner preloads)
CREATE INDEX idx_user_entries_active
    ON user_entries(is_active);

-- User entries: category browsing
CREATE INDEX idx_user_entries_category
    ON user_entries(category, is_active);

-- Entry variants: lookup by entry (loaded with parent entry)
CREATE INDEX idx_variants_entry
    ON entry_variants(entry_id);

-- Destination rules: lookup by entry + destination type
CREATE INDEX idx_dest_rules_entry_type
    ON destination_rules(entry_id, destination_type);

-- Destinations: type + active lookup
CREATE INDEX idx_destinations_type_active
    ON destinations(destination_type, is_active);

-- Inventory: classification + active (Posture Engine query)
CREATE INDEX idx_inventory_classification_active
    ON inventory(current_classification, is_active);

-- Inventory: storage location (Workspace Scanner dedup)
CREATE INDEX idx_inventory_location
    ON inventory(storage_location, storage_type, is_active);

-- Inventory: detected timestamp (recent inventory dashboard)
CREATE INDEX idx_inventory_detected
    ON inventory(detected_at);

-- Scan decisions: timestamp (recent decisions dashboard)
CREATE INDEX idx_decisions_timestamp
    ON scan_decisions(timestamp);

-- Scan decisions: direction + outcome (metrics queries)
CREATE INDEX idx_decisions_direction_outcome
    ON scan_decisions(direction, final_outcome);

-- Scan decisions: quarantine lookup
CREATE INDEX idx_decisions_quarantine
    ON scan_decisions(quarantine_id)
    WHERE quarantine_id IS NOT NULL;

-- Scan decisions: escalation lookup
CREATE INDEX idx_decisions_escalation
    ON scan_decisions(escalation_id)
    WHERE escalation_id IS NOT NULL;

-- Scan flags: decision lookup
CREATE INDEX idx_flags_decision
    ON scan_flags(decision_id);

-- Scan flags: entity type (frequency analysis)
CREATE INDEX idx_flags_entity_type
    ON scan_flags(entity_type);

-- Escalations: state (active escalation queries)
CREATE INDEX idx_escalations_state
    ON escalations(state)
    WHERE state = 'pending';

-- Escalations: expiry (timeout check)
CREATE INDEX idx_escalations_expires
    ON escalations(expires_at)
    WHERE state = 'pending';

-- Health checks: component + timestamp (recent checks per component)
CREATE INDEX idx_health_component_time
    ON health_checks(component, timestamp);

-- Quarantine queue: state (pending items)
CREATE INDEX idx_quarantine_state
    ON quarantine_queue(state)
    WHERE state IN ('pending', 'classifying', 'escalating', 'isolation_queued');

-- Quarantine queue: request lookup
CREATE INDEX idx_quarantine_request
    ON quarantine_queue(request_id);

-- Daily metrics: date range queries
-- (date is already PRIMARY KEY, no additional index needed)


-- ═══════════════════════════════════════════════════════════════
-- VIEWS
-- ═══════════════════════════════════════════════════════════════

-- Active inventory summary by classification level
CREATE VIEW v_inventory_summary AS
SELECT
    current_classification,
    COUNT(*)            AS item_count,
    storage_type,
    MAX(detected_at)    AS most_recent
FROM inventory
WHERE is_active = 1
GROUP BY current_classification, storage_type;

-- Active inventory for posture calculation
CREATE VIEW v_posture_input AS
SELECT
    COALESCE(SUM(CASE WHEN current_classification = 'NEVER_SHARE' THEN 1 ELSE 0 END), 0)   AS never_share_count,
    COALESCE(SUM(CASE WHEN current_classification = 'ASK_FIRST' THEN 1 ELSE 0 END), 0)     AS ask_first_count,
    COALESCE(SUM(CASE WHEN current_classification = 'INTERNAL_ONLY' THEN 1 ELSE 0 END), 0) AS internal_only_count,
    COUNT(*)                                                                                 AS total_active
FROM inventory
WHERE is_active = 1;

-- Recent scan decisions for dashboard
CREATE VIEW v_recent_decisions AS
SELECT
    sd.request_id,
    sd.timestamp,
    sd.direction,
    sd.tool_name,
    sd.destination_label,
    sd.source_channel,
    sd.scanner_verdict,
    sd.agent_decision,
    sd.escalation_response,
    sd.final_outcome,
    sd.flag_count,
    sd.total_duration_ms,
    sd.posture_level
FROM scan_decisions sd
ORDER BY sd.timestamp DESC
LIMIT 100;

-- User entries with variants (for Scanner preload)
CREATE VIEW v_entries_with_variants AS
SELECT
    e.id,
    e.label,
    e.display_name,
    e.primary_value,
    e.classification,
    e.category,
    e.is_active,
    GROUP_CONCAT(v.variant_text, '|||') AS variants
FROM user_entries e
LEFT JOIN entry_variants v ON v.entry_id = e.id
WHERE e.is_active = 1
GROUP BY e.id;

-- Pending quarantine items
CREATE VIEW v_pending_quarantine AS
SELECT
    q.quarantine_id,
    q.request_id,
    q.created_at,
    q.tool_name,
    q.destination_label,
    q.destination_public,
    q.state,
    q.state_updated_at,
    julianday('now') - julianday(q.created_at) AS age_days
FROM quarantine_queue q
WHERE q.state IN ('pending', 'classifying', 'escalating', 'isolation_queued')
ORDER BY q.created_at ASC;

-- Component health (latest per component)
CREATE VIEW v_component_health AS
SELECT
    h1.component,
    h1.status,
    h1.timestamp,
    h1.uptime_seconds,
    h1.version,
    h1.error_message,
    h1.response_time_ms
FROM health_checks h1
INNER JOIN (
    SELECT component, MAX(id) AS max_id
    FROM health_checks
    GROUP BY component
) h2 ON h1.id = h2.max_id;


-- ═══════════════════════════════════════════════════════════════
-- TRIGGERS
-- ═══════════════════════════════════════════════════════════════

-- Auto-update updated_at on locales
CREATE TRIGGER trg_locales_updated
AFTER UPDATE ON locales
FOR EACH ROW
BEGIN
    UPDATE locales SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE locale_id = NEW.locale_id;
END;

-- Auto-update updated_at on patterns
CREATE TRIGGER trg_patterns_updated
AFTER UPDATE ON patterns
FOR EACH ROW
BEGIN
    UPDATE patterns SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- Auto-update updated_at on user_entries
CREATE TRIGGER trg_user_entries_updated
AFTER UPDATE ON user_entries
FOR EACH ROW
BEGIN
    UPDATE user_entries SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;

-- Auto-update state_updated_at on quarantine_queue state changes
CREATE TRIGGER trg_quarantine_state_updated
AFTER UPDATE OF state ON quarantine_queue
FOR EACH ROW
BEGIN
    UPDATE quarantine_queue SET state_updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = NEW.id;
END;


-- ═══════════════════════════════════════════════════════════════
-- SEED DATA: US-GA LOCALE
-- ═══════════════════════════════════════════════════════════════

INSERT INTO locales (locale_id, display_name, description, priority)
VALUES ('us-ga', 'United States — Georgia', 'Federal US PII patterns with Georgia state overlay (Code 10-1-912)', 10);

-- Federal patterns
INSERT INTO patterns (locale_id, category, pattern_type, display_name, presidio_recognizer, default_classification) VALUES
    ('us-ga', 'government_id',  'ssn',              'US Social Security Number',    'UsSsnRecognizer',          'NEVER_SHARE'),
    ('us-ga', 'government_id',  'passport',         'US Passport Number',           'UsPassportRecognizer',     'NEVER_SHARE'),
    ('us-ga', 'government_id',  'drivers_license',  'Georgia Drivers License',      NULL,                       'NEVER_SHARE'),
    ('us-ga', 'financial',      'credit_card',      'Credit Card Number',           'CreditCardRecognizer',     'NEVER_SHARE'),
    ('us-ga', 'financial',      'bank_routing',     'Bank Routing Number',          NULL,                       'NEVER_SHARE'),
    ('us-ga', 'financial',      'bank_account',     'Bank Account Number',          'UsAccountNumberRecognizer','NEVER_SHARE'),
    ('us-ga', 'financial',      'ein',              'Employer ID Number',           NULL,                       'INTERNAL_ONLY'),
    ('us-ga', 'contact',        'email',            'Email Address',                'EmailRecognizer',          'ASK_FIRST'),
    ('us-ga', 'contact',        'phone_nanp',       'US/Canada Phone Number',       'PhoneRecognizer',          'ASK_FIRST'),
    ('us-ga', 'contact',        'address',          'Physical Address',             NULL,                       'ASK_FIRST'),
    ('us-ga', 'network',        'ip_address',       'IP Address',                   'IpRecognizer',             'INTERNAL_ONLY'),
    ('us-ga', 'network',        'mac_address',      'MAC Address',                  NULL,                       'INTERNAL_ONLY'),
    ('us-ga', 'health',         'dea_number',       'DEA Registration Number',      NULL,                       'NEVER_SHARE'),
    ('us-ga', 'health',         'medicare',         'Medicare/Medicaid Number',     NULL,                       'NEVER_SHARE'),
    ('us-ga', 'identity',       'dob',              'Date of Birth',                'DateTimeRecognizer',       'ASK_FIRST'),
    ('us-ga', 'military',       'service_number',   'Military Service Number',      NULL,                       'NEVER_SHARE');

-- Known destinations
INSERT INTO destinations (destination_type, target_pattern, label, is_public) VALUES
    ('PUBLIC_PLATFORM',  'moltbook\\.com',          'Moltbook',         1),
    ('PUBLIC_PLATFORM',  'twitter\\.com|x\\.com',   'Twitter/X',        1),
    ('PUBLIC_PLATFORM',  'reddit\\.com',            'Reddit',           1),
    ('PUBLIC_PLATFORM',  'facebook\\.com',          'Facebook',         1),
    ('PUBLIC_PLATFORM',  'instagram\\.com',         'Instagram',        1),
    ('PUBLIC_PLATFORM',  'linkedin\\.com',          'LinkedIn',         1),
    ('PRIVATE_CHANNEL',  'whatsapp',                'WhatsApp',         0),
    ('PRIVATE_CHANNEL',  'telegram',                'Telegram',         0),
    ('PRIVATE_CHANNEL',  'signal',                  'Signal',           0),
    ('PRIVATE_CHANNEL',  'discord',                 'Discord',          0),
    ('PRIVATE_CHANNEL',  'slack',                   'Slack',            0),
    ('PRIVATE_CHANNEL',  'imessage',                'iMessage',         0),
    ('LOCAL_FILE',       '^/',                       'Local filesystem', 0),
    ('LOCAL_FILE',       '^\\./',                    'Relative path',    0),
    ('OWNER_ONLY',       'owner',                   'Owner direct',     0);

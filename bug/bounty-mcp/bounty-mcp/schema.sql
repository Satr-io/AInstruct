
-- Bug Bounty MCP Database Schema
-- Phase 1: Normalized schema with raw/derived separation and provenance
-- SQLite backend

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ============================================================
-- AUDIT SESSIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,          -- UUID
    name TEXT NOT NULL,           -- Human label
    target_path TEXT,             -- Source code path
    target_address TEXT,          -- On-chain address (optional)
    target_chain TEXT,            -- Chain (optional)
    slither_version TEXT,         -- Parser version for replay
    schema_version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'active', -- active, completed, archived
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    snapshot_path TEXT            -- Path to source snapshot for replay
);

-- ============================================================
-- RAW SOLIDIT FINDINGS (as-is from API)
-- ============================================================
CREATE TABLE IF NOT EXISTS solodit_raw (
    solodit_id TEXT PRIMARY KEY,   -- ID from Solodit API
    slug TEXT,
    kind TEXT,
    raw_title TEXT,
    raw_content TEXT,              -- Full markdown content
    raw_summary TEXT,
    raw_impact TEXT,                -- HIGH/MEDIUM/LOW/GAS
    raw_protocol_name TEXT,
    raw_firm_name TEXT,
    raw_source_link TEXT,
    raw_github_link TEXT,
    raw_pdf_link TEXT,
    raw_report_date TEXT,          -- Usually empty {} from API
    raw_finders_count INTEGER,
    raw_quality_score INTEGER,
    raw_general_score INTEGER,
    search_rank REAL,
    raw_tags_json TEXT,             -- JSON array of tags
    raw_finders_json TEXT,          -- JSON array of warden handles
    raw_response_json TEXT,         -- Complete raw JSON response (for replay)
    first_fetched_at TEXT DEFAULT (datetime('now')),
    last_fetched_at TEXT DEFAULT (datetime('now')),
    fetch_count INTEGER DEFAULT 1
);

-- ============================================================
-- DERIVED METADATA (extracted from raw, with provenance)
-- ============================================================
CREATE TABLE IF NOT EXISTS solodit_derived (
    id TEXT PRIMARY KEY,            -- UUID
    solodit_id TEXT NOT NULL,
    field_name TEXT NOT NULL,        -- root_cause, attack_vector, attacker_capability, impact_summary, code_pattern
    field_value TEXT,
    derived_from TEXT NOT NULL,     -- Which raw field(s) this was derived from
    derivation_method TEXT,          -- How it was derived: 'llm_extract', 'regex_match', 'manual'
    derived_by TEXT,                 -- Agent/session that derived it
    confidence TEXT DEFAULT 'medium',-- high/medium/low
    derived_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (solodit_id) REFERENCES solodit_raw(solodit_id),
    UNIQUE(solodit_id, field_name)
);

-- ============================================================
-- PRECEDENT QUERIES (search log)
-- ============================================================
CREATE TABLE IF NOT EXISTS precedent_queries (
    id TEXT PRIMARY KEY,            -- UUID
    audit_id TEXT,
    query_keywords TEXT NOT NULL,
    filters_json TEXT,              -- Full filter object
    total_results INTEGER,
    returned_count INTEGER,
    page INTEGER,
    page_size INTEGER,
    rate_limit_remaining INTEGER,
    queried_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- Link findings to queries (many-to-many)
CREATE TABLE IF NOT EXISTS precedent_query_results (
    query_id TEXT NOT NULL,
    solodit_id TEXT NOT NULL,
    result_rank INTEGER,
    FOREIGN KEY (query_id) REFERENCES precedent_queries(id),
    FOREIGN KEY (solodit_id) REFERENCES solodit_raw(solodit_id),
    PRIMARY KEY (query_id, solodit_id)
);

-- ============================================================
-- ATTACK SURFACE MODEL (generic, not EVM-specific)
-- ============================================================
CREATE TABLE IF NOT EXISTS attack_surfaces (
    id TEXT PRIMARY KEY,            -- UUID
    audit_id TEXT NOT NULL,
    contract_name TEXT NOT NULL,
    contract_path TEXT,
    parser_used TEXT,               -- 'slither', 'manual', etc
    parser_version TEXT,
    model_json TEXT,                -- Full attack surface model JSON
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- Individual function extracted from attack surface
CREATE TABLE IF NOT EXISTS surface_functions (
    id TEXT PRIMARY KEY,
    surface_id TEXT NOT NULL,
    function_name TEXT NOT NULL,
    visibility TEXT,                -- external, public, internal, private
    state_mutating INTEGER DEFAULT 0, -- boolean
    modifiers_json TEXT,            -- JSON array of modifier names
    external_calls_json TEXT,       -- JSON array of external call targets
    storage_writes_json TEXT,       -- JSON array of storage variables written
    token_transfers_json TEXT,      -- JSON array of token transfer targets
    oracle_dependencies_json TEXT,  -- JSON array of oracle deps
    msg_sender_usage INTEGER DEFAULT 0,
    trust_boundary TEXT,            -- external, internal, privileged
    FOREIGN KEY (surface_id) REFERENCES attack_surfaces(id)
);

-- ============================================================
-- CANDIDATES (hypotheses)
-- ============================================================
CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,            -- UUID (H-001, H-002 etc as display ID)
    display_id TEXT,                -- Human-friendly: H-001
    audit_id TEXT NOT NULL,
    contract TEXT,
    function TEXT,
    hypothesis TEXT NOT NULL,
    properties_json TEXT,            -- JSON array: ["oracle_dependent", "permissionless", ...]
    status TEXT DEFAULT 'DISCOVERED', -- DISCOVERED, HYPOTHESIS, INVESTIGATING, TEST_CANDIDATE, CONFIRMED, REPORT_READY, KILLED, HOLD
    kill_reason TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- EVIDENCE (observations, not conclusions)
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,            -- UUID (E-001 etc)
    display_id TEXT,                -- E-001
    candidate_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,    -- reachability, attacker_control, invariant_violation, historical_precedent, missing_mitigation, access_control, bounds_check, safe_cast, oracle_validation, trusted_caller, economic_feasibility
    relationship TEXT NOT NULL,    -- SUPPORTS, DISCONFIRMS
    source TEXT,                    -- Contract.sol, Solodit #38021, analysis
    location TEXT,                  -- L142-149, null
    claim TEXT NOT NULL,            -- Observation: "msg.sender is not restricted"
    observed_value TEXT,            -- What was actually observed
    confidence TEXT DEFAULT 'medium', -- high/medium/low
    collected_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- VALIDATION RESULTS (state machine transitions)
-- ============================================================
CREATE TABLE IF NOT EXISTS validation_results (
    id TEXT PRIMARY KEY,            -- UUID
    candidate_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    -- State machine stages
    reachability TEXT,              -- pass, fail, unknown
    attacker_control TEXT,          -- pass, fail, unknown
    prerequisites TEXT,             -- satisfied, unsatisfied, partial, unknown
    state_impact TEXT,              -- pass, fail, unknown
    asset_impact TEXT,             -- pass, fail, unknown
    exploitability TEXT,            -- confirmed, unconfirmed, partial, unknown
    -- Confidence scores (per dimension, not single number)
    confidence_reachability INTEGER,
    confidence_attacker_control INTEGER,
    confidence_exploitability INTEGER,
    confidence_impact INTEGER,
    confidence_evidence_quality INTEGER,
    confidence_historical_similarity INTEGER,
    -- Final status
    final_status TEXT,              -- CONFIRMED, KILLED, TEST_CANDIDATE, HOLD
    -- Reasons
    kill_reason TEXT,
    confirm_reason TEXT,
    -- Evidence summary
    supporting_count INTEGER DEFAULT 0,
    disconfirming_count INTEGER DEFAULT 0,
    validated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- COVERAGE MATRIX (evidence-backed)
-- ============================================================
CREATE TABLE IF NOT EXISTS coverage (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    category TEXT NOT NULL,          -- access_control, oracle, accounting, rounding, reentrancy, flash_loan, liquidation, signature, initialization, upgradeability, token_compatibility, cross_contract, dos, economic_invariants
    status TEXT DEFAULT 'NOT_STARTED', -- NOT_STARTED, DISCOVERED, TESTING, SUPPORTED, DISCONFIRMED, CONFIRMED, KILLED
    candidate_ids_json TEXT,        -- JSON array of candidate IDs tested
    notes TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id),
    UNIQUE(audit_id, category)
);

-- ============================================================
-- IMPACT ASSESSMENT (independent from historical severity)
-- ============================================================
CREATE TABLE IF NOT EXISTS impact_assessments (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    can_steal_funds INTEGER,        -- boolean
    can_manipulate_price INTEGER,   -- boolean
    can_cause_dos INTEGER,          -- boolean
    can_manipulate_accounting INTEGER, -- boolean
    requires_capital TEXT,           -- amount or description
    capital_description TEXT,
    repeatable INTEGER,              -- boolean
    affected_asset TEXT,
    affected_asset_value TEXT,
    severity TEXT,                   -- HIGH, MEDIUM, LOW
    severity_rationale TEXT,
    assessed_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- PRECEDENT LINKAGE (candidate ↔ solodit finding)
-- ============================================================
CREATE TABLE IF NOT EXISTS candidate_precedents (
    candidate_id TEXT NOT NULL,
    solodit_id TEXT NOT NULL,
    similarity_type TEXT,            -- root_cause, code_structure, attacker_capability, state_transition, asset_flow, impact
    similarity_score REAL,           -- 0-1
    notes TEXT,
    linked_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (solodit_id) REFERENCES solodit_raw(solodit_id),
    PRIMARY KEY (candidate_id, solodit_id)
);

-- ============================================================
-- AUDIT SNAPSHOTS (for replayability)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_snapshots (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    snapshot_type TEXT,              -- source, attack_surface, candidates, evidence, validation, full
    version TEXT,                   -- Version label: v1, v2
    snapshot_json TEXT,              -- Complete state snapshot
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_candidates_audit ON candidates(audit_id);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_evidence_candidate ON evidence(candidate_id);
CREATE INDEX IF NOT EXISTS idx_evidence_audit ON evidence(audit_id);
CREATE INDEX IF NOT EXISTS idx_validation_candidate ON validation_results(candidate_id);
CREATE INDEX IF NOT EXISTS idx_coverage_audit ON coverage(audit_id);
CREATE INDEX IF NOT EXISTS idx_solodit_impact ON solodit_raw(raw_impact);
CREATE INDEX IF NOT EXISTS idx_solodit_protocol ON solodit_raw(raw_protocol_name);
CREATE INDEX IF NOT EXISTS idx_precedent_queries_audit ON precedent_queries(audit_id);

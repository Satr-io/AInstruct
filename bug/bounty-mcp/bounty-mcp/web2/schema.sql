
-- Web2 Bug Bounty MCP Database Schema
-- Web2/API-native mirror of the web3 schema. Endpoint/method/param-centric
-- instead of contract/function. Same candidate -> evidence -> validation ->
-- coverage lifecycle as the web3 server, but with web2 naming and web2
-- coverage categories (OWASP-flavored).
-- SQLite backend.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ============================================================
-- AUDIT SESSIONS (web2 target)
-- ============================================================
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,          -- e.g. <target>-<YYYY-MM-DD>
    name TEXT NOT NULL,           -- Human label
    target_host TEXT,             -- Primary host/domain (api.example.com)
    target_scope TEXT,            -- Scope description / base URLs
    surface_source TEXT,          -- openapi | postman | har | raw
    schema_version INTEGER DEFAULT 1,
    status TEXT DEFAULT 'active', -- active, IN_PROGRESS, completed, archived
    created_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    snapshot_path TEXT
);

-- ============================================================
-- ATTACK SURFACE MODEL (web2: endpoints, not contracts)
-- ============================================================
CREATE TABLE IF NOT EXISTS attack_surfaces (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    host TEXT,                       -- api.example.com
    source_type TEXT,                -- openapi | postman | har | raw
    endpoint_count INTEGER DEFAULT 0,
    model_json TEXT,                 -- Full parse_web2_surface output JSON
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- Individual endpoint extracted from the attack surface
CREATE TABLE IF NOT EXISTS surface_endpoints (
    id TEXT PRIMARY KEY,
    surface_id TEXT NOT NULL,
    method TEXT,                     -- GET/POST/PUT/PATCH/DELETE
    path TEXT,                       -- /api/users/{id}
    params_json TEXT,                -- JSON: params by location (path/query/body/header)
    auth_model TEXT,                 -- none | bearer | cookie | apikey | oauth | basic
    state_mutating INTEGER DEFAULT 0,
    trust_boundary TEXT,             -- public | authenticated | privileged
    potential_sinks_json TEXT,       -- JSON array of sink classes
    FOREIGN KEY (surface_id) REFERENCES attack_surfaces(id)
);

-- ============================================================
-- CANDIDATES (hypotheses)
-- ============================================================
CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,             -- UUID
    display_id TEXT,                 -- H-001
    audit_id TEXT NOT NULL,
    endpoint TEXT,                   -- host + path (api.example.com/api/users/{id})
    method TEXT,                     -- HTTP method (or logical operation)
    vuln_class TEXT,                 -- sqli, idor, bola, ssrf, xss, csrf, auth_bypass, ...
    hypothesis TEXT NOT NULL,
    properties_json TEXT,            -- JSON array: ["permissionless","state_mutating",...]
    status TEXT DEFAULT 'DISCOVERED',-- DISCOVERED, HYPOTHESIS, INVESTIGATING, TEST_CANDIDATE, CONFIRMED, REPORT_READY, KILLED, HOLD
    kill_reason TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- EVIDENCE (observations, not conclusions)
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    display_id TEXT,                 -- E-001
    candidate_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,     -- reachability, attacker_control, authz_check, injection_reflected, missing_mitigation, csrf_token, rate_limit, historical_precedent, transport, info_leak
    relationship TEXT NOT NULL,      -- SUPPORTS, DISCONFIRMS
    source TEXT,                     -- request/response, HackerOne #id, curl, analysis
    location TEXT,                   -- endpoint + param, response header, null
    claim TEXT NOT NULL,             -- Observation
    observed_value TEXT,             -- Actual observed value (status code, body snippet, header)
    confidence TEXT DEFAULT 'medium',-- high/medium/low
    collected_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- VALIDATION RESULTS (state machine transitions)
-- ============================================================
CREATE TABLE IF NOT EXISTS validation_results (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    reachability TEXT,               -- pass, fail, unknown
    attacker_control TEXT,           -- pass, fail, unknown
    prerequisites TEXT,              -- satisfied, unsatisfied, partial, unknown
    state_impact TEXT,               -- pass, fail, unknown
    asset_impact TEXT,               -- pass, fail, unknown
    exploitability TEXT,             -- confirmed, unconfirmed, partial, unknown
    confidence_reachability INTEGER,
    confidence_attacker_control INTEGER,
    confidence_exploitability INTEGER,
    confidence_impact INTEGER,
    confidence_evidence_quality INTEGER,
    confidence_historical_similarity INTEGER,
    final_status TEXT,               -- CONFIRMED, KILLED, TEST_CANDIDATE, HOLD
    kill_reason TEXT,
    confirm_reason TEXT,
    cvss_vector TEXT,                -- Suggested/final CVSS vector (v3.1 or v4.0)
    cvss_score REAL,                 -- Base score
    cvss_severity TEXT,              -- Critical/High/Medium/Low
    supporting_count INTEGER DEFAULT 0,
    disconfirming_count INTEGER DEFAULT 0,
    validated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    FOREIGN KEY (audit_id) REFERENCES audits(id)
);

-- ============================================================
-- COVERAGE MATRIX (web2/OWASP-flavored categories)
-- ============================================================
CREATE TABLE IF NOT EXISTS coverage (
    id TEXT PRIMARY KEY,
    audit_id TEXT NOT NULL,
    category TEXT NOT NULL,          -- authz, injection, ssrf, auth, session, csrf, business_logic, info_disclosure, transport, client_side, rate_limit, file_upload, misconfig, xxe
    status TEXT DEFAULT 'NOT_STARTED', -- NOT_STARTED, DISCOVERED, TESTING, SUPPORTED, DISCONFIRMED, CONFIRMED, KILLED
    candidate_ids_json TEXT,
    notes TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (audit_id) REFERENCES audits(id),
    UNIQUE(audit_id, category)
);

-- ============================================================
-- PRECEDENT LINKAGE (candidate <-> HackerOne / Bugcrowd report)
-- ============================================================
CREATE TABLE IF NOT EXISTS candidate_precedents (
    candidate_id TEXT NOT NULL,
    precedent_source TEXT NOT NULL,  -- hackerone | bugcrowd | cve | exploitdb
    precedent_ref TEXT NOT NULL,     -- report URL / CVE id / EDB id
    precedent_title TEXT,
    similarity_type TEXT,            -- root_cause, endpoint_shape, attacker_capability, impact
    similarity_score REAL,           -- 0-1
    notes TEXT,
    linked_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (candidate_id) REFERENCES candidates(id),
    PRIMARY KEY (candidate_id, precedent_source, precedent_ref)
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_candidates_audit ON candidates(audit_id);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_candidates_class ON candidates(vuln_class);
CREATE INDEX IF NOT EXISTS idx_evidence_candidate ON evidence(candidate_id);
CREATE INDEX IF NOT EXISTS idx_evidence_audit ON evidence(audit_id);
CREATE INDEX IF NOT EXISTS idx_validation_candidate ON validation_results(candidate_id);
CREATE INDEX IF NOT EXISTS idx_coverage_audit ON coverage(audit_id);
CREATE INDEX IF NOT EXISTS idx_surface_endpoints_surface ON surface_endpoints(surface_id);

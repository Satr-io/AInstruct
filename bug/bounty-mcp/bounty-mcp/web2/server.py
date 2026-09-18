#!/usr/bin/env python3
"""
Web2 References MCP Server
Provides CVE/CWE/GHSA/OSV/CVSS lookups for building bug bounty report
References sections. Web2-focused (public vulnerability databases) —
the Solodit/web3 side lives in the main bounty-mcp server.

Run via: python3 server.py (stdio transport)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from references import (
    search_cve,
    get_cve,
    get_cwe,
    search_ghsa,
    query_osv,
    search_bugcrowd,
    search_hackerone,
    search_exploitdb,
    read_exploit_file,
    get_owasp,
    cvss_calculator_url,
    suggest_cvss,
    build_references,
)
from web2_surface import parse_web2_surface
from db import Web2Database

# Web2 audit-state DB (endpoint/vuln_class-centric mirror of the web3 db).
# Backing file: web2/bounty_web2.db (separate from the web3 bounty_mcp.db).
_db = Web2Database()


async def handle_list_tools(ctx, params) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[
        types.Tool(
            name="search_cve",
            description="Search NVD CVE database by keyword. Returns CVEs with description, CVSS score/vector, CWE ids, published date, and NVD link. Use to find relevant CVEs for a bug bounty report's References section.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Search phrase, e.g. 'JWT algorithm confusion' or 'reentrancy'" },
                    "results_per_page": {"type": "integer", "description": "Max results (default 10)"},
                },
                "required": ["keywords"],
            },
        ),
        types.Tool(
            name="get_cve",
            description="Fetch full CVE detail by ID (e.g. CVE-2024-55555). Returns description, CVSS vector + score, CWE ids, published/modified dates, and advisory reference URLs.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE ID, e.g. CVE-2024-55555"},
                },
                "required": ["cve_id"],
            },
        ),
        types.Tool(
            name="get_cwe",
            description="Fetch CWE weakness detail by ID (e.g. 79). Returns name, description, likelihood, and cwe.mitre.org link.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cwe_id": {"type": "string", "description": "CWE ID, e.g. '79' or 'CWE-79'"},
                },
                "required": ["cwe_id"],
            },
        ),
        types.Tool(
            name="search_ghsa",
            description="Search GitHub Advisory Database by keyword. Returns GHSA ids, severity, linked CVE, summary, and github.com/advisories link.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search phrase"},
                    "results_per_page": {"type": "integer", "description": "Max results (default 10)"},
                },
                "required": ["query"],
            },
        ),
        types.Tool(
            name="query_osv",
            description="Query OSV.dev (Open Source Vulnerabilities) by package name + ecosystem (npm, PyPI, Maven, Go, crates.io, etc). Returns vulnerability ids, aliases, severity.",
            inputSchema={
                "type": "object",
                "properties": {
                    "package_name": {"type": "string", "description": "Package name, e.g. 'lodash'"},
                    "ecosystem": {"type": "string", "description": "Ecosystem, default npm"},
                    "results_per_page": {"type": "integer", "description": "Max results (default 10)"},
                },
                "required": ["package_name"],
            },
        ),
        types.Tool(
            name="search_bugcrowd",
            description="Search Bugcrowd's public crowdstream feed by keyword (program name / target URL). Returns accepted bounty records with amount, points, and link. Public JSON feed, no auth. Use as real-world precedent for a bug bounty report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Search phrase, e.g. 'sql injection' or a program/domain name. Empty = all recent disclosures"},
                    "results_per_page": {"type": "integer", "description": "Max results (default 10)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="search_hackerone",
            description="Search HackerOne Hacktivity (public disclosed reports) via the public GraphQL endpoint, no auth. Filter by free-text keywords, by CWE (number OR name), and/or by severity. IMPORTANT: the H1 index matches CWE by weakness NAME, not number — so this tool auto-resolves 'cwe:400' / 'cwe:\\\"CWE-400\\\"' and the dedicated 'cwe' arg to the real weakness name (e.g. 'Uncontrolled Resource Consumption'), and rewrites 'severity:high' to the real field 'severity_rating:high'. Returns disclosed reports with CWE, severity, awarded amount, program handle, reporter, and public report URL. Use as real-world exploitable precedent for a bug bounty report's References section.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Free text ('ssrf') or H1 DSL. Common mistakes auto-fixed: 'severity:high'->'severity_rating:high', 'cwe:400'/'cwe:\\\"CWE-400\\\"'->'cwe:\\\"<weakness name>\\\"'. Empty = latest disclosed."},
                    "cwe": {"type": "string", "description": "Dedicated CWE filter. Accepts a number (400), 'CWE-400', or a weakness name ('Uncontrolled Resource Consumption'). Auto-resolved to the H1 weakness name and ANDed into the query. Use this instead of guessing the field syntax."},
                    "severity": {"type": "string", "description": "Dedicated severity filter: critical|high|medium|low|none. ANDed as 'severity_rating:<level>'."},
                    "results_per_page": {"type": "integer", "description": "Max results (default 10, max 100)"},
                    "disclosed_only": {"type": "boolean", "description": "Only disclosed reports (default true). Auto-appends 'disclosed:true' unless already present."},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="search_exploitdb",
            description="Search local Exploit-DB database (searchsploit CSV, 47K+ entries) by keyword. Returns EDB-ID, title, type, platform, date, linked CVEs, and exploit-db.com link. Falls back to searchsploit CLI if CSV missing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Search phrase, e.g. 'wordpress sql injection'"},
                    "results_per_page": {"type": "integer", "description": "Max results (default 10)"},
                    "platform": {"type": "string", "description": "Optional platform filter, e.g. 'php', 'windows', 'linux'"},
                    "exploit_type": {"type": "string", "description": "Optional type filter, e.g. 'webapps', 'remote', 'dos'"},
                },
                "required": ["keywords"],
            },
        ),
        types.Tool(
            name="read_exploit_file",
            description="Read the full exploit source file for an EDB-ID from the local Exploit-DB mirror (/opt/exploitdb). Returns the actual code payload/technique — agent can LEARN from it, not just get a link. Use after search_exploitdb to read the exploit you want to study.",
            inputSchema={
                "type": "object",
                "properties": {
                    "edb_id": {"type": "string", "description": "EDB-ID from search_exploitdb results, e.g. '13768' or '50462'"},
                    "max_chars": {"type": "integer", "description": "Max chars to return (default 60000, max 128K)"},
                },
                "required": ["edb_id"],
            },
        ),
        types.Tool(
            name="get_owasp",
            description="Return OWASP reference links (Top 10 2021, API Security Top 10 2023, cheat sheets) relevant to a vulnerability keyword. Static mapping, no network. Use to cite OWASP framework in a bug bounty report's References section.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Vulnerability keywords, e.g. 'BOLA SQL injection SSRF'"},
                },
                "required": ["keywords"],
            },
        ),
        types.Tool(
            name="cvss_calculator_url",
            description="Build a FIRST CVSS calculator URL from a vector string (v2/v3.x/v4.0). E.g. 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "vector": {"type": "string", "description": "CVSS vector string"},
                },
                "required": ["vector"],
            },
        ),
        types.Tool(
            name="parse_web2_surface",
            description="Parse a web2/API target into an attack-surface model (the web2 analogue of get_attack_surface for Solidity). Accepts an OpenAPI/Swagger spec (JSON or YAML — file path, http(s) URL, or inline text), a Postman v2 collection (JSON), a HAR capture (JSON), or a raw newline-separated endpoint list ('GET /api/users/{id}' or bare URLs). Returns per-endpoint method/path/params(by location)/auth model/state-mutating flag/trust boundary + heuristic potential_sinks (IDOR-BOLA, SSRF, SQLi, path-traversal, command-injection, XSS-SSTI, mass-assignment, auth-abuse, business-logic, XXE, file-upload) and a summary (unauthenticated state-mutating count, sink_hits histogram, methods). Use this FIRST for a web2 target to build the attack surface before generating hypotheses/candidates — feed potential_sinks into create_candidate.",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "OpenAPI/Swagger spec (path/URL/inline), Postman collection JSON, HAR JSON, or newline-separated endpoint list."},
                    "source_type": {"type": "string", "description": "auto (default) | openapi | postman | har | raw", "enum": ["auto", "openapi", "postman", "har", "raw"]},
                },
                "required": ["source"],
            },
        ),
        types.Tool(
            name="suggest_cvss",
            description="Suggest a CVSS vector + computed base score for a finding from its impact class + exposure properties. Supports CVSS v3.1 AND v4.0 (default: both). impact_class picks the C/I/A impact legs (rce, sqli, idor, bola, idor_write, ssrf, xxe, xss, stored_xss, reflected_xss, csrf, auth_bypass, account_takeover, info_disclosure, path_traversal, command_injection, deserialization, ssti, open_redirect, dos, business_logic, mass_assignment, privilege_escalation). Exposure args set AV/AC/PR/UI. Returns per-version {vector, score, severity, calculator_url}. Use after a candidate is CONFIRMED to auto-derive a defensible severity vector instead of hand-guessing.",
            inputSchema={
                "type": "object",
                "properties": {
                    "impact_class": {"type": "string", "description": "Finding class, e.g. 'sqli', 'idor', 'ssrf', 'rce', 'account_takeover'"},
                    "attacker_control": {"type": "string", "description": "Attack vector: network (default) | adjacent | local | physical", "enum": ["network", "adjacent", "local", "physical"]},
                    "complexity": {"type": "string", "description": "Attack complexity: low (default) | high", "enum": ["low", "high"]},
                    "privileges": {"type": "string", "description": "Privileges required: none (default) | low | high", "enum": ["none", "low", "high"]},
                    "user_interaction": {"type": "string", "description": "User interaction: none (default) | required (v3.1) / passive | active (v4.0)"},
                    "scope_changed": {"type": "boolean", "description": "v3.1 scope change / v4.0 subsequent-system impact (default false)"},
                    "version": {"type": "string", "description": "3.1 | 4.0 | both (default)", "enum": ["3.1", "4.0", "both"]},
                },
                "required": ["impact_class"],
            },
        ),
        types.Tool(
            name="w2_create_candidate",
            description="Create a web2/API vulnerability hypothesis candidate in the web2 audit DB (bounty_web2.db). Candidate != Finding — status starts DISCOVERED. Endpoint/method/vuln_class-centric (web2 mirror of the web3 create_candidate). Auto-creates the audit row if it doesn't exist. Returns candidate id (UUID) + display_id (H-001). Feed potential_sinks from parse_web2_surface here.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string", "description": "Audit session id, e.g. <target>-<YYYY-MM-DD>. Auto-created if new."},
                    "endpoint": {"type": "string", "description": "host + path, e.g. api.example.com/api/users/{id}"},
                    "method": {"type": "string", "description": "HTTP method (GET/POST/...) or logical operation"},
                    "hypothesis": {"type": "string", "description": "Vulnerability hypothesis description"},
                    "vuln_class": {"type": "string", "description": "sqli, idor, bola, ssrf, xss, csrf, auth_bypass, mass_assignment, ssti, xxe, business_logic, ..."},
                    "properties": {"type": "array", "items": {"type": "string"}, "description": "Tags: permissionless, state_mutating, external_input, access_control, ..."},
                    "target_host": {"type": "string", "description": "Optional — set on the audit row when auto-creating"},
                },
                "required": ["audit_id", "endpoint", "method", "hypothesis"],
            },
        ),
        types.Tool(
            name="w2_add_evidence",
            description="Add evidence (observation, not conclusion) to a web2 candidate. relationship = SUPPORTS or DISCONFIRMS. Always search DISCONFIRMING evidence too (authz enforced, CSRF token present, rate-limited). evidence_type: reachability, attacker_control, authz_check, injection_reflected, missing_mitigation, csrf_token, rate_limit, historical_precedent, transport, info_leak. Returns evidence id + display_id (E-001).",
            inputSchema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string", "description": "Candidate UUID from w2_create_candidate"},
                    "audit_id": {"type": "string", "description": "Audit session id"},
                    "evidence_type": {"type": "string", "description": "reachability, attacker_control, authz_check, injection_reflected, missing_mitigation, csrf_token, rate_limit, historical_precedent, transport, info_leak"},
                    "relationship": {"type": "string", "enum": ["SUPPORTS", "DISCONFIRMS"]},
                    "source": {"type": "string", "description": "request/response, HackerOne #id, curl, analysis"},
                    "claim": {"type": "string", "description": "Observation: what was actually observed (not a conclusion)"},
                    "location": {"type": "string", "description": "endpoint + param, response header, or null"},
                    "observed_value": {"type": "string", "description": "Actual observed value (status code, body snippet, header)"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["candidate_id", "audit_id", "evidence_type", "relationship", "source", "claim"],
            },
        ),
        types.Tool(
            name="w2_validate_candidate",
            description="Run the validation state machine on a web2 candidate and persist the verdict. Checks reachability/attacker_control/prerequisites/state_impact/asset_impact/exploitability. Optionally store the CVSS vector/score/severity (from suggest_cvss). final_status = CONFIRMED / KILLED / TEST_CANDIDATE / HOLD updates the candidate. Returns validation id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "audit_id": {"type": "string"},
                    "reachability": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "attacker_control": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "prerequisites": {"type": "string", "enum": ["satisfied", "unsatisfied", "partial", "unknown"]},
                    "state_impact": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "asset_impact": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "exploitability": {"type": "string", "enum": ["confirmed", "unconfirmed", "partial", "unknown"]},
                    "confidence_scores": {"type": "object", "description": "Per-dimension 0-100: reachability, attacker_control, exploitability, impact, evidence_quality, historical_similarity"},
                    "final_status": {"type": "string", "enum": ["CONFIRMED", "KILLED", "TEST_CANDIDATE", "HOLD"]},
                    "kill_reason": {"type": "string"},
                    "confirm_reason": {"type": "string"},
                    "cvss_vector": {"type": "string", "description": "Optional CVSS vector (from suggest_cvss)"},
                    "cvss_score": {"type": "number"},
                    "cvss_severity": {"type": "string"},
                },
                "required": ["candidate_id", "audit_id"],
            },
        ),
        types.Tool(
            name="w2_store_surface",
            description="Persist a parse_web2_surface result into the web2 audit DB as an attack_surfaces row + surface_endpoints. Pass the full parse_web2_surface output as 'model'. Auto-creates the audit row. Returns surface id + endpoint count.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string"},
                    "host": {"type": "string", "description": "Primary host, e.g. api.example.com"},
                    "source_type": {"type": "string", "description": "openapi | postman | har | raw"},
                    "model": {"type": "object", "description": "Full parse_web2_surface output (must contain 'endpoints')"},
                },
                "required": ["audit_id", "host", "source_type", "model"],
            },
        ),
        types.Tool(
            name="w2_get_coverage",
            description="Get the web2 coverage matrix for an audit (OWASP-flavored categories: authz, injection, ssrf, auth, session, csrf, business_logic, info_disclosure, transport, client_side, rate_limit, file_upload, misconfig, xxe). Auto-inits NOT_STARTED rows. Any NOT_STARTED = incomplete audit.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string"},
                },
                "required": ["audit_id"],
            },
        ),
        types.Tool(
            name="w2_update_coverage",
            description="Update a web2 coverage category status (NOT_STARTED, DISCOVERED, TESTING, SUPPORTED, DISCONFIRMED, CONFIRMED, KILLED) with linked candidate ids + notes.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string"},
                    "category": {"type": "string", "description": "authz, injection, ssrf, auth, session, csrf, business_logic, info_disclosure, transport, client_side, rate_limit, file_upload, misconfig, xxe"},
                    "status": {"type": "string", "enum": ["NOT_STARTED", "DISCOVERED", "TESTING", "SUPPORTED", "DISCONFIRMED", "CONFIRMED", "KILLED"]},
                    "candidate_ids": {"type": "array", "items": {"type": "string"}},
                    "notes": {"type": "string"},
                },
                "required": ["audit_id", "category", "status"],
            },
        ),
        types.Tool(
            name="w2_link_precedent",
            description="Link a web2 candidate to a disclosed precedent (HackerOne report, Bugcrowd disclosure, CVE, ExploitDB) found via search_hackerone/search_bugcrowd/search_cve. Precedent = supporting evidence, NOT a severity verdict.",
            inputSchema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                    "precedent_source": {"type": "string", "enum": ["hackerone", "bugcrowd", "cve", "exploitdb"]},
                    "precedent_ref": {"type": "string", "description": "report URL / CVE id / EDB id"},
                    "precedent_title": {"type": "string"},
                    "similarity_type": {"type": "string", "description": "root_cause, endpoint_shape, attacker_capability, impact"},
                    "similarity_score": {"type": "number", "description": "0-1"},
                    "notes": {"type": "string"},
                },
                "required": ["candidate_id", "precedent_source", "precedent_ref"],
            },
        ),
        types.Tool(
            name="w2_get_audit_state",
            description="Dump the full state of a web2 audit from bounty_web2.db: audit row, all candidates (with status), attack surface endpoint count, and coverage matrix. Use to resume a web2 audit session or check progress.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string"},
                },
                "required": ["audit_id"],
            },
        ),
        types.Tool(
            name="w2_seed_candidates",
            description="Auto-bridge: generate DISCOVERED candidates in bulk from a parse_web2_surface model — one candidate per (endpoint x potential_sink). Each seed gets endpoint/method/mapped vuln_class + a templated hypothesis + property tags (permissionless/state_mutating/external_input derived from the endpoint). Idempotent (dedupe on endpoint+method+vuln_class). Turns a parsed attack surface into an instant candidate backlog. Also persists the surface. Returns the list of created candidates. Then triage each: add_evidence + validate.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string", "description": "Audit session id. Auto-created if new."},
                    "host": {"type": "string", "description": "Primary host, e.g. api.example.com (also stored on the audit + surface row)"},
                    "model": {"type": "object", "description": "Full parse_web2_surface output (must contain 'endpoints' with per-endpoint 'potential_sinks')"},
                    "source_type": {"type": "string", "description": "openapi | postman | har | raw (for the persisted surface row). Default: value from model or 'raw'."},
                    "only_sinks": {"type": "array", "items": {"type": "string"}, "description": "Optional filter — only seed candidates for these sink labels or vuln_classes. Omit = all sinks."},
                    "dedupe": {"type": "boolean", "description": "Skip seeds whose (endpoint, method, vuln_class) already exists (default true)."},
                    "store_surface": {"type": "boolean", "description": "Also persist the surface as attack_surfaces + surface_endpoints (default true)."},
                },
                "required": ["audit_id", "model"],
            },
        ),
        types.Tool(
            name="w2_get_candidate",
            description="Get the FULL detail of one web2 candidate for report writing: candidate row + all evidence grouped (SUPPORTS/DISCONFIRMS with counts) + latest validation verdict (dimensions + CVSS) + linked precedents. Use per-finding when drafting the report.",
            inputSchema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string"},
                },
                "required": ["candidate_id"],
            },
        ),
        types.Tool(
            name="w2_recall_proven",
            description="LEARN-FROM-DB: recall PROVEN findings (final_status=CONFIRMED) and their SUPPORTING evidence so you can reuse payloads / breakthrough signals that ACTUALLY worked before probing a sink. NO separate learned-patterns store — the evidence + validation tables ARE the memory. Only CONFIRMED candidates surface (theory/UNKNOWN/KILLED never appear, so you never learn an unproven assumption). Call this BEFORE probing a vuln_class: it returns each proven candidate's endpoint/method/vuln_class, CVSS verdict, and every SUPPORTING evidence row (claim + observed_value = the signal that proved the breakthrough, e.g. 'root:x:0:0 in response', '5s delay', 'SSRF callback received').",
            inputSchema={
                "type": "object",
                "properties": {
                    "vuln_class": {"type": "string", "description": "Filter by vuln_class, e.g. ssrf, idor, sqli, path_traversal, xss, auth_bypass. Omit = all classes."},
                    "sink": {"type": "string", "description": "Alternative filter by sink label (e.g. 'SSRF/open-redirect'); auto-mapped to vuln_class."},
                    "audit_id": {"type": "string", "description": "Restrict to one audit. Omit = recall across ALL audits in this db (cross-target learning within the same db)."},
                    "limit": {"type": "integer", "description": "Max proven patterns to return (default 25)."},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="build_references",
            description="Assemble a ready-to-paste markdown References section for a bug bounty report. Searches NVD for matching CVEs, pulls their CWE ids + CVSS calculator links, optional GitHub advisories, Bugcrowd precedents, HackerOne Hacktivity disclosed-report precedents, Exploit-DB entries, and OWASP links. Pass cve_ids to anchor specific CVEs, otherwise keywords drive the NVD search.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Vulnerability keywords, e.g. 'SQL injection authentication bypass'"},
                    "cve_ids": {"type": "array", "items": {"type": "string"}, "description": "Optional explicit CVE IDs to include"},
                    "include_cve": {"type": "boolean", "description": "Include CVE entries (default true)"},
                    "include_cwe": {"type": "boolean", "description": "Include CWE entries (default true)"},
                    "include_ghsa": {"type": "boolean", "description": "Include GitHub advisory entries (default false)"},
                    "include_bugcrowd": {"type": "boolean", "description": "Include Bugcrowd crowdstream precedents (default false)"},
                    "include_hackerone": {"type": "boolean", "description": "Include HackerOne Hacktivity disclosed-report precedents (default false)"},
                    "include_exploitdb": {"type": "boolean", "description": "Include Exploit-DB entries (default false)"},
                    "include_owasp": {"type": "boolean", "description": "Include OWASP framework links (default true)"},
                    "max_cve": {"type": "integer", "description": "Max CVE results from keyword search (default 5)"},
                },
                "required": ["keywords"],
            },
        ),
    ])


async def handle_call_tool(ctx, params) -> types.CallToolResult:
    name = params.name
    arguments = params.arguments or {}
    try:
        if name == "search_cve":
            result = search_cve(
                arguments["keywords"],
                results_per_page=arguments.get("results_per_page", 10),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "get_cve":
            result = get_cve(arguments["cve_id"])
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "get_cwe":
            result = get_cwe(arguments["cwe_id"])
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "search_ghsa":
            result = search_ghsa(
                arguments["query"],
                results_per_page=arguments.get("results_per_page", 10),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "query_osv":
            result = query_osv(
                arguments["package_name"],
                ecosystem=arguments.get("ecosystem", "npm"),
                results_per_page=arguments.get("results_per_page", 10),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "search_bugcrowd":
            result = search_bugcrowd(
                arguments.get("keywords", ""),
                results_per_page=arguments.get("results_per_page", 10),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "search_hackerone":
            result = search_hackerone(
                arguments.get("keywords", ""),
                results_per_page=arguments.get("results_per_page", 10),
                disclosed_only=arguments.get("disclosed_only", True),
                cwe=arguments.get("cwe"),
                severity=arguments.get("severity", ""),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "search_exploitdb":
            result = search_exploitdb(
                arguments["keywords"],
                results_per_page=arguments.get("results_per_page", 10),
                platform=arguments.get("platform", ""),
                exploit_type=arguments.get("exploit_type", ""),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "read_exploit_file":
            result = read_exploit_file(
                arguments["edb_id"],
                max_chars=arguments.get("max_chars", 60000),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "get_owasp":
            result = get_owasp(arguments["keywords"])
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "cvss_calculator_url":
            result = cvss_calculator_url(arguments["vector"])
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "suggest_cvss":
            result = suggest_cvss(
                arguments["impact_class"],
                attacker_control=arguments.get("attacker_control", "network"),
                complexity=arguments.get("complexity", "low"),
                privileges=arguments.get("privileges", "none"),
                user_interaction=arguments.get("user_interaction", "none"),
                scope_changed=arguments.get("scope_changed", False),
                version=arguments.get("version", "both"),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "parse_web2_surface":
            result = parse_web2_surface(
                arguments["source"],
                source_type=arguments.get("source_type", "auto"),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_create_candidate":
            _db.create_audit(audit_id=arguments["audit_id"],
                             name=arguments.get("target_host", arguments["audit_id"]),
                             target_host=arguments.get("target_host"))
            result = _db.create_candidate(
                arguments["audit_id"], arguments["endpoint"], arguments["method"],
                arguments["hypothesis"], vuln_class=arguments.get("vuln_class"),
                properties=arguments.get("properties"))
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_add_evidence":
            result = _db.add_evidence(
                arguments["candidate_id"], arguments["audit_id"],
                arguments["evidence_type"], arguments["relationship"],
                arguments["source"], arguments["claim"],
                location=arguments.get("location"),
                observed_value=arguments.get("observed_value"),
                confidence=arguments.get("confidence", "medium"))
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_validate_candidate":
            val_id = _db.save_validation(
                arguments["candidate_id"], arguments["audit_id"],
                reachability=arguments.get("reachability", "unknown"),
                attacker_control=arguments.get("attacker_control", "unknown"),
                prerequisites=arguments.get("prerequisites", "unknown"),
                state_impact=arguments.get("state_impact", "unknown"),
                asset_impact=arguments.get("asset_impact", "unknown"),
                exploitability=arguments.get("exploitability", "unknown"),
                confidence_scores=arguments.get("confidence_scores"),
                final_status=arguments.get("final_status"),
                kill_reason=arguments.get("kill_reason"),
                confirm_reason=arguments.get("confirm_reason"),
                cvss_vector=arguments.get("cvss_vector"),
                cvss_score=arguments.get("cvss_score"),
                cvss_severity=arguments.get("cvss_severity"))
            cand = _db.get_candidate(arguments["candidate_id"])
            result = {"validation_id": val_id, "final_status": arguments.get("final_status"),
                      "candidate_status": cand["status"] if cand else None}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_store_surface":
            _db.create_audit(audit_id=arguments["audit_id"], name=arguments["host"],
                             target_host=arguments["host"], surface_source=arguments["source_type"])
            surface_id = _db.store_attack_surface(
                arguments["audit_id"], arguments["host"],
                arguments["source_type"], arguments["model"])
            surf = _db.get_attack_surface(arguments["audit_id"])
            result = {"surface_id": surface_id,
                      "endpoint_count": len(surf["endpoints"]) if surf else 0}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_get_coverage":
            result = _db.get_coverage(arguments["audit_id"])
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_update_coverage":
            _db.update_coverage(
                arguments["audit_id"], arguments["category"], arguments["status"],
                candidate_ids=arguments.get("candidate_ids"),
                notes=arguments.get("notes"))
            result = {"ok": True, "category": arguments["category"], "status": arguments["status"]}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_link_precedent":
            _db.link_precedent(
                arguments["candidate_id"], arguments["precedent_source"],
                arguments["precedent_ref"], precedent_title=arguments.get("precedent_title"),
                similarity_type=arguments.get("similarity_type"),
                similarity_score=arguments.get("similarity_score"),
                notes=arguments.get("notes"))
            result = {"ok": True, "candidate_id": arguments["candidate_id"],
                      "precedent_ref": arguments["precedent_ref"]}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_get_audit_state":
            aid = arguments["audit_id"]
            audit = _db.get_audit(aid)
            cands = _db.get_candidates_by_audit(aid)
            surf = _db.get_attack_surface(aid)
            cov = _db.get_coverage(aid)
            result = {
                "audit": audit,
                "candidates": [{"display_id": c["display_id"], "endpoint": c["endpoint"],
                                "vuln_class": c["vuln_class"], "status": c["status"]} for c in cands],
                "candidate_count": len(cands),
                "surface_endpoint_count": len(surf["endpoints"]) if surf else 0,
                "coverage": [{"category": c["category"], "status": c["status"]} for c in cov],
            }
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_seed_candidates":
            _db.create_audit(audit_id=arguments["audit_id"],
                             name=arguments.get("host", arguments["audit_id"]),
                             target_host=arguments.get("host"),
                             surface_source=arguments.get("source_type"))
            model = arguments["model"]
            if arguments.get("store_surface", True) and arguments.get("host"):
                _db.store_attack_surface(
                    arguments["audit_id"], arguments["host"],
                    arguments.get("source_type") or model.get("source_type") or "raw", model)
            created = _db.seed_candidates_from_surface(
                arguments["audit_id"], model,
                only_sinks=arguments.get("only_sinks"),
                dedupe=arguments.get("dedupe", True))
            result = {"seeded_count": len(created), "candidates": created}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_get_candidate":
            detail = _db.get_candidate_detail(arguments["candidate_id"])
            result = detail if detail else {"error": "candidate not found"}
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "w2_recall_proven":
            result = _db.recall_proven(
                vuln_class=arguments.get("vuln_class"),
                sink=arguments.get("sink"),
                audit_id=arguments.get("audit_id"),
                limit=arguments.get("limit", 25))
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        elif name == "build_references":
            result = build_references(
                arguments["keywords"],
                include_cve=arguments.get("include_cve", True),
                include_cwe=arguments.get("include_cwe", True),
                include_ghsa=arguments.get("include_ghsa", False),
                include_bugcrowd=arguments.get("include_bugcrowd", False),
                include_hackerone=arguments.get("include_hackerone", False),
                include_exploitdb=arguments.get("include_exploitdb", False),
                include_owasp=arguments.get("include_owasp", True),
                max_cve=arguments.get("max_cve", 5),
                cve_ids=arguments.get("cve_ids"),
            )
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))])

        else:
            return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))], is_error=True)

    except Exception as e:
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps({"error": str(e)}))], is_error=True)


server = Server(
    "web2-references-mcp",
    on_list_tools=handle_list_tools,
    on_call_tool=handle_call_tool,
)


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

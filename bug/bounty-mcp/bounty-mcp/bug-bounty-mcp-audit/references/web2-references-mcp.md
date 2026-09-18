# Web2 References MCP — report References section builder

Sibling MCP server to the main bounty-mcp audit server. Both live under
`/root/bounty-mcp/` and are loaded as stdio MCP servers in Hermes
sessions that have them configured. **No restart needed** — if the
`mcp_web2_references_mcp_*` tools are visible in-session, they are live.
When Mas says "ga perlu restart / kita di session mcp", do NOT suggest
restarting Hermes or the MCP servers — just check state (DB, processes)
and continue.

## Purpose
Build the **References section** of a bug bounty report from public
vulnerability databases. Used at report/submission time, complementing
Solodit precedent search (main bounty-mcp `search_precedents`).

## Tools (mcp_web2_references_mcp_*)
| Tool | Source | Use |
|------|--------|-----|
| search_cve | NVD API v2 | keyword CVE search (desc, CVSS, CWE ids, link) |
| get_cve | NVD | full CVE detail incl. advisory reference URLs |
| get_cwe | MITRE CWE API | CWE name/description + cwe.mitre.org link |
| search_ghsa | GitHub Advisory API | GHSA search (severity, linked CVE) |
| query_osv | OSV.dev API | package+ecosystem vuln lookup (npm, PyPI, Maven, Go...) |
| search_bugcrowd | bugcrowd.com/crowdstream.json | recent disclosed bounties by program/target keyword (public feed, no auth) |
| search_hackerone | hackerone.com/graphql (public CompleteHacktivityReportIndex) | disclosed H1 reports by keyword/CWE/severity; returns title, cwe, severity, award, program, reporter, public report URL. Web2 precedent = mirror of Solodit for web3. |
| search_exploitdb | local /opt/exploitdb/files_exploits.csv | 47K+ exploit entries; falls back to searchsploit --json. Results now include `file_path` (absolute path to the local exploit file) so the agent can read it. |
| read_exploit_file | local /opt/exploitdb/exploits/ | read the FULL exploit source for an EDB-ID (resolved from CSV, path-traversal safe). Returns content (truncated at max_chars, default 60K / cap 128K) + metadata. Agent-LEARNING tool — lets the agent study the actual payload/technique, not just link to it. |
| get_owasp | static mapping | Top 10 2021 / API Top 10 2023 / cheat sheet links per keyword |
| cvss_calculator_url | FIRST | calculator URL from an existing vector string (v2/v3.x/v4.0 auto-detect) |
| suggest_cvss | preset table + `cvss` lib | auto-derive a CVSS vector + computed base score from a finding's impact_class + exposure props; returns BOTH v3.1 and v4.0 (default) with score+severity+calc URL |
| parse_web2_surface | offline parser | web2 analogue of get_attack_surface: OpenAPI/Swagger/Postman/HAR/raw endpoint list → per-endpoint model + heuristic potential_sinks + summary |
| build_references | combined | assembles markdown References section: CVE + CWE + CVSS calc links + optional GHSA/Bugcrowd/HackerOne/ExploitDB/OWASP |

### Web2 audit-state tools (mcp_web2_references_mcp_w2_*) — full lifecycle, own DB
The web2 server now mirrors the web3 candidate→evidence→validation→coverage
lifecycle, backed by its OWN db `/root/bounty-mcp/web2/bounty_web2.db`
(endpoint/method/vuln_class-centric — NOT contract/function; separate from the
web3 `bounty_mcp.db`). Use these for a pure web2/API audit so state does not
land in the web3-flavored DB.

| Tool | Use |
|------|-----|
| w2_create_candidate | create a web2 hypothesis (endpoint, method, vuln_class, hypothesis, properties). Auto-creates the audit row. status starts DISCOVERED, returns H-001. Feed potential_sinks from parse_web2_surface. |
| w2_add_evidence | add SUPPORTS/DISCONFIRMS observation (reachability, attacker_control, authz_check, injection_reflected, missing_mitigation, csrf_token, rate_limit, historical_precedent, transport, info_leak). Returns E-001. Always search DISCONFIRMING too. |
| w2_validate_candidate | run validation state machine + persist verdict (reachability/attacker_control/prerequisites/state_impact/asset_impact/exploitability + confidence_scores). Optionally store cvss_vector/score/severity from suggest_cvss. final_status CONFIRMED/KILLED/TEST_CANDIDATE/HOLD updates the candidate. |
| w2_store_surface | persist a parse_web2_surface result as attack_surfaces + surface_endpoints rows. |
| w2_seed_candidates | AUTO-BRIDGE: turn a parse_web2_surface model into a DISCOVERED candidate backlog in one call — one candidate per (endpoint × potential_sink), with auto property tags (permissionless/state_mutating/external_input). Idempotent (dedupe on endpoint+method+vuln_class). Also persists the surface. `only_sinks=[...]` to focus one class. Skips manual per-hypothesis w2_create_candidate. |
| w2_recall_proven | LEARN-FROM-DB: recall PROVEN findings (final_status=CONFIRMED) + their SUPPORTING evidence so you reuse payloads/breakthrough-signals that ACTUALLY worked BEFORE probing a sink. Filter by vuln_class or sink. NO separate store — the evidence+validation tables ARE the memory; only CONFIRMED surfaces (never learn an unproven assumption). Omit audit_id = recall across ALL audits in this db (cross-target); pass it to stay in one target. Returns endpoint/method/CVSS + claim (payload) + observed_value (signal). |
| w2_get_candidate | full per-finding detail: candidate + evidence grouped (SUPPORTS/DISCONFIRMS + counts) + latest validation verdict (dimensions + CVSS) + linked precedents. For report writing. |
| w2_get_coverage | web2 OWASP-flavored coverage matrix (authz, injection, ssrf, auth, session, csrf, business_logic, info_disclosure, transport, client_side, rate_limit, file_upload, misconfig, xxe). Auto-inits NOT_STARTED. |
| w2_update_coverage | set a category status + link candidate ids + notes. |
| w2_link_precedent | link candidate to a disclosed precedent (hackerone/bugcrowd/cve/exploitdb) from search_hackerone etc. Precedent = supporting evidence, not a severity verdict. |
| w2_get_audit_state | dump full audit state (audit row, candidates+status, surface endpoint count, coverage) — use to resume/check progress. |

## suggest_cvss quickstart
- `suggest_cvss(impact_class, attacker_control='network', complexity='low', privileges='none', user_interaction='none', scope_changed=False, version='both')`.
- impact_class drives the C/I/A (VC/VI/VA) impact legs from a 23-class preset table: rce, sqli, auth_bypass, account_takeover, idor, bola, idor_write, ssrf, xxe, info_disclosure, stored_xss, reflected_xss, xss, csrf, path_traversal, command_injection, deserialization, ssti, open_redirect, dos, business_logic, mass_assignment, privilege_escalation.
- Exposure args set AV/AC/PR/UI. `version` = `3.1` | `4.0` | `both` (default both).
- Output per version: `{vector, score, severity, calculator_url}`. Scores computed by the `cvss` lib (installed in the venv). Unknown class → `{error, known_classes[]}`.
- Use AFTER a candidate is CONFIRMED to get a defensible starting vector — then hand-adjust legs to the exact finding before reporting. Do NOT blindly ship the preset.

## parse_web2_surface quickstart
- `parse_web2_surface(source, source_type='auto')`. source = OpenAPI/Swagger spec (path/http(s) URL/inline JSON or YAML), Postman v2 collection JSON, HAR JSON, or raw newline-separated endpoints (`GET /api/users/{id}` or bare URLs). source_type: auto|openapi|postman|har|raw.
- Output: `{endpoint_count, endpoints[], summary}`. Each endpoint: method, path, params by location, auth model, state_mutating flag, trust_boundary, `potential_sinks[]`. Summary: total, state_mutating, unauthenticated_state_mutating, auth_required/no_auth, by_method, sink_hits histogram.
- potential_sinks classes: IDOR/BOLA, SSRF, SQLi, path-traversal, command-injection, XSS/SSTI, mass-assignment, auth-abuse, business-logic, XXE, file-upload.
- This is the web2 entry point — parse the surface FIRST, feed potential_sinks into create_candidate. Web2 analogue of get_attack_surface (web3 Solidity).

## build_references quickstart
- Always pass `keywords` even when `cve_ids` is set (schema wart).
- Default: include_cve+include_cwe+include_owasp = true; GHSA/Bugcrowd/HackerOne/ExploitDB = false.
- cve_ids anchors specific CVEs; otherwise keywords drive NVD search (`max_cve` default 5).
- Output: `{references_markdown, entries[], warnings[]}` — paste markdown straight into report.

## Coverage matrix
Covered:
- CVE (NVD), CWE (MITRE), GHSA (GitHub), OSV.dev, FIRST CVSS calculator
- **CVSS auto-scoring** — `suggest_cvss` derives v3.1 + v4.0 vector + base score + severity from impact_class + exposure (computed via `cvss` lib, not just a calculator link)
- **Web2 attack surface** — `parse_web2_surface` parses OpenAPI/Postman/HAR/raw into an endpoint model + potential_sinks (web2 mirror of get_attack_surface)
- Bugcrowd crowdstream (public JSON feed — recent disclosures only, keyword on program/target/substate)
- **HackerOne Hacktivity (public GraphQL `CompleteHacktivityReportIndex`, no session)** — this is the web2 mirror of Solodit. Search DSL: plain text (`ssrf`), field filter (`cwe:"CWE-79"`, `severity:high`, `weakness:xss`), combined with `AND`. `disclosed:true` auto-`AND`ed (bare space = OR in H1 DSL → returns everything, must AND to narrow). Returns real disclosed reports + public report URL + award + program.
- Exploit-DB (local CSV, 47K+ rows)
- OWASP (static keyword→link map)
- Solodit precedents — via main bounty-mcp `search_precedents` (web3 side)

NOT covered (no public API / bot-walled):
- Immunefi public advisories
- PacketStorm (search redirects / bot protection)

## Domain split (both sides of one bounty-mcp project)
- **web3 precedent** → main bounty-mcp `search_precedents` (Solodit / Cyfrin audit findings)
- **web2 precedent** → web2-references-mcp `search_hackerone` + `search_bugcrowd` (disclosed bounty reports)
- Same purpose (find real disclosed prior art for a finding), split by domain into two MCP servers under one `/root/bounty-mcp/` folder. web3 = root, web2 = `web2/`.

Most effective combo: CVE/CWE + 1-2 public precedent reports
(HackerOne for web2 / Solodit for web3) + OWASP when needed.

## Operational notes
- NVD unauth rate limit ~5 req/30s → built-in limiter 4 req/30s;
  build_references with many CVEs/CWEs can take 30s+.
- GitHub unauth ~60 req/hr → limiter 8 req/60s.
- Bugcrowd feed ~17KB — returns only recent disclosures; keyword search
  may return 0 for old vuln classes. Expected, not a bug.
- In-memory TTL cache 6h — repeated calls fast.
- Main server: `/root/bounty-mcp/server.py`; references server:
  `/root/bounty-mcp/web2/server.py` (`references.py` = data layer,
  `server.py` = MCP stdio transport, `db.py` = web2 audit-state layer).
  DBs: web3 state → `/root/bounty-mcp/bounty_mcp.db`; web2 state →
  `/root/bounty-mcp/web2/bounty_web2.db` (separate, endpoint-centric — created
  on first w2_* call / server boot; empty DB = no web2 audit started yet).
- Verify server live: `ps aux | grep web2/server.py`; handshake test:
  `echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' | timeout 5 <venv>/python3 /root/bounty-mcp/web2/server.py`
- Self-test: `<venv>/python3 /root/bounty-mcp/web2/test_tools.py`
- **mcp SDK version pinned to 2.0.0** (requirements.txt, matches the hermes venv).
  The server code uses the 2.0.0 constructor-style API:
  `Server("web2-references-mcp", on_list_tools=handle_list_tools, on_call_tool=handle_call_tool)`
  with handlers `(ctx, params) -> types.ListToolsResult / types.CallToolResult`
  (`params.name` / `params.arguments`). NOT the old `@server.list_tools()`
  decorator API from mcp 1.x — that breaks with AttributeError on 2.0.0.
  Full 24-tool handshake check: `<venv>/python3 /root/bounty-mcp/web2/test_mcp2_handshake.py`
  (spawns server, verifies initialize + tools/list = 24 + one tool call).

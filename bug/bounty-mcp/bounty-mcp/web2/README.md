# Web2 References MCP Server

Sibling to the main [bounty-mcp](../README.md) audit server. Builds the
**References section** of a bug bounty report from public vulnerability
databases — NVD/CVE, MITRE CWE, GitHub Advisory (GHSA), OSV.dev,
Bugcrowd crowdstream, HackerOne Hacktivity (public disclosed reports),
local Exploit-DB, OWASP static links, and FIRST CVSS calculator URLs.

## Files

- `references.py` — data layer: all lookups + rate limiters + cache + markdown formatter
- `server.py` — MCP stdio transport, exposes 11 tools
- `test_tools.py` — self-test for all tools (16 checks)

## Tools (exposed via `mcp_web2_references_mcp_*`)

| Tool | Source | Purpose |
|------|--------|---------|
| search_cve | NVD API v2 | keyword CVE search |
| get_cve | NVD | full CVE detail + advisory refs |
| get_cwe | MITRE CWE API | CWE name/description + link |
| search_ghsa | GitHub Advisory API | GHSA search |
| query_osv | OSV.dev API | package+ecosystem vuln lookup |
| search_bugcrowd | crowdstream.json | recent disclosed bounties |
| search_hackerone | H1 GraphQL (public) | disclosed reports by keyword / CWE (number or name) / severity, with award + program. CWE auto-resolved to weakness NAME (H1 index quirk); `severity:` auto-rewritten to `severity_rating:`. Ships `h1_weakness_map.json` (CWE#->name). |
| search_exploitdb | /opt/exploitdb CSV | exploit-db search (searchsploit fallback) |
| get_owasp | static map | OWASP Top10/API10/cheat-sheet links |
| cvss_calculator_url | FIRST | CVSS calculator URL from a vector (v2/v3/v4 auto) |
| suggest_cvss | preset + `cvss` lib | derive v3.1+v4.0 vector + base score + severity from impact_class + exposure |
| parse_web2_surface | offline parser | OpenAPI/Postman/HAR/raw → endpoint model + potential_sinks (web2 attack surface) |
| build_references | combined | ready-to-paste markdown References section |

### Web2 audit-state lifecycle (own DB)

These mirror the web3 candidate→evidence→validation→coverage loop, backed by
`web2/bounty_web2.db` (endpoint/method/vuln_class-centric — separate from the
web3 `../bounty_mcp.db`). Audit rows auto-create on first use.

| Tool | Purpose |
|------|---------|
| w2_create_candidate | create a web2 hypothesis (endpoint, method, vuln_class, hypothesis, properties) → H-001 |
| w2_add_evidence | SUPPORTS/DISCONFIRMS observation → E-001 |
| w2_validate_candidate | validation state machine + CVSS persist → CONFIRMED/KILLED/TEST_CANDIDATE/HOLD |
| w2_store_surface | persist a parse_web2_surface result as attack_surfaces + surface_endpoints |
| w2_get_coverage | OWASP-flavored coverage matrix (auto-inits NOT_STARTED) |
| w2_update_coverage | set category status + linked candidates + notes |
| w2_link_precedent | link candidate to a disclosed precedent (H1/Bugcrowd/CVE/EDB) |
| w2_get_audit_state | dump audit row + candidates + surface count + coverage |

## Requirements

Python 3.11+, `mcp`, `requests`, `cvss` (for suggest_cvss score computation), `PyYAML` (for OpenAPI YAML specs). All sources are public — no API keys.

## Run

```bash
# MCP stdio (as registered in ~/.hermes/config.yaml)
/usr/local/lib/hermes-agent/venv/bin/python3 server.py

# Self-test
/usr/local/lib/hermes-agent/venv/bin/python3 test_tools.py
```

## Registration

In `~/.hermes/config.yaml`:

```yaml
web2-references-mcp:
  command: /usr/local/lib/hermes-agent/venv/bin/python3
  args:
  - /root/bounty-mcp/web2/server.py
  enabled: true
```

## Notes

- NVD unauth ~5 req/30s → limiter 4 req/30s. GitHub ~60 req/hr → 8 req/60s. H1 → 8 req/60s.
- 6h in-memory TTL cache.
- Bugcrowd feed is recent disclosures only — old vuln classes may return 0 (expected).
- HackerOne uses the public `CompleteHacktivityReportIndex` GraphQL (no session). Search DSL: plain text (`ssrf`), field filters (`cwe:"CWE-79"`, `severity:high`, `weakness:xss`), combined with `AND`. `disclosed:true` is auto-`AND`ed (bare space = OR in H1 DSL, which would return everything).
- CVSS version auto-detect: explicit `CVSS:4.0/3.1/3.0/2` prefixes, else `Au:` = v2, else v3.1.

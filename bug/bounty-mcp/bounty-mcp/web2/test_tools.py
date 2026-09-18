#!/usr/bin/env python3
"""Quick self-test for web2-references-mcp data layer.

Run: <venv>/python3 /root/bounty-mcp/web2/test_tools.py
Covers references tools + suggest_cvss + parse_web2_surface + the web2
audit-state lifecycle (own DB bounty_web2.db). Offline-safe where possible;
network calls are short and rate-limited. Exit 0 = all green.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from references import (  # noqa: E402
    build_references,
    cvss_calculator_url,
    get_cve,
    get_cwe,
    get_owasp,
    query_osv,
    search_bugcrowd,
    search_hackerone,
    search_cve,
    search_exploitdb,
    read_exploit_file,
    search_ghsa,
)

FAIL = 0


def check(name: str, cond: bool, detail: str = ""):
    global FAIL
    status = "PASS" if cond else "FAIL"
    if not cond:
        FAIL += 1
    print(f"[{status}] {name} {detail}")


# 1. search_cve (network)
r = search_cve("jwt algorithm confusion", results_per_page=2)
check("search_cve", "results" in r and len(r["results"]) > 0, json.dumps(r)[:120])

# 2. get_cve (network)
r = get_cve("CVE-2024-55555")
check("get_cve", r.get("id") == "CVE-2024-55555", str(r.get("id")))

# 3. get_cwe (network)
r = get_cwe("79")
check("get_cwe", r.get("id") == "CWE-79", str(r.get("id")))
r = get_cwe("CWE-639")
check("get_cwe norm", r.get("id") == "CWE-639", str(r.get("id")))
r = get_cwe("nope")
check("get_cwe invalid", "error" in r, str(r.get("error"))[:80])

# 4. search_ghsa (network)
r = search_ghsa("jwt", results_per_page=3)
check("search_ghsa", "results" in r, json.dumps(r)[:120])

# 5. query_osv (network)
r = query_osv("express", ecosystem="npm", results_per_page=3)
check("query_osv", r.get("total_vulns", 0) > 0, json.dumps(r)[:120])

# 6. search_bugcrowd (network)
r = search_bugcrowd("", results_per_page=3)
check("search_bugcrowd", "results" in r, json.dumps(r)[:120])

# 7. search_exploitdb (local CSV)
r = search_exploitdb("wordpress sql injection", results_per_page=3)
check("search_exploitdb", r.get("total_results", 0) > 0, json.dumps(r)[:120])
# 7a. read_exploit_file (local file, first result)
if r.get("results"):
    edb_id = r["results"][0]["edb_id"]
    rf = read_exploit_file(edb_id, max_chars=2000)
    check("read_exploit_file", rf.get("edb_id") == edb_id and "content" in rf and rf.get("file_size", 0) > 0,
          f"edb={edb_id} size={rf.get('file_size')} content_len={len(rf.get('content',''))}")
    check("read_exploit_file path safe", rf.get("path", "").startswith("/opt/exploitdb/"),
          rf.get("path", ""))
    check("read_exploit_file file_path in search", "file_path" in r["results"][0],
          r["results"][0].get("file_path", ""))

# 7b. search_hackerone (network, public GraphQL)
r = search_hackerone("ssrf", results_per_page=3)
check("search_hackerone", r.get("results") and r["results"][0].get("url", "").startswith("https://hackerone.com/reports/"),
      json.dumps(r)[:150])
check("search_hackerone narrows", 0 < r.get("total_results", 0) < 10000, f"total={r.get('total_results')}")

# 7c. search_hackerone CWE-by-number resolves to weakness name (H1 index quirk)
r = search_hackerone(cwe=400, results_per_page=2)
check("search_hackerone cwe=number", 'cwe:"Uncontrolled Resource Consumption"' in r.get("query", "") and r.get("total_results", 0) > 0,
      f"q={r.get('query')} total={r.get('total_results')}")

# 7d. broken 'cwe:400' inside keywords is auto-corrected to the name filter
r = search_hackerone(keywords='cwe:"CWE-400"', results_per_page=2)
check("search_hackerone cwe DSL autofix", r.get("total_results", 0) > 0,
      f"q={r.get('query')} total={r.get('total_results')}")

# 7e. severity: alias rewrite + dedicated severity arg
r = search_hackerone(cwe=79, severity="high", results_per_page=2)
check("search_hackerone severity arg", "severity_rating:high" in r.get("query", ""),
      f"q={r.get('query')}")

# 8. get_owasp (offline)
r = get_owasp("bola ssrf xss")
check("get_owasp", len(r["results"]) >= 3, f"{len(r['results'])} results")
r = get_owasp("")
check("get_owasp empty", "error" not in r, json.dumps(r)[:80])

# 9. cvss_calculator_url (offline)
r = cvss_calculator_url("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
check("cvss v4", r.get("version") == "4.0" and "first.org" in r.get("calculator_url", ""), r.get("calculator_url", ""))
r = cvss_calculator_url("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
check("cvss v3", r.get("version") == "3.1", r.get("calculator_url", ""))
r = cvss_calculator_url("AV:N/AC:L/Au:N/C:P/I:P/A:P")
check("cvss v2 guess", r.get("version") == "2.0", r.get("calculator_url", ""))

# 10. build_references (network, bounded)
r = build_references("sql injection", max_cve=2, include_cve=True, include_cwe=True,
                     include_owasp=True, include_ghsa=False, include_bugcrowd=False,
                     include_exploitdb=False)
check("build_references", "references_markdown" in r, (r.get("references_markdown") or "")[:80].replace("\n", " "))

# 11. parse_web2_surface (offline, inline)
from web2_surface import parse_web2_surface
spec = json.dumps({
    "openapi": "3.0.0", "servers": [{"url": "https://api.x.com"}],
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
        "/fetch": {"post": {"security": [], "requestBody": {"content": {"application/json": {"schema": {"properties": {"url": {}}}}}}}},
    },
})
r = parse_web2_surface(spec, "openapi")
check("parse_web2_surface openapi", r.get("endpoint_count") == 2 and "IDOR/BOLA" in r["summary"]["sink_hits"], json.dumps(r.get("summary", {}))[:120])
check("parse_web2_surface ssrf sink", any("SSRF" in s for e in r["endpoints"] for s in e["potential_sinks"]), "ssrf hint on /fetch")
check("parse_web2_surface unauth-mut", r["summary"]["unauthenticated_state_mutating"] == 1, f"unauth_mut={r['summary']['unauthenticated_state_mutating']}")
r2 = parse_web2_surface("GET /api/orders/{order_id}\nPOST https://x.com/redirect?url=y", "raw")
check("parse_web2_surface raw", r2.get("endpoint_count") == 2, json.dumps(r2.get("summary", {}))[:100])

# 12. suggest_cvss (offline, computed)
from references import suggest_cvss
r = suggest_cvss("sqli")
check("suggest_cvss both", "v3.1" in r and "v4.0" in r, f"3.1={r.get('v3.1',{}).get('score')} 4.0={r.get('v4.0',{}).get('score')}")
check("suggest_cvss v3.1 score", r["v3.1"].get("score") == 9.4 and r["v3.1"].get("severity") == "Critical", r["v3.1"].get("vector", ""))
check("suggest_cvss v4.0 score", isinstance(r["v4.0"].get("score"), float) and r["v4.0"].get("severity"), r["v4.0"].get("vector", ""))
r = suggest_cvss("idor", version="3.1")
check("suggest_cvss version filter", "v3.1" in r and "v4.0" not in r, r["v3.1"].get("vector", ""))
r = suggest_cvss("nonsense")
check("suggest_cvss unknown class", "error" in r and r.get("known_classes"), f"{len(r.get('known_classes',[]))} known")

# 13. web2 audit-state lifecycle (own DB, offline)
from db import Web2Database  # noqa: E402
_tp = "/tmp/w2_selftest.db"
if os.path.exists(_tp):
    os.remove(_tp)
_d = Web2Database(_tp)
_aid = "selftest-2026-08-24"
_d.create_audit(audit_id=_aid, name="selftest", target_host="api.x.io", surface_source="openapi")
_c = _d.create_candidate(_aid, "api.x.io/users/{id}", "GET", "IDOR", vuln_class="idor", properties=["permissionless"])
check("w2 create_candidate", _c.get("display_id") == "H-001" and _c.get("status") == "DISCOVERED", _c.get("id", ""))
_e = _d.add_evidence(_c["id"], _aid, "reachability", "SUPPORTS", "curl", "200 for other user id", observed_value="200")
check("w2 add_evidence", _e.get("display_id") == "E-001", _e.get("id", ""))
_es = _d.get_evidence_summary(_c["id"])
check("w2 evidence_summary", _es["supporting_count"] == 1 and _es["disconfirming_count"] == 0, f"S={_es['supporting_count']}")
_v = _d.save_validation(_c["id"], _aid, reachability="pass", attacker_control="pass", exploitability="confirmed",
                        final_status="CONFIRMED", confirm_reason="cross-user read",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", cvss_score=7.5, cvss_severity="High")
_cand = _d.get_candidate(_c["id"])
check("w2 validate → CONFIRMED", _cand["status"] == "CONFIRMED", _v[:8])
_model = {"endpoints": [{"method": "GET", "path": "/users/{id}", "params": {"path": ["id"]}, "auth_model": "bearer", "state_mutating": False, "potential_sinks": ["IDOR/BOLA"]}]}
_sid = _d.store_attack_surface(_aid, "api.x.io", "openapi", _model)
_surf = _d.get_attack_surface(_aid)
check("w2 store/get surface", _surf and len(_surf["endpoints"]) == 1, f"eps={len(_surf['endpoints']) if _surf else 0}")
_d.update_coverage(_aid, "authz", "CONFIRMED", candidate_ids=[_c["id"]], notes="idor")
_cov = _d.get_coverage(_aid)
_authz = [x["status"] for x in _cov if x["category"] == "authz"]
check("w2 coverage matrix", len(_cov) == len(Web2Database.DEFAULT_CATEGORIES) and _authz == ["CONFIRMED"], f"rows={len(_cov)} authz={_authz}")
_d.link_precedent(_c["id"], "hackerone", "https://hackerone.com/reports/12345", similarity_score=0.9)
check("w2 link_precedent", len(_d.get_precedents_for_candidate(_c["id"])) == 1, "1 precedent")

# 14. candidate detail (full per-finding view)
_det = _d.get_candidate_detail(_c["id"])
check("w2 get_candidate_detail", _det and _det["candidate"]["status"] == "CONFIRMED"
      and _det["evidence"]["supporting_count"] == 1 and _det["validation"]["cvss_score"] == 7.5
      and len(_det["precedents"]) == 1, "candidate+evidence+validation+precedents")

# 15. auto-bridge: seed candidates from a parsed surface
_seed_spec = json.dumps({
    "openapi": "3.0.0", "servers": [{"url": "https://api.seed.io"}],
    "paths": {
        "/orders/{order_id}": {"get": {"parameters": [{"name": "order_id", "in": "path"}]}},
        "/proxy": {"post": {"security": [], "requestBody": {"content": {"application/json": {"schema": {"properties": {"url": {}}}}}}}},
    },
})
_smodel = parse_web2_surface(_seed_spec, "openapi")
_seeded = _d.seed_candidates_from_surface("seedtest-2026-08-24", _smodel)
check("w2 seed_candidates", len(_seeded) >= 2 and all("vuln_class" in s and "sink" in s for s in _seeded),
      f"{len(_seeded)} seeded")
_reseed = _d.seed_candidates_from_surface("seedtest-2026-08-24", _smodel)
check("w2 seed dedupe", len(_reseed) == 0, f"re-seed={len(_reseed)} (expect 0)")
_filtered = _d.seed_candidates_from_surface("seedfilter-2026-08-24", _smodel, only_sinks=["ssrf"])
check("w2 seed only_sinks", all(s["vuln_class"] == "ssrf" for s in _filtered) and len(_filtered) >= 1,
      f"{len(_filtered)} ssrf-only")

if os.path.exists(_tp):
    os.remove(_tp)

print()
print("RESULT:", "ALL PASS" if FAIL == 0 else f"{FAIL} FAILED")
sys.exit(1 if FAIL else 0)

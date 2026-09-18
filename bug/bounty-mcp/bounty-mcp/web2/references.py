"""
Web2 References Adapter — CVE/CWE/GHSA/OSV/Bugcrowd/ExploitDB/OWASP/CVSS lookups.

Sources (all public, no auth required):
- NVD API v2       https://services.nvd.nist.gov/rest/json/cves/2.0
- MITRE CWE API    https://cwe-api.mitre.org/api/v1/cwe/weakness/{id}
- GitHub Advisory  https://api.github.com/advisories
- OSV API          https://api.osv.dev/v1/query
- Bugcrowd         https://bugcrowd.com/crowdstream.json (public feed)
- HackerOne        https://hackerone.com/graphql (CompleteHacktivityReportIndex, public disclosed)
- Exploit-DB       local /opt/exploitdb/files_exploits.csv (searchsploit)
- OWASP            static mapping (Top 10 / API Top 10 / cheat sheets)
- FIRST CVSS       https://first.org/cvss/calculator/4.0

NOT feasible server-side (no public API / JS-rendered / bot-walled):
- Immunefi (no public API; /graphql redirects)
- PacketStorm (search redirects to TOS / bot protection)

Includes a naive rate limiter (NVD allows ~5 req/30s without an API key),
a tiny in-memory cache, and a markdown References-section formatter.
"""

import csv
import json
import os
import re
import time
import urllib.parse
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Rate limiter + cache
# ---------------------------------------------------------------------------

class RateLimiter:
    """Naive sliding-window rate limiter."""

    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: list[float] = []

    def wait(self):
        now = time.time()
        self._calls = [t for t in self._calls if now - t < self.window]
        if len(self._calls) >= self.max_calls:
            sleep = self.window - (now - self._calls[0]) + 0.2
            if sleep > 0:
                time.sleep(sleep)
        self._calls.append(time.time())


class Cache:
    """Simple TTL cache keyed by string."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._data: dict[str, tuple[float, object]] = {}

    def get(self, key: str):
        hit = self._data.get(key)
        if hit and time.time() - hit[0] < self.ttl:
            return hit[1]
        return None

    def set(self, key: str, value: object):
        self._data[key] = (time.time(), value)


_nvd_limiter = RateLimiter(4, 30.0)   # NVD: 5 req/30s unauthenticated
_ghsa_limiter = RateLimiter(8, 60.0)  # GitHub: 60 req/hr unauth -> be gentle
_cache = Cache(ttl_seconds=6 * 3600)

_HEADERS = {"User-Agent": "web2-references-mcp/1.0 (bug bounty report refs)"}

# ---------------------------------------------------------------------------
# NVD CVE
# ---------------------------------------------------------------------------

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{}"


def _cvss_summary(metrics: dict) -> dict:
    """Pull the highest CVSS version's score + vector from NVD metrics."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "vector": data.get("vectorString"),
            }
    return {}


def search_cve(keywords: str, results_per_page: int = 10) -> dict:
    """Search NVD by keyword. Returns normalized CVE entries with links."""
    key = f"nvd:{keywords}:{results_per_page}"
    cached = _cache.get(key)
    if cached:
        return cached

    _nvd_limiter.wait()
    try:
        resp = requests.get(
            NVD_BASE,
            params={"keywordSearch": keywords, "resultsPerPage": results_per_page},
            headers=_HEADERS,
            timeout=30,
        )
    except requests.RequestException as e:
        return {"error": f"NVD request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"NVD HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwes.append(d["value"])
        results.append({
            "id": cve.get("id"),
            "description": desc[:400],
            "cvss": _cvss_summary(cve.get("metrics", {})),
            "cwes": sorted(set(cwes)),
            "published": cve.get("published"),
            "link": NVD_DETAIL_URL.format(cve.get("id")),
        })

    out = {
        "source": "NVD",
        "total_results": data.get("totalResults", len(results)),
        "query": keywords,
        "results": results[:results_per_page],
    }
    _cache.set(key, out)
    return out


def get_cve(cve_id: str) -> dict:
    """Full CVE detail by ID, including advisory references."""
    key = f"nvd:detail:{cve_id}"
    cached = _cache.get(key)
    if cached:
        return cached

    _nvd_limiter.wait()
    try:
        resp = requests.get(
            NVD_BASE,
            params={"cveId": cve_id},
            headers=_HEADERS,
            timeout=30,
        )
    except requests.RequestException as e:
        return {"error": f"NVD request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"NVD HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {"error": f"{cve_id} not found in NVD", "id": cve_id}

    cve = vulns[0].get("cve", {})
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    refs = [
        {
            "url": r.get("url"),
            "source": r.get("source"),
            "tags": r.get("tags", []),
        }
        for r in cve.get("references", [])
    ]

    out = {
        "id": cve.get("id"),
        "description": desc,
        "cvss": _cvss_summary(cve.get("metrics", {})),
        "cwes": sorted(set(cwes)),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": refs,
        "link": NVD_DETAIL_URL.format(cve.get("id")),
    }
    _cache.set(key, out)
    return out

# ---------------------------------------------------------------------------
# MITRE CWE
# ---------------------------------------------------------------------------

CWE_API = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{}"
CWE_PAGE_URL = "https://cwe.mitre.org/data/definitions/{}.html"


def get_cwe(cwe_id: str) -> dict:
    """Fetch CWE detail by ID (e.g. '79'). Returns name, description, link."""
    if not cwe_id:
        return {"error": "cwe_id required (e.g. '79')"}
    cid = cwe_id.upper().replace("CWE-", "")
    if not cid.isdigit():
        return {"error": f"Invalid CWE id: {cwe_id}"}

    key = f"cwe:{cid}"
    cached = _cache.get(key)
    if cached:
        return cached

    try:
        resp = requests.get(CWE_API.format(cid), headers=_HEADERS, timeout=20)
    except requests.RequestException as e:
        return {"error": f"CWE request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"CWE HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()
    weaknesses = data.get("Weaknesses") or []
    if not weaknesses:
        return {"error": f"CWE-{cid} not found", "id": f"CWE-{cid}"}

    w = weaknesses[0]
    out = {
        "id": f"CWE-{w.get('ID')}",
        "name": w.get("Name"),
        "description": (w.get("Description") or "")[:500],
        "likelihood": w.get("LikelihoodOfExploit"),
        "abstraction": w.get("Abstraction"),
        "link": CWE_PAGE_URL.format(cid),
    }
    _cache.set(key, out)
    return out

# ---------------------------------------------------------------------------
# GitHub Security Advisories (GHSA)
# ---------------------------------------------------------------------------

GHSA_API = "https://api.github.com/advisories"
GHSA_DETAIL_URL = "https://github.com/advisories/{}"


def search_ghsa(query: str, results_per_page: int = 10) -> dict:
    """Search GitHub Advisory Database by keyword."""
    key = f"ghsa:{query}:{results_per_page}"
    cached = _cache.get(key)
    if cached:
        return cached

    _ghsa_limiter.wait()
    try:
        resp = requests.get(
            GHSA_API,
            params={"query": query, "per_page": results_per_page},
            headers={**_HEADERS, "Accept": "application/vnd.github+json"},
            timeout=30,
        )
    except requests.RequestException as e:
        return {"error": f"GHSA request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"GHSA HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()
    if not isinstance(data, list):
        return {"error": "Unexpected GHSA response", "raw": str(data)[:200]}

    results = []
    for a in data:
        results.append({
            "ghsa_id": a.get("ghsa_id"),
            "summary": (a.get("summary") or "")[:300],
            "severity": a.get("severity"),
            "cve_id": a.get("cve_id"),
            "cvss": a.get("cvss"),
            "published": a.get("published_at"),
            "link": GHSA_DETAIL_URL.format(a.get("ghsa_id")),
        })

    out = {"source": "GitHub Advisory DB", "query": query, "results": results}
    _cache.set(key, out)
    return out

# ---------------------------------------------------------------------------
# OSV (Open Source Vulnerabilities)
# ---------------------------------------------------------------------------

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://osv.dev/vulnerability/{}"


def query_osv(package_name: str, ecosystem: str = "npm", results_per_page: int = 10) -> dict:
    """Query OSV by package name + ecosystem. Returns vulnerability ids."""
    key = f"osv:{package_name}:{ecosystem}"
    cached = _cache.get(key)
    if cached:
        return cached

    payload = {"package": {"name": package_name, "ecosystem": ecosystem}}
    try:
        resp = requests.post(
            OSV_QUERY, json=payload, headers=_HEADERS, timeout=30
        )
    except requests.RequestException as e:
        return {"error": f"OSV request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"OSV HTTP {resp.status_code}: {resp.text[:200]}"}

    data = resp.json()
    vulns = data.get("vulns", [])[:results_per_page]
    results = []
    for v in vulns:
        results.append({
            "osv_id": v.get("id"),
            "summary": (v.get("summary") or v.get("details") or "")[:300],
            "aliases": v.get("aliases", []),
            "severity": [s.get("type") for s in v.get("severity", [])],
            "link": OSV_VULN_URL.format(v.get("id")),
        })

    out = {
        "source": "OSV.dev",
        "package": package_name,
        "ecosystem": ecosystem,
        "total_vulns": len(vulns),
        "results": results,
    }
    _cache.set(key, out)
    return out


# ---------------------------------------------------------------------------
# Bugcrowd — Public crowdstream (disclosed bounties feed)
# ---------------------------------------------------------------------------
# Public JSON feed at https://bugcrowd.com/crowdstream.json
# No auth required. Returns recent bounties with program name, amount, target.

_bc_limiter = RateLimiter(6, 60.0)
BC_FEED = "https://bugcrowd.com/crowdstream.json"


def search_bugcrowd(keywords: str = "", results_per_page: int = 10) -> dict:
    """Search Bugcrowd crowdstream by keyword (program name / target url)."""
    key = f"bc:{keywords}:{results_per_page}"
    cached = _cache.get(key)
    if cached:
        return cached

    _bc_limiter.wait()
    try:
        resp = requests.get(
            BC_FEED,
            params={"filter": "disclosures", "sort_by": "disclosed_at"},
            headers=_HEADERS,
            timeout=20,
        )
    except requests.RequestException as e:
        return {"error": f"Bugcrowd request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"Bugcrowd HTTP {resp.status_code}"}

    data = resp.json()
    results = data.get("results", [])
    kw = keywords.lower().strip() if keywords else ""

    filtered = []
    for r in results:
        if kw:
            haystack = " ".join([
                r.get("engagement_name", ""),
                r.get("target", ""),
                r.get("submission_state_text", ""),
            ]).lower()
            if kw not in haystack:
                continue
        filtered.append({
            "program": r.get("engagement_name", "").strip(),
            "target": r.get("target", ""),
            "amount": r.get("amount"),
            "points": r.get("points"),
            "status": r.get("substate"),
            "accepted_at": r.get("accepted_at"),
            "closed_at": r.get("closed_at"),
            "link": f"https://bugcrowd.com{r.get('engagement_path', '')}",
        })

    out = {
        "source": "Bugcrowd Crowdstream",
        "query": keywords or "(all recent)",
        "total_results": len(filtered),
        "results": filtered[:results_per_page],
    }
    _cache.set(key, out)
    return out


# ---------------------------------------------------------------------------
# HackerOne Hacktivity — Public disclosed reports (GraphQL, no auth)
# ---------------------------------------------------------------------------
# The public Hacktivity GraphQL endpoint serves disclosed reports without a
# session cookie. Index: CompleteHacktivityReportIndex. query_string uses H1's
# search DSL, e.g. 'ssrf', 'disclosed:true', 'cwe:"CWE-79"', 'severity:high'.
# Each node exposes cwe, severity_rating, total_awarded_amount, team, and the
# nested report{title,url,substate}. This gives real disclosed-precedent links
# ("this exact bug class was paid on program X") for a bug bounty report.

_h1_limiter = RateLimiter(8, 60.0)
H1_GRAPHQL = "https://hackerone.com/graphql"

_H1_QUERY = (
    "query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) {"
    " search(index: CompleteHacktivityReportIndex, query_string: $queryString, from: $from, size: $size, sort: $sort) {"
    " total_count nodes { ... on HacktivityDocument {"
    " id cwe cve_ids severity_rating total_awarded_amount currency disclosed_at"
    " latest_disclosable_action reporter { username } team { handle name }"
    " report { _id title url substate } } } } }"
)

_H1_HEADERS = {
    "User-Agent": "Mozilla/5.0 (bug bounty report refs)",
    "Accept": "application/json",
    "Content-Type": "application/json",
}


# ---------------------------------------------------------------------------
# H1 weakness taxonomy — the Hacktivity ES index exposes CWE only by its
# weakness NAME (e.g. "Uncontrolled Resource Consumption"), NOT by numeric id.
# `cwe:"CWE-400"` matches nothing; `cwe:"Uncontrolled Resource Consumption"`
# returns the real reports. We ship a cwe-number -> name map (pulled from the
# public H1 `weaknesses` GraphQL) so callers can filter by number or by name.
# ---------------------------------------------------------------------------
_H1_WEAKNESS_MAP_PATH = os.path.join(os.path.dirname(__file__), "h1_weakness_map.json")
_h1_cwe_map: dict | None = None

# Minimal fallback so the tool still resolves the common classes even if the
# JSON map file is missing. Keyed by CWE number -> H1 weakness name.
_H1_CWE_FALLBACK = {
    "400": "Uncontrolled Resource Consumption",
    "89": "SQL Injection",
    "79": "Cross-site Scripting (XSS) - Stored",
    "918": "Server-Side Request Forgery (SSRF)",
    "352": "Cross-Site Request Forgery (CSRF)",
    "78": "OS Command Injection",
    "77": "Command Injection - Generic",
    "94": "Code Injection",
    "22": "Path Traversal",
    "502": "Deserialization of Untrusted Data",
    "611": "XML External Entities (XXE)",
    "287": "Improper Authentication - Generic",
    "639": "Authorization Bypass Through User-Controlled Key",
    "863": "Incorrect Authorization",
    "434": "Unrestricted Upload of File with Dangerous Type",
}


def _load_h1_cwe_map() -> dict:
    global _h1_cwe_map
    if _h1_cwe_map is not None:
        return _h1_cwe_map
    m = {}
    try:
        with open(_H1_WEAKNESS_MAP_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        m = {str(k): v for k, v in (raw.get("cwe") or raw).items()}
    except Exception:
        m = {}
    if not m:
        m = dict(_H1_CWE_FALLBACK)
    _h1_cwe_map = m
    return m


def _resolve_cwe_to_name(val) -> str | None:
    """Accept 400 / '400' / 'CWE-400' / 'cwe-400' / a weakness name, and
    return the H1 weakness NAME to use in a `cwe:"..."` filter. If val is
    already a name (non-numeric), it's passed through unchanged."""
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    mobj = re.match(r"^\s*(?:cwe[-_ ]?)?(\d+)\s*$", s, re.IGNORECASE)
    if mobj:
        num = mobj.group(1)
        return _load_h1_cwe_map().get(num)
    return s  # already a weakness name


_SEV_ALIASES = {"crit": "critical", "critical": "critical", "high": "high",
                "med": "medium", "medium": "medium", "low": "low",
                "info": "none", "none": "none", "informational": "none"}


def _normalize_h1_query(qs: str) -> str:
    """Fix the two common field-syntax mistakes callers make in free-text:
      - `severity:high`  -> `severity_rating:high`  (real ES field name)
      - `cwe:"CWE-400"` / `cwe:CWE-400` / `cwe:400` -> `cwe:"<weakness name>"`
    Anything already correct is left alone."""
    if not qs:
        return qs

    # severity: -> severity_rating: (avoid double-rewriting severity_rating:)
    qs = re.sub(r"(?<![\w])severity\s*:", "severity_rating:", qs, flags=re.IGNORECASE)

    # cwe:<numeric-or-CWE-token> -> cwe:"<name>". Handles quoted + bare tokens.
    def _fix_cwe(mo):
        token = (mo.group("q") or mo.group("b") or "").strip()
        name = _resolve_cwe_to_name(token)
        if name:
            return f'cwe:"{name}"'
        return mo.group(0)  # leave untouched (likely already a name)

    qs = re.sub(
        r'cwe\s*:\s*(?:"(?P<q>[^"]*)"|(?P<b>cwe[-_ ]?\d+|\d+))',
        _fix_cwe, qs, flags=re.IGNORECASE,
    )
    return qs


def search_hackerone(keywords: str = "", results_per_page: int = 10,
                     disclosed_only: bool = True, cwe=None,
                     severity: str = "") -> dict:
    """Search HackerOne Hacktivity (public disclosed reports).

    Three ways to filter, freely combinable:
      - `keywords`: free text ('ssrf') OR H1 field DSL. Common mistakes are
        auto-corrected: `severity:high` -> `severity_rating:high`, and any
        `cwe:400` / `cwe:"CWE-400"` token -> `cwe:"<weakness name>"` (the ES
        index only matches CWE by NAME, not by number).
      - `cwe`: dedicated arg. Accepts 400 / '400' / 'CWE-400' / a weakness
        name. Resolved to the H1 weakness name and ANDed into the query.
      - `severity`: dedicated arg. critical|high|medium|low|none -> ANDed as
        `severity_rating:<level>`.
    Empty query = latest disclosed. Returns disclosed reports with CWE,
    severity, awarded amount, program handle, and public URL — real-world
    precedent for a bug bounty report's References section.
    """
    parts = []
    qs_kw = _normalize_h1_query((keywords or "").strip())
    if qs_kw:
        parts.append(qs_kw)

    cwe_name = _resolve_cwe_to_name(cwe)
    if cwe_name:
        parts.append(f'cwe:"{cwe_name}"')

    sev = _SEV_ALIASES.get((severity or "").strip().lower())
    if sev:
        parts.append(f"severity_rating:{sev}")

    # H1 ES: space between clauses = OR, so AND them explicitly to narrow.
    qs = " AND ".join(p for p in parts if p)

    if disclosed_only and "disclosed:" not in qs:
        qs = (f"{qs} AND disclosed:true" if qs else "disclosed:true")
    key = f"h1:{qs}:{results_per_page}"
    cached = _cache.get(key)
    if cached:
        return cached

    _h1_limiter.wait()
    payload = {
        "operationName": "HacktivitySearchQuery",
        "variables": {
            "queryString": qs,
            "size": max(1, min(int(results_per_page), 100)),
            "from": 0,
            "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"},
        },
        "query": _H1_QUERY,
    }
    try:
        resp = requests.post(H1_GRAPHQL, headers=_H1_HEADERS, json=payload, timeout=25)
    except requests.RequestException as e:
        return {"error": f"HackerOne request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"HackerOne HTTP {resp.status_code}"}

    try:
        data = resp.json()
    except ValueError:
        return {"error": "HackerOne: non-JSON response (bot wall?)"}

    if data.get("errors"):
        return {"error": f"HackerOne GraphQL error: {data['errors'][0].get('message', 'unknown')}"}

    search = (data.get("data") or {}).get("search") or {}
    nodes = search.get("nodes") or []
    results = []
    for n in nodes:
        rep = n.get("report") or {}
        team = n.get("team") or {}
        reporter = n.get("reporter") or {}
        url = rep.get("url")
        if not url and rep.get("_id"):
            url = f"https://hackerone.com/reports/{rep['_id']}"
        results.append({
            "title": rep.get("title"),
            "url": url,
            "cwe": n.get("cwe"),
            "cve_ids": n.get("cve_ids"),
            "severity": n.get("severity_rating"),
            "awarded_amount": n.get("total_awarded_amount"),
            "currency": n.get("currency"),
            "program": team.get("handle"),
            "program_name": team.get("name"),
            "reporter": reporter.get("username"),
            "substate": rep.get("substate"),
            "disclosed_at": n.get("disclosed_at"),
        })

    out = {
        "source": "HackerOne Hacktivity",
        "query": qs or "(latest disclosed)",
        "total_results": search.get("total_count", len(results)),
        "results": results[:results_per_page],
    }
    _cache.set(key, out)
    return out


# ---------------------------------------------------------------------------
# Exploit-DB — Local CSV (searchsploit DB at /opt/exploitdb/)
# ---------------------------------------------------------------------------
# Uses /opt/exploitdb/files_exploits.csv (47K+ entries). Cached on first load.
# Fallback to searchsploit --json subprocess if CSV missing.

EXPLOITDB_CSV = "/opt/exploitdb/files_exploits.csv"

EXPLOITDB_DIR = "/opt/exploitdb"
EXPLOITDB_MAX_READ = 128 * 1024


def _exploitdb_abs_path(rel: str) -> str:
    if not rel:
        return ""
    rel = rel.replace("\\", "/").lstrip("/")
    full = os.path.abspath(os.path.join(EXPLOITDB_DIR, rel))
    root = os.path.abspath(EXPLOITDB_DIR)
    if not full.startswith(root + os.sep):
        return ""
    return full


def read_exploit_file(edb_id: str, max_chars: int = 60000) -> dict:
    key = f"edbread:{edb_id}:{max_chars}"
    cached = _cache.get(key)
    if cached:
        return cached
    edb_id = str(edb_id).strip()
    if not edb_id:
        return {"error": "edb_id required"}
    rows = _load_exploitdb()
    row = None
    for r in rows:
        if str(r.get("id", "")).strip() == edb_id:
            row = r
            break
    if row is None:
        out = {"error": f"EDB-ID {edb_id} not found in local exploitdb", "edb_id": edb_id}
        _cache.set(key, out)
        return out
    rel = row.get("file", "")
    path = _exploitdb_abs_path(rel)
    if not path or not os.path.isfile(path):
        out = {"error": f"exploit file not found on disk for EDB-{edb_id}", "edb_id": edb_id}
        _cache.set(key, out)
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(EXPLOITDB_MAX_READ)
    except Exception as e:
        return {"error": f"read failed: {e}", "edb_id": edb_id}
    truncated = len(content) >= EXPLOITDB_MAX_READ
    if max_chars and len(content) > max_chars:
        content = content[:max_chars]
        truncated = True
    out = {
        "edb_id": edb_id,
        "title": (row.get("description", "").strip('"') or "")[:300],
        "type": row.get("type", ""),
        "platform": row.get("platform", ""),
        "verified": row.get("verified", "0") == "1",
        "cve_ids": [c.strip() for c in row.get("codes", "").split(";") if c.startswith("CVE-")],
        "path": path,
        "file_size": os.path.getsize(path),
        "truncated": truncated,
        "content": content,
    }
    _cache.set(key, out)
    return out


_exploitdb_cache: list[dict] | None = None


def _load_exploitdb():
    global _exploitdb_cache
    if _exploitdb_cache is not None:
        return _exploitdb_cache
    if not os.path.isfile(EXPLOITDB_CSV):
        _exploitdb_cache = []  # fallback: try searchsploit per-call
        return _exploitdb_cache
    rows = []
    try:
        with open(EXPLOITDB_CSV, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except Exception:
        return []
    _exploitdb_cache = rows
    return rows


def search_exploitdb(
    keywords: str,
    results_per_page: int = 10,
    platform: str = "",
    exploit_type: str = "",
) -> dict:
    """Search local Exploit-DB CSV by keyword. Returns EDB-ID, title, type, link."""
    key = f"edb:{keywords}:{platform}:{exploit_type}:{results_per_page}"
    cached = _cache.get(key)
    if cached:
        return cached

    rows = _load_exploitdb()
    kw = keywords.lower().strip() if keywords else ""
    plat = platform.lower().strip() if platform else ""
    etype = exploit_type.lower().strip() if exploit_type else ""

    results = []
    hits = 0
    for r in rows:
        desc = r.get("description", "")
        codes = r.get("codes", "")
        tags = r.get("tags", "")
        app = r.get("application_url", "")
        haystack = f"{desc} {codes} {tags} {app}".lower()

        if kw and kw not in haystack:
            continue
        if plat:
            rp = r.get("platform", "").lower()
            if plat not in rp:
                continue
        if etype:
            rt = r.get("type", "").lower()
            if etype not in rt:
                continue

        hits += 1
        if hits > results_per_page:
            break

        edb_id = r.get("id", "")
        rel = r.get("file", "")
        results.append({
            "edb_id": edb_id,
            "title": (desc.strip('"') if desc else "")[:300],
            "type": r.get("type", ""),
            "platform": r.get("platform", ""),
            "date_published": r.get("date_published", ""),
            "verified": r.get("verified", "0") == "1",
            "cve_ids": [c.strip() for c in codes.split(";") if c.startswith("CVE-")],
            "link": f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else "",
            "source_url": r.get("source_url", ""),
            "file_path": _exploitdb_abs_path(rel),
        })

    # Fallback to searchsploit if CSV empty/not found
    if not results and keywords:
        try:
            import subprocess
            sp = subprocess.run(
                ["searchsploit", "--json", keywords],
                capture_output=True, text=True, timeout=15,
            )
            if sp.returncode == 0:
                data = json.loads(sp.stdout)
                for r in data.get("RESULTS_EXPLOIT", [])[:results_per_page]:
                    sp_path = r.get("Path", "")
                    results.append({
                        "edb_id": r.get("EDB-ID"),
                        "title": r.get("Title", ""),
                        "type": r.get("Type", ""),
                        "platform": r.get("Platform", ""),
                        "date_published": r.get("Date_Published", ""),
                        "verified": r.get("Verified", "0") == "1",
                        "cve_ids": [c.strip() for c in r.get("Codes", "").split(";") if c.startswith("CVE-")],
                        "link": f"https://www.exploit-db.com/exploits/{r.get('EDB-ID', '')}",
                        "source_url": r.get("Source", ""),
                        "file_path": sp_path if sp_path.startswith(EXPLOITDB_DIR) else _exploitdb_abs_path(sp_path),
                    })
        except Exception:
            pass

    out = {
        "source": "Exploit-DB",
        "query": keywords,
        "total_results": len(results),
        "results": results[:results_per_page],
    }
    _cache.set(key, out)
    return out


# ---------------------------------------------------------------------------
# OWASP — Static reference links (cheat sheets + API Security Top 10)
# ---------------------------------------------------------------------------

_OWASP_CHEAT_SHEET = "https://cheatsheetseries.owasp.org/cheatsheets/{}.html"
_OWASP_API_TOP10 = "https://owasp.org/API-Security/editions/2023/en/{}.html"
_OWASP_TOP10 = "https://owasp.org/Top10/{}/"

# keyword -> (owasp_top10_anchor, api_top10_anchor, cheat_sheet)
_OWASP_MAP = [
    ("xss", None, None, "Cross_Site_Scripting_Prevention_Cheat_Sheet"),
    ("sql injection", "A03_2021-Injection", None, "SQL_Injection_Prevention_Cheat_Sheet"),
    ("sqli", "A03_2021-Injection", None, "SQL_Injection_Prevention_Cheat_Sheet"),
    ("idor", "A01_2021-Broken_Access_Control", "0x11-t10", "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet"),
    ("bola", "A01_2021-Broken_Access_Control", "0x11-t10", "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet"),
    ("ssrf", "A10_2021-Server-Side_Request_Forgery", "0x11-t16", "Server_Side_Request_Forgery_Prevention_Cheat_Sheet"),
    ("csrf", None, None, "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet"),
    ("xxe", "A05_2021-Security_Misconfiguration", None, "XML_External_Entity_Prevention_Cheat_Sheet"),
    ("rce", "A03_2021-Injection", None, "OS_Command_Injection_Defense_Cheat_Sheet"),
    ("command injection", "A03_2021-Injection", None, "OS_Command_Injection_Defense_Cheat_Sheet"),
    ("ssti", "A03_2021-Injection", None, None),
    ("path traversal", "A01_2021-Broken_Access_Control", None, "Input_Validation_Cheat_Sheet"),
    ("lfi", "A01_2021-Broken_Access_Control", None, "Input_Validation_Cheat_Sheet"),
    ("deserialization", None, None, "Deserialization_Cheat_Sheet"),
    ("open redirect", None, None, "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"),
    ("clickjacking", None, None, "Clickjacking_Defense_Cheat_Sheet"),
    ("jwt", "A07_2021-Identification_and_Authentication_Failures", "0x11-t11", "JSON_Web_Token_Cheat_Sheet"),
    ("auth bypass", "A07_2021-Identification_and_Authentication_Failures", "0x11-t11", "Authentication_Cheat_Sheet"),
    ("authn", "A07_2021-Identification_and_Authentication_Failures", "0x11-t11", "Authentication_Cheat_Sheet"),
    ("authz", "A01_2021-Broken_Access_Control", "0x11-t14", "Authorization_Cheat_Sheet"),
    ("access control", "A01_2021-Broken_Access_Control", "0x11-t14", "Authorization_Cheat_Sheet"),
    ("crypto", "A02_2021-Cryptographic_Failures", None, "Cryptographic_Storage_Cheat_Sheet"),
    ("information disclosure", "A05_2021-Security_Misconfiguration", None, None),
    ("info disclosure", "A05_2021-Security_Misconfiguration", None, None),
    ("rate limit", "A04_2021-Insecure_Design", "0x11-t13", "Denial_of_Service_Cheat_Sheet"),
    ("race condition", "A04_2021-Insecure_Design", None, None),
    ("supply chain", "A06_2021-Vulnerable_and_Outdated_Components", None, None),
    ("hardcoded credentials", "A07_2021-Identification_and_Authentication_Failures", None, None),
    ("cors", "A05_2021-Security_Misconfiguration", None, "Cross-Origin_Resource_Sharing_Cheat_Sheet"),
    ("logging", "A09_2021-Security_Logging_and_Monitoring_Failures", "0x11-t17", None),
    ("injection", "A03_2021-Injection", "0x11-t18", "Input_Validation_Cheat_Sheet"),
    ("security misconfiguration", "A05_2021-Security_Misconfiguration", "0x11-t17", None),
]


def get_owasp(keywords: str) -> dict:
    """Return OWASP reference links relevant to keywords (static mapping)."""
    kw = keywords.lower()
    results = []
    seen = set()

    for match_kw, top10, api_top10, cs in _OWASP_MAP:
        if match_kw in kw:
            if top10 and top10 not in seen:
                seen.add(top10)
                results.append({
                    "type": "OWASP Top 10 (2021)",
                    "title": top10.replace("_", " ").title(),
                    "link": _OWASP_TOP10.format(top10),
                })
            if api_top10 and api_top10 not in seen:
                seen.add(api_top10)
                results.append({
                    "type": "OWASP API Security Top 10 (2023)",
                    "title": f"API Security Top 10 — {api_top10}",
                    "link": _OWASP_API_TOP10.format(api_top10),
                })
            if cs and cs not in seen:
                seen.add(cs)
                results.append({
                    "type": "OWASP Cheat Sheet",
                    "title": cs.replace("_", " ").replace("Cheat Sheet", "Cheat Sheet"),
                    "link": _OWASP_CHEAT_SHEET.format(cs),
                })

    if not results:
        results.append({
            "type": "OWASP Top 10 (2021)",
            "title": "A00 Overview",
            "link": _OWASP_TOP10.format("A00_2021-Overview"),
        })

    return {
        "source": "OWASP",
        "query": keywords,
        "results": results,
    }


# ---------------------------------------------------------------------------
# CVSS calculator URL

def cvss_calculator_url(vector: str) -> dict:
    """Build a FIRST CVSS calculator URL from a vector string.

    Accepts CVSS v2 ('AV:N/AC:L/...'), v3.x ('CVSS:3.1/AV:N/...'),
    and v4.0 ('CVSS:4.0/AV:N/...'). Guesses the version from the vector.
    """
    if not vector:
        return {"error": "vector required"}

    v = vector.strip()
    # v4 / v3 with explicit prefix
    if v.upper().startswith("CVSS:4.0"):
        url = "https://first.org/cvss/calculator/4.0#" + v
        version = "4.0"
    elif v.upper().startswith("CVSS:3.1"):
        url = "https://first.org/cvss/calculator/3.1#" + v
        version = "3.1"
    elif v.upper().startswith("CVSS:3.0"):
        url = "https://first.org/cvss/calculator/3.0#" + v
        version = "3.0"
    elif "Au:" in v or v.upper().startswith("CVSS:2"):
        # v2 has no CVSS: prefix in NVD; starts with AV:, has Au: (Authentication)
        url = "https://first.org/cvss/calculator/2.0#" + v
        version = "2.0"
    else:
        # assume v3.1 (most common in modern NVD entries)
        url = "https://first.org/cvss/calculator/3.1#CVSS:3.1/" + v.lstrip("/")
        version = "3.1"

    return {"version": version, "vector": vector, "calculator_url": url}

# ---------------------------------------------------------------------------
# CVSS auto-suggest from candidate impact properties
# ---------------------------------------------------------------------------

# Impact-class presets. Each maps a coarse finding class to the CIA/impact
# metric legs that class typically carries. Access-vector legs (AV/AC/PR/UI)
# come from the caller-supplied exposure properties, not the class.
_CVSS_IMPACT_PRESETS = {
    # class            v3.1 (C,I,A)      v4.0 (VC,VI,VA)
    "rce":            {"v3": ("H", "H", "H"), "v4": ("H", "H", "H")},
    "sqli":           {"v3": ("H", "H", "L"), "v4": ("H", "H", "L")},
    "auth_bypass":    {"v3": ("H", "H", "N"), "v4": ("H", "H", "N")},
    "account_takeover": {"v3": ("H", "H", "N"), "v4": ("H", "H", "N")},
    "idor":           {"v3": ("H", "N", "N"), "v4": ("H", "N", "N")},
    "bola":           {"v3": ("H", "N", "N"), "v4": ("H", "N", "N")},
    "idor_write":     {"v3": ("H", "H", "N"), "v4": ("H", "H", "N")},
    "ssrf":           {"v3": ("H", "L", "N"), "v4": ("H", "L", "N")},
    "xxe":            {"v3": ("H", "N", "L"), "v4": ("H", "N", "L")},
    "info_disclosure": {"v3": ("H", "N", "N"), "v4": ("H", "N", "N")},
    "stored_xss":     {"v3": ("L", "L", "N"), "v4": ("L", "L", "N")},
    "reflected_xss":  {"v3": ("L", "L", "N"), "v4": ("L", "L", "N")},
    "xss":            {"v3": ("L", "L", "N"), "v4": ("L", "L", "N")},
    "csrf":           {"v3": ("N", "H", "N"), "v4": ("N", "H", "N")},
    "path_traversal": {"v3": ("H", "N", "N"), "v4": ("H", "N", "N")},
    "command_injection": {"v3": ("H", "H", "H"), "v4": ("H", "H", "H")},
    "deserialization": {"v3": ("H", "H", "H"), "v4": ("H", "H", "H")},
    "ssti":           {"v3": ("H", "H", "H"), "v4": ("H", "H", "H")},
    "open_redirect":  {"v3": ("N", "L", "N"), "v4": ("N", "L", "N")},
    "dos":            {"v3": ("N", "N", "H"), "v4": ("N", "N", "H")},
    "business_logic": {"v3": ("N", "H", "N"), "v4": ("N", "H", "N")},
    "mass_assignment": {"v3": ("H", "H", "N"), "v4": ("H", "H", "N")},
    "privilege_escalation": {"v3": ("H", "H", "N"), "v4": ("H", "H", "N")},
}


def suggest_cvss(
    impact_class: str,
    attacker_control: str = "network",   # network | adjacent | local | physical
    complexity: str = "low",             # low | high
    privileges: str = "none",            # none | low | high
    user_interaction: str = "none",      # none | required (v4: none|passive|active)
    scope_changed: bool = False,         # v3.1 scope; maps to v4 subsequent-system impact
    version: str = "both",               # 3.1 | 4.0 | both
) -> dict:
    """Suggest a CVSS vector + computed base score from a finding's impact class
    and exposure properties. Supports CVSS v3.1 and v4.0 (default: both).

    impact_class picks the C/I/A (VC/VI/VA) impact legs from a preset table
    (rce, sqli, idor, bola, ssrf, xss, csrf, auth_bypass, account_takeover,
    info_disclosure, path_traversal, command_injection, ssti, dos,
    business_logic, mass_assignment, privilege_escalation, ...). The AV/AC/PR/UI
    legs come from the exposure args. Returns per-version {vector, score,
    severity, calculator_url}. Scores computed with the `cvss` library when
    available; otherwise vector-only with a calculator link.
    """
    cls = (impact_class or "").lower().strip().replace("-", "_").replace(" ", "_")
    preset = _CVSS_IMPACT_PRESETS.get(cls)
    if not preset:
        return {
            "error": f"unknown impact_class '{impact_class}'",
            "known_classes": sorted(_CVSS_IMPACT_PRESETS.keys()),
        }

    av_map = {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}
    ac = "L" if str(complexity).lower().startswith("l") else "H"
    pr_map = {"none": "N", "low": "L", "high": "H"}
    av = av_map.get(str(attacker_control).lower(), "N")
    pr = pr_map.get(str(privileges).lower(), "N")

    out: dict = {"impact_class": cls, "inputs": {
        "attacker_control": attacker_control, "complexity": complexity,
        "privileges": privileges, "user_interaction": user_interaction,
        "scope_changed": scope_changed,
    }}

    try:
        from cvss import CVSS3, CVSS4
        have_lib = True
    except Exception:
        have_lib = False

    want_31 = version in ("3.1", "both")
    want_40 = version in ("4.0", "both")

    # ---- v3.1 ----
    if want_31:
        c, i, a = preset["v3"]
        ui31 = "N" if str(user_interaction).lower() == "none" else "R"
        s = "C" if scope_changed else "U"
        vec31 = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui31}/S:{s}/C:{c}/I:{i}/A:{a}"
        entry = {"vector": vec31,
                 "calculator_url": f"https://www.first.org/cvss/calculator/3.1#{vec31}"}
        if have_lib:
            try:
                obj = CVSS3(vec31)
                entry["score"] = float(obj.base_score)
                entry["severity"] = obj.severities()[0]
            except Exception as e:
                entry["warning"] = f"score calc failed: {e}"
        out["v3.1"] = entry

    # ---- v4.0 ----
    if want_40:
        vc, vi, va = preset["v4"]
        at = "N"  # attack requirements: none (no special conditions) by default
        ui40 = "N" if str(user_interaction).lower() == "none" else (
            "P" if str(user_interaction).lower() == "passive" else "A")
        # subsequent-system impact: mirror scope_changed -> low subsequent impact
        sc = si = sa = "L" if scope_changed else "N"
        vec40 = (f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui40}"
                 f"/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}")
        entry = {"vector": vec40,
                 "calculator_url": f"https://www.first.org/cvss/calculator/4.0#{vec40}"}
        if have_lib:
            try:
                obj = CVSS4(vec40)
                entry["score"] = float(obj.base_score)
                entry["severity"] = obj.severity
            except Exception as e:
                entry["warning"] = f"score calc failed: {e}"
        out["v4.0"] = entry

    if not have_lib:
        out["note"] = "cvss library not installed — vectors + calculator links only, no computed score"

    return out

# ---------------------------------------------------------------------------
# Combined References-section builder
# ---------------------------------------------------------------------------

COMMON_CWE_MAP = {
    "XSS": "79", "SQL injection": "89", "SQLi": "89", "IDOR": "639",
    "BOLA": "639", "CSRF": "352", "SSRF": "918", "XXE": "611",
    "path traversal": "22", "LFI": "22", "RCE": "94", "command injection": "78",
    "deserialization": "502", "SSTI": "1336", "open redirect": "601",
    "auth bypass": "287", "privilege escalation": "269", "info disclosure": "200",
    "information disclosure": "200", "hardcoded credentials": "798",
    "weak password": "521", "race condition": "362", "prototype pollution": "1321",
    "HTTP request smuggling": "444", "clickjacking": "1021", "CORS": "942",
    "JWT": "347", "reentrancy": "841", "access control": "862",
}


def _norm_cwe(cid: str) -> str | None:
    """Normalize CWE ID to numeric form (e.g. 'CWE-639' -> '639', '79' -> '79')."""
    c = str(cid).upper().strip().replace("CWE-", "")
    return c if c.isdigit() else None


def _pick_cwe_ids(keywords: str) -> list[str]:
    """Heuristic CWE-ID pick from a keyword phrase + common vuln names."""
    kw = keywords.lower()
    hits = []
    for label, cwe in COMMON_CWE_MAP.items():
        if label.lower() in kw:
            hits.append(cwe)
    # include CWE-xxx patterns typed directly in keywords
    hits += re.findall(r"CWE-(\d{2,4})", keywords)
    return list(dict.fromkeys(hits))  # dedupe, keep order


def build_references(
    keywords: str,
    include_cve: bool = True,
    include_cwe: bool = True,
    include_ghsa: bool = False,
    include_bugcrowd: bool = False,
    include_hackerone: bool = False,
    include_exploitdb: bool = False,
    include_owasp: bool = True,
    max_cve: int = 5,
    cve_ids: Optional[list] = None,
) -> dict:
    """Assemble a ready-to-paste markdown References section.

    Steps:
      1. If cve_ids given -> fetch each via get_cve. Else search NVD by keywords.
      2. Collect CWE ids from the CVEs (plus heuristic match on keywords).
      3. Fetch CWE details from MITRE.
      4. Optional GHSA search.
      5. Optional Bugcrowd crowdstream search.
      6. Optional Exploit-DB search (local CSV).
      7. Optional OWASP links (static mapping).
      8. Build CVSS calculator links for every CVE vector.
    Returns {"references_markdown": ..., "entries": [...], "warnings": [...]}.
    """
    warnings: list[str] = []
    entries: list[dict] = []

    # 1. CVE layer
    if include_cve:
        if cve_ids:
            cves = []
            for cid in cve_ids:
                r = get_cve(cid)
                if "error" not in r:
                    cves.append(r)
                else:
                    warnings.append(r["error"])
        else:
            r = search_cve(keywords, results_per_page=max_cve)
            if "error" in r:
                warnings.append(r["error"])
                cves = []
            else:
                cves = r.get("results", [])
                if not cves:
                    warnings.append("NVD returned 0 results")

        for cve in cves:
            cvss = cve.get("cvss", {})
            entry = {
                "type": "CVE",
                "id": cve.get("id"),
                "title": cve.get("description", "")[:200],
                "link": cve.get("link"),
            }
            if cvss.get("vector"):
                entry["cvss"] = cvss_calculator_url(cvss["vector"])
            entries.append(entry)
    else:
        cves = []

    # 2. CWE layer
    if include_cwe:
        raw_cwe_ids = _pick_cwe_ids(keywords) + [
            c for cve in cves for c in cve.get("cwes", [])
        ]
        cwe_ids = list(dict.fromkeys(
            c for c in (_norm_cwe(c) for c in raw_cwe_ids) if c
        ))[:8]
        for cid in cwe_ids:
            r = get_cwe(cid)
            if "error" not in r:
                entries.append({
                    "type": "CWE",
                    "id": r["id"],
                    "title": r["name"],
                    "link": r["link"],
                })
            else:
                warnings.append(r["error"])

    # 3. GHSA layer (optional)
    if include_ghsa:
        r = search_ghsa(keywords)
        if "error" in r:
            warnings.append(r["error"])
        else:
            for g in r.get("results", [])[:5]:
                entries.append({
                    "type": "GHSA",
                    "id": g.get("ghsa_id"),
                    "title": g.get("summary", "")[:150],
                    "link": g.get("link"),
                })

    # 4. Bugcrowd layer (optional)
    if include_bugcrowd:
        r = search_bugcrowd(keywords, results_per_page=5)
        if "error" in r:
            warnings.append(r["error"])
        else:
            for b in r.get("results", [])[:5]:
                entries.append({
                    "type": "Bugcrowd",
                    "id": b.get("program", "Bugcrowd"),
                    "title": f"{b.get('amount', '')} accepted — {b.get('target', '')}"[:150],
                    "link": b.get("link", "https://bugcrowd.com"),
                })

    # 5. HackerOne Hacktivity layer (optional — real disclosed precedent)
    if include_hackerone:
        r = search_hackerone(keywords, results_per_page=5)
        if "error" in r:
            warnings.append(r["error"])
        else:
            for h in r.get("results", [])[:5]:
                amt = h.get("awarded_amount")
                sev = h.get("severity") or ""
                prog = h.get("program") or ""
                meta = " ".join(x for x in [sev, f"${amt}" if amt else "", f"@{prog}" if prog else ""] if x)
                entries.append({
                    "type": "HackerOne",
                    "id": h.get("cwe") or "H1 report",
                    "title": f"{h.get('title', '')} ({meta})"[:180],
                    "link": h.get("url", "https://hackerone.com/hacktivity"),
                })

    # 6. Exploit-DB layer (optional)
    if include_exploitdb:
        r = search_exploitdb(keywords, results_per_page=5)
        if "error" in r:
            warnings.append(r["error"])
        else:
            for x in r.get("results", [])[:5]:
                entries.append({
                    "type": "ExploitDB",
                    "id": x.get("edb_id", ""),
                    "title": x.get("title", "")[:150],
                    "link": x.get("link", ""),
                })

    # 6. OWASP layer (optional, static + fast)
    if include_owasp:
        r = get_owasp(keywords)
        for o in r.get("results", []):
            entries.append({
                "type": "OWASP",
                "id": o.get("title", ""),
                "title": o.get("type", ""),
                "link": o.get("link", ""),
            })

    # 7. Format markdown
    lines = ["## References", ""]
    for e in entries:
        t = e["type"]
        title = e.get("title") or ""
        if t == "CVE":
            lines.append(f"- [{e['id']}]({e['link']}) — {title}")
            if e.get("cvss"):
                lines.append(f"  - CVSS {e['cvss']['version']}: [calculator]({e['cvss']['calculator_url']})")
        elif t == "OWASP":
            lines.append(f"- [{e['id']}]({e['link']}) — {title}")
        else:
            lines.append(f"- [{e['id']}]({e['link']}) — {title}")
    lines.append("")

    return {
        "references_markdown": "\n".join(lines),
        "entries": entries,
        "warnings": warnings,
    }

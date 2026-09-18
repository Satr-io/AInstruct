"""
Web2 Attack Surface Model — sibling to the web3 attack_surface.py.

Parses a web2/API target description into a generic attack-surface model
(the web2 analogue of the Solidity surface the main bounty-mcp builds).

Accepts, in priority order (auto-detected):
- OpenAPI / Swagger spec  (JSON or YAML, file path OR http(s) URL)
- Postman collection v2.x  (JSON)
- HAR capture             (.har JSON, browser/Burp export)
- Raw endpoint list        (newline-separated "METHOD /path" or bare URLs)

Output model (mirrors the web3 surface shape):
{
  source, source_type, parser,
  endpoint_count,
  endpoints: [{
     method, path, base_url,
     params: {path:[], query:[], header:[], body:[], cookie:[]},
     auth: {required: bool, schemes: [...]},
     consumes, produces,
     potential_sinks: [...],      # heuristic vuln-class hints per endpoint
     state_mutating: bool,        # non-GET/HEAD/OPTIONS
     trust_boundary: "public" | "authenticated" | "unknown",
     operation_id, summary
  }],
  summary: {
     total, state_mutating, unauthenticated_state_mutating,
     auth_required, no_auth, by_method{}, distinct_params,
     sink_hits{sink: count}
  },
  auth_schemes: [...],   # global security schemes declared
  servers: [...]
}

No network needed except when given an http(s) URL for the spec.
Pure stdlib + PyYAML (already in the Hermes venv).
"""

import json
import os
import re
import urllib.parse
from typing import Optional

try:
    import yaml  # PyYAML, present in Hermes venv
except Exception:  # pragma: no cover
    yaml = None

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


# ---------------------------------------------------------------------------
# Heuristic sink map: param-name / path token -> likely vuln class to probe.
# These are HINTS for hypothesis generation, NOT findings. Mirror the web3
# "oracle_dependencies / token_transfers" hinting idea.
# ---------------------------------------------------------------------------

_SINK_HINTS = [
    # (regex over param/path token, sink label)
    (r"\b(id|uid|user_?id|account_?id|order_?id|obj|object_?id|doc_?id|file_?id|pid|gid|num|no)\b", "IDOR/BOLA"),
    (r"\b(url|uri|link|redirect|next|return|callback|dest|target|domain|host|feed|webhook|proxy|fetch|image_?url|img)\b", "SSRF/open-redirect"),
    (r"\b(q|query|search|filter|sort|order_?by|where|id|name|email|username)\b", "SQLi/NoSQLi"),
    (r"\b(file|path|dir|folder|template|page|include|doc|download|attachment|name)\b", "path-traversal/LFI"),
    (r"\b(cmd|command|exec|run|ping|host|ip|domain|dns|action)\b", "command-injection"),
    (r"\b(html|body|content|message|comment|desc|description|title|text|bio|note|template)\b", "XSS/SSTI"),
    (r"\b(role|is_?admin|admin|priv|permission|scope|group|access|level|type|status|verified|active)\b", "mass-assignment/privesc"),
    (r"\b(token|jwt|auth|session|key|secret|password|otp|code|signature|hmac)\b", "auth/token-abuse"),
    (r"\b(amount|price|qty|quantity|total|balance|cost|discount|coupon|fee|limit|count|page|size|offset)\b", "business-logic/param-tampering"),
    (r"\b(xml|soap|svg|xsl|dtd)\b", "XXE"),
    (r"\b(file|upload|avatar|attachment|import|document)\b", "file-upload"),
]

_STATE_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _sink_hints_for(tokens: list[str]) -> list[str]:
    """Return distinct sink labels whose pattern matches any token."""
    joined = " ".join(t.lower() for t in tokens if t)
    hits = []
    for pat, label in _SINK_HINTS:
        if re.search(pat, joined):
            hits.append(label)
    return list(dict.fromkeys(hits))


# ---------------------------------------------------------------------------
# Loader — string / file / URL -> parsed object + detected type
# ---------------------------------------------------------------------------

def _load_raw(source: str) -> tuple[str, str]:
    """Return (raw_text, origin) where origin is 'url'|'file'|'inline'."""
    s = source.strip()
    if s.startswith("http://") or s.startswith("https://"):
        if requests is None:
            raise RuntimeError("requests unavailable; cannot fetch spec URL")
        r = requests.get(s, timeout=25, headers={"User-Agent": "web2-surface/1.0"})
        r.raise_for_status()
        return r.text, "url"
    if os.path.isfile(s):
        with open(s, "r", encoding="utf-8", errors="replace") as f:
            return f.read(), "file"
    # treat as inline content (raw endpoint list or inline spec)
    return source, "inline"


def _try_parse_structured(raw: str) -> Optional[dict]:
    """Parse JSON, then YAML. Return dict/list or None."""
    raw = raw.strip()
    if not raw:
        return None
    # JSON first
    try:
        return json.loads(raw)
    except Exception:
        pass
    if yaml is not None:
        try:
            obj = yaml.safe_load(raw)
            if isinstance(obj, (dict, list)):
                return obj
        except Exception:
            pass
    return None


def _detect_type(obj) -> str:
    if isinstance(obj, dict):
        if "openapi" in obj or "swagger" in obj:
            return "openapi"
        if isinstance(obj.get("info"), dict) and "item" in obj:
            return "postman"
        if isinstance(obj.get("log"), dict) and "entries" in obj["log"]:
            return "har"
    return "unknown"


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------

def _openapi_param_bucket(p: dict) -> str:
    loc = (p.get("in") or "").lower()
    return {"path": "path", "query": "query", "header": "header",
            "cookie": "cookie"}.get(loc, "query")


def _parse_openapi(spec: dict) -> dict:
    is_v3 = "openapi" in spec
    servers = []
    if is_v3:
        servers = [s.get("url", "") for s in spec.get("servers", []) if isinstance(s, dict)]
    else:  # swagger 2.0
        host = spec.get("host", "")
        base = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        if host:
            servers = [f"{schemes[0]}://{host}{base}"]

    # global security schemes
    if is_v3:
        sec_schemes = list((spec.get("components", {}) or {}).get("securitySchemes", {}).keys())
    else:
        sec_schemes = list((spec.get("securityDefinitions", {}) or {}).keys())
    global_security = bool(spec.get("security"))

    endpoints = []
    paths = spec.get("paths", {}) or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", []) or []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            params = {"path": [], "query": [], "header": [], "body": [], "cookie": []}
            all_params = list(shared_params) + list(op.get("parameters", []) or [])
            for p in all_params:
                if not isinstance(p, dict):
                    continue
                name = p.get("name")
                if not name:
                    continue
                if (p.get("in") or "").lower() == "body":
                    # swagger 2.0 body param — expand schema props if present
                    schema = p.get("schema", {}) or {}
                    props = list((schema.get("properties", {}) or {}).keys())
                    params["body"].extend(props or [name])
                else:
                    params[_openapi_param_bucket(p)].append(name)
            # openapi 3 requestBody
            rb = op.get("requestBody", {}) or {}
            content = rb.get("content", {}) or {}
            for _mt, mdef in content.items():
                schema = (mdef or {}).get("schema", {}) or {}
                props = list((schema.get("properties", {}) or {}).keys())
                params["body"].extend(props)
            for k in params:
                params[k] = list(dict.fromkeys(params[k]))

            # auth: op-level security overrides global; [] means explicitly public
            op_security = op.get("security", None)
            if op_security is not None:
                auth_required = len(op_security) > 0
                schemes = [list(s.keys())[0] for s in op_security if isinstance(s, dict) and s]
            else:
                auth_required = global_security
                schemes = sec_schemes if global_security else []

            path_tokens = re.findall(r"\{(\w+)\}", path) + re.split(r"[/_\-.]", path)
            all_tokens = (params["path"] + params["query"] + params["body"]
                          + params["header"] + path_tokens)
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "base_url": servers[0] if servers else "",
                "params": params,
                "auth": {"required": bool(auth_required), "schemes": schemes},
                "consumes": list(content.keys()) if content else op.get("consumes", []),
                "produces": op.get("produces", []),
                "potential_sinks": _sink_hints_for(all_tokens),
                "state_mutating": method.upper() in _STATE_MUTATING_METHODS,
                "trust_boundary": ("authenticated" if auth_required else "public"),
                "operation_id": op.get("operationId"),
                "summary": op.get("summary") or op.get("description", "")[:120],
            })

    return _finalize(endpoints, servers, sec_schemes, "openapi", "openapi_parser")


# ---------------------------------------------------------------------------
# Postman collection v2.x
# ---------------------------------------------------------------------------

def _walk_postman_items(items, out):
    for it in items:
        if not isinstance(it, dict):
            continue
        if "item" in it and isinstance(it["item"], list):
            _walk_postman_items(it["item"], out)
        elif "request" in it:
            out.append(it)


def _parse_postman(coll: dict) -> dict:
    reqs = []
    _walk_postman_items(coll.get("item", []) or [], reqs)
    endpoints = []
    servers = set()
    schemes_seen = set()
    for it in reqs:
        req = it.get("request", {})
        if isinstance(req, str):
            method, urlstr = "GET", req
            req = {}
        else:
            method = (req.get("method") or "GET").upper()
            url = req.get("url", "")
            urlstr = url if isinstance(url, str) else (url.get("raw", "") if isinstance(url, dict) else "")
        parsed = urllib.parse.urlparse(urlstr.split("?")[0]) if urlstr else None
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed and parsed.netloc else ""
        if base:
            servers.add(base)
        path = parsed.path if parsed else urlstr

        params = {"path": [], "query": [], "header": [], "body": [], "cookie": []}
        if urlstr and "?" in urlstr:
            for k, _ in urllib.parse.parse_qsl(urlstr.split("?", 1)[1]):
                params["query"].append(k)
        for h in (req.get("header", []) or []):
            if isinstance(h, dict) and h.get("key"):
                params["header"].append(h["key"])
                if h["key"].lower() in ("authorization", "x-api-key", "cookie", "x-auth-token"):
                    schemes_seen.add(h["key"])
        body = req.get("body", {}) or {}
        mode = body.get("mode")
        if mode == "urlencoded":
            for kv in body.get("urlencoded", []) or []:
                if kv.get("key"):
                    params["body"].append(kv["key"])
        elif mode == "formdata":
            for kv in body.get("formdata", []) or []:
                if kv.get("key"):
                    params["body"].append(kv["key"])
        elif mode == "raw":
            raw = body.get("raw", "")
            j = _try_parse_structured(raw)
            if isinstance(j, dict):
                params["body"].extend(list(j.keys()))
        for k in params:
            params[k] = list(dict.fromkeys(params[k]))

        auth = req.get("auth")
        auth_required = bool(auth) or "Authorization" in params["header"] or "authorization" in [x.lower() for x in params["header"]]
        path_tokens = re.split(r"[/_\-.]", path or "")
        all_tokens = params["query"] + params["body"] + params["path"] + path_tokens
        endpoints.append({
            "method": method,
            "path": path or urlstr,
            "base_url": base,
            "params": params,
            "auth": {"required": auth_required, "schemes": list(schemes_seen)},
            "consumes": [], "produces": [],
            "potential_sinks": _sink_hints_for(all_tokens),
            "state_mutating": method in _STATE_MUTATING_METHODS,
            "trust_boundary": "authenticated" if auth_required else "unknown",
            "operation_id": None,
            "summary": it.get("name", "")[:120],
        })
    return _finalize(endpoints, list(servers), list(schemes_seen), "postman", "postman_parser")


# ---------------------------------------------------------------------------
# HAR
# ---------------------------------------------------------------------------

def _parse_har(har: dict) -> dict:
    entries = (har.get("log", {}) or {}).get("entries", []) or []
    seen = {}
    servers = set()
    schemes_seen = set()
    for e in entries:
        req = e.get("request", {}) or {}
        method = (req.get("method") or "GET").upper()
        urlstr = req.get("url", "")
        parsed = urllib.parse.urlparse(urlstr)
        base = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else ""
        if base:
            servers.add(base)
        path = parsed.path
        key = (method, base, path)
        params = seen.get(key, {"path": [], "query": [], "header": [], "body": [], "cookie": []})
        for qp in (req.get("queryString", []) or []):
            if qp.get("name"):
                params["query"].append(qp["name"])
        for h in (req.get("headers", []) or []):
            hn = h.get("name", "")
            if hn and not hn.startswith(":"):
                params["header"].append(hn)
                if hn.lower() in ("authorization", "x-api-key", "cookie", "x-auth-token"):
                    schemes_seen.add(hn)
        for c in (req.get("cookies", []) or []):
            if c.get("name"):
                params["cookie"].append(c["name"])
        pd = req.get("postData", {}) or {}
        if pd.get("params"):
            for kv in pd["params"]:
                if kv.get("name"):
                    params["body"].append(kv["name"])
        elif pd.get("text"):
            j = _try_parse_structured(pd["text"])
            if isinstance(j, dict):
                params["body"].extend(list(j.keys()))
        for k in params:
            params[k] = list(dict.fromkeys(params[k]))
        seen[key] = params

    endpoints = []
    for (method, base, path), params in seen.items():
        auth_required = any(h.lower() in ("authorization", "x-api-key", "x-auth-token")
                            for h in params["header"]) or bool(params["cookie"])
        path_tokens = re.split(r"[/_\-.]", path or "")
        all_tokens = params["query"] + params["body"] + path_tokens
        endpoints.append({
            "method": method,
            "path": path,
            "base_url": base,
            "params": params,
            "auth": {"required": auth_required, "schemes": list(schemes_seen)},
            "consumes": [], "produces": [],
            "potential_sinks": _sink_hints_for(all_tokens),
            "state_mutating": method in _STATE_MUTATING_METHODS,
            "trust_boundary": "authenticated" if auth_required else "unknown",
            "operation_id": None,
            "summary": "",
        })
    return _finalize(endpoints, list(servers), list(schemes_seen), "har", "har_parser")


# ---------------------------------------------------------------------------
# Raw endpoint list ("GET /api/users/{id}" or bare URLs, one per line)
# ---------------------------------------------------------------------------

def _parse_raw_list(raw: str) -> dict:
    endpoints = []
    servers = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        method = "GET"
        rest = line
        m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.*)$", line, re.I)
        if m:
            method = m.group(1).upper()
            rest = m.group(2).strip()
        base = ""
        path = rest
        if rest.startswith("http://") or rest.startswith("https://"):
            parsed = urllib.parse.urlparse(rest.split("?")[0])
            base = f"{parsed.scheme}://{parsed.netloc}"
            servers.add(base)
            path = parsed.path or "/"
        params = {"path": [], "query": [], "header": [], "body": [], "cookie": []}
        if "?" in rest:
            for k, _ in urllib.parse.parse_qsl(rest.split("?", 1)[1]):
                params["query"].append(k)
        params["path"] = re.findall(r"\{(\w+)\}|:(\w+)", path)
        params["path"] = [a or b for a, b in params["path"]]
        path_tokens = re.split(r"[/_\-.]", path or "")
        all_tokens = params["query"] + params["path"] + path_tokens
        endpoints.append({
            "method": method,
            "path": path,
            "base_url": base,
            "params": params,
            "auth": {"required": False, "schemes": []},
            "consumes": [], "produces": [],
            "potential_sinks": _sink_hints_for(all_tokens),
            "state_mutating": method in _STATE_MUTATING_METHODS,
            "trust_boundary": "unknown",
            "operation_id": None,
            "summary": "",
        })
    return _finalize(endpoints, list(servers), [], "raw_list", "raw_list_parser")


# ---------------------------------------------------------------------------
# Finalize + summary
# ---------------------------------------------------------------------------

def _finalize(endpoints: list, servers: list, schemes: list,
              source_type: str, parser: str) -> dict:
    by_method: dict = {}
    sink_hits: dict = {}
    distinct_params = set()
    state_mut = 0
    unauth_state_mut = 0
    auth_req = 0
    no_auth = 0
    for e in endpoints:
        by_method[e["method"]] = by_method.get(e["method"], 0) + 1
        for s in e["potential_sinks"]:
            sink_hits[s] = sink_hits.get(s, 0) + 1
        for bucket in e["params"].values():
            distinct_params.update(bucket)
        if e["state_mutating"]:
            state_mut += 1
            if not e["auth"]["required"]:
                unauth_state_mut += 1
        if e["auth"]["required"]:
            auth_req += 1
        else:
            no_auth += 1
    return {
        "source_type": source_type,
        "parser": parser,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "servers": servers,
        "auth_schemes": schemes,
        "summary": {
            "total": len(endpoints),
            "state_mutating": state_mut,
            "unauthenticated_state_mutating": unauth_state_mut,
            "auth_required": auth_req,
            "no_auth": no_auth,
            "by_method": by_method,
            "distinct_params": len(distinct_params),
            "sink_hits": dict(sorted(sink_hits.items(), key=lambda kv: -kv[1])),
        },
    }


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def parse_web2_surface(source: str, source_type: str = "auto") -> dict:
    """Parse a web2/API target into an attack-surface model.

    source: OpenAPI/Swagger spec (JSON/YAML) as file path, http(s) URL, or
      inline text; a Postman v2 collection (JSON); a HAR capture (JSON); or a
      raw newline-separated endpoint list ("GET /api/users/{id}" / bare URLs).
    source_type: 'auto' (default) | 'openapi' | 'postman' | 'har' | 'raw'.
    """
    try:
        raw, origin = _load_raw(source)
    except Exception as e:
        return {"error": f"load failed: {e}"}

    if source_type == "raw":
        return {**_parse_raw_list(raw), "source": source, "origin": origin}

    obj = _try_parse_structured(raw)
    detected = source_type if source_type != "auto" else (_detect_type(obj) if obj is not None else "raw_list")

    try:
        if detected == "openapi" and isinstance(obj, dict):
            model = _parse_openapi(obj)
        elif detected == "postman" and isinstance(obj, dict):
            model = _parse_postman(obj)
        elif detected == "har" and isinstance(obj, dict):
            model = _parse_har(obj)
        else:
            model = _parse_raw_list(raw)
    except Exception as e:
        return {"error": f"parse failed ({detected}): {e}"}

    model["source"] = source
    model["origin"] = origin
    return model


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: web2_surface.py <spec|har|postman|urllist> [type]")
        sys.exit(1)
    st = sys.argv[2] if len(sys.argv) > 2 else "auto"
    print(json.dumps(parse_web2_surface(sys.argv[1], st), indent=2, default=str))

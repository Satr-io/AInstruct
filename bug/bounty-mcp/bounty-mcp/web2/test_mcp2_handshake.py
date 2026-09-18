#!/usr/bin/env python3
"""MCP 2.0 handshake self-test for web2-references-mcp server."""
import json
import select
import subprocess
import sys
import time

VENV_PY = "/usr/local/lib/hermes-agent/venv/bin/python3"
SERVER = "/root/bounty-mcp/web2/server.py"

MSGS = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
     "params": {"name": "search_cve",
                "arguments": {"keywords": "JWT algorithm confusion", "results_per_page": 2}}},
]

proc = subprocess.Popen(
    [VENV_PY, SERVER],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)

for i, msg in enumerate(MSGS):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    time.sleep(2.0 if i == 3 else 1.0)

time.sleep(20)

results = {}
errors = []
raw = []
while True:
    rlist, _, _ = select.select([proc.stdout], [], [], 5)
    if not rlist:
        break
    line = proc.stdout.readline()
    if not line:
        break
    raw.append(line.decode(errors="replace").strip())

for line in raw:
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        errors.append("non-json: " + line[:200])
        continue
    rid = d.get("id")
    if rid == 1:
        results["init"] = d.get("result", {}).get("serverInfo")
    elif rid == 2:
        tools = (d.get("result") or {}).get("tools", [])
        results["tools_count"] = len(tools)
        results["tools"] = [t["name"] for t in tools]
    elif rid == 3:
        r = d.get("result") or {}
        text = r.get("content", [{}])[0].get("text", "")
        if r.get("is_error"):
            results["call"] = "ERROR: " + text[:300]
        else:
            results["call"] = "OK (chars=%d): %s" % (len(text), text[:180])

try:
    proc.kill()
except Exception:
    pass
_, err = proc.communicate(timeout=5)

print(json.dumps(results, indent=2))
if errors:
    print("PARSE issues:", errors[:5])
if err:
    print("STDERR tail:", err.decode(errors="replace")[-500:])

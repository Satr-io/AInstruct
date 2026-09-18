#!/usr/bin/env python3
"""MCP 2.0 call self-test — fast local tool (get_owasp)."""
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
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
     "params": {"name": "get_owasp", "arguments": {"keywords": "ssrf"}}},
]

proc = subprocess.Popen(
    [VENV_PY, SERVER],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)

for i, msg in enumerate(MSGS):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    time.sleep(2.0)

time.sleep(8)

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
    print("RAW>", line[:600])

try:
    proc.kill()
except Exception:
    pass
_, err = proc.communicate(timeout=5)
if err:
    print("STDERR>", err.decode(errors="replace")[-800:])

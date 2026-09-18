#!/usr/bin/env python3
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import references
import importlib
importlib.reload(references)
r = references.search_exploitdb("wordpress sql injection", results_per_page=2)
print("total:", r.get("total_results"))
for res in r.get("results", []):
    print("edb:", res.get("edb_id"), "| file_path:", res.get("file_path", "MISSING"), "| source_url:", (res.get("source_url") or "")[:40])
# read first file
if r.get("results"):
    rid = r["results"][0]["edb_id"]
    rf = references.read_exploit_file(rid, max_chars=500)
    print("read_exploit_file:", rf.get("edb_id"), "| content_len:", len(rf.get("content", "")), "| path:", rf.get("path"))
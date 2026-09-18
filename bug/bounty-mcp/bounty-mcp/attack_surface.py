"""
Bug Bounty MCP — Attack Surface Model
Parses Solidity contracts via Slither to build a generic attack surface model.
Uses slither CLI --json output, falls back to regex parser.
"""

import json
import os
import subprocess
import sys
import re
from typing import Optional


class AttackSurfaceParser:

    def __init__(self, slither_path: str = None):
        self.slither_path = slither_path or self._find_slither()
        self.python = self._get_python()

    def _find_slither(self) -> str:
        candidates = [
            "/usr/local/lib/hermes-agent/venv/bin/slither",
            "slither",
        ]
        import shutil
        for c in candidates:
            if os.path.exists(c):
                return c
            found = shutil.which(c)
            if found:
                return found
        return "slither"

    def _get_python(self) -> str:
        venv = "/usr/local/lib/hermes-agent/venv/bin/python3"
        if os.path.exists(venv):
            return venv
        return sys.executable

    def parse(self, contract_path: str, use_slither: bool = True) -> dict:
        """Parse contract(s). Tries Slither first, falls back to regex."""
        if use_slither:
            result = self._slither_json(contract_path)
            if "error" not in result:
                return self._build_model(result, contract_path, "slither")
        return self._regex_parse(contract_path)

    def _slither_json(self, contract_path: str) -> dict:
        """Run slither to get AST/contract info via Python API."""
        # Use direct Python import to get richer data
        code = self._make_slither_script(contract_path)
        try:
            result = subprocess.run(
                [self.python, "-c", code],
                capture_output=True, text=True, timeout=120,
                cwd=os.path.dirname(contract_path) if os.path.isfile(contract_path) else contract_path
            )
            if result.returncode != 0 and not result.stdout.strip():
                return {"error": result.stderr[:500]}
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"error": f"JSON parse failed: {result.stdout[:300]}"}
        except subprocess.TimeoutExpired:
            return {"error": "Slither timed out (120s)"}
        except Exception as e:
            return {"error": str(e)}

    def _make_slither_script(self, contract_path: str) -> str:
        """Build a Python script that uses Slither API to extract attack surface."""
        # Use string formatting (not f-string) to avoid interpolation issues
        return (
            "import json, sys\n"
            "sys.path.insert(0, '/usr/local/lib/hermes-agent/venv/lib/python3.11/site-packages')\n"
            "try:\n"
            "    from slither import Slither\n"
            "    path = " + repr(contract_path) + "\n"
            "    slither = Slither(path)\n"
            "    contracts_out = []\n"
            "    for contract in slither.contracts:\n"
            "        funcs_out = []\n"
            "        for func in contract.functions:\n"
            "            ext_calls = []\n"
            "            tok_transfers = []\n"
            "            oracle_deps = []\n"
            "            for call in list(func.internal_calls) + list(func.external_calls):\n"
            "                cs = str(call)\n"
            "                ext_calls.append(cs[:200])\n"
            "                low = cs.lower()\n"
            "                if any(x in low for x in ['transfer','approve','mint','burn','deposit','withdraw']):\n"
            "                    tok_transfers.append(cs[:200])\n"
            "                if any(x in low for x in ['oracle','price','getprice','latestrounddata','pricefeed','twap']):\n"
            "                    oracle_deps.append(cs[:200])\n"
            "            stor_writes = [str(v) for v in func.state_variables_written]\n"
            "            msg_sender = False\n"
            "            for node in func.nodes:\n"
            "                if 'msg.sender' in str(node):\n"
            "                    msg_sender = True\n"
            "                    break\n"
            "            mods = [str(m) for m in func.modifiers]\n"
            "            trust = 'privileged' if str(func.visibility) in ['internal','private'] or any('only' in str(m).lower() for m in mods) else 'external'\n"
            "            funcs_out.append({\n"
            "                'name': func.name,\n"
            "                'visibility': str(func.visibility),\n"
            "                'state_mutating': bool(func.state_variables_written),\n"
            "                'modifiers': mods,\n"
            "                'external_calls': ext_calls[:20],\n"
            "                'storage_writes': stor_writes[:20],\n"
            "                'token_transfers': tok_transfers[:20],\n"
            "                'oracle_dependencies': oracle_deps[:20],\n"
            "                'msg_sender_usage': msg_sender,\n"
            "                'trust_boundary': trust\n"
            "            })\n"
            "        contracts_out.append({\n"
            "            'name': contract.name,\n"
            "            'inheritance': [str(c) for c in contract.inheritance],\n"
            "            'is_upgradeable': getattr(contract, 'is_upgradeable', False),\n"
            "            'functions': funcs_out,\n"
            "            'state_variables': [{'name': str(v), 'type': str(v.type)} for v in contract.state_variables]\n"
            "        })\n"
            "    print(json.dumps({'contracts': contracts_out}, default=str))\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error': str(e)}))\n"
        )

    def _build_model(self, slither_data: dict, source_path: str, parser: str) -> dict:
        contracts = slither_data.get("contracts", [])
        model = {
            "source_path": source_path,
            "parser": parser,
            "contract_count": len(contracts),
            "contracts": contracts,
            "summary": {
                "external_functions": 0,
                "public_functions": 0,
                "privileged_functions": 0,
                "token_transfers": 0,
                "oracle_dependencies": 0,
                "storage_writes": 0,
                "msg_sender_usage": 0,
                "upgradeable": False,
            }
        }
        for c in contracts:
            if c.get("is_upgradeable"):
                model["summary"]["upgradeable"] = True
            for fn in c.get("functions", []):
                vis = fn.get("visibility", "")
                if vis == "external":
                    model["summary"]["external_functions"] += 1
                elif vis == "public":
                    model["summary"]["public_functions"] += 1
                if fn.get("trust_boundary") == "privileged":
                    model["summary"]["privileged_functions"] += 1
                model["summary"]["token_transfers"] += len(fn.get("token_transfers", []))
                model["summary"]["oracle_dependencies"] += len(fn.get("oracle_dependencies", []))
                model["summary"]["storage_writes"] += len(fn.get("storage_writes", []))
                if fn.get("msg_sender_usage"):
                    model["summary"]["msg_sender_usage"] += 1
        return model

    def _regex_parse(self, contract_path: str) -> dict:
        """Regex fallback when Slither unavailable."""
        files = []
        if os.path.isfile(contract_path):
            files = [contract_path]
        elif os.path.isdir(contract_path):
            for root, _, flist in os.walk(contract_path):
                for f in flist:
                    if f.endswith(".sol"):
                        files.append(os.path.join(root, f))

        all_functions = []
        contract_names = []
        for filepath in files:
            with open(filepath, "r") as f:
                source = f.read()
            for m in re.finditer(r"contract\s+(\w+)", source):
                contract_names.append(m.group(1))
            for m in re.finditer(
                r"function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?",
                source
            ):
                name = m.group(1)
                vis = m.group(2) or "public"
                func_body = source[m.start():m.start()+3000]
                fn = {
                    "name": name,
                    "visibility": vis,
                    "state_mutating": "view" not in func_body,
                    "modifiers": [],
                    "external_calls": [],
                    "storage_writes": [],
                    "token_transfers": [],
                    "oracle_dependencies": [],
                    "msg_sender_usage": "msg.sender" in func_body,
                    "trust_boundary": "external" if vis in ("public", "external") else "internal",
                }
                for p in ["transfer(", "transferFrom(", "approve(", "mint(", "burn("]:
                    if p in func_body:
                        fn["token_transfers"].append(p.rstrip("("))
                for p in ["oracle", "getPrice", "latestRoundData", "priceFeed", "TWAP", "twap"]:
                    if p.lower() in func_body.lower():
                        fn["oracle_dependencies"].append(p)
                all_functions.append(fn)

        return {
            "source_path": contract_path,
            "parser": "regex_fallback",
            "contract_count": len(contract_names),
            "contracts": [{"name": n, "functions": all_functions, "inheritance": [], "is_upgradeable": False} for n in contract_names],
            "summary": {
                "external_functions": sum(1 for f in all_functions if f["visibility"] == "external"),
                "public_functions": sum(1 for f in all_functions if f["visibility"] == "public"),
                "privileged_functions": 0,
                "token_transfers": sum(len(f["token_transfers"]) for f in all_functions),
                "oracle_dependencies": sum(len(f["oracle_dependencies"]) for f in all_functions),
                "storage_writes": 0,
                "msg_sender_usage": sum(1 for f in all_functions if f["msg_sender_usage"]),
                "upgradeable": False,
            }
        }

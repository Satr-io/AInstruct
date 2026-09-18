# Direct Python API Fallback (when MCP tools are NOT callable in-session)

If the 7 MCP tools are not wired as callable tools in the current Hermes session, drive the
SAME SQLite state directly by importing the bounty-mcp server modules. Same DB, same audit
state, survives across sessions. This is the verified fallback path used on the SwingHook audit.

```python
import sys, os
sys.path.insert(0, '/root/bounty-mcp')
from db import Database
from solodit import SoloditAdapter
from attack_surface import AttackSurfaceParser
d = Database('/root/bounty-mcp/bounty_mcp.db')
s = SoloditAdapter(api_key=os.environ["SOLODIT_API_KEY"], db=d)
p = AttackSurfaceParser()
```

Run scripts with the SAME interpreter the MCP server uses (it has `mcp`, `requests`, `slither`):
`/usr/local/lib/hermes-agent/venv/bin/python3`. Keys live in `/root/bounty-mcp/config.env`
and in `~/.hermes/config.yaml` under `mcp_servers.bounty-mcp.env.SOLODIT_API_KEY`.

## Verified method map (db.Database)

- `create_audit(name, target_path=None, target_address=None, target_chain=None, snapshot_path=None)` -> audit_id (str)
- `store_attack_surface(audit_id, contract_name, contract_path, model, parser_used='slither', parser_version=None, functions=None)`
- `init_coverage(audit_id)`
- `create_candidate(audit_id, contract, function, hypothesis, properties=None)` -> **dict** `{"id","display_id","status"}`
- `add_evidence(candidate_id, audit_id, evidence_type, relationship, source, claim, location=None, observed_value=None, confidence='medium')`
- `save_validation(candidate_id, audit_id, reachability='unknown', attacker_control='unknown', prerequisites='unknown', state_impact='unknown', asset_impact='unknown', exploitability='unknown', confidence_scores=None, final_status=None, kill_reason=None, confirm_reason=None)`
- `update_coverage(audit_id, category, status, candidate_ids=None, notes=None)`
- `get_coverage(audit_id)`, `get_candidates_by_audit(audit_id, status=None)`, `get_evidence_by_candidate(candidate_id)`
- `AttackSurfaceParser.parse(path)` -> `{source_path, parser, contract_count, contracts:[{name, functions:[...]}], summary}`
- `SoloditAdapter.search(keywords=None, impact=None, protocol=None, tags=None, ..., page_size=20, use_cache=True)` -> `{findings/results, total}`

15 coverage categories (DEFAULT_CATEGORIES): access_control, oracle, accounting, rounding,
precision, reentrancy, flash_loan, liquidation, signature, initialization, upgradeability,
token_compatibility, cross_contract, dos, economic_invariants.

## API gotchas (each one cost a retry on the SwingHook run)

1. **`create_candidate` returns a dict**, not a bare id. Extract `r["id"]` before passing to
   `add_evidence` / `save_validation`. Wrap it: `cid = r["id"] if isinstance(r, dict) else r`.
2. **`add_evidence` positionals are primitives only.** Passing a dict/list (e.g. a helper param
   named `val` that shadows `observed_value`) throws
   `sqlite3.ProgrammingError: Error binding parameter N: type 'dict' is not supported`.
   Never shadow `observed_value` with a `val` kwarg.
3. **relationship free-text** is stored as given ("supporting"/"disconfirming"), but
   `get_evidence_summary` filters on `'SUPPORTS'`/`'DISCONFIRMS'`. If the summary looks empty,
   use `get_evidence_by_candidate` and count `relationship` yourself.
4. **Orphan cleanup.** Candidates created but never given evidence linger as DISCOVERED and
   pollute the summary. Delete directly:
   `DELETE FROM candidates WHERE audit_id=? AND id NOT IN (SELECT DISTINCT candidate_id FROM evidence)`.
5. **Solodit `search(impact=[...])` binding bug** on some builds:
   `Incorrect number of bindings supplied (uses 19, supplied 18)`. Drop the `impact` filter and
   filter client-side, or retry without it.
6. **Solodit keywords:** single words flood (oracle = 2530). Use 2-4 word phrases.
   `total=0` is NOT novelty proof — usually poor keyword choice. Rate limit 20 req/60s; cached free.
7. **urllib3/charset RequestsDependencyWarning** spams stderr on this venv — harmless, grep it out:
   `... 2>&1 | grep -v Warning | grep -v warnings.warn`.

## Coverage discipline

Mark categories honestly: `TESTED` (candidate + evidence exist), `NOT_APPLICABLE` (no surface —
state WHY in notes, e.g. "no proxy; all immutable" / "no lending/liquidation in scope"), or leave
`NOT_STARTED`. An audit with any `NOT_STARTED` is incomplete. `NOT_APPLICABLE` with a stated reason
is expected and fine.

## Worked flow (SwingHook, audit 60be51d7)

1. `create_audit` -> store surface for all N contracts via `AttackSurfaceParser.parse` + `store_attack_surface`.
2. `init_coverage`.
3. Form hypotheses from surface FIRST (do not let Solodit seed them).
4. `create_candidate` per hypothesis; `add_evidence` supporting AND disconfirming for each.
5. `save_validation` to run the state machine -> CONFIRMED / KILLED / TEST_CANDIDATE.
6. `search` Solodit for precedent AFTER candidates exist.
7. `update_coverage` for all 15 categories; delete orphan candidates.
8. `get_coverage` + `get_candidates_by_audit` to print the final system-of-record summary.

Outcome discipline: a TEST_CANDIDATE that later falsifies (e.g. feeKey pre-occupy griefing —
nonce space unbounded, victim retries free, attacker bears capital + same-block front-run)
must be downgraded to KILLED with a `kill_reason`, and disconfirming evidence appended. The
value of the MCP pass is that the coverage matrix FORCED checking a category (dos) that a
pure fuzz/reasoning pass had skipped.

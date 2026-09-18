---
name: bug-bounty-mcp-audit
description: "Bug bounty MCP audit workflow — attack surface, precedent search (Solodit web3 + HackerOne/Bugcrowd web2), candidate lifecycle, evidence, validation, coverage. AUTO-LOAD for ANY bug bounty / security audit across ALL domains — web2, web3, API, mobile, infra. Triggers: audit, bug bounty, vulnerability, finding, exploit, precedent, coverage, candidate, evidence, validate; web3 (smart contract, solidity, reentrancy, oracle, proxy, bridge, signature); web2/API (SQLi, XSS, SSRF, IDOR, BOLA, CSRF, XXE, SSTI, RCE, auth bypass, JWT, OAuth, GraphQL, endpoint). Web3 MCP tools: get_attack_surface, search_precedents, get_finding_detail, create_candidate, add_evidence, validate_candidate, get_coverage. Web2 sibling web2-references-mcp (own DB): parse_web2_surface, w2_seed_candidates, w2_recall_proven, w2_create_candidate, w2_add_evidence, w2_validate_candidate, suggest_cvss, search_hackerone, search_bugcrowd, build_references + full lifecycle — see references/web2-references-mcp.md. Full trigger keyword list in body."
version: 1.3.0
author: timplexz
license: MIT
metadata:
  hermes:
    tags: [bug-bounty, audit, mcp, solodit, attack-surface, evidence, coverage, validation, smart-contract]
    related_skills:
      - solidity-exploit-reference
      - source-code-recon
      - bounty-finding-impact-chain-validation
      - bounty-claim-discipline-protocol
      - scanner-results-review
---
priority: critical
mandatory_load: true


# Bug Bounty MCP Audit Workflow

> **⚠️ CRITICAL — MANDATORY LOAD FOR ALL BUG BOUNTY WORK (WEB2 + WEB3 + API + MOBILE + INFRA)**
> 
> This skill MUST be loaded BEFORE any bug bounty audit, finding validation, 
> precedent search, coverage check, web app / API assessment, or smart contract review.
> This MCP is domain-agnostic — it drives BOTH the web3 audit server (attack surface,
> Solodit precedent, candidate/evidence/validation state machine) AND the web2 references
> server (CVE/CWE/GHSA/OSV/OWASP + HackerOne/Bugcrowd web2 precedent). Do NOT treat it as
> web3-only. A SQLi/XSS/SSRF/IDOR/auth-bypass web app finding uses the SAME candidate →
> evidence → validate → coverage workflow as a Solidity finding; only the precedent source
> differs (HackerOne/Bugcrowd for web2, Solodit for web3).
> 
> If ANY of these keywords appear in the task, this skill MUST be active:
> audit, bug bounty, vulnerability, finding, findings, exploit,
> precedent, solodit, hackerone, bugcrowd, coverage, candidate, evidence, validate, review, scan,
> bounty hunt, immunefi,
> --- WEB2 / API / WEB APP (this MCP triggers for these too, not just web3) ---
> SQLi, SQL injection, XSS, cross-site scripting, SSRF, server-side request forgery,
> IDOR, BOLA, BFLA, broken access control, CSRF, XXE, SSTI, template injection,
> RCE, command injection, LFI, path traversal, deserialization, prototype pollution,
> auth bypass, authentication bypass, JWT, OAuth, OIDC, SAML, SSO, session, cookie,
> API, REST, GraphQL, endpoint, web app, web application, HTTP, request smuggling,
> CORS, open redirect, clickjacking, CRLF, host header, cache poisoning, cache deception,
> mass assignment, parameter tampering, rate limit, race condition, business logic,
> file upload, web cache, HTTP parameter pollution, NoSQL injection, LDAP injection,
> subdomain takeover, information disclosure, PII, secret leak, credential leak, CVE, CWE, GHSA, OSV, exploit-db,
> --- WEB3 / SMART CONTRACT ---
> smart contract, solidity, review contract, scan contract,
> BOLA, IDOR, access control, reentrancy, oracle, flash loan, bridge, signature,
> EIP-712, replay, inflation, donation, rounding, accounting, initialization,
> upgradeability, proxy, UUPS, CREATE2, selector collision, privilege escalation,
> fund loss, fund theft, drain, steal, manipulation, bypass, missing, unchecked,
> search precedent, historical finding, similar bug, same pattern, severity reference,
> is this by design, has this been reported, novelty, cross-reference,
> attack surface, attack vector, trust boundary, invariant, state transition,
> confirmation bias, disconfirming, kill, confirm, TEST_CANDIDATE, REPORT_READY,
> validate finding, validate candidate, pre-submit, submission prep,
> scope, attack surface mapping, hypothesis, generate hypothesis,
> code review, source review, contract review, deep review, deep audit,
> recon, probe, scan, fingerprint, enumerate,
> 0x address, contract address, on-chain, verified source, etherscan, arbiscan, basescan, bscscan, polygonscan, snowtrace, ftmscan, optimism, basescan, blast, mantle, mode, soneium, zksync, lineascan, scrollscan, celoscan, aurora, harmony, moonbeam, cronos, metis, arbitrum, sepolia, goerli, mainnet, holesky, amoy, bali, quake,
> deployer, implementation, proxy admin, storage slot, function selector,
> mainnet, testnet, fork, chain, multi-chain, cross-chain,
> token, ERC20, ERC721, ERC1155, ERC4626, vault, staking, yield,
> DEX, AMM, liquidity pool, swap, router, pair,
> lending, borrow, collateral, liquidation, health factor,
> bridge, wrapper, messenger, relayer, sequencer,
> governance, multisig, timelock, Gnosis Safe,
> gas, DoS, griefing, front-run, MEV, sandwich,
> slither, mythril, foundry, forge test, cast call
> 
> This skill provides the instruction layer for the bounty-mcp server family:
> **web3 side = 7 MCP tools** (get_attack_surface, search_precedents, get_finding_detail, create_candidate, add_evidence, validate_candidate, get_coverage);
> **web2 side (web2-references-mcp, own DB) = 24 tools** (references/CVSS/precedent builders + full `w2_*` lifecycle — see references/web2-references-mcp.md).
The MCP server handles state (SQLite), the skill tells you HOW and WHEN to use each tool.

## Session Resume & Server State Check

When starting a NEW session and the user wants to continue an audit, verify state FIRST before doing any work:

1. **Server liveness** (processes must be running):
   `ps aux | grep -E "bounty-mcp/(server|web2/server)\.py"`
   - Main: `/root/bounty-mcp/server.py` (bounty audit MCP)
   - Web2: `/root/bounty-mcp/web2/server.py` (web2 references MCP)
2. **State DB**: `/root/bounty-mcp/bounty_mcp.db` (SQLite, ~2.2MB). Tables: audits, candidates, evidence, validation_results, coverage, attack_surfaces, surface_functions, impact_assessments, candidate_precedents, audit_snapshots.
3. **Check for existing audit sessions**:
   `python3 -c "import sqlite3; db=sqlite3.connect('/root/bounty-mcp/bounty_mcp.db'); print(list(db.execute('SELECT id,name,target_path,target_chain,status,created_at FROM audits ORDER BY id DESC LIMIT 5')))"`
   - 0 rows in `audits` = no persisted session. **AUTO-CREATE (fixed 2026-08-24, charm):** the web3 MCP now wraps `db.ensure_audit()` (idempotent `INSERT OR IGNORE`) into `get_attack_surface`, `create_candidate`, `add_evidence`, `validate_candidate`, and `get_coverage`. So you can pass an arbitrary human label like `charm-2026-08-24` directly to any of those tools and the audit row is created on first use — NO manual SQL insert, NO more `FOREIGN KEY constraint failed`. This mirrors the web2 `w2_seed_candidates` auto-create behavior; web3 and web2 sides now behave the same on audit bootstrap. Audit id convention: `<target>-<YYYY-MM-DD>` (e.g. `charm-2026-08-24`).
     - **Caveat — takes effect NEXT session only:** the MCP subprocess is spawned by Hermes at session boot, so a fix landed mid-session is NOT live until a new session. In the session where you just patched it, the OLD binary still errors with `FOREIGN KEY constraint failed`. Two options in that window: (a) drive the db layer directly from `/root/bounty-mcp/`: `/usr/local/lib/hermes-agent/venv/bin/python3 -c "import db; print(db.Database().create_audit('<name>', target_path='<path>', target_chain='<chain>'))"` (class is `db.Database`, NOT `db.DB`) — it RETURNS a UUID; pass THAT uuid to the MCP tools; or (b) raw SQL insert:
     ```sql
     INSERT INTO audits (id, name, target_path, target_chain, status, created_at)
     VALUES ('<audit_id>', '<name>', '<path>', '<chain>', 'IN_PROGRESS', '<utc iso>');
     ```
     - Historical note: before the 2026-08-24 fix (verified 2026-08-23 dolomite session), NO MCP tool auto-created audits and every new audit_id threw `FOREIGN KEY constraint failed` — that is why older runs required the manual insert first.
   - Existing rows = resume that audit_id; candidates/evidence/coverage persist in SQLite across sessions.
4. **MCP tools already loaded in the current Hermes session = server is live, NO restart needed.** "kita di session mcp" / "ga perlu restart" means the tools (mcp_bounty_mcp_*, mcp_web2_references_mcp_*) are available right now — proceed directly. Empty DB is NOT a broken server; it just means no audit has been persisted yet.
5. Empty `audits` table + a previous deep-dive session that didn't use MCP = prior findings live only in the chat transcript; re-create the audit session in MCP if you want state persisted.

## Backfilling a Completed Audit (persist findings post-hoc)

When the audit was already done (report/transcript exists) and you want the state in MCP, this is the working sequence (verified on dolomite-2026-08-23):

1. Insert the audit row directly (see Session Resume above — MCP tools will NOT create it).
2. `get_attack_surface` — on old Solidity (0.5.x, dYdX-style facades like `DolomiteMargin.sol` that inherit `Admin/Getters/Operation/Permission`), the regex parser returns 0 functions. Point it at the impl file (e.g. `impl/OperationImpl.sol`) or accept the empty surface and rely on manual source review.
3. `create_candidate` for EACH tested hypothesis — including KILLED ones. Verified findings get a candidate too. Use `properties` tags (access_control, accounting, economic, oracle_dependent...).
4. `add_evidence` per candidate: `relationship=SUPPORTS` for confirmed findings, `relationship=DISCONFIRMS` for disproven hypotheses, `evidence_type` ∈ (access_control, accounting, economic, oracle_validation, missing_mitigation). Confidence high only when backed by the actual report/curl/code.
5. `validate_candidate` with `final_status=CONFIRMED` (real findings) or `KILLED` (disproven, kill_reason = what disproved it). Fill reachability/exploitability/prerequisites honestly.
6. `search_precedents` for the confirmed classes (e.g. "clickjacking missing X-Frame-Options", "OAuth redirect_uri http"). Note: a `filters`/`impact` combo can throw `Incorrect number of bindings supplied` (server bug) — retry with fewer filter fields.
7. **No MCP tool updates coverage rows** — `get_coverage` only init's NOT_STARTED rows. Update status + candidate_ids_json + notes via direct SQL on `coverage` table (map each candidate to its category; mark tested categories TESTED).
8. **No MCP tool links precedents** — insert into `candidate_precedents` (candidate_id, solodit_id, similarity_type='historical_similarity', similarity_score, notes) directly.
9. Mark audit done via direct SQL: `UPDATE audits SET status='COMPLETED', completed_at=? WHERE id=?`.

The DB is the single source of truth — candidates/evidence/coverage survive across sessions even if the chat transcript is lost.

## Web2 / API Target Workflow (mirrors the web3 flow)

For a web2/API target the SAME candidate → evidence → validate → coverage loop applies, but web2 now has its OWN dedicated tools + OWN DB (`/root/bounty-mcp/web2/bounty_web2.db`, endpoint/method/vuln_class-centric — NOT the web3-flavored `bounty_mcp.db`). Use the `w2_*` web2-references-mcp tools so web2 state never lands in the web3 DB. The audit row is auto-created on the first `w2_*` call — no manual SQL insert needed (unlike the web3 side).

1. **Attack surface (web2 analogue of get_attack_surface):** call `parse_web2_surface(source, source_type)` FIRST. Feed it an OpenAPI/Swagger spec (path/URL/inline JSON or YAML), a Postman v2 collection, a HAR capture, or a raw newline-separated endpoint list (`GET /api/users/{id}` or bare URLs). It returns per-endpoint method/path/params-by-location/auth-model/state-mutating flag/trust-boundary + heuristic `potential_sinks` (IDOR/BOLA, SSRF, SQLi, path-traversal, command-injection, XSS/SSTI, mass-assignment, auth-abuse, business-logic, XXE, file-upload) and a summary (unauthenticated state-mutating count, sink_hits histogram, by_method). Do NOT hand-guess the surface — parse it. Persist it with `w2_store_surface(audit_id, host, source_type, model)` (pass the full parse output).
   - **Shortcut:** `w2_seed_candidates(audit_id, host, model)` does step 1's persist + step 2/3's seeding in one call — it turns the parsed surface into a DISCOVERED candidate backlog (one candidate per endpoint×sink, with auto property tags), idempotent on (endpoint, method, vuln_class). Use it to skip manual per-hypothesis `w2_create_candidate` calls, then jump straight to triaging each seeded candidate. `only_sinks=[...]` to focus one class.
2. **LEARN-FROM-DB BEFORE PROBING (do this per vuln_class):** call `w2_recall_proven(vuln_class=...)` (or `sink=...`) BEFORE you start probing a sink. It queries the DB's OWN evidence + validation tables for PROVEN findings (final_status=CONFIRMED) and returns the payloads + breakthrough signals that ACTUALLY worked before — each proven candidate's endpoint/method/CVSS + every SUPPORTING evidence row (claim + observed_value, e.g. `q=1' AND sleep(5)--` → `5.02s vs 0.03s`, `url=http://169.254.169.254/` → IAM role leaked). This is learning-from-DB with NO separate store — the evidence table IS the memory. Only CONFIRMED surfaces, so you never reuse an unproven assumption. Omit `audit_id` to recall across ALL audits in the db (cross-target learning); pass it to stay within one target. Reuse the proven payload/signal to probe faster and smarter instead of guessing from zero.
3. **Generate hypotheses** from `potential_sinks` + the unauthenticated-state-mutating endpoints (Hermes reasoning, not MCP). Each sink hit on a reachable endpoint = a candidate seed.
4. **w2_create_candidate(audit_id, endpoint, method, hypothesis, vuln_class, properties)** per hypothesis (or use `w2_seed_candidates` from step 1) — endpoint/method/vuln_class are first-class web2 fields (no more shoehorning into contract/function). status starts DISCOVERED → H-001. Use `properties` tags (permissionless, state_mutating, external_input, access_control...).
5. **w2_add_evidence** per observation, SUPPORTS and DISCONFIRMS. evidence_type maps naturally: reachability (endpoint live/authz-gated), attacker_control (param reflected into sink), authz_check (authz enforced = disconfirming), missing_mitigation (no CSRF token / no authz check), injection_reflected, csrf_token, rate_limit, transport, info_leak, historical_precedent. **Put the real payload in `claim` and the breakthrough signal in `observed_value`** — that is exactly what `w2_recall_proven` re-serves later, so record it well.
6. **w2_validate_candidate** → CONFIRMED/KILLED/TEST_CANDIDATE/HOLD, same state machine (reachability/attacker_control/prerequisites/state_impact/asset_impact/exploitability + confidence_scores). Store the CVSS vector/score/severity here too (from suggest_cvss).
7. **Precedent (web2 analogue of Solodit):** `search_hackerone(keywords)` for disclosed HackerOne reports (real awarded precedent) + `search_bugcrowd(keywords)` for Bugcrowd crowdstream. DSL note: HackerOne treats spaces as OR — the tool auto-appends `AND disclosed:true`, so multi-word keywords narrow correctly (e.g. ssrf→355, idor→383, sql injection→1473). Precedent = supporting evidence, NOT severity verdict. Link it to the candidate with `w2_link_precedent(candidate_id, precedent_source, precedent_ref, ...)`.
8. **Severity (auto-derive, don't hand-guess):** after CONFIRMED, call `suggest_cvss(impact_class, attacker_control, complexity, privileges, user_interaction, scope_changed, version)`. impact_class picks the C/I/A impact legs from a preset table (rce, sqli, idor, bola, idor_write, ssrf, xxe, xss/stored_xss/reflected_xss, csrf, auth_bypass, account_takeover, info_disclosure, path_traversal, command_injection, deserialization, ssti, open_redirect, dos, business_logic, mass_assignment, privilege_escalation). Exposure args set AV/AC/PR/UI. Returns BOTH CVSS v3.1 and v4.0 by default (`version=3.1|4.0|both`) with computed base score + severity + calculator_url. Use the vector as a defensible starting point; adjust legs to the actual finding before reporting. Feed the final vector into `w2_validate_candidate`.
9. **References:** `build_references(keywords, include_hackerone=True, include_bugcrowd=True, ...)` assembles the markdown References section with external public links (NVD CVE, MITRE CWE, GHSA, OWASP, HackerOne, Bugcrowd, Exploit-DB) + CVSS calculator links. NEVER put local file paths in References.
10. **Report detail** — `w2_get_candidate(candidate_id)` returns the full per-finding view (candidate + evidence grouped SUPPORTS/DISCONFIRMS + validation verdict + CVSS + linked precedents) for report writing.
11. **Coverage** — `w2_get_coverage(audit_id)` / `w2_update_coverage(audit_id, category, status, ...)`. Web2 categories are OWASP-flavored: authz, injection, ssrf, auth, session, csrf, business_logic, info_disclosure, transport, client_side, rate_limit, file_upload, misconfig, xxe. Auto-inits NOT_STARTED rows. Any NOT_STARTED = incomplete audit. Resume/check progress anytime with `w2_get_audit_state(audit_id)`.

`parse_web2_surface`/`w2_seed_candidates` → `w2_recall_proven` (reuse proven payloads) → `w2_create_candidate` (from potential_sinks) → `w2_add_evidence` → `w2_validate_candidate` → `search_hackerone`/`search_bugcrowd` + `w2_link_precedent` (precedent) → `suggest_cvss` (severity) → `w2_get_candidate` (report detail) → `w2_get_coverage`/`w2_update_coverage` → `build_references` is the full web2 mirror of the web3 `get_attack_surface` → `create_candidate` → ... → `search_precedents` chain — now with its own endpoint-centric DB **and a learn-from-DB recall loop web3 doesn't have**.

## Critical Invariants

1. **Candidate != Finding.** Never report a candidate as a finding without full validation.
2. **Discovery before Historical.** Build attack surface and hypotheses FIRST. Search Solodit AFTER. Do not let Solodit generate your hypotheses (confirmation bias).
3. **Always search disconfirming evidence.** For every supporting evidence, actively look for what would disprove the hypothesis.
4. **Historical severity != Target severity.** Solodit findings are precedent evidence, not severity verdicts for your target.
5. **Raw data must be preserved.** Solodit raw fields are stored as-is. Derived fields must have provenance.
6. **ALWAYS use MCP tools for audit state.** Do NOT keep audit state in conversation. Use create_candidate, add_evidence, validate_candidate. State survives in SQLite across sessions.
7. **ALWAYS check coverage before finishing.** Call get_coverage before declaring an audit complete. Any NOT_STARTED category = incomplete audit.

## MCP Tools (7)

| Tool | When to call | What it returns |
|------|-------------|-----------------|
| `get_attack_surface` | FIRST step. Before any hypothesis. | Parsed contract model with functions, calls, transfers, oracle deps |
| `search_precedents` | AFTER hypotheses are formed. To validate/escalate. | Solodit findings matching keywords + filters, cached in SQLite |
| `get_finding_detail` | When you need full content of a cached Solodit finding | Raw title, content, impact, protocol, firm, source |
| `create_candidate` | When you have a hypothesis from attack surface analysis | Candidate ID (H-001), status DISCOVERED |
| `add_evidence` | For each observation (supporting OR disconfirming) | Evidence ID (E-001), linked to candidate |
| `validate_candidate` | When evidence is sufficient to run state machine | Validation result: CONFIRMED/KILLED/TEST_CANDIDATE + confidence per dimension |
| `get_coverage` | After validating candidates. To find untested categories. | Coverage matrix: 15 categories with status |

## Audit Workflow

### Step 1: Start Audit Session
Create an audit session in the MCP database (done internally when you first call a tool with audit_id).

### Step 2: Attack Surface Mapping (MUST BE FIRST)
Call `get_attack_surface(contract_path)` on the target.
- Review the returned model: external functions, token transfers, oracle dependencies, msg.sender usage, trust boundaries
- Identify functions with no access control (public/external, no modifiers)
- Identify functions with oracle dependencies
- Identify functions with token transfers
- Identify upgradeable contracts

DO NOT search Solodit yet. DO NOT create candidates yet. UNDERSTAND the attack surface first.

### Step 3: Generate Hypotheses (Hermes reasoning, NOT MCP)
Based on the attack surface model, generate hypotheses:
- Which functions accept attacker-controlled input?
- Which state transitions could violate invariants?
- Which asset flows could be manipulated?
- Which trust boundaries could be crossed?
- What compositional chains exist? (property A + property B = exploit)

For each hypothesis, determine properties:
- oracle_dependent, permissionless, state_mutating, economic, share_based,
  external_input, decimal_sensitive, valuation_used_for_asset_transfer,
  access_control, bridge, upgradeable, signature_based

### Step 4: Create Candidates
For each hypothesis, call `create_candidate(audit_id, contract, function, hypothesis, properties)`.
- Each candidate gets a display_id (H-001, H-002, ...)
- Status starts as DISCOVERED
- Remember: these are CANDIDATES, not findings

### Step 5: Search Precedents (AFTER candidates exist)
For each candidate, call `search_precedents(keywords=<pattern_description>)`.
- Use 2-4 word phrases (single words return too many results)
- Filter by impact and tags when relevant
- Results are cached in SQLite (no repeat API calls)
- Link relevant precedents to candidates

PRECEDENT = supporting evidence, NOT confirmation. Historical severity != target severity.

### Step 6: Gather Evidence
For each candidate, call `add_evidence()` for EVERY observation:

SUPPORTING evidence:
- reachability: "function X is external, no access control, L142"
- attacker_control: "msg.sender controls amount parameter, L145"
- invariant_violation: "totalAssets can become < sum(user claims)"
- historical_precedent: "Solodit #38021, similar pattern accepted as HIGH"
- missing_mitigation: "no SafeCast on share calculation, L188"

DISCONFIRMING evidence (ALWAYS search for these):
- access_control: "onlyOwner modifier present, L143"
- bounds_check: "require(amount <= maxDeposit), L146"
- safe_cast: "SafeCast.toUint256() used, L150"
- oracle_validation: "TWAP 30min period, Oracle.sol L30"
- trusted_caller: "only whitelisted callers, L160"
- economic_feasibility: "flash loan cost > potential profit"

Evidence = observation, NOT conclusion.
Good: "msg.sender is not restricted" (observable fact)
Bad: "attacker can exploit this" (conclusion, not evidence)

### Step 7: Validate
Call `validate_candidate(candidate_id, audit_id, ...)` with state machine results:
- reachability: pass/fail
- attacker_control: pass/fail
- prerequisites: satisfied/unsatisfied/partial
- state_impact: pass/fail
- asset_impact: pass/fail
- exploitability: confirmed/unconfirmed/partial
- confidence_scores: per-dimension 0-100
- final_status: CONFIRMED/KILLED/TEST_CANDIDATE/HOLD

State machine:
```
HYPOTHESIS -> REACHABILITY -> ATTACKER_CONTROL -> PREREQUISITES -> STATE_IMPACT -> ASSET_IMPACT -> EXPLOITABILITY
         FAIL=KILL         FAIL=KILL        UNSATISFIED=KILL/HOLD  FAIL=KILL     NONE=KILL
```

### Step 8: Coverage Check
Call `get_coverage(audit_id)` to see which categories are tested:
- access_control, oracle, accounting, rounding, precision, reentrancy, 
  flash_loan, liquidation, signature, initialization, upgradeability,
  token_compatibility, cross_contract, dos, economic_invariants

For any NOT_STARTED category, generate new hypotheses and repeat Steps 4-7.

### Step 9: Impact Assessment (independent from historical severity)
For CONFIRMED candidates, assess impact:
- Can attacker steal funds? manipulate price? cause DoS?
- What capital is required?
- Is it repeatable?
- What asset is affected?
- Set severity based on THIS target's impact, NOT Solodit's severity

### Step 10: Report
Only report CONFIRMED candidates with:
- Root cause (from evidence)
- Attack path (from evidence chain)
- On-chain evidence (from observations)
- Impact (from impact assessment)
- Severity (from THIS target's impact)
- PoC (from validation)
- Recommendation

## Anti-Bias Rules

1. Do NOT search Solodit before forming hypotheses. This creates confirmation bias.
2. Do NOT use Solodit severity as your severity. Assess your target independently.
3. Do NOT skip disconfirming evidence. Actively search for what would DISPROVE your hypothesis.
4. Do NOT claim "by design" or "vulnerability" without evidence. Let the evidence decide.
5. Do NOT report candidates as findings. Only CONFIRMED candidates are findings.
6. A candidate with only supporting evidence and no disconfirming evidence is NOT confirmed — it means you did not search hard enough for disconfirming evidence.

## Solodit Search Tips

- Multi-word phrases work best: "bridge pause threshold asymmetric"
- Single words return too many: "oracle" = 2530 results
- Specific patterns: "verifyingContract address(0)" = 18 results
- No get-by-ID endpoint. Use title keywords to retrieve specific findings.
- Rate limit: 20 req/60s. Cached results don't count against limit.
- pageSize max 100. >100 silently returns 0.

## Failure Modes

- If Slither fails to parse: falls back to regex parser. Regex is less accurate.
- If Solodit rate limited: 429 response. Wait 60s. Cached results still work.
- If no precedents found: this is NOT evidence of novelty. It may mean poor keyword choice.
- If all evidence is supporting: you have NOT validated. You have cherry-picked. Search for disconfirming evidence.

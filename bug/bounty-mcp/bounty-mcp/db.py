"""
Bug Bounty MCP SQLite Database Layer
Handles all CRUD operations for audit state, evidence graph, precedents, and coverage.
"""

import sqlite3
import uuid
import json
import os
from datetime import datetime
from contextlib import contextmanager
from typing import Optional


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


class Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "bounty_mcp.db")
        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            with open(SCHEMA_PATH, "r") as f:
                conn.executescript(f.read())

    def _uuid(self) -> str:
        return str(uuid.uuid4())

    # ============================================================
    # AUDIT SESSIONS
    # ============================================================

    def create_audit(self, name, target_path=None, target_address=None,
                     target_chain=None, snapshot_path=None):
        audit_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audits (id, name, target_path, target_address, target_chain, snapshot_path) VALUES (?, ?, ?, ?, ?, ?)",
                (audit_id, name, target_path, target_address, target_chain, snapshot_path))
        return audit_id

    def ensure_audit(self, audit_id, name=None, target_path=None,
                     target_address=None, target_chain=None):
        """Idempotently guarantee an audit row exists for a caller-supplied
        audit_id (arbitrary string). Returns the audit_id unchanged. Lets
        get_attack_surface / create_candidate / add_evidence / validate_candidate
        accept a human label like 'charm-2026-08-24' without a prior create_audit
        (mirrors web2 w2_seed_candidates auto-create, avoids FK constraint fail)."""
        if not audit_id:
            return audit_id
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO audits (id, name, target_path, target_address, target_chain) VALUES (?, ?, ?, ?, ?)",
                (audit_id, name or audit_id, target_path, target_address, target_chain))
        return audit_id

    def get_audit(self, audit_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
            return dict(row) if row else None

    def list_audits(self, status=None):
        with self._conn() as conn:
            if status:
                rows = conn.execute("SELECT * FROM audits WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audits ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def complete_audit(self, audit_id):
        with self._conn() as conn:
            conn.execute("UPDATE audits SET status = 'completed', completed_at = ? WHERE id = ?",
                        (datetime.utcnow().isoformat(), audit_id))

    # ============================================================
    # SOLODIT RAW FINDINGS (cache)
    # ============================================================

    def upsert_solodit_finding(self, raw_response):
        solodit_id = raw_response["id"]
        tags_json = json.dumps(raw_response.get("issues_issuetagscore", []))
        finders_json = json.dumps(raw_response.get("issues_issue_finders", []))
        with self._conn() as conn:
            existing = conn.execute("SELECT solodit_id FROM solodit_raw WHERE solodit_id = ?", (solodit_id,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE solodit_raw SET raw_title=?, raw_content=?, raw_summary=?, raw_impact=?, raw_protocol_name=?, raw_firm_name=?, raw_source_link=?, raw_github_link=?, raw_pdf_link=?, raw_report_date=?, raw_finders_count=?, raw_quality_score=?, raw_general_score=?, search_rank=?, raw_tags_json=?, raw_finders_json=?, raw_response_json=?, last_fetched_at=?, fetch_count=fetch_count+1 WHERE solodit_id=?",
                    (raw_response.get("title"), raw_response.get("content"), raw_response.get("summary"),
                     raw_response.get("impact"), raw_response.get("protocol_name"), raw_response.get("firm_name"),
                     raw_response.get("source_link"), raw_response.get("github_link", ""),
                     raw_response.get("pdf_link", ""), json.dumps(raw_response.get("report_date", {})),
                     raw_response.get("finders_count", 0), raw_response.get("quality_score", 0),
                     raw_response.get("general_score", 0), raw_response.get("search_rank", 0),
                     tags_json, finders_json, json.dumps(raw_response), solodit_id))
            else:
                conn.execute(
                    "INSERT INTO solodit_raw (solodit_id, slug, kind, raw_title, raw_content, raw_summary, raw_impact, raw_protocol_name, raw_firm_name, raw_source_link, raw_github_link, raw_pdf_link, raw_report_date, raw_finders_count, raw_quality_score, raw_general_score, search_rank, raw_tags_json, raw_finders_json, raw_response_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (solodit_id, raw_response.get("slug", ""), raw_response.get("kind", "MARKDOWN"),
                     raw_response.get("title"), raw_response.get("content"), raw_response.get("summary"),
                     raw_response.get("impact"), raw_response.get("protocol_name"), raw_response.get("firm_name"),
                     raw_response.get("source_link"), raw_response.get("github_link", ""),
                     raw_response.get("pdf_link", ""), json.dumps(raw_response.get("report_date", {})),
                     raw_response.get("finders_count", 0), raw_response.get("quality_score", 0),
                     raw_response.get("general_score", 0), raw_response.get("search_rank", 0),
                     tags_json, finders_json, json.dumps(raw_response)))
        return solodit_id

    def get_solodit_finding(self, solodit_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM solodit_raw WHERE solodit_id = ?", (solodit_id,)).fetchone()
            return dict(row) if row else None

    def search_solodit_cache(self, keywords, impact=None, protocol=None, limit=20):
        query = "SELECT * FROM solodit_raw WHERE raw_title LIKE ?"
        params = [f"%{keywords}%"]
        if impact:
            placeholders = ",".join("?" * len(impact))
            query += f" AND raw_impact IN ({placeholders})"
            params.extend(impact)
        if protocol:
            query += " AND raw_protocol_name LIKE ?"
            params.append(f"%{protocol}%")
        query += " ORDER BY search_rank DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    # ============================================================
    # DERIVED METADATA
    # ============================================================

    def add_derived_field(self, solodit_id, field_name, field_value,
                          derived_from, derivation_method="llm_extract",
                          derived_by=None, confidence="medium"):
        derived_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO solodit_derived (id, solodit_id, field_name, field_value, derived_from, derivation_method, derived_by, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (derived_id, solodit_id, field_name, field_value, derived_from, derivation_method, derived_by, confidence))
        return derived_id

    def get_derived_fields(self, solodit_id):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM solodit_derived WHERE solodit_id = ?", (solodit_id,)).fetchall()
            return [dict(r) for r in rows]

    # ============================================================
    # PRECEDENT QUERIES
    # ============================================================

    def log_precedent_query(self, audit_id, keywords, filters, total_results,
                            returned_count, rate_limit_remaining, page=1,
                            page_size=20, finding_ids=None):
        query_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO precedent_queries (id, audit_id, query_keywords, filters_json, total_results, returned_count, page, page_size, rate_limit_remaining) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (query_id, audit_id, keywords, json.dumps(filters), total_results, returned_count, page, page_size, rate_limit_remaining))
            if finding_ids:
                for rank, fid in enumerate(finding_ids):
                    conn.execute(
                        "INSERT OR IGNORE INTO precedent_query_results (query_id, solodit_id, result_rank) VALUES (?, ?, ?)",
                        (query_id, fid, rank))
        return query_id

    # ============================================================
    # ATTACK SURFACE
    # ============================================================

    def store_attack_surface(self, audit_id, contract_name, contract_path, model,
                            parser_used="slither", parser_version=None, functions=None):
        surface_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO attack_surfaces (id, audit_id, contract_name, contract_path, parser_used, parser_version, model_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (surface_id, audit_id, contract_name, contract_path, parser_used, parser_version, json.dumps(model)))
            if functions:
                for fn in functions:
                    fn_id = self._uuid()
                    conn.execute(
                        "INSERT INTO surface_functions (id, surface_id, function_name, visibility, state_mutating, modifiers_json, external_calls_json, storage_writes_json, token_transfers_json, oracle_dependencies_json, msg_sender_usage, trust_boundary) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (fn_id, surface_id, fn.get("name", ""), fn.get("visibility", ""),
                         1 if fn.get("state_mutating") else 0,
                         json.dumps(fn.get("modifiers", [])),
                         json.dumps(fn.get("external_calls", [])),
                         json.dumps(fn.get("storage_writes", [])),
                         json.dumps(fn.get("token_transfers", [])),
                         json.dumps(fn.get("oracle_dependencies", [])),
                         1 if fn.get("msg_sender_usage") else 0,
                         fn.get("trust_boundary", "external")))
        return surface_id

    def get_attack_surface(self, audit_id):
        with self._conn() as conn:
            surface = conn.execute("SELECT * FROM attack_surfaces WHERE audit_id = ?", (audit_id,)).fetchone()
            if not surface:
                return None
            surface_dict = dict(surface)
            surface_dict["model"] = json.loads(surface_dict.pop("model_json", "{}"))
            funcs = conn.execute("SELECT * FROM surface_functions WHERE surface_id = ?", (surface_dict["id"],)).fetchall()
            surface_dict["functions"] = []
            for fn in funcs:
                fn_dict = dict(fn)
                for key in ["modifiers_json", "external_calls_json", "storage_writes_json",
                           "token_transfers_json", "oracle_dependencies_json"]:
                    k = key.replace("_json", "")
                    fn_dict[k] = json.loads(fn_dict.pop(key, "[]"))
                surface_dict["functions"].append(fn_dict)
            return surface_dict

    # ============================================================
    # CANDIDATES
    # ============================================================

    def create_candidate(self, audit_id, contract, function, hypothesis, properties=None):
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM candidates WHERE audit_id = ?", (audit_id,)).fetchone()[0]
        display_id = f"H-{count + 1:03d}"
        cand_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO candidates (id, display_id, audit_id, contract, function, hypothesis, properties_json, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'DISCOVERED')",
                (cand_id, display_id, audit_id, contract, function, hypothesis, json.dumps(properties or [])))
        return {"id": cand_id, "display_id": display_id, "status": "DISCOVERED"}

    def update_candidate_status(self, candidate_id, status, kill_reason=None):
        with self._conn() as conn:
            conn.execute(
                "UPDATE candidates SET status = ?, kill_reason = ?, updated_at = ? WHERE id = ?",
                (status, kill_reason, datetime.utcnow().isoformat(), candidate_id))

    def get_candidate(self, candidate_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM candidates WHERE id = ?", (candidate_id,)).fetchone()
            if not row:
                return None
            c = dict(row)
            c["properties"] = json.loads(c.pop("properties_json", "[]"))
            return c

    def get_candidates_by_audit(self, audit_id, status=None):
        with self._conn() as conn:
            if status:
                rows = conn.execute("SELECT * FROM candidates WHERE audit_id = ? AND status = ? ORDER BY display_id", (audit_id, status)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM candidates WHERE audit_id = ? ORDER BY display_id", (audit_id,)).fetchall()
            results = []
            for r in rows:
                c = dict(r)
                c["properties"] = json.loads(c.pop("properties_json", "[]"))
                results.append(c)
            return results

    # ============================================================
    # EVIDENCE
    # ============================================================

    def add_evidence(self, candidate_id, audit_id, evidence_type, relationship,
                     source, claim, location=None, observed_value=None, confidence="medium"):
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM evidence WHERE audit_id = ?", (audit_id,)).fetchone()[0]
        display_id = f"E-{count + 1:03d}"
        ev_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO evidence (id, display_id, candidate_id, audit_id, evidence_type, relationship, source, location, claim, observed_value, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ev_id, display_id, candidate_id, audit_id, evidence_type, relationship, source, location, claim, observed_value, confidence))
        return {"id": ev_id, "display_id": display_id, "candidate_id": candidate_id}

    def get_evidence_by_candidate(self, candidate_id):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM evidence WHERE candidate_id = ? ORDER BY display_id", (candidate_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_evidence_summary(self, candidate_id):
        with self._conn() as conn:
            supporting = conn.execute("SELECT * FROM evidence WHERE candidate_id = ? AND relationship = 'SUPPORTS' ORDER BY display_id", (candidate_id,)).fetchall()
            disconfirming = conn.execute("SELECT * FROM evidence WHERE candidate_id = ? AND relationship = 'DISCONFIRMS' ORDER BY display_id", (candidate_id,)).fetchall()
        return {
            "supporting": [dict(r) for r in supporting],
            "disconfirming": [dict(r) for r in disconfirming],
            "supporting_count": len(supporting),
            "disconfirming_count": len(disconfirming),
        }

    # ============================================================
    # VALIDATION
    # ============================================================

    def save_validation(self, candidate_id, audit_id, reachability="unknown",
                        attacker_control="unknown", prerequisites="unknown",
                        state_impact="unknown", asset_impact="unknown",
                        exploitability="unknown", confidence_scores=None,
                        final_status=None, kill_reason=None, confirm_reason=None):
        val_id = self._uuid()
        cs = confidence_scores or {}
        ev_summary = self.get_evidence_summary(candidate_id)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO validation_results (id, candidate_id, audit_id, reachability, attacker_control, prerequisites, state_impact, asset_impact, exploitability, confidence_reachability, confidence_attacker_control, confidence_exploitability, confidence_impact, confidence_evidence_quality, confidence_historical_similarity, final_status, kill_reason, confirm_reason, supporting_count, disconfirming_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (val_id, candidate_id, audit_id, reachability, attacker_control,
                 prerequisites, state_impact, asset_impact, exploitability,
                 cs.get("reachability"), cs.get("attacker_control"),
                 cs.get("exploitability"), cs.get("impact"),
                 cs.get("evidence_quality"), cs.get("historical_similarity"),
                 final_status, kill_reason, confirm_reason,
                 ev_summary["supporting_count"], ev_summary["disconfirming_count"]))
            if final_status:
                conn.execute("UPDATE candidates SET status = ?, updated_at = ?, kill_reason = ? WHERE id = ?",
                            (final_status, datetime.utcnow().isoformat(), kill_reason, candidate_id))
        return val_id

    def get_validation(self, candidate_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM validation_results WHERE candidate_id = ? ORDER BY validated_at DESC LIMIT 1", (candidate_id,)).fetchone()
            return dict(row) if row else None

    # ============================================================
    # COVERAGE MATRIX
    # ============================================================

    DEFAULT_CATEGORIES = [
        "access_control", "oracle", "accounting", "rounding", "precision",
        "reentrancy", "flash_loan", "liquidation", "signature", "initialization",
        "upgradeability", "token_compatibility", "cross_contract", "dos", "economic_invariants"
    ]

    def init_coverage(self, audit_id):
        with self._conn() as conn:
            for cat in self.DEFAULT_CATEGORIES:
                conn.execute("INSERT OR IGNORE INTO coverage (id, audit_id, category) VALUES (?, ?, ?)",
                            (self._uuid(), audit_id, cat))

    def update_coverage(self, audit_id, category, status, candidate_ids=None, notes=None):
        with self._conn() as conn:
            existing = conn.execute("SELECT id, candidate_ids_json FROM coverage WHERE audit_id = ? AND category = ?", (audit_id, category)).fetchone()
            if existing:
                current_ids = json.loads(existing["candidate_ids_json"] or "[]")
                if candidate_ids:
                    current_ids = list(set(current_ids + candidate_ids))
                conn.execute("UPDATE coverage SET status = ?, candidate_ids_json = ?, notes = ?, updated_at = ? WHERE id = ?",
                            (status, json.dumps(current_ids), notes, datetime.utcnow().isoformat(), existing["id"]))
            else:
                conn.execute("INSERT INTO coverage (id, audit_id, category, status, candidate_ids_json, notes) VALUES (?, ?, ?, ?, ?, ?)",
                            (self._uuid(), audit_id, category, status, json.dumps(candidate_ids or []), notes))

    def get_coverage(self, audit_id):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM coverage WHERE audit_id = ? ORDER BY category", (audit_id,)).fetchall()
            results = []
            for r in rows:
                c = dict(r)
                c["candidate_ids"] = json.loads(c.pop("candidate_ids_json") or "[]")
                results.append(c)
            return results

    # ============================================================
    # IMPACT ASSESSMENT
    # ============================================================

    def save_impact(self, candidate_id, audit_id, can_steal_funds=False,
                    can_manipulate_price=False, can_cause_dos=False,
                    can_manipulate_accounting=False, requires_capital=None,
                    capital_description=None, repeatable=False, affected_asset=None,
                    affected_asset_value=None, severity=None, severity_rationale=None):
        impact_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO impact_assessments (id, candidate_id, audit_id, can_steal_funds, can_manipulate_price, can_cause_dos, can_manipulate_accounting, requires_capital, capital_description, repeatable, affected_asset, affected_asset_value, severity, severity_rationale) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (impact_id, candidate_id, audit_id,
                 1 if can_steal_funds else 0, 1 if can_manipulate_price else 0,
                 1 if can_cause_dos else 0, 1 if can_manipulate_accounting else 0,
                 requires_capital, capital_description,
                 1 if repeatable else 0, affected_asset, affected_asset_value,
                 severity, severity_rationale))
        return impact_id

    def get_impact(self, candidate_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM impact_assessments WHERE candidate_id = ? ORDER BY assessed_at DESC LIMIT 1", (candidate_id,)).fetchone()
            return dict(row) if row else None

    # ============================================================
    # PRECEDENT LINKAGE
    # ============================================================

    def link_precedent(self, candidate_id, solodit_id, similarity_type=None,
                       similarity_score=None, notes=None):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO candidate_precedents (candidate_id, solodit_id, similarity_type, similarity_score, notes) VALUES (?, ?, ?, ?, ?)",
                (candidate_id, solodit_id, similarity_type, similarity_score, notes))

    def get_precedents_for_candidate(self, candidate_id):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT cp.*, sr.raw_title, sr.raw_impact, sr.raw_protocol_name, sr.raw_firm_name, sr.raw_source_link FROM candidate_precedents cp JOIN solodit_raw sr ON cp.solodit_id = sr.solodit_id WHERE cp.candidate_id = ?",
                (candidate_id,)).fetchall()
            return [dict(r) for r in rows]

    # ============================================================
    # SNAPSHOTS (replayability)
    # ============================================================

    def create_snapshot(self, audit_id, snapshot_type="full", version=None):
        snapshot_id = self._uuid()
        if version is None:
            with self._conn() as conn:
                count = conn.execute("SELECT COUNT(*) FROM audit_snapshots WHERE audit_id = ?", (audit_id,)).fetchone()[0]
                version = f"v{count + 1}"
        state = {"version": version, "type": snapshot_type, "timestamp": datetime.utcnow().isoformat()}
        with self._conn() as conn:
            state["candidates"] = [dict(r) for r in conn.execute("SELECT * FROM candidates WHERE audit_id = ?", (audit_id,)).fetchall()]
            state["evidence"] = [dict(r) for r in conn.execute("SELECT * FROM evidence WHERE audit_id = ?", (audit_id,)).fetchall()]
            state["validation_results"] = [dict(r) for r in conn.execute("SELECT * FROM validation_results WHERE audit_id = ?", (audit_id,)).fetchall()]
            state["coverage"] = [dict(r) for r in conn.execute("SELECT * FROM coverage WHERE audit_id = ?", (audit_id,)).fetchall()]
            state["impact_assessments"] = [dict(r) for r in conn.execute("SELECT * FROM impact_assessments WHERE audit_id = ?", (audit_id,)).fetchall()]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_snapshots (id, audit_id, snapshot_type, version, snapshot_json) VALUES (?, ?, ?, ?, ?)",
                (snapshot_id, audit_id, snapshot_type, version, json.dumps(state, default=str)))
        return snapshot_id

    def list_snapshots(self, audit_id):
        with self._conn() as conn:
            rows = conn.execute("SELECT id, snapshot_type, version, created_at FROM audit_snapshots WHERE audit_id = ? ORDER BY created_at", (audit_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_snapshot(self, snapshot_id):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM audit_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
            if not row:
                return None
            s = dict(row)
            s["snapshot"] = json.loads(s.pop("snapshot_json", "{}"))
            return s

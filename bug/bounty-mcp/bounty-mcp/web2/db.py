"""
Web2 Bug Bounty MCP SQLite Database Layer.

Web2/API-native mirror of the web3 db.py. Endpoint/method/vuln_class-centric
instead of contract/function. Same candidate -> evidence -> validation ->
coverage lifecycle. Backing file: web2/bounty_web2.db (separate from the
web3 bounty_mcp.db in the parent folder).
"""

import sqlite3
import uuid
import json
import os
from datetime import datetime
from contextlib import contextmanager
from typing import Optional


SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


class Web2Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "bounty_web2.db")
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

    def create_audit(self, audit_id=None, name="", target_host=None,
                      target_scope=None, surface_source=None, status="IN_PROGRESS"):
        """Create (or upsert) an audit session. audit_id optional — generated if omitted."""
        aid = audit_id or self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO audits (id, name, target_host, target_scope, surface_source, status) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (aid, name, target_host, target_scope, surface_source, status))
        return aid

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
    # ATTACK SURFACE (endpoints)
    # ============================================================

    def store_attack_surface(self, audit_id, host, source_type, model, endpoints=None):
        surface_id = self._uuid()
        ep_count = len(endpoints or model.get("endpoints", []) or [])
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO attack_surfaces (id, audit_id, host, source_type, endpoint_count, model_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (surface_id, audit_id, host, source_type, ep_count, json.dumps(model)))
            for ep in (endpoints or model.get("endpoints", []) or []):
                auth = ep.get("auth_model")
                if auth is None:
                    a = ep.get("auth", "")
                    if isinstance(a, dict):
                        schemes = a.get("schemes") or []
                        auth = (",".join(schemes) if schemes
                                else ("required" if a.get("required") else "none"))
                    else:
                        auth = a or ""
                conn.execute(
                    "INSERT INTO surface_endpoints (id, surface_id, method, path, params_json, auth_model, "
                    "state_mutating, trust_boundary, potential_sinks_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (self._uuid(), surface_id, ep.get("method", ""), ep.get("path", ""),
                     json.dumps(ep.get("params", {})),
                     auth,
                     1 if ep.get("state_mutating") else 0,
                     ep.get("trust_boundary", "public"),
                     json.dumps(ep.get("potential_sinks", []))))
        return surface_id

    def get_attack_surface(self, audit_id):
        with self._conn() as conn:
            surface = conn.execute("SELECT * FROM attack_surfaces WHERE audit_id = ? ORDER BY created_at DESC LIMIT 1",
                                   (audit_id,)).fetchone()
            if not surface:
                return None
            sd = dict(surface)
            sd["model"] = json.loads(sd.pop("model_json", "{}") or "{}")
            eps = conn.execute("SELECT * FROM surface_endpoints WHERE surface_id = ?", (sd["id"],)).fetchall()
            sd["endpoints"] = []
            for ep in eps:
                ed = dict(ep)
                ed["params"] = json.loads(ed.pop("params_json", "{}") or "{}")
                ed["potential_sinks"] = json.loads(ed.pop("potential_sinks_json", "[]") or "[]")
                sd["endpoints"].append(ed)
            return sd

    # ============================================================
    # CANDIDATES
    # ============================================================

    def create_candidate(self, audit_id, endpoint, method, hypothesis,
                         vuln_class=None, properties=None):
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM candidates WHERE audit_id = ?", (audit_id,)).fetchone()[0]
        display_id = f"H-{count + 1:03d}"
        cand_id = self._uuid()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO candidates (id, display_id, audit_id, endpoint, method, vuln_class, hypothesis, "
                "properties_json, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DISCOVERED')",
                (cand_id, display_id, audit_id, endpoint, method, vuln_class, hypothesis,
                 json.dumps(properties or [])))
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
            c["properties"] = json.loads(c.pop("properties_json", "[]") or "[]")
            return c

    def get_candidates_by_audit(self, audit_id, status=None):
        with self._conn() as conn:
            if status:
                rows = conn.execute("SELECT * FROM candidates WHERE audit_id = ? AND status = ? ORDER BY display_id",
                                    (audit_id, status)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM candidates WHERE audit_id = ? ORDER BY display_id",
                                    (audit_id,)).fetchall()
            out = []
            for r in rows:
                c = dict(r)
                c["properties"] = json.loads(c.pop("properties_json", "[]") or "[]")
                out.append(c)
            return out

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
                "INSERT INTO evidence (id, display_id, candidate_id, audit_id, evidence_type, relationship, "
                "source, location, claim, observed_value, confidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ev_id, display_id, candidate_id, audit_id, evidence_type, relationship,
                 source, location, claim, observed_value, confidence))
        return {"id": ev_id, "display_id": display_id, "candidate_id": candidate_id}

    def get_evidence_by_candidate(self, candidate_id):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM evidence WHERE candidate_id = ? ORDER BY display_id",
                                (candidate_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_evidence_summary(self, candidate_id):
        with self._conn() as conn:
            supporting = conn.execute(
                "SELECT * FROM evidence WHERE candidate_id = ? AND relationship = 'SUPPORTS' ORDER BY display_id",
                (candidate_id,)).fetchall()
            disconfirming = conn.execute(
                "SELECT * FROM evidence WHERE candidate_id = ? AND relationship = 'DISCONFIRMS' ORDER BY display_id",
                (candidate_id,)).fetchall()
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
                        final_status=None, kill_reason=None, confirm_reason=None,
                        cvss_vector=None, cvss_score=None, cvss_severity=None):
        val_id = self._uuid()
        cs = confidence_scores or {}
        ev_summary = self.get_evidence_summary(candidate_id)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO validation_results (id, candidate_id, audit_id, reachability, attacker_control, "
                "prerequisites, state_impact, asset_impact, exploitability, confidence_reachability, "
                "confidence_attacker_control, confidence_exploitability, confidence_impact, "
                "confidence_evidence_quality, confidence_historical_similarity, final_status, kill_reason, "
                "confirm_reason, cvss_vector, cvss_score, cvss_severity, supporting_count, disconfirming_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (val_id, candidate_id, audit_id, reachability, attacker_control,
                 prerequisites, state_impact, asset_impact, exploitability,
                 cs.get("reachability"), cs.get("attacker_control"),
                 cs.get("exploitability"), cs.get("impact"),
                 cs.get("evidence_quality"), cs.get("historical_similarity"),
                 final_status, kill_reason, confirm_reason,
                 cvss_vector, cvss_score, cvss_severity,
                 ev_summary["supporting_count"], ev_summary["disconfirming_count"]))
            if final_status:
                conn.execute("UPDATE candidates SET status = ?, updated_at = ?, kill_reason = ? WHERE id = ?",
                             (final_status, datetime.utcnow().isoformat(), kill_reason, candidate_id))
        return val_id

    def get_validation(self, candidate_id):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM validation_results WHERE candidate_id = ? ORDER BY validated_at DESC LIMIT 1",
                (candidate_id,)).fetchone()
            return dict(row) if row else None

    # ============================================================
    # COVERAGE MATRIX (web2/OWASP-flavored)
    # ============================================================

    DEFAULT_CATEGORIES = [
        "authz", "injection", "ssrf", "auth", "session", "csrf",
        "business_logic", "info_disclosure", "transport", "client_side",
        "rate_limit", "file_upload", "misconfig", "xxe",
    ]

    def init_coverage(self, audit_id):
        with self._conn() as conn:
            for cat in self.DEFAULT_CATEGORIES:
                conn.execute("INSERT OR IGNORE INTO coverage (id, audit_id, category) VALUES (?, ?, ?)",
                             (self._uuid(), audit_id, cat))

    def update_coverage(self, audit_id, category, status, candidate_ids=None, notes=None):
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id, candidate_ids_json FROM coverage WHERE audit_id = ? AND category = ?",
                (audit_id, category)).fetchone()
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
        # always ensure default categories exist (idempotent via INSERT OR IGNORE)
        self.init_coverage(audit_id)
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM coverage WHERE audit_id = ? ORDER BY category", (audit_id,)).fetchall()
            out = []
            for r in rows:
                c = dict(r)
                c["candidate_ids"] = json.loads(c.pop("candidate_ids_json") or "[]")
                out.append(c)
            return out

    # ============================================================
    # PRECEDENT LINKAGE (HackerOne / Bugcrowd / CVE / ExploitDB)
    # ============================================================

    def link_precedent(self, candidate_id, precedent_source, precedent_ref,
                       precedent_title=None, similarity_type=None,
                       similarity_score=None, notes=None):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO candidate_precedents (candidate_id, precedent_source, precedent_ref, "
                "precedent_title, similarity_type, similarity_score, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (candidate_id, precedent_source, precedent_ref, precedent_title,
                 similarity_type, similarity_score, notes))

    def get_precedents_for_candidate(self, candidate_id):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM candidate_precedents WHERE candidate_id = ?", (candidate_id,)).fetchall()
            return [dict(r) for r in rows]

    # ============================================================
    # CANDIDATE DETAIL (full: candidate + evidence + validation + precedents)
    # ============================================================

    def get_candidate_detail(self, candidate_id):
        """Full per-finding view: candidate + all evidence (grouped) + latest
        validation verdict + linked precedents. Report-writing convenience."""
        cand = self.get_candidate(candidate_id)
        if not cand:
            return None
        ev = self.get_evidence_summary(candidate_id)
        return {
            "candidate": cand,
            "evidence": ev,
            "validation": self.get_validation(candidate_id),
            "precedents": self.get_precedents_for_candidate(candidate_id),
        }

    # ============================================================
    # AUTO-BRIDGE: attack surface -> seed DISCOVERED candidates
    # ============================================================

    # Map a parse_web2_surface potential_sink label to a candidate vuln_class.
    _SINK_TO_CLASS = {
        "IDOR/BOLA": "idor",
        "SSRF/open-redirect": "ssrf",
        "SQLi/NoSQLi": "sqli",
        "path-traversal/LFI": "path_traversal",
        "command-injection": "command_injection",
        "XSS/SSTI": "xss",
        "mass-assignment/privesc": "mass_assignment",
        "auth/token-abuse": "auth_bypass",
        "business-logic/param-tampering": "business_logic",
        "XXE": "xxe",
        "file-upload": "file_upload",
    }

    @classmethod
    def sink_to_class(cls, sink_label):
        return cls._SINK_TO_CLASS.get(sink_label, sink_label.split("/")[0].lower().replace("-", "_"))

    def seed_candidates_from_surface(self, audit_id, surface_model,
                                     only_sinks=None, dedupe=True):
        """Auto-generate DISCOVERED candidates from a parse_web2_surface model:
        one candidate per (endpoint x potential_sink). Each seed carries the
        endpoint, method, mapped vuln_class, a templated hypothesis, and
        property tags derived from the endpoint (permissionless / state_mutating
        / external_input). Returns a list of created candidate summaries.

        only_sinks: optional iterable of sink labels or vuln_classes to include
          (filters which sinks become candidates). None = all.
        dedupe: skip a seed if a candidate with the SAME (endpoint, method,
          vuln_class) already exists for this audit (idempotent re-seeding).
        """
        endpoints = surface_model.get("endpoints", []) or []
        # ensure the audit row exists (idempotent) so FK constraints hold
        # even when called directly at the db layer (not via server handler)
        self.create_audit(audit_id=audit_id, name=audit_id, target_host="web2")
        # existing (endpoint, method, vuln_class) tuples for dedupe
        existing = set()
        if dedupe:
            for c in self.get_candidates_by_audit(audit_id):
                existing.add((c.get("endpoint"), c.get("method"), c.get("vuln_class")))

        only = None
        if only_sinks:
            only = set(only_sinks)

        created = []
        for ep in endpoints:
            method = ep.get("method", "")
            path = ep.get("path", "")
            base = ep.get("base_url") or ""
            endpoint_ref = f"{base.rstrip('/')}{path}" if base else path
            auth = ep.get("auth", {}) or {}
            auth_required = auth.get("required") if isinstance(auth, dict) else bool(ep.get("auth_model"))
            state_mut = bool(ep.get("state_mutating"))
            params = ep.get("params", {}) or {}
            has_input = any(params.get(loc) for loc in ("path", "query", "body", "header", "cookie"))

            props = []
            if not auth_required:
                props.append("permissionless")
            if state_mut:
                props.append("state_mutating")
            if has_input:
                props.append("external_input")

            for sink in ep.get("potential_sinks", []) or []:
                vuln_class = self.sink_to_class(sink)
                if only and sink not in only and vuln_class not in only:
                    continue
                key = (endpoint_ref, method, vuln_class)
                if dedupe and key in existing:
                    continue
                hypothesis = (f"{sink} on {method} {path}: endpoint exposes a "
                              f"{sink} sink; verify attacker-controlled input reaches it "
                              f"and that authz/mitigation does not block exploitation.")
                res = self.create_candidate(audit_id, endpoint_ref, method, hypothesis,
                                            vuln_class=vuln_class, properties=props)
                if dedupe:
                    existing.add(key)
                created.append({
                    "display_id": res["display_id"],
                    "id": res["id"],
                    "endpoint": endpoint_ref,
                    "method": method,
                    "vuln_class": vuln_class,
                    "sink": sink,
                })
        return created

    # ============================================================
    # RECALL: learn from the DB itself (no separate store)
    # ============================================================

    def recall_proven(self, vuln_class=None, sink=None, audit_id=None, limit=25):
        """Learn-from-DB: query already-stored PROVEN findings and their
        SUPPORTING evidence so the agent can reuse payloads/breakthrough
        signals that ACTUALLY worked. No separate learned-patterns store —
        the evidence + validation_results tables ARE the memory.

        A pattern qualifies ONLY if a candidate reached final_status='CONFIRMED'
        (PROVEN). Theory / UNKNOWN / KILLED never surface here, so the agent
        never 'learns' an unproven assumption.

        Filters: vuln_class (e.g. 'ssrf','idor','sqli'), sink label, audit_id
        (None = cross-audit within THIS db). Returns, per proven candidate:
        endpoint/method/vuln_class, the CVSS verdict, and every SUPPORTING
        evidence row (claim + observed_value = the breakthrough signal).
        """
        where = ["v.final_status = 'CONFIRMED'"]
        params = []
        if vuln_class:
            where.append("c.vuln_class = ?")
            params.append(vuln_class)
        if sink:
            # sink label maps to a class; match either the raw class or mapped
            where.append("(c.vuln_class = ? OR c.vuln_class = ?)")
            params.append(sink)
            params.append(self.sink_to_class(sink))
        if audit_id:
            where.append("c.audit_id = ?")
            params.append(audit_id)
        clause = " AND ".join(where)
        with self._conn() as conn:
            cands = conn.execute(
                "SELECT c.id, c.display_id, c.audit_id, c.endpoint, c.method, "
                "c.vuln_class, c.hypothesis, v.cvss_score, v.cvss_severity, "
                "v.cvss_vector, v.exploitability "
                "FROM candidates c "
                "JOIN validation_results v ON v.candidate_id = c.id "
                f"WHERE {clause} "
                "GROUP BY c.id "
                "ORDER BY v.cvss_score DESC NULLS LAST, c.updated_at DESC "
                "LIMIT ?",
                (*params, limit)).fetchall()
            out = []
            for c in cands:
                cd = dict(c)
                ev_rows = conn.execute(
                    "SELECT evidence_type, source, location, claim, observed_value, confidence "
                    "FROM evidence WHERE candidate_id = ? AND relationship = 'SUPPORTS' "
                    "ORDER BY display_id",
                    (cd["id"],)).fetchall()
                cd["proven_evidence"] = [dict(r) for r in ev_rows]
                out.append(cd)
            return {
                "query": {"vuln_class": vuln_class, "sink": sink, "audit_id": audit_id},
                "proven_count": len(out),
                "patterns": out,
            }

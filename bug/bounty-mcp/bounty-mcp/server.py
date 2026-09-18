#!/usr/bin/env python3
"""
Bug Bounty MCP Server
Provides 7 tools for bug bounty audit workflow via Model Context Protocol.
Run via: python3 server.py (stdio transport)
"""

import json
import os
import sys
import asyncio

# Add our modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from db import Database
from solodit import SoloditAdapter
from attack_surface import AttackSurfaceParser

# Config
API_KEY = os.environ.get("SOLODIT_API_KEY", "")
DB_PATH = os.environ.get("BOUNTY_MCP_DB", os.path.join(os.path.dirname(__file__), "bounty_mcp.db"))

# Initialize components
db = Database(DB_PATH)
solodit = SoloditAdapter(api_key=API_KEY, db=db)
parser = AttackSurfaceParser()


async def handle_list_tools(ctx, params) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[
        types.Tool(
            name="get_attack_surface",
            description="Parse Solidity contract(s) to build an attack surface model. Returns functions, visibility, external calls, token transfers, oracle dependencies, msg.sender usage, and trust boundaries.",
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_path": {"type": "string", "description": "Path to .sol file or directory"},
                    "use_slither": {"type": "boolean", "description": "Use Slither AST parser (default true, falls back to regex)"},
                    "audit_id": {"type": "string", "description": "Optional audit session ID to store the surface"},
                },
                "required": ["contract_path"],
            },
        ),
        types.Tool(
            name="search_precedents",
            description="Search Solodit historical audit findings by keywords and filters. Caches results in SQLite. Returns matching findings with severity, protocol, audit firm, and relevance score.",
            inputSchema={
                "type": "object",
                "properties": {
                    "keywords": {"type": "string", "description": "Multi-word search phrase (2-4 words work best)"},
                    "impact": {"type": "array", "items": {"type": "string"}, "description": "Filter by severity: HIGH, MEDIUM, LOW, GAS"},
                    "protocol": {"type": "string", "description": "Filter by protocol name"},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter by vulnerability tags"},
                    "page_size": {"type": "integer", "description": "Results per page (max 100, default 20)"},
                    "audit_id": {"type": "string", "description": "Optional audit session ID to log query"},
                },
                "required": ["keywords"],
            },
        ),
        types.Tool(
            name="get_finding_detail",
            description="Get full detail of a Solodit finding from SQLite cache by solodit_id. Returns raw title, content, impact, protocol, firm, source link.",
            inputSchema={
                "type": "object",
                "properties": {
                    "solodit_id": {"type": "string", "description": "Solodit finding ID"},
                },
                "required": ["solodit_id"],
            },
        ),
        types.Tool(
            name="create_candidate",
            description="Create a vulnerability hypothesis candidate. Candidate != Finding. Status starts as DISCOVERED. Returns candidate ID (H-001 format).",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string", "description": "Audit session ID"},
                    "contract": {"type": "string", "description": "Contract name"},
                    "function": {"type": "string", "description": "Function name"},
                    "hypothesis": {"type": "string", "description": "Vulnerability hypothesis description"},
                    "properties": {"type": "array", "items": {"type": "string"}, "description": "Properties: oracle_dependent, permissionless, state_mutating, economic, share_based, etc"},
                },
                "required": ["audit_id", "contract", "function", "hypothesis"],
            },
        ),
        types.Tool(
            name="add_evidence",
            description="Add evidence (observation, not conclusion) to a candidate. Evidence has a relationship: SUPPORTS or DISCONFIRMS. Each evidence gets an ID (E-001 format).",
            inputSchema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string", "description": "Candidate ID"},
                    "audit_id": {"type": "string", "description": "Audit session ID"},
                    "evidence_type": {"type": "string", "description": "Type: reachability, attacker_control, invariant_violation, historical_precedent, missing_mitigation, access_control, bounds_check, safe_cast, oracle_validation, trusted_caller, economic_feasibility"},
                    "relationship": {"type": "string", "enum": ["SUPPORTS", "DISCONFIRMS"]},
                    "source": {"type": "string", "description": "Source: contract file, Solodit #ID, analysis"},
                    "claim": {"type": "string", "description": "Observation: what was actually observed (not a conclusion)"},
                    "location": {"type": "string", "description": "Code location: L142-149, null for external"},
                    "observed_value": {"type": "string", "description": "The actual observed value"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["candidate_id", "audit_id", "evidence_type", "relationship", "source", "claim"],
            },
        ),
        types.Tool(
            name="validate_candidate",
            description="Run validation state machine on a candidate. Checks reachability, attacker control, prerequisites, state impact, asset impact, exploitability. Returns CONFIRMED, KILLED, or TEST_CANDIDATE with confidence scores per dimension.",
            inputSchema={
                "type": "object",
                "properties": {
                    "candidate_id": {"type": "string", "description": "Candidate ID"},
                    "audit_id": {"type": "string", "description": "Audit session ID"},
                    "reachability": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "attacker_control": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "prerequisites": {"type": "string", "enum": ["satisfied", "unsatisfied", "partial", "unknown"]},
                    "state_impact": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "asset_impact": {"type": "string", "enum": ["pass", "fail", "unknown"]},
                    "exploitability": {"type": "string", "enum": ["confirmed", "unconfirmed", "partial", "unknown"]},
                    "confidence_scores": {"type": "object", "description": "Per-dimension confidence: {reachability, attacker_control, exploitability, impact, evidence_quality, historical_similarity} (0-100)"},
                    "final_status": {"type": "string", "enum": ["CONFIRMED", "KILLED", "TEST_CANDIDATE", "HOLD"]},
                    "kill_reason": {"type": "string"},
                    "confirm_reason": {"type": "string"},
                },
                "required": ["candidate_id", "audit_id"],
            },
        ),
        types.Tool(
            name="get_coverage",
            description="Get coverage matrix for an audit session. Shows which vulnerability categories have been tested and their status: NOT_STARTED, DISCOVERED, TESTING, SUPPORTED, DISCONFIRMED, CONFIRMED, KILLED.",
            inputSchema={
                "type": "object",
                "properties": {
                    "audit_id": {"type": "string", "description": "Audit session ID"},
                },
                "required": ["audit_id"],
            },
        ),
    ])


async def handle_call_tool(ctx, params) -> types.CallToolResult:
    name = params.name
    arguments = params.arguments or {}
    try:
        if name == "get_attack_surface":
            path = arguments["contract_path"]
            use_slither = arguments.get("use_slither", True)
            audit_id = arguments.get("audit_id")

            model = parser.parse(path, use_slither=use_slither)

            if audit_id and "error" not in model:
                # Idempotently ensure audit row exists (accept human label)
                db.ensure_audit(audit_id, target_path=path)
                # Store in DB
                for c in model.get("contracts", []):
                    db.store_attack_surface(
                        audit_id, c["name"], path, model,
                        parser_used=model.get("parser", "slither"),
                        functions=c.get("functions", [])
                    )

            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps(model, indent=2, default=str))
            ])

        elif name == "search_precedents":
            keywords = arguments["keywords"]
            audit_id = arguments.get("audit_id")
            page_size = min(arguments.get("page_size", 20), 100)

            result = solodit.search(
                keywords=keywords,
                impact=arguments.get("impact"),
                protocol=arguments.get("protocol"),
                tags=arguments.get("tags"),
                page_size=page_size,
                audit_id=audit_id
            )

            # Format output
            findings = result.get("findings", [])
            summary = {
                "total_results": result.get("total_results", 0),
                "returned": len(findings),
                "rate_limit_remaining": result.get("rate_limit_remaining"),
                "cache_ids": result.get("cached_ids", []),
                "findings": [
                    {
                        "id": f["id"],
                        "title": f["title"],
                        "impact": f["impact"],
                        "protocol": f.get("protocol_name", ""),
                        "firm": f.get("firm_name", ""),
                        "source": f.get("source_link", ""),
                        "search_rank": f.get("search_rank", 0),
                        "content_preview": f.get("content", "")[:500],
                    }
                    for f in findings
                ]
            }
            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps(summary, indent=2, default=str))
            ])

        elif name == "get_finding_detail":
            sid = arguments["solodit_id"]
            finding = db.get_solodit_finding(sid)
            if not finding:
                return types.CallToolResult(content=[
                    types.TextContent(type="text", text=json.dumps({"error": f"Finding {sid} not in cache. Search first to cache it."}))
                ])
            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps(finding, indent=2, default=str))
            ])

        elif name == "create_candidate":
            audit_id = arguments["audit_id"]
            contract = arguments["contract"]
            function = arguments["function"]
            hypothesis = arguments["hypothesis"]
            properties = arguments.get("properties", [])

            db.ensure_audit(audit_id, name=contract)
            cand = db.create_candidate(audit_id, contract, function, hypothesis, properties)
            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps({
                    "candidate_id": cand["id"],
                    "display_id": cand["display_id"],
                    "status": cand["status"],
                    "message": f"Created {cand['display_id']}. Remember: Candidate != Finding."
                }, indent=2))
            ])

        elif name == "add_evidence":
            cand_id = arguments["candidate_id"]
            audit_id = arguments["audit_id"]

            db.ensure_audit(audit_id)
            ev = db.add_evidence(
                candidate_id=cand_id,
                audit_id=audit_id,
                evidence_type=arguments["evidence_type"],
                relationship=arguments["relationship"],
                source=arguments["source"],
                claim=arguments["claim"],
                location=arguments.get("location"),
                observed_value=arguments.get("observed_value"),
                confidence=arguments.get("confidence", "medium"),
            )
            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps({
                    "evidence_id": ev["id"],
                    "display_id": ev["display_id"],
                    "message": f"Added {ev['display_id']} ({arguments['relationship']}) to {cand_id[:8]}"
                }, indent=2))
            ])

        elif name == "validate_candidate":
            cand_id = arguments["candidate_id"]
            audit_id = arguments["audit_id"]

            db.ensure_audit(audit_id)
            val_id = db.save_validation(
                candidate_id=cand_id,
                audit_id=audit_id,
                reachability=arguments.get("reachability", "unknown"),
                attacker_control=arguments.get("attacker_control", "unknown"),
                prerequisites=arguments.get("prerequisites", "unknown"),
                state_impact=arguments.get("state_impact", "unknown"),
                asset_impact=arguments.get("asset_impact", "unknown"),
                exploitability=arguments.get("exploitability", "unknown"),
                confidence_scores=arguments.get("confidence_scores", {}),
                final_status=arguments.get("final_status"),
                kill_reason=arguments.get("kill_reason"),
                confirm_reason=arguments.get("confirm_reason"),
            )

            # Get evidence summary
            ev_summary = db.get_evidence_summary(cand_id)
            validation = db.get_validation(cand_id)

            result = {
                "validation_id": val_id,
                "candidate_id": cand_id,
                "final_status": validation.get("final_status", arguments.get("final_status", "unknown")),
                "evidence_summary": ev_summary,
                "validation_stages": {
                    "reachability": validation.get("reachability"),
                    "attacker_control": validation.get("attacker_control"),
                    "prerequisites": validation.get("prerequisites"),
                    "state_impact": validation.get("state_impact"),
                    "asset_impact": validation.get("asset_impact"),
                    "exploitability": validation.get("exploitability"),
                },
                "confidence_scores": {
                    "reachability": validation.get("confidence_reachability"),
                    "attacker_control": validation.get("confidence_attacker_control"),
                    "exploitability": validation.get("confidence_exploitability"),
                    "impact": validation.get("confidence_impact"),
                    "evidence_quality": validation.get("confidence_evidence_quality"),
                    "historical_similarity": validation.get("confidence_historical_similarity"),
                },
            }
            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))
            ])

        elif name == "get_coverage":
            audit_id = arguments["audit_id"]

            # Init coverage if not exists
            db.ensure_audit(audit_id)
            db.init_coverage(audit_id)

            coverage = db.get_coverage(audit_id)

            # Format as matrix
            categories = [
                {"category": c["category"], "status": c["status"],
                 "candidates": c["candidate_ids"], "notes": c.get("notes")}
                for c in coverage
            ]

            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps({
                    "audit_id": audit_id,
                    "total_categories": len(categories),
                    "categories": categories,
                    "summary": {
                        "tested": sum(1 for c in categories if c["status"] != "NOT_STARTED"),
                        "untested": sum(1 for c in categories if c["status"] == "NOT_STARTED"),
                    }
                }, indent=2, default=str))
            ])

        else:
            return types.CallToolResult(content=[
                types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))
            ])

    except Exception as e:
        return types.CallToolResult(content=[
            types.TextContent(type="text", text=json.dumps({"error": str(e)}))
        ])


server = Server(
    "bounty-mcp",
    on_list_tools=handle_list_tools,
    on_call_tool=handle_call_tool,
)


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())

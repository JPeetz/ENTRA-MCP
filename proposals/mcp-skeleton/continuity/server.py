"""Entra Continuity MCP server — dependency-free stdio skeleton.

Run:  python3 -m continuity.server
Speaks JSON-RPC 2.0 over stdin/stdout (MCP): initialize, tools/list, tools/call.

Everything here is local and synthetic. It exists to demonstrate the tool contract
proposed in docs/proposals/entra-continuation-pr.md, not to talk to a live tenant.
"""

import json
import sys
import time
from typing import Any, Dict, List

from .policy import evaluate, explain
from .snapshot import diff_policy, make_snapshot, verify_snapshot
from .downstream import EXTRA_TOOLS, extra_call

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "entra-continuity-mcp", "version": "0.1.0-skeleton"}

# Demo policy set, so the tools are callable with no arguments.
DEMO_POLICIES: List[Dict[str, Any]] = [
    {"id": "CA001", "name": "Require MFA for all users", "state": "enabled",
     "operator": "OR", "controls": ["require_mfa"]},
    {"id": "CA002", "name": "Block legacy auth for finance", "state": "enabled",
     "include_groups": ["finance"], "client_apps": ["exchangeActiveSync"],
     "controls": ["block"]},
    {"id": "CA003", "name": "Compliant device for admin portal", "state": "enabled",
     "include_apps": ["admin-portal"], "trusted_locations_only": True,
     "operator": "AND", "controls": ["require_compliant_device", "require_mfa"]},
    {"id": "CA004", "name": "Report-only: risky sign-in step-up", "state": "reportOnly",
     "controls": ["require_mfa"]},
]

STATE = {"state": "healthy", "since": int(time.time()), "seq": 1, "snapshot": None}


def _ensure_snapshot() -> Dict[str, Any]:
    if STATE["snapshot"] is None:
        STATE["snapshot"] = make_snapshot(DEMO_POLICIES, seq=STATE["seq"])
    return STATE["snapshot"]


TOOLS = [
    {"name": "get_continuity_status",
     "description": "Report whether the tenant is healthy, degraded, or in a declared drill window.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "fetch_snapshot",
     "description": "Fetch a signed, read-only continuity snapshot (policies, groups, sequence).",
     "inputSchema": {"type": "object", "properties": {
         "ttl_hours": {"type": "integer", "default": 24}}}},
    {"name": "verify_snapshot",
     "description": "Verify signature, version, expiry and sequence of a snapshot.",
     "inputSchema": {"type": "object", "properties": {
         "snapshot": {"type": "object"}, "min_seq": {"type": "integer", "default": 0}},
         "required": ["snapshot"]}},
    {"name": "evaluate_policy_locally",
     "description": "Evaluate a sign-in context against a policy set offline. Returns allow/deny/mfa/compliant.",
     "inputSchema": {"type": "object", "properties": {
         "policies": {"type": "array"}, "context": {"type": "object"}},
         "required": ["context"]}},
    {"name": "explain_denial",
     "description": "Explain, policy by policy, why a sign-in was allowed, denied or challenged.",
     "inputSchema": {"type": "object", "properties": {
         "policies": {"type": "array"}, "context": {"type": "object"}},
         "required": ["context"]}},
    {"name": "diff_policy",
     "description": "Compare live policy against a snapshot: added, removed, changed.",
     "inputSchema": {"type": "object", "properties": {
         "current": {"type": "object"}, "snapshot": {"type": "object"}},
         "required": ["current", "snapshot"]}},
]


def call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "get_continuity_status":
        return {"state": STATE["state"], "since": STATE["since"],
                "snapshot_seq": _ensure_snapshot()["seq"],
                "note": "synthetic state; no tenant contacted"}

    if name == "fetch_snapshot":
        ttl = int(args.get("ttl_hours", 24))
        return make_snapshot(DEMO_POLICIES, seq=STATE["seq"], ttl_hours=ttl)

    if name == "verify_snapshot":
        return verify_snapshot(args["snapshot"], int(args.get("min_seq", 0)))

    if name == "evaluate_policy_locally":
        policies = args.get("policies") or DEMO_POLICIES
        return evaluate(policies, args["context"])

    if name == "explain_denial":
        policies = args.get("policies") or DEMO_POLICIES
        result = evaluate(policies, args["context"])
        return {"decision": result["decision"],
                "missing": result["missing"],
                "trace": explain(policies, args["context"])}

    if name == "diff_policy":
        return diff_policy(args["current"], args["snapshot"])

    extra = extra_call(name, args)
    if extra is not None:
        return extra

    raise ValueError(f"unknown tool: {name}")


def handle(req: Dict[str, Any]) -> Dict[str, Any]:
    method = req.get("method")
    rid = req.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO}}

    if method in ("notifications/initialized", "notifications/cancelled"):
        return {}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS + EXTRA_TOOLS}}

    if method == "tools/call":
        params = req.get("params") or {}
        try:
            out = call_tool(params.get("name", ""), params.get("arguments") or {})
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                "isError": False}}
        except Exception as e:  # keep the server alive; surface the error to the client
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}],
                "isError": True}}

    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}

    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            print(json.dumps({"jsonrpc": "2.0", "id": None,
                              "error": {"code": -32700, "message": f"parse error: {e}"}}),
                  flush=True)
            continue
        resp = handle(req)
        if resp:
            print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()

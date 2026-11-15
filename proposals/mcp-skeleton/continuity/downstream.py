"""Downstream fallback surface — tools that let the MCP act as the local authority.

Kept in its own module so `server.py` stays small and the MCP tool contract is easy to
diff in review.

The gateway is the thing downstream services actually call. These tools start it, enrol
principals while the tenant is healthy, flip the mode during an incident, and mint
short-lived continuity tokens from pre-established sessions.
"""

from typing import Any, Dict, List, Optional

from .gateway import serve_in_thread
from .state import ContinuityState
from .tokens import verify
from .beacon import build_beacon
from .health import HealthMonitor

STATE = ContinuityState()
_GATEWAY: Dict[str, Any] = {"server": None, "port": None}
_MON: Dict[str, Any] = {"monitor": None, "state_id": None}


def _monitor() -> HealthMonitor:
    """A monitor bound to the current STATE (tests replace STATE between cases)."""
    if _MON["state_id"] != id(STATE):
        _MON["monitor"] = HealthMonitor(STATE)
        _MON["state_id"] = id(STATE)
    return _MON["monitor"]


def _require_minting() -> None:
    if not STATE.can_mint():
        raise PermissionError(
            f"continuity tokens are only issued while degraded or in a declared drill "
            f"(current mode: {STATE.mode})")


EXTRA_TOOLS: List[Dict[str, Any]] = [
    {"name": "serve_gateway",
     "description": "Start the local continuity gateway on loopback. Downstream services "
                    "point their issuer at this address during an outage.",
     "inputSchema": {"type": "object", "properties": {
         "port": {"type": "integer", "default": 8400}}}},
    {"name": "enrol_session",
     "description": "Enrol a principal while the tenant is healthy: records subject, "
                    "audience, approved scopes and the device key used later for binding.",
     "inputSchema": {"type": "object", "properties": {
         "subject": {"type": "string"}, "audience": {"type": "string"},
         "scopes": {"type": "array", "items": {"type": "string"}},
         "device_key": {"type": "string"}},
         "required": ["subject", "audience", "scopes", "device_key"]}},
    {"name": "set_continuity_mode",
     "description": "Switch mode: healthy | degraded | drill. Tokens can only be minted "
                    "in degraded or drill.",
     "inputSchema": {"type": "object", "properties": {
         "mode": {"type": "string", "enum": ["healthy", "degraded", "drill"]},
         "reason": {"type": "string"}}, "required": ["mode"]}},
    {"name": "issue_local_token",
     "description": "Mint a short-lived continuity token for an enrolled session. Refuses "
                    "in healthy mode, refuses scope escalation, refuses privileged claims.",
     "inputSchema": {"type": "object", "properties": {
         "session_id": {"type": "string"}, "device_key": {"type": "string"},
         "scopes": {"type": "array", "items": {"type": "string"}},
         "ttl": {"type": "integer", "default": 900}, "aud": {"type": "string"}},
         "required": ["session_id", "device_key"]}},
    {"name": "verify_local_token",
     "description": "Verify a continuity token issued by this gateway.",
     "inputSchema": {"type": "object", "properties": {
         "token": {"type": "string"}, "aud": {"type": "string"}},
         "required": ["token"]}},
    {"name": "get_fallback_endpoint",
     "description": "The endpoint downstream services should use while degraded.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "reconcile_delta",
     "description": "Drain the local audit ledger for replay once the tenant recovers.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "get_beacon",
     "description": "Signed continuity beacon, served in every mode. Tells a downstream "
                    "service whether to use the cloud (authority=cloud) or this issuer "
                    "(authority=local), plus every endpoint it needs.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "probe_idp",
     "description": "Check the identity plane now (DNS, TLS, HTTP separately) and, if "
                    "automatic mode is on, transition the mode with hysteresis.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "set_auto_mode",
     "description": "Enable or disable automatic outage detection. When on, the monitor "
                    "degrades after 3 consecutive failures and recovers after 2 successes.",
     "inputSchema": {"type": "object", "properties": {
         "enabled": {"type": "boolean"}}, "required": ["enabled"]}},
    {"name": "admin_bootstrap",
     "description": "Bootstrap from a tenant administrator's Entra access token: binds the "
                    "tenant and returns a downstream API key (shown once). The caller must "
                    "hold an administrative directory role in that tenant.",
     "inputSchema": {"type": "object", "properties": {
         "admin_token": {"type": "string",
                         "description": "Entra access token for an admin account"},
         "label": {"type": "string"}}, "required": ["admin_token"]}},
]


def start_gateway(port: int = 8400) -> Dict[str, Any]:
    if _GATEWAY["server"] is not None:
        return {"already_running": True, "port": _GATEWAY["port"]}
    srv = serve_in_thread(STATE, port)
    _GATEWAY["server"], _GATEWAY["port"] = srv, port
    STATE._log("gateway_started", port=port)
    return {"running": True, "port": port,
            "issuer": f"http://127.0.0.1:{port}",
            "token_endpoint": f"http://127.0.0.1:{port}/token"}


def extra_call(name: str, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if name == "serve_gateway":
        return start_gateway(int(args.get("port", 8400)))

    if name == "enrol_session":
        s = STATE.enrol(args["subject"], args["audience"],
                        args["scopes"], args["device_key"])
        return {"session_id": s.id, "subject": s.subject, "audience": s.audience,
                "approved_scopes": s.approved_scopes,
                "note": "enrol while healthy; this session is what offline minting uses"}

    if name == "set_continuity_mode":
        STATE.set_mode(args["mode"], args.get("reason", ""))
        return STATE.status()

    if name == "issue_local_token":
        _require_minting()
        session = STATE.sessions.get(args["session_id"])
        if not session:
            raise KeyError("unknown_session")
        if not session.usable():
            raise PermissionError("session_revoked_or_expired")
        if not STATE.check_device(session, str(args.get("device_key", ""))):
            STATE._log("token_denied", reason="device_key_mismatch",
                       session=session.id)
            raise PermissionError("device_key_mismatch")

        requested_aud = args.get("aud")
        if requested_aud and requested_aud != session.audience:
            STATE._log("token_denied", reason="audience_override",
                       session=session.id, requested=str(requested_aud))
            raise PermissionError("audience_not_approved")

        from .tokens import mint
        tok = mint(subject=session.subject,
                   audience=session.audience,
                   approved_scopes=session.approved_scopes,
                   requested_scopes=args.get("scopes"),
                   key=STATE.key, ttl=int(args.get("ttl", 900)),
                   extra={"session": session.id},
                   device_thumbprint=session.device_hash[:32])
        STATE._log("token_issued", session=session.id, subject=session.subject,
                   scope=tok["scope"], ttl=tok["expires_in"])
        return tok

    if name == "verify_local_token":
        return verify(args["token"], STATE.key, audience=args.get("aud"))

    if name == "get_fallback_endpoint":
        port = _GATEWAY["port"] or 8400
        return {"issuer": f"http://127.0.0.1:{port}",
                "token_endpoint": f"http://127.0.0.1:{port}/token",
                "health": f"http://127.0.0.1:{port}/health",
                "mode": STATE.mode,
                "available": _GATEWAY["server"] is not None}

    if name == "reconcile_delta":
        return {"reconciled": STATE.drain_audit(), "seq": STATE.seq}

    if name == "get_beacon":
        port = _GATEWAY["port"] or 8400
        return build_beacon(STATE, base_url=f"http://127.0.0.1:{port}")

    if name == "probe_idp":
        return _monitor().tick()

    if name == "set_auto_mode":
        return _monitor().set_automatic(bool(args["enabled"]))

    if name == "admin_bootstrap":
        from .admin import verify_admin_claims
        from .gateway import KEYSTORE, decode_claims
        claims = decode_claims(str(args["admin_token"]))
        if claims is None:
            raise ValueError("admin_token is not a readable JWT")
        who = verify_admin_claims(claims, expected_tenant=STATE.tenant_id)
        if STATE.tenant_id is None:
            STATE.tenant_id = who["tenant_id"]
        plaintext, rec = KEYSTORE.issue(
            tenant_id=who["tenant_id"], label=str(args.get("label") or "downstream"),
            scopes=["continuity.read", "continuity.mint"],
            created_by=str(who["subject"]))
        STATE._log("bootstrap", tenant=who["tenant_id"], key_id=rec.id,
                   admin=who["admin_roles"], subject=who["subject"])
        return {"api_key": plaintext, "key_id": rec.id, "tenant_id": who["tenant_id"],
                "scopes": rec.scopes, "admin_roles": who["admin_roles"],
                "expires_at": rec.expires_at,
                "note": "shown once; store in your secret manager, never in config"}

    return None

"""Local continuity gateway — the downstream face of the fallback.

Downstream services point here instead of at login.microsoftonline.com when the tenant
declares an incident. Endpoints deliberately mirror the shapes they already speak:

    GET  /health                              -> mode + readiness
    GET  /.well-known/openid-configuration    -> local issuer metadata
    POST /token                               -> short-lived continuity token
    GET  /jwks.json                           -> signing key publication
    POST /reconcile                           -> drain the audit ledger

Everything is stdlib. Bind to loopback by default; this must never be internet-facing.
"""

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from .tokens import MAX_TTL_SECONDS, mint, verify
from .state import ContinuityState
from .hardening import MAX_BODY, RateLimiter
from .beacon import build_beacon, verify_beacon
from .admin import AdminBootstrapError, KeyStore, verify_admin_claims

RATE = RateLimiter()
KEYSTORE = KeyStore()


def decode_claims(jwt: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT payload WITHOUT verifying its signature.

    Signature verification is deliberately a separate hook
    (`verify_admin_claims(validator=...)`) so the omission is visible rather than implied.
    Output of this function alone is untrusted input.
    """
    try:
        parts = jwt.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def build_handler(state: ContinuityState, host_header: str = "127.0.0.1:8400"):
    class Handler(BaseHTTPRequestHandler):
        server_version = "continuity-local/0.1"

        def log_message(self, *a):  # keep stdout clean for MCP on the same process
            return

        def _send(self, code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            path = urlparse(self.path).path
            base = f"http://{host_header}"

            if path == "/health":
                self._send(200, {**state.status(), "ready": state.can_mint()})
                return

            if path == "/.well-known/openid-configuration":
                self._send(200, {
                    "issuer": "continuity-local",
                    "authorization_endpoint": f"{base}/authorize",
                    "token_endpoint": f"{base}/token",
                    "jwks_uri": f"{base}/jwks.json",
                    "id_token_signing_alg_values_supported": ["HS256"],
                    "xms_continuity_mode": state.mode,
                    "note": "local fallback issuer, only valid during a declared incident",
                })
                return

            if path == "/jwks.json":
                self._send(200, {
                    "keys": [],
                    "note": ("HS256 pre-shared key model: consumers receive the key at "
                             "enrolment. Production replaces this with asymmetric keys "
                             "and publishes the public half here."),
                })
                return

            # The beacon is served in EVERY mode, including healthy. It is read-only and
            # signed, and it is how a downstream service discovers the fallback at all.
            if path == "/.well-known/continuity-beacon.json":
                self._send(200, build_beacon(state, base_url=base))
                return

            self._send(404, {"error": "not_found", "path": path})

        def do_POST(self):  # noqa: N802
            path = urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                # Refuse before reading: an oversized body is a memory-exhaustion attempt.
                self._send(413, {"error": "body_too_large", "max": MAX_BODY})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send(400, {"error": "invalid_json"})
                return

            if path == "/admin/bootstrap":
                self._bootstrap()
                return
            if path == "/token":
                self._token(body)
                return
            if path == "/reconcile":
                self._send(200, {"reconciled": state.drain_audit(),
                                 "seq": state.seq, "mode": state.mode})
                return

            self._send(404, {"error": "not_found", "path": path})

        def _bootstrap(self) -> None:
            """Bind a tenant and issue the downstream API key from an admin's Entra token.

            This is the only route that accepts such a token, and the token's administrative
            role is the sole basis for issuing a key. The key returned is narrower: it can
            read continuity state and mint continuity tokens, and nothing else.
            """
            auth = self.headers.get("Authorization") or ""
            if not auth.startswith("Bearer "):
                self._send(401, {"error": "admin_token_required"})
                return

            claims = decode_claims(auth[7:].strip())
            if claims is None:
                self._send(401, {"error": "admin_token_unreadable"})
                return

            bound = getattr(state, "tenant_id", None)
            try:
                who = verify_admin_claims(claims, expected_tenant=bound)
            except AdminBootstrapError as e:
                state._log("bootstrap_denied", reason=str(e))
                self._send(403, {"error": "admin_not_authorised", "detail": str(e)})
                return

            if bound is None:
                state.tenant_id = who["tenant_id"]

            plaintext, rec = KEYSTORE.issue(
                tenant_id=who["tenant_id"], label="downstream",
                scopes=["continuity.read", "continuity.mint"],
                created_by=str(who["subject"]),
            )
            state._log("bootstrap", tenant=who["tenant_id"], key_id=rec.id,
                       admin=who["admin_roles"], subject=who["subject"])
            self._send(200, {
                "api_key": plaintext, "key_id": rec.id,
                "tenant_id": who["tenant_id"], "scopes": rec.scopes,
                "admin_roles": who["admin_roles"], "expires_at": rec.expires_at,
                "note": "shown once; store in your secret manager, never in config",
            })

        def _token(self, body: Dict[str, Any]) -> None:
            # Every mint requires a downstream API key, and that key can only exist because
            # a tenant administrator bootstrapped this gateway.
            presented = self.headers.get("X-API-Key") or ""
            key = KEYSTORE.verify(presented, tenant_id=getattr(state, "tenant_id", None))
            if key is None:
                state._log("token_denied", reason="api_key_invalid",
                           prefix=KEYSTORE.prefix_of(presented))
                self._send(401, {"error": "api_key_required"})
                return
            if "continuity.mint" not in key.scopes:
                state._log("token_denied", reason="api_key_scope", key_id=key.id)
                self._send(403, {"error": "api_key_lacks_mint_scope"})
                return

            if not state.can_mint():
                self._send(503, {"error": "not_in_continuity_mode", "mode": state.mode,
                                 "detail": "tokens are only issued during a declared incident"})
                return

            sid = str(body.get("session_id", ""))[:128]

            # Rate limit BEFORE any session lookup so unknown ids cannot be enumerated
            # quickly, and a short device key cannot be brute forced offline.
            allowed, remaining = RATE.allow(f"token:{sid or '-'}")
            if not allowed:
                state._log("rate_limited", session=sid)
                self._send(429, {"error": "rate_limited"})
                return

            session = state.sessions.get(sid)
            if not session:
                self._send(404, {"error": "unknown_session"})
                return
            if not session.usable():
                state._log("token_denied", reason="session_unusable", session=sid)
                self._send(403, {"error": "session_revoked_or_expired"})
                return

            # Hardware binding — constant-time comparison against the stored hash.
            if not state.check_device(session, str(body.get("device_key", ""))):
                state._log("token_denied", reason="device_key_mismatch", session=sid)
                self._send(403, {"error": "device_key_mismatch"})
                return

            # Audience is fixed by the enrolment. A caller must not be able to mint a
            # token for an audience the session was never approved for.
            requested_aud = body.get("aud")
            if requested_aud and requested_aud != session.audience:
                state._log("token_denied", reason="audience_override", session=sid,
                           requested=str(requested_aud))
                self._send(403, {"error": "audience_not_approved",
                                 "approved": session.audience})
                return

            try:
                ttl = int(body.get("ttl", 900))
            except (TypeError, ValueError):
                self._send(400, {"error": "invalid_ttl"})
                return
            if ttl > MAX_TTL_SECONDS:
                self._send(400, {"error": "ttl_too_long", "max": MAX_TTL_SECONDS})
                return

            try:
                tok = mint(subject=session.subject,
                           audience=session.audience,
                           approved_scopes=session.approved_scopes,
                           requested_scopes=body.get("scopes"),
                           key=state.key, ttl=ttl,
                           extra={"session": sid},
                           device_thumbprint=session.device_hash[:32])
            except ValueError as e:
                state._log("token_denied", reason=str(e), session=sid)
                self._send(403, {"error": "refused", "detail": str(e)})
                return

            state._log("token_issued", session=sid, subject=session.subject,
                       scope=tok["scope"], ttl=ttl, remaining_quota=remaining)
            self._send(200, tok)

    return Handler


def serve_in_thread(state: ContinuityState, port: int = 8400) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), build_handler(state, f"127.0.0.1:{port}"))
    import threading
    t = threading.Thread(target=srv.serve_forever, daemon=True, name="continuity-gateway")
    t.start()
    return srv

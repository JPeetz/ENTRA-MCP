"""Adversarial tests. Each case performs an attack and asserts it is refused.

These are the tests that matter for the security claims: if one fails, a guard is
decorative.
"""

import base64
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuity import downstream                                    # noqa: E402
from continuity.hardening import AuditChain, RateLimiter             # noqa: E402
from continuity.state import ContinuityState                         # noqa: E402
from continuity.tokens import mint, verify                           # noqa: E402

PORT = 8421


def _reset():
    srv = downstream._GATEWAY.get("server")
    if srv is not None:
        try:
            srv.shutdown()
            srv.server_close()
        except Exception:
            pass
    downstream.STATE = ContinuityState()
    downstream._GATEWAY["server"] = None
    downstream._GATEWAY["port"] = None


def _post(path, payload, port=PORT, raw=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 headers={"Content-Type": "application/json",
                                          "X-API-Key": _api_key()})
    return json.load(urllib.request.urlopen(req, timeout=5))


_API_KEY = None


def _api_key():
    """A downstream key minted the way production mints it — via an admin bootstrap.

    These tests are attacks from a caller who *has* a key; the keyless case is covered
    separately in test_admin.py.
    """
    global _API_KEY
    if _API_KEY is None:
        from continuity.gateway import KEYSTORE
        _API_KEY, _ = KEYSTORE.issue(tenant_id="test-tenant", label="tests",
                                     scopes=["continuity.read", "continuity.mint"],
                                     created_by="tests")
    return _API_KEY


class TestAttacks(unittest.TestCase):
    def setUp(self):
        _reset()
        downstream.extra_call("serve_gateway", {"port": PORT})
        s = downstream.extra_call("enrol_session", {
            "subject": "monk@ordo", "audience": "api://ordo",
            "scopes": ["read"], "device_key": "dev-key-1"})
        self.sid = s["session_id"]
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})

    # A1 — mint a token for an audience the session was never approved for
    def test_audience_override_refused_http(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _post("/token", {"session_id": self.sid, "device_key": "dev-key-1",
                             "aud": "api://attacker"})
        self.assertEqual(ctx.exception.code, 403)

    def test_audience_override_refused_mcp(self):
        with self.assertRaises(PermissionError):
            downstream.extra_call("issue_local_token", {
                "session_id": self.sid, "device_key": "dev-key-1",
                "aud": "api://attacker"})

    # A2 — device key must not be recoverable from the stored session
    def test_device_key_not_stored_in_clear(self):
        session = downstream.STATE.sessions[self.sid]
        self.assertFalse(hasattr(session, "device_key"),
                         "plaintext device key attribute must not exist")
        self.assertTrue(session.device_hash.startswith(("0", "1", "2", "3", "4", "5",
                                                        "6", "7", "8", "9", "a", "b",
                                                        "c", "d", "e", "f")))
        self.assertNotIn("dev-key-1", session.device_hash)

    # A3 — an expired enrolment cannot mint
    def test_expired_session_refused(self):
        s = downstream.STATE.enrol("x@y", "api://ordo", ["read"], "k", ttl_seconds=-1)
        with self.assertRaises(PermissionError):
            downstream.extra_call("issue_local_token", {
                "session_id": s.id, "device_key": "k"})

    # A4 — revoked session cannot mint
    def test_revoked_session_refused(self):
        downstream.STATE.revoke(self.sid)
        with self.assertRaises(PermissionError):
            downstream.extra_call("issue_local_token", {
                "session_id": self.sid, "device_key": "dev-key-1"})

    # A5 — algorithm confusion: alg=none token must be refused
    def test_alg_none_token_refused(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "iss": "continuity-local", "sub": "attacker", "aud": "api://ordo",
            "exp": int(time.time()) + 600, "xms_continuity": True}).encode()).rstrip(b"=")
        forged = f"{header.decode()}.{payload.decode()}."
        result = verify(forged, downstream.STATE.key)
        self.assertFalse(result["valid"])

    # A6 — tampered audit chain is detectable
    def test_audit_tampering_detected(self):
        entries = downstream.STATE.drain_audit()
        self.assertTrue(entries)
        self.assertTrue(downstream.STATE.verify_audit(entries))
        tampered = [dict(e) for e in entries]
        tampered[0]["subject"] = "someone-else"
        self.assertFalse(downstream.STATE.verify_audit(tampered),
                         "edited entry must break the chain")

    def test_audit_deletion_detected(self):
        entries = downstream.STATE.drain_audit()
        if len(entries) < 2:
            entries.append(downstream.STATE.audit.append("filler"))
        self.assertFalse(downstream.STATE.verify_audit(entries[1:]),
                         "removing an entry must break the chain")

    # A7 — brute force on the device key is throttled
    def test_rate_limit_blocks_bruteforce(self):
        rl = RateLimiter(max_events=3, window=60)
        for _ in range(3):
            self.assertTrue(rl.allow("s1")[0])
        allowed, _ = rl.allow("s1")
        self.assertFalse(allowed)

    # A8 — oversized body is refused before it is read
    def test_body_too_large_refused(self):
        blob = b'{"padding":"' + b"A" * 40000 + b'"}'
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _post("/token", None, raw=blob)
        self.assertEqual(ctx.exception.code, 413)

    # A9 — token carries proof-of-possession binding
    def test_token_bound_to_device(self):
        tok = downstream.extra_call("issue_local_token", {
            "session_id": self.sid, "device_key": "dev-key-1"})
        claims = verify(tok["access_token"], downstream.STATE.key)["claims"]
        self.assertIn("cnf", claims)
        self.assertIn("jkt", claims["cnf"])

    # A10 — privileged claims cannot be smuggled through `extra`
    def test_privileged_claim_refused(self):
        with self.assertRaises(ValueError):
            mint(subject="x", audience="a", approved_scopes=["read"],
                 requested_scopes=["read"], key=downstream.STATE.key,
                 extra={"roles": ["Global Administrator"]})


class TestHardeningPrimitives(unittest.TestCase):
    def test_audit_chain_detects_first_entry_edit(self):
        chain = AuditChain()
        chain.append("a")
        chain.append("b")
        entries = chain.drain()
        entries[0]["event"] = "evil"
        self.assertFalse(AuditChain().verify(entries))

    def test_rate_limiter_window_expiry(self):
        rl = RateLimiter(max_events=1, window=1)
        self.assertTrue(rl.allow("k", now=100.0)[0])
        self.assertFalse(rl.allow("k", now=100.5)[0])
        self.assertTrue(rl.allow("k", now=102.0)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for the downstream fallback: sessions, minting guards, and the HTTP gateway."""

import json
import os
import sys
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuity import downstream                                  # noqa: E402
from continuity.state import ContinuityState                       # noqa: E402

_KEY = None


def _api_key():
    """Downstream key, minted the way production mints it: via an admin bootstrap."""
    global _KEY
    if _KEY is None:
        from continuity.gateway import KEYSTORE
        _KEY, _ = KEYSTORE.issue(tenant_id="test-tenant", label="tests",
                                 scopes=["continuity.read", "continuity.mint"],
                                 created_by="tests")
    return _KEY


def _reset() -> None:
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


class TestFallback(unittest.TestCase):
    def setUp(self):
        _reset()

    def _enrol(self):
        return downstream.extra_call("enrol_session", {
            "subject": "monk@ordo", "audience": "api://ordo",
            "scopes": ["read", "write"], "device_key": "dev-abc"})

    def test_minting_refused_while_healthy(self):
        self._enrol()
        with self.assertRaises(PermissionError):
            downstream.extra_call("issue_local_token", {
                "session_id": "x", "device_key": "dev-abc"})

    def test_mint_after_degrade(self):
        s = self._enrol()
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        tok = downstream.extra_call("issue_local_token", {
            "session_id": s["session_id"], "device_key": "dev-abc"})
        self.assertIn("access_token", tok)
        self.assertEqual(tok["expires_in"], 900)
        v = downstream.extra_call("verify_local_token", {"token": tok["access_token"]})
        self.assertTrue(v["valid"], v.get("reasons"))
        self.assertTrue(v["claims"]["xms_continuity"])

    def test_scope_escalation_refused(self):
        s = self._enrol()
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        with self.assertRaises(ValueError):
            downstream.extra_call("issue_local_token", {
                "session_id": s["session_id"], "device_key": "dev-abc",
                "scopes": ["read", "admin.everything"]})

    def test_privileged_scope_refused(self):
        downstream.extra_call("enrol_session", {
            "subject": "x", "audience": "a",
            "scopes": ["Directory.ReadWrite.All"], "device_key": "k"})
        sid = list(downstream.STATE.sessions)[0]
        downstream.extra_call("set_continuity_mode", {"mode": "drill"})
        with self.assertRaises(ValueError):
            downstream.extra_call("issue_local_token", {
                "session_id": sid, "device_key": "k"})

    def test_device_key_mismatch_refused(self):
        s = self._enrol()
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        with self.assertRaises(PermissionError):
            downstream.extra_call("issue_local_token", {
                "session_id": s["session_id"], "device_key": "wrong"})

    def test_ttl_cap(self):
        s = self._enrol()
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        tok = downstream.extra_call("issue_local_token", {
            "session_id": s["session_id"], "device_key": "dev-abc", "ttl": 99999})
        self.assertLessEqual(tok["expires_in"], 3600)

    def test_gateway_http_flow(self):
        s = self._enrol()
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        info = downstream.extra_call("serve_gateway", {"port": 8411})
        self.assertTrue(info["running"])

        health = json.load(urllib.request.urlopen("http://127.0.0.1:8411/health", timeout=5))
        self.assertEqual(health["mode"], "degraded")
        self.assertTrue(health["ready"])

        req = urllib.request.Request(
            "http://127.0.0.1:8411/token",
            data=json.dumps({"session_id": s["session_id"], "device_key": "dev-abc",
                             "scopes": ["read"]}).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": _api_key()})
        tok = json.load(urllib.request.urlopen(req, timeout=5))
        self.assertEqual(tok["scope"], "read")

        # healthy mode must close the door again
        downstream.extra_call("set_continuity_mode", {"mode": "healthy"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 503)

        rec = json.load(urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8411/reconcile", data=b"{}",
            headers={"Content-Type": "application/json"}), timeout=5))
        events = [e["event"] for e in rec["reconciled"]]
        self.assertIn("token_issued", events)
        self.assertIn("mode", events)

    def test_discovery_document(self):
        downstream.extra_call("serve_gateway", {"port": 8412})
        d = json.load(urllib.request.urlopen(
            "http://127.0.0.1:8412/.well-known/openid-configuration", timeout=5))
        self.assertEqual(d["issuer"], "continuity-local")
        self.assertIn("xms_continuity_mode", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)

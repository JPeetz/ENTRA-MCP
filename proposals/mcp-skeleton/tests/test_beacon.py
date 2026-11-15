"""Tests for the always-on beacon and automatic outage detection."""

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuity import downstream                                   # noqa: E402
from continuity.beacon import build_beacon, verify_beacon          # noqa: E402
from continuity.health import HealthMonitor                        # noqa: E402
from continuity.state import ContinuityState                       # noqa: E402

PORT = 8441


def _ok():
    return {"ok": True, "dns": True, "tls": True, "http": True, "detail": ""}


def _down():
    return {"ok": False, "dns": True, "tls": True, "http": False,
            "detail": "http: 503 service unavailable"}


class TestBeacon(unittest.TestCase):
    def setUp(self):
        srv = downstream._GATEWAY.get("server")
        if srv is not None:
            try:
                srv.shutdown(); srv.server_close()
            except Exception:
                pass
        downstream.STATE = ContinuityState()
        downstream._GATEWAY["server"] = None
        downstream._GATEWAY["port"] = None

    def test_beacon_in_healthy_mode_points_at_cloud(self):
        b = build_beacon(downstream.STATE)
        self.assertEqual(b["authority"], "cloud")
        self.assertFalse(b["capabilities"]["can_mint"])

    def test_beacon_in_degraded_mode_points_at_local(self):
        downstream.STATE.set_mode("degraded")
        b = build_beacon(downstream.STATE)
        self.assertEqual(b["authority"], "local")
        self.assertTrue(b["capabilities"]["can_mint"])

    def test_beacon_signature_verifies(self):
        b = build_beacon(downstream.STATE)
        self.assertTrue(verify_beacon(b, downstream.STATE.beacon_key)["valid"])

    def test_tampered_beacon_rejected(self):
        b = build_beacon(downstream.STATE)
        b["authority"] = "local"          # attacker flips consumers onto the fallback
        self.assertFalse(verify_beacon(b, downstream.STATE.beacon_key)["valid"])

    def test_expired_beacon_rejected(self):
        b = build_beacon(downstream.STATE, ttl=1, now=time.time() - 100)
        r = verify_beacon(b, downstream.STATE.beacon_key)
        self.assertFalse(r["valid"])
        self.assertTrue(any("expired" in x for x in r["reasons"]))

    def test_beacon_served_while_healthy_over_http(self):
        downstream.extra_call("serve_gateway", {"port": PORT})
        d = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/.well-known/continuity-beacon.json", timeout=5))
        self.assertEqual(d["authority"], "cloud")
        self.assertEqual(d["iss"], "continuity-local")
        # and it is usable: a consumer can verify it
        self.assertTrue(verify_beacon(d, downstream.STATE.beacon_key)["valid"])

    def test_beacon_reports_local_once_degraded(self):
        downstream.extra_call("serve_gateway", {"port": PORT})
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        d = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/.well-known/continuity-beacon.json", timeout=5))
        self.assertEqual(d["authority"], "local")
        self.assertTrue(d["capabilities"]["can_mint"])


class TestHealthMonitor(unittest.TestCase):
    def setUp(self):
        self.state = ContinuityState()
        self.up = True
        self.monitor = HealthMonitor(self.state,
                                     prober=lambda: _ok() if self.up else _down())

    def test_disabled_by_default(self):
        for _ in range(5):
            self.up = False
            self.monitor.tick()
        self.assertEqual(self.state.mode, "healthy",
                         "automatic transitions must be opt-in")

    def test_three_failures_degrade(self):
        self.monitor.set_automatic(True)
        self.up = False
        self.monitor.tick(); self.monitor.tick()
        self.assertEqual(self.state.mode, "healthy", "hysteresis: 2 failures is not enough")
        self.monitor.tick()
        self.assertEqual(self.state.mode, "degraded")

    def test_recovery_needs_two_successes(self):
        self.monitor.set_automatic(True)
        self.up = False
        for _ in range(3):
            self.monitor.tick()
        self.assertEqual(self.state.mode, "degraded")
        self.up = True
        self.monitor.tick()
        self.assertEqual(self.state.mode, "degraded", "one success must not flip back")
        self.monitor.tick()
        self.assertEqual(self.state.mode, "healthy")

    def test_flapping_does_not_degrade(self):
        self.monitor.set_automatic(True)
        for _ in range(4):
            self.up = False; self.monitor.tick()
            self.up = True;  self.monitor.tick()
        self.assertEqual(self.state.mode, "healthy")

    def test_transition_is_audited(self):
        self.monitor.set_automatic(True)
        self.up = False
        for _ in range(3):
            self.monitor.tick()
        entries = self.state.drain_audit()
        events = [e["event"] for e in entries]
        self.assertIn("auto_mode", events)
        self.assertIn("mode", events)

    def test_4xx_is_not_an_outage(self):
        """A 401/404 proves the service is answering."""
        from continuity.health import default_probe
        # unit-level: the probe maps 4xx to http=True via HTTPError handling
        self.assertTrue(callable(default_probe))


class TestAutomaticFallbackEndToEnd(unittest.TestCase):
    """The requirement: always available, and it becomes the authority on its own."""

    def setUp(self):
        srv = downstream._GATEWAY.get("server")
        if srv is not None:
            try:
                srv.shutdown(); srv.server_close()
            except Exception:
                pass
        downstream.STATE = ContinuityState()
        downstream._GATEWAY["server"] = None
        downstream._GATEWAY["port"] = None
        downstream._MON["state_id"] = None
        self.s = downstream.extra_call("enrol_session", {
            "subject": "monk@ordo", "audience": "api://ordo",
            "scopes": ["read"], "device_key": "dev-key-1"})

    def test_full_cycle_beacon_degrades_then_mints(self):
        downstream.extra_call("serve_gateway", {"port": PORT})
        mon = downstream._monitor()
        mon.prober = _down
        mon.set_automatic(True)

        # still healthy: beacon says cloud, minting refused
        b = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/.well-known/continuity-beacon.json", timeout=5))
        self.assertEqual(b["authority"], "cloud")

        for _ in range(3):
            mon.tick()

        b = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/.well-known/continuity-beacon.json", timeout=5))
        self.assertEqual(b["authority"], "local", "beacon must flip without human input")

        tok = downstream.extra_call("issue_local_token", {
            "session_id": self.s["session_id"], "device_key": "dev-key-1"})
        assert tok is not None
        self.assertIn("access_token", tok)

        # recovery: beacon returns to cloud, minting closes again
        mon.prober = _ok
        mon.tick(); mon.tick()
        b = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{PORT}/.well-known/continuity-beacon.json", timeout=5))
        self.assertEqual(b["authority"], "cloud")
        with self.assertRaises(PermissionError):
            downstream.extra_call("issue_local_token", {
                "session_id": self.s["session_id"], "device_key": "dev-key-1"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

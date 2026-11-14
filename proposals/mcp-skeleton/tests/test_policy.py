"""Tests for the policy evaluator and snapshot verification.

Run from proposals/mcp-skeleton:  python3 -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuity.policy import evaluate, explain                       # noqa: E402
from continuity.snapshot import diff_policy, make_snapshot, verify_snapshot  # noqa: E402

POLICIES = [
    {"id": "CA001", "state": "enabled", "operator": "OR", "controls": ["require_mfa"]},
    {"id": "CA002", "state": "enabled", "include_groups": ["finance"],
     "client_apps": ["exchangeActiveSync"], "controls": ["block"]},
    {"id": "CA003", "state": "enabled", "include_apps": ["admin-portal"],
     "operator": "AND", "controls": ["require_compliant_device", "require_mfa"]},
    {"id": "CA004", "state": "reportOnly", "controls": ["block"]},
]


class TestEvaluate(unittest.TestCase):
    def test_no_policies_allows(self):
        self.assertEqual(evaluate([], {"user_id": "u1"})["decision"], "allow")

    def test_disabled_policy_ignored(self):
        pols = [{"id": "X", "state": "disabled", "controls": ["block"]}]
        self.assertEqual(evaluate(pols, {"user_id": "u1"})["decision"], "allow")

    def test_mfa_challenge_when_not_performed(self):
        r = evaluate([POLICIES[0]], {"user_id": "u1"})
        self.assertEqual(r["decision"], "mfa")
        self.assertIn("require_mfa", r["missing"])

    def test_allow_when_mfa_performed(self):
        r = evaluate([POLICIES[0]], {"user_id": "u1", "mfa_performed": True})
        self.assertEqual(r["decision"], "allow")

    def test_block_wins(self):
        ctx = {"user_id": "u1", "groups": ["finance"], "client_app": "exchangeActiveSync",
               "mfa_performed": True}
        r = evaluate(POLICIES, ctx)
        self.assertEqual(r["decision"], "deny")
        self.assertIn("blocked by policy CA002", " ".join(r["reasons"]))

    def test_block_does_not_apply_outside_group(self):
        ctx = {"user_id": "u1", "groups": ["sales"], "client_app": "exchangeActiveSync",
               "mfa_performed": True}
        self.assertNotEqual(evaluate(POLICIES, ctx)["decision"], "deny")

    def test_exclusion_beats_inclusion(self):
        pols = [{"id": "E", "state": "enabled", "include_groups": ["staff"],
                 "exclude_users": ["ceo"], "controls": ["block"]}]
        self.assertEqual(evaluate(pols, {"user_id": "ceo", "groups": ["staff"]})["decision"],
                         "allow")

    def test_and_operator_requires_all_controls(self):
        ctx = {"user_id": "u1", "app_id": "admin-portal",
               "mfa_performed": True, "device_compliant": False}
        r = evaluate([POLICIES[2]], ctx)
        self.assertEqual(r["decision"], "deny")
        self.assertEqual(r["missing"], ["require_compliant_device"])

    def test_and_operator_all_satisfied(self):
        ctx = {"user_id": "u1", "app_id": "admin-portal",
               "mfa_performed": True, "device_compliant": True}
        self.assertEqual(evaluate([POLICIES[2]], ctx)["decision"], "allow")

    def test_report_only_does_not_enforce(self):
        self.assertEqual(evaluate([POLICIES[3]], {"user_id": "u1"})["decision"], "allow")

    def test_explain_trace_mentions_each_policy(self):
        trace = explain(POLICIES, {"user_id": "u1"})
        self.assertEqual(len(trace), len(POLICIES))
        self.assertTrue(any("CA002: not applicable" in line for line in trace))


class TestSnapshot(unittest.TestCase):
    def test_valid_snapshot(self):
        snap = make_snapshot(POLICIES, seq=5)
        r = verify_snapshot(snap, min_seq=1)
        self.assertTrue(r["valid"], r["reasons"])

    def test_expired_snapshot(self):
        snap = make_snapshot(POLICIES, seq=5, now=time.time() - 100 * 3600, ttl_hours=1)
        r = verify_snapshot(snap)
        self.assertFalse(r["valid"])
        self.assertTrue(any("expired" in x for x in r["reasons"]))

    def test_tampered_snapshot(self):
        snap = make_snapshot(POLICIES, seq=5)
        snap["policies"].append({"id": "INJECTED", "state": "enabled", "controls": []})
        r = verify_snapshot(snap)
        self.assertFalse(r["valid"])
        self.assertTrue(any("signature" in x for x in r["reasons"]))

    def test_stale_sequence(self):
        snap = make_snapshot(POLICIES, seq=2)
        r = verify_snapshot(snap, min_seq=10)
        self.assertFalse(r["valid"])
        self.assertTrue(any("stale sequence" in x for x in r["reasons"]))

    def test_diff_detects_change(self):
        snap = make_snapshot(POLICIES, seq=5)
        live = {"policies": [dict(p) for p in POLICIES]}
        live["policies"][0]["controls"] = ["require_mfa", "require_compliant_device"]
        live["policies"].append({"id": "NEW", "state": "enabled", "controls": []})
        d = diff_policy(live, snap)
        self.assertIn("NEW", d["added"])
        self.assertIn("CA001", d["changed"])
        self.assertEqual(d["removed"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

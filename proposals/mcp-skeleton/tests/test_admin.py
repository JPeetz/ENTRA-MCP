"""Admin bootstrap — the requirement: a tenant administrator's Entra account bootstraps
the gateway and receives an API key for downstream use.

These tests cover both halves: who is allowed to bootstrap, and what the resulting key
can and cannot do.
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
from continuity.admin import AdminBootstrapError, KeyStore, verify_admin_claims  # noqa: E402
from continuity.gateway import KEYSTORE                              # noqa: E402
from continuity.state import ContinuityState                         # noqa: E402

PORT = 8451
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def make_jwt(claims):
    """Build an unsigned JWT with arbitrary claims. Signature checking is a separate
    hook and is exercised explicitly below."""
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256', 'typ': 'JWT'})}.{enc(claims)}.sig"


def admin_claims(**over):
    base = {"tid": "11111111-2222-3333-4444-555555555555", "oid": "admin-oid-1",
            "exp": int(time.time()) + 3600, "wids": [GLOBAL_ADMIN], "roles": []}
    base.update(over)
    return base


def post(path, payload=None, headers=None, port=PORT):
    data = json.dumps(payload or {}).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h)
    return urllib.request.urlopen(req, timeout=5)


def post_status(path, payload=None, headers=None, port=PORT):
    try:
        r = post(path, payload, headers, port)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class TestAdminClaimChecks(unittest.TestCase):
    def test_global_admin_accepted(self):
        who = verify_admin_claims(admin_claims())
        self.assertEqual(who["tenant_id"], "11111111-2222-3333-4444-555555555555")
        self.assertIn("Global Administrator", who["admin_roles"])

    def test_role_name_in_roles_claim_accepted(self):
        who = verify_admin_claims(admin_claims(wids=[], roles=["Cloud Application Administrator"]))
        self.assertIn("Cloud Application Administrator", who["admin_roles"])

    def test_non_admin_refused(self):
        with self.assertRaises(AdminBootstrapError) as c:
            verify_admin_claims(admin_claims(wids=[], roles=["Directory Readers"]))
        self.assertIn("no administrative directory role", str(c.exception))

    def test_expired_admin_token_refused(self):
        with self.assertRaises(AdminBootstrapError) as c:
            verify_admin_claims(admin_claims(exp=int(time.time()) - 10))
        self.assertIn("expired", str(c.exception))

    def test_continuity_token_cannot_bootstrap(self):
        """A token this system issued must never be usable to widen its own authority."""
        with self.assertRaises(AdminBootstrapError) as c:
            verify_admin_claims(admin_claims(xms_continuity=True))
        self.assertIn("continuity token used as an admin credential", str(c.exception))

    def test_tenant_binding_enforced(self):
        with self.assertRaises(AdminBootstrapError) as c:
            verify_admin_claims(admin_claims(), expected_tenant="other-tenant-id")
        self.assertIn("tenant mismatch", str(c.exception))

    def test_missing_tid_refused(self):
        c = admin_claims()
        c.pop("tid")
        with self.assertRaises(AdminBootstrapError):
            verify_admin_claims(c)

    def test_signature_hook_is_fail_closed(self):
        with self.assertRaises(AdminBootstrapError) as c:
            verify_admin_claims(admin_claims(), validator=lambda _c: False)
        self.assertIn("signature validation failed", str(c.exception))


class TestKeyStore(unittest.TestCase):
    def test_plaintext_key_is_not_stored(self):
        ks = KeyStore()
        plaintext, rec = ks.issue("t1", "lbl", ["continuity.mint"], "admin")
        self.assertTrue(plaintext.startswith("ok_"))
        self.assertNotIn(plaintext, rec.key_hash)
        self.assertNotIn(plaintext, repr(ks.keys))

    def test_verify_accepts_issued_key(self):
        ks = KeyStore()
        plaintext, rec = ks.issue("t1", "lbl", ["continuity.mint"], "admin")
        self.assertEqual(ks.verify(plaintext).id, rec.id)

    def test_verify_rejects_random_key(self):
        ks = KeyStore()
        ks.issue("t1", "lbl", ["continuity.mint"], "admin")
        self.assertIsNone(ks.verify("ok_not-a-real-key"))

    def test_revoked_key_rejected(self):
        ks = KeyStore()
        plaintext, rec = ks.issue("t1", "lbl", ["continuity.mint"], "admin")
        ks.revoke(rec.id)
        self.assertIsNone(ks.verify(plaintext))

    def test_tenant_mismatch_rejected(self):
        ks = KeyStore()
        plaintext, _ = ks.issue("t1", "lbl", ["continuity.mint"], "admin")
        self.assertIsNone(ks.verify(plaintext, tenant_id="t2"))


class TestBootstrapOverHttp(unittest.TestCase):
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
        downstream.extra_call("serve_gateway", {"port": PORT})
        self.s = downstream.extra_call("enrol_session", {
            "subject": "monk@ordo", "audience": "api://ordo",
            "scopes": ["read"], "device_key": "dev-key-1"})
        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})

    def test_bootstrap_without_token_refused(self):
        code, body = post_status("/admin/bootstrap")
        self.assertEqual(code, 401)
        self.assertEqual(body["error"], "admin_token_required")

    def test_bootstrap_with_non_admin_token_refused(self):
        tok = make_jwt(admin_claims(wids=[], roles=[]))
        code, body = post_status("/admin/bootstrap", headers={"Authorization": f"Bearer {tok}"})
        self.assertEqual(code, 403)
        self.assertEqual(body["error"], "admin_not_authorised")

    def test_bootstrap_issues_key_and_binds_tenant(self):
        tok = make_jwt(admin_claims())
        code, body = post_status("/admin/bootstrap", headers={"Authorization": f"Bearer {tok}"})
        self.assertEqual(code, 200)
        self.assertTrue(body["api_key"].startswith("ok_"))
        self.assertIn("continuity.mint", body["scopes"])
        self.assertEqual(body["tenant_id"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(downstream.STATE.tenant_id, body["tenant_id"])

    def test_key_mints_and_keyless_caller_cannot(self):
        tok = make_jwt(admin_claims())
        _, boot = post_status("/admin/bootstrap", headers={"Authorization": f"Bearer {tok}"})
        key = boot["api_key"]

        code, _ = post_status("/token", {"session_id": self.s["session_id"],
                                         "device_key": "dev-key-1"})
        self.assertEqual(code, 401, "no key must mean no token")

        code, body = post_status("/token",
                                 {"session_id": self.s["session_id"], "device_key": "dev-key-1"},
                                 headers={"X-API-Key": key})
        self.assertEqual(code, 200)
        self.assertIn("access_token", body)

    def test_revoked_key_stops_minting(self):
        tok = make_jwt(admin_claims())
        _, boot = post_status("/admin/bootstrap", headers={"Authorization": f"Bearer {tok}"})
        KEYSTORE.revoke(boot["key_id"])
        code, body = post_status("/token",
                                 {"session_id": self.s["session_id"], "device_key": "dev-key-1"},
                                 headers={"X-API-Key": boot["api_key"]})
        self.assertEqual(code, 401)
        self.assertEqual(body["error"], "api_key_required")

    def test_second_tenant_cannot_rebind(self):
        tok_a = make_jwt(admin_claims())
        post_status("/admin/bootstrap", headers={"Authorization": f"Bearer {tok_a}"})
        tok_b = make_jwt(admin_claims(tid="99999999-0000-0000-0000-000000000000"))
        code, body = post_status("/admin/bootstrap",
                                 headers={"Authorization": f"Bearer {tok_b}"})
        self.assertEqual(code, 403)
        self.assertIn("tenant mismatch", body["detail"])

    def test_bootstrap_is_audited_without_secret(self):
        tok = make_jwt(admin_claims())
        post_status("/admin/bootstrap", headers={"Authorization": f"Bearer {tok}"})
        events = downstream.STATE.drain_audit()
        boot = [e for e in events if e["event"] == "bootstrap"]
        self.assertTrue(boot)
        blob = json.dumps(events)
        self.assertNotIn("ok_", blob, "the API key must never reach the audit ledger")


if __name__ == "__main__":
    unittest.main(verbosity=2)

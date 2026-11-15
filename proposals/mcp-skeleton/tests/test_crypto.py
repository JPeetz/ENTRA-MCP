"""Cryptographic hardening tests.

Covers the three things that were previously asserted in prose and are now asserted in
code: key separation, real RS256 verification of admin tokens, and replay refusal.
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuity.crypto import (                                      # noqa: E402
    ReplayCache, b64u_encode, derive, rsa_verify_pkcs1v15_sha256,
    verify_rs256)
from continuity.hardening import AuditChain                          # noqa: E402
from continuity.state import ContinuityState                         # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
with open(os.path.join(FIXTURES, "jwks.json")) as _fh:
    JWKS = json.load(_fh)
with open(os.path.join(FIXTURES, "tokens.json")) as _fh:
    TOKENS = json.load(_fh)
NOW = TOKENS["_now"]


class TestKeySeparation(unittest.TestCase):
    def test_purposes_derive_different_keys(self):
        master = b"x" * 32
        keys = {p: derive(master, p) for p in ("token-signing", "beacon", "audit")}
        self.assertEqual(len(set(keys.values())), 3)

    def test_derivation_is_deterministic(self):
        self.assertEqual(derive(b"m", "beacon"), derive(b"m", "beacon"))

    def test_different_masters_differ(self):
        self.assertNotEqual(derive(b"a", "beacon"), derive(b"b", "beacon"))

    def test_state_exposes_separate_keys(self):
        s = ContinuityState()
        self.assertEqual(len({s.key, s.beacon_key, s.audit_key, s.salt}), 4)

    def test_beacon_key_cannot_verify_tokens(self):
        """A leaked beacon key must not be usable against the token surface."""
        from continuity.tokens import mint, verify
        s = ContinuityState()
        tok = mint("u", "aud", ["read"], None, key=s.key)
        self.assertFalse(verify(tok["access_token"], s.beacon_key)["valid"])
        self.assertTrue(verify(tok["access_token"], s.key)["valid"])


class TestAuditChainKeyed(unittest.TestCase):
    def test_chain_valid_with_matching_key(self):
        chain = AuditChain(key=b"k")
        chain.append("a", x=1)
        chain.append("b", y=2)
        self.assertTrue(chain.verify(chain.drain()))

    def test_foreign_key_cannot_forge_history(self):
        """Full write access is not enough: without the audit key, a rebuilt chain fails."""
        chain = AuditChain(key=b"real-key")
        entries = [chain.append("a", x=1), chain.append("b", y=2)]
        forger = AuditChain(key=b"attacker-key")
        forged = []
        prev = AuditChain.GENESIS
        for e in entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            body["prev"] = prev
            mac = forger._mac(prev, repr(sorted(body.items())).encode())
            forged.append({**body, "hash": mac})
            prev = mac
        verifier = AuditChain(key=b"real-key")
        self.assertFalse(verifier.verify(forged), "forged chain must not verify")

    def test_edit_breaks_chain(self):
        chain = AuditChain(key=b"k")
        entries = [chain.append("a", x=1), chain.append("b", y=2)]
        entries[0]["x"] = 999
        self.assertFalse(chain.verify(entries))


class TestRS256(unittest.TestCase):
    """Real signatures produced by a real RSA key (fixtures generated with openssl)."""

    def test_valid_token_accepted(self):
        r = verify_rs256(TOKENS["valid"], JWKS, now=NOW)
        self.assertTrue(r["valid"], r.get("reasons"))
        self.assertEqual(r["claims"]["tid"], "11111111-2222-3333-4444-555555555555")

    def test_expired_token_refused(self):
        r = verify_rs256(TOKENS["expired"], JWKS, now=NOW)
        self.assertFalse(r["valid"])
        self.assertIn("token expired", r["reasons"])

    def test_unknown_kid_refused(self):
        r = verify_rs256(TOKENS["wrongkid"], JWKS, now=NOW)
        self.assertFalse(r["valid"])
        self.assertIn("unknown kid", r["reasons"][0])

    def test_tampered_payload_refused(self):
        r = verify_rs256(TOKENS["tampered"], JWKS, now=NOW)
        self.assertFalse(r["valid"])
        self.assertEqual(r["reasons"], ["signature mismatch"])

    def test_alg_none_refused(self):
        """The classic JWT bypass: strip the signature and claim alg=none."""
        header = b64u_encode(json.dumps({"alg": "none", "kid": "test-kid"}).encode())
        payload = TOKENS["valid"].split(".")[1]
        r = verify_rs256(f"{header}.{payload}.", JWKS, now=NOW)
        self.assertFalse(r["valid"])
        self.assertIn("algorithm refused", r["reasons"][0])

    def test_hs256_confusion_refused(self):
        """Token signed with the public key as an HMAC secret must not pass."""
        import hashlib
        import hmac
        header = b64u_encode(json.dumps({"alg": "HS256", "kid": "test-kid"}).encode())
        payload = TOKENS["valid"].split(".")[1]
        sig = b64u_encode(hmac.new(b"public", f"{header}.{payload}".encode(),
                                   hashlib.sha256).digest())
        r = verify_rs256(f"{header}.{payload}.{sig}", JWKS, now=NOW)
        self.assertFalse(r["valid"])
        self.assertIn("algorithm refused", r["reasons"][0])

    def test_tenant_binding(self):
        r = verify_rs256(TOKENS["valid"], JWKS, now=NOW, expected_tenant="other-tenant")
        self.assertFalse(r["valid"])
        self.assertIn("tenant mismatch", r["reasons"])

    def test_signature_must_be_below_modulus(self):
        jwk = JWKS["keys"][0]
        n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
        self.assertFalse(rsa_verify_pkcs1v15_sha256(b"x", n.to_bytes(256, "big"), n, 65537))


class TestReplayCache(unittest.TestCase):
    def test_fresh_jti_accepted_once(self):
        rc = ReplayCache()
        self.assertTrue(rc.check_and_record("j1"))
        self.assertFalse(rc.check_and_record("j1"))

    def test_missing_jti_refused(self):
        self.assertFalse(ReplayCache().check_and_record(None))

    def test_expired_entry_allows_reuse(self):
        rc = ReplayCache(ttl_seconds=10)
        self.assertTrue(rc.check_and_record("j1", now=1000))
        self.assertTrue(rc.check_and_record("j1", now=2000), "TTL passed, slot is reusable")


if __name__ == "__main__":
    unittest.main(verbosity=2)

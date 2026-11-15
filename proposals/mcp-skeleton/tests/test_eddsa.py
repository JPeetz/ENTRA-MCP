"""Ed25519 and asymmetric continuity tokens.

The vectors below are transcribed from RFC 8032 §7.1 (fetched from rfc-editor.org, not from
memory — three of my first four recollections were wrong, which is exactly why this file
exists). If the curve arithmetic regresses, these fail before anything else notices.
"""

import base64
import json
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuity import downstream, ed25519, tokens                      # noqa: E402
from continuity.state import ContinuityState                            # noqa: E402

# RFC 8032 §7.1, TEST 1 / 2 / 3 — (secret, public, message hex, signature)
RFC_VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class TestRFC8032Vectors(unittest.TestCase):
    def test_public_key_derivation(self):
        for i, (sk, pk, _msg, _sig) in enumerate(RFC_VECTORS, 1):
            self.assertEqual(ed25519.public_key(bytes.fromhex(sk)).hex(), pk,
                             f"RFC test {i}: public key")

    def test_signature_byte_for_byte(self):
        for i, (sk, _pk, msg, sig) in enumerate(RFC_VECTORS, 1):
            self.assertEqual(ed25519.sign(bytes.fromhex(sk), bytes.fromhex(msg)).hex(), sig,
                             f"RFC test {i}: signature")

    def test_verification(self):
        for i, (_sk, pk, msg, sig) in enumerate(RFC_VECTORS, 1):
            self.assertTrue(ed25519.verify(bytes.fromhex(pk), bytes.fromhex(msg),
                                           bytes.fromhex(sig)), f"RFC test {i}")

    def test_tampered_signature_refused(self):
        _sk, pk, msg, sig = RFC_VECTORS[0]
        bad = bytearray(bytes.fromhex(sig))
        bad[0] ^= 0xFF
        self.assertFalse(ed25519.verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes(bad)))

    def test_wrong_message_refused(self):
        _sk, pk, _msg, sig = RFC_VECTORS[1]
        self.assertFalse(ed25519.verify(bytes.fromhex(pk), b"\x73", bytes.fromhex(sig)))

    def test_wrong_public_key_refused(self):
        _sk, _pk, msg, sig = RFC_VECTORS[2]
        other = bytes.fromhex(RFC_VECTORS[0][1])
        self.assertFalse(ed25519.verify(other, bytes.fromhex(msg), bytes.fromhex(sig)))

    def test_short_inputs_refused(self):
        self.assertFalse(ed25519.verify(b"\x00" * 31, b"m", b"\x00" * 64))
        self.assertFalse(ed25519.verify(b"\x00" * 32, b"m", b"\x00" * 63))


class TestAsymmetricTokens(unittest.TestCase):
    def setUp(self):
        self.state = ContinuityState()

    def _mint(self, scopes=("read",), ttl=900):
        return tokens.mint_eddsa("monk@ordo", "api://ordo", list(scopes), None,
                                 secret=self.state.signing_secret, ttl=ttl)

    def test_token_verifies_with_public_key_only(self):
        tok = self._mint()
        r = tokens.verify_eddsa(tok["access_token"], self.state.signing_public)
        self.assertTrue(r["valid"], r.get("reasons"))
        self.assertEqual(r["claims"]["sub"], "monk@ordo")

    def test_public_key_cannot_forge(self):
        """Verification must not imply minting: a consumer only ever holds the public half."""
        tok = self._mint()
        forged = tokens.mint_eddsa("attacker", "api://ordo", ["read"], None,
                                   secret=self.state.signing_public)
        self.assertFalse(tokens.verify_eddsa(forged["access_token"],
                                             self.state.signing_public)["valid"])
        self.assertTrue(tokens.verify_eddsa(tok["access_token"],
                                            self.state.signing_public)["valid"])

    def test_signature_must_cover_payload(self):
        tok = self._mint()
        head, payload, sig = tok["access_token"].split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "==="))
        claims["sub"] = "attacker"
        tampered = (f"{head}."
                    f"{base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')}."
                    f"{sig}")
        self.assertFalse(tokens.verify_eddsa(tampered, self.state.signing_public)["valid"])

    def test_expiry_enforced(self):
        tok = self._mint(ttl=1)
        head, payload, sig = tok["access_token"].split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "==="))
        self.assertFalse(tokens.verify_eddsa(tok["access_token"], self.state.signing_public,
                                            now=claims["exp"] + 1)["valid"])

    def test_audience_enforced(self):
        tok = self._mint()
        self.assertFalse(tokens.verify_eddsa(tok["access_token"], self.state.signing_public,
                                             audience="api://other")["valid"])

    def test_hs256_token_refused_by_asymmetric_verifier(self):
        """Key-confusion: a shared-key token must never pass an Ed25519 verifier."""
        hs = tokens.mint("monk@ordo", "api://ordo", ["read"], None, key=self.state.key)
        r = tokens.verify_eddsa(hs["access_token"], self.state.signing_public)
        self.assertFalse(r["valid"])
        self.assertIn("algorithm refused", r["reasons"][0])

    def test_eddsa_token_refused_by_hmac_verifier(self):
        tok = self._mint()
        r = tokens.verify(tok["access_token"], self.state.key)
        self.assertFalse(r["valid"])
        self.assertIn("algorithm refused", r["reasons"][0])

    def test_scope_escalation_still_refused(self):
        with self.assertRaises(ValueError):
            tokens.mint_eddsa("monk@ordo", "api://ordo", ["read"], ["admin"],
                              secret=self.state.signing_secret)

    def test_jwks_shape(self):
        jwk = ed25519.jwk_from_public(self.state.signing_public)
        self.assertEqual(jwk["kty"], "OKP")
        self.assertEqual(jwk["crv"], "Ed25519")
        self.assertEqual(base64.urlsafe_b64decode(jwk["x"] + "=="), self.state.signing_public)


class TestJwksOverHttp(unittest.TestCase):
    PORT = 8461

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
        downstream.extra_call("serve_gateway", {"port": self.PORT})

    def test_consumer_verifies_with_published_key(self):
        """End to end: fetch the key, mint, verify — no shared secret anywhere."""
        jwks = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{self.PORT}/jwks.json", timeout=5))
        x = base64.urlsafe_b64decode(jwks["keys"][0]["x"] + "==")

        downstream.extra_call("set_continuity_mode", {"mode": "degraded"})
        s = downstream.extra_call("enrol_session", {
            "subject": "monk@ordo", "audience": "api://ordo",
            "scopes": ["read"], "device_key": "dev-key-1"})
        tok = downstream.extra_call("issue_local_token", {
            "session_id": s["session_id"], "device_key": "dev-key-1"})

        self.assertEqual(tok["alg"], "EdDSA")
        r = tokens.verify_eddsa(tok["access_token"], x, audience="api://ordo")
        self.assertTrue(r["valid"], r.get("reasons"))

    def test_jwks_does_not_leak_the_secret(self):
        jwks = json.load(urllib.request.urlopen(
            f"http://127.0.0.1:{self.PORT}/jwks.json", timeout=5))
        blob = json.dumps(jwks)
        secret = base64.urlsafe_b64encode(downstream.STATE.signing_secret).decode().rstrip("=")
        self.assertNotIn(secret, blob)
        self.assertNotIn("d", jwks["keys"][0], "private exponent must never be published")


if __name__ == "__main__":
    unittest.main(verbosity=2)

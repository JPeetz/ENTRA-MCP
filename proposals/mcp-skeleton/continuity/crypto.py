"""Cryptographic primitives, dependency-free.

Three jobs, deliberately separated:

1. **Key separation (HKDF).** One master secret must not do four jobs. Token signing, the
   beacon, the audit ledger and device-key hashing each get their own derived key, so
   leaking one does not compromise the others.
2. **RS256 verification.** Entra ID signs access tokens with RSA. Verifying that signature
   is what turns "the token says I am an admin" into "Microsoft says you are an admin".
   Pure integer arithmetic — no third-party library, no C extension.
3. **Replay cache.** A captured admin token is valid for its whole lifetime; a `jti` seen
   twice must be refused.

Nothing here is novel cryptography. It is the boring, standard construction, written out so
it can be read and tested.
"""

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


# ---------------------------------------------------------------------------
# Key separation
# ---------------------------------------------------------------------------

HKDF_SALT = b"entra-continuity/hkdf/v1"


def derive(master: bytes, purpose: str) -> bytes:
    """HKDF-SHA256 (RFC 5869) with a fixed salt and a labelled info string.

    Same master + different purpose => unrelated keys. This is why a stolen beacon key
    cannot sign tokens.
    """
    prk = hmac.new(HKDF_SALT, master, hashlib.sha256).digest()
    return hmac.new(prk, purpose.encode() + b"\x01", hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------

def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    import base64
    return base64.urlsafe_b64decode(s + pad)


def b64u_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# RS256 (RSASSA-PKCS1-v1_5 with SHA-256) — as used by Entra ID
# ---------------------------------------------------------------------------

# DER prefix of DigestInfo for SHA-256 (RFC 8017 §9.2, note 1).
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_verify_pkcs1v15_sha256(signing_input: bytes, signature: bytes,
                               n: int, e: int) -> bool:
    """Verify an RS256 signature given the RSA modulus and public exponent."""
    if n <= 0 or e <= 0:
        return False
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False

    s = int.from_bytes(signature, "big")
    if s >= n:                       # signature must be < modulus
        return False

    em = pow(s, e, n).to_bytes(k, "big")
    t = _SHA256_DIGESTINFO + hashlib.sha256(signing_input).digest()
    if k < len(t) + 11:
        return False

    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def _select_jwk(jwks: Dict[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
    keys = (jwks or {}).get("keys") or []
    for k in keys:
        if k.get("kty") != "RSA":
            continue
        if kid is None or k.get("kid") == kid:
            return k
    return None


def verify_rs256(token: str, jwks: Dict[str, Any], expected_issuer: Optional[str] = None,
                 now: Optional[float] = None, skew: int = 120,
                 expected_tenant: Optional[str] = None) -> Dict[str, Any]:
    """Full RS256 verification plus claim checks. Returns {valid, claims|reasons}.

    Refuses, in order: malformed tokens, any algorithm other than RS256 (`none`, `HS256`
    confusion), unknown `kid`, bad signature, then time and tenant claims.
    """
    now = time.time() if now is None else now
    reasons: List[str] = []

    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return {"valid": False, "reasons": ["malformed token"]}

    try:
        header = json.loads(b64u_decode(header_b64))
        claims = json.loads(b64u_decode(payload_b64))
        signature = b64u_decode(sig_b64)
    except Exception:
        return {"valid": False, "reasons": ["undecodable token"]}

    alg = header.get("alg")
    if alg != "RS256":
        # Explicitly kill alg-confusion: a token claiming `none` or `HS256` is never
        # acceptable here, whatever key material we happen to hold.
        return {"valid": False, "reasons": [f"algorithm refused: {alg!r}"],
                "claims": claims}

    jwk = _select_jwk(jwks, header.get("kid"))
    if jwk is None:
        return {"valid": False, "reasons": [f"unknown kid {header.get('kid')!r}"],
                "claims": claims}

    try:
        n = int.from_bytes(b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(b64u_decode(jwk["e"]), "big")
    except Exception:
        return {"valid": False, "reasons": ["unusable jwk"], "claims": claims}

    signing_input = f"{header_b64}.{payload_b64}".encode()
    if not rsa_verify_pkcs1v15_sha256(signing_input, signature, n, e):
        return {"valid": False, "reasons": ["signature mismatch"], "claims": claims}

    if expected_issuer and claims.get("iss") != expected_issuer:
        reasons.append(f"unexpected issuer {claims.get('iss')!r}")
    if int(claims.get("exp", 0)) + skew <= int(now):
        reasons.append("token expired")
    if int(claims.get("nbf", 0)) > int(now) + skew:
        reasons.append("token not yet valid")
    if expected_tenant and claims.get("tid") != expected_tenant:
        reasons.append("tenant mismatch")

    return ({"valid": not reasons, "claims": claims} if not reasons
            else {"valid": False, "reasons": reasons, "claims": claims})


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class ReplayCache:
    """Remember recently seen `jti` values so a captured token works exactly once."""

    def __init__(self, ttl_seconds: int = 7200, max_entries: int = 4096):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._seen: Dict[str, float] = {}

    def _evict(self, now: float) -> None:
        if len(self._seen) <= self.max_entries:
            return
        for k, ts in sorted(self._seen.items(), key=lambda kv: kv[1]):
            if now - ts > self.ttl or len(self._seen) > self.max_entries:
                self._seen.pop(k, None)

    def check_and_record(self, jti: Optional[str], now: Optional[float] = None) -> bool:
        """True if this jti is fresh (and now recorded); False if it is a replay."""
        if not jti:
            return False
        now = time.time() if now is None else now
        if jti in self._seen and now - self._seen[jti] <= self.ttl:
            return False
        self._seen[jti] = now
        self._evict(now)
        return True

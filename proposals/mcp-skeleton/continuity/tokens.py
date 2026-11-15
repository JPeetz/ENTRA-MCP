"""Local token minting for continuity mode.

Two signing modes, one token contract:

  * **EdDSA (Ed25519)** — default. Consumers verify with the *public* key published at
    `/jwks.json`, so no consumer holds minting authority. With HS256 every downstream
    service that can verify can also mint; that is the flaw this default removes.
  * **HS256** — retained for constrained deployments where a shared key is the only option.
    Explicit, never silent.

Constraints enforced in code, not in prose:
  * TTL is hard-capped (default 900 s, maximum 3600 s).
  * Requested scopes must be a subset of the scopes approved for that session.
  * Privileged role claims (`roles`, `wids`, `Directory.*`) are refused outright.
  * Every token carries `xms_continuity: true` so downstream can apply stricter policy.
"""

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional

from . import ed25519

MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 900
ISSUER = "continuity-local"
ED_KID = "continuity-ed25519-1"
HS_KID = "continuity-local-1"

FORBIDDEN_SCOPE_PREFIXES = ("Directory.", "RoleManagement.", "Application.ReadWrite")
FORBIDDEN_CLAIMS = ("roles", "wids", "groups")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _hs_sign(signing_input: str, key: bytes) -> str:
    return _b64u(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def _si(header: Dict[str, Any], claims: Dict[str, Any]) -> str:
    return (f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}."
            f"{_b64u(json.dumps(claims, separators=(',', ':')).encode())}")


def build_claims(subject: str,
                 audience: str,
                 approved_scopes: Iterable[str],
                 requested_scopes: Optional[Iterable[str]],
                 ttl: int = DEFAULT_TTL_SECONDS,
                 extra: Optional[Dict[str, Any]] = None,
                 device_thumbprint: Optional[str] = None) -> Dict[str, Any]:
    """Validate and assemble claims. Raises ValueError on any guard violation."""
    ttl = min(int(ttl), MAX_TTL_SECONDS)
    if ttl <= 0:
        raise ValueError("ttl must be positive")

    approved = sorted(set(approved_scopes))
    requested = sorted(set(requested_scopes)) if requested_scopes else approved

    over = [s for s in requested if s not in approved]
    if over:
        raise ValueError(f"scope escalation refused: {over}")

    forbidden = [s for s in requested if s.startswith(FORBIDDEN_SCOPE_PREFIXES)]
    if forbidden:
        raise ValueError(f"privileged scope refused in continuity mode: {forbidden}")

    if extra:
        bad = [c for c in FORBIDDEN_CLAIMS if c in extra]
        if bad:
            raise ValueError(f"privileged claims refused: {bad}")

    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": subject,
        "aud": audience,
        "scp": " ".join(requested),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
        "xms_continuity": True,
    }
    if extra:
        claims.update({k: v for k, v in extra.items() if k not in FORBIDDEN_CLAIMS})

    # Proof-of-possession binding (RFC 7800): ties the token to the enrolled device
    # thumbprint so a stolen bearer token is not replayable from another host.
    if device_thumbprint:
        claims["cnf"] = {"jkt": device_thumbprint}
    return claims


def _pack(claims: Dict[str, Any], header: Dict[str, Any], sig: bytes) -> Dict[str, Any]:
    token = f"{_si(header, claims)}.{_b64u(sig)}"
    return {"access_token": token, "token_type": "Bearer",
            "expires_in": int(claims["exp"]) - int(claims["iat"]),
            "scope": claims["scp"], "alg": header["alg"]}


def mint(subject: str,
         audience: str,
         approved_scopes: Iterable[str],
         requested_scopes: Optional[Iterable[str]],
         key: bytes,
         ttl: int = DEFAULT_TTL_SECONDS,
         extra: Optional[Dict[str, Any]] = None,
         device_thumbprint: Optional[str] = None) -> Dict[str, Any]:
    """HS256 mint. `key` is a shared signing key — every holder can mint."""
    claims = build_claims(subject, audience, approved_scopes, requested_scopes,
                          ttl, extra, device_thumbprint)
    header = {"alg": "HS256", "typ": "JWT", "kid": HS_KID}
    sig = hmac.new(key, _si(header, claims).encode(), hashlib.sha256).digest()
    return _pack(claims, header, sig)


def mint_eddsa(subject: str,
               audience: str,
               approved_scopes: Iterable[str],
               requested_scopes: Optional[Iterable[str]],
               secret: bytes,
               ttl: int = DEFAULT_TTL_SECONDS,
               extra: Optional[Dict[str, Any]] = None,
               device_thumbprint: Optional[str] = None) -> Dict[str, Any]:
    """EdDSA mint. The secret stays here; consumers only ever receive the public key."""
    claims = build_claims(subject, audience, approved_scopes, requested_scopes,
                          ttl, extra, device_thumbprint)
    header = {"alg": "EdDSA", "typ": "JWT", "kid": ED_KID}
    return _pack(claims, header, ed25519.sign(secret, _si(header, claims).encode()))


def _split(token: str):
    try:
        h, p, s = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64u_dec(h))
        claims = json.loads(_b64u_dec(p))
        sig = _b64u_dec(s)
    except Exception:
        return None
    return h, p, header, claims, sig


def _check_claims(claims: Dict[str, Any], now: float,
                  audience: Optional[str]) -> List[str]:
    reasons: List[str] = []
    if claims.get("iss") != ISSUER:
        reasons.append(f"unexpected issuer {claims.get('iss')!r}")
    if int(claims.get("exp", 0)) <= int(now):
        reasons.append("token expired")
    if int(claims.get("nbf", 0)) > int(now) + 30:
        reasons.append("token not yet valid")
    if audience and claims.get("aud") != audience:
        reasons.append("audience mismatch")
    if not claims.get("xms_continuity"):
        reasons.append("missing continuity marker")
    return reasons


def verify(token: str, key: bytes, audience: Optional[str] = None,
           now: Optional[float] = None) -> Dict[str, Any]:
    """Verify an HS256 token. `key` is the shared signing key."""
    now = time.time() if now is None else now
    parts = _split(token)
    if parts is None:
        return {"valid": False, "reasons": ["malformed token"]}
    h, p, header, claims, sig = parts

    # Algorithm check first: an EdDSA token must never be validated with a shared secret.
    if header.get("alg") != "HS256":
        return {"valid": False, "reasons": [f"algorithm refused: {header.get('alg')!r}"]}

    expected = _hs_sign(f"{h}.{p}", key)
    if not hmac.compare_digest(_b64u(sig), expected):
        return {"valid": False, "reasons": ["signature mismatch"]}

    reasons = _check_claims(claims, now, audience)
    return ({"valid": True, "claims": claims} if not reasons
            else {"valid": False, "reasons": reasons, "claims": claims})


def verify_eddsa(token: str, public: bytes, audience: Optional[str] = None,
                 now: Optional[float] = None) -> Dict[str, Any]:
    """Verify an EdDSA token using only the public key."""
    now = time.time() if now is None else now
    parts = _split(token)
    if parts is None:
        return {"valid": False, "reasons": ["malformed token"]}
    h, p, header, claims, sig = parts

    # Refuse the symmetric path here: accepting HS256 would let a consumer's public key be
    # abused as an HMAC secret (the classic key-confusion attack).
    if header.get("alg") != "EdDSA":
        return {"valid": False, "reasons": [f"algorithm refused: {header.get('alg')!r}"]}

    if not ed25519.verify(public, f"{h}.{p}".encode(), sig):
        return {"valid": False, "reasons": ["signature mismatch"]}

    reasons = _check_claims(claims, now, audience)
    return ({"valid": True, "claims": claims} if not reasons
            else {"valid": False, "reasons": reasons, "claims": claims})


def verify_any(token: str, *, secret: Optional[bytes] = None,
               public: Optional[bytes] = None, audience: Optional[str] = None,
               now: Optional[float] = None) -> Dict[str, Any]:
    """Dispatch on the token's own algorithm, refusing anything else."""
    parts = _split(token)
    if parts is None:
        return {"valid": False, "reasons": ["malformed token"]}
    alg = parts[2].get("alg")
    if alg == "EdDSA" and public is not None:
        return verify_eddsa(token, public, audience, now)
    if alg == "HS256" and secret is not None:
        return verify(token, secret, audience, now)
    return {"valid": False, "reasons": [f"algorithm refused: {alg!r}"]}

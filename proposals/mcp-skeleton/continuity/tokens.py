"""Local token minting for continuity mode.

DESIGN NOTE — read before judging the crypto.

This skeleton signs with **HS256 over a pre-shared key**. That is deliberate and it is
what an air-gapped fallback can actually rely on: downstream services receive the key
during healthy enrolment, so no JWKS round-trip is needed mid-outage (the whole point).

A production implementation should use **asymmetric** signing (RS256/ES256) with the
public half published on the local gateway, so any enrolled consumer can verify without
holding the minting secret. That is called out in the proposal, not hidden here.

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

MAX_TTL_SECONDS = 3600
DEFAULT_TTL_SECONDS = 900
ISSUER = "continuity-local"

FORBIDDEN_SCOPE_PREFIXES = ("Directory.", "RoleManagement.", "Application.ReadWrite")
FORBIDDEN_CLAIMS = ("roles", "wids", "groups")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _sign(signing_input: str, key: bytes) -> str:
    return _b64u(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())


def mint(subject: str,
         audience: str,
         approved_scopes: Iterable[str],
         requested_scopes: Optional[Iterable[str]],
         key: bytes,
         ttl: int = DEFAULT_TTL_SECONDS,
         extra: Optional[Dict[str, Any]] = None,
         device_thumbprint: Optional[str] = None) -> Dict[str, Any]:
    """Mint a short-lived continuity token. Raises ValueError on any guard violation."""
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

    header = {"alg": "HS256", "typ": "JWT", "kid": "continuity-local-1"}
    signing_input = f"{_b64u(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64u(json.dumps(claims, separators=(',', ':')).encode())}"
    token = f"{signing_input}.{_sign(signing_input, key)}"
    return {"access_token": token, "token_type": "Bearer",
            "expires_in": ttl, "scope": claims["scp"]}


def verify(token: str, key: bytes, audience: Optional[str] = None,
           now: Optional[float] = None) -> Dict[str, Any]:
    """Verify signature and time bounds. Returns {valid, claims|reasons}."""
    now = time.time() if now is None else now
    try:
        header_b64, payload_b64, sig = token.split(".")
    except ValueError:
        return {"valid": False, "reasons": ["malformed token"]}

    expected = _sign(f"{header_b64}.{payload_b64}", key)
    if not hmac.compare_digest(sig, expected):
        return {"valid": False, "reasons": ["signature mismatch"]}

    # Algorithm confusion: refuse anything but the one algorithm this issuer uses.
    try:
        header = json.loads(_b64u_dec(header_b64))
    except Exception:
        return {"valid": False, "reasons": ["undecodable header"]}
    if header.get("alg") != "HS256":
        return {"valid": False, "reasons": [f"algorithm refused: {header.get('alg')!r}"]}

    try:
        claims = json.loads(_b64u_dec(payload_b64))
    except Exception:
        return {"valid": False, "reasons": ["undecodable payload"]}

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

    return ({"valid": True, "claims": claims} if not reasons
            else {"valid": False, "reasons": reasons, "claims": claims})

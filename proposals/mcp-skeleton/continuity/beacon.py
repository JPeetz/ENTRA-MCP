"""Continuity beacon — always-on discovery for every downstream service.

The beacon is the answer to "how does a service know to fail over at all?" It is served
**at all times**, in every mode, including healthy. That is safe because it is read-only:
it advertises state and endpoints, never credentials.

Signing lets a consumer trust the beacon it found (mDNS/well-known discovery is otherwise
spoofable by anything on the LAN).
"""

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

BEACON_VERSION = "continuity-beacon/v1"
BEACON_TTL_SECONDS = 60        # short: a stale beacon is worse than no beacon


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign(payload: Dict[str, Any], key: bytes) -> str:
    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


def build_beacon(state: Any,
                 base_url: str = "http://127.0.0.1:8400",
                 services: Optional[List[str]] = None,
                 ttl: int = BEACON_TTL_SECONDS,
                 now: Optional[float] = None) -> Dict[str, Any]:
    """Build a signed beacon describing where to authenticate right now.

    `authority` is the field a consumer acts on:
        cloud    -> keep using Microsoft; the local issuer will not mint
        local    -> Microsoft is unavailable; point at this issuer
        drill    -> a rehearsal; minting enabled but flagged as non-production
    """
    now = time.time() if now is None else now
    mode = getattr(state, "mode", "healthy")
    authority = {"healthy": "cloud", "degraded": "local", "drill": "drill"}.get(mode, "cloud")

    payload = {
        "version": BEACON_VERSION,
        "iss": "continuity-local",
        "mode": mode,
        "authority": authority,
        "issued_at": int(now),
        "expires_at": int(now + ttl),
        "endpoints": {
            "issuer": base_url,
            "token": f"{base_url}/token",
            "health": f"{base_url}/health",
            "discovery": f"{base_url}/.well-known/openid-configuration",
            "reconcile": f"{base_url}/reconcile",
        },
        "capabilities": {
            "can_mint": bool(getattr(state, "can_mint", lambda: False)()),
            "max_ttl_seconds": 3600,
            "continuity_marker": "xms_continuity",
        },
        "services": services or [],
        "tenant_placeholder": "{tenantid}",
    }
    return {**payload, "sig": sign(payload, state.key)}


def verify_beacon(beacon: Dict[str, Any], key: bytes,
                  now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    body = {k: v for k, v in beacon.items() if k != "sig"}
    reasons: List[str] = []

    if not hmac.compare_digest(beacon.get("sig", ""), sign(body, key)):
        reasons.append("signature mismatch")
    if beacon.get("version") != BEACON_VERSION:
        reasons.append(f"unsupported version {beacon.get('version')!r}")
    if int(beacon.get("expires_at", 0)) <= int(now):
        reasons.append("beacon expired — treat as unreachable, do not guess")
    if beacon.get("authority") not in ("cloud", "local", "drill"):
        reasons.append(f"unknown authority {beacon.get('authority')!r}")

    return {"valid": not reasons, "reasons": reasons,
            "authority": beacon.get("authority"),
            "expires_in_s": int(beacon.get("expires_at", 0)) - int(now)}

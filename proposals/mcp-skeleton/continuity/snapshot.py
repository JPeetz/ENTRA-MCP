"""Snapshot schema and verification.

IMPORTANT: the signature check here is a LOCAL STAND-IN using a demo HMAC key so the
skeleton is runnable. In the real API the snapshot is signed with a Microsoft key and
verified against a published JWKS. Never treat the demo signature as a security control.
"""

import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional

SNAPSHOT_VERSION = "continuity/v1"
DEMO_KEY = b"demo-only-not-a-real-signing-key"
DEFAULT_TTL_HOURS = 24


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign(payload: Dict[str, Any]) -> str:
    return hmac.new(DEMO_KEY, _canonical(payload), hashlib.sha256).hexdigest()


def make_snapshot(policies: List[Dict[str, Any]],
                  groups: Optional[Dict[str, List[str]]] = None,
                  seq: int = 1,
                  ttl_hours: int = DEFAULT_TTL_HOURS,
                  now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    body = {
        "version": SNAPSHOT_VERSION,
        "tenant_placeholder": "{tenantid}",
        "seq": seq,
        "issued_at": int(now),
        "expires_at": int(now + ttl_hours * 3600),
        "policies": policies,
        "groups": groups or {},
        "read_only": True,
        "contains_secrets": False,
    }
    return {**body, "sig": _sign(body)}


def verify_snapshot(snapshot: Dict[str, Any],
                    min_seq: int = 0,
                    now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    reasons: List[str] = []

    body = {k: v for k, v in snapshot.items() if k != "sig"}
    if not hmac.compare_digest(snapshot.get("sig", ""), _sign(body)):
        reasons.append("signature mismatch (demo key)")
    if snapshot.get("version") != SNAPSHOT_VERSION:
        reasons.append(f"unsupported version {snapshot.get('version')!r}")
    if int(snapshot.get("expires_at", 0)) <= int(now):
        reasons.append("snapshot expired")
    if int(snapshot.get("seq", 0)) < int(min_seq):
        reasons.append(f"stale sequence: {snapshot.get('seq')} < required {min_seq}")
    if snapshot.get("contains_secrets"):
        reasons.append("snapshot must not contain secrets")

    return {"valid": not reasons, "reasons": reasons,
            "seq": snapshot.get("seq"), "expires_in_s": int(snapshot.get("expires_at", 0)) - int(now)}


def diff_policy(current: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Compare live policy to snapshot policy by id, returning added/removed/changed."""
    live = {p["id"]: p for p in current.get("policies", [])}
    snap = {p["id"]: p for p in snapshot.get("policies", [])}

    added = sorted(set(live) - set(snap))
    removed = sorted(set(snap) - set(live))
    changed = sorted(
        pid for pid in set(live) & set(snap)
        if json.dumps(live[pid], sort_keys=True) != json.dumps(snap[pid], sort_keys=True)
    )
    return {"added": added, "removed": removed, "changed": changed,
            "count_live": len(live), "count_snapshot": len(snap)}

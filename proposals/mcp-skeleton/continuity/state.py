"""Shared continuity state: enrolled sessions, mode, and a tamper-evident audit chain.

Hardening decisions taken here, each tied to a threat:
  * Device keys are stored as salted hashes, never in the clear — a stolen snapshot must
    not yield usable device keys.
  * Comparison is constant time (hardening.safe_eq) — no timing oracle.
  * Sessions expire — stale enrolment cannot mint forever.
  * Audit entries are hash-chained — deletion or edit is detectable.
"""

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .hardening import AuditChain, hash_secret, safe_eq

DEFAULT_SESSION_TTL_SECONDS = 30 * 24 * 3600


@dataclass
class Session:
    """A principal enrolled while the tenant was HEALTHY."""
    id: str
    subject: str
    audience: str
    approved_scopes: List[str]
    device_hash: str
    enrolled_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(
        default_factory=lambda: int(time.time()) + DEFAULT_SESSION_TTL_SECONDS)
    revoked: bool = False

    def expired(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return int(self.expires_at) <= int(now)

    def usable(self, now: Optional[float] = None) -> bool:
        return not self.revoked and not self.expired(now)


class ContinuityState:
    def __init__(self, key: Optional[bytes] = None, salt: Optional[bytes] = None):
        self.key: bytes = key or os.urandom(32)      # token signing key
        self.salt: bytes = salt or os.urandom(32)    # device-key hashing salt
        self.sessions: Dict[str, Session] = {}
        self.audit = AuditChain()
        self.mode: str = "healthy"                   # healthy | degraded | drill
        self.since: int = int(time.time())
        self.seq: int = 1
        # Bound by the first successful admin bootstrap; every API key must match it.
        self.tenant_id: Optional[str] = None

    # ---- enrolment (performed while healthy) --------------------------------
    def enrol(self, subject: str, audience: str, scopes: List[str],
              device_key: str, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> Session:
        if not device_key:
            raise ValueError("device_key required: an unbound session cannot mint")
        s = Session(
            id=uuid.uuid4().hex,
            subject=subject,
            audience=audience,
            approved_scopes=sorted(set(scopes)),
            device_hash=hash_secret(self.salt, device_key),
            expires_at=int(time.time()) + int(ttl_seconds),
        )
        self.sessions[s.id] = s
        self.audit.append("enrol", subject=subject, session=s.id, audience=audience)
        return s

    def check_device(self, session: Session, device_key: str) -> bool:
        """Constant-time device binding check."""
        if not device_key:
            return False
        return safe_eq(session.device_hash, hash_secret(self.salt, device_key))

    def revoke(self, session_id: str) -> bool:
        s = self.sessions.get(session_id)
        if not s:
            return False
        s.revoked = True
        self.audit.append("revoke", session=session_id, subject=s.subject)
        return True

    # ---- mode ---------------------------------------------------------------
    def set_mode(self, mode: str, reason: str = "") -> None:
        if mode not in ("healthy", "degraded", "drill"):
            raise ValueError(f"bad mode {mode!r}")
        self.mode = mode
        self.since = int(time.time())
        self.audit.append("mode", mode=mode, reason=reason)

    def can_mint(self) -> bool:
        """Continuity tokens may only be issued while degraded or in a declared drill."""
        return self.mode in ("degraded", "drill")

    # ---- audit --------------------------------------------------------------
    def _log(self, event: str, **fields: Any) -> None:
        self.audit.append(event, **fields)

    def drain_audit(self) -> List[Dict[str, Any]]:
        return self.audit.drain()

    def verify_audit(self, entries: List[Dict[str, Any]]) -> bool:
        return self.audit.verify(entries)

    def status(self) -> Dict[str, Any]:
        now = time.time()
        return {"mode": self.mode, "since": self.since, "seq": self.seq,
                "sessions": len(self.sessions),
                "active_sessions": sum(1 for s in self.sessions.values() if s.usable(now)),
                "can_mint": self.can_mint()}

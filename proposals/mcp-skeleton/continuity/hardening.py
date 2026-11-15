"""Security primitives for the continuity gateway.

Every helper here exists because of a specific, named threat. Nothing is decorative.

T1  device-key brute force        -> RateLimiter
T2  timing oracle on comparison   -> safe_eq (constant time)
T3  key disclosure at rest        -> hash_secret (per-state salt)
T4  request-body memory DoS       -> MAX_BODY
T5  audit-log tampering           -> AuditChain (HMAC'd chain, keyed)

Handled elsewhere, not here: unbounded thread spawning (gateway.BoundedHTTPServer, capped at
32) and asymmetric admin-token verification (crypto.verify_rs256). The remaining
shared-secret exposure is the *continuity token* signing key, which SECURITY.md lists as a
residual risk.
"""

import hashlib
import hmac
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

MAX_BODY = 16 * 1024          # continuity requests are tiny; anything larger is hostile
RATE_WINDOW_SECONDS = 60
RATE_MAX_EVENTS = 30


def safe_eq(a: str, b: str) -> bool:
    """Constant-time comparison. Never use == on secrets: it leaks length and prefix."""
    return hmac.compare_digest(a.encode("utf-8", "ignore"), b.encode("utf-8", "ignore"))


def hash_secret(salt: bytes, secret: str) -> str:
    """Store device keys as salted hashes. A stolen snapshot must not yield live keys."""
    return hmac.new(salt, secret.encode("utf-8"), hashlib.sha256).hexdigest()


class RateLimiter:
    """Sliding-window limiter keyed by an opaque string (session id, or client address).

    Prevents offline brute force of the device key, which is the only secret in the
    fallback path and is short by nature.
    """

    def __init__(self, max_events: int = RATE_MAX_EVENTS,
                 window: int = RATE_WINDOW_SECONDS):
        self.max_events = max_events
        self.window = window
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: Optional[float] = None) -> Tuple[bool, int]:
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t >= cutoff]
            if len(hits) >= self.max_events:
                self._hits[key] = hits
                return False, 0
            hits.append(now)
            self._hits[key] = hits
            return True, self.max_events - len(hits)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


class AuditChain:
    """Append-only ledger where each entry is HMAC'd to the previous one.

    Keyed on purpose. A plain hash chain can be *recomputed* by anyone who can write to it
    — edit an entry, rehash the rest, and the chain looks intact. Keying it means an
    outsider cannot forge a consistent history even with full write access.
    """

    GENESIS = "0" * 64

    def __init__(self, key: bytes = b"") -> None:
        self.key = key or b""
        self._entries: List[Dict[str, Any]] = []
        self._prev = self.GENESIS
        self._lock = threading.Lock()

    def _mac(self, prev: str, blob: bytes) -> str:
        return hmac.new(self.key, prev.encode() + blob, hashlib.sha256).hexdigest()

    def append(self, event: str, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            entry = {
                "at": int(time.time()),
                "event": event,
                "prev": self._prev,
                **fields,
            }
            blob = repr(sorted(entry.items())).encode()
            entry["hash"] = self._mac(self._prev, blob)
            self._prev = entry["hash"]
            self._entries.append(entry)
            return entry

    def drain(self) -> List[Dict[str, Any]]:
        with self._lock:
            out, self._entries = self._entries, []
            return out

    def verify(self, entries: List[Dict[str, Any]]) -> bool:
        prev = self.GENESIS
        for e in entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            expected = self._mac(prev, repr(sorted(body.items())).encode())
            if e.get("prev") != prev or not hmac.compare_digest(str(e.get("hash")), expected):
                return False
            prev = e["hash"]
        return True

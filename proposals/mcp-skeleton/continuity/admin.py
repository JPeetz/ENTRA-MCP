"""Admin bootstrap and downstream API keys.

Model
-----
1. A **tenant administrator** signs in to Entra with their own account and presents the
   resulting access token.
2. The continuity service verifies the token carries an administrative role **for the
   tenant it binds to**, then binds the tenant and issues a **downstream API key**.
3. Downstream services authenticate to the gateway with that API key. Sessions and
   per-request continuity tokens sit underneath it.

Why an API key here at all: downstream services frequently cannot do an interactive OIDC
flow and cannot hold certificates. A scoped, revocable, tenant-bound bearer key is the
pragmatic credential — and it is deliberately *narrower* than the admin token that created
it, which can only be presented once, at bootstrap.

Honesty about verification
--------------------------
`verify_admin_claims` performs the checks we can do locally: issuer, tenant binding,
expiry, role membership and continuity-marker absence. **Signature verification against
Microsoft's JWKS is a hook (`validator=`) and is left unwired in this skeleton** — faking it
would be worse than leaving it explicit. In production, wire `validator` to
`https://login.microsoftonline.com/{tid}/discovery/v2.0/keys` and fail closed.
"""

import hashlib
import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .hardening import hash_secret, safe_eq

# Directory role template IDs that count as "administrator of the tenant".
ADMIN_ROLE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}

ADMIN_ROLE_NAMES = set(ADMIN_ROLE_IDS.values())
DEFAULT_KEY_TTL_SECONDS = 90 * 24 * 3600


@dataclass
class ApiKey:
    id: str
    tenant_id: str
    label: str
    scopes: List[str]
    key_hash: str
    created_by: str
    created_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(default_factory=lambda: int(time.time()) + DEFAULT_KEY_TTL_SECONDS)
    revoked: bool = False

    def usable(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        return not self.revoked and int(self.expires_at) > int(now)


class AdminBootstrapError(PermissionError):
    """Raised when a token does not prove administrative rights for the tenant."""


def verify_admin_claims(claims: Dict[str, Any],
                        expected_tenant: Optional[str] = None,
                        now: Optional[float] = None,
                        validator: Optional[Callable[[Dict[str, Any]], bool]] = None) -> Dict[str, Any]:
    """Structural + role check on an Entra access token. Raises AdminBootstrapError.

    NOTE: signature verification is the `validator` hook. Without it this function proves
    only what the token *says*, not that Microsoft issued it — acceptable for a skeleton,
    never for production.
    """
    now = time.time() if now is None else now
    reasons: List[str] = []

    if claims.get("xms_continuity"):
        reasons.append("continuity token used as an admin credential")
    if int(claims.get("exp", 0)) <= int(now):
        reasons.append("admin token expired")

    tid = claims.get("tid")
    if not tid:
        reasons.append("no tenant id (tid) in token")
    elif expected_tenant and tid != expected_tenant:
        reasons.append(f"tenant mismatch: token {tid} != bound {expected_tenant}")

    wids = set(claims.get("wids") or [])
    roles = set(claims.get("roles") or [])
    granted = [ADMIN_ROLE_IDS[w] for w in wids if w in ADMIN_ROLE_IDS]
    granted += [r for r in roles if r in ADMIN_ROLE_NAMES]

    if not granted:
        reasons.append("token carries no administrative directory role")

    if validator is not None and not validator(claims):
        reasons.append("signature validation failed")

    if reasons:
        raise AdminBootstrapError("; ".join(reasons))

    return {"tenant_id": tid, "admin_roles": sorted(set(granted)),
            "subject": claims.get("oid") or claims.get("sub")}


class KeyStore:
    """Tenant-bound downstream API keys. Only hashes are retained."""

    def __init__(self, salt: Optional[bytes] = None):
        self.salt = salt or os.urandom(32)
        self.keys: Dict[str, ApiKey] = {}

    def issue(self, tenant_id: str, label: str, scopes: Iterable[str],
              created_by: str, ttl: int = DEFAULT_KEY_TTL_SECONDS) -> Tuple[str, ApiKey]:
        """Return (plaintext_key, record). The plaintext is shown once and never stored."""
        plaintext = "ok_" + secrets.token_urlsafe(32)
        rec = ApiKey(
            id=uuid.uuid4().hex,
            tenant_id=tenant_id,
            label=label,
            scopes=sorted(set(scopes)),
            key_hash=hash_secret(self.salt, plaintext),
            created_by=created_by,
            expires_at=int(time.time()) + int(ttl),
        )
        self.keys[rec.id] = rec
        return plaintext, rec

    def verify(self, presented: str, tenant_id: Optional[str] = None) -> Optional[ApiKey]:
        """Constant-time lookup across stored hashes. Returns the record or None."""
        if not presented:
            return None
        digest = hash_secret(self.salt, presented)
        for rec in self.keys.values():
            if safe_eq(rec.key_hash, digest):
                if not rec.usable():
                    return None
                if tenant_id and rec.tenant_id != tenant_id:
                    return None
                return rec
        return None

    def revoke(self, key_id: str) -> bool:
        rec = self.keys.get(key_id)
        if not rec:
            return False
        rec.revoked = True
        return True

    def prefix_of(self, presented: str) -> str:
        """Non-secret display prefix — safe for logs and support tickets."""
        return presented[:7] if presented else ""

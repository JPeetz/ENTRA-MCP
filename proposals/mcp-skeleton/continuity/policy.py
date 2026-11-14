"""Deterministic Conditional Access policy evaluation against a local snapshot.

This is the reference semantics behind `evaluate_policy_locally`. It is intentionally
small: the goal is *parity of behaviour*, not a full CA engine. Every rule here is
explicit so it can be reviewed and matched by an implementation elsewhere.

Model
-----
A policy has conditions (users, apps, platforms, locations, client apps) and grant
controls. Exclusions always win. Conditions within a group AND together; a condition
dimension that is absent or empty matches everything.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

BLOCK = "block"
MFA = "require_mfa"
COMPLIANT = "require_compliant_device"


@dataclass
class Policy:
    id: str
    name: str = ""
    state: str = "enabled"          # enabled | disabled | reportOnly
    include_users: List[str] = field(default_factory=list)
    exclude_users: List[str] = field(default_factory=list)
    include_groups: List[str] = field(default_factory=list)
    exclude_groups: List[str] = field(default_factory=list)
    include_apps: List[str] = field(default_factory=list)
    exclude_apps: List[str] = field(default_factory=list)
    include_platforms: List[str] = field(default_factory=list)
    trusted_locations_only: bool = False
    client_apps: List[str] = field(default_factory=list)   # browser | mobileApps | exchangeActiveSync
    operator: str = "OR"                                    # OR | AND
    controls: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Policy":
        return Policy(
            id=d.get("id", ""),
            name=d.get("name", ""),
            state=d.get("state", "enabled"),
            include_users=d.get("include_users", []),
            exclude_users=d.get("exclude_users", []),
            include_groups=d.get("include_groups", []),
            exclude_groups=d.get("exclude_groups", []),
            include_apps=d.get("include_apps", []),
            exclude_apps=d.get("exclude_apps", []),
            include_platforms=d.get("include_platforms", []),
            trusted_locations_only=bool(d.get("trusted_locations_only", False)),
            client_apps=d.get("client_apps", []),
            operator=d.get("operator", "OR"),
            controls=d.get("controls", []),
        )


@dataclass
class SignInContext:
    user_id: str
    groups: List[str] = field(default_factory=list)
    app_id: str = ""
    platform: str = ""
    trusted_location: bool = False
    client_app: str = "browser"
    device_compliant: bool = False
    mfa_performed: bool = False

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SignInContext":
        return SignInContext(
            user_id=d.get("user_id", ""),
            groups=d.get("groups", []),
            app_id=d.get("app_id", ""),
            platform=d.get("platform", ""),
            trusted_location=bool(d.get("trusted_location", False)),
            client_app=d.get("client_app", "browser"),
            device_compliant=bool(d.get("device_compliant", False)),
            mfa_performed=bool(d.get("mfa_performed", False)),
        )


def _matches_targets(values: List[str], *candidates: str) -> bool:
    return any(c in values for c in candidates if c)


def is_excluded(p: Policy, ctx: SignInContext) -> bool:
    if ctx.user_id and ctx.user_id in p.exclude_users:
        return True
    return any(g in p.exclude_groups for g in ctx.groups)


def applies(p: Policy, ctx: SignInContext) -> bool:
    """True when every declared condition dimension is satisfied by the context."""
    if p.state == "disabled" or is_excluded(p, ctx):
        return False

    # users: include list empty means "all users"
    if p.include_users or p.include_groups:
        if not _matches_targets(p.include_users, ctx.user_id) and not any(
            g in p.include_groups for g in ctx.groups
        ):
            return False

    if p.include_apps and not _matches_targets(p.include_apps, ctx.app_id):
        return False
    if p.exclude_apps and _matches_targets(p.exclude_apps, ctx.app_id):
        return False

    if p.include_platforms and ctx.platform not in p.include_platforms:
        return False
    if p.trusted_locations_only and not ctx.trusted_location:
        return False
    if p.client_apps and ctx.client_app not in p.client_apps:
        return False

    return True


def _satisfied(control: str, ctx: SignInContext) -> bool:
    if control == MFA:
        return ctx.mfa_performed
    if control == COMPLIANT:
        return ctx.device_compliant
    if control == BLOCK:
        return False
    # Unknown control: treated as unsatisfied rather than silently allowing.
    return False


def evaluate(policies: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
    """Return {decision: allow|deny|mfa|compliant, applied: [...], reasons: [...]}."""
    ctx = SignInContext.from_dict(context)
    applied: List[Dict[str, Any]] = []
    blocking: List[str] = []
    required: List[str] = []
    and_mode = False

    for raw in policies:
        p = Policy.from_dict(raw)
        if not applies(p, ctx):
            continue
        applied.append({"id": p.id, "name": p.name, "state": p.state, "controls": p.controls})
        if p.state == "reportOnly":
            continue
        if BLOCK in p.controls:
            blocking.append(p.id)
        required.extend(c for c in p.controls if c != BLOCK)
        if p.operator.upper() == "AND":
            and_mode = True

    if blocking:
        return {"decision": "deny", "applied": applied,
                "reasons": [f"blocked by policy {i}" for i in blocking],
                "missing": []}

    unique_required = sorted(set(required))
    missing = [c for c in unique_required if not _satisfied(c, ctx)]

    if not unique_required:
        return {"decision": "allow", "applied": applied,
                "reasons": ["no applicable grant controls"], "missing": []}

    if and_mode:
        # AND semantics: every required control must be satisfied.
        if missing:
            return {"decision": "deny", "applied": applied,
                    "reasons": ["AND-operator policy not fully satisfied"],
                    "missing": missing}
        return {"decision": "allow", "applied": applied,
                "reasons": ["all required controls satisfied"], "missing": []}

    # OR semantics: satisfying any one control is enough.
    if len(missing) < len(unique_required):
        return {"decision": "allow", "applied": applied,
                "reasons": ["at least one OR control satisfied"], "missing": missing}

    decision = "mfa" if MFA in missing else "compliant"
    return {"decision": decision, "applied": applied,
            "reasons": ["grant controls unmet"], "missing": missing}


def explain(policies: List[Dict[str, Any]], context: Dict[str, Any]) -> List[str]:
    """Human-readable trace: why each policy did or did not apply."""
    ctx = SignInContext.from_dict(context)
    lines: List[str] = []
    for raw in policies:
        p = Policy.from_dict(raw)
        if p.state == "disabled":
            lines.append(f"{p.id}: skipped (disabled)")
        elif is_excluded(p, ctx):
            lines.append(f"{p.id}: skipped (excluded user/group)")
        elif applies(p, ctx):
            lines.append(f"{p.id}: APPLIED -> {p.controls or ['(no controls)']}")
        else:
            lines.append(f"{p.id}: not applicable (conditions unmet)")
    return lines

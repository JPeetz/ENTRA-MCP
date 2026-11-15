# entra-continuity-mcp — reference skeleton

The tool contract proposed in `docs/proposals/entra-continuation-pr.md`, implemented far
enough to run, test and argue about.

**Dependency-free on purpose.** Standard library only, Python 3.9+. No FastMCP, no SDK,
no pip install. The JSON-RPC envelope is written out explicitly because in a design
proposal the protocol contract should be readable, not hidden behind a framework.

## Run

```bash
cd proposals/mcp-skeleton
python3 -m continuity.server        # speaks MCP over stdin/stdout
```

## Test

```bash
python3 -m unittest discover -s tests -v
# 16 tests, all passing
```

## Tools

The server is not just an advisor — it is the **local authority downstream services point
at** during an outage. Nine of the thirteen tools exist for that fallback role.

| Tool | Real logic? | What it does |
|---|---|---|
| `get_continuity_status` | stub | healthy / degraded / drill, plus snapshot sequence |
| `fetch_snapshot` | real schema, synthetic data | signed read-only bundle: policies, groups, seq, expiry |
| `verify_snapshot` | **real** | signature, version, expiry, stale-sequence, no-secrets checks |
| `evaluate_policy_locally` | **real** | deterministic CA evaluation → allow / deny / mfa / compliant |
| `explain_denial` | **real** | per-policy trace of why a sign-in was allowed, denied or challenged |
| `diff_policy` | **real** | added / removed / changed between live policy and snapshot |
| `serve_gateway` | **real** | starts the loopback HTTP issuer downstream services call |
| `enrol_session` | **real** | records principal, audience, approved scopes, device key — while healthy |
| `set_continuity_mode` | **real** | healthy / degraded / drill; minting is only possible in the last two |
| `issue_local_token` | **real** | mints a short-lived continuity token from an enrolled session |
| `verify_local_token` | **real** | signature, expiry, audience, continuity marker |
| `get_fallback_endpoint` | **real** | the endpoint downstream should switch to |
| `reconcile_delta` | **real** | drains the audit ledger for replay on recovery |

## Downstream fallback — how a service survives the outage

The gateway is the point of the whole exercise. Downstream services do not talk to the
MCP directly; they point their issuer at it:

```
GET  /health                             -> mode + readiness
GET  /.well-known/continuity-beacon.json  -> SIGNED beacon, served in every mode
GET  /.well-known/openid-configuration    -> local issuer metadata
POST /token                              -> short-lived continuity token
POST /reconcile                          -> drain the tamper-evident ledger
```

### The beacon — always on, for every service

The gateway is **always available**. In every mode, including healthy, it serves a signed
beacon that answers the only question a downstream service needs:

| `authority` | Meaning |
|---|---|
| `cloud` | Keep using Microsoft. The local issuer will not mint. |
| `local` | Microsoft is unreachable — point at this issuer now. |
| `drill` | Rehearsal; minting enabled but flagged non-production. |

The beacon is signed, so a consumer can trust what it discovered (well-known endpoints and
mDNS are otherwise spoofable by anything on the segment), and it expires in 60 seconds — a
stale beacon is treated as unreachable rather than acted on.

### Detection is automatic, not a button

The worst moment to ask a human to declare an incident is during one. `HealthMonitor`
probes the identity plane on three independent signals — DNS, TLS, HTTP — and flips the
mode itself, with **hysteresis on both edges**: three consecutive failures to degrade, two
consecutive successes to recover. A single 502 never starts minting. A 401/404 counts as
*up*, because the service is answering.

Automatic mode is **opt-in** (`set_auto_mode`), so nothing changes behaviour by surprise.

### Bootstrap: tenant administrator → downstream API key

The gateway is not self-authorising. It is bound by **an administrator of your original
Entra tenant**, and that admin's own account is the only thing that can create it:

```
POST /admin/bootstrap     Authorization: Bearer <Entra access token of an admin account>
  → 200 { "api_key": "ok_…", "key_id": …, "tenant_id": …, "scopes": ["continuity.read",
          "continuity.mint"], "expires_at": …, "note": "shown once" }
```

What is checked before a key is issued:

| Check | Refusal |
|---|---|
| Token carries an administrative directory role (`wids` / `roles`) | `admin_not_authorised` |
| Token is not expired | `admin_not_authorised` |
| Token is not one this gateway issued (`xms_continuity`) | `admin_not_authorised` |
| Tenant matches the already-bound tenant | `admin_not_authorised` |
| Signature valid (`validator=` hook → Microsoft JWKS) | `admin_not_authorised` |

Accepted administrative roles: Global Administrator, Application Administrator, Cloud
Application Administrator, Privileged Role Administrator.

The **API key** is what downstream services use. It is deliberately narrower than the admin
token that created it: it can read continuity state and mint continuity tokens, nothing
else. It is stored only as a salted HMAC, compared in constant time, tenant-bound,
revocable, and 90-day limited. The plaintext is returned exactly once and never written to
the audit ledger.

**The admin token can only do this one thing, once.** It cannot mint continuity tokens, and
a continuity token can never be used to bootstrap — that direction is closed explicitly,
because a fallback that can promote itself into its own authority is not a fallback.

Guards that make this safe rather than a permanent bypass:

- **Minting is impossible in `healthy` mode.** The endpoint returns 503 until a mode
  change is declared, and the mode change is itself an audited event.
- **Only pre-enrolled sessions can mint.** Enrolment happens while the tenant is healthy —
  a session that did not exist before the outage cannot be created during it.
- **Hardware binding.** The caller must present the device key captured at enrolment.
- **Scope subset only.** Requested scopes must be within the approved set; escalation
  raises and is logged.
- **Privileged scopes and claims refused outright** — `Directory.*`,
  `RoleManagement.*`, `Application.ReadWrite*`, `roles`, `wids`, `groups`.
- **TTL hard-capped at 3600 s**, default 900 s.
- **Every token carries `xms_continuity: true`** so downstream can apply a stricter
  policy on first contact after recovery.
- **Loopback only.** This must never be internet-facing.

## What is real and what is not

**Real:** the evaluator. Exclusions beat inclusions, conditions AND within a dimension, a
`block` control wins over everything else, `AND`-operator policies require every control,
`reportOnly` policies never enforce, and unknown controls fail closed rather than open.
Snapshot verification rejects tampered payloads, expired snapshots and stale sequences.

**Synthetic:** the signature. It is a demo HMAC so the skeleton runs without Microsoft
keys. The real API signs with a Microsoft key verified against published JWKS — the
local HMAC is **not** a security control and the code says so where it matters.

**Not implemented:** any network call. This never contacts a tenant.

## Worked examples

```jsonc
// AND-operator policy, device not compliant -> deny
{"context": {"user_id":"u1","app_id":"admin-portal","trusted_location":true,
             "mfa_performed":true,"device_compliant":false}}
// -> {"decision":"deny","missing":["require_compliant_device"]}

// same context, MFA absent -> mfa challenge (OR semantics)
{"context": {"user_id":"u1"}}
// -> {"decision":"mfa","missing":["require_mfa"]}
```

## Wiring it into a Hermes / MCP client

```yaml
mcp_servers:
  entra-continuity:
    command: python3
    args: ["-m", "continuity.server"]
    cwd: ~/workspace/entra-sso-reference/proposals/mcp-skeleton
```

## Deliberate omissions (for the PR discussion)

1. **No token issuance.** `POST /continuity/v1/token` is the risky half; the skeleton
   proves evaluation parity first, which is the part that has to be exact.
2. **No policy compiler.** The schema here is a simplified projection of real CA policies;
   a production version needs a converter and a parity test suite against the service.
3. **No persistence.** Snapshots live in memory; real deployments need encrypted-at-rest
   storage with a customer-held key.

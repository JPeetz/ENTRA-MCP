# ENTRA-MCP

**A local continuation layer for Microsoft Entra ID** — so a business keeps authenticating
when the identity plane is down — plus the protocol reference it is built on.

Two artefacts, one argument:

1. **A proposal** to Microsoft (`docs/proposals/entra-continuation-pr.md`) asking for a
   supported continuation API and first-party MCP servers.
2. **A working implementation** of that surface (`proposals/mcp-skeleton/`), 94 tests
   passing, no dependencies, no tenant contact.

> **New here? Start with [`docs/GUIDE.md`](docs/GUIDE.md).** It explains the whole project
> in plain words — what breaks, what this does about it, and how to run it in five minutes.

## The problem

On **12 November 2026** Entra sign-in and dependent applications degraded from roughly
12:00 to 20:00 UTC. Aggregated reports peaked at ~109× the normal rate, dominated by
*"Entra login is not working"* and *"Entra apps not loading"*.
*(Third-party aggregator data — Microsoft published no postmortem at time of writing.)*

For an organisation that authenticates only to Entra, that is not a degraded experience.
It is a **full stop**.

Microsoft already ships every primitive needed to survive it — resilience defaults, backup
authentication, disconnected Azure Local — but **not the contract that lets a customer use
them**. Conditional Access resilience keeps *existing sessions* alive; it cannot issue a
token for a new one. There is no supported way to hold a verifiable local copy of identity
and policy state, and no MCP surface for agents to operate during an outage.

## What the proposal asks for

| API | Purpose |
|---|---|
| `GET /continuity/v1/snapshot` | Signed, read-only policy + membership bundle. **No secrets.** |
| `POST /continuity/v1/token` | Short-lived token from a **pre-enrolled** session, only while an incident is declared |
| `GET /continuity/v1/delta` | Reconcile everything that happened while degraded |

Plus `Entra.Continuity.Mcp` and `Entra.Policy.Mcp` in `microsoft/mcp`.

## What actually runs here

```bash
cd proposals/mcp-skeleton
python3 -m unittest discover -s tests -v     # 94 tests, adversarial by default
python3 -m continuity.server                 # MCP over stdio
```

Thirteen MCP tools, plus a loopback HTTP issuer that downstream services repoint at:

```
GET  /health                             -> mode + readiness
GET  /.well-known/openid-configuration    -> local issuer metadata
POST /token                              -> short-lived continuity token
POST /reconcile                          -> drain the tamper-evident ledger
```

### Attacks that fail, by test

```
wrong device key        -> 403      audience override       -> 403
scope escalation        -> 403      oversized body (40 KB)  -> 413
rapid attempts          -> 429      alg:none forged token   -> rejected
expired enrolment       -> 403      revoked session         -> 403
edited/deleted audit    -> chain breaks
```

The design rule that makes it a fallback rather than a bypass:

> It cannot create a session, cannot widen a scope, cannot change an audience, cannot mint
> outside a declared incident, cannot issue a privileged claim, cannot mint for longer than
> an hour, and cannot hide what it did.

Security model, including six **residual risks** (shared-secret token signing, no mTLS,
in-process key custody, no hardware attestation, clock skew, no policy compiler):
[`proposals/mcp-skeleton/SECURITY.md`](proposals/mcp-skeleton/SECURITY.md).

## Security posture

The fallback is a second way to obtain credentials, so it must be **strictly narrower** than
the real one. Everything below is enforced in code and has a test that attacks it.

| Control | Why |
|---|---|
| **Admin tokens verified with RS256** against the tenant JWKS, before any claim is read | A token that says "I am Global Admin" is worthless unless Microsoft signed it |
| **Fails closed without JWKS** | No trust anchor means no bootstrap, not "trust it anyway" |
| **`alg` allowlist** | `none` and HS256-confusion are the classic JWT bypasses |
| **`jti` replay cache** | A captured admin token works exactly once |
| **HKDF key separation** | Token, beacon and audit keys are independent; one leak does not cascade |
| **HMAC'd audit chain** | Write access is not enough to forge a history — the key is needed too |
| **Bounded handler pool (32)** | Connection floods are refused, not absorbed until OOM |
| **Tenant-bound, hashed, revocable API keys** | Downstream credentials are narrower than the admin token and can be withdrawn |
| **Loopback-only binding** | Never internet-facing; loopback + same-user is the trust boundary |

**Still not done, and stated rather than hidden:** continuity tokens are signed HS256 (a
shared key), there is no mTLS between downstream and gateway, and the signing key is held in
process rather than an HSM. See [`SECURITY.md`](proposals/mcp-skeleton/SECURITY.md).

## Repository map

| Path | Contents |
|---|---|
| `docs/proposals/entra-continuation-pr.md` | The submission: problem, evidence, API + MCP ask, security model |
| `docs/design/delegated-app-platform.md` | Delegated app + API-key platform with approval gating |
| `docs/traps.md` | Verified divergences from the specs, evidence-backed |
| `docs/claims/README.md` | Claim reference — standard vs Entra vs to-verify |
| `evidence/` | Captured public discovery documents, with fetch timestamps |
| `proposals/mcp-skeleton/` | Runnable implementation + 94 tests + SECURITY.md |
| `SCOPE.md` | Four phases, effort, and the legal boundary |

## Rules this repo holds itself to

1. **No live tenant artefacts** — no tenant IDs, object IDs, UPNs, client IDs, tokens.
2. **Synthetic but schema-accurate** samples.
3. **No auth bypass, no MFA/CA evasion, no token-theft tooling.**
4. Phase 4 (undocumented service internals) never shares a repo with the rest.

## Relationship to Active Directory

Entra ID is **not** hosted Active Directory — different protocols (OIDC/SAML vs
Kerberos/LDAP/RPC), different data model, different trust model. They meet in **hybrid
identity** (Entra Connect, PHS, PTA, seamless SSO, device join), which is where deep AD
knowledge is load-bearing. The genuine exception is **Entra Domain Services**, which is
managed Windows Server AD in the cloud.

## Status

- Repo: **published** — https://github.com/JPeetz/ENTRA-MCP
- Microsoft outreach: **submitted** — https://github.com/microsoft/mcp/issues/4182
  (`microsoft/mcp` has Discussions disabled, so this went in as an issue)
- Implementation: **working**, stdlib-only, 94 tests green

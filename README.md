# ENTRA-MCP

**A local continuation layer for Microsoft Entra ID** — so a business keeps authenticating
when the identity plane is down — plus the protocol reference it is built on.

Two artefacts, one argument:

1. **A proposal** to Microsoft (`docs/proposals/entra-continuation-pr.md`) asking for a
   supported continuation API and first-party MCP servers.
2. **A working implementation** of that surface (`proposals/mcp-skeleton/`), 38 tests
   passing, no dependencies, no tenant contact.

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
python3 -m unittest discover -s tests -v     # 38 tests, 14 adversarial
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

Security model, including seven **residual risks** (shared-secret signing, no mTLS,
`http.server` thread growth): [`proposals/mcp-skeleton/SECURITY.md`](proposals/mcp-skeleton/SECURITY.md).

## Repository map

| Path | Contents |
|---|---|
| `docs/proposals/entra-continuation-pr.md` | The submission: problem, evidence, API + MCP ask, security model |
| `docs/design/delegated-app-platform.md` | Delegated app + API-key platform with approval gating |
| `docs/traps.md` | Verified divergences from the specs, evidence-backed |
| `docs/claims/README.md` | Claim reference — standard vs Entra vs to-verify |
| `evidence/` | Captured public discovery documents, with fetch timestamps |
| `proposals/mcp-skeleton/` | Runnable implementation + 38 tests + SECURITY.md |
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

- Proposal: **drafted, not submitted.**
- Implementation: **working**, stdlib-only, 38 tests green.
- Published: **no** — see [`SUBMITTING.md`](SUBMITTING.md) for what remains.

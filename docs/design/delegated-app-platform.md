# Design — delegated app + API-key platform on Entra ID

**Requirement.** AD-gated users may create applications, OAuth clients and API keys for
services they want to use, but **nothing is usable until a superior account approves it**.

## The central finding

Roughly **70% of this already exists in Entra** and should be configured, not coded.
The custom surface is narrow: the API-key issuer and the approval ledger.

| Capability | Native? | Where |
|---|---|---|
| User authenticates, identity from AD (hybrid) | ✅ | Entra ID + Entra Connect |
| Restrict who may register apps | ✅ | "Users can register applications" = No + a role |
| User requests access to an app, admin approves | ✅ | **Admin consent workflow** |
| Request → approver → time-bound grant, with policy | ✅ (licensed) | **Entitlement Management access packages** |
| Per-approver routing to the user's superior | ⚠️ partial | Approver = manager / group, not dynamic chain |
| API key issuance, rotation, revocation | ❌ | **Build** |
| Approval record that the key issuer trusts | ⚠️ | Read from Graph, do not keep a local flag |

**Licensing, verified 2026-11-12:** Entitlement Management *"requires Microsoft Entra ID
Governance or Microsoft Entra Suite subscriptions"* (some capabilities additionally need
P2). The Admin consent workflow page lists only an Azure account and Global Administrator
as prerequisites — **no premium gate is stated there**. So the cheap design is consent
workflow + role assignment; the richer design costs a Governance licence.

## Architecture

```
AD (on-prem) ──Entra Connect──▶ Entra ID (synced users, groups)
                                     │
                    ┌────────────────┴─────────────────┐
                    │                                  │
             [ User portal ]                    [ Approver portal ]
             request app / scope / key           approve or deny
                    │                                  │
                    ▼                                  ▼
        ┌───────────────────────┐          ┌───────────────────────┐
        │ Admin consent workflow│          │ Entitlement Mgmt      │
        │ (app + delegated perm)│          │ (access package)      │
        └───────────┬───────────┘          └───────────┬───────────┘
                    └──────────────┬───────────────────┘
                                   ▼
                        [ Approval ledger ]  ◀── source of truth
                                   │
                          ┌────────┴────────┐
                          ▼                 ▼
                   [ API-key issuer ]   [ Audit / SIEM ]
                          │
                   keys bound to a service principal + scope set
```

## Flow 1 — user wants an app or an API

1. User authenticates (OIDC, delegated). Eligibility is an **AD-synced group**, not a
   local list.
2. User requests: app registration + desired scopes, or API key for service X.
3. Request lands with the **superior** — routed by manager attribute or a designated
   approver group.
4. Approver grants via the native mechanism (consent for app permissions; access package
   for the entitlement).
5. Only then does the issuer mint anything.

## Flow 2 — API key issuance (the part you build)

```
POST /keys  {service, scopes, justification}
  → verify caller's token (aud/iss/exp/scp)      ← Entra-issued, not a local session
  → verify approval in Graph                      ← access package assignment OR
                                                    consent grant, freshly read
  → mint: 32-byte random, prefix "ok_" + 8 chars
  → store: argon2id(key), prefix, sp_id, scopes, expires_at, approver, ticket
  → return plaintext ONCE
```

Rules that are not negotiable:

- **The key never grants more than the approval.** Scopes are copied from the approval
  record at mint time, not supplied by the caller.
- **Approval is re-read from Graph, never trusted from a local flag.** A revoked access
  package must invalidate keys without a second job.
- **Keys expire.** Default 90 days, maximum 180, rotation overlap of 7 days.
- **Hash at rest.** Argon2id, prefix-lookup, constant-time compare.
- **Every mint, use, rotate and revoke is logged** with the approver identity.

## Traps that decide whether this is secure

1. **An approved app can escalate itself.** Once a user owns a service principal, they
   can add credentials to it and, if it holds `Directory.ReadWrite.All` or
   `AppRoleAssignment.ReadWrite.All`, escalate. Approval must scope the **app's
   permissions**, not just its existence.
2. **Creator ≠ approver must be enforced by role, not convention.** If the approver group
   also holds Application Administrator, the control is theatre.
3. **Consent phishing is the actual threat model.** An approved redirect URI that the
   attacker controls turns the whole platform into a token-harvesting funnel. Redirect
   URIs must be validated at approval time, and wildcards refused.
4. **API keys bypass Conditional Access.** They carry no user context, no device state,
   no MFA. Treat every key as lower-trust: separate scopes, rate limits, and no access to
   anything a human could not reach from an unmanaged device.
5. **PIM the approver role.** A permanent approver is a permanent single point of
   compromise; make the approval right time-bound and auditable.

## Two client classes, deliberately split

| | Human users | Machine clients |
|---|---|---|
| Credential | OIDC delegated token | Client credentials (preferred) or API key |
| Scoped by | `scp` in token | Approval record |
| Revocation | Session + access package | Key revoke + SP credential remove |
| CA applies | ✅ | ❌ (keys) / partial (client creds) |

**Prefer client credentials over API keys wherever the client can do OAuth.** Keys exist
for the services that cannot, and they should be the exception, measured and reported.

## Open decisions

1. Governance licence (access packages, real approver policy) **or** consent workflow +
   role assignment (no extra licence, weaker policy engine)? This is the cost fork.
2. Is "superior" a fixed approver group, or a hierarchy resolved from the AD manager
   attribute? The latter needs a resolver service; Entra will not walk the chain for you.
3. Do API keys authenticate services **inside** the tenant only, or are they issued to
   external partners? External changes the entire threat model.

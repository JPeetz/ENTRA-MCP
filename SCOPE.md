# Scope and plan

## Definition of "reverse engineer" used here

Three distinct activities, deliberately separated because they carry different risk:

| Activity | Legitimate? | Notes |
|---|---|---|
| Implementing documented protocols and documenting the deltas | Yes | The bulk of the work |
| Traffic analysis of **your own** tenant, published redacted | Yes | Own data, own consent |
| Publishing analysis of **undocumented** service internals | Grey | Separate repo, deliberate decision |

## Phase 1 — Protocol map (publishable, low risk)

**Deliverables**
- Flow notes: authorization code + PKCE, client credentials, device code, on-behalf-of,
  SAML 2.0 SP-initiated, WS-Federation, SCIM 2.0 provisioning.
- Claim reference: every claim, its issuing context (ID vs access token), and how
  presence varies by tenant type and app registration.
- `docs/traps.md`: verified divergences from the base specs.
- Discovery capture per tenant type (`common`, `organizations`, `consumers`, tenant).

**Already verified in this repo**
- `common` discovery document omits `grant_types_supported` and
  `code_challenge_methods_supported`, both of which vanilla OIDC defines. Captured in
  `evidence/oidc-common.json`.

**Done when:** every flow has a runnable harness path and a written trace, and every
claim in the reference has a verified source or is explicitly marked unverified.

## Phase 2 — On-prem foundations (publishable)

Not binary reverse engineering — reading Microsoft's own Open Specifications
(MS-ADTS, MS-KILE, MS-DRSR, MS-NRPC, MS-SPNG) and standing up **Samba** as a domain
controller to observe real Kerberos and LDAP exchanges.

**Deliverables:** a working Samba DC in Docker; captured TGT/service-ticket exchanges;
notes on the PAC, group expansion, and where Entra's claim model maps onto AD
attributes (`onprem_sid`, `onprem_domain`, group SIDs).

**Done when:** you can explain, from captured traffic, how a domain-joined login becomes
a Kerberos ticket set — without touching a Windows binary.

## Phase 3 — Hybrid bridge (publishable)

Entra Connect sync (object/attribute flow, source anchor), password hash sync,
pass-through authentication, seamless SSO, hybrid Entra join.

**Done when:** each mechanism has a documented failure signature — the specific symptom
when it breaks — which is the thing that actually gets searched for at 2am.

## Phase 4 — Service internals (separate repo)

Primary Refresh Token lifecycle, Conditional Access evaluation, device compliance
claims, token binding, undocumented Graph behaviour.

**Constraint:** own tenant only, redacted, and a written decision to publish before any
of it is committed. This phase never shares a repository with Phases 1–3.

## Effort

| Phase | Elapsed |
|---|---|
| 1 | 2–3 weeks part-time |
| 2 | 2–3 weeks part-time |
| 3 | 2–4 weeks part-time |
| 4 | open-ended |

## Explicit non-goals

- Bypassing authentication, MFA, or Conditional Access.
- Credential harvesting, token replay tooling, or anything usable as a phishing kit.
- Republishing Microsoft documentation as if it were original analysis.

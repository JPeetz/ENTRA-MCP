# Ready-to-post: microsoft/mcp discussion

**Venue:** https://github.com/microsoft/mcp/discussions (or Issues → feature request)
**Title:**

> Continuation surface for Entra ID: signed policy snapshot + constrained local issuance

**Body:**

---

### Summary

When the Entra identity plane is unavailable, an organisation that authenticates only to
Entra stops operating — not degraded, stopped. Microsoft already ships most of the
primitives (Conditional Access resilience defaults, Backup Authentication System,
disconnected Azure Local), but there is no supported contract that lets a customer hold a
verifiable local copy of policy and identity state, and no MCP surface for agents to
operate during the outage.

This is a proposal for that contract, with a reference implementation and a test suite.

### Evidence

Entra sign-in and dependent applications degraded on **12 November 2026**, roughly
12:00–20:00 UTC, with aggregated reports peaking at ~109× the normal rate, dominated by
"Entra login is not working" and "Entra apps not loading".

Source: third-party outage aggregators (`instatus.com`, `statusgator`). **Microsoft has not
published a postmortem at time of writing**, so these figures are indicative, not official.

### Where current mitigations stop

| Mechanism | Covers | Stops at |
|---|---|---|
| CA resilience defaults | Keeps existing sessions usable | No new tokens, no new devices |
| Backup Authentication System | Microsoft-internal failover | No customer surface, no API |
| Windows Hello cached creds | Enrolled, previously-signed-in devices | Nothing for VDI, BYOD, service principals, APIs |
| Azure Local disconnected ops | Azure infrastructure | No Entra identity continuation |
| Azure MCP Server v3 | Management plane | Assumes reachability |

### Proposal

**APIs**

- `GET  /continuity/v1/snapshot` — signed, read-only bundle: policies in evaluation-ready
  form, group/role membership for named principals, app registrations and required scopes,
  sequence + validity window. No secrets, no keys, no refresh tokens.
- `POST /continuity/v1/token` — short-lived (≤60 min), scope-allowlisted token, only while
  an incident is declared or a pre-authorised drill window is open. Marked
  `xms_continuity: true` so downstream can step up on reconnect.
- `GET  /continuity/v1/delta` — reconciliation of everything that happened while degraded.

**MCP servers** (this repo)

- `Entra.Continuity.Mcp` — status, snapshot fetch/verify, degraded sessions, reconcile.
- `Entra.Policy.Mcp` — `evaluate_policy_locally(snapshot, context)`, `diff_policy`,
  `explain_denial`. The point is **evaluation parity**: an agent should be able to answer
  "would this sign-in have been allowed?" offline with the same result the service returns.

### Safety properties (the reason this is a fallback and not a bypass)

1. Continuation can never escalate — snapshot roles are a read-only subset.
2. Time-boxed by construction — issuance requires an active incident or declared drill.
3. Hardware-bound — credentials derive from a key enrolled while healthy.
4. Visible — every continuity token carries a marker claim.
5. No offline master secrets — the snapshot is data, not a credential store.
6. Customer-held keys — snapshots encrypted to a customer key.

### Reference implementation

A dependency-free stdio MCP server implementing the tool contract, plus a loopback issuer
(`/health`, OIDC discovery, `/token`, `/reconcile`) so downstream services repoint by
configuration. 94 tests, most of them adversarial: audience override, scope escalation,
device-key brute force, `alg:none` forgery, expired/revoked sessions, audit tampering,
oversized bodies — all refused.

Repository: `<link once published>`

### Questions for the team

1. Is a snapshot model compatible with the existing resilience defaults, or does it
   supersede them?
2. What is the minimum safe snapshot TTL given token lifetime policy?
3. Can Azure Local disconnected operations host the continuation service, making the path
   single-vendor and air-gappable?
4. Would Microsoft publish a reference `evaluate_policy_locally` so third-party gateways
   can match semantics exactly?

---

*Note: the attached implementation is Python for reviewability; `Azure.Mcp.Server` is .NET,
so this is offered as a design + conformance artefact, not a merge-ready PR.*

# Enterprise proposal — Local Synchronization & Continuation for Microsoft Entra ID

**To:** Microsoft Entra product group / Microsoft MCP program
**Subject:** APIs and MCP servers that let enterprises keep operating during an identity outage
**Status:** Draft for submission · 2026-11-12

---

## 1. Ask, in one paragraph

Publish a supported **continuation surface** for Entra ID: a signed, locally-replicable
policy and identity snapshot; a time-boxed, policy-constrained **degraded-mode token
issuance** path; and first-party **MCP servers** that expose both to agents and automation.
Today an enterprise can survive Azure *infrastructure* loss (Azure Local disconnected
operations) but has **no supported way to keep authenticating users when Entra itself is
unavailable**. The gap is not capability — the primitives largely exist — it is a supported,
documented, security-bounded contract.

## 2. Evidence

**Incident, 12 November 2026 (third-party aggregator data; Microsoft has not published a
postmortem at time of writing):** Entra sign-in and dependent application access degraded
from 12:00 UTC, with recovery reported around 20:00 UTC. Aggregated user reports peaked at
**437/hour — 109× the normal rate** — with the dominant symptoms being *"Entra login is not
working"* and *"Entra apps not loading"*. Sources: `instatus.com` incident 2026-11-12-18;
`statusgator` tracking for Microsoft Entra ID. Treat volumes as indicative, not official.

**Why this matters commercially:** for any organisation whose workforce authenticates only
to Entra, an identity-plane outage is a **full stop** — not a degraded experience. Under
DORA and NIS2, that is an operational-resilience finding, not an inconvenience. Microsoft
already publishes DORA mapping for Entra, which makes the absence of a continuation path
the more conspicuous.

## 3. What exists today, and where it stops

| Mechanism | What it covers | Where it stops |
|---|---|---|
| Conditional Access **resilience defaults** | Keeps sessions usable for a bounded window when the IdP is unreachable | Policy-only; does **not** issue new tokens for new sessions or new devices |
| **Backup Authentication System** | Microsoft-internal failover for authentication | Not a customer-controllable surface; no published API |
| Windows Hello / cached credentials | Local unlock on enrolled, previously-signed-in devices | Device-bound; nothing for VDI, BYOD, service principals, or APIs |
| **Azure Local — Disconnected Operations** | Runs Azure infrastructure disconnected | Infrastructure plane only — **no Entra identity continuation** |
| Azure MCP Server (v3) | Management-plane operations via MCP | No continuity semantics; assumes reachability |

**The hole:** there is no supported way to (a) hold a *verifiable* local copy of the
identity and policy state an enterprise needs, and (b) issue short-lived, narrowly-scoped
credentials from it, with guarantees that the degraded path cannot become a permanent
bypass.

## 4. Proposal A — Continuation APIs

### A1. Signed policy + identity snapshot (`GET /continuity/v1/snapshot`)

- Returns a **signed** (Microsoft-keyed) bundle: tenant policy set (CA policies in
  evaluation-ready form), group/role membership for named principals, app registrations and
  their required scopes, plus a validity window and a monotonically increasing sequence.
- Consumer stores it behind the tenant's own key management.
- **Read-only, no secrets** — no password hashes, no keys, no refresh tokens.

### A2. Degraded-mode token issuance (`POST /continuity/v1/token`)

- Available **only** while the control plane declares an incident, or during a declared,
  pre-authorised drill window.
- Requires: a device or workload identity established **before** the outage; a
  hardware-backed key; and a snapshot no older than N hours.
- Issues **short-lived** (≤ 60 min), **narrow** (explicit scope allowlist) tokens marked
  `xms_continuity: true` so downstream services can apply a stricter policy.
- **Cannot** mint privileged roles, cannot modify directory state, cannot enrol new devices.

### A3. Reconciliation (`GET /continuity/v1/delta?since=<seq>`)

- Every action taken in degraded mode is logged locally and replayed on reconnect:
  sessions established, scopes granted, failures.
- Guarantees eventual consistency and gives auditors a single timeline.

### A4. Downstream failover contract — the part that actually keeps a business running

Everything above is useless if applications still call `login.microsoftonline.com`. The
proposal therefore requires a **local issuer that speaks the same shapes** so downstream
services repoint with a configuration change, not a code change:

| Local endpoint | Purpose |
|---|---|
| `GET /health` | mode + readiness, so orchestrators can route |
| `GET /.well-known/continuity-beacon.json` | **always-on signed beacon** — tells every service whether to use the cloud or this issuer |
| `GET /.well-known/openid-configuration` | lets clients discover the fallback issuer natively |
| `POST /token` | short-lived continuity token for a **pre-enrolled** session |
| `POST /reconcile` | drain the local audit ledger on recovery |

**Enrolment is the safety mechanism.** A session can only mint if it was established while
the tenant was healthy — so an outage cannot be used to create new identities or widen an
existing one. Combined with hardware binding, scope-subset enforcement, refusal of
privileged scopes and a hard TTL cap, the fallback is a narrowed continuation of what
already existed, not a parallel identity system.

**Fail-back** is explicit: on recovery the ledger is replayed, every token issued offline
carries `xms_continuity: true`, and downstream services are expected to step up
authentication on first contact.

## 5. Proposal B — MCP servers

Two first-party MCP servers, shipped in `microsoft/mcp`, so agents can operate this
surface without bespoke glue:

**`Entra.Continuity.Mcp`** — tools: `get_continuity_status`, `fetch_snapshot`,
`verify_snapshot`, `list_degraded_sessions`, `reconcile_delta`, `declare_drill_window`.
Read-mostly; every mutating tool requires an explicit human approval token.

**`Entra.Policy.Mcp`** — tools: `evaluate_policy_locally(snapshot, context)`,
`diff_policy(tenant, snapshot)`, `explain_denial(policy_id, context)`.
The value here is **evaluation parity**: an agent should be able to answer "would this
sign-in have been allowed?" against a snapshot, offline, with the same result the service
would have returned.

## 6. Security model — the constraints that make this shippable

1. **Continuation can never escalate.** Snapshot roles are a *subset* rendered read-only;
   no path from a degraded token to a directory write.
2. **Time-boxed by construction.** Degraded issuance requires an active incident or a
   pre-declared drill; both expire automatically and are logged.
3. **Hardware-bound.** Continuation credentials derive from a device/workload key enrolled
   while healthy — not from a password.
4. **Visible.** Every continuation token carries a marker claim; Conditional Access can
   require step-up on first reconnect.
5. **No offline master secrets.** The snapshot is data, not a credential store.
6. **Customer-held keys.** Snapshots encrypted to a customer key; Microsoft cannot decrypt
   a stored copy.

## 7. Success criteria

| Metric | Target |
|---|---|
| New sessions issuable during IdP outage | > 0 (today: 0) |
| Time to restore authentication after outage onset | < 5 min (from local replica) |
| Privilege escalation paths introduced | 0 by design review |
| Reconnect reconciliation completeness | 100% of degraded actions |

## 8. Scope and sequencing

1. **Phase 1 (6–9 months):** snapshot API + local policy evaluation; MCP read tools; drills.
2. **Phase 2:** degraded token issuance for first-party apps, then third-party via
   `xms_continuity` claim.
3. **Phase 3:** reconciliation API, audit integration, and DORA/NIS2 evidence packs.

## 9. Open questions for Microsoft

1. Is the snapshot model compatible with existing **resilience defaults**, or does it
   supersede them?
2. What is the minimum safe snapshot TTL given token lifetime policy?
3. Can Azure Local disconnected operations host the continuation service, making the whole
   path single-vendor and air-gappable?
4. Would Microsoft expose `evaluate_policy_locally` as a reference implementation so
   third-party gateways can match semantics exactly?

---

### Note on form of submission

If this is filed as a **code contribution**, the equivalent artefact is a design document +
MCP server skeleton PR against `microsoft/mcp`. If filed as a **product request**, the
above is submailable as-is through the Entra feedback channel. The content is identical;
only the venue differs.

**Attached implementation:** `proposals/mcp-skeleton/` — a runnable, dependency-free stdio
MCP server implementing the tool contract in §5 **and the downstream failover contract in
§A4**. Thirteen tools; the local HTTP issuer (`/health`, discovery, `/token`, `/reconcile`)
runs on loopback inside the same process. All 24 tests pass, including minting refused in
healthy mode, scope-escalation refused, device-key mismatch refused, TTL capped, and a
full HTTP round trip that mints and then re-validates a token. Only the snapshot signature
is a labelled demo stand-in.

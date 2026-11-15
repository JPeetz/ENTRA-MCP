# Security model — continuity gateway

A fallback identity issuer is, by definition, a second way to obtain credentials. If it is
not narrower than the real one, it is not a fallback — it is a bypass. This document states
what it trusts, what it refuses, what the tests prove, and what remains open.

## Trust boundaries

```
  downstream service  ──HTTP, loopback──▶  gateway  ──▶  in-process state
        (must already hold                     (minting authority)
         session id + device key)                     │
                                                      ▼
                                              audit chain (hash-linked)
```

No network egress. No tenant contact. The gateway never holds a Microsoft credential.

## Assets, in order of value

1. **Token signing key** — compromise means unlimited forged continuity tokens.
2. **Device keys** — the only secret protecting a session.
3. **Session records** — subject, audience, approved scopes.
4. **Audit ledger** — the evidence trail after an incident.

## Threats, mitigations, and the test that proves each

| # | Threat | Attack | Mitigation | Proven by |
|---|---|---|---|---|
| T1 | Device-key brute force | Try short keys offline against `/token` | Sliding-window rate limit before lookup | `test_rate_limit_blocks_bruteforce` |
| T2 | Timing oracle | Infer key prefixes from response time | `hmac.compare_digest` on salted hashes | `test_device_key_not_stored_in_clear` |
| T3 | Key disclosure at rest | Steal snapshot, read device keys | Salted HMAC hashing, no plaintext attribute | `test_device_key_not_stored_in_clear` |
| T4 | Audience confusion | Mint for `api://attacker` off an approved session | Audience fixed at enrolment; override → 403 | `test_audience_override_refused_http` / `_mcp` |
| T5 | Privilege injection | Smuggle `roles`/`wids` via extra claims | Forbidden claim list, hard fail | `test_privileged_claim_refused` |
| T6 | Scope escalation | Request a scope never approved | Subset check at mint | `test_scope_escalation_refused` |
| T7 | Algorithm confusion | Forge `alg: none` or swap to another alg | Signature + explicit alg allowlist | `test_alg_none_token_refused` |
| T8 | Token replay off-host | Steal a bearer token, use elsewhere | `cnf.jkt` proof-of-possession claim + short TTL | `test_token_bound_to_device` |
| T9 | Stale enrolment | Use a session from months ago | Enrolment expiry | `test_expired_session_refused` |
| T10 | Post-revocation minting | Mint after the session was revoked | `usable()` gate | `test_revoked_session_refused` |
| T11 | Audit tampering | Edit or delete ledger entries | Hash chain, verified on drain | `test_audit_tampering_detected`, `test_audit_deletion_detected` |
| T12 | Memory-exhaustion DoS | 40 KB+ body to `/token` | `MAX_BODY` refused before read → 413 | `test_body_too_large_refused` |
| T13 | Session enumeration | Probe ids to learn which exist | Rate limit precedes lookup | covered by T1 test path |
| T14 | Healthy-mode bypass | Mint while the tenant is fine | 503 unless degraded/drill | `test_gateway_http_flow` (503 assertion) |
| T15 | Beacon spoofing | Rogue LAN service advertises itself as the fallback | Beacon is HMAC-signed; consumers verify before acting | `test_tampered_beacon_rejected` |
| T16 | Beacon replay / staleness | Old beacon replayed after recovery | 60 s TTL; expired beacon is treated as unreachable | `test_expired_beacon_rejected` |
| T17 | Oscillation attack | Flap the probe to force mode churn and mint inside windows | Hysteresis both edges (3 fails / 2 successes) | `test_flapping_does_not_degrade` |
| T18 | Silent behaviour change | Auto-detection switching modes unasked | Opt-in only; every transition audited | `test_disabled_by_default`, `test_transition_is_audited` |
| T19 | Self-promotion | A continuity token used to bootstrap the gateway into wider authority | `xms_continuity` claim refused at bootstrap | `test_continuity_token_cannot_bootstrap` |
| T20 | Tenant hijack | A different tenant's admin rebinding the gateway | First bootstrap binds; later mismatches refused | `test_second_tenant_cannot_rebind` |
| T21 | Key theft / leakage | Stolen API key used to mint | Hashed at rest, constant-time compare, revocable, never in audit log | `test_revoked_key_stops_minting`, `test_plaintext_key_is_not_stored` |
| T22 | Unauthenticated minting | Calling `/token` without a key | 401 before any session lookup | `test_key_mints_and_keyless_caller_cannot` |

**72 tests total.** The `test_security`, `test_beacon` and `test_admin` suites are
adversarial by construction: each case performs an attack and asserts it is refused. If a
guard regresses, a test goes red.

**Unwired hook — stated plainly:** admin token **signature** verification is a hook
(`verify_admin_claims(validator=...)`) and is *not* wired in this skeleton. Everything else
about the token is checked (role, tenant, expiry, continuity marker), but until `validator`
is bound to `https://login.microsoftonline.com/{tid}/discovery/v2.0/keys` the check proves
what the token *claims*, not who issued it. Faking that would be worse than leaving it
visible; in production it must be wired and fail closed.

## Side-channel notes

- **Timing.** Device-key comparison and audit verification are constant-time. Session
  lookup by dict key is not, but the rate limiter bounds the observable sample and the
  response codes are deliberately coarse (404 for unknown, 403 for refused).
- **Error message leakage.** Responses never echo the device key, the signing key, or the
  expected audience. `audience_not_approved` returns the *approved* audience on purpose —
  the caller already holds the session id, so this is not new information; if that trade
  is unwanted, drop the field.
- **Log contents.** The audit chain records `subject`, `session`, `scope`, `ttl` and denial
  reasons. It deliberately does **not** record device keys or tokens.
- **Timing of mode transitions.** `/health` reports the mode; that is intentional (routing
  needs it) and is not a secret.

## Residual risks — stated plainly, not mitigated in the skeleton

| Risk | Why it matters | Production answer |
|---|---|---|
| **HS256 shared key** | Every consumer holding the key can mint. A single leak is total. | Asymmetric signing (ES256/RS256); publish the public half at `/jwks.json`; per-consumer keys |
| **No mTLS on the gateway** | Any local process that learns a session id + device key can mint | mTLS or workload identity between downstream and gateway |
| **http.server thread growth** | Connection flood exhausts threads | Front with nginx/envoy with `worker_connections` and rate limits |
| **Single-process key custody** | Gateway compromise = mint authority | HSM/KMS-held key, non-exportable, PAM-gated start |
| **No HSM-backed device attestation** | Device key is a shared secret, not a hardware assertion | WebAuthn/TPM attestation with a real key pair |
| **Clock skew** | ±30 s tolerance on `nbf`; larger skew rejects valid tokens | Time sync + configurable skew, monitored |
| **Policy compiler absence** | Snapshot policies are a simplified projection of real CA | Converter + parity suite against the service |

## What the gateway refuses to do — by design

This is the sentence that makes it a fallback rather than a bypass:

> It cannot create a session, cannot widen a scope, cannot change an audience, cannot mint
> outside a declared incident, cannot issue a privileged claim, cannot mint for longer than
> one hour, and cannot hide what it did.

If a future change breaks any clause of that sentence, the change is wrong regardless of
what it fixes.

## Reporting

This is a reference skeleton, not a shipped product. If you fork it for real use, add:
dependency scanning, secret scanning in CI (`gitleaks`), SAST, and a signing-key rotation
runbook with an overlap window.

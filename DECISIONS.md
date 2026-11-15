# DECISIONS

Decisions, and the reasoning that produced them. A decision without a recorded *why* gets
relitigated by the next session; worse, it gets silently reversed.

---

## D1 — Publish as an issue, not a pull request

`microsoft/mcp` is C#. This implementation is Python. A PR would arrive in a language the
repo does not build, with no prior agreement on the contract, and would be closed on triage.

**Sequence:** issue (is the contract wanted?) → agreement → .NET implementation → PR.
The issue is a conversation opener; a PR that gets closed changes nothing.

*Rejected:* opening a PR with the Python skeleton attached to "start the discussion".

---

## D2 — Audience is fixed at enrolment

A caller must never be able to widen `aud`. This was a real privilege-escalation bug in the
first revision: `issue_local_token` accepted a caller-supplied audience.

**Rule:** the audience comes from the session record, never from the request.

---

## D3 — Fail closed without a JWKS

Earlier the admin token's *claims* were trusted without verifying Microsoft's signature.
Once RS256 verification existed, the remaining choice was the default when no key set is
loaded.

**Chosen:** refuse (`admin_signature_unverifiable`). `allow_unverified_admin` exists for local
testing only and is named to be alarming.

*Rejected:* trusting claims with a warning. A warning in a log is not a control.

---

## D4 — Ed25519 for continuity tokens, HS256 opt-in

HS256 means every verifier can also mint. That is the wrong shape for a fallback whose whole
purpose is to be a *narrower* second door.

**Chosen:** EdDSA default; public key published at `/jwks.json`; each verifier refuses the
other algorithm outright (kills key-confusion in both directions). HS256 retained for devices
that cannot do Ed25519 — explicit, never silent.

---

## D5 — Hand-rolled Ed25519, validated against RFC vectors

Hand-rolling crypto is normally wrong. It is defensible here only because the algorithm is
fully specified, the implementation is small enough to audit, and it is checked **byte for
byte** against RFC 8032 §7.1 — not against itself.

This decision has already paid for itself: the first version failed to clear the low three
bits of the clamped scalar, so roughly a third of keys derived wrongly, while two hand-picked
keys still "worked". The published vectors caught it immediately.

*Rejected:* adding `cryptography` as a dependency — the fallback path should not need a wheel
that may not be installable on the machine that is having the outage.

---

## D6 — One master secret, four derived keys

Token signing, beacon signing, audit chaining and device-key hashing each get their own HKDF
derivation. A leaked beacon key must not sign tokens.

---

## D7 — Detection is automatic, but opt-in

Failover that waits for a human to declare an incident fails precisely when nobody has time
to declare it. `HealthMonitor` probes DNS, TLS and HTTP separately and flips the mode itself.

**But:** hysteresis on both edges (3 failures down, 2 successes up), and automatic mode is
opt-in (`set_auto_mode`) so nothing changes behaviour by surprise. Every transition is
audited.

---

## D8 — The beacon is served in every mode

Discovery, not just availability, is the missing piece. A service cannot fail over to an
endpoint it cannot find. The beacon is always on, signed (LAN discovery is spoofable), and
carries a 60-second TTL so a stale beacon is treated as unreachable rather than acted on.

---

## D9 — CI enforces the docs

The repo shipped "16 tests" while running 38, then "38" while running 72, then "72" while
running 94. Every instance was caught by hand, which is not a process.

`tools/claim_check.py` fails the build when a stated count disagrees with the code. It found a stale test-count claim in the proposal on its first run.

---

## D10 — Do not fabricate, ever

If a tool cannot run, the answer includes the gap. The repo's credibility rests on every
number being reproducible; one invented result would cost more than the whole project is
worth.

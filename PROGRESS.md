# PROGRESS

## Current State

Last commit: `45208c9` (harness install) · `make check`: passing (112 tests) · CI: green on 3.9 + 3.12

The repo is a working reference implementation plus a proposal. Nothing is mid-edit; the tree
is consistent.

## In Progress

Nothing active. Last completed work: Ed25519 signing for continuity tokens, with RFC 8032
vector tests, plus CI enforcement of the doc/code consistency.

## Next Steps

1. **Write `AGENTS.md`** — the operating manual the harness audit requires is blocked on
   explicit approval (protected file). Until it exists, this repo is not safely driveable by
   a long-running agent session.
2. **Watch microsoft/mcp#4182** — no human reply yet; labelled `needs-team-triage`. Do not
   write a .NET port until someone confirms the contract is wanted.
3. **mTLS between downstream and gateway** — the largest remaining security gap
   (`SECURITY.md`, residual risks). Design first: which identity does a local caller present?
4. **Policy compiler parity** — `evaluate_policy_locally` covers a simplified projection of
   Conditional Access. A parity suite against the service is the missing proof.
5. **HSM/KMS key custody** — signing key currently lives in process memory.

## Blockers

- `AGENTS.md` cannot be created without user approval (protected agent-instruction file). The
  harness audit therefore reports CRITICAL failures for instructions and verification docs.
- GitHub PAT supplied in chat is still live and carries broad scopes. Not a blocker for work,
  but it should be rotated: nothing here depends on it.

## Session log

- `45208c9` — harness install (PROGRESS/DECISIONS/feature_list/Makefile/scripts/arch rules).
- `33a2f5d` — Ed25519 default, JWKS publication, CI (tests + secret scan + claim check); fixed
  a 3.9 runner provisioning failure by pinning ubuntu-22.04.
- `53a1040` — RS256 admin-token verification, HKDF key separation, HMAC'd audit chain,
  bounded handler pool, replay cache. (Suite then: 94.)
- `6b46b12` — repaired doc section ordering and stale claims left by the security pass.

# Traps — verified divergences and failure modes

Each entry records something observed, with the date and the evidence file. Nothing here
is recalled from memory; if it is not verified it is marked **unverified**.

## T1 — `common` discovery document omits PKCE and grant-type metadata

**Verified** 2026-11-12 · `evidence/oidc-common.json`

The `common` tenant's OpenID discovery document:

```
grant_types_supported              → absent
code_challenge_methods_supported   → absent
```

Vanilla OpenID Connect Discovery defines both. Their absence breaks spec-strict clients
that use the document to decide whether PKCE is available — a client that requires the
field to be present will refuse to start against Entra, even though PKCE works on the
authorization endpoint.

**Practical consequence:** never infer PKCE support from the discovery document. Assume
it and test the authorize endpoint (`code_challenge` + `code_challenge_method=S256`).

## T2 — the issuer is a template, not a literal

**Verified** 2026-11-12 · `evidence/oidc-common.json`

```json
"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"
```

Returned literally with `{tenantid}` unsubstituted when queried through `common`. Token
validation that string-matches `iss` against the discovery `issuer` will fail on every
real token. Resolve the tenant first, or validate against the tenant-specific document.

## T3 — only RS256 is advertised

**Verified** 2026-11-12 · `evidence/oidc-common.json`

`id_token_signing_alg_values_supported: ["RS256"]`. Any harness or validator that
assumes algorithm agility should be informed by this, and multi-tenant apps should treat
an unexpected `alg` as an attack signal rather than a configuration variant.

---

## To verify in Phase 1

- Claim presence differences between ID tokens and access tokens.
- `ver` behaviour on v1 vs v2 endpoints.
- Token lifetime variance by tenant type and by policy.
- Error-code surface for `invalid_grant` sub-causes (they are not distinguishable in the
  response body — confirm what *is* distinguishable).

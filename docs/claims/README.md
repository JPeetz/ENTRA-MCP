# Claim reference

Status key: **std** = defined by OpenID Connect / OAuth core specs · **entra** =
Microsoft-specific · **verify** = presence/behaviour to be confirmed in Phase 1 against
a dev tenant.

> No example tokens in this repo contain real values. Where an example appears it is
> synthetic and schema-accurate.

## Identity (standard)

| Claim | Token | Notes |
|---|---|---|
| `iss` | ID | Tenant-template in `common` discovery — see traps.md T2 |
| `sub` | ID | Pairwise per (user, app). Never use as a cross-app user key |
| `aud` | both | Client ID of the intended audience |
| `exp` / `nbf` / `iat` | both | NumericDate |
| `nonce` | ID | Replay protection; must be echoed from the request |
| `auth_time` | ID | When the user actually authenticated |
| `amr` | ID | Auth methods (`pwd`, `mfa`, …) — **verify** exact set |
| `acr` | ID | Auth context class ref |
| `at_hash` / `c_hash` | ID | Binding to access/authorization code |
| `azp` | both | Authorised party (acting client) |

## Identity (Entra-specific)

| Claim | Token | Notes |
|---|---|---|
| `tid` | both | Tenant ID — the reliable tenant discriminator |
| `oid` | both | Immutable object ID **within a tenant**; the correct user key |
| `upn` | both | May be absent for guest users — **verify** |
| `unique_name` | both | Legacy; may not be an email — **verify** |
| `preferred_username` | ID | Mutable; not an identifier |
| `name`, `given_name`, `family_name` | ID | Display only |
| `groups` | both | Overage behaviour above the claim limit — **verify** threshold |
| `roles` | both | App roles |
| `wids` | both | Well-known directory role template IDs |
| `scp` | access | Delegated scopes |
| `appid` | both | v1-era client id |
| `ver` | both | `1.0` or `2.0` — changes endpoint shapes |
| `ipaddr` | both | Client IP |
| `onprem_sid` | both | Populated only for synced identities |
| `deviceid` | both | Present for device-bound tokens |
| `xms_*` | varies | Reserved family — treat as unstable |

## The rule that matters

`sub` for identifying a user **within one app**, `oid` for identifying a user **within
one tenant**. Using `upn`, `email`, or `preferred_username` as a key is the single most
common integration bug in this space: all three are mutable and two of them are optional.

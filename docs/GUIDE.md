# ENTRA-MCP — the simple guide

This page explains the whole project in small words, on purpose. If you can follow a
recipe, you can follow this.

---

## 1. The problem, in one picture

Every morning, people at a company open their laptops and start work. To get in, they ask
one big online service: *"Is this really Joerg?"* That service is **Microsoft Entra ID**.

```
  Worker ──"let me in?"──► Entra ID ──"yes, it's Joerg"──► Worker gets in
                              │
                          (one big service)
```

Now imagine that one service stops answering. Not slowly — *stops*.

```
  Worker ──"let me in?"──► ......silence......      ✗ nobody gets in
```

On **12 November 2026** this really happened. For about eight hours, many companies could
not sign anyone in. Not because the companies did anything wrong. Because they had only
one door, and the door was locked from the inside.

## 2. What this project is

A **spare key** and a **nightlight**.

- The **spare key** lets your own computers say *"yes, it's Joerg"* for a short while, using
  a copy of the rules they saved earlier. So work does not stop.
- The **nightlight** is a small lamp that is *always* on. It quietly tells every computer
  *"Microsoft is fine, use the normal door"* or *"Microsoft is down, use the spare key."*
  A computer only has to look at the lamp. Nobody has to phone anybody.

```
  Worker ──"let me in?"──► YOUR spare key ──"yes, it's Joerg (for 15 min)"──► Worker gets in
                                  ▲
                            the nightlight said to come here
```

## 3. Words, explained

| Word | What it really means | Think of it as |
|---|---|---|
| **Entra ID** | Microsoft's service that checks who people are | the front door of the building |
| **Tenant** | One company's own copy of that service | your company's building, with its own door |
| **Admin** | A person with the highest permission in the tenant | the building manager with the master key |
| **Token** | A short note that says "this is Joerg, until 14:05" | a visitor badge |
| **API key** | A long password that a computer uses | a key kept in a drawer |
| **Beacon** | A small file that says which door to use | the nightlight |
| **MCP** | A standard way for AI helpers to use tools | a plug socket that fits any tool |
| **Snapshot** | A saved copy of the rules, made while everything worked | a printed copy of the rulebook |

## 4. Who does what

```
┌─────────────────────────────────────────────────────────────┐
│  A building manager (tenant admin) signs in normally         │
│  and says: "here, set up the spare key for this building"    │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
              ┌──────────────────────────┐
              │  THE GATEWAY (this code) │
              │  • knows the building    │
              │  • hands out ONE API key │
              └────────────┬─────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │  Your apps use that API key to ask:  │
        │  "give this person a badge"          │
        └──────────────────────────────────────┘
```

**Important:** the building manager's master key is used **once**, to set things up. After
that it is not needed and not kept. What stays is a small key (the API key) that can only
do one job: hand out short visitor badges. It cannot rebuild the building, and it cannot
make more copies of itself.

## 5. Try it in five minutes

You need a computer with Python 3.9 or newer. Nothing else. No downloads, no installs.

```bash
# 1. go to the folder
cd proposals/mcp-skeleton

# 2. start the helper (it will sit and wait for instructions)
python3 -m continuity.server

# 3. in a second window, check everything works
python3 -m unittest discover -s tests
# -> "OK" and a number of tests that passed
```

If you see `OK`, the machine works. That is the whole test.

## 6. The helper's tools, in plain words

These are the things the helper can do when an AI asks it.

| Tool | Plain meaning |
|---|---|
| `admin_bootstrap` | "I am the building manager. Set this up." → you get an API key |
| `serve_gateway` | "Open the small office" (start the local service) |
| `enrol_session` | "Write Joerg into the guest book, so he can get a badge later" |
| `set_continuity_mode` | "We are in an emergency now" / "The emergency is over" |
| `issue_local_token` | "Give Joerg a badge, valid for 15 minutes" |
| `verify_local_token` | "Is this badge real?" |
| `get_beacon` | "Which door should I use right now?" |
| `probe_idp` | "Is the big door working? Let me check." |
| `set_auto_mode` | "Watch the big door for me and switch automatically" |
| `get_fallback_endpoint` | "Where do I go if the big door is down?" |
| `reconcile_delta` | "Tell me everything that happened while we were on the spare key" |
| `fetch_snapshot` | "Give me the saved copy of the rulebook" |
| `verify_snapshot` | "Is this rulebook genuine, and is it still fresh?" |
| `evaluate_policy_locally` | "Would this person have been allowed in? Answer without asking Microsoft" |
| `explain_denial` | "Why was this person refused?" |
| `diff_policy` | "What changed since we saved the rulebook?" |
| `get_continuity_status` | "How are we doing?" |

## 7. The five things that keep this safe

Read these. They are the point of the project.

1. **The spare key cannot make better guests.** A badge made during an outage is smaller,
   not bigger. It can do a little, not a lot.
2. **Badges last a short time.** Fifteen minutes by default. Never more than an hour.
3. **There is no copy of the master key.** The admin's key is used to set up, then gone.
4. **Everything is written down.** A list nobody can quietly edit — if anything is changed,
   the list stops checking out.
5. **The nightlight never lies for long.** It is only trusted for 60 seconds. An old
   nightlight is treated as *broken*, not as *maybe true*.

## 8. What you must never do

- Do **not** put this service on the internet. It belongs on `127.0.0.1` (your own computer
  only).
- Do **not** paste an API key into a config file or into a chat. Put it in a secret manager.
- Do **not** leave `set_auto_mode` on without watching it the first time. Try it in a drill
  first (`set_continuity_mode` → `drill`).
- Do **not** use this as a way to skip Microsoft's rules. It is a *spare key for an
  emergency*, not a second front door.

## 9. What is not finished

Being honest is part of the project.

- **The master key's signature is not checked yet.** The code checks what the token *says*
  (which roles, which tenant, not expired) but not that Microsoft truly signed it. The hook
  for that is there and empty on purpose. Before real use, it must be connected to
  Microsoft's public keys and must refuse anything it cannot verify.
- Everything is **synthetic**. No real company data is inside.
- The shared-key signing model should become proper public/private keys.

## 10. If you only remember one sentence

> When Microsoft's door is locked, the company should not have to stop working — and it
> should be able to find its own spare key without being told.

---

### Where to read more

| If you want… | Open |
|---|---|
| the official proposal to Microsoft | `docs/proposals/entra-continuation-pr.md` |
| the security detail and what is still risky | `proposals/mcp-skeleton/SECURITY.md` |
| the exact tool list with real behaviour | `proposals/mcp-skeleton/README.md` |
| the ready-to-post text for the Microsoft thread | `docs/proposals/microsoft-post.md` |

# Submitting ENTRA-MCP

Current state: **everything is local and committed. Nothing has been pushed or sent.**

```
repo      ~/workspace/ENTRA-MCP
remote    none
gh CLI    not installed on this machine
ssh       ~/.ssh/hermes_m5_ed25519 exists but is NOT authorised on github.com
```

So publishing is blocked on credentials, not on content.

## Step 1 — publish the repository (pick one)

**A. SSH key already on this machine?** Add `~/.ssh/hermes_m5_ed25519.pub` to
GitHub → Settings → SSH and GPG keys, then:

```bash
cd ~/workspace/ENTRA-MCP
git remote add origin git@github.com:JPeetz/ENTRA-MCP.git
git branch -M main
git push -u origin main
```

(Create the empty repo at https://github.com/new first — name `ENTRA-MCP`, public,
**no** README/.gitignore/licence, so the first push isn't rejected.)

**B. Install the CLI instead:**

```bash
brew install gh && gh auth login
gh repo create JPeetz/ENTRA-MCP --public --source=. --remote=origin --push
```

**C. No credentials on this box?** Push from the machine that has them — the repo is
self-contained and needs nothing but `git`.

## Step 2 — Microsoft outreach (optional, separate decision)

| Venue | What to post | Note |
|---|---|---|
| Discussion on `microsoft/mcp` | `docs/proposals/entra-continuation-pr.md` + link to the repo | Best fit: a design conversation, not a code merge |
| Issue on `microsoft/mcp` | Same, framed as a feature request | Faster triage, less discussion |
| Entra feedback channel | The API half (§4), not the MCP half | Product request only |

**Do not open a code PR against `microsoft/mcp`** without porting the server to .NET —
`Azure.Mcp.Server` is C#, and a Python skeleton will not merge regardless of quality.

Suggested framing for the discussion title:

> Continuation surface for Entra ID: signed policy snapshot + constrained local issuance
> (design + reference implementation)

## Step 3 — pre-flight before making it public

- [ ] `git log --oneline` shows no secret-bearing commit (history is forever)
- [ ] No `.env` committed — `.gitignore` covers `.env`, `*.token`, `*.jwt`, `captures/`,
      `traces/`, `*.har`
- [ ] Run a secret scan: `gitleaks detect --source . --no-git`
- [ ] `LICENSE` present (MIT in this repo — change if you want a different posture)
- [ ] Confirm the incident figures are still attributed to the third-party aggregator, and
      Microsoft still has not published a postmortem
- [ ] Decide whether `evidence/oidc-common.json` stays (it is public, but it is a capture)

## What is deliberately not included

- No live tenant identifiers, tokens, or screenshots.
- No tenant-specific configuration.
- Phase 4 material (undocumented service internals) — that belongs in a separate repo,
  and only after an explicit decision to publish it.

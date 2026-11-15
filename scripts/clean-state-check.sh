#!/usr/bin/env bash
# Clock-out gate. Idempotent: safe to run as often as you like.
#
#   bash scripts/clean-state-check.sh .
#
# A session is not complete until all five dimensions pass. This exists because "I think
# I'm done" is not a state, and an agent that believes it is finished is exactly the agent
# that leaves the tree broken.
set -uo pipefail

REPO="${1:-.}"
cd "$REPO"
FAIL=0

ok()   { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; FAIL=1; }

echo "clean-state check"

# 1 — build / static
if python3 -m compileall -q proposals/mcp-skeleton/continuity >/dev/null 2>&1; then
  ok "build: modules compile"
else
  bad "build: compileall failed"
fi

# 2 — tests
if ( cd proposals/mcp-skeleton && python3 -W error::ResourceWarning -m unittest discover -s tests >/tmp/clean_tests.log 2>&1 ); then
  n=$(grep -oE "Ran [0-9]+ tests" /tmp/clean_tests.log | grep -oE "[0-9]+" | head -1)
  ok "tests: ${n:-?} passing"
else
  bad "tests: failing (see /tmp/clean_tests.log)"
fi

# 3 — state files updated
if grep -q "Last commit:" PROGRESS.md 2>/dev/null; then
  ok "state: PROGRESS.md has a Current State line"
else
  bad "state: PROGRESS.md missing 'Last commit:'"
fi

if python3 - <<'PY'
import json, sys
try:
    items = json.load(open("feature_list.json"))
except Exception:
    sys.exit(1)
ids = {f["id"] for f in items}
active = [f for f in items if f["state"] == "active"]
# WIP=1
if len(active) > 1:
    print("  FAIL  state: more than one active feature:", [f["id"] for f in active])
    sys.exit(1)
# passing features must carry evidence
for f in items:
    if f["state"] == "passing" and not f.get("evidence"):
        print(f"  FAIL  state: {f['id']} is passing without evidence")
        sys.exit(1)
print(f"  PASS  state: {len(ids)} features, {len(active)} active")
PY
then :; else bad "state: feature_list.json check failed"; fi

# 4 — no debug artifacts
DEBRIS=$(git status --porcelain 2>/dev/null | grep -E "\.(orig|rej|bak|log)$|__pycache__|\.DS_Store" || true)
if [[ -z "$DEBRIS" ]]; then
  ok "hygiene: no debug artifacts staged or untracked"
else
  bad "hygiene: debug artifacts present"
  echo "$DEBRIS" | sed 's/^/        /'
fi

# 5 — the gate itself
if make -s check >/tmp/clean_check.log 2>&1; then
  ok "gate: make check exits 0"
else
  bad "gate: make check failed (see /tmp/clean_check.log)"
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
  echo "clean-state: PASS — safe to commit."
else
  echo "clean-state: FAIL — do not commit yet."
fi
exit $FAIL

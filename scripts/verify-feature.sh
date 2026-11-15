#!/usr/bin/env bash
# Run a feature's verification layers in order, then record evidence.
#
#   bash scripts/verify-feature.sh F03
#
# A feature only becomes `passing` through this script. Setting state by hand is the failure
# mode this exists to prevent: the state file must never claim more than the code proves.
set -uo pipefail

FEATURE="${1:-}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKEL="$REPO/proposals/mcp-skeleton"
LIST="$REPO/feature_list.json"

[[ -n "$FEATURE" ]] || { echo "usage: verify-feature.sh <feature-id>"; exit 2; }
[[ -f "$LIST" ]]    || { echo "feature_list.json not found"; exit 2; }

cd "$REPO"

read -r ID NLAYERS < <(python3 - "$LIST" "$FEATURE" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))
for f in items:
    if f["id"] == sys.argv[2]:
        print(f["id"], len(f.get("layers") or []))
        break
else:
    print("", 0)
PY
)

if [[ -z "${ID:-}" ]]; then
  echo "unknown feature: $FEATURE"
  exit 2
fi

if [[ "$NLAYERS" -eq 0 ]]; then
  echo "feature $FEATURE declares no verification layers."
  echo "Add layers[] to feature_list.json first — a feature without a command cannot be proven."
  exit 2
fi

# WIP=1: refuse to verify a feature while another is active.
ACTIVE=$(python3 - "$LIST" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))
print(" ".join(f["id"] for f in items if f["state"] == "active"))
PY
)
if [[ -n "$ACTIVE" && "$ACTIVE" != "$FEATURE" ]]; then
  echo "WIP=1 violated: $ACTIVE is active. Finish it before verifying $FEATURE."
  exit 3
fi

FAILED=0
i=0
while IFS=$'\t' read -r LABEL CMD REPAIR; do
  i=$((i + 1))
  echo ""
  echo "── layer $i/$NLAYERS: $LABEL"
  echo "   \$ $CMD"
  if ( cd "$SKEL" && eval "$CMD" ) > /tmp/verify_${FEATURE}_${i}.log 2>&1; then
    echo "   PASS"
  else
    echo "   FAIL"
    tail -15 /tmp/verify_${FEATURE}_${i}.log | sed 's/^/   │ /'
    echo "   repair: $REPAIR"
    FAILED=1
    break
  fi
done < <(python3 - "$LIST" "$FEATURE" <<'PY'
import json, sys
items = json.load(open(sys.argv[1]))
for f in items:
    if f["id"] == sys.argv[2]:
        for layer in f.get("layers") or []:
            print("\t".join([layer.get("label",""), layer.get("cmd",""), layer.get("repair","")]))
PY
)

if [[ $FAILED -ne 0 ]]; then
  echo ""
  echo "verify-feature $FEATURE: FAILED — state unchanged."
  exit 1
fi

COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "uncommitted")
DATE=$(date -u +%Y-%m-%d)
python3 - "$LIST" "$FEATURE" "$COMMIT" "$DATE" <<'PY'
import json, sys
path, fid, commit, date = sys.argv[1:5]
items = json.load(open(path))
for f in items:
    if f["id"] == fid:
        f["state"] = "passing"
        f["evidence"] = f"commit {commit}, verified {date}"
json.dump(items, open(path, "w"), indent=2)
open(path, "a").write("\n")
PY

echo ""
echo "verify-feature $FEATURE: PASS — state=passing, evidence recorded (commit $COMMIT, $DATE)."
echo "Remember: the evidence points at the working tree. Commit, then re-run if HEAD moved."

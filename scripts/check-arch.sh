#!/usr/bin/env bash
# Architectural constraint runner.
#
#   bash scripts/check-arch.sh .
#
# Prints WHAT / WHY / FIX for every violation, because a rule an agent cannot act on is
# just noise with a rule number attached.
set -uo pipefail

REPO="${1:-.}"
cd "$REPO"

python3 - <<'PY'
import fnmatch
import glob
import json
import re
import sys

rules_path = ".harness/arch-rules.json"
try:
    data = json.load(open(rules_path))
except FileNotFoundError:
    print(f"check-arch: {rules_path} missing")
    sys.exit(1)

violations = []
for rule in data.get("rules", []):
    pattern = rule["glob"]
    files = glob.glob(pattern, recursive=True)
    rx = re.compile(rule["forbidden"])
    exclude = set(rule.get("exclude", []))
    for path in files:
        if path in exclude or not path.endswith(".py"):
            continue
        try:
            lines = open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if rx.search(line):
                violations.append((rule, path, n, line.strip()[:100]))

if violations:
    print(f"check-arch: {len(violations)} violation(s)\n")
    for rule, path, n, snippet in violations:
        print(f"  [{rule['id']}] {path}:{n}")
        print(f"    WHAT: {rule['what']}")
        print(f"    WHY:  {rule['why']}")
        print(f"    FIX:  {rule['fix']}")
        print(f"    CODE: {snippet}")
        print()
    sys.exit(1)

print(f"check-arch: clean ({len(data.get('rules', []))} rules)")
PY

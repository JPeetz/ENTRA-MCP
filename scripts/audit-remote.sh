#!/usr/bin/env bash
# Run the upstream harness audit against this repo (needs network).
# Not part of `make check` — the gate must work offline, during an outage, precisely.
set -uo pipefail
REPO="${1:-.}"
URL="https://raw.githubusercontent.com/walkinglabs/learn-harness-engineering/main/tools/audit-harness.sh"
TMP="$(mktemp -t audit-harness.XXXXXX)"
trap 'rm -f "$TMP"' EXIT
curl -fsSL "$URL" -o "$TMP" || { echo "could not fetch audit script (offline?)"; exit 2; }
bash "$TMP" "$(cd "$REPO" && pwd)"

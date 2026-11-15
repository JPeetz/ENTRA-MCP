#!/usr/bin/env python3
"""Fail the build on anything that looks like a live credential.

Dependency-free on purpose: a security check that needs a toolchain is a security check that
gets skipped. This is deliberately narrow — high-signal patterns only — because a scanner
that cries wolf gets muted, and a muted scanner is worse than none.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

PATTERNS = [
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Anthropic/OpenAI key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}")),
    ("JWT with signature", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# Test material and fixtures legitimately contain key-shaped data. Named explicitly rather
# than silently skipped.
ALLOWLIST_PATHS = {
    # Signed RS256 JWTs used to prove signature verification. Test material, generated with
    # openssl against a throwaway key; contains no live credential.
    "proposals/mcp-skeleton/tests/fixtures/tokens.json",
    "tools/secret_scan.py",            # this file necessarily contains the patterns
}

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}


def main() -> int:
    hits = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(d in path.parts for d in SKIP_DIRS):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel in ALLOWLIST_PATHS:
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for name, rx in PATTERNS:
            for m in rx.finditer(text):
                line = text[:m.start()].count("\n") + 1
                hits.append(f"{rel}:{line}: {name}")

    if hits:
        print("Potential credentials found:\n")
        for h in hits:
            print("  " + h)
        print("\nIf one of these is legitimate test material, add the path to "
              "ALLOWLIST_PATHS with a reason.")
        return 1

    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

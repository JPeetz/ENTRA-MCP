#!/usr/bin/env python3
"""Fail the build when the docs drift from the code.

Every number in a README is a claim. Claims rot: this repo shipped "16 tests" while running
38, then "38" while running 72, then "72" while running 94. Each time it was caught by hand,
which is not a process.

This check is deliberately narrow — the counts that people actually read — so that a red
build means "the docs are wrong", never "the checker is noisy".
"""

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKEL = ROOT / "proposals" / "mcp-skeleton"

WORD_NUMBERS = {"seventeen": 17, "sixteen": 16, "eighteen": 18, "nineteen": 19,
                "twenty": 20, "thirteen": 13, "fourteen": 14, "fifteen": 15}


def count_tests() -> int:
    n = 0
    for f in (SKEL / "tests").glob("test_*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                n += 1
    return n


def count_tools() -> int:
    import importlib
    sys.path.insert(0, str(SKEL))
    downstream = importlib.import_module("continuity.downstream")
    server = importlib.import_module("continuity.server")
    extra = len(getattr(downstream, "EXTRA_TOOLS", []))
    base = len(getattr(server, "TOOLS", []))
    return base + extra


def main() -> int:
    tests = count_tests()
    tools = count_tools()
    problems = []

    md_files = [p for p in ROOT.rglob("*.md") if ".git" not in p.parts]

    for path in md_files:
        text = path.read_text(errors="ignore")
        rel = path.relative_to(ROOT).as_posix()
        for m in re.finditer(r"\b(\d{1,3})\s+tests\b", text):
            claimed = int(m.group(1))
            if claimed != tests:
                line = text[:m.start()].count("\n") + 1
                problems.append(f"{rel}:{line}: says {claimed} tests, code has {tests}")

        # "seventeen tools" / "17 tools"
        for m in re.finditer(r"\b([a-z]+|\d{1,3})\s+tools\b", text):
            token = m.group(1)
            claimed = int(token) if token.isdigit() else WORD_NUMBERS.get(token)
            if claimed is not None and claimed != tools:
                line = text[:m.start()].count("\n") + 1
                problems.append(f"{rel}:{line}: says {token} tools, code has {tools}")

    if problems:
        print("Documentation claims do not match the code:\n")
        for p in problems:
            print("  " + p)
        print(f"\nActual: {tests} tests, {tools} tools.")
        return 1

    print(f"claim check: clean ({tests} tests, {tools} tools)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

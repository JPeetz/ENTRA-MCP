# The repo is consistent when `make check` exits 0. Nothing else counts.
SKEL := proposals/mcp-skeleton
PY   := python3

.DEFAULT_GOAL := check
.PHONY: check compile test e2e scan claims arch setup verify-feature clean-check vcr audit help

check: compile test scan claims arch  ## full gate: must exit 0 before commit
	@echo "\nmake check: PASS"

compile:  ## layer 1 — everything parses
	@$(PY) -m compileall -q $(SKEL)/continuity tools
	@for f in $(SKEL)/tests/*.py tools/*.py; do $(PY) -m py_compile "$$f"; done
	@echo "compile: ok ($(shell ls $(SKEL)/continuity/*.py | wc -l | tr -d ' ') modules)"

test:  ## layer 2 — behaviour (ResourceWarnings are errors)
	@cd $(SKEL) && $(PY) -W error::ResourceWarning -m unittest discover -s tests
	@echo "test: ok"

e2e:  ## layer 3 — the HTTP boundary specifically
	@cd $(SKEL) && $(PY) -W error::ResourceWarning -m unittest tests.test_downstream tests.test_admin.TestBootstrapOverHttp tests.test_eddsa.TestJwksOverHttp
	@echo "e2e: ok"

scan:  ## no credential-shaped strings in the tree
	@$(PY) tools/secret_scan.py

claims:  ## docs must agree with code (test count, tool count)
	@$(PY) tools/claim_check.py

arch:  ## architecture rules from .harness/arch-rules.json
	@bash scripts/check-arch.sh .

setup:  ## nothing to install: standard library only
	@$(PY) --version
	@test -f requirements.txt && echo "requirements.txt: no third-party runtime deps"

verify-feature:  ## make verify-feature F=F03 — run layers, then record evidence
	@test -n "$(F)" || { echo "usage: make verify-feature F=F03"; exit 2; }
	@bash scripts/verify-feature.sh $(F)

clean-check:  ## clock-out gate: build, tests, state files, no debug artifacts
	@bash scripts/clean-state-check.sh .

vcr:  ## verified-complete ratio: passing / (active + passing)
	@$(PY) -c "import json;f=json.load(open('feature_list.json'));p=[x for x in f if x['state']=='passing'];a=[x for x in f if x['state']=='active'];d=len(p)+len(a);print(f'VCR: {len(p)}/{d} = {100*len(p)//d if d else 0}%');print('active:',[x['id'] for x in a] or 'none')"

audit:  ## external harness audit (needs network; not part of check)
	@bash scripts/audit-remote.sh .

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t

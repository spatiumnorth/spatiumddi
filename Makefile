.PHONY: charts-lint perf-test versions-check versions-upstream workflow-shell-check image-upgrade-check help up down dev build build-supervisor migrate lint test lint-backend lint-frontend test-backend test-cov test-durations \
        openapi \
        lint-untyped-routes \
        lint-untyped-routes-baseline \
        ci ci-backend-lint ci-frontend-lint ci-frontend-build screenshots \
        docs docs-down docs-verify \
        trivy \
        appliance appliance-builder appliance-iso appliance-clean \
        appliance-bake-images appliance-clean-baked-images appliance-dev-iso \
        appliance-baked-iso appliance-baked-iso-cross appliance-verify-arch \
        appliance-stamp-dev appliance-slot-image \
        appliance-fetch-k3s appliance-bake-chart appliance-bake-control-chart \
        appliance-bake-metallb-chart

# #553 — the appliance ISO targets list their fetch/bake steps as
# independent prerequisites with no inter-dependencies. Under ``make -j``
# mkosi's ``appliance`` recipe reads mkosi.extra/ while the bake targets
# are still populating it → the ISO ships without k3s / chart / images,
# and ``appliance-iso`` / ``appliance-slot-image`` can hit "no raw image
# found" before the raw exists. On GNU Make 4.4+ this scopes serialisation
# to just these targets' prerequisites; on older make the target list is
# ignored and it applies globally — either way the race is gone.
.NOTPARALLEL: appliance-dev-iso appliance-baked-iso appliance-iso appliance-slot-image

# ── Configuration ──────────────────────────────────────────────────────────────
COMPOSE        = docker compose
COMPOSE_DEV    = docker compose -f docker-compose.yml -f docker-compose.dev.yml
BACKEND_DIR    = backend
FRONTEND_DIR   = frontend

# The architecture the APPLIANCE image is built for, as a Docker
# platform string (#1026). This drives the whole build: mkosi's
# ``--architecture`` (and through it the kernel + GRUB packages selected
# by ``appliance/mkosi.conf.d/``), the k3s fetch, the container-image
# bake, the root GPT type both ISO scripts look for, and the
# ``APPLIANCE_ARCH`` stamped into /etc/spatiumddi/appliance-release.
#
# Declared globally (rather than only target-scoped on the two
# cross-build targets, where it was) because ``appliance-stamp-dev``
# writes it into ``/etc/spatiumddi/appliance-release`` — and an
# undefined variable there would stamp an EMPTY architecture, which the
# host runner would read as a value and compare, rather than as the
# absence it actually is.
APPLIANCE_ARCH ?= linux/amd64

# mkosi's spelling of the same thing. Its ``--architecture`` vocabulary
# is x86-64 / arm64, while Docker platforms are linux/amd64 //arm64 and
# the artifacts are named amd64 / arm64 (#1026). One translation, here,
# rather than three call sites each getting it right.
MKOSI_ARCH := $(if $(filter arm64,$(notdir $(APPLIANCE_ARCH))),arm64,x86-64)

# Per-build identifier used as the image tag (compose substitutes via
# ``${SPATIUMDDI_VERSION}``). Computed once per ``make`` invocation —
# git short sha + 4 random hex chars — so each ISO cut produces a
# distinct tag visible in ``docker ps`` (e.g. ``ghcr.io/spatiumnorth/
# spatiumddi-api:dev-148c437-a3f2``). Mirrors how ISOs are tracked
# by build-NN; gives operators an in-container way to confirm which
# build a running stack came from.
#
# Override by exporting SPATIUMDDI_VERSION before invoking make. CI
# release builds set it to the CalVer tag (e.g. 2026.05.14-1) and
# BAKE_SOURCE=ghcr to pull pre-published images.
ifeq ($(origin SPATIUMDDI_VERSION), undefined)
SPATIUMDDI_VERSION := dev-$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)-$(shell openssl rand -hex 2 2>/dev/null || date +%s | tail -c5)
endif
export SPATIUMDDI_VERSION

# ── Help ───────────────────────────────────────────────────────────────────────
help:
	@echo "SpatiumDDI development targets:"
	@echo ""
	@echo "  make up          Start the full stack (production images)"
	@echo "  make dev         Start the dev stack (hot-reload)"
	@echo "  make down        Stop and remove containers"
	@echo "  make build       Build all Docker images"
	@echo "  make migrate     Run Alembic migrations inside the running api container"
	@echo "  make lint        Lint backend (ruff+mypy) and frontend (eslint+prettier)"
	@echo "  make test        Run backend tests against a live DB"
	@echo "  make ci          Run the exact same lint + typecheck + build jobs CI runs"
	@echo "  make screenshots Re-capture docs/assets/screenshots/ via headless chromium"
	@echo "  make docs        Serve the documentation site locally on :4000 (Jekyll)"
	@echo "  make docs-down   Stop the local documentation site"
	@echo "  make docs-verify Check every docs SVG diagram for overflow / clipping"
	@echo "  make versions-check     Assert every pin matches versions.json (part of make ci)"
	@echo "  make versions-upstream  Current-vs-latest table for every pinned component"
	@echo "  make workflow-shell-check  Refuse \$$? captured after a bare command under set -e"
	@echo "  make image-upgrade-check   Refuse a shipped image that never upgrades its packages"
	@echo "  make appliance      Build the OS-appliance qcow2 (Phase 1 — Debian 13 amd64)"
	@echo "  make appliance-iso  Wrap the Phase 1 raw image as a hybrid USB/CD ISO (Phase 2)"
	@echo ""

# ── Stack ──────────────────────────────────────────────────────────────────────
up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

dev:
	$(COMPOSE_DEV) up

build: build-supervisor
	$(COMPOSE) build
	# #272 — explicitly build the frontend. No compose service has a
	# ``build:`` in the prod compose, and the frontend is the one image
	# nothing else rebuilds routinely (api/dns/dhcp get rebuilt during
	# dev iteration; the frontend dev loop runs ``npm run dev`` and its
	# built image goes stale). Without this the appliance bake embeds a
	# STALE spatiumddi-frontend:dev — caught on the #272 phase7 ISO,
	# where the control-plane node showed up under Service agents
	# because the baked UI predated the two-role / promote-UI changes.
	# Mirrors build-supervisor; the retag loop below maps it to ghcr:dev.
	docker build -t spatiumddi-frontend:dev $(FRONTEND_DIR)
	# #272 — explicitly build api / dns / dhcp too. The PROD compose
	# (``$(COMPOSE)`` = docker-compose.yml) has NO ``build:`` sections —
	# every service pins a pre-built ``image:`` — so ``docker compose
	# build`` above rebuilds NOTHING for these. Only the dev compose
	# carries ``build:`` (with the api on ``target: dev``), so unless an
	# operator happened to run a dev-compose build recently, the baked
	# ISO embeds a stale ``spatiumddi-api:dev``. That bit the #272 Phase
	# 7b join-fix ISO: the api image predated migration d5f1a37c20e9, so
	# the migrate Job stopped at the prior alembic head, the ``node_ip``
	# column never existed, and every supervisor heartbeat silently
	# dropped the field → promote fell back to the pod IP again. Build
	# the api at its ``runtime`` (prod) stage, NOT ``dev`` (which adds
	# pytest + a 1M-line test tree we don't want in the appliance).
	docker build -t spatiumddi-api:dev --target runtime $(BACKEND_DIR)
	docker build -t spatiumddi-dns-bind9:dev -f agent/dns/images/bind9/Dockerfile .
	docker build -t spatiumddi-dns-powerdns:dev -f agent/dns/images/powerdns/Dockerfile .
	docker build -t spatiumddi-dns-technitium:dev -f agent/dns/images/technitium/Dockerfile .
	docker build -t spatiumddi-dhcp-kea:dev -f agent/dhcp/images/kea/Dockerfile .
	# #573 — the BGP Looking Glass collector (#566) is in bake-images.sh's
	# IMAGES set but the PROD compose pins its ``image:`` with no ``build:``,
	# so — exactly like the DNS/DHCP agents above — it needs an explicit
	# build here or ``make build`` leaves ``spatiumddi-looking-glass:dev``
	# stale and the baked ISO ships an old collector (or trips the #272 >24h
	# stale-source guard when nothing rebuilt it recently).
	docker build -t spatiumddi-looking-glass:dev -f agent/looking-glass/images/gobgp/Dockerfile .
	# #272 Phase 1 — retag compose-built images under the canonical
	# ``ghcr.io/spatiumnorth/<name>:dev`` form so
	# ``appliance/scripts/bake-images.sh``'s resolve_source_tag picks
	# the freshly-built image. Pre-#272 the bake's first-candidate
	# was ``ghcr.io/...:dev``, which on most dev hosts was a
	# stale months-old image left over from a previous CI pull;
	# ``spatiumddi-<name>:dev`` (the compose-style tag) was only
	# tried second and ignored. Result: ``make appliance-baked-iso``
	# baked stale api / frontend images that didn't include the
	# operator's local edits (caught during #272 Phase 1 ISO test —
	# the migrate Job ran against a 4-day-old api image and stopped
	# at the wrong alembic head). Retag every compose service that
	# the bake script looks for; the supervisor image is dual-tagged
	# by ``build-supervisor`` already.
	@# Compose tags ``<project>-<service>:dev`` (project=spatiumddi).
	@# bake-images.sh's IMAGES list uses the canonical
	@# ``ghcr.io/spatiumnorth/<short>`` form where <short> matches the
	@# upstream image name — which is NOT always the compose service
	@# name. Map explicitly:
	@for pair in \
	    "api:spatiumddi-api" \
	    "frontend:spatiumddi-frontend" \
	    "dns-bind9:dns-bind9" \
	    "dns-powerdns:dns-powerdns" \
	    "dns-technitium:dns-technitium" \
	    "dhcp-kea:dhcp-kea" \
	    "looking-glass:looking-glass"; do \
	  compose="$${pair%%:*}"; target="$${pair##*:}"; \
	  if docker image inspect "spatiumddi-$$compose:dev" >/dev/null 2>&1; then \
	    docker tag "spatiumddi-$$compose:dev" "ghcr.io/spatiumnorth/$$target:dev"; \
	  fi; \
	done

# Build the standalone spatium-supervisor image (#170). The image
# isn't in docker-compose.yml — it ships out of band as part of the
# appliance bake — so ``make build`` (which is ``docker compose
# build``) wouldn't otherwise rebuild it. Without this, edits to
# ``agent/supervisor/`` go in unnoticed because the bake reuses
# whatever ``spatium-supervisor:dev`` already sits in local docker
# from an earlier manual build. Tag both the bare name and the
# ghcr canonical name so ``appliance/scripts/bake-images.sh``'s
# local-source resolver finds it under either form.
build-supervisor:
	docker build -t spatium-supervisor:dev \
	             -t ghcr.io/spatiumnorth/spatium-supervisor:dev \
	             --build-arg APP_VERSION=$(SPATIUMDDI_VERSION) \
	             -f agent/supervisor/images/supervisor/Dockerfile .

# ── Database ───────────────────────────────────────────────────────────────────
migrate:
	$(COMPOSE) run --rm migrate

migration:
	@test -n "$(MSG)" || (echo "Usage: make migration MSG='describe change'"; exit 1)
	$(COMPOSE) run --rm --user root -v $(PWD)/backend:/app api alembic revision --autogenerate -m "$(MSG)"

# ── Linting ────────────────────────────────────────────────────────────────────
lint: lint-backend lint-frontend

lint-backend:
	cd $(BACKEND_DIR) && \
	  python -m ruff check app tests && \
	  python -m black --check app tests && \
	  python -m mypy app

lint-frontend:
	cd $(FRONTEND_DIR) && \
	  npm run lint && \
	  npm run format:check

# ── Tests ──────────────────────────────────────────────────────────────────────
#
# pytest runs *inside* the api container so the suite is exactly the
# version-pinned interpreter + deps the rest of CI uses, without
# requiring the operator to have python3 + pyproject's [dev] extras
# installed on the host. The dev compose's api ``build.target: dev``
# bakes pytest into the image; ``TEST_DATABASE_URL`` is pre-set on the
# environment so the conftest carves its per-worker test DB against
# the dev compose's postgres service.
#
# ``-T`` on ``docker compose exec`` disables TTY allocation so the
# output streams cleanly on CI runners + pipes to ``tee`` / grep
# without ANSI artefacts.
test: test-backend

test-backend:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T api python -m pytest -n auto

test-one:
	@test -n "$(T)" || (echo "Usage: make test-one T=tests/test_health.py::test_liveness"; exit 1)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T api python -m pytest $(T) -v

# Coverage is opt-in (#1019). It used to ride ``addopts`` in
# backend/pyproject.toml, which made every CI shard — and every
# ``make test-one`` — pay 15-30 % tracing overhead for a table nothing read.
# This is the one place it runs.
test-cov:
	docker compose -f docker-compose.yml -f docker-compose.dev.yml exec -T api python -m pytest -n auto --cov=app --cov-report=term-missing

# Refresh backend/.test_durations — the file pytest-split balances the CI
# shards with (#1019) — from the ``test-durations`` artifact the most recent
# successful CI run on main produced, then commit it. Run at release prep,
# or when the ``Backend — Tests`` aggregator warns that the shards have
# drifted. A stale file only costs balance (an unknown test is assumed
# average), never correctness. Needs an authenticated GitHub CLI.
test-durations:
	@command -v gh >/dev/null || { echo "make test-durations needs the GitHub CLI (gh)"; exit 1; }
	@run=$$(gh run list --workflow CI --branch main --event push --status success --limit 1 --json databaseId --jq '.[0].databaseId'); \
	test -n "$$run" || { echo "no successful CI run on main found"; exit 1; }; \
	echo "downloading test-durations from CI run $$run"; \
	gh run download "$$run" -n test-durations -D backend/ && \
	echo "wrote backend/.test_durations — review the diff and commit it"

# ── CI parity ──────────────────────────────────────────────────────────────────
# `make ci` runs the same lint + typecheck + build jobs GitHub Actions runs on
# every push (backend-lint, frontend-lint, frontend-build). The separate
# backend-tests job is not included — it needs a fresh `spatiumddi_test`
# database and is covered by `make test`. Requires the dev stack to be running
# (backend checks execute inside the api container) and Node 20+ locally.
# ── Trivy — container image vulnerability scan ────────────────────────────────
#
# Run this before pushing ANY change to an agent Dockerfile. CI's Trivy step is
# path-filtered (each build-*-images.yml only fires when its own agent/<x>/**
# paths change) AND PR-only, so an image can sit for months accumulating CVEs
# that nothing scans. The moment you touch its Dockerfile for an unrelated
# reason, CI scans it and fails on a PRE-EXISTING vulnerability you didn't
# introduce — which is exactly how PR #639 (an Alpine base bump) tripped over
# CVE-2026-39822 sitting in the gobgp image's Go toolchain pin.
#
# Gate matches the Trivy step in .github/workflows/build-*-images.yml exactly:
# HIGH,CRITICAL + --ignore-unfixed + non-zero exit on findings.
#
# Note on Go images: the toolchain pin (golang:X.Y.Z-alpine) is a SECURITY pin.
# Go static-links its stdlib into the binary, so a stdlib CVE ships inside
# gobgpd itself and Trivy flags it against the `gobinary` target. No package
# patch or `apk upgrade` can fix it — only rebuilding on a newer golang base.
#
# The frontend image is here for the same reason, and it is the case that
# proves the point. It has no per-PR Trivy gate, and the weekly
# trivy-scheduled.yml superset that nominally covers it has been exiting
# at the backend image before reaching it — so in practice nothing scanned
# it, and the first scan in 2026.09.04-1 found four HIGH CVEs in the
# nginx-alpine base. Its build context is ``frontend/`` rather than the
# repo root, which is why each spec carries one —
# ``dockerfile:context:name``.
#
# IMAGE=<name> scans one image; omit to scan all eight.
TRIVY_CACHE ?= $(CURDIR)/.trivy-cache
TRIVY_IMAGES ?= \
	agent/dhcp/images/kea/Dockerfile:.:kea \
	agent/dns/images/bind9/Dockerfile:.:bind9 \
	agent/dns/images/powerdns/Dockerfile:.:powerdns \
	agent/dns/images/technitium/Dockerfile:.:technitium \
	agent/dns/images/dnsdist/Dockerfile:.:dnsdist \
	agent/supervisor/images/supervisor/Dockerfile:.:supervisor \
	agent/looking-glass/images/gobgp/Dockerfile:.:looking-glass \
	frontend/Dockerfile:frontend:frontend

trivy:
	@mkdir -p $(TRIVY_CACHE)
	@fail=0; \
	for spec in $(TRIVY_IMAGES); do \
	  df=$${spec%%:*}; name=$${spec##*:}; ctx=$${spec#*:}; ctx=$${ctx%:*}; \
	  if [ -n "$(IMAGE)" ] && [ "$(IMAGE)" != "$$name" ]; then continue; fi; \
	  printf "→ %-14s building… " "$$name"; \
	  if ! docker build -q -f "$$df" -t "spatiumddi-trivy-$$name:scan" "$$ctx" >/dev/null 2>&1; then \
	    printf "BUILD FAILED\n"; fail=1; continue; \
	  fi; \
	  printf "scanning… "; \
	  if docker run --rm \
	      -v /var/run/docker.sock:/var/run/docker.sock \
	      -v "$(TRIVY_CACHE)":/root/.cache/ \
	      aquasec/trivy:latest image \
	      --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --scanners vuln -q \
	      "spatiumddi-trivy-$$name:scan" >/tmp/trivy-$$name.txt 2>&1; then \
	    printf "clean\n"; \
	  else \
	    printf "FINDINGS\n"; \
	    grep -E "CVE-|Total:" /tmp/trivy-$$name.txt | head -8 | sed 's/^/     /'; \
	    fail=1; \
	  fi; \
	done; \
	if [ $$fail -ne 0 ]; then \
	  echo ""; echo "✗ Trivy found HIGH/CRITICAL vulnerabilities — fix before pushing."; \
	  exit 1; \
	fi; \
	echo ""; echo "✓ Trivy clean (HIGH/CRITICAL, ignore-unfixed) — safe to push."

# ── OpenAPI contract export (#903) ──────────────────────────────────────────
#
# Produces the same openapi.json the release workflow attaches to every CalVer
# tag, so a client repo (spatiumnorth/spatiumddi-mobile) can regenerate and diff
# the contract without waiting for a release.
#
# Runs inside the API image rather than a host venv on purpose: the artifact is
# the contract for a specific SERVER build, so it should be generated by the
# same interpreter and dependency set that build ships — a host venv on a
# different pydantic could emit a subtly different schema. (This builds the
# ``dev`` stage, which is ``runtime`` plus test packages; the release job runs
# the published ``runtime`` image. Same app code and same pinned deps, so the
# document matches — but reproduce a RELEASE byte-for-byte by checking out
# that tag first, since this target always exports the working tree.)
#
# ``--network none`` is not only hygiene, it PROVES the export needs no
# database, Redis or outbound access. That is what lets the release job run
# this as a plain step instead of standing up a stack.
#
# VERSION defaults to ``dev``; pass VERSION=2026.08.22-1 to stamp info.version
# the way a release does.
openapi: VERSION ?= dev
openapi:
	@echo "→ Rebuilding the API image so the export matches the current tree"
	@$(COMPOSE_DEV) build api
	@docker run --rm --network none \
	  -v "$(PWD)/scripts:/scripts:ro" \
	  -e VERSION="$(VERSION)" \
	  spatiumddi-api:dev \
	  python3 /scripts/export_openapi.py > openapi.json
	@echo "✓ Wrote openapi.json ($$(wc -c < openapi.json) bytes, version=$$(python3 -c 'import json;print(json.load(open("openapi.json"))["info"]["version"])'))"

# ── IANA TLD registry (issue #986) ───────────────────────────────────────────
# Regenerates backend/app/data/iana_tlds.json, the bundled root-zone list that
# decides whether a zone name reads as Public or Undelegated. Run at
# release-prep: an install that never clicks Settings → DNS → TLD Registry →
# Refresh classifies against whatever the release shipped, so a stale bundled
# list makes recently-delegated TLDs look unprotected.
#
# The hand-curated special-use table in the same file is preserved verbatim —
# it changes by RFC and by ICANN action, not by download — and the script
# refuses to run if it is missing rather than emitting a registry that would
# reclassify every reserved zone as public.
#
# Runs in a bare python:3.12 with no backend dependencies, which is why the
# parser it shares with the product is stdlib-only. `tld-registry-check`
# reports whether the bundled copy is behind IANA without writing anything
# (exit 1 when stale) — that is the release-prep question.
.PHONY: tld-registry tld-registry-check
tld-registry:
	@docker run --rm -v "$(PWD)":/repo -w /repo python:3.12-slim \
	  python3 scripts/refresh_iana_tlds.py

tld-registry-check:
	@docker run --rm -v "$(PWD)":/repo -w /repo python:3.12-slim \
	  python3 scripts/refresh_iana_tlds.py --check

# ── Untyped-route guard (issue #917) ─────────────────────────────────────────
# A route with no response_model publishes an unconstrained object as its
# response schema, so a generated client gets an untyped container. 91 routes
# were in that state when the guard landed; the baseline stops the set from
# growing, exactly like scripts/lint_migrations.py does for destructive
# migrations. Extraction runs inside the API image (it imports the app); the
# comparison is pure stdlib and runs on the host.
UNTYPED_LIST := /tmp/spatiumddi-untyped-routes.txt

.PHONY: lint-untyped-routes lint-untyped-routes-baseline

# NOT ``2>/dev/null`` (#1030): the extraction imports the app, so when it
# fails the traceback IS the diagnosis — and hiding it left an operator
# with a bare non-zero exit and nothing to read. stderr goes to the
# terminal; only stdout is captured into the listing, so letting it
# through costs nothing. The output goes to a temp file that is moved
# into place only on success, so a failed run cannot leave an EMPTY
# listing behind for a later ``--check`` to pass over.
$(UNTYPED_LIST): FORCE
	@$(COMPOSE_DEV) build api >/dev/null
	@docker run --rm --network none \
	  -v "$(PWD)/scripts:/scripts:ro" \
	  spatiumddi-api:dev \
	  python3 /scripts/lint_untyped_routes.py --list > $@.tmp
	@mv $@.tmp $@

lint-untyped-routes: $(UNTYPED_LIST)
	@python3 scripts/lint_untyped_routes.py --check $(UNTYPED_LIST)

lint-untyped-routes-baseline: $(UNTYPED_LIST)
	@python3 scripts/lint_untyped_routes.py --baseline $(UNTYPED_LIST)

FORCE:

ci: ci-backend-lint ci-frontend-lint ci-frontend-build charts-lint perf-test versions-check workflow-shell-check image-upgrade-check
	@echo ""
	@echo "✓ All CI checks passed — safe to push."

ci-backend-lint:
	@echo "→ Backend — Lint & Type Check (matches .github/workflows/ci.yml)"
	@# The prod `api` image doesn't ship dev tools. Install them on first run;
	@# they persist until the container is recreated.
	@$(COMPOSE_DEV) exec -T api python -m ruff --version >/dev/null 2>&1 || \
	  $(COMPOSE_DEV) exec -T -u root api pip install --quiet --root-user-action=ignore \
	    ruff black mypy
	$(COMPOSE_DEV) exec -T api python -m ruff check app tests
	$(COMPOSE_DEV) exec -T api python -m black --check app tests
	$(COMPOSE_DEV) exec -T api python -m mypy app

ci-frontend-lint:
	@echo "→ Frontend — Lint & Type Check"
	cd $(FRONTEND_DIR) && npm run lint && npm run format:check && npm run typecheck && npm test

ci-frontend-build:
	@echo "→ Frontend — Build"
	cd $(FRONTEND_DIR) && npm run build

# Charts — Lint & Template (#966): the same script CI's job runs, inside a
# helm container so a dev box with no helm / kubeconform can run it. Renders
# land in ./.charts-render/ (gitignored) for inspection.
HELM_IMAGE ?= alpine/helm:4.3.0
charts-lint:
	@echo "→ Charts — Lint & Template (matches .github/workflows/ci.yml)"
	@mkdir -p .charts-render
	docker run --rm --entrypoint sh -v "$(PWD):/repo" -w /repo -e HOME=/tmp -e OUT=/repo/.charts-render \
	  $(HELM_IMAGE) -c 'apk add -q --no-cache bash curl python3 py3-yaml \
	    && .github/scripts/install-kubeconform.sh \
	    && .github/scripts/charts-render-check.sh'

# Version-pin manifest (#975). Asserts that every pin declared in the root
# versions.json still appears, at that version, in each file that carries a
# copy of it — Helm's five literals, chart values, Dockerfile ARGs, the
# appliance bake arrays, CI script defaults. Same check CI's Backend Lint job
# runs; stdlib-only, no network, no container.
#
# ``versions-upstream`` is the other half: it resolves each declared upstream
# and prints a current-vs-latest table. Advisory and network-bound, so it is
# deliberately NOT part of `make ci` — the weekly trivy-scheduled workflow
# runs it and files the delta.
versions-check:
	@echo "→ Version-pin manifest (matches .github/workflows/ci.yml)"
	@python3 scripts/lint_versions.py

versions-upstream:
	@python3 scripts/lint_versions.py --check-upstream

# Workflow shell-status guard (#1036). GitHub Actions runs every `run:` block
# under `bash -e`, which `set -uo pipefail` does NOT clear — so `cmd; rc=$$?`
# is dead code on exactly the failure it was written to handle. Neither
# actionlint nor shellcheck reports it. Same check CI's Backend Lint job runs.
workflow-shell-check:
	@echo "→ Workflow shell-status linter (matches .github/workflows/ci.yml)"
	@python3 scripts/lint_workflow_shell.py

# Shipped-image package-upgrade guard (#1088). Every published image must
# upgrade its base image's own packages AND declare the snapshot ARG that lets
# the nightly bust the cached package layer — an upgrade line that never runs
# is indistinguishable, in the built image, from no upgrade line at all. The
# api image had neither and shipped 34 HIGH/CRITICAL findings whose fixes had
# been on deb.debian.org for days. Same check CI's Backend Lint job runs.
image-upgrade-check:
	@echo "→ Shipped-image package-upgrade linter (matches .github/workflows/ci.yml)"
	@python3 scripts/lint_image_upgrades.py

# Perf — Tests (#968): hermetic tests under perf/ (no network, no appliance).
# PyYAML + dnspython are what the orchestrator and report tests import
# (#1057); hdrhistogram has an x86_64 wheel only and builds a C extension
# elsewhere, so it is taken as a wheel when one exists — the single assertion
# that needs the HdrHistogram backend is gated on it in the test.
perf-test:
	@echo "→ Perf — Tests (matches .github/workflows/ci.yml)"
	docker run --rm -v "$(PWD):/repo" -w /repo python:3.12-slim sh -c \
	  'pip -q install pytest pyyaml dnspython >/dev/null \
	   && (pip -q install --only-binary=:all: hdrhistogram >/dev/null 2>&1 \
	       || echo "hdrhistogram: no binary wheel for this arch; the .hdr assertion is gated") \
	   && python -m pytest perf -q'

# ── Screenshots ────────────────────────────────────────────────────────────────
# Re-captures the README screenshots via headless chromium. The dev stack must
# be running and reachable at the configured URL (default http://localhost:8077).
# See scripts/screenshots/README.md for options + troubleshooting.
#
# Pass extra flags via SCREENSHOT_ARGS, e.g.:
#   make screenshots SCREENSHOT_ARGS="--only dashboard,ipam"
#   make screenshots SCREENSHOT_ARGS="--base-url http://localhost:8077 --width 1920"
screenshots:
	@command -v node >/dev/null || (echo "node not installed — apt-get install -y nodejs"; exit 1)
	@test -x /usr/bin/chromium || (echo "chromium missing — apt-get install -y chromium"; exit 1)
	@test -d scripts/screenshots/node_modules || \
	  (cd scripts/screenshots && npm install --no-audit --no-fund)
	node scripts/screenshots/capture.mjs $(SCREENSHOT_ARGS)

# ── Docs site ──────────────────────────────────────────────────────────────────
# Renders docs/ with the same Jekyll plugin set GitHub Pages uses, so a page can
# be reviewed before it ships. Override the port with DOCS_PORT=8081.
docs:
	docker compose -f docker-compose.docs.yml up -d --build
	@echo "docs site → http://localhost:$${DOCS_PORT:-4000}  (make docs-down to stop)"

docs-down:
	docker compose -f docker-compose.docs.yml down

# Diagram geometry gate — the same check CI runs. Measures real text metrics in
# headless Chromium, so a relabelled box that now spills out of its container
# fails here instead of on the published site.
docs-verify:
	@test -x /usr/bin/chromium || command -v google-chrome >/dev/null || \
	  (echo "chromium missing — apt-get install -y chromium"; exit 1)
	python3 scripts/verify_svg_diagrams.py

# ── OS Appliance (Phase 1: Debian 13 amd64 qcow2 MVP) ──────────────────────────
# See appliance/README.md for the full design + prereqs.
#
# The build runs inside a published builder container so the only host
# requirement is Docker. Override APPLIANCE_BUILDER to point at a
# locally-built image (e.g. for iterating on appliance/builder/Dockerfile):
#   make appliance APPLIANCE_BUILDER=spatiumddi-appliance-builder:dev
APPLIANCE_DIR     = appliance
APPLIANCE_OUT     = $(APPLIANCE_DIR)/build
# mkosi names the output `<ImageId>_<ImageVersion>.raw` — derive both
# at runtime from whatever appears in build/ so a version bump in
# mkosi.conf doesn't break the Makefile.
APPLIANCE_BUILDER = ghcr.io/spatiumnorth/appliance-builder:latest

appliance:
	@command -v docker >/dev/null || \
	  (echo "docker not found — the appliance build runs inside a container"; exit 1)
	mkdir -p $(APPLIANCE_OUT)
	@echo "→ Pulling builder image $(APPLIANCE_BUILDER)…"
	@docker pull $(APPLIANCE_BUILDER) 2>/dev/null || \
	  echo "  (couldn't pull — assuming a local image with that tag exists)"
	@echo "→ Building appliance image (this takes ~5–10 min)…"
	docker run --rm --privileged \
	    -v $(PWD)/$(APPLIANCE_DIR):/work \
	    $(APPLIANCE_BUILDER) \
	    --architecture=$(MKOSI_ARCH) \
	    --output-directory=build --force build
	@raw=$$(ls $(APPLIANCE_OUT)/spatiumddi-appliance*.raw 2>/dev/null | head -1); \
	if [ -n "$$raw" ]; then \
	  ls -lh "$$raw"; \
	  echo ""; \
	  echo "✓ Built: $$raw"; \
	  echo "  Wrap as ISO with: make appliance-iso"; \
	else \
	  echo "✗ mkosi did not produce a .raw file in $(APPLIANCE_OUT) — check the log above."; \
	  exit 1; \
	fi
	@# qcow2 sidecar (disabled — not needed when shipping the ISO; ~1 GB
	@# disk + a qemu-img convert pass per build). Uncomment to restore.
	@# raw=$$(ls $(APPLIANCE_OUT)/spatiumddi-appliance*.raw 2>/dev/null | head -1); \
	# qcow2=$${raw%.raw}.qcow2; \
	# echo "→ Converting raw → qcow2…"; \
	# docker run --rm --entrypoint qemu-img \
	#     -v $(PWD)/$(APPLIANCE_OUT):/build \
	#     $(APPLIANCE_BUILDER) \
	#     convert -O qcow2 "/build/$$(basename $$raw)" "/build/$$(basename $$qcow2)"; \
	# ls -lh "$$qcow2"; \
	# echo "✓ Built: $$qcow2"; \
	# echo "  Boot it with: qemu-system-x86_64 -enable-kvm -m 4G -smp 2 \\"; \
	# echo "                -drive file=$$qcow2,if=virtio \\"; \
	# echo "                -nic user,hostfwd=tcp::8080-:80,hostfwd=tcp::2222-:22"

# Build the builder container locally (e.g. when iterating on its
# Dockerfile before pushing to ghcr.io).
appliance-builder:
	docker build -t spatiumddi-appliance-builder:dev $(APPLIANCE_DIR)/builder
	@echo ""
	@echo "✓ Built: spatiumddi-appliance-builder:dev"
	@echo "  Use it via: make appliance APPLIANCE_BUILDER=spatiumddi-appliance-builder:dev"

# Phase 2 — wrap the raw image as a hybrid USB/CD ISO. Requires
# `make appliance` to have run first (or for a raw image to exist
# in $(APPLIANCE_OUT)).
appliance-iso:
	@raw=$$(ls $(APPLIANCE_OUT)/spatiumddi-appliance*.raw 2>/dev/null | head -1); \
	if [ -z "$$raw" ]; then \
	  echo "✗ no raw image found in $(APPLIANCE_OUT) — run 'make appliance' first."; \
	  exit 1; \
	fi; \
	iso=$${raw%.raw}.iso; \
	echo "→ Wrapping $$raw → $$iso (hybrid USB/CD)…"; \
	docker run --rm --privileged \
	    --entrypoint /work/scripts/wrap-iso.sh \
	    -e APPLIANCE_ARCH=$(notdir $(APPLIANCE_ARCH)) \
	    -v $(PWD)/$(APPLIANCE_DIR):/work \
	    $(APPLIANCE_BUILDER) \
	    "/work/build/$$(basename $$raw)" \
	    "/work/build/$$(basename $$iso)"; \
	echo ""; \
	echo "✓ Built: $$iso"; \
	echo "  Burn to USB:  sudo dd if=$$iso of=/dev/sdX bs=4M conv=fsync"; \
	echo "  Or attach as CD-ROM in your hypervisor."

# Phase 8b-1 — build a slot image (.raw.xz of just the rootfs) suitable
# for sysupdate / spatium-upgrade-slot to write to an inactive A/B
# partition. Requires `make appliance` to have run first (consumes the
# raw output). Output: spatiumddi-appliance-slot-<version>.raw.xz +
# .sha256 next to the existing artifacts in $(APPLIANCE_OUT).
appliance-slot-image:
	@raw=$$(ls $(APPLIANCE_OUT)/spatiumddi-appliance*.raw 2>/dev/null | head -1); \
	if [ -z "$$raw" ]; then \
	  echo "✗ no raw image found in $(APPLIANCE_OUT) — run 'make appliance' first."; \
	  exit 1; \
	fi; \
	echo "→ Building slot image from $$raw …"; \
	docker run --rm --privileged \
	    --entrypoint /work/scripts/build-slot-image.sh \
	    -e APPLIANCE_ARCH=$(notdir $(APPLIANCE_ARCH)) \
	    -v $(PWD)/$(APPLIANCE_DIR):/work \
	    $(APPLIANCE_BUILDER) \
	    "/work/build/$$(basename $$raw)" \
	    "/work/build"

appliance-clean:
	@if [ -d $(APPLIANCE_OUT) ]; then \
	  echo "Removing $(APPLIANCE_OUT) (may need sudo — mkosi outputs are root-owned)"; \
	  rm -rf $(APPLIANCE_OUT) 2>/dev/null || sudo rm -rf $(APPLIANCE_OUT); \
	fi

# Bake every container image into the appliance rootfs overlay so the
# next ``make appliance`` ships them inside the ISO. See
# appliance/scripts/bake-images.sh for what's covered + how source
# selection (local :dev tags vs pulled :<calver> from ghcr) works.
#
# Source defaults to ``local`` (uses spatiumddi-*:dev) when
# SPATIUMDDI_VERSION is empty/dev; the release workflow sets
# SPATIUMDDI_VERSION=<calver> + BAKE_SOURCE=ghcr to pull the cut
# tag from the just-published images.
#
# Depends on ``build-supervisor`` so a stale supervisor image (the
# only service container not in docker-compose.yml + not rebuilt by
# ``make build`` before that target gained build-supervisor as a
# dep) can't slip into the baked overlay. The Docker layer cache
# makes the no-op case ~3 s; full rebuild ~30 s.
# Issue #183 — k3s migration. Pinned release tag the slot image ships.
# Bump in PRs alongside the slot image cut; the fetch script caches
# downloads under mkosi.extra/ keyed on this version so re-runs are
# cheap when nothing's changed.
K3S_VERSION ?= v1.36.4+k3s1

# Issue #183 Phase 1 — air-gap-ready k3s baking. Downloads the pinned
# k3s static binary + airgap images tarball + LICENSE into mkosi.extra/
# at build time. The slot rootfs carries everything; fielded appliance
# never reaches github.com on first boot. Idempotent (cache-stamped
# against K3S_VERSION). Runs ahead of ``appliance-bake-images`` in the
# composed targets so the mkosi build sees both image sets.
# #553 — pin ARCH to the IMAGE arch, not the build-host arch. fetch-k3s.sh
# defaults ARCH to `uname -m`, but mkosi.conf hardcodes Architecture=x86-64;
# on an arm64 build host that baked the -arm64 k3s binary + airgap tarball
# into an amd64 rootfs (won't exec / won't import). Keep in lock-step with
# mkosi.conf's Architecture.
appliance-fetch-k3s:
	@# #1026 — ARCH follows APPLIANCE_ARCH rather than being pinned to
	@# x86_64. fetch-k3s.sh has understood both since #991; it was the
	@# caller that only ever asked for one. A mismatch here is not a
	@# build failure — it is an appliance that boots and then cannot
	@# start k3s, because the static binary is for the other silicon.
	@K3S_VERSION="$(K3S_VERSION)" ARCH=$(notdir $(APPLIANCE_ARCH)) 	  bash $(APPLIANCE_DIR)/scripts/fetch-k3s.sh

# Issue #183 Phase 3 — chart bake. Packages
# charts/spatiumddi-appliance/ into a stable tgz at
# mkosi.extra/usr/lib/spatiumddi/charts/spatiumddi-appliance.tgz
# so the supervisor's service_lifecycle_k3s module can base64-encode
# it into a HelmChart CR. Air-gap: chart ships in the slot image,
# no chart repo lookup at runtime.
appliance-bake-chart:
	@bash $(APPLIANCE_DIR)/scripts/bake-chart.sh

# Phase 11 (#183) — umbrella chart bake for the AIO + Core install
# variants. Same bake script, CHART_NAME points at the umbrella
# instead of the appliance chart. Output:
# appliance/mkosi.extra/usr/lib/spatiumddi/charts/spatiumddi.tgz.
appliance-bake-control-chart:
	@CHART_NAME=spatiumddi bash $(APPLIANCE_DIR)/scripts/bake-chart.sh

# #272 — MetalLB chart bake. Separate chart so MetalLB lands in its own
# metallb-system namespace (the upstream chart hardcodes .Release.Namespace,
# so it can't be a subchart of spatiumddi-appliance and still escape the
# spatium namespace). firstboot renders it as the spatium-metallb HelmChart.
appliance-bake-metallb-chart:
	@CHART_NAME=spatiumddi-metallb bash $(APPLIANCE_DIR)/scripts/bake-chart.sh

# BAKE_FLAGS lets an operator pass --allow-stale-images to bypass the
# >24h stale-source-image guard (#272 follow-up): make appliance-baked-iso
# BAKE_FLAGS=--allow-stale-images  (or ALLOW_STALE_IMAGES=1, which the
# script also honours from the environment).
appliance-bake-images: build-supervisor
	@bash $(APPLIANCE_DIR)/scripts/bake-images.sh $(BAKE_FLAGS)

# Convenience for fast laptop iteration on appliance-level changes
# (installer, firstboot, console dashboard, partition layout,
# networking stack) where you don't want to wait on the docker-image
# rebuild + bake cycle. Skips the bake — firstboot falls back to
# ``docker compose pull`` from ghcr.io on first boot. NOT how releases
# are cut (the release pipeline always bakes — #170 Phase A4).
appliance-dev-iso: appliance-clean-baked-images appliance-stamp-dev appliance-fetch-k3s appliance-bake-chart appliance-bake-control-chart appliance-bake-metallb-chart appliance appliance-iso
	@echo ""
	@echo "✓ Dev-flavored appliance ISO ready at $(APPLIANCE_OUT)/spatiumddi-appliance_0.1.0.iso"
	@echo "  All container images (api / frontend / DNS / DHCP agents) pull from"
	@echo "  ghcr.io on first boot. Copy this ISO to your NAS / hypervisor library"
	@echo "  and boot a VM from it. Use 'make appliance-baked-iso' instead to"
	@echo "  produce a self-contained (air-gap-ready) ISO."

# Release-style local build — bakes every image at the local :dev tag
# (run ``make build`` first to produce them) into the rootfs, then
# builds the ISO + slot image. Mirrors what the release workflow
# produces, just driven by your local :dev images instead of ghcr.io's
# cut tag. ~1 GB larger than appliance-dev-iso.
appliance-baked-iso: appliance-stamp-dev appliance-fetch-k3s appliance-bake-chart appliance-bake-control-chart appliance-bake-metallb-chart appliance-bake-images appliance appliance-iso appliance-slot-image
	@echo ""
	@echo "✓ Baked appliance ISO ready at $(APPLIANCE_OUT)/"
	@echo "  All container images embedded. Air-gap-ready. First boot does no docker pull."
	@echo "  Mirrors what the .github/workflows/release.yml ``build-appliance-iso`` job"
	@echo "  does on CI — stamps appliance-release with the local commit, bakes the"
	@echo "  docker overlay image, builds the raw image, wraps as ISO, builds the"
	@echo "  slot-upgrade .raw.xz + .sha256. Difference: BAKE_SOURCE=local (uses your"
	@echo "  ``make build`` :dev tags) vs CI's BAKE_SOURCE=ghcr (pulls the cut tag)."

# Cross-build entry point for an arm64 host — Apple Silicon, an
# ARM server (#991).
#
# The appliance ISO is x86-64 (``Architecture=x86-64`` in mkosi.conf) and
# mkosi cross-builds it without complaint, but ONE ``make`` invocation
# cannot drive both halves of the build, because they need opposite
# environments:
#
#   * the app-image builds and the third-party pulls must produce
#     **amd64** artefacts, so they want DOCKER_DEFAULT_PLATFORM set;
#   * mkosi, the ISO wrap and the slot image must run the builder
#     **natively**, so they need it UNSET — an emulated builder dies on
#     ``mount_setattr(2)``, which qemu-user and Rosetta do not implement
#     and ``--privileged`` does not fix.
#
# So this target sets the variable per recipe line rather than for the
# whole invocation. On an amd64 host it is simply equivalent to
# ``appliance-baked-iso`` — the platform pins name the native arch — so
# there is no second code path to keep in step.
#
# BAKE_SAVE_PLATFORM is what makes ``docker save`` work under Docker
# Desktop's containerd image store, and what stops a third-party image
# already present as arm64 (from the dev compose stack) being baked into
# an x86-64 appliance, where it would ``exec format error`` on first boot.
#
# ⚠️  Side effect: ``make build`` retags the ``spatiumddi-*:dev`` images
# the dev compose stack uses, so after this the dev stack would start
# amd64 images under emulation. Restore them with
# ``docker compose -f docker-compose.dev.yml build``.
appliance-baked-iso-cross: APPLIANCE_ARCH ?= linux/amd64
appliance-baked-iso-cross:
	@echo "→ Cross-building an $(APPLIANCE_ARCH) appliance on $$(uname -m)"
	DOCKER_DEFAULT_PLATFORM=$(APPLIANCE_ARCH) $(MAKE) build build-supervisor
	$(MAKE) appliance-verify-arch APPLIANCE_ARCH=$(APPLIANCE_ARCH)
	DOCKER_DEFAULT_PLATFORM=$(APPLIANCE_ARCH) BAKE_SAVE_PLATFORM=$(APPLIANCE_ARCH) \
	  $(MAKE) appliance-stamp-dev appliance-fetch-k3s appliance-bake-chart \
	          appliance-bake-control-chart appliance-bake-metallb-chart \
	          appliance-bake-images
	@# DOCKER_DEFAULT_PLATFORM deliberately absent from here down: the
	@# builder container must run native or mkosi cannot start.
	$(MAKE) appliance appliance-iso appliance-slot-image
	@echo ""
	@echo "✓ Cross-built appliance ISO ready at $(APPLIANCE_OUT)/"
	@echo "  NOTE: your dev compose images are now $(APPLIANCE_ARCH). Restore with:"
	@echo "    docker compose -f docker-compose.dev.yml build"

# Assert every source image really is the appliance's architecture
# before it is baked (#991 §2). The check itself lives in
# ``appliance/scripts/verify-image-arch.sh`` — it moved out of this
# recipe in #1028, where the naive ``docker image inspect
# -f '{{.Architecture}}'`` probe turned out to answer for the HOST
# platform on Docker Desktop's containerd store and blocked the arm64
# cross-build on correct images. The logic needed to distinguish three
# outcomes rather than two, which is more than a make recipe should
# carry and more importantly is now unit-testable
# (``appliance/tests/test_verify_image_arch.py`` runs it against a
# stubbed docker, including the negative controls).
#
# Run automatically by ``appliance-baked-iso-cross`` between building the
# images and baking them, which is the only moment the mistake is still
# cheap to fix.
appliance-verify-arch: APPLIANCE_ARCH ?= linux/amd64
appliance-verify-arch:
	@$(APPLIANCE_DIR)/scripts/verify-image-arch.sh "$(APPLIANCE_ARCH)"

# Wipe any baked overlay artefacts that a previous
# ``appliance-bake-images`` left under the mkosi.extra overlay. mkosi
# copies the overlay verbatim into the rootfs, so a stale image file
# would still be baked even after we dropped the ``appliance-bake-
# images`` dep from ``appliance-dev-iso``. The artefacts are
# gitignored.
appliance-clean-baked-images:
	@d=$(APPLIANCE_DIR)/mkosi.extra/usr/lib/spatiumddi; \
	if [ -f $$d/docker-overlay.img ] || [ -f $$d/docker-overlay.manifest ]; then \
	  echo "→ Cleaning previously-baked docker overlay from $$d …"; \
	  rm -f $$d/docker-overlay.img $$d/docker-overlay.manifest $$d/docker-overlay.version; \
	fi
	@# Pre-E1 tarball layout — wipe any leftovers from an older bake.
	@d2=$(APPLIANCE_DIR)/mkosi.extra/usr/local/share/spatiumddi/images; \
	if ls $$d2/*.tar.zst >/dev/null 2>&1 || [ -f $$d2/BAKED_AT ]; then \
	  echo "→ Cleaning pre-E1 image tarballs from $$d2 …"; \
	  rm -f $$d2/*.tar.zst $$d2/BAKED_AT $$d2/VERSION $$d2/MANIFEST; \
	  rmdir $$d2 2>/dev/null || true; \
	fi
	@# Issue #183 — k3s binary + airgap tarball + LICENSE artefacts.
	@# Force a re-fetch on the next ``appliance-fetch-k3s`` (which is
	@# itself cache-stamped against K3S_VERSION so this is rarely
	@# needed unless the operator is reproducing a build from
	@# scratch). Doesn't touch /etc/rancher/k3s/config.yaml since
	@# that's source-tracked, not generated.
	@d3=$(APPLIANCE_DIR)/mkosi.extra; \
	if [ -x $$d3/usr/local/bin/k3s ] || [ -f $$d3/usr/share/doc/k3s/.version ]; then \
	  echo "→ Cleaning baked k3s artefacts (forces fetch-k3s re-run) …"; \
	  rm -f $$d3/usr/local/bin/k3s; \
	  rm -f $$d3/usr/local/bin/kubectl $$d3/usr/local/bin/crictl $$d3/usr/local/bin/ctr; \
	  rm -f $$d3/var/lib/rancher/k3s/agent/images/*.tar.zst; \
	  rm -f $$d3/usr/share/doc/k3s/LICENSE \
	        $$d3/usr/share/doc/k3s/NOTICE \
	        $$d3/usr/share/doc/k3s/k3s-images.txt \
	        $$d3/usr/share/doc/k3s/.version; \
	fi
	@# Issue #183 Phase 3 — baked Helm chart tarball.
	@d4=$(APPLIANCE_DIR)/mkosi.extra/usr/lib/spatiumddi/charts; \
	if [ -f $$d4/spatiumddi-appliance.tgz ]; then \
	  echo "→ Cleaning baked Helm chart from $$d4 …"; \
	  rm -f $$d4/spatiumddi-appliance.tgz; \
	fi

# Stamp a dev version into mkosi.extra/etc/spatiumddi/appliance-release
# so a freshly-installed local-build appliance reports a non-empty
# ``installed_appliance_version`` in the Fleet view. The release
# workflow does the same thing in CI with a CalVer tag; for local
# builds we use ``dev-<short-sha>`` so each WIP ISO has a unique stamp
# tied to the commit it came from. The file is gitignored — see
# ``appliance/.gitignore``.
appliance-stamp-dev:
	@f=$(APPLIANCE_DIR)/mkosi.extra/etc/spatiumddi/appliance-release; \
	mkdir -p $$(dirname $$f); \
	{ \
	  echo "# Generated by ``make appliance-stamp-dev`` for local-build ISOs."; \
	  echo "# CI release builds overwrite this with the real CalVer tag."; \
	  echo "APPLIANCE_VERSION=\"$(SPATIUMDDI_VERSION)\""; \
	  echo "APPLIANCE_ARCH=\"$(notdir $(APPLIANCE_ARCH))\""; \
	} > $$f; \
	echo "→ Stamped appliance-release: $$(cat $$f | grep APPLIANCE_VERSION)"

# ── Performance test suite (perf/) ───────────────────────────────────────────────
# Off-box load + soak harness. Targets live in perf/Makefile.inc (perf-*).
# `make perf-help` for the list. See docs/PERFORMANCE_TESTING.md.
-include perf/Makefile.inc

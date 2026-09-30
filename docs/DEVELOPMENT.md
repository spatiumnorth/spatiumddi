# Development Guide

> Coding standards, the lint/test stack, the CI gate, the migration
> workflow, and the conventions every change must follow. Read
> [`CONTRIBUTING.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md) first for the high-level
> contribution flow; this doc is the detailed reference behind it.

The canonical spec for *what* the project is and *why* decisions were
made lives in [`CLAUDE.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md). This guide covers *how* to
build, test, and ship changes.

---

## 1. Prerequisites

- **Docker Engine 25+** and **Docker Compose v2.20+** — the backend, its
  tests, and the linters all run inside containers, so you don't need a
  local Python toolchain to contribute backend code.
- **Node 20+** (CI builds the frontend on **Node 22**) — only needed for
  the frontend dev loop and the frontend lint/build jobs, which run on
  the host.
- **Python 3.12** is the pinned interpreter version (`backend/pyproject.toml`
  → `target-version = "py312"`). You only need it on the host if you want
  to run the migration-shape linter or backend tooling outside Docker.

---

## 2. First-Time Setup

```bash
git clone https://github.com/spatiumnorth/spatiumddi.git
cd spatiumddi

# Create your environment file — at minimum change POSTGRES_PASSWORD and SECRET_KEY
cp .env.example .env
#   SECRET_KEY: openssl rand -hex 32
#   POSTGRES_PASSWORD: any non-default value

make build      # build all Docker images
make migrate    # apply Alembic migrations inside the api container
make up         # start the full stack (production images)
#   — or —
make dev        # start the dev stack with hot-reload (docker-compose.dev.yml)
```

The frontend is served on `http://localhost:8077` by default
(`HTTP_PORT` in `.env`; the container listens on port 80). See
[`deployment/DOCKER.md`](deployment/DOCKER.md) for the full port
reference and TLS setup.

**Default login:** `admin` / `admin`. On a non-demo install the seeded
admin carries `force_password_change=True`, so the first login redirects
to a password-change form (`backend/app/main.py` → `_seed_default_admin`).

To run the DNS and/or DHCP service containers alongside the control
plane, enable the matching Compose profiles:

```bash
COMPOSE_PROFILES=dns,dhcp make up
```

### Frontend-only dev loop

The fastest UI iteration loop runs Vite directly on the host (React 18 +
TypeScript + Vite) against the containerized API:

```bash
cd frontend
npm install
npm run dev
```

If you get locked out of the admin account, see the password-reset
recipe in [`CLAUDE.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md#development-commands) and
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

---

## 3. Coding Standards

### Backend (Python)

| Tool | Config | Notes |
|---|---|---|
| `ruff` | `[tool.ruff]` in `backend/pyproject.toml` | `line-length = 100`, `target-version = "py312"`. E501 is delegated to black. |
| `black` | `[tool.black]` | `line-length = 100`, `target-version = ["py312"]`. Black owns formatting; ruff owns lint rules. |
| `mypy` | `[tool.mypy]` | `python_version = "3.12"`, `strict = false` (default mode), `plugins = ["pydantic.mypy"]`. |

Run them via Docker so you get the exact pinned versions:

```bash
make lint          # backend (ruff + black + mypy) AND frontend (eslint + prettier)
make lint-backend  # backend only
```

> **Note:** the dev container ships whatever ruff/black/mypy versions
> were installed when the image was built, which can drift from the
> versions CI installs from `pyproject.toml`'s `[dev]` extra. If you have
> a host Python 3.12 with the `[dev]` extras installed, running ruff,
> black, and mypy on the host gives the closest match to the CI gate.

### Frontend (TypeScript)

| Tool | npm script | Notes |
|---|---|---|
| `eslint` | `npm run lint` | Runs with `--max-warnings 0` — a warning fails the job. |
| `prettier` | `npm run format:check` | Use `npm run format` to auto-fix. |
| `tsc` | `npm run typecheck` | `tsc --noEmit`, no emit. |

```bash
make lint-frontend   # eslint + prettier check
```

Note `npm run typecheck` is `tsc --noEmit` and **`npm run build` is
`tsc -b`**, which is stricter. Build mode catches errors `--noEmit`
does not — a name colliding with a local declaration, an unused import,
a config key the imported `defineConfig` overload does not accept. It is
what CI's Frontend — Build job runs, so run it before pushing rather
than trusting a green typecheck.

#### Detail-page headers

Action rows follow a fixed grammar, locked in by the `HeaderButton`
primitive (`components/ui/header-button.tsx`):

```
[Refresh] [Sync …] [Import] [Export] [misc reads] [Edit] [Resize] [Delete] [+ Primary]
```

That ordering was written for five or six buttons and does not scale.
Past roughly **seven** simultaneously-visible controls a header stops
fitting: the DNS zone detail reached eleven and clipped `+ Add Record`,
its own primary action, to a sliver at ~1,460 px with the sidebar open
(#996). At that point fold the once-per-object actions into
`HeaderMenu` (`components/ui/header-menu.tsx`) and keep the shape every
detail page should read as:

* `Refresh`
* at most two menus (`Data ▾` / `Zone ▾`, `Sync ▾` / `Tools ▾`)
* one primary action, always last

Carry each item's `disabled` state **and its `title` reason** into the
menu — a dead item with no explanation is worse than a dead button. A
menu whose items all vanish (a forward DNS zone has nothing to import or
export) renders nothing at all rather than a trigger onto an empty
panel.

Regardless of menus, every header gets `flex-wrap` on the row,
`min-w-0 flex-1` on the title block and `shrink-0` on the actions, so a
narrow window wraps the actions under the title instead of clipping
them. This is the same rule the `/admin` pages adopted in Wave D.

Reuse `HeaderMenu`; do not hand-roll the open-state and
outside-mousedown dance. `IPAMPage.tsx` alone had accumulated **three**
copies of it before #996, and the keyboard handling (arrow wrap, Home /
End, Escape returning focus to the trigger, skipping disabled items) is
exactly what every copy left out. It is covered by
`components/ui/header-menu.test.tsx` — the first component test in the
repo, and the reason `jsdom` is a dev dependency.

New keybindings are declared in `lib/shortcuts.ts` and matched via
`matchesShortcut`, never added straight to a component: that is what
puts them in the `?` overlay and keeps the keycap, the handler and the
help text in step (#81).

---

## 4. The Absolute Non-Negotiables

These rules from [`CLAUDE.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md#absolute-non-negotiables)
apply to every change. They are reproduced here as a quick checklist;
the canonical wording lives in `CLAUDE.md`.

1. **API-first** — every UI action must also work via the REST API.
2. **Async throughout** — no synchronous DB or network calls in request
   handlers.
3. **Permissions enforced server-side** — the API validates authorization
   independently of the UI (see [`PERMISSIONS.md`](PERMISSIONS.md)).
4. **Audit everything** — every mutation is written to the append-only
   `audit_log` *before* the response is returned.
5. **Config caching on agents** — DHCP/DNS containers cache their
   last-known-good config locally and keep running if the control plane
   is unreachable.
6. **No hardcoded secrets** — credentials come from env vars or mounted
   secrets; secrets at rest are Fernet-encrypted.
7. **Structured logs always** — every log line is valid JSON with
   `timestamp`, `level`, `service`, `request_id`.
8. **Incremental DNS updates** — record changes use RFC 2136 DDNS or the
   driver API, never a full server restart.
9. **Idempotent tasks** — every Celery task must be safe to retry.
10. **Driver abstraction** — DHCP/DNS backend logic never leaks into the
    service layer (`backend/app/drivers/{dns,dhcp}/`).
11. **Multi-arch builds** — all Docker images support `linux/amd64` and
    `linux/arm64` (see §11).
12. **K8s manifests stay current** — when you add or change a service,
    update `k8s/base/` and `k8s/README.md`.
13. **MCP coverage for new features** — a new REST resource also gets
    matching Operator-Copilot MCP tools, with the default-enabled state
    an explicit decision per tool.
14. **Feature-module gating** — a new top-level resource family is
    evaluated for a togglable feature module (`app.services.feature_modules`).
    It ships **enabled** only if it is core IPAM / DNS / DHCP workflow, a
    zero-footprint UI convenience, or a hand-invoked read-only diagnostic;
    otherwise disabled. Declare the value in the guard test
    `tests/test_feature_module_defaults.py`, and never seed a
    `feature_module` row in a migration.
15. **New integrations show up on the Dashboard** — wire a new
    read-only integration mirror into both the IPAM `IntegrationsPanel`
    and the dedicated Integrations dashboard tab.
16. **Per-role node-label gating** — a new top-level Helm workload gates
    scheduling on a per-role node label, not on a chart-render toggle.

When in doubt, read the full text and the surrounding "Cross-cutting
Patterns" section in `CLAUDE.md` before you start.

---

## 5. Tests

The backend test suite runs against a **real PostgreSQL instance** (not
mocks) so ORM and query issues surface early
(`backend/tests/conftest.py`).

```bash
make test                                  # full suite — pytest -n auto inside the api container
make test-one T=tests/test_health.py::test_liveness   # a single test, run serially
make test-cov                              # the suite with coverage — the ONLY place coverage runs (#1019)
make test-durations                        # refresh backend/.test_durations from the latest main CI run (#1019)
```

The **frontend** has a test suite too, added with the enrolment QR
(#906) and run by the `frontend-lint` CI job:

```bash
cd frontend && npm test          # vitest, jsdom, run once
cd frontend && npm test -- --watch
```

It exists for the class of bug review and `tsc` cannot catch — the QR
tests decode the image the component actually renders, because a
transposed row or an inverted polarity produces a code that looks
entirely normal and scans as nothing.

### Parallelism + per-worker databases

`make test` runs `python -m pytest -n auto` (pytest-xdist), one worker
per CPU. Each worker **carves its own throwaway database** off the same
Postgres instance — `spatiumddi_test_gw0`, `spatiumddi_test_gw1`, … — so
the session-scoped schema reset and per-test `TRUNCATE` can't step on
another worker's data. The non-xdist case (`pytest` with no `-n`) falls
back to the unsuffixed base database name.

`conftest.py` reads `TEST_DATABASE_URL` (default
`postgresql+asyncpg://spatiumddi:changeme@localhost:5432/spatiumddi_test`)
and rewrites `DATABASE_URL` to the per-worker URL **before** any `app.*`
import, so module-level engines and Celery `task_session` engines land in
the right database. `make test` runs inside the dev-compose `api`
container, which has `pytest` baked into its `build.target: dev` image and
`TEST_DATABASE_URL` pre-set against the dev Postgres service.

Because a single test doesn't benefit from xdist overhead, `make test-one`
runs serially (`-v`, no `-n`).

### Coverage is opt-in

`make test-cov` is the only place coverage runs (`--cov=app
--cov-report=term-missing`). It used to ride `addopts` in
`backend/pyproject.toml`, which meant every CI shard and every
`make test-one` paid 15–30 % tracing overhead for a table nothing read —
#435 had removed `--cov` from the CI command line and the `addopts` line
quietly re-added it (#1019). Do not put it back in `addopts`.

### Shard balancing (`backend/.test_durations`)

pytest-split balances the twelve CI shards by **duration** only when a
`.test_durations` file exists; without one it splits by test **count**, and
the alphabetical slice holding the heavy DB-bound files becomes the straggler
(one shard of eight took 25–28 min while the other seven took ~11, for the
same 595 tests — PR #1018). The file is committed and kept honest by CI:

1. Every shard runs with `--store-durations --clean-durations`, so its
   `.test_durations` ends up holding ONLY the tests it ran, and uploads it.
2. On a full run the aggregator merges the pieces
   (`scripts/merge_test_durations.py`) into a `test-durations` artifact.
   **Each shard is first normalized by its runner's speed** — the ratio of
   what it measured to what the committed file predicted for its slice —
   because hosted runners vary about 2× run to run (the same trivial tests
   measured 1.5 s each on one run and 10 s on the next, on a different
   shard each time). A raw measurement would bake one slow runner into the
   weight of every test it happened to hold, which is exactly what the
   first bootstrap of this file did. The normalized value is then blended
   50/50 with the committed one, so a single noisy run cannot swing a
   weight and a genuine change lands within a couple of refreshes.
3. The report prints the raw per-shard wall time with each runner's speed
   factor (that is where the clock went), and emits a `::warning::` only
   when the committed file has stopped describing *relative* costs — more
   than 15 % of the suite's normalized cost moved, or more than 10 % of it
   belongs to tests the file has never seen. Runner variance never trips
   it, because no refresh can fix runner variance.
4. `make test-durations` downloads the newest `main` artifact into
   `backend/.test_durations` for you to commit. Do it at release prep, or
   when the warning fires.

A stale file only costs balance — pytest-split assumes the average for a
test it has never seen — never correctness, so this is a chore, not a gate.
What balancing cannot do is remove the slow-runner tail: with twelve
shards, expect one to land on a runner ~2× slower than the rest, so the
wall clock is bounded by roughly twice the median shard (~7 min → ~14 min
on a bad day, versus 28 min before, when the slowest shard was slow by
construction on every run).
Narrowed PR runs (below) neither upload nor merge durations: a subset must
never become the file the shards are balanced with.

### Test-impact selection (#1020)

A PR does not necessarily run all ~4,200 backend tests. The push-to-`main`
shards run with `--cov-context=test`, and the aggregator folds their
coverage data into a **test-impact map** — `{app file → test files that
executed a line of it inside a test}` — published as the `test-impact-map`
artifact (`.github/scripts/build_test_impact_map.py`). The next PR's
`changes` job downloads the newest one and runs
`.github/scripts/select_impacted_tests.py` over the diff. Its output is
`all` or a list of test files, and the shards run exactly that.

Every rule fails **open**, toward `all` — a wrong "run these" is caught by
the push-to-`main` run, which always runs everything; a wrong "skip that"
would not be:

| Changed path | Selection |
|---|---|
| no map, unreadable map, other schema | `all` |
| anything the deny-list does not call irrelevant that is not one of the two rows below — migrations, `pyproject.toml`, `Dockerfile`, `app/data/*`, templates, `conftest.py`, test helpers, the must-run carve-outs, this machinery | `all` |
| `backend/tests/test_*.py` added or modified | that file |
| `backend/app/**/*.py` in the map, tests attributed | those files |
| `backend/app/**/*.py` in the map, **no** tests attributed (only ever executed at import — a model, a registry) | `all` |
| `backend/app/**/*.py` absent from the map (new, or never imported by a test) | nothing — whatever exercises it is a changed test file or reached through a changed module, both already selected |
| selection empty, or over 60 % of the suite's test files | `all` |

Why not a name mapping or an import graph: only 65 of 358 test-file stems
match an `app/` module name, and 228 of 358 test files use the `client`
fixture, which imports the whole app through `app.main` — a static graph
reaches every test from any change. Observed coverage is the only
dependency data that is actually true.

Pinned by `backend/tests/test_test_impact_selection.py` and
`test_merge_test_durations.py`, both of which skip inside the dev api
container (no repo root above `backend/` there) and run in CI.

### What a new endpoint needs

Per [`CONTRIBUTING.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md), every new API endpoint needs
tests covering the **success**, **unauthorized**, and **validation-error**
cases.

---

## 6. CI Parity — `make ci`

`make ci` runs the same lint/typecheck/build jobs GitHub Actions runs on
every push and pull request. Run it locally before pushing.

```bash
make ci
```

It chains seven targets:

| `make` target | What it runs |
|---|---|
| `ci-backend-lint` | `ruff check app tests`, `black --check app tests`, `mypy app` (inside the api container; installs ruff/black/mypy on first run if missing) |
| `ci-frontend-lint` | `npm run lint && npm run format:check && npm run typecheck` (CI's `frontend-lint` job also runs `npm test`) |
| `ci-frontend-build` | `npm run build` |
| `charts-lint` | The `Charts — Lint & Template` gate, in a helm container (see the job table below) |
| `perf-test` | `python -m pytest perf` in a python container |
| `versions-check` | `python3 scripts/lint_versions.py` — asserts every pin in `versions.json` still matches the files that carry it (see §9). Stdlib-only, no container, no network |
| `workflow-shell-check` | `python3 scripts/lint_workflow_shell.py` — refuses `$?` captured after a bare command in a workflow `run:` block, where GitHub's `bash -e` makes it dead code (see §10) |

`make ci` requires the dev stack to be running (the backend checks
execute inside the api container) and Node 20+ on the host. It does **not**
run the backend tests — use `make test` separately for those.

### The actual CI jobs

The CI workflow is [`.github/workflows/ci.yml`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/workflows/ci.yml),
triggered on push to `main` and on every pull request:

| Job | What it does |
|---|---|
| **Backend — Lint & Type Check** (`backend-lint`) | `pip install -e ".[dev]"` on Python 3.12, then `ruff check`, `black --check`, `mypy app`, **plus the migration-shape linter** (`python3 scripts/lint_migrations.py` — see §8), the **version-pin manifest linter** (`python3 scripts/lint_versions.py` — see §9) and the **workflow shell-status linter** (`python3 scripts/lint_workflow_shell.py` — see §10). |
| **Backend — Tests** (`backend-test`) | A required-check aggregator over **twelve** parallel `backend-test-shard` jobs. Each shard spins up `postgres:16-alpine` + `redis:8.10.2-alpine` services, runs `alembic upgrade head`, then `pytest -n auto --splits 12 --group N --store-durations --clean-durations` (pytest-split selects the shard's slice, **balanced by duration** from the committed `backend/.test_durations` — see §Shard balancing; `-n auto` parallelizes it across the runner's vCPUs, each xdist worker on its own `spatiumddi_test_gw<N>` DB). On a PR the `changes` job may first narrow the run to the test files the diff can affect (#1020 — see §Test-impact selection). The aggregator passes only if all twelve shards pass; on a full run it also merges the shards' measured durations into a `test-durations` artifact, and on a push to `main` it builds the `test-impact-map` artifact from the shards' coverage contexts. Coverage is otherwise **not** collected here (#1019). |
| **Frontend — Lint & Type Check** (`frontend-lint`) | Node 22, `npm install`, then `npm run lint`, `npm run format:check`, `npm run typecheck`, `npm test`. |
| **Frontend — Build** (`frontend-build`) | Node 22, `npm install`, `npm run build`. |
| **Charts — Lint & Template** (`charts-lint`) | Helm v4.3.0 + a checksum-pinned kubeconform. `helm lint --strict` all three charts at defaults and with every role / feature toggle on, `helm template` 14 value sets (umbrella: defaults, all-on, external DB + Redis, the CNPG + Sentinel HA shape, and two pod-posture shapes; appliance: defaults, all-on, the single-node full-stack shape, and the two release-bootstrap / release-supervisor shapes; metallb: defaults, all-on, BGP mode), `kubeconform -strict` against the Kubernetes 1.36 + CRD-catalog schemas (kept at the version the appliance's k3s serves — it was five minors behind until #974), and `.github/scripts/chart-no-besteffort.py` on every render (#965 — no serving container may lack CPU + memory requests or limits; init containers are exempt, they finish before the pod serves) plus `chart-toggle-coverage.py`, which fails if a template is gated on a values key none of the value sets flips. Rendered manifests are uploaded as the `rendered-charts` artifact. Until #966 nothing on a PR parsed the appliance chart at all; it was first read by helm during the release. `make charts-lint` runs the same script in a helm container. |
| **Perf — Tests** (`perf-test`) | Python 3.12 + pytest, `python -m pytest perf`. Hermetic (fake sockets, no network, no appliance). Tests only — `perf/` is outside the Backend Lint scope and carries pre-existing ruff/black drift (#968). `make perf-test` reproduces it. |

Branch protection on `main` (the `protect-main` ruleset) requires every
stable check name above — the two aggregators (`Backend — Tests`,
`Agent — Tests`) and the single-job checks — so a red job blocks the merge
without anyone reading the run (#1022; before that only Backend Lint and the
two Frontend jobs were required, and a 28-minute `Backend — Tests` that
nobody was forced to wait for). `make ci` reproduces
the two lint jobs, the frontend build, the chart gate and the perf tests
locally (the last two via Docker, so neither helm nor kubeconform needs to
be on the host); `make test` reproduces the backend test job
(single-runner rather than sharded).

### What runs when — the trigger policy

Every workflow trigger should answer "what would we miss without it?".
Three of the four events have distinct jobs:

| Event | Runs | Why |
|---|---|---|
| **Pull request** | `ci.yml` (backend shards gated on change detection — see below), the per-image builds (single-arch + **Trivy**, path-filtered to their own `agent/<name>/**`), `agent-e2e.yml` (path-filtered to `agent/**` + `charts/spatiumddi/**` — it installs the control plane from the `:latest` release images, so a `backend/` or `frontend/` change cannot reach the cluster it tests; #1021), plus two GitHub-managed CodeQL runs that are not workflow files: **CodeQL** (default setup: actions, JS/TS, Python) and **CodeQL - Code Quality** (JS/TS, Python — the source of the bot review threads that must be resolved before merge). | Where correctness is gated. Nothing merges without it. |
| **Push to `main`** | `ci.yml`, `docs-publish.yml`, `build-appliance-builder.yml` | Post-merge safety net + the two things that must be *published* from `main`. |
| **Release tag** | `release.yml` only | Builds and publishes every image multi-arch, the chart, and the appliance ISO — after three gates (#1226): the tag is on `main` and `ci.yml` passed on it; each image is built once, pushed by digest, and both architectures pass Trivy + `trivy-gate.sh` before that digest is tagged; and `:latest` moves last, once the GitHub release exists. |
| **Schedule** | `nightly.yml`, `trivy-scheduled.yml`, `prune-release-assets.yml` | Work that is about *elapsed time*, not about a change. |

Two rules follow, and both were violations once:

- **Per-image build workflows do not trigger on push.** On a tag they raced
  `release.yml`, which builds the same image and pushes the same
  `:<VERSION>` tag — two concurrent multi-arch builds of identical source,
  with the winner decided by whichever finished last, on a release
  artifact. On `main` they published `:main` and `:sha-<short>` that
  nothing consumes (no chart, compose file or manifest pins them, and
  `agent-e2e.yml` deliberately builds from PR source instead) *and* skipped
  Trivy on that path. Both jobs are covered better elsewhere: releases by
  `release.yml`, "build `main` periodically" by `nightly.yml` — which
  scans before it publishes.
- **`build-appliance-builder.yml` is the exception and must stay on
  `main`.** `release.yml`'s ISO job and the `APPLIANCE_BUILDER` default in
  the Makefile both pull `appliance-builder:latest`; that tag is how the
  builder image gets published at all.

`ci.yml` stays on push to `main` on purpose. It is redundant with the PR
run in the common case — GitHub tests the merge result — but it validates
the actual squashed commit, and it is the only check that covers a direct
push or a merge made with `--admin` while shards were still pending.

### Skipping the backend shards on a PR that can't affect them

The workflow has no `paths-ignore` and never will: a skipped workflow run
posts none of the check-runs `protect-main` waits for, so a docs-only PR
would sit blocked forever. What [#813](https://github.com/spatiumnorth/spatiumddi/issues/813)
added instead is **per-job** change detection, which keeps the workflow —
and every check name — unconditional:

1. A `changes` job diffs the PR against its merge base and pipes the file
   list through [`.github/scripts/ci-backend-relevant.sh`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/scripts/ci-backend-relevant.sh).
2. The 12 `backend-test-shard` jobs are gated on its output.
3. The `Backend — Tests` aggregator treats a skip as a pass — but **only a
   skip that detection asked for**. An empty output (the `changes` job
   itself failed, taking the shards with it) fails the aggregator.

Push to `main` always runs the full suite; the filter applies to
`pull_request` only.

The path list is a **deny-list**, and that shape is the point. An
allow-list (`run when backend/** changes`) fails silently in the worst
direction — a new top-level directory nobody added stops running the
tests, and the tell is a green PR that was never tested. A deny-list makes
the cost of forgetting a few runner-minutes instead.

Two directories look unrelated to the backend and are deliberately *not*
deny-listed, because backend tests load files out of them by path:

| Test | Reads |
|---|---|
| `test_spatium_console.py` (52 tests) | `appliance/mkosi.extra/usr/local/bin/spatium-console` |
| `test_appliance_firewall_render.py` | `agent/supervisor/spatium_supervisor/firewall_renderer.py` |

Check for new cross-boundary reads before widening the list.
`backend/tests/test_ci_backend_relevant.py` pins the whole table, so
edits to the script are exercised without pushing a branch.

Not yet filtered, and each for a reason: the frontend jobs and
`Backend — Lint` are `protect-main`'s **required** checks, and a skipped
required check is exactly the blocked-PR failure mode above; `agent-test`
and `appliance-test` are seconds each, so the detection would cost more
than it saves.

### Nightly builds

[`.github/workflows/nightly.yml`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/workflows/nightly.yml) builds
and publishes every image from `main` at **20:05 America/New_York**, so
the pre-release is done by about 21:00 for the evening QA walk. GitHub
starts scheduled runs in this repository hours late, so a small companion,
[`nightly-trigger.yml`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/workflows/nightly-trigger.yml), fires
early, waits for the instant on the Eastern clock, and dispatches the
build; `nightly.yml`'s own 03:23 crons are only a fallback for a night
the trigger never fired. Every nightly is named for the **evening it
belongs to** — a build between one 20:05 and the next is
`nightly-<that evening's date>`, whether it ran at 20:05, after midnight,
or as the 03:23 fallback — and an evening that already published is never
rebuilt without `force`. It exists because
nothing else builds the *release* image except a release — which is how
[#732](https://github.com/spatiumnorth/spatiumddi/issues/732) shipped an api
image carrying pytest as root, undetected until the next release cut it.
The nightly also runs the same Trivy scan CI uses on PRs (HIGH/CRITICAL,
fix available), *before* anything is pushed, so a base-image CVE surfaces
the night it lands rather than at the next tag. The verdict comes from
[`.github/scripts/trivy-gate.sh`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/scripts/trivy-gate.sh),
which asks the image's own package index whether each flagged fix is
installable today: if it is, the image fails (a rebuild would cure it);
if Alpine has committed the fix but the package has not reached the
mirrors yet, the finding is **deferred** — a warning, not a failure — and
the next night picks it up. That works because every Alpine image
declares `ARG APK_SNAPSHOT` right before its `apk upgrade`, and the
nightly passes the date tag, so the package layer is rebuilt against the
current index each night instead of being served from the layer cache.

To run current `main` without cutting a release:

```bash
docker pull ghcr.io/spatiumnorth/spatiumddi-api:nightly
```

| Tag | Meaning |
|---|---|
| `:nightly` | The most recent successful nightly. Mutable — it moves. |
| `:nightly-YYYYMMDD` | Immutable snapshot of that build. The newest **7** are kept, the rest pruned in the same run. |

The dated ring exists so "nightly broke X" is answerable: without it the
pointer has already rolled and there is nothing to compare against, and a
broken nightly leaves no fallback. Seven is deliberately small — anyone
pulling `:nightly` never sees the rest.

A run is **skipped entirely when `main` has not moved** since the last
nightly, so the seven tags cover seven *changed* days rather than seven
calendar days.

Each nightly also publishes a **pre-release tagged `nightly-YYYY.MM.DD`**
(the build date, prefixed so it can never match `release.yml`'s
release-tag triggers), carrying that build's appliance ISO + slot-upgrade image and
a `built-from:` line recording the exact commit. Pre-releases older than
**7 days** are deleted automatically, git tag included, so the Releases
page shows at most a week of dated nightlies alongside the real releases
(`prune-release-assets.sh` skips `nightly-*` — the nightly owns its own
retention). A failing nightly opens or comments on a single reused
tracking issue rather than one per night.

`workflow_dispatch` takes `force` (build anyway) and `dry_run` (build and
scan, push and prune nothing).

**Nightly is never tagged `:latest`.** That tag means "latest release".

---

## 7. Repo Layout

A condensed map (full version in [`CLAUDE.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md#repo-layout)):

```
backend/app/
  api/v1/        HTTP route handlers (ipam/, dns/, dhcp/, auth/, …)
  models/        SQLAlchemy 2.x async models
  services/      Business logic (dns/, dhcp/, dns_io/, ipam_io/, ai/)
  drivers/       DNS + DHCP backend abstraction + concrete impls
  tasks/         Celery tasks
  core/          permissions.py, crypto.py, auth/, audit, …
  config.py, db.py, main.py, celery_app.py
backend/alembic/ Migrations (tracked in git)
backend/tests/   pytest suite (conftest.py carves per-worker DBs)
frontend/src/
  pages/         Top-level routes
  components/     Shared UI; shadcn-style primitives under components/ui/
  lib/api.ts     API clients
agent/           Standalone DNS / DHCP agents + supervisor
charts/          Helm charts
k8s/             Kubernetes manifests
scripts/         lint_migrations.py, seed_demo.py, screenshots/, …
```

---

## 8. Migration Workflow

Models are SQLAlchemy 2.x async (`backend/app/models/`); schema changes
are versioned with Alembic in `backend/alembic/`.

```bash
# Generate a migration by autogenerating against the models
make migration MSG="add foo column"

# Apply pending migrations
make migrate
```

`make migration` runs `alembic revision --autogenerate` inside the api
container; review the generated file in `backend/alembic/versions/` —
autogenerate is a starting point, not a final answer.

### Conventions that bite if you miss them

- **Hand-written `create_table` for a `TimestampMixin` model** must set
  `server_default=text("now()")` on `created_at`/`modified_at`. Tests pass
  via `create_all`, but a fresh-install migration NULL-violates without it.
- **Verify the real Alembic head before setting `down_revision`.** A
  recently-dated file is not necessarily the head — run Alembic's
  `get_heads()` (or `alembic heads`); picking the wrong parent creates two
  heads and breaks CI.

### Expand/contract — the migration-shape linter

SpatiumDDI runs rolling N→N+1 upgrades across multiple control-plane
nodes, so during the mixed-version window the database is shared between
old (N-1) and new (N) application code. A destructive migration that
drops a column N-1 still reads will crash the old pods mid-upgrade.

The contract: **every migration must be safe against both N-1 and N
code** — expand in release N (add the new column/table/dual-write), drop
the old one in release N+1.

`scripts/lint_migrations.py` (stdlib-only, runs in the `backend-lint` CI
job) flags destructive ops (`drop_column` / `drop_table` in downgrades,
etc.) so they get the two-release treatment. Historical violations are
captured in a baseline file at
`backend/alembic/migrations_lint_baseline.txt`. If you intentionally add
a finding the linter should accept, regenerate the baseline and commit it:

```bash
python3 scripts/lint_migrations.py --baseline   # rewrite the baseline
python3 scripts/lint_migrations.py              # what CI runs (exit 1 on non-baselined findings)
python3 scripts/lint_migrations.py --show       # every finding, baselined or not
```

---

## 9. Version Pins — `versions.json`

Dependabot covers four ecosystems in this repo: `github-actions`,
`docker` base images in the directories listed in
[`.github/dependabot.yml`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/dependabot.yml), `pip` and `npm`.
Everything else is invisible to it. It has no Helm ecosystem, and it does
not read Dockerfile `ARG` values, chart `values.yaml`, action `with:`
inputs, CI shell-script defaults or the appliance bake arrays.

Those pins are declared in **[`versions.json`](https://github.com/spatiumnorth/spatiumddi/blob/main/versions.json)** at the
repo root — one entry per component, carrying the canonical `version`,
every file that holds a copy of it, the `upstream` to check it against,
and (where a pin is deliberately behind) a `hold` field with the reason.

```bash
make versions-check       # offline; part of make ci and of CI's Backend Lint job
make versions-upstream     # current-vs-latest table; advisory, needs network
```

### Bumping a component

Edit the `version` field and run `make versions-check`. Every site's
expected string is a **template** over that field, so the lint reports
exactly which files still carry the old value — that list is the
worklist. Nothing reads the manifest at build time, so the literals in
each file stay real and greppable.

### Adding a pin

Add an entry with a `pinned_in` list. Two fields are easy to get wrong:

- **`count`** is the *exact* number of occurrences required. Omit it and
  the rule becomes "at least one" — which passes a bump that moved two
  of three copies and left a mixed-version cluster. Use an exact count
  wherever the copies must be exhaustive.
- **`digest`**, for a component pinned by tag *and* digest. A digest does
  not derive from a version, so the offline lint can only assert the
  literal; `make versions-upstream` is what resolves the tag and reports
  a pair that has come apart.

Unknown keys are **refused** rather than ignored, because a typo such as
`"counts": 3` would otherwise silently downgrade the guard.

### What does not belong here

Anything a lockfile or Dependabot already owns — `pyproject` /
`package-lock` dependencies, `uses:` action refs, and `FROM` lines
Dependabot actually bumps. Listing those twice re-creates the drift the
file exists to remove.

The **one deliberate exception** is a Dependabot-visible `FROM` that
shares a component with a copy Dependabot cannot see. `nginx` is the
worked example: the bot moved `frontend/Dockerfile` to 1.31 and the
appliance chart's copy sat on 1.30.3 for seven weeks, because nothing
connected them. Listing both means the next bot bump fails the lint until
the other copies move with it.

---

## 10. Workflow Shell — `$?` under `set -e`

GitHub Actions runs every `run:` block under **`bash -e`**. Writing
`set -uo pipefail` at the top — which several steps here do — does **not**
clear that flag:

```console
$ bash -ec 'set -uo pipefail; case "$-" in *e*) echo "-e STILL ON";; esac'
-e STILL ON
```

So this shape is dead code on exactly the failure it was written to handle:

```bash
some_command > out      # -e kills the step here when it fails
rc=$?                   # never reached
if [ "$rc" -eq 0 ]; ...
```

**It is invisible by construction.** The step is green on the happy path, and
the branch that would report a problem is the one that never runs. It cost
this repo a working weekly CVE scan: `trivy-scheduled.yml` captured Trivy's
status this way, and Trivy exits 1 *on findings* — so the step died at the
first image with a CVE, `has_findings` was never written, and a clean week
looked identical to a week full of criticals
([#1036](https://github.com/spatiumnorth/spatiumddi/issues/1036)).

`scripts/lint_workflow_shell.py` refuses the shape, in CI's Backend Lint job
and in `make ci`. Neither `actionlint` nor `shellcheck -S style` reports it
(both checked) — shellcheck's SC2181 fires on a direct `if [ $? -ne 0 ]` but
not on `rc=$?` followed by a test of `$rc`.

### The three accepted forms

```bash
if cmd; then rc=0; else rc=$?; fi   # preferred — keeps the status AND the guard
cmd || true                          # when the status is not needed
set +e; cmd; rc=$?; set -e           # for a long run of commands
```

A genuine exception carries `# lint-workflow-shell: allow`.

### Standalone `.sh` files

The linter also scans `.github/scripts/*.sh`, where `-e` comes from the script
rather than the interpreter. Turning the check **on** there requires an
*unindented* `set -e`; turning it **off** accepts a `set +e` at any indent.
That asymmetry is deliberate — file order is not execution order.
`spatium-install` is `set -uo pipefail` at the top and enables `-e` deep inside
`do_install()`, which runs *after* the wizard loop and preseed parser that
appear below it in the file. Counting an indented `set -e` produced four
confident findings about code where `-e` is off, and a linter that cries wolf
on the installer is one that gets deleted.

---

## 11. Multi-Arch Image Builds

Every Docker image must support **`linux/amd64` and `linux/arm64`**
(non-negotiable #11). The release pipeline
([`.github/workflows/release.yml`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/workflows/release.yml))
builds each image with `docker/setup-qemu-action` +
`docker/setup-buildx-action` and `platforms: linux/amd64,linux/arm64`.
Local `make build` produces single-arch images for your host — the
multi-arch fan-out happens in CI on a tagged release.

---

## 12. Branch & PR Conventions

- **Branch from `main`.** The project uses one branch per issue, named
  `issue-NNN` (keep every phase of a multi-phase change on the same
  branch). Squash-merge back to `main`.
- **Conventional-commit PR titles:** `<type>(<scope>): <short summary>`
  where `type` ∈ `feat, fix, docs, refactor, perf, test, build, ci,
  chore` and `scope` ∈ `ipam, dns, dhcp, auth, rbac, audit, ui, api, k8s,
  compose, agent-dns, agent-dhcp` (see
  [`.github/pull_request_template.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/.github/pull_request_template.md)).
- **Fill in the PR template** — Summary, Area, Test plan, and
  Migration/deployment notes. Don't leave them blank.
- **Link issues with the keyword per issue:**
  `Closes #123, Closes #456` — a comma-list like `Closes #123, #456` only
  closes the first.
- **Run `make ci` before pushing**, and `make test` for any
  behavioral change.

### Pre-PR checklist

- [ ] `make ci` passes (backend lint, frontend lint + typecheck, frontend build)
- [ ] `make test` passes (new/changed behavior is covered)
- [ ] Mutations write to `audit_log` before returning
- [ ] New endpoints have success / unauthorized / validation-error tests
- [ ] Alembic migration included if models changed (and it's expand/contract-safe)
- [ ] `k8s/base/` + `k8s/README.md` updated if a service or its env changed
- [ ] Matching MCP tools added for any new REST surface
- [ ] Third-party components added to the root `NOTICE` if you bundled any

---

## 13. Security Disclosure

Do **not** file security vulnerabilities as public issues. Use
[GitHub Security Advisories](https://github.com/spatiumnorth/spatiumddi/security/advisories/new)
for private disclosure, as described in
[`CONTRIBUTING.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md).

---

## See Also

- [`CONTRIBUTING.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CONTRIBUTING.md) — contribution flow, code
  standards summary, PR process
- [`CLAUDE.md`](https://github.com/spatiumnorth/spatiumddi/blob/main/CLAUDE.md) — the canonical project spec, full
  non-negotiables, and cross-cutting patterns
- [`PERMISSIONS.md`](PERMISSIONS.md) — the RBAC permission grammar enforced
  server-side
- [`deployment/DOCKER.md`](deployment/DOCKER.md) — Compose setup, ports, TLS
- [`OBSERVABILITY.md`](OBSERVABILITY.md) — structured logging, metrics,
  health dashboard
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — recovery recipes

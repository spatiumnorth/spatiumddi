#!/usr/bin/env bash
#
# Does a change set require the backend test suite? (issues #813, #821)
#
# Reads changed paths on stdin, one per line. Prints "true" if the suite must
# run, "false" if every changed path is known not to affect it.
#
# ── Two lists, checked in order ──────────────────────────────────────────────
#
# 1. ci-backend-must-run.txt (sibling file) — prefixes OUTSIDE backend/ that
#    must run the suite anyway: files backend tests read directly, plus the
#    gate machinery itself. Checked FIRST, so a subtree can be denied below
#    while the specific paths the suite depends on keep running it. The
#    manifest is enforced against reality by
#    backend/tests/test_ci_backend_relevant.py — a scan fails when a backend
#    test grows a new repo-root read that isn't declared, so the carve-outs
#    cannot go stale in the direction that loses coverage.
#
# 2. The IRRELEVANT deny-list below. An allow-list ("run when backend/**
#    changes") fails open in the wrong direction: a new top-level directory
#    nobody remembered to add silently stops running the tests, and the
#    failure is invisible — a green PR that was never tested. A deny-list
#    fails the other way. Anything unrecognised runs the suite, so the worst
#    case of forgetting to update this file is a few wasted runner-minutes.
#
# So: only add a path to the deny-list when you can say why the backend suite
# cannot possibly care about it — and if a denied subtree contains something
# the suite DOES care about, declare that in the manifest instead of undoing
# the deny.
#
# ── Why agent/, appliance/ and .github/ are denied WITH carve-outs ───────────
#
# All three used to run the suite wholesale (#813 left them off the deny-list)
# because a handful of backend tests read files out of them:
#
#   backend/tests/test_spatium_console.py
#       → appliance/mkosi.extra/usr/local/bin/spatium-console  (52 tests)
#   backend/tests/test_appliance_firewall_render.py
#       → agent/supervisor/spatium_supervisor/firewall_renderer.py
#   backend/tests/test_ci_backend_relevant.py
#       → this script + its manifest
#
# Those reads are now declared in the manifest, which lets the rest of each
# subtree skip: the agent packages and appliance image have their own
# unconditional jobs (Agent — Tests, Appliance — Tests), and no workflow
# other than ci.yml runs backend tests. If the backend shards ever move to a
# different workflow file, add it to the manifest.
#
# ── Testability ──────────────────────────────────────────────────────────────
#
# Path matching lives here rather than inline in ci.yml so it can be exercised
# without pushing a branch: backend/tests/test_ci_backend_relevant.py pipes
# synthetic change sets through it. The workflow computes the diff and pipes
# it in; this script never shells out to git.

set -euo pipefail

# Paths that cannot affect the backend test suite.
#
#   docs/       Jekyll site + specs. No backend test reads them; the
#               docs-diagrams job covers the SVG geometry separately.
#   website/    Marketing site source, not built or imported by anything here.
#   frontend/   Separate toolchain, covered by the frontend jobs.
#   charts/     Helm templates. test_upgrades_chart_bump.py exercises the
#               chart-bump LOGIC against inline YAML, never the real chart.
#   k8s/        Static manifests, read by nothing in the suite.
#   agent/      Agent packages, covered by the Agent — Tests jobs. The
#               shipped packages backend tests read (the firewall renderer,
#               the outbound-host guard's scan) are carved out in the manifest.
#   appliance/  Image build tree, covered by Appliance — Tests. The host
#               scripts backend tests load are carved out in the manifest.
#   .github/    Workflows + repo config. ci.yml and the gate machinery are
#               carved out in the manifest; nothing else here runs the suite.
#   *.md        Root-level prose (README, CHANGELOG, CLAUDE.md, ...). Nested
#               *.md are covered by their own directory's entry, or fall
#               through and run the suite — which is the safe direction.
#   perf/       Off-box load-generation + campaign tooling (#968). Nothing in
#               backend/ imports it and no backend test reads it; it has its
#               own Perf — Tests job. Before this entry a perf-only PR fell
#               through to "unrecognised → run" and spent all 8 shards on
#               tests that could not be affected, while running none that
#               could — exactly inverted.
#   NOTICE      Third-party attribution.
#   LICENSE     Apache 2.0 text.
IRRELEVANT='^(docs/|website/|frontend/|charts/|k8s/|agent/|appliance/|perf/|\.github/|[^/]+\.md$|NOTICE$|LICENSE$)'

# Load the must-run carve-outs. A missing or unreadable manifest fails toward
# running the suite — same direction as every other failure here.
MANIFEST="$(dirname "${BASH_SOURCE[0]}")/ci-backend-must-run.txt"
MUST_RUN=()
if [ -r "$MANIFEST" ]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        # Trim surrounding whitespace without forking a process per line.
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -n "$line" ] && MUST_RUN+=("$line")
    done < "$MANIFEST"
else
    echo "true"
    exit 0
fi

saw_any=0
while IFS= read -r path; do
    [ -n "$path" ] || continue
    saw_any=1
    for prefix in "${MUST_RUN[@]}"; do
        case "$path" in
            "$prefix"*)
                echo "true"
                exit 0
                ;;
        esac
    done
    if ! printf '%s\n' "$path" | grep -qE "$IRRELEVANT"; then
        # One relevant file is enough — no need to read the rest.
        echo "true"
        exit 0
    fi
done

# An empty change set is not evidence that nothing needs testing; it means the
# diff failed, the caller piped nothing, or something else went wrong upstream.
# Run the suite.
if [ "$saw_any" -eq 0 ]; then
    echo "true"
    exit 0
fi

echo "false"

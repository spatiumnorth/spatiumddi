#!/usr/bin/env bash
# Has the FULL backend suite passed on this exact commit? (#2429)
#
# release.yml's gate (#1226). Since #2429 a push to main may report success
# with the 12 backend shards skipped, resting on the merged PR's own run of
# the identical tree. That is sound for merging, but a release must never
# rest on a skipped-shards run alone, so this asks for a ci.yml run on SHA
# itself — push, schedule, workflow_dispatch or merge_group — whose LATEST
# attempt published the ``backend-full-suite-attempt-<n>`` marker (all 12
# shards, full suite, that attempt). A ``workflow_dispatch`` run cannot skip:
# the ``changes`` job only consults ci-tested-on-pr-head.sh on a push.
#
# #2431 — a ``merge_group`` run counts because the merge queue fast-forwards
# main to the very commit it tested, so its head_sha IS the released commit
# and it ran that commit's own workflow. Only one from a
# ``gh-readonly-queue/main/`` branch of this repository; a merge-group run
# never narrows its tests (#1020), and the marker check below still decides.
#
# Push runs created before LEGACY_CUTOFF predate the markers and always ran
# the full suite (there was no skip), so a successful one counts on its own.
# A run after the cutoff with no marker does not: an expired or deleted
# marker must never read as "full".
#
# Inputs (environment): SHA, REPO. Needs gh (actions read) and jq.
# Exit codes, with the reason on stderr:
#   0  passed — a full-suite run on SHA succeeded
#   1  failed — no run will pass as things stand (or an API error)
#   2  pending — a ci.yml run on SHA has not finished yet
#   3  needs a full run — SHA's run(s) succeeded but skipped the shards
#   4  none — ci.yml has not run on SHA (yet)
#
# Pinned by backend/tests/test_ci_tested_on_pr_head.py.

set -uo pipefail

LEGACY_CUTOFF="2026-10-23T00:00:00Z"

say() { echo "$*" >&2; }

SHA="${SHA:-}"
REPO="${REPO:-}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { say "SHA is not a commit id"; exit 1; }
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { say "REPO is not owner/name"; exit 1; }

# The merge-queue trust predicate and the marker lookup, shared with
# ci-tested-on-pr-head.sh.
# shellcheck source=ci-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/ci-lib.sh" || { say "cannot load ci-lib.sh"; exit 1; }

tmp="$(mktemp -d)" || { say "cannot create a temp dir"; exit 1; }
trap 'rm -rf "$tmp"' EXIT

gh api "repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${SHA}&per_page=50" > "$tmp/runs.json" 2>/dev/null \
  || { say "could not list ci.yml runs for ${SHA::7}"; exit 1; }
rows="$(jq -r --arg sha "$SHA" --arg repo "$REPO" "$CI_MERGE_QUEUE_RUN_JQ"'
    .workflow_runs[]
    | select(.head_sha == $sha
             and (.event == "push" or .event == "schedule" or .event == "workflow_dispatch"
                  or merge_queue_run($repo)))
    | [.id, .event, .status, (.conclusion // "none"), .run_attempt, .created_at, .html_url] | @tsv' \
    "$tmp/runs.json" 2>/dev/null)" || { say "unexpected reply listing ci.yml runs"; exit 1; }

if [ -z "$rows" ]; then
  say "ci.yml has not run on ${SHA::7} as a push, schedule, dispatch or merge group"
  exit 4
fi

# Does run $id carry artifact $1? Expired artifacts are still listed by
# name, which is all this needs. An API error or an unexpected reply is a
# failure of the gate, never a "no".
has() {
  local rc=0
  ci_run_has_artifact "$id" "$1" any || rc=$?
  if [ "$rc" -eq 2 ]; then
    say "could not list the artifacts of run $id"
    exit 1
  fi
  [ "$rc" -eq 0 ]
}

pending=0
skipped=0
# Every field is non-empty (no conclusion is "none"): tab is IFS whitespace,
# so an empty field would collapse and shift the rest.
while IFS=$'\t' read -r id event status conclusion attempt created url; do
  [[ "$id" =~ ^[0-9]+$ && "$attempt" =~ ^[0-9]+$ ]] || continue
  if [ "$status" != "completed" ]; then
    pending=1
    continue
  fi
  [ "$conclusion" = "success" ] || continue
  if has "$(ci_full_suite_marker "$attempt")"; then
    say "✓ the full backend suite passed on ${SHA::7} in $event run $id (attempt $attempt): $url"
    exit 0
  fi
  if [ "$event" = push ] && [[ "$created" < "$LEGACY_CUTOFF" ]] \
     && ! has "backend-skipped-tested-on-pr-head-attempt-${attempt}" \
     && ! has "backend-skipped-tested-in-merge-queue-attempt-${attempt}"; then
    say "✓ push run $id predates the backend-suite markers and ran the full suite: $url"
    exit 0
  fi
  if has "backend-skipped-tested-on-pr-head-attempt-${attempt}"; then
    say "$event run $id passed with the backend shards SKIPPED (tree tested on the merged PR's head, #2429): $url"
  elif has "backend-skipped-tested-in-merge-queue-attempt-${attempt}"; then
    say "$event run $id passed with the backend shards SKIPPED (commit tested in the merge queue, #2431): $url"
  else
    say "$event run $id passed but carries no full-suite marker for attempt $attempt: $url"
  fi
  skipped=1
done <<< "$rows"

if [ "$pending" -eq 1 ]; then
  say "a ci.yml run on ${SHA::7} has not finished"
  exit 2
fi
if [ "$skipped" -eq 1 ]; then
  exit 3
fi
say "no ci.yml run on ${SHA::7} succeeded"
exit 1

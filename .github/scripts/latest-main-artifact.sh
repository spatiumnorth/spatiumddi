#!/usr/bin/env bash
# Download the newest artifact NAME that a successful main-branch CI run
# (push, schedule or workflow_dispatch) published, into DEST. (#2429)
#
# Usage: latest-main-artifact.sh NAME DEST
#
# Shared by ci.yml (the test-impact map, #1020) and ``make test-durations``
# (#1019), which used to carry two copies of "find the latest main run, try
# to download". Since #2429 most pushes to main skip the shards and publish
# neither artifact, so walking runs and attempting a download from each
# wasted a call per skipped run. This asks the artifacts API for the name
# directly, newest first.
#
# A ``pull_request`` run's artifact is NEVER accepted, whatever it is called:
# a fork PR's run executes the fork's copy of the workflow and can report
# ``head_branch: main``, so it could publish a crafted map. Every candidate's
# run is therefore fetched and must be a successful ci.yml run of this
# repository on main, from one of the three main-only events. A narrowed
# PR run's measurements must never become the durations file either.
#
# Each download goes into a fresh subdirectory, so a partial or failed
# download cannot block the next candidate. On success the artifact's files
# are copied into DEST and the run id is printed on stdout.
#
# Env: REPO (defaults to GITHUB_REPOSITORY, then the gh default repo); gh
# authenticated (GH_TOKEN in CI); jq.
#
# Pinned by backend/tests/test_ci_tested_on_pr_head.py.

set -uo pipefail

NAME="${1:-}"
DEST="${2:-}"
# How many candidate artifacts to consider before giving up.
MAX_CANDIDATES=10

fail() {
  echo "latest-main-artifact: $*" >&2
  exit 1
}

[[ "$NAME" =~ ^[A-Za-z0-9._-]+$ ]] || fail "artifact name missing or malformed"
[ -n "$DEST" ] && [ -d "$DEST" ] || fail "DEST must be an existing directory"
command -v gh >/dev/null 2>&1 || fail "gh is not installed"
command -v jq >/dev/null 2>&1 || fail "jq is not installed"
REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
if [ -z "$REPO" ]; then
  REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)" || REPO=""
fi
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "cannot tell which repository to read"

tmp="$(mktemp -d)" || fail "cannot create a temp dir"
trap 'rm -rf "$tmp"' EXIT

gh api "repos/${REPO}/actions/artifacts?name=${NAME}&per_page=100" > "$tmp/artifacts.json" 2>/dev/null \
  || fail "could not list artifacts named $NAME"
# head_repository_id == repository_id: a cheap first cut that drops fork runs
# before the per-run check below, which is the one that decides.
runs="$(jq -r --arg n "$NAME" --argjson max "$MAX_CANDIDATES" '
    [ .artifacts[]
      | select(.name == $n and .expired == false
               and .workflow_run.head_branch == "main"
               and .workflow_run.head_repository_id == .workflow_run.repository_id) ]
    | sort_by(.created_at) | reverse | .[:$max] | .[] | .workflow_run.id' "$tmp/artifacts.json" 2>/dev/null)" \
  || fail "unexpected reply listing artifacts named $NAME"
[ -n "$runs" ] || fail "no unexpired $NAME artifact from a main run"

i=0
for run in $runs; do
  [[ "$run" =~ ^[0-9]+$ ]] || continue
  gh api "repos/${REPO}/actions/runs/${run}" > "$tmp/run.json" 2>/dev/null || continue
  ok="$(jq -r --arg repo "$REPO" '
      (.event == "push" or .event == "schedule" or .event == "workflow_dispatch")
      and .head_branch == "main" and .conclusion == "success"
      and (.path | split("@")[0]) == ".github/workflows/ci.yml"
      and (.repository.full_name // "") == $repo
      and (.head_repository.full_name // "") == $repo' "$tmp/run.json" 2>/dev/null)"
  [ "$ok" = "true" ] || continue
  i=$((i + 1))
  sub="$tmp/download-$i"
  mkdir "$sub" || continue
  if gh run download "$run" -R "$REPO" -n "$NAME" -D "$sub" >/dev/null 2>&1; then
    cp -a "$sub"/. "$DEST"/ || fail "could not copy the artifact into $DEST"
    echo "$run"
    exit 0
  fi
done
fail "no successful main run among the newest $NAME artifacts could be downloaded"

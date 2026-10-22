#!/usr/bin/env bash
# Was the tree of this push to main already tested by a green, full backend
# run on a PR head? (#2429)
#
# A push to main runs the full backend suite as the post-merge safety net.
# Under strict up-to-date branch protection that net re-tests a tree CI has
# just passed: the squash-merge of an up-to-date PR has exactly the tree of
# the PR head, and the PR's own run tested ``refs/pull/N/merge`` — the PR
# head merged into the main of that moment, which is an ancestor of the
# head, so that merge's tree is the head's tree too. The re-run costs ~180
# runner-minutes per merge on a 20-job runner pool and is cancelled by the
# next merge more than half the time anyway.
#
# This answers "may the 12 shards be skipped?" and FAILS SAFE: exit 0 only
# when every condition below is positively established; anything else —
# an API error, an unexpected shape, a missing artifact — is exit 1, and
# the caller runs the full suite.
#
# Two independent ways to establish it, tried in this order:
#
#   A. The merge queue (#2431) tested THIS COMMIT. The queue builds each
#      entry on a ``gh-readonly-queue/main/...`` branch and, when the group
#      merges, fast-forwards main to that branch's head — the very commit
#      its ``merge_group`` run tested, whatever the number of commits in the
#      push (a group of N squash commits lands as one push). So: a
#      ``merge_group`` run of ci.yml in this repository with head_sha == SHA,
#      from a ``gh-readonly-queue/main/`` branch, concluded ``success``,
#      created no more than MAX_RUN_AGE_SECONDS ago, whose LATEST attempt
#      published ``backend-full-suite-attempt-<run_attempt>``. A merge-group
#      run never narrows (#1020), but a docs-only group skips its shards
#      (#813) and publishes no marker, so its push runs the suite. Commit
#      identity is a stronger guarantee than the tree comparison of path B,
#      and the run executed the workflow of the commit itself, so no fork
#      concern arises. Any failure on this path falls through to B.
#
#   B. The merged PR's own run tested an identical tree:
#
#   1. The push added exactly one commit: BEFORE is SHA's only parent. A
#      direct push, a multi-commit rebase merge or a merge commit fails.
#   2. GitHub records exactly one PR, merged into main, whose merge commit
#      IS this SHA, and whose head branch lives in this repository. A fork
#      PR is refused: its run executed the fork's copy of the workflow.
#   3. That PR's head H (fetched by its pull ref) has the same tree as SHA,
#      and contains BEFORE — so H was up to date with main when it merged,
#      and the run's test merge was a no-op on H's tree.
#   4. A ``pull_request`` run of ci.yml on exactly H, from the PR's own head
#      branch in this repository, concluded ``success``, was created before
#      the merge and no more than MAX_RUN_AGE_SECONDS before it, and its
#      LATEST attempt published the unexpired marker
#      ``backend-full-suite-attempt-<run_attempt>``. The aggregator uploads
#      that marker only when all 12 shards passed the FULL suite in that
#      attempt's view, so a narrowed (#1020) or shard-skipped (#813) run
#      never qualifies, and neither does a marker an earlier attempt left.
#      A narrowed PR run keeps relying on this push run to catch what it did
#      not select, so it must never be skipped here.
#
#      The run is tied to the PR by head SHA + head branch + head repository
#      rather than by the run's ``pull_requests`` array, because GitHub
#      clears that array once the PR merges (observed on run 39771722974,
#      PR #2379) — at the only moment this script ever asks.
#
# Inputs (environment, never interpolated into code): SHA, BEFORE, REPO.
# Needs ``gh`` with GH_TOKEN (contents, pull-requests and actions read),
# ``jq``, and a checkout with full history (fetch-depth: 0). Every API reply
# is fetched as raw JSON and filtered here with jq, so the filters are the
# ones the tests exercise.
#
# stdout on exit 0: one line — path A ``merge_group run=<id> attempt=<n>``,
# path B ``pr=<N> head=<sha> run=<id> attempt=<n>``. ci.yml keys the skip
# reason it reports on the first word.
# stderr: the reason for the verdict either way.
#
# Pinned by backend/tests/test_ci_tested_on_pr_head.py.

set -uo pipefail

# The PR run must be this recent at merge time. The merge train re-runs CI
# after merging main into each PR, so a fresh run normally exists; an old
# one is not trusted to describe today's runners, services and images.
MAX_RUN_AGE_SECONDS=86400

no() {
  echo "full suite: $*" >&2
  exit 1
}

is_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

SHA="${SHA:-}"
BEFORE="${BEFORE:-}"
REPO="${REPO:-}"

is_sha "$SHA" || no "SHA is not a commit id"
is_sha "$BEFORE" || no "BEFORE is not a commit id (a new branch, or a forced push)"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || no "REPO is not owner/name"
command -v gh >/dev/null 2>&1 || no "gh is not installed"
command -v jq >/dev/null 2>&1 || no "jq is not installed"

# The merge-queue trust predicate and the marker lookup, shared with
# ci-full-suite-passed.sh.
# shellcheck source=ci-lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/ci-lib.sh" || no "cannot load ci-lib.sh"

tmp="$(mktemp -d)" || no "cannot create a temp dir"
trap 'rm -rf "$tmp"' EXIT

# A. The merge queue's run of this exact commit (#2431). Every failure here
#    only means "not established this way": fall through to B.
merge_queue_run() {
  gh api "repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${SHA}&event=merge_group&status=completed&per_page=30" \
    > "$tmp/mq-runs.json" 2>/dev/null || return 1
  local now cands id attempt
  now="$(date -u +%s)" || return 1
  cands="$(jq -r --arg sha "$SHA" --arg repo "$REPO" --argjson now "$now" \
                --argjson max "$MAX_RUN_AGE_SECONDS" "$CI_MERGE_QUEUE_RUN_JQ"'
      [ .workflow_runs[]
        | select(.head_sha == $sha and merge_queue_run($repo)
                 and .status == "completed" and .conclusion == "success")
        | (.created_at | fromdateiso8601) as $c
        | select($c <= $now and ($now - $c) <= $max)
        | {id, run_attempt, c: $c} ]
      | sort_by(-.c) | .[] | "\(.id)\t\(.run_attempt)"' "$tmp/mq-runs.json" 2>/dev/null)" || return 1
  [ -n "$cands" ] || return 1
  while IFS=$'\t' read -r id attempt; do
    [[ "$id" =~ ^[0-9]+$ && "$attempt" =~ ^[0-9]+$ ]] || continue
    if ci_run_has_artifact "$id" "$(ci_full_suite_marker "$attempt")" unexpired; then
      echo "skip shards: the merge queue's CI run $id (attempt $attempt) passed the full backend suite on exactly ${SHA:0:12}" >&2
      echo "merge_group run=$id attempt=$attempt"
      return 0
    fi
  done <<< "$cands"
  return 1
}
if merge_queue_run; then
  exit 0
fi
echo "not tested in the merge queue as this exact commit; checking the merged PR's head" >&2

# B. The merged PR's head.

# 1. Exactly one new commit, with exactly one parent.
parents="$(git rev-list --parents -n 1 "$SHA" 2>/dev/null)" || no "cannot read $SHA"
read -r -a fields <<< "$parents"
[ "${#fields[@]}" -eq 2 ] || no "$SHA is not a single-parent commit"
[ "${fields[1]}" = "$BEFORE" ] || no "the push added more than one commit"

# 2. The PR this commit is the merge of.
gh api "repos/${REPO}/commits/${SHA}/pulls" > "$tmp/pulls.json" 2>/dev/null \
  || no "could not list the PRs for $SHA"
match="$(jq -r --arg sha "$SHA" '
    [ .[] | select(.merged_at != null and .merge_commit_sha == $sha and .base.ref == "main") ]
    | if length == 1 then .[0] | [.number, .head.sha, (.head.ref // "-"), (.head.repo.full_name // "-"), .merged_at] | @tsv
      else empty end' "$tmp/pulls.json" 2>/dev/null)" \
  || no "unexpected reply listing the PRs for $SHA"
[ -n "$match" ] || no "$SHA is not the merge commit of exactly one PR into main"
# Every field is non-empty (absent ones are "-"): tab is IFS whitespace, so
# an empty field would collapse and shift the rest.
IFS=$'\t' read -r pr head head_ref head_repo merged_at <<< "$match"
[[ "$pr" =~ ^[0-9]+$ ]] || no "unexpected PR number"
is_sha "$head" || no "unexpected PR head"
[ "$head_repo" = "$REPO" ] || no "PR #$pr comes from another repository ($head_repo); its run used that copy of the workflow"
[ "$head_ref" != "-" ] || no "PR #$pr has no head branch"

# 3. Same tree, and the head was up to date with main.
ref="refs/ci-tested/pr-head"
git fetch --no-tags --quiet origin "+refs/pull/${pr}/head:${ref}" 2>/dev/null \
  || no "could not fetch the head of PR #$pr"
[ "$(git rev-parse --verify --quiet "$ref")" = "$head" ] \
  || no "PR #$pr's head ref is not the head GitHub recorded"
tree_sha="$(git rev-parse --verify --quiet "${SHA}^{tree}")" || no "no tree for $SHA"
tree_head="$(git rev-parse --verify --quiet "${head}^{tree}")" || no "no tree for $head"
[ "$tree_sha" = "$tree_head" ] || no "$SHA's tree differs from PR #$pr's head"
git merge-base --is-ancestor "$BEFORE" "$head" 2>/dev/null \
  || no "PR #$pr's head did not contain main when it merged"

# 4. A recent green PR run on exactly that head, from that branch, whose
#    latest attempt ran the full backend suite.
gh api "repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${head}&event=pull_request&status=completed&per_page=30" \
  > "$tmp/runs.json" 2>/dev/null || no "could not list ci.yml runs for $head"
candidates="$(jq -r --arg h "$head" --arg br "$head_ref" --arg repo "$REPO" \
                 --arg merged "$merged_at" --argjson max "$MAX_RUN_AGE_SECONDS" '
    ($merged | fromdateiso8601) as $m
    | [ .workflow_runs[]
        | select(.head_sha == $h and .event == "pull_request"
                 and .status == "completed" and .conclusion == "success"
                 and .head_branch == $br
                 and (.head_repository.full_name // "") == $repo)
        | (.created_at | fromdateiso8601) as $c
        | select($c < $m and ($m - $c) <= $max)
        | {id, run_attempt, c: $c} ]
    | sort_by(-.c) | .[] | "\(.id)\t\(.run_attempt)"' "$tmp/runs.json" 2>/dev/null)" \
  || no "unexpected reply listing ci.yml runs for $head"
[ -n "$candidates" ] \
  || no "no successful pull_request CI run of PR #$pr's head in the $((MAX_RUN_AGE_SECONDS / 3600)) h before it merged"
while IFS=$'\t' read -r id attempt; do
  [[ "$id" =~ ^[0-9]+$ && "$attempt" =~ ^[0-9]+$ ]] || continue
  rc=0
  ci_run_has_artifact "$id" "$(ci_full_suite_marker "$attempt")" unexpired || rc=$?
  [ "$rc" -ne 2 ] || no "could not list the artifacts of run $id (or an unexpected reply)"
  if [ "$rc" -eq 0 ]; then
    echo "skip shards: tree identical to PR #$pr head ${head:0:12}, whose CI run $id (attempt $attempt) passed the full backend suite" >&2
    echo "pr=$pr head=$head run=$id attempt=$attempt"
    exit 0
  fi
done <<< "$candidates"
no "PR #$pr's green run(s) on that head did not run the full backend suite in their latest attempt (narrowed, shards skipped, or the marker expired)"

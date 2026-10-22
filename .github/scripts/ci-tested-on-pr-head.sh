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
#   1. The push added exactly one commit: BEFORE is SHA's only parent. A
#      direct push, a multi-commit rebase merge or a merge commit fails.
#   2. GitHub records exactly one PR, merged into main, whose merge commit
#      IS this SHA.
#   3. That PR's head H (fetched by its pull ref) has the same tree as SHA,
#      and contains BEFORE — so H was up to date with main when it merged,
#      and the run's test merge was a no-op on H's tree.
#   4. ci.yml has a ``pull_request`` run on head H whose conclusion is
#      ``success`` and that uploaded the ``test-durations`` artifact. The
#      aggregator uploads that artifact only when all 12 shards succeeded on
#      the FULL suite, so its presence is the proof the run was neither
#      narrowed (#1020) nor shard-skipped (#813). A narrowed PR run keeps
#      relying on this push run to catch what it did not select, so it must
#      never be skipped here.
#
# Inputs (environment, never interpolated into code): SHA, BEFORE, REPO.
# Needs ``gh`` with GH_TOKEN (contents, pull-requests and actions read) and
# a checkout with full history (fetch-depth: 0).
#
# stdout on exit 0: one line, ``pr=<N> head=<sha> run=<id>``.
# stderr: the reason for the verdict either way.
#
# Pinned by backend/tests/test_ci_tested_on_pr_head.py.

set -uo pipefail

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

# 1. Exactly one new commit, with exactly one parent.
parents="$(git rev-list --parents -n 1 "$SHA" 2>/dev/null)" || no "cannot read $SHA"
read -r -a fields <<< "$parents"
[ "${#fields[@]}" -eq 2 ] || no "$SHA is not a single-parent commit"
[ "${fields[1]}" = "$BEFORE" ] || no "the push added more than one commit"

# 2. The PR this commit is the merge of.
prs="$(gh api "repos/${REPO}/commits/${SHA}/pulls" \
         --jq '.[] | [.number, .head.sha, (.merge_commit_sha // ""), .base.ref, (.merged_at // "")] | @tsv' \
         2>/dev/null)" || no "could not list the PRs for $SHA"
match="$(awk -F '\t' -v sha="$SHA" '$3 == sha && $4 == "main" && $5 != ""' <<< "$prs")"
[ -n "$match" ] || no "$SHA is not the merge commit of a PR into main"
[ "$(wc -l <<< "$match")" -eq 1 ] || no "more than one PR claims $SHA"
pr="$(cut -f1 <<< "$match")"
head="$(cut -f2 <<< "$match")"
[[ "$pr" =~ ^[0-9]+$ ]] || no "unexpected PR number"
is_sha "$head" || no "unexpected PR head"

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

# 4. A green PR run on exactly that head that ran the full backend suite.
runs="$(gh api "repos/${REPO}/actions/workflows/ci.yml/runs?head_sha=${head}&event=pull_request&per_page=30" \
          --jq '.workflow_runs[] | [.id, .head_sha, .event, .status, (.conclusion // "")] | @tsv' \
          2>/dev/null)" || no "could not list ci.yml runs for $head"
ids="$(awk -F '\t' -v h="$head" \
         '$2 == h && $3 == "pull_request" && $4 == "completed" && $5 == "success" { print $1 }' \
         <<< "$runs")"
[ -n "$ids" ] || no "no successful pull_request CI run on PR #$pr's head"
for id in $ids; do
  [[ "$id" =~ ^[0-9]+$ ]] || continue
  n="$(gh api "repos/${REPO}/actions/runs/${id}/artifacts?name=test-durations" \
         --jq '[.artifacts[] | select(.name == "test-durations")] | length' 2>/dev/null)" || continue
  if [ "$n" -ge 1 ] 2>/dev/null; then
    echo "skip shards: tree identical to PR #$pr head ${head:0:12}, whose CI run $id passed the full backend suite" >&2
    echo "pr=$pr head=$head run=$id"
    exit 0
  fi
done
no "PR #$pr's green run(s) on that head did not run the full backend suite (narrowed or shards skipped)"

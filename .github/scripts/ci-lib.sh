# shellcheck shell=bash
# Shared by ci-tested-on-pr-head.sh and ci-full-suite-passed.sh (#2431), so
# "which merge-group run do we trust" and "did this attempt pass the full
# suite" have one definition each. Sourced, never executed. Callers set REPO
# (owner/name, already validated) and have gh + jq on PATH.
#
# Pinned through both callers by backend/tests/test_ci_tested_on_pr_head.py.

# A jq definition: is this workflow run the merge queue's run for main, in
# this repository? Prepend it to a filter and call ``merge_queue_run($repo)``.
# Only a ``gh-readonly-queue/main/`` branch counts — a queue for another
# branch tested a tree that never lands on main — and the run must be of
# this repository's own workflow, never a fork's.
# SC2016: jq variables, not shell ones. SC2034: read by the sourcing scripts.
# shellcheck disable=SC2016,SC2034
CI_MERGE_QUEUE_RUN_JQ='def merge_queue_run($repo):
  .event == "merge_group"
  and ((.head_branch // "") | startswith("gh-readonly-queue/main/"))
  and (.repository.full_name // "") == $repo
  and (.head_repository.full_name // "") == $repo;'

# The marker the ``Backend — Tests`` aggregator uploads when all 12 shards
# passed the FULL suite in attempt $1. Named per attempt so a re-run never
# inherits an earlier attempt's verdict.
ci_full_suite_marker() {
  printf 'backend-full-suite-attempt-%s' "$1"
}

# ci_run_has_artifact RUN NAME MODE — does run RUN carry artifact NAME?
# MODE ``unexpired`` counts only a live artifact; ``any`` also counts an
# expired one (the listing by name is the proof; retention does not change
# what ran). Returns 0 yes, 1 no, 2 could not tell (API error or an
# unexpected reply) — callers must treat 2 as "not established".
ci_run_has_artifact() {
  local run="$1" name="$2" mode="$3" reply rc
  [[ "$run" =~ ^[0-9]+$ && "$name" =~ ^[A-Za-z0-9._-]+$ ]] || return 2
  reply="$(gh api "repos/${REPO}/actions/runs/${run}/artifacts?name=${name}" 2>/dev/null)" || return 2
  rc=0
  jq -e --arg n "$name" --arg mode "$mode" \
    'any(.artifacts[]; .name == $n and ($mode == "any" or .expired == false))' \
    <<< "$reply" > /dev/null 2>&1 || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
}

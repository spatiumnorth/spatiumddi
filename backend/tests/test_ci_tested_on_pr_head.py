"""The scripts behind skipping the backend shards on a push to main (#2429).

Three scripts under ``.github/scripts/``:

* ``ci-tested-on-pr-head.sh`` decides whether a push to main re-runs the 12
  backend shards or rests on the merged PR's own CI run. Its one acceptable
  failure direction is toward running the suite, so every refusal is pinned
  here beside the one case it answers yes to.
* ``ci-full-suite-passed.sh`` is release.yml's gate: a release must never
  rest on a skipped-shards run alone.
* ``latest-main-artifact.sh`` finds the newest test-impact map / durations
  artifact a main run published, and must never accept a pull_request run's.

All three fetch raw JSON with ``gh api`` and filter it with ``jq`` locally,
so the stub ``gh`` here returns realistic API payloads and the scripts' own
jq filters run against them (the stub refuses ``--jq``, which would hide
them). It also logs every endpoint, so the query parameters are pinned too.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPTS = _REPO_ROOT / ".github" / "scripts"
_TESTED = _SCRIPTS / "ci-tested-on-pr-head.sh"
_GATE = _SCRIPTS / "ci-full-suite-passed.sh"
_LATEST = _SCRIPTS / "latest-main-artifact.sh"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout.
pytestmark = pytest.mark.skipif(
    not _TESTED.exists() or shutil.which("git") is None or shutil.which("jq") is None,
    reason="the CI scripts, git or jq are not present in this environment",
)

_GH_STUB = r"""#!/usr/bin/env bash
for a in "$@"; do
  [ "$a" != --jq ] || { echo "stub gh: --jq would bypass the script's own filter" >&2; exit 9; }
done
reply() {  # reply KEY FILE [DEFAULT]
  [ -z "$(printenv "STUB_FAIL_$1")" ] || { echo "HTTP 502" >&2; exit 1; }
  if [ -f "$STUB_DIR/$2" ]; then cat "$STUB_DIR/$2"
  elif [ -n "${3:-}" ]; then printf '%s\n' "$3"
  else echo "HTTP 404" >&2; exit 1; fi
}
case "$1" in
  api)
    ep="$2"; echo "$ep" >> "$STUB_DIR/calls"
    case "$ep" in
      */commits/*/pulls) reply pulls pulls.json ;;
      */actions/workflows/ci.yml/runs\?*) reply runs runs.json ;;
      */actions/runs/*/artifacts*)
        id="${ep#*/actions/runs/}"; id="${id%%/*}"
        reply artifacts "artifacts-$id.json" '{"total_count":0,"artifacts":[]}' ;;
      */actions/artifacts\?*) reply named named.json ;;
      */actions/runs/*)
        id="${ep##*/}"; reply run "run-$id.json" ;;
      *) echo "unexpected endpoint: $ep" >&2; exit 1 ;;
    esac ;;
  run)
    # gh run download ID -R REPO -n NAME -D DIR
    [ "$2" = download ] || exit 1
    id="$3"; dir=""
    while [ $# -gt 0 ]; do [ "$1" = -D ] && dir="$2"; shift; done
    src="$STUB_DIR/download-$id"
    [ -d "$src" ] || { echo "no artifact" >&2; exit 1; }
    cp -a "$src"/. "$dir"/
    [ ! -f "$STUB_DIR/download-$id.fail" ] || exit 1 ;;
  *) echo "unexpected gh call: $*" >&2; exit 1 ;;
esac
"""

REPO = "example/repo"
PR = 7
RUN = 100
BRANCH = "issue-7"
MERGED = datetime(2026, 10, 22, 12, 0, 0, tzinfo=UTC)


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(cwd: pathlib.Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


class Stub:
    """A stub ``gh`` on PATH whose replies are JSON files in a directory."""

    def __init__(self, tmp: pathlib.Path) -> None:
        self.dir = tmp / "stub"
        self.dir.mkdir()
        self.bin = tmp / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(_GH_STUB)
        gh.chmod(0o755)

    def put(self, name: str, payload: object) -> None:
        (self.dir / name).write_text(json.dumps(payload))

    def calls(self) -> list[str]:
        path = self.dir / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def env(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "STUB_DIR": str(self.dir),
            "REPO": REPO,
            **extra,
        }


def _pull(head_sha: str, merge: str, **over: object) -> dict[str, object]:
    pull: dict[str, object] = {
        "number": PR,
        "head": {"sha": head_sha, "ref": BRANCH, "repo": {"full_name": REPO}},
        "base": {"ref": "main", "repo": {"full_name": REPO}},
        "merge_commit_sha": merge,
        "merged_at": _iso(MERGED),
    }
    pull.update(over)
    return pull


def _run(head_sha: str, **over: object) -> dict[str, object]:
    run: dict[str, object] = {
        "id": RUN,
        "head_sha": head_sha,
        "head_branch": BRANCH,
        "head_repository": {"full_name": REPO},
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "created_at": _iso(MERGED - timedelta(hours=1)),
        "run_attempt": 1,
        "path": ".github/workflows/ci.yml",
        "html_url": f"https://github.com/{REPO}/actions/runs/{RUN}",
    }
    run.update(over)
    return run


def _artifacts(*names: str, expired: bool = False) -> dict[str, object]:
    return {
        "total_count": len(names),
        "artifacts": [{"id": i + 1, "name": n, "expired": expired} for i, n in enumerate(names)],
    }


# ── ci-tested-on-pr-head.sh ──────────────────────────────────────────────────


class Repo:
    """An origin whose main is ``base -> squash`` and whose ``refs/pull/7/head``
    is a PR head built on ``base`` with the same tree as ``squash``; plus a
    stub ``gh`` describing a merged PR with a green, full, fresh CI run."""

    def __init__(self, tmp: pathlib.Path) -> None:
        self.origin = tmp / "origin"
        self.origin.mkdir()
        o = self.origin
        _git(o, "init", "-q", "-b", "main")
        (o / "a.txt").write_text("a\n")
        _git(o, "add", "a.txt")
        _git(o, "commit", "-q", "-m", "base")
        self.base = _git(o, "rev-parse", "HEAD")
        _git(o, "checkout", "-q", "-b", "pr")
        (o / "b.txt").write_text("b\n")
        _git(o, "add", "b.txt")
        _git(o, "commit", "-q", "-m", "change")
        _git(o, "commit", "-q", "--allow-empty", "-m", "fixup")
        self.head = _git(o, "rev-parse", "HEAD")
        _git(o, "update-ref", f"refs/pull/{PR}/head", self.head)
        _git(o, "checkout", "-q", "main")
        _git(o, "merge", "-q", "--squash", "pr")
        _git(o, "commit", "-q", "-m", f"change (#{PR})")
        self.squash = _git(o, "rev-parse", "HEAD")
        self.work = tmp / "work"
        _git(tmp, "clone", "-q", str(o), str(self.work))
        self.stub = Stub(tmp)
        self.pulls([_pull(self.head, self.squash)])
        self.runs([_run(self.head)])
        self.artifacts(RUN, "backend-full-suite-attempt-1")

    def pulls(self, rows: list[dict[str, object]]) -> None:
        self.stub.put("pulls.json", rows)

    def runs(self, rows: list[dict[str, object]]) -> None:
        self.stub.put("runs.json", {"total_count": len(rows), "workflow_runs": rows})

    def artifacts(self, run: int, *names: str, expired: bool = False) -> None:
        self.stub.put(f"artifacts-{run}.json", _artifacts(*names, expired=expired))

    def refetch(self) -> None:
        _git(self.work, "fetch", "-q", "origin", "+main:refs/remotes/origin/main")

    def run(self, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(_TESTED)],
            cwd=self.work,
            env=self.stub.env(**{"SHA": self.squash, "BEFORE": self.base, **env}),
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.fixture()
def repo(tmp_path: pathlib.Path) -> Repo:
    return Repo(tmp_path)


def test_identical_tree_with_a_full_green_pr_run_skips(repo: Repo) -> None:
    result = repo.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"pr={PR} head={repo.head} run={RUN} attempt=1"
    calls = repo.stub.calls()
    assert f"repos/{REPO}/commits/{repo.squash}/pulls" in calls
    assert (
        f"repos/{REPO}/actions/workflows/ci.yml/runs?head_sha={repo.head}"
        "&event=pull_request&status=completed&per_page=30"
    ) in calls
    assert f"repos/{REPO}/actions/runs/{RUN}/artifacts?name=backend-full-suite-attempt-1" in calls


def test_a_narrowed_or_shard_skipped_pr_run_runs_the_suite(repo: Repo) -> None:
    """No full-suite marker: the PR run selected a subset (#1020) or skipped
    the shards (#813), and this push run is what catches the rest."""
    repo.artifacts(RUN, "test-durations-shard-1", "backend-skipped-tested-on-pr-head-attempt-1")
    result = repo.run()
    assert result.returncode == 1
    assert "did not run the full backend suite" in result.stderr


def test_an_expired_marker_does_not_count(repo: Repo) -> None:
    repo.artifacts(RUN, "backend-full-suite-attempt-1", expired=True)
    assert repo.run().returncode == 1


def test_only_the_latest_attempts_marker_counts(repo: Repo) -> None:
    """Attempt 1 ran the full suite; attempt 2 (the one the conclusion
    describes) did not publish a marker. The leftover must not count."""
    repo.runs([_run(repo.head, run_attempt=2)])
    repo.artifacts(RUN, "backend-full-suite-attempt-1")
    assert repo.run().returncode == 1
    repo.artifacts(RUN, "backend-full-suite-attempt-1", "backend-full-suite-attempt-2")
    result = repo.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("attempt=2")


def test_an_older_qualifying_run_is_found_behind_a_newer_one(repo: Repo) -> None:
    repo.runs(
        [
            _run(repo.head, id=101, created_at=_iso(MERGED - timedelta(minutes=30))),
            _run(repo.head, id=RUN, created_at=_iso(MERGED - timedelta(hours=2))),
        ]
    )
    result = repo.run()
    assert result.returncode == 0, result.stderr
    assert f"run={RUN} " in result.stdout


@pytest.mark.parametrize(
    "over",
    [
        {"conclusion": "failure"},
        {"status": "in_progress", "conclusion": None},
        {"event": "push"},
        {"head_branch": "someone-elses-branch"},
        {"head_repository": {"full_name": "fork/repo"}},
        {"created_at": _iso(MERGED + timedelta(minutes=1))},  # after the merge
        {"created_at": _iso(MERGED - timedelta(hours=25))},  # too old
    ],
)
def test_a_run_that_does_not_qualify_runs_the_suite(repo: Repo, over: dict[str, object]) -> None:
    repo.runs([_run(repo.head, **over)])
    result = repo.run()
    assert result.returncode == 1
    assert "no successful pull_request CI run" in result.stderr


def test_a_run_on_another_head_does_not_count(repo: Repo) -> None:
    repo.runs([_run(repo.base)])
    assert repo.run().returncode == 1


def test_a_run_within_the_freshness_window_counts(repo: Repo) -> None:
    repo.runs([_run(repo.head, created_at=_iso(MERGED - timedelta(hours=23)))])
    assert repo.run().returncode == 0


def test_a_fork_pr_runs_the_suite(repo: Repo) -> None:
    repo.pulls(
        [
            _pull(
                repo.head,
                repo.squash,
                head={"sha": repo.head, "ref": BRANCH, "repo": {"full_name": "fork/repo"}},
            )
        ]
    )
    result = repo.run()
    assert result.returncode == 1
    assert "another repository" in result.stderr


def test_a_pr_whose_head_repo_is_gone_runs_the_suite(repo: Repo) -> None:
    """A deleted fork reports ``head.repo: null``. The empty field must not
    collapse in the tab-separated read and shift the merge time into place."""
    repo.pulls(
        [_pull(repo.head, repo.squash, head={"sha": repo.head, "ref": BRANCH, "repo": None})]
    )
    result = repo.run()
    assert result.returncode == 1
    assert "another repository" in result.stderr


def test_a_differing_tree_runs_the_suite(repo: Repo) -> None:
    o = repo.origin
    (o / "c.txt").write_text("c\n")
    _git(o, "add", "c.txt")
    _git(o, "commit", "-q", "--amend", "-m", f"change plus (#{PR})")
    squash = _git(o, "rev-parse", "HEAD")
    repo.refetch()
    repo.pulls([_pull(repo.head, squash)])
    result = repo.run(SHA=squash)
    assert result.returncode == 1
    assert "tree differs" in result.stderr


def test_a_head_that_did_not_contain_main_runs_the_suite(repo: Repo) -> None:
    """Same tree, but main had moved under the PR: the PR run tested a merge
    of the head with an older main, not this tree."""
    o = repo.origin
    _git(o, "checkout", "-q", "-b", "stale", repo.base)
    (o / "b.txt").write_text("b\n")
    _git(o, "add", "b.txt")
    _git(o, "commit", "-q", "-m", "stale head")
    stale_head = _git(o, "rev-parse", "HEAD")
    _git(o, "checkout", "-q", "main")
    _git(o, "reset", "-q", "--hard", repo.base)
    _git(o, "commit", "-q", "--allow-empty", "-m", "main moved")
    moved = _git(o, "rev-parse", "HEAD")
    (o / "b.txt").write_text("b\n")
    _git(o, "add", "b.txt")
    _git(o, "commit", "-q", "-m", f"change (#{PR})")
    squash = _git(o, "rev-parse", "HEAD")
    _git(o, "update-ref", f"refs/pull/{PR}/head", stale_head)
    repo.refetch()
    repo.pulls([_pull(stale_head, squash)])
    repo.runs([_run(stale_head)])
    result = repo.run(SHA=squash, BEFORE=moved)
    assert result.returncode == 1
    assert "did not contain main" in result.stderr


def test_more_than_one_pushed_commit_runs_the_suite(repo: Repo) -> None:
    o = repo.origin
    _git(o, "commit", "-q", "--allow-empty", "-m", "direct push")
    top = _git(o, "rev-parse", "HEAD")
    repo.refetch()
    repo.pulls([_pull(repo.head, top)])
    result = repo.run(SHA=top, BEFORE=repo.base)
    assert result.returncode == 1
    assert "more than one commit" in result.stderr


def test_a_merge_commit_runs_the_suite(repo: Repo) -> None:
    o = repo.origin
    _git(o, "merge", "-q", "--no-ff", "--no-edit", "pr")
    merge = _git(o, "rev-parse", "HEAD")
    repo.refetch()
    repo.pulls([_pull(repo.head, merge)])
    result = repo.run(SHA=merge, BEFORE=repo.squash)
    assert result.returncode == 1
    assert "single-parent" in result.stderr


@pytest.mark.parametrize(
    "case",
    ["none", "another_commit", "not_into_main", "not_merged", "ambiguous"],
)
def test_no_single_merged_pr_runs_the_suite(repo: Repo, case: str) -> None:
    pulls = {
        "none": [],
        "another_commit": [_pull(repo.head, "e" * 40)],
        "not_into_main": [_pull(repo.head, repo.squash, base={"ref": "release"})],
        "not_merged": [_pull(repo.head, repo.squash, merged_at=None)],
        "ambiguous": [_pull(repo.head, repo.squash), _pull(repo.head, repo.squash, number=8)],
    }[case]
    repo.pulls(pulls)
    result = repo.run()
    assert result.returncode == 1
    assert "exactly one PR" in result.stderr


def test_a_head_the_pull_ref_disagrees_with_runs_the_suite(repo: Repo) -> None:
    repo.pulls([_pull(repo.base, repo.squash)])
    result = repo.run()
    assert result.returncode == 1
    assert "head ref is not the head" in result.stderr


@pytest.mark.parametrize("which", ["pulls", "runs", "artifacts"])
def test_an_api_failure_runs_the_suite(repo: Repo, which: str) -> None:
    result = repo.run(**{f"STUB_FAIL_{which}": "1"})
    assert result.returncode == 1
    assert "could not list" in result.stderr


@pytest.mark.parametrize("which", ["pulls.json", "runs.json", f"artifacts-{RUN}.json"])
def test_a_malformed_api_reply_runs_the_suite(repo: Repo, which: str) -> None:
    (repo.stub.dir / which).write_text("<html>rate limited</html>")
    assert repo.run().returncode == 1


@pytest.mark.parametrize(
    "env",
    [
        {"SHA": ""},
        {"SHA": "not-a-sha; touch /tmp/x"},
        {"BEFORE": "0" * 39},
        {"REPO": "a/b c"},
    ],
)
def test_malformed_input_runs_the_suite(repo: Repo, env: dict[str, str]) -> None:
    assert repo.run(**env).returncode == 1


# ── ci-tested-on-pr-head.sh, path A: the merge queue (#2431) ────────────────


def _mq_run(sha: str, **over: object) -> dict[str, object]:
    """A merge_group run of SHA, created an hour ago (path A's age bound is
    measured against now, not against a merge time)."""
    fields: dict[str, object] = {
        "id": 300,
        "head_branch": f"gh-readonly-queue/main/pr-{PR}-{'f' * 40}",
        "event": "merge_group",
        "repository": {"full_name": REPO},
        "created_at": _iso(datetime.now(UTC) - timedelta(hours=1)),
    }
    fields.update(over)
    return _run(sha, **fields)


def test_a_merge_queue_run_of_this_commit_skips(repo: Repo) -> None:
    """The queue fast-forwards main to the commit its run tested, so commit
    identity is the proof — no PR lookup, no tree comparison needed."""
    repo.runs([_mq_run(repo.squash)])
    repo.artifacts(300, "backend-full-suite-attempt-1")
    result = repo.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "merge_group run=300 attempt=1"
    calls = repo.stub.calls()
    assert (
        f"repos/{REPO}/actions/workflows/ci.yml/runs?head_sha={repo.squash}"
        "&event=merge_group&status=completed&per_page=30"
    ) in calls
    assert f"repos/{REPO}/commits/{repo.squash}/pulls" not in calls


def test_a_merge_queue_group_of_several_commits_skips(repo: Repo) -> None:
    """A group of N squash commits lands as one push: path B refuses that
    (more than one commit), path A does not need to."""
    o = repo.origin
    _git(o, "commit", "-q", "--allow-empty", "-m", "second queued PR (#8)")
    top = _git(o, "rev-parse", "HEAD")
    repo.refetch()
    repo.runs([_mq_run(top)])
    repo.artifacts(300, "backend-full-suite-attempt-1")
    result = repo.run(SHA=top, BEFORE=repo.base)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("merge_group ")


@pytest.mark.parametrize(
    "over",
    [
        {"conclusion": "failure"},
        {"status": "in_progress", "conclusion": None},
        {"head_branch": "gh-readonly-queue/release/pr-7-abc"},
        {"head_branch": "main"},
        {"repository": {"full_name": "fork/repo"}},
        {"head_repository": {"full_name": "fork/repo"}},
        {"created_at": _iso(datetime.now(UTC) - timedelta(hours=25))},
    ],
)
def test_a_merge_queue_run_that_does_not_qualify_falls_through(
    repo: Repo, over: dict[str, object]
) -> None:
    """Falls through to path B, which (no qualifying PR run here) refuses."""
    repo.runs([_mq_run(repo.squash, **over)])
    repo.artifacts(300, "backend-full-suite-attempt-1")
    result = repo.run()
    assert result.returncode == 1
    assert "not tested in the merge queue" in result.stderr


def test_a_merge_queue_run_of_another_commit_does_not_count(repo: Repo) -> None:
    repo.runs([_mq_run(repo.head)])
    repo.artifacts(300, "backend-full-suite-attempt-1")
    assert repo.run().returncode == 1


@pytest.mark.parametrize(
    "names",
    [
        (),  # a docs-only group skipped its shards (#813): no marker
        ("backend-full-suite-attempt-1",),  # an earlier attempt's marker
    ],
)
def test_a_merge_queue_run_without_the_latest_full_marker_does_not_count(
    repo: Repo, names: tuple[str, ...]
) -> None:
    repo.runs([_mq_run(repo.squash, run_attempt=2)])
    repo.artifacts(300, *names)
    assert repo.run().returncode == 1


def test_path_b_still_answers_when_the_merge_queue_lookup_fails(repo: Repo) -> None:
    """Both lookups share the runs endpoint in the stub, so a malformed
    merge-group row must not stop path B finding the PR run beside it."""
    repo.runs([_run(repo.head), _mq_run(repo.squash, created_at="not-a-date")])
    result = repo.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(f"pr={PR} ")


# ── ci-full-suite-passed.sh (release.yml's gate) ─────────────────────────────

SHA = "a" * 40
BEFORE_CUTOFF = "2026-10-20T10:00:00Z"
AFTER_CUTOFF = "2026-10-24T10:00:00Z"


class Gate:
    def __init__(self, tmp: pathlib.Path) -> None:
        self.tmp = tmp
        self.stub = Stub(tmp)

    def runs(self, *rows: dict[str, object]) -> None:
        self.stub.put("runs.json", {"total_count": len(rows), "workflow_runs": list(rows)})

    def artifacts(self, run: int, *names: str, expired: bool = False) -> None:
        self.stub.put(f"artifacts-{run}.json", _artifacts(*names, expired=expired))

    def run(self, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(_GATE)],
            cwd=self.tmp,
            env=self.stub.env(**{"SHA": SHA, **env}),
            capture_output=True,
            text=True,
            check=False,
        )


def _main_run(run_id: int, event: str = "push", **over: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "id": run_id,
        "event": event,
        "head_branch": "main",
        "created_at": AFTER_CUTOFF,
    }
    fields.update(over)
    return _run(SHA, **fields)


@pytest.fixture()
def gate(tmp_path: pathlib.Path) -> Gate:
    return Gate(tmp_path)


def test_gate_passes_on_a_full_suite_push_run(gate: Gate) -> None:
    gate.runs(_main_run(1))
    gate.artifacts(1, "backend-full-suite-attempt-1")
    result = gate.run()
    assert result.returncode == 0, result.stderr
    calls = gate.stub.calls()
    assert f"repos/{REPO}/actions/workflows/ci.yml/runs?head_sha={SHA}&per_page=50" in calls


def test_gate_refuses_a_skipped_shards_run_alone(gate: Gate) -> None:
    gate.runs(_main_run(1))
    gate.artifacts(1, "backend-skipped-tested-on-pr-head-attempt-1")
    result = gate.run()
    assert result.returncode == 3
    assert "SKIPPED" in result.stderr


@pytest.mark.parametrize("event", ["workflow_dispatch", "schedule"])
def test_gate_accepts_a_full_run_beside_a_skipped_one(gate: Gate, event: str) -> None:
    gate.runs(_main_run(2, event), _main_run(1))
    gate.artifacts(1, "backend-skipped-tested-on-pr-head-attempt-1")
    gate.artifacts(2, "backend-full-suite-attempt-1")
    assert gate.run().returncode == 0


def test_gate_waits_while_a_dispatched_run_is_in_progress(gate: Gate) -> None:
    gate.runs(
        _main_run(2, "workflow_dispatch", status="in_progress", conclusion=None), _main_run(1)
    )
    gate.artifacts(1, "backend-skipped-tested-on-pr-head-attempt-1")
    assert gate.run().returncode == 2


def test_gate_accepts_the_merge_queue_run_of_the_commit(gate: Gate) -> None:
    """#2431 — the queue fast-forwards main to the commit it tested, so its
    full run of that commit counts beside a skipped push run."""
    gate.runs(
        _main_run(
            2,
            "merge_group",
            head_branch="gh-readonly-queue/main/pr-7-abc",
            repository={"full_name": REPO},
        ),
        _main_run(1),
    )
    gate.artifacts(1, "backend-skipped-tested-in-merge-queue-attempt-1")
    gate.artifacts(2, "backend-full-suite-attempt-1")
    result = gate.run()
    assert result.returncode == 0, result.stderr
    assert "merge_group run 2" in result.stderr


@pytest.mark.parametrize(
    "over",
    [
        {"head_branch": "issue-7"},
        {"head_branch": "gh-readonly-queue/release/pr-7-abc"},
        {"repository": {"full_name": "fork/repo"}},
    ],
)
def test_gate_ignores_a_merge_group_run_off_mains_queue(
    gate: Gate, over: dict[str, object]
) -> None:
    fields: dict[str, object] = {
        "head_branch": "gh-readonly-queue/main/pr-7-abc",
        "repository": {"full_name": REPO},
    }
    fields.update(over)
    gate.runs(_main_run(2, "merge_group", **fields))
    gate.artifacts(2, "backend-full-suite-attempt-1")
    assert gate.run().returncode == 4


def test_gate_refuses_a_merge_queue_skipped_push_run_alone(gate: Gate) -> None:
    gate.runs(_main_run(1))
    gate.artifacts(1, "backend-skipped-tested-in-merge-queue-attempt-1")
    result = gate.run()
    assert result.returncode == 3
    assert "merge queue" in result.stderr


def test_gate_legacy_push_with_a_merge_queue_skip_marker_is_not_full(gate: Gate) -> None:
    gate.runs(_main_run(1, created_at=BEFORE_CUTOFF))
    gate.artifacts(1, "backend-skipped-tested-in-merge-queue-attempt-1")
    assert gate.run().returncode == 3


def test_gate_reports_no_run(gate: Gate) -> None:
    gate.runs()
    assert gate.run().returncode == 4


def test_gate_ignores_a_pull_request_run_on_the_same_sha(gate: Gate) -> None:
    gate.runs(_run(SHA, id=5))
    gate.artifacts(5, "backend-full-suite-attempt-1")
    assert gate.run().returncode == 4


def test_gate_accepts_a_push_run_from_before_the_markers(gate: Gate) -> None:
    gate.runs(_main_run(1, created_at=BEFORE_CUTOFF))
    assert gate.run().returncode == 0


def test_gate_refuses_an_unmarked_push_run_after_the_cutoff(gate: Gate) -> None:
    """An expired or deleted marker must never read as "full"."""
    gate.runs(_main_run(1))
    assert gate.run().returncode == 3


def test_gate_requires_the_latest_attempts_full_marker(gate: Gate) -> None:
    gate.runs(_main_run(1, run_attempt=2))
    gate.artifacts(1, "backend-full-suite-attempt-1", "backend-skipped-tested-on-pr-head-attempt-2")
    assert gate.run().returncode == 3


def test_gate_accepts_an_expired_full_marker(gate: Gate) -> None:
    """Listing by name is the proof; retention does not change what ran."""
    gate.runs(_main_run(1))
    gate.artifacts(1, "backend-full-suite-attempt-1", expired=True)
    assert gate.run().returncode == 0


def test_gate_fails_when_the_only_run_failed(gate: Gate) -> None:
    gate.runs(_main_run(1, conclusion="failure"))
    assert gate.run().returncode == 1


@pytest.mark.parametrize("which", ["runs", "artifacts"])
def test_gate_fails_on_an_api_error(gate: Gate, which: str) -> None:
    gate.runs(_main_run(1))
    gate.artifacts(1, "backend-full-suite-attempt-1")
    assert gate.run(**{f"STUB_FAIL_{which}": "1"}).returncode == 1


# ── latest-main-artifact.sh ──────────────────────────────────────────────────


class Latest:
    def __init__(self, tmp: pathlib.Path) -> None:
        self.tmp = tmp
        self.stub = Stub(tmp)
        self.dest = tmp / "dest"
        self.dest.mkdir()
        self.items: list[dict[str, object]] = []

    def artifact(
        self,
        run_id: int,
        created: str,
        *,
        event: str = "push",
        branch: str = "main",
        fork: bool = False,
        conclusion: str = "success",
        expired: bool = False,
        fail_download: bool = False,
    ) -> None:
        self.items.append(
            {
                "id": run_id * 10,
                "name": "test-impact-map",
                "expired": expired,
                "created_at": created,
                "workflow_run": {
                    "id": run_id,
                    "head_branch": branch,
                    "repository_id": 1,
                    "head_repository_id": 2 if fork else 1,
                },
            }
        )
        self.stub.put(
            "named.json", {"total_count": len(self.items), "artifacts": list(reversed(self.items))}
        )
        self.stub.put(
            f"run-{run_id}.json",
            {
                "id": run_id,
                "event": event,
                "head_branch": branch,
                "conclusion": conclusion,
                "path": ".github/workflows/ci.yml",
                "repository": {"full_name": REPO},
                "head_repository": {"full_name": "fork/repo" if fork else REPO},
            },
        )
        src = self.stub.dir / f"download-{run_id}"
        src.mkdir()
        (src / f"from-{run_id}.json").write_text("{}")
        if fail_download:
            (self.stub.dir / f"download-{run_id}.fail").write_text("")

    def run(self, name: str = "test-impact-map", **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(_LATEST), name, str(self.dest)],
            cwd=self.tmp,
            env=self.stub.env(**env),
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.fixture()
def latest(tmp_path: pathlib.Path) -> Latest:
    return Latest(tmp_path)


def test_latest_picks_the_newest_main_run(latest: Latest) -> None:
    latest.artifact(1, "2026-10-20T00:00:00Z")
    latest.artifact(2, "2026-10-21T00:00:00Z", event="schedule")
    result = latest.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "2"
    assert sorted(p.name for p in latest.dest.iterdir()) == ["from-2.json"]
    calls = latest.stub.calls()
    assert f"repos/{REPO}/actions/artifacts?name=test-impact-map&per_page=100" in calls


@pytest.mark.parametrize(
    "kwargs",
    [
        {"event": "pull_request"},  # a same-repo PR run reporting main
        {"fork": True},  # a fork PR's run of the fork's workflow
        {"branch": "issue-9"},
        {"conclusion": "failure"},
        {"expired": True},
    ],
)
def test_latest_never_takes_a_disqualified_run(latest: Latest, kwargs: dict[str, object]) -> None:
    latest.artifact(1, "2026-10-20T00:00:00Z")
    latest.artifact(2, "2026-10-22T00:00:00Z", **kwargs)  # type: ignore[arg-type]
    result = latest.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"


def test_latest_falls_back_past_a_failed_download_in_a_fresh_dir(latest: Latest) -> None:
    """A partial download must neither block the next candidate nor leak."""
    latest.artifact(1, "2026-10-20T00:00:00Z")
    latest.artifact(2, "2026-10-22T00:00:00Z", fail_download=True)
    result = latest.run()
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "1"
    assert sorted(p.name for p in latest.dest.iterdir()) == ["from-1.json"]


def test_latest_fails_when_nothing_qualifies(latest: Latest) -> None:
    latest.artifact(1, "2026-10-20T00:00:00Z", event="pull_request")
    assert latest.run().returncode == 1


def test_latest_fails_on_an_api_error(latest: Latest) -> None:
    latest.artifact(1, "2026-10-20T00:00:00Z")
    assert latest.run(STUB_FAIL_named="1").returncode == 1


def test_latest_refuses_a_malformed_name(latest: Latest) -> None:
    assert latest.run("../x; rm").returncode == 1

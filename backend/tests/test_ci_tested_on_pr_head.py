"""May a push to main skip the backend shards? (#2429)

``.github/scripts/ci-tested-on-pr-head.sh`` decides whether a push to main
re-runs the 12 backend shards or rests on the merged PR's own CI run. Its one
acceptable failure direction is toward running the suite, so every refusal is
pinned here alongside the single case it answers yes to: a single-parent
squash commit whose tree is the PR head's, the head contained main, and the
head's green run published ``test-durations`` (the aggregator's proof that
the FULL suite ran — #1019 / #1020). These run the real script against a
throwaway origin and a stubbed ``gh`` that returns pre-filtered rows (the
real one applies ``--jq``; the stub ignores it).
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / ".github" / "scripts" / "ci-tested-on-pr-head.sh"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists() or shutil.which("git") is None,
    reason="ci-tested-on-pr-head.sh or git not present in this environment",
)

_GH_STUB = r"""#!/usr/bin/env bash
[ "$1" = api ] || { echo "unexpected gh call: $*" >&2; exit 1; }
ep="$2"
case "$ep" in
  */commits/*/pulls)
    [ -z "${STUB_FAIL_PULLS:-}" ] || { echo "HTTP 502" >&2; exit 1; }
    cat "$STUB_DIR/pulls" ;;
  */actions/workflows/ci.yml/runs*)
    cat "$STUB_DIR/runs" ;;
  */actions/runs/*/artifacts*)
    id="${ep#*/actions/runs/}"; id="${id%%/*}"
    cat "$STUB_DIR/artifacts-$id" 2>/dev/null || echo 0 ;;
  *) echo "unexpected endpoint: $ep" >&2; exit 1 ;;
esac
"""

PR = 7
RUN = 100


def _git(cwd: pathlib.Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


class Repo:
    """An origin whose main is ``base -> squash`` and whose ``refs/pull/7/head``
    is a PR head built on ``base`` with the same tree as ``squash``."""

    def __init__(self, tmp: pathlib.Path) -> None:
        self.tmp = tmp
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
        self.stub = tmp / "stub"
        self.stub.mkdir()
        self.bin = tmp / "bin"
        self.bin.mkdir()
        gh = self.bin / "gh"
        gh.write_text(_GH_STUB)
        gh.chmod(0o755)
        self.pulls([(PR, self.head, self.squash, "main", "2026-10-22T10:00:00Z")])
        self.runs([(RUN, self.head, "pull_request", "completed", "success")])
        self.artifacts(RUN, 1)

    def pulls(self, rows: list[tuple[object, ...]]) -> None:
        (self.stub / "pulls").write_text("".join("\t".join(map(str, r)) + "\n" for r in rows))

    def runs(self, rows: list[tuple[object, ...]]) -> None:
        (self.stub / "runs").write_text("".join("\t".join(map(str, r)) + "\n" for r in rows))

    def artifacts(self, run: int, count: int) -> None:
        (self.stub / f"artifacts-{run}").write_text(f"{count}\n")

    def run(self, **env: str) -> subprocess.CompletedProcess[str]:
        full = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "STUB_DIR": str(self.stub),
            "SHA": self.squash,
            "BEFORE": self.base,
            "REPO": "example/repo",
            **env,
        }
        return subprocess.run(
            ["bash", str(_SCRIPT)],
            cwd=self.work,
            env=full,
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
    assert result.stdout.strip() == f"pr={PR} head={repo.head} run={RUN}"


def test_a_narrowed_or_shard_skipped_pr_run_runs_the_suite(repo: Repo) -> None:
    """No ``test-durations`` artifact: the PR run selected a subset (#1020) or
    skipped the shards (#813), and this push run is what catches the rest."""
    repo.artifacts(RUN, 0)
    result = repo.run()
    assert result.returncode == 1
    assert "did not run the full backend suite" in result.stderr


def test_a_failed_pr_run_does_not_count(repo: Repo) -> None:
    repo.runs([(RUN, repo.head, "pull_request", "completed", "failure")])
    assert repo.run().returncode == 1


def test_a_run_on_another_head_does_not_count(repo: Repo) -> None:
    repo.runs([(RUN, repo.base, "pull_request", "completed", "success")])
    assert repo.run().returncode == 1


def test_a_push_run_on_the_head_does_not_count(repo: Repo) -> None:
    repo.runs([(RUN, repo.head, "push", "completed", "success")])
    assert repo.run().returncode == 1


def test_a_differing_tree_runs_the_suite(repo: Repo) -> None:
    o = repo.origin
    (o / "c.txt").write_text("c\n")
    _git(o, "add", "c.txt")
    _git(o, "commit", "-q", "--amend", "-m", f"change plus (#{PR})")
    squash = _git(o, "rev-parse", "HEAD")
    _git(repo.work, "fetch", "-q", "origin", "+main:refs/remotes/origin/main")
    repo.pulls([(PR, repo.head, squash, "main", "2026-10-22T10:00:00Z")])
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
    _git(repo.work, "fetch", "-q", "origin", "+main:refs/remotes/origin/main")
    repo.pulls([(PR, stale_head, squash, "main", "2026-10-22T10:00:00Z")])
    repo.runs([(RUN, stale_head, "pull_request", "completed", "success")])
    result = repo.run(SHA=squash, BEFORE=moved)
    assert result.returncode == 1
    assert "did not contain main" in result.stderr


def test_more_than_one_pushed_commit_runs_the_suite(repo: Repo) -> None:
    o = repo.origin
    _git(o, "commit", "-q", "--allow-empty", "-m", "direct push")
    top = _git(o, "rev-parse", "HEAD")
    _git(repo.work, "fetch", "-q", "origin", "+main:refs/remotes/origin/main")
    repo.pulls([(PR, repo.head, top, "main", "2026-10-22T10:00:00Z")])
    result = repo.run(SHA=top, BEFORE=repo.base)
    assert result.returncode == 1
    assert "more than one commit" in result.stderr


def test_a_merge_commit_runs_the_suite(repo: Repo) -> None:
    o = repo.origin
    _git(o, "merge", "-q", "--no-ff", "--no-edit", "pr")
    merge = _git(o, "rev-parse", "HEAD")
    _git(repo.work, "fetch", "-q", "origin", "+main:refs/remotes/origin/main")
    repo.pulls([(PR, repo.head, merge, "main", "2026-10-22T10:00:00Z")])
    result = repo.run(SHA=merge, BEFORE=repo.squash)
    assert result.returncode == 1
    assert "single-parent" in result.stderr


@pytest.mark.parametrize(
    "rows",
    [
        [],  # no PR recorded for the commit
        [(PR, "f" * 40, "e" * 40, "main", "2026-10-22T10:00:00Z")],  # another commit's PR
        [(PR, "HEAD", "SQUASH", "release", "2026-10-22T10:00:00Z")],  # not into main
        [(PR, "HEAD", "SQUASH", "main", "")],  # not merged
        [
            (PR, "HEAD", "SQUASH", "main", "2026-10-22T10:00:00Z"),
            (PR + 1, "HEAD", "SQUASH", "main", "2026-10-22T10:00:00Z"),
        ],  # ambiguous
    ],
)
def test_no_single_merged_pr_runs_the_suite(repo: Repo, rows: list[tuple[object, ...]]) -> None:
    sub = {"HEAD": repo.head, "SQUASH": repo.squash}
    repo.pulls([tuple(sub.get(str(c), c) for c in r) for r in rows])
    assert repo.run().returncode == 1


def test_a_head_the_pull_ref_disagrees_with_runs_the_suite(repo: Repo) -> None:
    repo.pulls([(PR, repo.base, repo.squash, "main", "2026-10-22T10:00:00Z")])
    result = repo.run()
    assert result.returncode == 1
    assert "head ref is not the head" in result.stderr


def test_an_api_failure_runs_the_suite(repo: Repo) -> None:
    assert repo.run(STUB_FAIL_PULLS="1").returncode == 1


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

"""Which tags a release decision may rank against (#1226).

``.github/scripts/release-tags.sh`` feeds release.yml's "previous release"
and "is this the newest release" decisions. Ranking against every tag in the
repository let one stray tag freeze ``:latest`` for good: a ``9.0.0`` pushed
on a feature branch is refused by release.yml's own gate, but it stays in
``git tag -l`` and outranks every real release after it. So a tag counts only
when it is on main AND has a published GitHub release. These run the real
script against a throwaway origin and a stubbed ``gh``.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / ".github" / "scripts" / "release-tags.sh"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists() or shutil.which("git") is None,
    reason="release-tags.sh or git not present in this environment",
)

_GH_STUB = """#!/usr/bin/env bash
[ "$1 $2" = "release list" ] || { echo "unexpected gh call: $*" >&2; exit 1; }
[ -z "${STUB_GH_FAIL:-}" ] || { echo "HTTP 502" >&2; exit 1; }
cat "$STUB_PUBLISHED"
"""


def _git(cwd: pathlib.Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture()
def work(tmp_path: pathlib.Path) -> pathlib.Path:
    """A clone of an origin whose main carries two tagged commits, plus a
    feature branch carrying a third."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    _git(origin, "commit", "-q", "--allow-empty", "-m", "one")
    _git(origin, "tag", "2026.09.04-1")
    _git(origin, "commit", "-q", "--allow-empty", "-m", "two")
    _git(origin, "tag", "2026.10.06-1")
    _git(origin, "checkout", "-q", "-b", "feature")
    _git(origin, "commit", "-q", "--allow-empty", "-m", "stray")
    _git(origin, "tag", "9.0.0")
    _git(origin, "checkout", "-q", "main")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    return work


def _run(
    work: pathlib.Path, published: list[str], **extra: str
) -> subprocess.CompletedProcess[str]:
    stub = work.parent / "bin"
    stub.mkdir(exist_ok=True)
    gh = stub / "gh"
    gh.write_text(_GH_STUB)
    gh.chmod(0o755)
    listing = work.parent / "published.txt"
    listing.write_text("".join(f"{tag}\n" for tag in published))
    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "STUB_PUBLISHED": str(listing),
        "GITHUB_REPOSITORY": "example/repo",
        **extra,
    }
    return subprocess.run(
        ["bash", str(_SCRIPT)], cwd=work, env=env, capture_output=True, text=True, check=False
    )


def test_only_released_tags_on_main_count(work: pathlib.Path) -> None:
    """9.0.0 is off main; 2026.10.06-1 is on main but was never released
    (its run failed a gate). Neither may outrank a real release."""
    result = _run(work, ["2026.09.04-1", "9.0.0", "nightly-2026.09.27"])
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["2026.09.04-1"]


def test_a_gh_failure_is_fatal_not_an_empty_list(work: pathlib.Path) -> None:
    """An empty list reads as "no earlier release", which makes every tag
    the newest: an outage must fail the release, not re-point :latest."""
    result = _run(work, ["2026.09.04-1"], STUB_GH_FAIL="1")
    assert result.returncode != 0
    assert result.stdout == ""

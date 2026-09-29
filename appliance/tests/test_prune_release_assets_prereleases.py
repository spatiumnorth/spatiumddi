"""The asset pruner keeps pre-releases out of the keep window (#1226).

Once release.yml publishes SemVer release candidates as GitHub
pre-releases (#1182), the pruner's keep window — the KEEP_VERSIONED newest
releases that keep their heavy ISO and slot image — would count them.
Cutting several candidates before a release would then push that many
FINAL releases out of the window early, and operators pinned to those lose
their install media. These run the real script against a stubbed ``gh`` in
dry-run mode and read what it would delete.

HOW TO RUN (from the repo root or this directory):
    python3 -m pytest appliance/tests/test_prune_release_assets_prereleases.py -v

Needs bash 4 (the script uses mapfile); no network, no gh CLI.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
PRUNER = REPO / "scripts" / "prune-release-assets.sh"

_GH_STUB = """#!/usr/bin/env bash
# gh release list … → the prepared TSV; gh release view TAG … → its assets.
case "$1 $2" in
  "release list") cat "$STUB_DIR/releases.tsv" ;;
  "release view") cat "$STUB_DIR/assets/$3" 2>/dev/null ;;
  *) echo "unexpected gh call: $*" >&2; exit 1 ;;
esac
"""


def _heavy(tag: str) -> list[str]:
    return [
        f"spatiumddi-appliance-{tag}-amd64.iso",
        f"spatiumddi-appliance-slot-{tag}-amd64.raw.xz",
    ]


def _run(tmp_path: Path, releases: list[tuple[str, bool, bool]], keep: int) -> set[tuple[str, str]]:
    """Run the pruner over ``releases`` (newest first: tag, is_latest,
    is_prerelease). Returns the (tag, asset) pairs it would delete."""
    stub = tmp_path / "bin"
    stub.mkdir()
    gh = stub / "gh"
    gh.write_text(_GH_STUB)
    gh.chmod(0o755)
    (tmp_path / "assets").mkdir()
    rows = []
    for tag, latest, pre in releases:
        rows.append(f"{tag}\t{str(latest).lower()}\t{str(pre).lower()}")
        sha = f"spatiumddi-appliance-slot-{tag}-amd64.sha256"
        (tmp_path / "assets" / tag).write_text("\n".join(_heavy(tag) + [sha]) + "\n")
    (tmp_path / "releases.tsv").write_text("\n".join(rows) + "\n")

    env = {
        **os.environ,
        "PATH": f"{stub}{os.pathsep}{os.environ['PATH']}",
        "STUB_DIR": str(tmp_path),
        "REPO": "example/repo",
        "DRY_RUN": "true",
        "KEEP_VERSIONED": str(keep),
        "PROTECT_TAG": "",
    }
    result = subprocess.run(
        ["bash", str(PRUNER)], env=env, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return set(re.findall(r"would delete (\S+) :: (\S+)", result.stdout))


def test_release_candidates_do_not_push_final_releases_out_of_the_window(
    tmp_path: Path,
) -> None:
    deleted = _run(
        tmp_path,
        [
            ("1.0.0", True, False),
            ("1.0.0-rc.2", False, True),
            ("1.0.0-rc.1", False, True),
            ("2026.11.03-1", False, False),
            ("2026.10.20-1", False, False),
        ],
        keep=2,
    )
    # The bridge is the second-newest FINAL release: inside a window of 2.
    # Counting the two candidates would have made it the fourth.
    for asset in _heavy("2026.11.03-1"):
        assert ("2026.11.03-1", asset) not in deleted
    # The third final release is outside it.
    for asset in _heavy("2026.10.20-1"):
        assert ("2026.10.20-1", asset) in deleted


def test_a_superseded_release_candidate_loses_its_heavy_assets(tmp_path: Path) -> None:
    deleted = _run(
        tmp_path,
        [("1.0.0", True, False), ("1.0.0-rc.1", False, True)],
        keep=15,
    )
    for asset in _heavy("1.0.0-rc.1"):
        assert ("1.0.0-rc.1", asset) in deleted
    # Provenance is always kept.
    assert ("1.0.0-rc.1", "spatiumddi-appliance-slot-1.0.0-rc.1-amd64.sha256") not in deleted


def test_a_candidate_newer_than_every_final_release_keeps_its_assets(tmp_path: Path) -> None:
    """The candidate being tested right now must stay installable."""
    deleted = _run(
        tmp_path,
        [("1.0.0-rc.1", False, True), ("2026.11.03-1", True, False)],
        keep=15,
    )
    assert not {pair for pair in deleted if pair[0] == "1.0.0-rc.1"}


@pytest.mark.parametrize("keep", [1, 2])
def test_final_releases_still_age_out_by_count(tmp_path: Path, keep: int) -> None:
    """The window itself is unchanged for final releases."""
    tags = ["2026.11.03-1", "2026.10.20-1", "2026.10.06-1"]
    deleted = _run(
        tmp_path,
        [(tag, i == 0, False) for i, tag in enumerate(tags)],
        keep=keep,
    )
    for i, tag in enumerate(tags):
        beyond = i >= keep
        for asset in _heavy(tag):
            assert ((tag, asset) in deleted) is beyond, (tag, asset)

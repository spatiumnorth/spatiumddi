"""The release workflow's tag decisions (#1226, #1182).

``scripts/release_version.py`` decides, for a pushed tag, whether it may be
published at all, which release its notes and compare link start from, and
whether it becomes the release everything points at (GitHub's latest,
``:latest``, the stable download URLs). The workflow used to decide all three
in shell, and each shell answer was wrong across the switch to SemVer:
``sort -V`` ranks every ``2026.*`` above every ``1.*``, and the CHANGELOG
lookup matched by prefix. These pin the answers, including the orderings a
string or ``sort -V`` comparison gets backwards.
"""

from __future__ import annotations

import importlib.util
import pathlib
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "release_version.py"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout. Same
# convention as test_lint_versions.py.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="release tag helper not present in this checkout",
)

# The tags the repo will carry around the switch: CalVer releases, the
# bridge, release candidates, and nightly tags that must be ignored.
_TAGS = [
    "2026.08.22-1",
    "2026.09.04-1",
    "2026.11.03-1",  # the bridge
    "nightly-2026.11.10",
    "1.0.0-rc.1",
    "1.0.0-rc.2",
]


@pytest.fixture(scope="module")
def rv() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("release_version", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tag(rv: types.ModuleType, name: str):
    tag = rv.parse_tag(name)
    assert tag is not None, name
    return tag


# ── check: which tags may be published ───────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "prerelease"),
    [
        ("2026.09.04-1", False),
        ("1.0.0", False),
        ("1.2.10", False),
        ("1.0.0-rc.1", True),
        ("1.0.0-beta.2", True),
        ("1.0.0-rc.0", True),
        ("1.0.0-0a.1", True),  # alphanumeric may start with a digit
    ],
)
def test_release_tags_are_accepted(rv: types.ModuleType, name: str, prerelease: bool) -> None:
    assert _tag(rv, name).prerelease is prerelease


@pytest.mark.parametrize(
    "name",
    [
        "2026.09.04",  # a CalVer tag always carries its -N
        "2026.9.4",  # nor is it SemVer: that major would outrank every release
        "1.01.0",  # SemVer forbids leading zeros
        "1.0.0-rc.01",  # ...in numeric pre-release identifiers too: a second rc.1
        "1.0.0-",
        "1.0.0-rc..1",
        "2026.13.40-1",  # not a date
        "0.1.0",  # the packaging placeholder; SemVer releases start at 1.0.0
        "0.0.0-nightly-20260928",
        "nightly-2026.09.28",
        "1.0.0+abc123",  # '+' is not legal in an image tag
        "v1.0.0",
        "1.0",
        "",
    ],
)
def test_other_tags_are_refused(rv: types.ModuleType, name: str) -> None:
    assert rv.parse_tag(name) is None
    assert rv.main(["check", name]) == 1


def test_check_prints_the_prerelease_output(
    rv: types.ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    assert rv.main(["check", "1.0.0-rc.1"]) == 0
    assert capsys.readouterr().out.strip() == "prerelease=true"


# ── previous: where the notes and compare link start ─────────────────────────


def test_a_final_release_starts_from_the_previous_final_release(rv: types.ModuleType) -> None:
    """1.0.0's notes cover everything since the bridge, not only the delta
    from its last release candidate. ``sort -V`` would have picked
    2026.11.03-1 as "newer" than 1.0.0 and returned something else again."""
    assert rv.previous(_tag(rv, "1.0.0"), _TAGS + ["1.0.0"]).name == "2026.11.03-1"


def test_a_release_candidate_starts_from_whatever_came_before_it(rv: types.ModuleType) -> None:
    assert rv.previous(_tag(rv, "1.0.0-rc.2"), _TAGS).name == "1.0.0-rc.1"
    assert rv.previous(_tag(rv, "1.0.0-rc.1"), _TAGS).name == "2026.11.03-1"


def test_semver_components_compare_numerically(rv: types.ModuleType) -> None:
    tags = ["1.0.9", "1.0.10", "1.0.2"]
    assert rv.previous(_tag(rv, "1.0.11"), tags).name == "1.0.10"


def test_calver_releases_keep_their_order(rv: types.ModuleType) -> None:
    assert rv.previous(_tag(rv, "2026.11.03-1"), _TAGS).name == "2026.09.04-1"


def test_the_first_release_has_no_previous(rv: types.ModuleType) -> None:
    assert rv.previous(_tag(rv, "2026.08.22-1"), _TAGS) is None


# ── is-newest: who becomes latest ────────────────────────────────────────────


def test_the_first_semver_release_becomes_latest(rv: types.ModuleType) -> None:
    assert rv.is_newest(_tag(rv, "1.0.0"), _TAGS + ["1.0.0"]) is True


def test_a_release_candidate_never_becomes_latest(rv: types.ModuleType) -> None:
    """It would move :latest and the stable ISO URL onto a candidate."""
    assert rv.is_newest(_tag(rv, "1.0.0-rc.2"), _TAGS) is False


def test_a_calver_tag_after_1_0_0_does_not_become_latest(rv: types.ModuleType) -> None:
    tags = _TAGS + ["1.0.0"]
    assert rv.is_newest(_tag(rv, "2026.11.20-1"), tags + ["2026.11.20-1"]) is False


def test_a_patch_on_an_older_line_does_not_become_latest(rv: types.ModuleType) -> None:
    tags = ["1.0.0", "1.1.0", "1.0.1"]
    assert rv.is_newest(_tag(rv, "1.0.1"), tags) is False
    assert rv.is_newest(_tag(rv, "1.1.1"), tags + ["1.1.1"]) is True


def test_a_newer_release_candidate_does_not_block_latest(rv: types.ModuleType) -> None:
    """1.1.0-rc.1 exists; 1.0.1 is still the newest FINAL release."""
    tags = ["1.0.0", "1.1.0-rc.1", "1.0.1"]
    assert rv.is_newest(_tag(rv, "1.0.1"), tags) is True


# ── notes: the CHANGELOG section ─────────────────────────────────────────────

_CHANGELOG = """\
# Changelog

## Unreleased

- pending

## 1.0.10 — 2027-02-01

- ten

## 1.0.1 — 2026-12-01

- one

## 2026.09.04-1 — 2026-09-04

- calver
"""


def test_the_heading_is_matched_exactly_not_by_prefix(rv: types.ModuleType) -> None:
    """A prefix match finds "## 1.0.10" first when asked for 1.0.1."""
    assert rv.changelog_section("1.0.1", _CHANGELOG).strip() == "- one"
    assert rv.changelog_section("1.0.10", _CHANGELOG).strip() == "- ten"


def test_a_calver_section_is_found(rv: types.ModuleType) -> None:
    assert rv.changelog_section("2026.09.04-1", _CHANGELOG).strip() == "- calver"


def test_a_missing_section_is_empty(rv: types.ModuleType) -> None:
    """Empty, so the workflow falls back to a commit shortlog."""
    assert rv.changelog_section("1.0.2", _CHANGELOG) == ""
    assert rv.changelog_section("1.0", _CHANGELOG) == ""


# ── the CLI the workflow calls ───────────────────────────────────────────────


def test_previous_and_is_newest_read_tags_from_stdin(
    rv: types.ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_TAGS + ["1.0.0"]) + "\n"))
    assert rv.main(["previous", "1.0.0"]) == 0
    assert capsys.readouterr().out.strip() == "2026.11.03-1"

    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(_TAGS + ["1.0.0"]) + "\n"))
    assert rv.main(["is-newest", "1.0.0"]) == 0
    assert capsys.readouterr().out.strip() == "true"


def test_notes_reads_the_file(
    rv: types.ModuleType, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "CHANGELOG.md"
    path.write_text(_CHANGELOG)
    assert rv.main(["notes", "1.0.1", str(path)]) == 0
    assert capsys.readouterr().out.strip() == "- one"


# ── chart-version: what Helm is told the chart is ────────────────────────────


@pytest.mark.parametrize(
    ("name", "chart"),
    [
        # Helm rejects leading zeros, so a CalVer tag drops them.
        ("2026.04.20-1", "2026.4.20-1"),
        ("2026.09.04-1", "2026.9.4-1"),
        ("2026.10.10-12", "2026.10.10-12"),
        ("2026.11.03-01", "2026.11.3-1"),
        # A SemVer tag is already a valid chart version.
        ("1.0.0", "1.0.0"),
        ("1.0.0-rc.1", "1.0.0-rc.1"),
        ("1.10.0", "1.10.0"),
        ("2.0.10", "2.0.10"),
    ],
)
def test_chart_version(rv: types.ModuleType, name: str, chart: str) -> None:
    assert rv.chart_version(_tag(rv, name)) == chart


def test_every_calver_chart_is_a_prerelease_and_semver_charts_are_not(
    rv: types.ModuleType,
) -> None:
    """Why the manual helm command must pass --version (#1182): Helm's
    unversioned resolution skips pre-releases, and a CalVer chart always is
    one. 1.0.0 is the first chart it would resolve on its own."""
    assert "-" in rv.chart_version(_tag(rv, "2026.09.04-1"))
    assert "-" not in rv.chart_version(_tag(rv, "1.0.0"))


def test_chart_version_subcommand(rv: types.ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    assert rv.main(["chart-version", "2026.04.20-1"]) == 0
    assert capsys.readouterr().out.strip() == "2026.4.20-1"
    assert rv.main(["chart-version", "nightly-2026.09.28"]) == 1

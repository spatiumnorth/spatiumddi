"""``scripts/changelog_assemble.py`` — CHANGELOG fragments for the merge queue (#2431).

PRs add ``changelog.d/<issue>-<slug>.md`` instead of editing CHANGELOG.md, so
two queued PRs never conflict on the same ``## Unreleased`` spot. Release prep
folds the fragments in, and release.yml refuses a tag that still carries one
(``--pending``). What matters here: entries land under the right section of
``## Unreleased`` and nowhere else, earlier releases are untouched, a bad
fragment is refused before anything is written, and nothing is deleted unless
the fold was written.
"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "changelog_assemble.py"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout.
pytestmark = pytest.mark.skipif(not _SCRIPT.exists(), reason="scripts/ not in this checkout")


def _load():
    spec = importlib.util.spec_from_file_location("changelog_assemble", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ca = _load() if _SCRIPT.exists() else None

CHANGELOG = """\
# Changelog

Preamble.

---

## Unreleased

### Added

- **Existing added (#1).** Body
  wrapped.

### Fixed

- **Existing fix (#2).** Body.

### Migrations

- `aaaaaaaaaaaa` — #3, existing migration.

## 1.0.0 — 2026-10-21

### Fixed

- **Released fix (#0).** Body.
"""


def _unreleased(text: str) -> str:
    start = text.index("## Unreleased")
    return text[start : text.index("## 1.0.0")]


def test_entries_append_to_their_section_in_unreleased() -> None:
    frag = "### Fixed\n\n- **New fix (#10).** Body\n  wrapped.\n"
    out = ca.assemble(CHANGELOG, [("10-new-fix.md", frag)])
    unrel = _unreleased(out)
    assert (
        "### Fixed\n\n- **Existing fix (#2).** Body.\n\n"
        "- **New fix (#10).** Body\n  wrapped.\n\n### Migrations"
    ) in unrel
    # Earlier releases and the preamble are byte-identical.
    assert out[out.index("## 1.0.0") :] == CHANGELOG[CHANGELOG.index("## 1.0.0") :]
    assert out[: out.index("## Unreleased")] == CHANGELOG[: CHANGELOG.index("## Unreleased")]


def test_one_fragment_may_fill_several_sections() -> None:
    frag = (
        "### Fixed\n\n- **Fix (#11).** Body.\n\n"
        "### Migrations\n\n- `bbbbbbbbbbbb` — #11, new migration.\n"
    )
    unrel = _unreleased(ca.assemble(CHANGELOG, [("11-x.md", frag)]))
    assert "- **Existing fix (#2).** Body.\n\n- **Fix (#11).** Body.\n\n### Migrations" in unrel
    assert unrel.rstrip().endswith(
        "- `aaaaaaaaaaaa` — #3, existing migration.\n\n- `bbbbbbbbbbbb` — #11, new migration."
    )


def test_a_missing_section_is_created_in_canonical_order() -> None:
    frag = "### Security\n\n- **Sec (#12).** Body.\n"
    unrel = _unreleased(ca.assemble(CHANGELOG, [("12-sec.md", frag)]))
    fixed, sec, mig = (unrel.index(h) for h in ("### Fixed", "### Security", "### Migrations"))
    assert fixed < sec < mig
    assert "### Security\n\n- **Sec (#12).** Body.\n\n### Migrations" in unrel

    frag = "### Changed\n\n- **Chg (#13).** Body.\n"
    unrel = _unreleased(ca.assemble(CHANGELOG, [("13-chg.md", frag)]))
    assert unrel.index("### Added") < unrel.index("### Changed") < unrel.index("### Fixed")


def test_a_changelog_without_unreleased_gets_one_above_the_first_release() -> None:
    text = CHANGELOG.replace(_unreleased(CHANGELOG), "")
    out = ca.assemble(text, [("14-x.md", "### Fixed\n\n- **F (#14).** B.\n")])
    assert out.index("## Unreleased") < out.index("## 1.0.0")
    assert "## Unreleased\n\n### Fixed\n\n- **F (#14).** B.\n\n## 1.0.0" in out


def test_fragments_fold_in_issue_number_order(tmp_path: pathlib.Path) -> None:
    d = tmp_path / "changelog.d"
    d.mkdir()
    for name in ("900-b.md", "1000-a.md", "95-c.md", "README.md", ".gitkeep"):
        (d / name).write_text("### Fixed\n\n- x\n")
    assert [p.name for p in ca.fragment_paths(d)] == ["95-c.md", "900-b.md", "1000-a.md"]


@pytest.mark.parametrize(
    ("name", "text", "why"),
    [
        ("15-x.md", "- **No heading (#15).**\n", "before the first"),
        ("15-x.md", "### Fixes\n\n- x\n", "unknown section"),
        ("15-x.md", "### Fixed\n\n", "no entries"),
        ("15-x.md", "", "no '### <Section>' heading"),
        ("15-x.md", "### Fixed\n\n- a\n\n### Fixed\n\n- b\n", "appears twice"),
        ("15-x.md", "## 1.0.1\n\n### Fixed\n\n- a\n", "only '### <Section>'"),
        ("15-x.md", "### Fixed\n\n- **A (x).** see\n  #1234 for why\n", "must not start with"),
        ("Fix-thing.md", "### Fixed\n\n- a\n", "name must be"),
        ("15_x.md", "### Fixed\n\n- a\n", "name must be"),
        ("15-x.txt", "### Fixed\n\n- a\n", "name must be"),
    ],
)
def test_a_bad_fragment_is_refused(name: str, text: str, why: str) -> None:
    with pytest.raises(ca.FragmentError) as err:
        ca.parse_fragment(name, text)
    assert why in str(err.value)


def test_one_bad_fragment_refuses_the_whole_fold() -> None:
    with pytest.raises(ca.FragmentError) as err:
        ca.assemble(
            CHANGELOG,
            [("16-ok.md", "### Fixed\n\n- ok\n"), ("17-bad.md", "### Nope\n\n- x\n")],
        )
    assert "17-bad.md" in str(err.value)
    assert "16-ok.md" not in str(err.value)


def _run(tmp: pathlib.Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--changelog",
            str(tmp / "CHANGELOG.md"),
            "--dir",
            str(tmp / "changelog.d"),
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture()
def tree(tmp_path: pathlib.Path) -> pathlib.Path:
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG)
    d = tmp_path / "changelog.d"
    d.mkdir()
    (d / "README.md").write_text("# not a fragment\n\n### Fixed\n")
    (d / "20-a.md").write_text("### Fixed\n\n- **A (#20).** Body.\n")
    (d / "21-b.md").write_text("### Added\n\n- **B (#21).** Body.\n")
    return tmp_path


def test_cli_folds_then_deletes_only_the_fragments(tree: pathlib.Path) -> None:
    result = _run(tree)
    assert result.returncode == 0, result.stderr
    text = (tree / "CHANGELOG.md").read_text()
    assert "- **A (#20).** Body." in _unreleased(text)
    assert "- **B (#21).** Body." in _unreleased(text)
    assert sorted(p.name for p in (tree / "changelog.d").iterdir()) == ["README.md"]
    # A second run is a no-op.
    again = _run(tree)
    assert again.returncode == 0
    assert (tree / "CHANGELOG.md").read_text() == text


def test_cli_dry_run_changes_nothing(tree: pathlib.Path) -> None:
    result = _run(tree, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "- **A (#20).** Body." in result.stdout
    assert (tree / "CHANGELOG.md").read_text() == CHANGELOG
    assert (tree / "changelog.d" / "20-a.md").exists()


def test_cli_a_bad_fragment_writes_and_deletes_nothing(tree: pathlib.Path) -> None:
    (tree / "changelog.d" / "22-bad.md").write_text("- no heading\n")
    result = _run(tree)
    assert result.returncode == 1
    assert "22-bad.md" in result.stderr
    assert (tree / "CHANGELOG.md").read_text() == CHANGELOG
    assert (tree / "changelog.d" / "20-a.md").exists()


def test_cli_check_validates_without_writing(tree: pathlib.Path) -> None:
    assert _run(tree, "--check").returncode == 0
    (tree / "changelog.d" / "23-bad.md").write_text("### Fixd\n\n- x\n")
    result = _run(tree, "--check")
    assert result.returncode == 1
    assert "23-bad.md" in result.stderr
    assert (tree / "CHANGELOG.md").read_text() == CHANGELOG


def test_cli_pending_is_release_yml_gate(tree: pathlib.Path) -> None:
    """release.yml refuses a tag whose tree still carries a fragment."""
    result = _run(tree, "--pending")
    assert result.returncode == 1
    assert "20-a.md" in result.stderr
    for p in (tree / "changelog.d").glob("2*.md"):
        p.unlink()
    assert _run(tree, "--pending").returncode == 0


def test_cli_pending_with_no_directory_passes(tmp_path: pathlib.Path) -> None:
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG)
    assert _run(tmp_path, "--pending").returncode == 0

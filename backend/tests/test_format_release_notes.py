"""The release-body formatter (``scripts/format_release_notes.py``).

release.yml pipes the version's CHANGELOG section through it before it
creates the GitHub release. Two ways it can break a release are pinned here:

* GitHub refuses a release body over 125,000 characters, and the release is
  created only after every image is built and scanned. A long CHANGELOG
  section must come out condensed under the limit, not fail the publish.
* A bullet's wrapped line that starts with an issue number (``  #1140).**``)
  is not a heading. Taking it for one split the bullet mid-sentence.
"""

from __future__ import annotations

import importlib.util
import pathlib
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "format_release_notes.py"

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout. Same
# convention as test_release_version_script.py.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(),
    reason="release notes formatter not present in this checkout",
)


@pytest.fixture(scope="module")
def fmt() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("format_release_notes", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bullet(n: int) -> str:
    """A CHANGELOG bullet: bold headline, then ~1 KB of wrapped detail."""
    detail = "\n".join(f"  detail line {i} for entry {n} goes on for a while." for i in range(20))
    return f"- **Entry {n} was fixed (#{1000 + n}).** It\n{detail}\n"


def _section(entries: int) -> str:
    bullets = "\n".join(_bullet(n) for n in range(entries))
    return (
        "# ⚠️ Please don't roll back to 2026.09.04-1\n"
        "\n"
        "> **Do not go back.** The schema moved\n"
        "> on and the old release cannot run on it.\n"
        "\n"
        "**The summary.** It wraps\n"
        "across two lines.\n"
        "\n"
        "### Fixed\n"
        "\n"
        f"{bullets}\n"
        "### Migrations\n"
        "\n"
        "- `abcdef012345` — #1: a table, with a long\n"
        "  description that must survive condensing.\n"
    )


# ── headings ──────────────────────────────────────────────────────────────────


def test_a_wrapped_line_starting_with_an_issue_number_is_not_a_heading(fmt):
    out = fmt.transform(
        "### Fixed\n\n- **Relayed DHCPv6 never reached Kea (#1139,\n  #1140).** Two faults.\n"
    )
    assert "- **Relayed DHCPv6 never reached Kea (#1139, #1140).** Two faults." in out
    assert "\n#1140" not in out


def test_a_banner_above_the_summary_keeps_the_highlights_heading(fmt):
    out = fmt.transform(_section(1))
    lines = out.splitlines()
    assert lines[0] == "# ⚠️ Please don't roll back to 2026.09.04-1"
    # The banner's blockquote stays one quoted paragraph.
    assert (
        "> **Do not go back.** The schema moved on and the old release cannot run on it." in lines
    )
    highlights = lines.index("### 🚀 Highlights")
    assert lines[highlights + 2] == "**The summary.** It wraps across two lines."


# ── size limit ────────────────────────────────────────────────────────────────


def test_notes_under_the_limit_are_left_alone(fmt):
    notes = fmt.transform(_section(3))
    assert fmt.condense(notes, fmt.DEFAULT_MAX_CHARS) == notes


def test_notes_over_the_limit_are_condensed_to_headlines(fmt):
    notes = fmt.transform(_section(200))
    assert len(notes) > fmt.DEFAULT_MAX_CHARS
    url = "https://github.com/o/r/blob/2026.10.02-1/CHANGELOG.md"
    out = fmt.condense(notes, fmt.DEFAULT_MAX_CHARS, url)

    assert len(out) <= fmt.DEFAULT_MAX_CHARS
    # The banner and the summary are kept as they are.
    assert out.startswith("# ⚠️ Please don't roll back to 2026.09.04-1\n")
    assert "**The summary.** It wraps across two lines." in out
    # Every entry survives as its headline, detail dropped.
    assert "- **Entry 0 was fixed (#1000).**" in out
    assert "- **Entry 199 was fixed (#1199).**" in out
    assert "detail line" not in out
    # Migrations are kept whole.
    assert "a table, with a long description that must survive condensing." in out
    # And the reader is told where the rest is.
    assert f"[CHANGELOG.md]({url})" in out
    assert out.index("These notes are condensed") < out.index("### 🐛 Fixed")


def test_condensed_notes_that_still_do_not_fit_are_cut_under_the_limit(fmt):
    notes = fmt.transform(_section(200))
    out = fmt.condense(notes, 2_000)
    assert len(out) <= 2_000
    assert out.rstrip().endswith("The full text is in CHANGELOG.md at this tag.")


def test_a_bullet_with_no_bold_headline_keeps_its_first_sentence(fmt):
    assert (
        fmt._headline("- Choosing the CredSSP transport failed on every call. It never worked.")
        == "- Choosing the CredSSP transport failed on every call."
    )


def test_main_condenses_only_over_max_chars(fmt, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(_section(200)))
    fmt.main(["--max-chars", "0"])
    assert "detail line" in capsys.readouterr().out

    monkeypatch.setattr("sys.stdin", io.StringIO(_section(200)))
    fmt.main([])
    captured = capsys.readouterr()
    assert "detail line" not in captured.out
    assert len(captured.out) <= fmt.DEFAULT_MAX_CHARS
    assert "release notes condensed" in captured.err

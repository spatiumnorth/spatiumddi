#!/usr/bin/env python3
"""Fold ``changelog.d/`` fragments into ``CHANGELOG.md`` (merge-queue prep).

Every PR used to insert its entry at the top of ``### Fixed`` under
``## Unreleased``, so every pair of open PRs conflicted on that one spot. A
merge queue removes an entry that conflicts with the one ahead of it, so with
that convention the queue would only ever bounce PRs. Each PR now adds ONE
new file under ``changelog.d/`` instead, which never conflicts, and release
prep runs this script to fold the fragments into ``## Unreleased`` before the
section is renamed to the release version. ``release.yml`` publishes the
notes from ``CHANGELOG.md`` and refuses a tag whose tree still carries
fragments (``--pending``), so a forgotten assembly cannot ship notes with
entries missing.

Fragment format (``changelog.d/<issue>-<slug>.md``)::

    ### Fixed

    - **One-line summary (#1234).** Hard-wrapped body, as in
      CHANGELOG.md itself.

    ### Migrations

    - `abcdef012345` — #1234, what the migration does.

One or more ``### <Section>`` headings, each followed by its entries, exactly
as they would read under ``## Unreleased``. Sections are matched by name to
the ones ``CHANGELOG.md`` uses; a section ``## Unreleased`` does not have yet
is created in the canonical order. Folded entries go to the TOP of their
section, newest issue first, above what is already there: CHANGELOG.md lists
newest first. Lines inside a ``` fence are content, never headings.

The fold refuses, writing nothing, when ``CHANGELOG.md`` has no
``## Unreleased`` (a fold after the section was renamed would put the entries
into a release they did not ship in), or when ``changelog.d/`` holds anything
but ``README.md`` and top-level ``<issue>-<slug>.md`` files — a subdirectory,
a dotfile or a misnamed file would otherwise be silently left out of the
notes. ``--check`` and ``--pending`` refuse the same things.

Usage::

    scripts/changelog_assemble.py            # fold, then delete the fragments
    scripts/changelog_assemble.py --dry-run  # print the result, change nothing
    scripts/changelog_assemble.py --check    # validate fragments only (CI)
    scripts/changelog_assemble.py --pending  # exit 1 if any fragment exists

Pinned by ``backend/tests/test_changelog_assemble.py``. Stdlib only, so it
runs on a bare runner and the host.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# The section headings fragments may use, in the order a missing one is
# created under ``## Unreleased``. Matches the headings CHANGELOG.md has used
# and the ones scripts/format_release_notes.py decorates.
SECTIONS: tuple[str, ...] = (
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Migrations",
    "Breaking",
)

UNRELEASED = "## Unreleased"

# ``<issue>-<slug>.md``: the issue number first so the fold order follows the
# issue tracker, then a short slug so two PRs for one issue get two files.
FRAGMENT_NAME = re.compile(r"^[0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")

# The one file in changelog.d/ that is not a fragment.
README = "README.md"

_HEADING = re.compile(r"^###\s+(.+?)\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")


class FragmentError(ValueError):
    """A fragment, or the fragment directory, that cannot be folded as is."""


def _issue(p: pathlib.Path) -> int:
    m = re.match(r"^([0-9]+)-", p.name)
    return int(m.group(1)) if m else -1


def scan(directory: pathlib.Path) -> tuple[list[pathlib.Path], list[str]]:
    """``(fragments, problems)`` for DIRECTORY.

    Fragments come newest issue first (then by name). A problem is anything
    in the directory that is neither README.md nor a top-level
    ``<issue>-<slug>.md`` file: it would be skipped by the fold, so its
    entries would silently miss the release notes.
    """
    if not directory.exists():
        return [], []
    if not directory.is_dir():
        return [], [f"{directory}: not a directory"]
    found: list[pathlib.Path] = []
    problems: list[str] = []
    for p in sorted(directory.iterdir()):
        if p.name == README and p.is_file():
            continue
        if p.is_dir():
            problems.append(
                f"{p.name}/: subdirectories are not folded; put fragments at the top level"
            )
        elif not p.is_file():
            problems.append(f"{p.name}: not a regular file")
        elif not FRAGMENT_NAME.match(p.name):
            problems.append(
                f"{p.name}: name must be <issue>-<slug>.md (lower-case, digits and hyphens), "
                "e.g. 1234-dhcp-lease-sweep.md; nothing else may live in changelog.d/"
            )
        else:
            found.append(p)
    found.sort(key=lambda p: (-_issue(p), p.name))
    return found, problems


def fragment_paths(directory: pathlib.Path) -> list[pathlib.Path]:
    """Every fragment in DIRECTORY, newest issue first; FragmentError on a stray."""
    found, problems = scan(directory)
    if problems:
        raise FragmentError("\n".join(problems))
    return found


def parse_fragment(name: str, text: str) -> dict[str, list[str]]:
    """Split a fragment into ``{section: lines}``; raise FragmentError.

    Each section's lines are trimmed of leading and trailing blank lines.
    """
    errors: list[str] = []
    if not FRAGMENT_NAME.match(name):
        errors.append(
            f"{name}: name must be <issue>-<slug>.md (lower-case, digits and hyphens), "
            "e.g. 1234-dhcp-lease-sweep.md"
        )
    out: dict[str, list[str]] = {}
    current: str | None = None
    fenced = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if _FENCE.match(line):
            fenced = not fenced
        elif not fenced:
            m = _HEADING.match(line)
            if m:
                section = m.group(1)
                if section not in SECTIONS:
                    errors.append(
                        f"{name}:{lineno}: unknown section '### {section}' "
                        f"(use one of: {', '.join(SECTIONS)})"
                    )
                    current = None
                    continue
                if section in out:
                    errors.append(f"{name}:{lineno}: '### {section}' appears twice")
                current = section
                out.setdefault(section, [])
                continue
            if line.startswith("#"):
                # A column-0 hash is a heading to the release-notes formatter:
                # ``## x`` would open a release inside Unreleased, and a
                # wrapped line starting "#1234" would split its bullet.
                errors.append(
                    f"{name}:{lineno}: only '### <Section>' headings may start a line with '#' "
                    "(indent a wrapped line, or re-wrap it)"
                )
                continue
        if current is None:
            if line.strip():
                errors.append(f"{name}:{lineno}: text before the first '### <Section>' heading")
            continue
        out[current].append(line)
    if fenced:
        errors.append(f"{name}: a ``` fence is never closed")
    for section, lines in out.items():
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        if not lines:
            errors.append(f"{name}: '### {section}' has no entries")
    if not out and not errors:
        errors.append(f"{name}: no '### <Section>' heading (use one of: {', '.join(SECTIONS)})")
    if errors:
        raise FragmentError("\n".join(errors))
    return out


def _unreleased_bounds(lines: list[str]) -> tuple[int, int]:
    """Index of ``## Unreleased`` and of the next ``## `` heading (or EOF).

    Refuses a changelog without one: by then the section has been renamed to
    a release, and folding would file the entries under a release they are
    not part of.
    """
    try:
        start = lines.index(UNRELEASED)
    except ValueError:
        raise FragmentError(
            f"CHANGELOG.md has no '{UNRELEASED}' section. Fold the fragments before renaming "
            f"it to the release version, or add an empty '{UNRELEASED}' above the newest "
            "release if they belong to the next one."
        ) from None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return start, end


def _section_top(lines: list[str], start: int, end: int, section: str) -> int:
    """Index of SECTION's first entry under Unreleased, creating it if absent.

    For a new section, the index just after its heading's blank line.
    """
    heading = f"### {section}"
    found = next((i for i in range(start + 1, end) if lines[i] == heading), None)
    if found is None:
        # Before the first existing section that sorts after this one, or at
        # the end of Unreleased.
        rank = SECTIONS.index(section)
        later = {f"### {s}" for s in SECTIONS[rank + 1 :]}
        at = next((i for i in range(start + 1, end) if lines[i] in later), end)
        while at > start + 1 and not lines[at - 1].strip():
            at -= 1
        lines[at:at] = ["", heading, ""]
        return at + 3
    top = found + 1
    while top < end and not lines[top].strip():
        top += 1
    return top


def assemble(changelog: str, fragments: list[tuple[str, str]]) -> str:
    """Return CHANGELOG text with every fragment folded into Unreleased.

    FRAGMENTS is ``[(name, text), ...]`` newest first (``fragment_paths``
    order). Each section receives its fragments' entries at the top, in that
    order, above what it already holds. Raises FragmentError listing every
    problem before changing anything.
    """
    parsed: list[dict[str, list[str]]] = []
    errors: list[str] = []
    for name, text in fragments:
        try:
            parsed.append(parse_fragment(name, text))
        except FragmentError as exc:
            errors.append(str(exc))
    if errors:
        raise FragmentError("\n".join(errors))

    lines = changelog.splitlines()
    if not parsed:
        return changelog
    _unreleased_bounds(lines)
    for section in SECTIONS:
        bodies = [frag[section] for frag in parsed if frag.get(section)]
        if not bodies:
            continue
        block: list[str] = []
        for body in bodies:
            block += [*body, ""]
        start, end = _unreleased_bounds(lines)
        at = _section_top(lines, start, end, section)
        # The block ends with a blank line; drop it when one already follows.
        if at < len(lines) and not lines[at].strip():
            block.pop()
        lines[at:at] = block
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--changelog", type=pathlib.Path, default=root / "CHANGELOG.md")
    ap.add_argument("--dir", type=pathlib.Path, default=root / "changelog.d")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="validate the fragments only")
    mode.add_argument(
        "--pending", action="store_true", help="exit 1 if any fragment has not been folded"
    )
    mode.add_argument(
        "--dry-run", action="store_true", help="print the assembled CHANGELOG, change nothing"
    )
    args = ap.parse_args(argv)

    paths, problems = scan(args.dir)
    for problem in problems:
        print(problem, file=sys.stderr)

    if args.pending:
        if paths:
            print(
                f"{len(paths)} changelog fragment(s) not folded into {args.changelog.name}: "
                + ", ".join(p.name for p in paths),
                file=sys.stderr,
            )
        if paths or problems:
            return 1
        print("no pending changelog fragments")
        return 0

    fragments = [(p.name, p.read_text(encoding="utf-8")) for p in paths]
    if args.check:
        bad = len(problems)
        for name, text in fragments:
            try:
                parse_fragment(name, text)
            except FragmentError as exc:
                bad += 1
                print(exc, file=sys.stderr)
        if bad:
            print(f"{bad} problem(s) in changelog.d/", file=sys.stderr)
            return 1
        print(f"{len(fragments)} changelog fragment(s) OK")
        return 0

    if problems:
        print("refusing to fold: changelog.d/ holds files the fold would skip", file=sys.stderr)
        return 1
    try:
        result = assemble(args.changelog.read_text(encoding="utf-8"), fragments)
    except FragmentError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.dry_run:
        sys.stdout.write(result)
        return 0
    if not fragments:
        print("no changelog fragments to fold")
        return 0
    args.changelog.write_text(result, encoding="utf-8")
    for p in paths:
        p.unlink()
    print(f"folded {len(fragments)} fragment(s) into {args.changelog.name} and removed them")
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
is created in the canonical order.

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

# ``<issue>-<slug>.md``: the issue number first so the fold order (and a
# directory listing) follows the issue tracker, then a short slug so two PRs
# for the same issue still get different files.
FRAGMENT_NAME = re.compile(r"^[0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")

# Files in changelog.d/ that are not fragments.
NOT_FRAGMENTS = frozenset({"README.md"})

_HEADING = re.compile(r"^###\s+(.+?)\s*$")


class FragmentError(ValueError):
    """A fragment that cannot be folded as written."""


def fragment_paths(directory: pathlib.Path) -> list[pathlib.Path]:
    """Every fragment in DIRECTORY, in fold order (issue number, then name)."""
    if not directory.is_dir():
        return []
    found = [
        p
        for p in directory.iterdir()
        if p.is_file() and not p.name.startswith(".") and p.name not in NOT_FRAGMENTS
    ]

    def key(p: pathlib.Path) -> tuple[int, str]:
        m = re.match(r"^([0-9]+)", p.name)
        return (int(m.group(1)) if m else sys.maxsize, p.name)

    return sorted(found, key=key)


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
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
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
            # ``## x`` would open a release section inside Unreleased; a
            # deeper heading has no place in the release notes either.
            errors.append(f"{name}:{lineno}: only '### <Section>' headings are allowed here")
            continue
        if re.match(r"^\s+#[0-9]", line):
            # format_release_notes.py unwraps continuation lines; one that
            # starts with "#NNN" is read as a heading and splits the bullet.
            errors.append(
                f"{name}:{lineno}: a continuation line must not start with '#<number>' "
                "(re-wrap so the issue reference is mid-line)"
            )
        if current is None:
            if line.strip():
                errors.append(f"{name}:{lineno}: text before the first '### <Section>' heading")
            continue
        out[current].append(line)
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

    A changelog without ``## Unreleased`` gets one, above its first release.
    """
    try:
        start = lines.index(UNRELEASED)
    except ValueError:
        first = next((i for i, x in enumerate(lines) if x.startswith("## ")), len(lines))
        lines[first:first] = [UNRELEASED, ""]
        start = first
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return start, end


def _section_end(lines: list[str], start: int, end: int, section: str) -> int:
    """Where to append to SECTION under Unreleased, creating it if absent.

    Returns the index just after the section's last non-blank line.
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
        lines[at:at] = ["", heading]
        return at + 2
    nxt = next(
        (i for i in range(found + 1, end) if lines[i].startswith("### ")),
        end,
    )
    while nxt > found + 1 and not lines[nxt - 1].strip():
        nxt -= 1
    return nxt


def assemble(changelog: str, fragments: list[tuple[str, str]]) -> str:
    """Return CHANGELOG text with every fragment folded into Unreleased.

    FRAGMENTS is ``[(name, text), ...]`` in fold order; within each section
    entries are appended in that order, after what the section already holds.
    Raises FragmentError listing every bad fragment, before changing anything.
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
    for frag in parsed:
        for section in SECTIONS:
            body = frag.get(section)
            if not body:
                continue
            start, end = _unreleased_bounds(lines)
            at = _section_end(lines, start, end, section)
            lines[at:at] = ["", *body]
            # Keep one blank line before whatever follows.
            if at + 1 + len(body) < len(lines) and lines[at + 1 + len(body)].strip():
                lines.insert(at + 1 + len(body), "")
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

    paths = fragment_paths(args.dir)
    if args.pending:
        if paths:
            print(
                f"{len(paths)} changelog fragment(s) not folded into {args.changelog.name}: "
                + ", ".join(p.name for p in paths),
                file=sys.stderr,
            )
            return 1
        print("no pending changelog fragments")
        return 0

    fragments = [(p.name, p.read_text(encoding="utf-8")) for p in paths]
    if args.check:
        bad = 0
        for name, text in fragments:
            try:
                parse_fragment(name, text)
            except FragmentError as exc:
                bad += 1
                print(exc, file=sys.stderr)
        if bad:
            print(f"{bad} of {len(fragments)} changelog fragment(s) invalid", file=sys.stderr)
            return 1
        print(f"{len(fragments)} changelog fragment(s) OK")
        return 0

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

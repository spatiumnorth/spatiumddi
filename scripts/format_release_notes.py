#!/usr/bin/env python3
"""Reformat a CHANGELOG.md section for the GitHub release body.

CHANGELOG.md is hard-wrapped at ~70 chars for terminal reading. The
GitHub release renderer applies ``breaks: true`` GFM, which turns
every single ``\\n`` into a literal ``<br>`` — so a 54-line summary
paragraph reads as a tall narrow column instead of flowing prose.

This script reads the changelog section text on stdin and writes a
release-body-friendly version on stdout that:

1. Joins consecutive prose lines into a single line (so the renderer
   reflows them as one paragraph). Blank lines remain — they're the
   real paragraph break.
2. Leaves headings (``# / ## / ### / ####``), list items
   (``- ``, ``* ``, ``\\d+. ``), and fenced code blocks alone.
   A blockquote is joined like prose but keeps ONE ``> `` marker —
   joining it naively strips the callout and leaves the markers
   stranded mid-sentence, which is what a release-note warning
   ("you must pull new agent images") cannot afford.
3. Renames the standard Keep-a-Changelog section headings with
   emoji prefixes for readability on GitHub.
4. Wraps the top prose paragraph (the release summary) in a new
   ``### 🚀 Highlights`` heading so it's visually distinct from the
   detail bullets below. A ``#`` / ``##`` banner above the summary
   (a "don't roll back" warning) does not stop that.
5. Condenses the result when it is over ``--max-chars`` (default
   100,000; GitHub refuses a release body over 125,000): each entry
   is cut to its bold headline, Migrations and Breaking stay whole,
   and a note links ``--full-notes-url`` for the full text.

The transform is idempotent — re-running on already-transformed
input is a no-op (the emoji-prefixed headings don't double-prefix,
and prose paragraphs that are already a single line stay one line).

Usage::

    awk '/^## 2026\\.05\\.05-2/,/^## /' CHANGELOG.md \\
        | python3 scripts/format_release_notes.py
"""

from __future__ import annotations

import re
import sys

# ── Section heading rewrites ─────────────────────────────────────────
# Mirror Keep-a-Changelog's vocabulary (Added / Changed / Fixed /
# Removed / Deprecated / Security) plus our extras (Migrations).
# Match only at the start of the line and only when the heading
# isn't already emoji-prefixed (idempotency).
_SECTION_EMOJI: dict[str, str] = {
    "Added": "✨",
    "Changed": "🔧",
    "Fixed": "🐛",
    "Removed": "🗑️",
    "Deprecated": "⚠️",
    "Security": "🔒",
    "Migrations": "🗃️",
    "Breaking": "💥",
}


def _is_list_item(line: str) -> bool:
    """`- foo` / `* foo` / `1. foo`. Indented continuations of a
    bullet aren't bullets themselves; we treat them as prose so they
    join into the bullet's text on output."""
    stripped = line.lstrip()
    if line != stripped:  # indented — continuation
        return False
    if stripped.startswith(("- ", "* ")):
        return True
    return bool(re.match(r"\d+\.\s", stripped))


def _is_blockquote(line: str) -> bool:
    """``> foo``. A callout, not prose — see ``flush_para``."""
    return line.lstrip().startswith(">")


def _is_heading(line: str) -> bool:
    """``### Fixed`` — hashes at column 0, then a space.

    Both halves matter. An indented line is a bullet's wrapped
    continuation, and one that happens to start with an issue number
    (``  #1140).** Two faults…``) is not a heading: treating it as one
    split the bullet in two mid-sentence in the release body. And
    ``#1140`` with no space is not a heading in GFM either."""
    return bool(re.match(r"#{1,6}(\s|$)", line))


def _heading_level(line: str) -> int:
    return len(line) - len(line.lstrip("#"))


def _strip_quote_marker(line: str) -> str:
    """``>  foo`` ↦ ``foo``. Tolerates ``>foo`` (no space), which GFM
    accepts and hard-wrapping tools emit."""
    return re.sub(r"^\s*>\s?", "", line)


def _rewrite_heading(line: str) -> str:
    """`### Added` → `### ✨ Added`. Idempotent — already-emojified
    headings pass through untouched."""
    m = re.match(r"^(#{1,6})\s+(.*)$", line.rstrip())
    if not m:
        return line
    hashes, title = m.group(1), m.group(2).strip()
    # Skip rewriting when the title already starts with a non-ASCII
    # glyph (covers our emoji + any future symbol prefix).
    if title and ord(title[0]) > 127:
        return line
    emoji = _SECTION_EMOJI.get(title)
    if not emoji:
        return line
    return f"{hashes} {emoji} {title}"


def transform(text: str) -> str:
    """Apply the full transform to a CHANGELOG section body."""
    lines = text.splitlines()
    out: list[str] = []
    para: list[str] = []
    in_fence = False
    in_list_item = False  # last non-blank line was a bullet or its continuation
    current_list_buf: list[str] = []
    summary_emitted = False
    saw_section_heading = False

    def _join(lines: list[str]) -> str:
        """Join hard-wrapped lines back into a single line. Soft-hyphen
        edge case: when a line ends in ``\\w-`` (letter + hyphen) the
        hyphen was a wrap point inside a hyphenated word (``per-`` ↦
        ``framework`` ↦ ``per-framework``). Don't insert a space in
        that case. A line ending in `` -`` (space-hyphen) — the em-
        dash convention — keeps the space."""
        result: list[str] = []
        for raw in lines:
            piece = raw.strip()
            if not piece:
                continue
            if result and re.search(r"\w-$", result[-1]):
                result[-1] = result[-1] + piece
            else:
                result.append(piece)
        return " ".join(result)

    def flush_para() -> None:
        nonlocal summary_emitted, saw_section_heading
        if not para:
            return
        # A paragraph whose every line is quoted is one blockquote: join
        # the contents, then re-mark the result once. Without the strip
        # the markers survive INSIDE the joined sentence ("the fixes >
        # (#856) ... > all live in"), which is worse than losing the
        # callout, because it reads as a typo in the warning.
        quoted = all(_is_blockquote(line) for line in para)
        if quoted:
            joined = _join([_strip_quote_marker(line) for line in para])
            if joined:
                out.append(f"> {joined}")
            para.clear()
            return
        joined = _join(para)
        if joined:
            # The first prose paragraph becomes the "Highlights"
            # section. Everything else is just prose between
            # bullet blocks.
            if not summary_emitted and not saw_section_heading:
                out.append("### 🚀 Highlights")
                out.append("")
                summary_emitted = True
            out.append(joined)
        para.clear()

    def flush_list_item() -> None:
        nonlocal in_list_item
        if current_list_buf:
            out.append(_join(current_list_buf))
            current_list_buf.clear()
        in_list_item = False

    for raw in lines:
        line = raw.rstrip()
        # Fenced code block — pass through verbatim. ``in_fence``
        # toggles on every ``` line.
        if line.startswith("```"):
            flush_para()
            flush_list_item()
            out.append(line)
            in_fence = not in_fence
            continue
        if in_fence:
            out.append(raw)
            continue

        if line.strip() == "":
            flush_para()
            flush_list_item()
            out.append("")
            continue

        if _is_heading(line):
            flush_para()
            flush_list_item()
            out.append(_rewrite_heading(line))
            # Only a ``###`` (or deeper) heading starts the detail
            # sections. A bigger one above the summary is a banner
            # (``# ⚠️ Don't roll back to …``), and the summary under it
            # still gets its Highlights heading.
            if _heading_level(line) >= 3:
                saw_section_heading = True
            continue

        if _is_list_item(line):
            flush_para()
            flush_list_item()
            current_list_buf.append(line)
            in_list_item = True
            continue

        # Indented continuation of a bullet (the typical
        # "  continuation text" two-space indent or wrapped at any
        # leading whitespace).
        if (
            in_list_item
            and (line.startswith("  ") or line.startswith("\t"))
            and not _is_blockquote(line)
        ):
            current_list_buf.append(line)
            continue

        # Otherwise — plain prose. If we were inside a bullet, the
        # prose line ends the bullet block.
        flush_list_item()
        para.append(line)

    flush_para()
    flush_list_item()

    # Trim trailing blank lines.
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out) + "\n"


# ── Size limit ───────────────────────────────────────────────────────
# GitHub refuses a release body over 125,000 characters, and the
# create-release call fails at the very end of release.yml, after every
# image is built. The notes are not the whole body: the release template
# adds the appliance ISO and slot-upgrade sections around them. So the
# default leaves room for those.
DEFAULT_MAX_CHARS = 100_000

# Sections kept whole when condensing: the summary (the Highlights heading
# ``transform`` adds), and the two an operator needs every line of — every
# migration id and every breaking change — which are short.
_KEEP_WHOLE = {"Highlights", "Migrations", "Breaking"}

_HEADLINE = re.compile(r"^- (\*\*.+?\*\*)")


def _section_title(heading: str) -> str:
    """``### 🗃️ Migrations`` ↦ ``Migrations``."""
    title = heading.lstrip("#").strip()
    return re.sub(r"^[^\w`]+", "", title).strip()


def _headline(bullet: str, limit: int = 200) -> str:
    """The bold lead of a bullet, or its first sentence, or a cut."""
    m = _HEADLINE.match(bullet)
    if m:
        return f"- {m.group(1)}"
    text = bullet[2:]
    sentence = re.match(r"(.{20,}?[.!?])\s", text)
    if sentence and len(sentence.group(1)) <= limit:
        return f"- {sentence.group(1)}"
    if len(text) <= limit:
        return bullet
    return "- " + text[:limit].rsplit(" ", 1)[0] + " …"


def condense(text: str, max_chars: int, full_notes_url: str | None = None) -> str:
    """Fit already-transformed notes under ``max_chars``.

    Everything above the first section heading (a banner), the summary,
    and the Migrations and Breaking sections are kept as they are.
    Every other entry is cut to its bold headline, and a note says where
    the full text is. If even that does not fit, the end is cut at a line
    boundary, so the result is never over the limit."""
    if len(text) <= max_chars:
        return text
    where = f"[CHANGELOG.md]({full_notes_url})" if full_notes_url else "CHANGELOG.md at this tag"
    notice = (
        "> **These notes are condensed.** The full entry is longer than GitHub "
        "allows in a release, so each item below is cut to its headline. "
        f"The full text is in {where}."
    )
    out: list[str] = []
    section: str | None = None
    noticed = False
    for line in text.splitlines():
        if _is_heading(line) and _heading_level(line) >= 3:
            section = _section_title(line)
            if not noticed and section != "Highlights":
                if out and out[-1] != "":
                    out.append("")
                out += [notice, ""]
                noticed = True
            if out and out[-1] != "":
                out.append("")
            out += [line, ""]
            continue
        if section is None or section in _KEEP_WHOLE:
            if not (line == "" and out and out[-1] == ""):
                out.append(line)
            continue
        # Inside a condensed section: headlines only, as one tight list.
        if _is_list_item(line):
            out.append(_headline(line))
    if not noticed:
        out += ["", notice]
    result = "\n".join(out).strip("\n") + "\n"
    if len(result) <= max_chars:
        return result
    cut = f"\n\n> **Cut short here.** The full text is in {where}.\n"
    head = result[: max_chars - len(cut)]
    return head[: head.rfind("\n")].rstrip() + cut


def main(argv: list[str] | None = None) -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--max-chars",
        type=int,
        default=DEFAULT_MAX_CHARS,
        help="condense the notes above this many characters (0 = never)",
    )
    parser.add_argument(
        "--full-notes-url",
        default=None,
        help="where the full notes are, linked from condensed notes",
    )
    args = parser.parse_args(argv)
    notes = transform(sys.stdin.read())
    if args.max_chars and len(notes) > args.max_chars:
        condensed = condense(notes, args.max_chars, args.full_notes_url)
        print(
            f"release notes condensed: {len(notes)} -> {len(condensed)} characters",
            file=sys.stderr,
        )
        notes = condensed
    sys.stdout.write(notes)


if __name__ == "__main__":
    main()

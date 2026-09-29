#!/usr/bin/env python3
"""Release-tag decisions for .github/workflows/release.yml (#1226, #1182).

The release workflow used to make these in shell: a tag glob that only knew
CalVer, ``grep -E '^[0-9]{4}\\.' | sort -V`` for the previous tag, and an awk
prefix match for the CHANGELOG section. None of that survives the switch to
SemVer at 1.0.0: ``sort -V`` puts every ``2026.*`` above every ``1.*``, and a
prefix match finds ``## 1.0.10`` when asked for ``## 1.0.1``. So the
decisions live here, on top of the product's own ordering in
``backend/app/core/versions.py``, where they can be tested.

Subcommands (tags on stdin, one per line, where noted):

  check TAG            print ``prerelease=true|false``; exit 1 when TAG is
                       not a release tag this workflow may publish
  previous TAG         print the release the notes and compare link start
                       from, or nothing when there is none   (stdin: tags)
  is-newest TAG        print ``true`` when TAG is a final release no other
                       final release is newer than            (stdin: tags)
  notes TAG FILE       print TAG's section of the CHANGELOG at FILE

stdlib only: it runs on a bare runner, before anything is installed.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import types
from typing import Any, NamedTuple

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_VERSIONS = _REPO_ROOT / "backend" / "app" / "core" / "versions.py"

# A CalVer release tag always carries its ``-N``: the bare date is what
# versions.py accepts from a reporting build, not what a tag may be.
_CALVER_TAG = re.compile(r"^\d{4}\.\d{2}\.\d{2}-\d+$")
# SemVer, with no leading zeros (SemVer §2) and no build metadata (``+`` is
# not legal in an image tag). The leading-zero rule is what keeps a CalVer
# date that lost its ``-N`` (``2026.09.04``) from reading as SemVer.
_SEMVER_TAG = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
# A SemVer major this large is a CalVer date typed without its zeros
# (``2026.9.4``), never a real release, and published it would outrank
# every release after it.
_SEMVER_MAX_MAJOR = 999


def _load_versions() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("spatiumddi_versions", _VERSIONS)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before exec: the dataclass in it resolves its own module
    # through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


versions = _load_versions()


class Tag(NamedTuple):
    """A release tag. Order tags by ``release``, which is versions.py's
    ``Release`` and compares in release order."""

    name: str
    release: Any
    prerelease: bool


def parse_tag(name: str) -> Tag | None:
    """The release ``name`` tags, or None if it is not a release tag.

    None covers nightly tags, ``0.x`` placeholders, a CalVer date with no
    ``-N``, and anything carrying build metadata.
    """
    name = name.strip()
    if _CALVER_TAG.match(name):
        prerelease = False
    elif (match := _SEMVER_TAG.match(name)) and int(match.group(1)) <= _SEMVER_MAX_MAJOR:
        prerelease = "-" in name
    else:
        return None
    release = versions.parse_release(name)
    if release is None:
        return None
    return Tag(name, release, prerelease)


def _tags(lines: list[str]) -> list[Tag]:
    return [tag for tag in (parse_tag(line) for line in lines) if tag is not None]


def previous(current: Tag, lines: list[str]) -> Tag | None:
    """The newest release older than ``current``.

    A final release starts its notes from the previous FINAL release, so
    ``1.0.0`` covers everything since the bridge and not just the delta
    from its last release candidate. A pre-release starts from whatever
    came before it, candidates included.
    """
    older = [
        tag
        for tag in _tags(lines)
        if tag.release < current.release and (current.prerelease or not tag.prerelease)
    ]
    return max(older, key=lambda tag: tag.release, default=None)


def is_newest(current: Tag, lines: list[str]) -> bool:
    """Whether ``current`` should become the release everything points at:
    GitHub's latest release, the ``:latest`` images, the stable download
    URLs. A pre-release never does, and nor does a final release cut below
    a newer one (a CalVer tag pushed after 1.0.0, say)."""
    if current.prerelease:
        return False
    return not any(
        tag.release > current.release for tag in _tags(lines) if not tag.prerelease
    )


def changelog_section(version: str, text: str) -> str:
    """The body under ``## <version>``, up to the next ``## `` heading.

    The heading must be exactly the version, or the version followed by a
    space (``## 2026.09.04-1 — 2026-09-04``). A prefix match would take the
    ``## 1.0.10`` section when asked for ``1.0.1``.
    """
    heading = f"## {version}"
    out: list[str] = []
    found = False
    for line in text.splitlines():
        if found:
            if line.startswith("## "):
                break
            out.append(line)
        elif line == heading or line.startswith(heading + " "):
            found = True
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in {"check", "previous", "is-newest", "notes"}:
        print(__doc__, file=sys.stderr)
        return 2
    command, name = argv[0], argv[1]
    if command == "notes":
        if len(argv) != 3:
            print("usage: notes TAG CHANGELOG", file=sys.stderr)
            return 2
        print(changelog_section(name, pathlib.Path(argv[2]).read_text(encoding="utf-8")))
        return 0

    current = parse_tag(name)
    if current is None:
        print(
            f"{name!r} is not a release tag: expected CalVer YYYY.MM.DD-N or "
            "SemVer MAJOR.MINOR.PATCH[-PRERELEASE] with MAJOR >= 1 and no build metadata",
            file=sys.stderr,
        )
        return 1
    if command == "check":
        print(f"prerelease={'true' if current.prerelease else 'false'}")
        return 0

    lines = sys.stdin.read().splitlines()
    if command == "previous":
        found = previous(current, lines)
        if found is not None:
            print(found.name)
        return 0
    print("true" if is_newest(current, lines) else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

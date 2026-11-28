#!/usr/bin/env python3
"""Fail on a third-party GitHub Action referenced by tag instead of commit (#1334).

A tag can be moved to point at other code, so ``uses: owner/repo@v4`` can run
something different tomorrow than it ran today. Every third-party ``uses:`` in
.github/workflows/ and .github/actions/ must be ``owner/repo@<40-hex> # vX.Y.Z``.
Local ``./`` references and ``docker://`` images with a digest are exempt.
Stdlib-only; run from the repo root.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    files = sorted(
        list((ROOT / ".github/workflows").glob("*.y*ml"))
        + list((ROOT / ".github/actions").glob("**/*.y*ml"))
    )
    bad: list[str] = []
    for f in files:
        for n, line in enumerate(f.read_text().splitlines(), 1):
            m = USES.match(line)
            if not m:
                continue
            ref, rest = m.group(1).strip("'\""), m.group(2)
            if ref.startswith("./"):
                continue
            if ref.startswith("docker://"):
                ok = "@sha256:" in ref
            else:
                _, _, rev = ref.partition("@")
                ok = bool(SHA.match(rev))
            if not ok:
                bad.append(f"{f.relative_to(ROOT)}:{n}: not pinned to a commit: {ref}")
            elif not rest.strip().startswith("#"):
                bad.append(f"{f.relative_to(ROOT)}:{n}: missing '# vX.Y.Z' comment: {ref}")
    for b in bad:
        print(b)
    if bad:
        print(
            "\nPin with owner/repo@<40-char commit sha> # vX.Y.Z so a moved tag "
            "cannot change what CI runs."
        )
        return 1
    print(f"action pins ok ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

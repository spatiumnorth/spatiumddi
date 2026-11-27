#!/usr/bin/env python3
"""Print the Alembic head revisions of a versions directory, one per line.

No database and no alembic import: it reads ``revision`` / ``down_revision``
out of each migration file, the same way the maintainers' syncrel ``heads.py``
does. release-forward-merge.yml runs it on the merged tree and labels the PR
``forward-merge:alembic-heads`` when it prints more than one line.

    alembic_heads.py [backend/alembic/versions]
"""

from __future__ import annotations

import pathlib
import re
import sys

_REV = re.compile(r"""^revision\s*[:=][^\n]*?["']([0-9a-f_]+)["']""", re.MULTILINE)
_DOWN = re.compile(r"^down_revision\s*[:=]\s*(.*)$", re.MULTILINE)
_ID = re.compile(r"""["']([0-9a-f_]+)["']""")


def heads(versions: pathlib.Path) -> list[str]:
    downs: dict[str, list[str]] = {}
    for f in sorted(versions.glob("*.py")):
        s = f.read_text(encoding="utf-8")
        r = _REV.search(s)
        if not r:
            continue
        d = _DOWN.search(s)
        downs[r.group(1)] = _ID.findall(d.group(1)) if d else []
    pointed = {x for v in downs.values() for x in v}
    return sorted(h for h in downs if h not in pointed)


if __name__ == "__main__":
    path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "backend/alembic/versions")
    print("\n".join(heads(path)))

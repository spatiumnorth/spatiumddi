#!/usr/bin/env python3
"""No surface may send an operator to a "Web UI Certificate" Appliance tab (#3045).

Since #404 the Web UI Certificate page is an entry in the Appliance page's
Fleet side list, not an Appliance tab of its own. Eight surfaces kept naming
the tab that was gone — the DNS DoT / DoH card, its 422, the certificate-expiry
alert, the notes stored on the appliance's own certificates, the supervisor's
pinning messages, and the docs that describe each — and an operator following
any of them looked for a tab that does not exist. Several of those texts were
written months AFTER #404, by copying the wording of one that had been missed.

WHY A LINTER AND NOT A TEST. The stale pointers live in ``frontend/src``,
``docs/``, ``README.md`` and the supervisor package as well as
``backend/app``, and the backend suite is path-filtered off all of them
(#821); a backend test reading them would have to carve each one back in.
Backend Lint is not path-filtered and needs no database, which is this
check's shape — the precedent is ``lint_ssh_recovery_claims.py``.

Historical text is deliberately out of scope: ``CHANGELOG.md``,
``changelog.d/``, ``docs/SHIPPED.md``, ``docs/design/`` and migrations record
what was true when they were written.

Exit non-zero (with a human-readable report) on any violation.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Files an operator's eyes, or an operator's API client, actually reach.
SEARCH: tuple[tuple[str, str], ...] = (
    ("backend/app", "*.py"),
    ("frontend/src", "*.ts"),
    ("frontend/src", "*.tsx"),
    ("agent", "*.py"),
    ("docs", "*.md"),
    ("appliance/mkosi.extra", "*"),
)
TOP_LEVEL: tuple[str, ...] = ("README.md",)

#: Historical records, which say what was true when they were written.
EXCLUDED_DIRS: tuple[str, ...] = ("docs/design",)
EXCLUDED_FILES: tuple[str, ...] = ("docs/SHIPPED.md",)

#: Matched against normalised text: Markdown emphasis dropped, ``->`` read as
#: ``→``, and every run of whitespace (a wrapped line included) one space —
#: README wrapped one of these as "Appliance → Web UI" / "Certificate".
STALE = (
    # The tab #404 retired, under each name it carried.
    re.compile(r"Appliance → (Web UI Cert|TLS\b)", re.I),
    re.compile(r"Web UI Cert\w* tab\b", re.I),
)


def normalise(text: str) -> str:
    text = text.replace("**", "").replace("->", "→")
    return re.sub(r"\s+", " ", text)


def _scanned_files() -> list[Path]:
    files: list[Path] = [REPO_ROOT / name for name in TOP_LEVEL]
    for subdir, glob in SEARCH:
        root = REPO_ROOT / subdir
        if root.is_dir():
            files.extend(sorted(root.rglob(glob)))
    me = Path(__file__).resolve()
    out = []
    for path in files:
        if not path.is_file() or path.resolve() == me:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if "node_modules" in path.parts or "__pycache__" in path.parts:
            continue
        # Agents' test suites ship nothing an operator reads.
        if rel.startswith("agent/") and "/tests/" in f"/{rel}":
            continue
        if rel in EXCLUDED_FILES or any(rel.startswith(d + "/") for d in EXCLUDED_DIRS):
            continue
        out.append(path)
    return out


def offenders() -> list[str]:
    found: list[str] = []
    for path in _scanned_files():
        try:
            text = normalise(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        for pattern in STALE:
            for m in pattern.finditer(text):
                rel = path.relative_to(REPO_ROOT).as_posix()
                found.append(f"{rel}: {m.group(0)!r}")
    return found


def main() -> int:
    bad = offenders()
    if not bad:
        print("OK — no surface points at a Web UI Certificate Appliance tab.")
        return 0
    print(
        "These name an Appliance tab that does not exist. Since #404 the Web UI\n"
        "Certificate is an entry under Appliance → Fleet (shown only on an\n"
        "appliance-hosted control plane); name it that way (#3045):\n"
    )
    for line in bad:
        print(f"  {line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Guard for the appliance host-side runner scripts (issues #550, #553).

None of the ``appliance/mkosi.extra/usr/local/bin/*`` runners are covered
by tests, and two shipped features once shipped completely dead because a
runner was neither executable in git NOR chmod'd in ``mkosi.postinst`` (so
its ``.service`` ExecStart hit ``203/EXEC``). This stdlib-only linter runs
in CI (Backend Lint job) and asserts the invariants that would have caught
that class of bug:

  1. Every ``ExecStart=/usr/local/bin/<runner>`` (or ``ExecStartPre=``,
     ``ExecStartPost=``, ``ExecCondition=``) referenced by a shipped
     systemd unit resolves to a runner that will be executable in the
     built image — i.e. it is EITHER already executable in the git
     checkout OR it is chmod'd 0755 in ``mkosi.postinst``.
  2. Every runner named in the postinst ``chmod 0755`` block actually
     exists on disk.
  3. Every runner with a ``bash`` shebang is ``bash -n`` clean.

Exit non-zero (with a human-readable report) on any violation.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / "appliance" / "mkosi.extra" / "usr" / "local" / "bin"
UNIT_DIR = REPO_ROOT / "appliance" / "mkosi.extra" / "etc" / "systemd" / "system"
POSTINST = REPO_ROOT / "appliance" / "mkosi.postinst"

_CHMOD_RE = re.compile(
    r'chmod\s+0?755\s+"\$BUILDROOT/usr/local/bin/([A-Za-z0-9._-]+)"'
)
_EXECSTART_RE = re.compile(
    r"^\s*(?:ExecStart(?:Pre|Post)?|ExecCondition)=-?(/usr/local/bin/[A-Za-z0-9._-]+)",
    re.MULTILINE,
)


# Binaries fetched at build time by appliance/scripts/fetch-k3s.sh and
# dropped into the rootfs (k3s + its kubectl/crictl/ctr symlinks). They are
# gitignored, so they are legitimately absent from the source checkout —
# skip them rather than flag them as missing runners.
_BUILD_FETCHED = frozenset({"k3s", "kubectl", "crictl", "ctr"})


def _postinst_chmodded() -> set[str]:
    if not POSTINST.is_file():
        return set()
    return set(_CHMOD_RE.findall(POSTINST.read_text(encoding="utf-8")))


def _execstart_runners() -> dict[str, str]:
    """basename -> unit filename that references it via ExecStart*."""
    out: dict[str, str] = {}
    for unit in sorted(UNIT_DIR.glob("*.service")):
        text = unit.read_text(encoding="utf-8")
        for path in _EXECSTART_RE.findall(text):
            out.setdefault(os.path.basename(path), unit.name)
    return out


def _has_bash_shebang(p: Path) -> bool:
    try:
        first = p.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    except OSError:
        return False
    return bool(first) and first[0].startswith("#!") and "bash" in first[0]


def main() -> int:
    errors: list[str] = []

    chmodded = _postinst_chmodded()

    # (1) + (2) — chmod-referenced runners must exist (build-fetched
    # binaries excepted; they aren't in the source checkout).
    for name in sorted(chmodded):
        if name in _BUILD_FETCHED:
            continue
        if not (BIN_DIR / name).is_file():
            errors.append(
                f"mkosi.postinst chmods 'usr/local/bin/{name}' but no such "
                f"file exists under {BIN_DIR.relative_to(REPO_ROOT)}/"
            )

    # (1) — every unit ExecStart runner is executable in the built image.
    for name, unit in sorted(_execstart_runners().items()):
        if name in _BUILD_FETCHED:
            continue
        src = BIN_DIR / name
        if not src.is_file():
            errors.append(
                f"{unit}: ExecStart runner 'usr/local/bin/{name}' does not "
                f"exist under {BIN_DIR.relative_to(REPO_ROOT)}/"
            )
            continue
        git_exec = os.access(src, os.X_OK)
        if not git_exec and name not in chmodded:
            fix = f'chmod 0755 "$BUILDROOT/usr/local/bin/{name}"'
            errors.append(
                f"{unit}: ExecStart runner '{name}' is NOT executable in git "
                f"AND is NOT chmod'd 0755 in mkosi.postinst — its ExecStart "
                f"will hit 203/EXEC in the built image. Add a `{fix}` line to "
                f"mkosi.postinst (and `git update-index --chmod=+x` the file)."
            )

    # (3) — bash -n on every bash runner.
    for src in sorted(BIN_DIR.iterdir()):
        if not src.is_file() or not _has_bash_shebang(src):
            continue
        res = subprocess.run(
            ["bash", "-n", str(src)],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            errors.append(
                f"{src.name}: bash -n failed:\n"
                + "\n".join("      " + ln for ln in res.stderr.splitlines())
            )

    if errors:
        print("appliance runner lint FAILED:\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            f"\n{len(errors)} problem(s) found.",
            file=sys.stderr,
        )
        return 1

    print("appliance runner lint OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

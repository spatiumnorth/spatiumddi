#!/usr/bin/env python3
"""Report PR authors who are not linked in the README's Contributors section.

The README rule is "everyone who has opened a pull request" (any state), so
this takes every PR author and diffs it against the ``github.com/<login>``
links inside the ``## Contributors`` section only.

Input (``--prs FILE``, ``-`` for stdin): a JSON array whose items are either
a login string or an object ``{"login": ..., "number": ...}`` -- the shape
the workflow produces with ``gh api --paginate ... --jq '.[] | {login:
.user.login, number}' | jq -s .``.

Exit codes: 0 nobody missing, 1 someone missing, 2 the check could not run
(no Contributors section, empty/invalid PR list). Exit 2 is deliberate: a
guard that evaluated nothing must not look like a pass (#1030).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = "spatiumnorth/spatiumddi"
MAX_PRS = 5
_BOT_LOGINS = {"copilot", "copilot-swe-agent"}
_LINK = re.compile(r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)", re.I)


def is_bot(login: str) -> bool:
    low = login.lower()
    return low.endswith("[bot]") or low.startswith("app/") or low in _BOT_LOGINS


def contributors_section(readme: str) -> str | None:
    lines = readme.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"##\s+Contributors\s*$", line):
            out = []
            for nxt in lines[i + 1 :]:
                if re.match(r"#{1,6}\s", nxt) or re.match(r"-{3,}\s*$", nxt):
                    break
                out.append(nxt)
            return "\n".join(out)
    return None


def listed_logins(section: str) -> set[str]:
    return {m.group(1).lower() for m in _LINK.finditer(section)}


def read_ignore(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    out = set()
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.add(line.lower())
    return out


def parse_prs(data: object) -> dict[str, list[int]]:
    """login (original case, first seen) -> sorted PR numbers."""
    if not isinstance(data, list):
        raise ValueError("PR list must be a JSON array")
    prs: dict[str, tuple[str, list[int]]] = {}
    for item in data:
        if isinstance(item, str):
            login, number = item, None
        elif isinstance(item, dict):
            login, number = item.get("login"), item.get("number")
        else:
            raise ValueError(f"unsupported PR entry: {item!r}")
        if not login:  # deleted account ("ghost") arrives as null
            continue
        entry = prs.setdefault(login.lower(), (login, []))
        if isinstance(number, int):
            entry[1].append(number)
    return {login: sorted(nums) for login, nums in prs.values()}


def find_missing(
    prs: dict[str, list[int]], section: str, ignore: set[str]
) -> dict[str, list[int]]:
    listed = listed_logins(section)
    return {
        login: nums
        for login, nums in prs.items()
        if not is_bot(login) and login.lower() not in ignore and login.lower() not in listed
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--prs", required=True, help="JSON file of PR authors, or - for stdin")
    ap.add_argument("--readme", default="README.md")
    ap.add_argument("--ignore", default=".github/contributors-ignore.txt")
    ap.add_argument("--repo", default=REPO)
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.prs == "-" else Path(args.prs).read_text()
        prs = parse_prs(json.loads(raw))
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read the PR list: {exc}", file=sys.stderr)
        return 2
    if not prs:
        print("ERROR: the PR list is empty; refusing to report a pass.", file=sys.stderr)
        return 2

    try:
        section = contributors_section(Path(args.readme).read_text())
    except OSError as exc:
        print(f"ERROR: cannot read {args.readme}: {exc}", file=sys.stderr)
        return 2
    if section is None or not listed_logins(section):
        print(
            f"ERROR: no '## Contributors' section with github.com links in {args.readme}.",
            file=sys.stderr,
        )
        return 2

    missing = find_missing(prs, section, read_ignore(Path(args.ignore)))
    if not missing:
        print(f"OK: all {len(prs)} PR author(s) are listed or excluded.")
        return 0

    print(f"{len(missing)} PR author(s) not in the README Contributors table:\n")
    for login in sorted(missing, key=str.lower):
        nums = missing[login]
        shown = ", ".join(
            f"#{n} (https://github.com/{args.repo}/pull/{n})" for n in nums[:MAX_PRS]
        )
        more = f" and {len(nums) - MAX_PRS} more" if len(nums) > MAX_PRS else ""
        print(f"- @{login} (https://github.com/{login}): {shown}{more}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

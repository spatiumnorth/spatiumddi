#!/usr/bin/env python3
"""Is the pinned nginx inside a range nginx.org lists as affected? (#4816)

Trivy cannot answer this. The official ``nginx:*-alpine`` image installs nginx
from nginx.org's own Alpine repository, a package set Alpine's database does
not track, so an image scan reports nothing about nginx itself. nginx.org
publishes its own list of affected and fixed versions for every problem it
fixes (https://nginx.org/en/security_advisories.html); this reads that page
and compares it with the ``nginx`` pin in ``versions.json``.

Each entry on the page carries two lines, an affected range list
(``1.9.5-1.31.8, 1.30.0-1.30.5``; ``all``) and a fixed list (``1.31.9+,
1.30.7+``; ``none``). A ``+`` term fixes its own branch from that release on,
and the newest term also fixes every later mainline release.

Exit codes:
  0  no listed entry affects the pin
  1  at least one entry affects the pin (the list is printed)
  3  the page could not be fetched or parsed, or the pin could not be read.
     Never 0: "could not tell" must not read as "clean" (#1030).

Stdlib only; informational, run weekly by .github/workflows/trivy-scheduled.yml.
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import sys
import urllib.request
from typing import NamedTuple

PAGE_URL = "https://nginx.org/en/security_advisories.html"
MANIFEST_PATH = pathlib.Path(__file__).resolve().parent.parent / "versions.json"

EXIT_CLEAN = 0
EXIT_AFFECTED = 1
EXIT_UNKNOWN = 3

Version = tuple[int, ...]

_ENTRY_RE = re.compile(r"<li><p>(.*?)</p></li>", re.S)
# The page's own labels for the two lists.
_FIXED_RE = re.compile(r"Not vulnerable:\s*([^<]*)")
_AFFECTED_RE = re.compile(r"(?<!Not )Vulnerable:\s*([^<]*)")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)+$")
_SEVERITY_RE = re.compile(r"Severity:\s*(?:<b>)?([a-z]+)")
_LINK_RE = re.compile(r'<a href="([^"]+)">Advisory</a>')


class FetchError(Exception):
    """The page could not be read, or did not look like the expected page."""


class Entry(NamedTuple):
    title: str
    link: str | None
    affected: str
    fixed: str
    severity: str = ""


def parse_version(text: str) -> Version | None:
    text = text.strip()
    if not _VERSION_RE.match(text):
        return None
    return tuple(int(p) for p in text.split("."))


def pin_version(manifest_path: pathlib.Path) -> Version:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw = str(data["components"]["nginx"]["version"])
    except (OSError, ValueError, KeyError) as exc:
        raise FetchError(f"cannot read the nginx pin from {manifest_path}: {exc}") from exc
    parsed = parse_version(raw.removesuffix("-alpine"))
    if parsed is None:
        raise FetchError(f"the nginx pin {raw!r} is not a plain version")
    return parsed


def parse_page(page: str) -> list[Entry]:
    entries: list[Entry] = []
    for block in _ENTRY_RE.findall(page):
        affected = _AFFECTED_RE.search(block)
        fixed = _FIXED_RE.search(block)
        if not affected or not fixed:
            continue
        title = html.unescape(re.sub(r"<[^>]+>", "", block.split("<br>", 1)[0])).strip()
        link = _LINK_RE.search(block)
        severity = _SEVERITY_RE.search(block)
        entries.append(
            Entry(
                title=title,
                link=link.group(1) if link else None,
                affected=html.unescape(affected.group(1)).strip(),
                fixed=html.unescape(fixed.group(1)).strip(),
                severity=severity.group(1) if severity else "",
            )
        )
    return entries


def _terms(text: str) -> list[str]:
    return [t.strip() for t in text.split(",") if t.strip()]


def in_affected(pin: Version, text: str) -> bool:
    for term in _terms(text):
        if term == "all":
            return True
        if "-" in term:
            lo_s, _, hi_s = term.partition("-")
            lo, hi = parse_version(lo_s), parse_version(hi_s)
            if lo and hi and lo <= pin <= hi:
                return True
        else:
            single = parse_version(term)
            if single is not None and single == pin:
                return True
        # Anything else ("nginx/Windows 0.7.52-1.3.0") names another build.
    return False


def is_fixed(pin: Version, text: str) -> bool:
    plus: list[Version] = []
    for term in _terms(text):
        if term.endswith("+"):
            v = parse_version(term[:-1])
            if v is not None:
                plus.append(v)
    if not plus:
        return False
    newest = max(plus)
    for v in plus:
        if pin < v:
            continue
        # A stable-branch term covers its own branch; the newest term is the
        # mainline fix and covers every later release.
        if pin[:2] == v[:2] or v == newest:
            return True
    return False


def affecting(pin: Version, entries: list[Entry]) -> list[Entry]:
    # nginx rates one 2009 entry "none" with no fixed release at all; counting
    # it would make the check report every pin, every week.
    return [
        e
        for e in entries
        if e.severity != "none" and in_affected(pin, e.affected) and not is_fixed(pin, e.fixed)
    ]


def fetch_page(url: str, timeout: float = 30.0) -> str:
    if not url.startswith("https://"):
        raise FetchError(f"refusing to fetch {url!r}: not an https URL")
    req = urllib.request.Request(url, headers={"User-Agent": "spatiumddi-nginx-fixed-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return str(resp.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001 — every failure mode is exit 3
        raise FetchError(f"cannot fetch {url}: {type(exc).__name__}: {exc}") from exc


def run(manifest: pathlib.Path, url: str, page_file: pathlib.Path | None) -> int:
    try:
        pin = pin_version(manifest)
        page = page_file.read_text(encoding="utf-8") if page_file else fetch_page(url)
        entries = parse_page(page)
        if not entries:
            raise FetchError("no entries found on the page; its layout may have changed")
    except (FetchError, OSError) as exc:
        print(f"could not check: {exc}", file=sys.stderr)
        print("RESULT status=unknown", file=sys.stderr)
        return EXIT_UNKNOWN

    pin_s = ".".join(str(p) for p in pin)
    hits = affecting(pin, entries)
    if not hits:
        print(f"nginx {pin_s}: none of {len(entries)} entries on {PAGE_URL} affect it.")
        print(f"RESULT affected=0 entries={len(entries)}")
        return EXIT_CLEAN

    print(f"nginx {pin_s} is inside the affected range of {len(hits)} entr(y/ies) on {PAGE_URL}:")
    print()
    print("| Entry | Affected | Fixed in | Details |")
    print("|---|---|---|---|")
    for e in hits:
        link = f"[link]({e.link})" if e.link else "-"
        print(f"| {e.title} | `{e.affected}` | `{e.fixed}` | {link} |")
    print()
    print(f"RESULT affected={len(hits)} entries={len(entries)}")
    return EXIT_AFFECTED


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0], allow_abbrev=False)
    ap.add_argument("--manifest", type=pathlib.Path, default=MANIFEST_PATH)
    ap.add_argument("--url", default=PAGE_URL)
    ap.add_argument("--page-file", type=pathlib.Path, default=None, help="read a saved copy")
    args = ap.parse_args(argv)
    return run(args.manifest, args.url, args.page_file)


if __name__ == "__main__":
    sys.exit(main())

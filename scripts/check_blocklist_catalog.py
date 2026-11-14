#!/usr/bin/env python3
"""Monthly check of the DNS blocklist catalog's feeds (#3522).

Nothing told us when a feed in ``backend/app/data/dns_blocklist_catalog.json``
died, moved or shrank, or when upstream published a list worth adding; we found
out when an operator's refresh failed. This fetches every ``feed_url``, parses
it with the product's own parser (``parse_feed_detailed``, the code a refresh
runs) and reports, as markdown:

* **dead**       -- HTTP error, timeout, or the connection failing;
* **not a list** -- an HTML page (an error page, a captcha, a moved-to notice)
  where a list should be;
* **unparseable** -- the declared ``feed_format`` yields (almost) nothing while
  another format yields plenty, or nothing at all parses;
* **shrunken**   -- fewer entries than a floor, or down sharply from the
  baseline recorded by the previous run;
* **skipped**    -- the share of adblock rules the parser could not turn into
  entries is high, or rose sharply (the feed's author started using syntax RPZ
  cannot express);
* **upstream**   -- AdGuard's HostlistsRegistry lists not in the catalog, and
  catalog entries the registry has marked deprecated.

It never edits the catalog: adding a third-party source is a judgment call.
The report is bounded (``MAX_REPORT_BYTES``) so it always fits in an issue
body; rows past the bound are counted, not dropped silently.

The baseline (entry counts of the last run) is NOT kept in the repo, so the
repo does not churn. The workflow passes the previous run's artifact in with
``--baseline`` and uploads ``--write-baseline`` for the next one.

Exit codes: 0 always, including when there are findings (they go to the
tracking issue, not to a red CI run); 2 when the check itself could not run
(catalog unreadable, parser unloadable -- e.g. ``dns_blocklist_parse.py``
gained an import outside the standard library -- or every feed AND the registry failed,
which says the runner's network is broken rather than the catalog). Whether
there were findings is written to ``--status-out`` (``clean`` / ``findings``).

CI's outbound traffic, not the product's: non-negotiable #17 and
``docs/PRIVACY.md`` cover what the backend does, not this script.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
import time
import types
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "backend" / "app" / "data" / "dns_blocklist_catalog.json"
# The product's parser, in a module that imports only the standard library so
# it loads here without the app (#3522). ``dns_blocklist.py`` re-exports it.
PARSER_PATH = REPO_ROOT / "backend" / "app" / "services" / "dns_blocklist_parse.py"

# Generic: names the tool and the project, no person.
USER_AGENT = (
    "spatiumddi-blocklist-catalog-check/1 (+https://github.com/spatiumnorth/spatiumddi)"
)
REGISTRY_URL = "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json"
# Per socket operation, and a wall-clock cap on one whole download: a server
# trickling bytes would otherwise hold the job until its timeout.
FETCH_TIMEOUT = 30
FETCH_DEADLINE = 180
MAX_BYTES = 150 * 1024 * 1024
# GitHub caps an issue body at 65,536 characters; leave room for the footer the
# workflow appends.
MAX_REPORT_BYTES = 60_000

# An entry count under this is "something is wrong with the feed" for any list
# in the catalog; the smallest healthy one carries thousands. Override per
# source id below when a list is legitimately small.
GLOBAL_FLOOR = 500
PER_SOURCE_FLOOR: dict[str, int] = {
    # A short, curated list of search-engine hostnames: ~200 entries is healthy.
    "hagezi-nosafesearch": 50,
}
# HostlistsRegistry entries are matched by ``filterId`` (the N in
# ``https://adguardteam.github.io/HostlistsRegistry/assets/filter_N.txt``).
#
# A registry list counts as already in the catalog when (a) one of its URLs is
# a catalog ``feed_url``, (b) COVERED_UPSTREAM maps it to a catalog source id
# that exists, or (c) its homepage is a catalog homepage AND no other registry
# list shares that homepage. (c) is deliberately narrow: HaGeZi publishes over
# twenty registry lists under one homepage, and matching on homepage alone
# would hide every new one of them.
#
# Registry lists the catalog carries from a different URL (upstream's own
# rather than AdGuard's mirror), keyed filterId -> catalog source id. An entry
# whose source id is not (yet) in the catalog does not count, so the list is
# reported until it is.
COVERED_UPSTREAM: dict[int, str] = {
    1: "adguard-dns-filter",
    5: "oisd-small",
    11: "urlhaus",
    18: "phishing-army-extended",
    24: "1hosts-lite",
    27: "oisd-big",
    33: "stevenblack-unified",
    34: "hagezi-multi-normal",
    44: "hagezi-tif-medium",
    47: "hagezi-gambling",
    48: "hagezi-multi-pro",
    52: "hagezi-doh-vpn-proxy-bypass",
}
# Registry lists reviewed and declined as catalog additions (#3521), so they
# stop being re-reported every month. filterId -> reason; keep sorted by id.
_OVERLAP = "overlaps the shipped ads / tracker tiers"
_BREAKAGE = "too breakage-prone for a catalog default"
_NICHE = "niche device / vendor list; an operator can add it by URL"
_CONTENT = "content policy, not general purpose"
_REGIONAL = "regional / language list"
_THREAT = "covered by HaGeZi TIF medium + Phishing Army"
_HAGEZI_SPECIAL = "narrow, breakage-prone HaGeZi special-purpose list"
IGNORED_UPSTREAM: dict[int, str] = {
    3: _OVERLAP,  # Peter Lowe
    4: _OVERLAP,  # Dan Pollock
    6: _NICHE,  # Game Console
    7: _NICHE,  # Smart-TV
    8: _THREAT,  # NoCoin
    9: _THREAT,  # Big List of Hacked Malware Sites
    10: _THREAT,  # Scam (DurableNapkin)
    12: _THREAT,  # Dandelion Anti-Malware
    13: _REGIONAL,  # NOR
    14: _REGIONAL,  # POL
    15: _REGIONAL,  # KOR YousList
    16: _REGIONAL,  # VNM
    17: _REGIONAL,  # SWE
    19: _REGIONAL,  # IRN
    20: _REGIONAL,  # MKD
    21: _REGIONAL,  # CHN anti-AD
    22: _REGIONAL,  # IDN
    25: _REGIONAL,  # KOR filterslists-KO
    26: _REGIONAL,  # TUR
    29: _REGIONAL,  # CHN AdRules
    30: "new host (gitlab.com) for one phishing list",  # PhishTank / OpenPhish
    31: _THREAT,  # Stalkerware
    35: _REGIONAL,  # HUN
    36: _REGIONAL,  # LIT
    37: _NICHE,  # No Google
    39: _NICHE,  # Anti Push Notifications
    40: _REGIONAL,  # TUR Ad Hosts
    41: _REGIONAL,  # POL CERT
    42: _THREAT,  # ShadowWhisperer Malware
    43: _REGIONAL,  # ISR
    45: _NICHE,  # HaGeZi Allowlist Referral
    46: _CONTENT,  # Anti-Piracy
    49: _BREAKAGE,  # HaGeZi Ultimate
    50: "adblock URL rules DNS cannot enforce",  # uBlock Badware
    51: _BREAKAGE,  # HaGeZi Pro++
    53: _OVERLAP,  # AWAvenue
    54: _HAGEZI_SPECIAL,  # DynDNS
    55: _HAGEZI_SPECIAL,  # Badware Hoster
    56: _HAGEZI_SPECIAL,  # Most Abused TLDs
    57: _CONTENT,  # Dating
    59: _OVERLAP,  # AdGuard Popup Hosts
    60: _NICHE,  # Xiaomi
    61: _NICHE,  # Samsung
    62: _CONTENT,  # Ukrainian Security Filter
    63: _NICHE,  # Windows / Office
    65: _NICHE,  # Vivo
    66: _NICHE,  # OPPO / Realme
    67: _NICHE,  # Apple
    68: _HAGEZI_SPECIAL,  # URL Shortener
    69: _OVERLAP,  # ShadowWhisperer Tracking
    70: _BREAKAGE,  # 1Hosts Xtra
    71: _HAGEZI_SPECIAL,  # DNS Rebind Protection
    72: _NICHE,  # LG webOS
    73: _NICHE,  # Huawei
}
# Fraction of the baseline below which a list counts as shrunken.
SHRINK_RATIO = 0.5
# Adblock skip share: flagged above this, or when it rose by this much.
SKIP_SHARE_MAX = 0.25
SKIP_SHARE_RISE = 0.10
# Declared format "no longer parses" when it yields under this fraction of the
# best alternative's count and the alternative is substantial.
FORMAT_MISMATCH_RATIO = 0.1
ALL_FORMATS = ("hosts", "domains", "adblock")


@dataclass
class Fetched:
    """Result of fetching one URL: text, or a short reason it failed."""

    text: str | None = None
    error: str | None = None
    content_type: str = ""


@dataclass
class Finding:
    # dead | not_a_list | unparseable | shrunken | skipped | upstream_new | upstream_retired
    kind: str
    source: str
    message: str


@dataclass
class Measured:
    """What one healthy fetch measured, kept as the next run's baseline."""

    entries: int
    skipped: int = 0

    @property
    def skip_share(self) -> float:
        total = self.entries + self.skipped
        return self.skipped / total if total else 0.0


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    measured: dict[str, Measured] = field(default_factory=dict)
    checked: int = 0
    registry_ok: bool = True


Fetch = Callable[[str], Fetched]


# --------------------------------------------------------------------------
# Parser loading
# --------------------------------------------------------------------------


def load_parser(path: pathlib.Path = PARSER_PATH) -> types.ModuleType:
    """Load the product's feed parser from source, without the app.

    ``dns_blocklist_parse.py`` imports only the standard library, so it loads
    on a bare runner with nothing stubbed: the parser is the product's own code,
    never a copy. If it ever gains an import the runner cannot satisfy, this
    raises a RuntimeError naming the module, and ``main`` exits 2 (the job goes
    red) rather than reporting on a parser it did not load.
    """
    spec = importlib.util.spec_from_file_location("_spatium_dns_blocklist_parse", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules[cls.__module__],
    # so the module must be registered while it executes.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:
        raise RuntimeError(
            f"{path} no longer loads on its own ({exc}); it must import only the "
            "standard library so this check can run without the app"
        ) from exc
    finally:
        sys.modules.pop(spec.name, None)
    for name in ("parse_feed_detailed", "ParsedFeed"):
        if not hasattr(module, name):
            raise RuntimeError(f"{path} no longer defines {name}")
    return module


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------


def http_fetch(url: str) -> Fetched:
    """GET ``url`` with a timeout and a size cap; one retry on a transient error."""
    last = "unknown error"
    for attempt in (1, 2):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(
                req, timeout=FETCH_TIMEOUT
            ) as resp:  # noqa: S310
                started = time.monotonic()
                chunks: list[bytes] = []
                size = 0
                while chunk := resp.read(1024 * 1024):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_BYTES:
                        return Fetched(
                            error=f"larger than {MAX_BYTES // (1024 * 1024)} MiB"
                        )
                    if time.monotonic() - started > FETCH_DEADLINE:
                        return Fetched(
                            error=f"download took longer than {FETCH_DEADLINE}s"
                        )
                raw = b"".join(chunks)
                ctype = resp.headers.get("Content-Type", "")
                return Fetched(
                    text=raw.decode("utf-8", errors="replace"), content_type=ctype
                )
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code < 500:  # a 4xx will not change on retry
                return Fetched(error=last)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
        if attempt == 1:
            time.sleep(2)
    return Fetched(error=last)


def looks_like_html(text: str) -> bool:
    head = text[:2048].lstrip().lower()
    return (
        head.startswith(("<!doctype html", "<html"))
        or "<html" in head
        or "<body" in head
    )


# --------------------------------------------------------------------------
# Classification (pure; the tests drive these with fixtures)
# --------------------------------------------------------------------------


def check_source(
    source: dict[str, Any],
    fetched: Fetched,
    parser: types.ModuleType,
    baseline: dict[str, dict[str, Any]],
) -> tuple[list[Finding], Measured | None]:
    sid = source["id"]
    url = source["feed_url"]
    fmt = source["feed_format"]
    if fetched.error is not None or fetched.text is None:
        return [
            Finding("dead", sid, f"`{url}` -- {fetched.error or 'no content'}")
        ], None
    text = fetched.text
    if looks_like_html(text):
        return [
            Finding(
                "not_a_list",
                sid,
                f"`{url}` returned an HTML page ({fetched.content_type or 'no content type'}), "
                "not a list -- moved, or behind an error / challenge page",
            )
        ], None

    parsed = parser.parse_feed_detailed(text, fmt)
    entries = len(parsed.domains) + len(parsed.literal_domains)
    skipped = parsed.skipped.total if parsed.skipped is not None else 0
    measured = Measured(entries=entries, skipped=skipped)
    findings: list[Finding] = []

    # Declared format vs the others: a feed that switched syntax parses to ~0
    # under the old declaration while another declaration reads it fine.
    alternatives = {
        alt: len(parser.parse_feed_detailed(text, alt).domains)
        for alt in ALL_FORMATS
        if alt != fmt
    }
    best_alt, best_n = max(alternatives.items(), key=lambda kv: kv[1])
    # A feed already reported as unparseable is not also reported as shrunken:
    # the count is wrong because the format is, not because the list shrank.
    unparseable = False
    if entries == 0 and best_n == 0:
        unparseable = True
        findings.append(
            Finding(
                "unparseable",
                sid,
                f"`feed_format: {fmt}` yields 0 entries and so does every other format "
                f"({len(text):,} bytes fetched)",
            )
        )
    elif best_n >= GLOBAL_FLOOR and entries < best_n * FORMAT_MISMATCH_RATIO:
        unparseable = True
        findings.append(
            Finding(
                "unparseable",
                sid,
                f"`feed_format: {fmt}` yields {entries:,} entries but `{best_alt}` yields "
                f"{best_n:,} -- the feed likely changed syntax",
            )
        )

    floor = PER_SOURCE_FLOOR.get(sid, GLOBAL_FLOOR)
    prev = baseline.get(sid)
    if not isinstance(prev, dict):
        prev = None
    if entries < floor and not unparseable:
        findings.append(
            Finding(
                "shrunken", sid, f"{entries:,} entries, below the floor of {floor:,}"
            )
        )
    elif prev and prev.get("entries") and entries < prev["entries"] * SHRINK_RATIO:
        findings.append(
            Finding(
                "shrunken",
                sid,
                f"{entries:,} entries, down from {prev['entries']:,} last run "
                f"({entries / prev['entries']:.0%})",
            )
        )

    prev_share = (
        Measured(
            int(prev.get("entries") or 0), int(prev.get("skipped") or 0)
        ).skip_share
        if prev
        else 0.0
    )
    if measured.skip_share > SKIP_SHARE_MAX or (
        prev and measured.skip_share - prev_share > SKIP_SHARE_RISE
    ):
        findings.append(
            Finding(
                "skipped",
                sid,
                f"{measured.skipped:,} of {measured.entries + measured.skipped:,} rules skipped "
                f"({measured.skip_share:.0%}"
                + (f", {prev_share:.0%} last run" if prev else "")
                + ") -- the parser cannot express them",
            )
        )
    return findings, measured


def _norm_url(url: str) -> str:
    return (
        url.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
    )


def _code(text: Any) -> str:
    """Third-party text as an inline code span: no markdown, no @mentions."""
    return "`" + str(text).replace("`", "'").replace("\n", " ") + "`"


def _filter_label(f: dict[str, Any]) -> str:
    return f"{f.get('filterId', '?')} {f.get('filterKey', '?')}"


def diff_registry(
    catalog_sources: list[dict[str, Any]], registry: dict[str, Any]
) -> list[Finding]:
    """New upstream lists, and catalog entries the registry deprecated.

    See COVERED_UPSTREAM for what counts as "already in the catalog".
    """
    filters = registry.get("filters")
    if not isinstance(filters, list) or not filters:
        raise ValueError("registry document carries no 'filters' list")
    filters = [f for f in filters if isinstance(f, dict)]
    catalog_ids = {s["id"] for s in catalog_sources}
    url_to_source = {_norm_url(s["feed_url"]): s["id"] for s in catalog_sources}
    homepage_to_source: dict[str, str] = {}
    for s in catalog_sources:
        if s.get("homepage"):
            homepage_to_source.setdefault(_norm_url(s["homepage"]), s["id"])
    homepage_uses: dict[str, int] = {}
    for f in filters:
        if f.get("homepage"):
            hp = _norm_url(f["homepage"])
            homepage_uses[hp] = homepage_uses.get(hp, 0) + 1

    def covering_source(f: dict[str, Any]) -> str | None:
        for key in ("subscriptionUrl", "downloadUrl"):
            if f.get(key) and _norm_url(f[key]) in url_to_source:
                return url_to_source[_norm_url(f[key])]
        mapped = COVERED_UPSTREAM.get(f.get("filterId"))  # type: ignore[arg-type]
        if mapped in catalog_ids:
            return mapped
        hp = _norm_url(f["homepage"]) if f.get("homepage") else None
        if hp and homepage_uses.get(hp) == 1 and hp in homepage_to_source:
            return homepage_to_source[hp]
        return None

    findings: list[Finding] = []
    for f in filters:
        source = covering_source(f)
        if source is not None:
            if f.get("deprecated"):
                findings.append(
                    Finding(
                        "upstream_retired",
                        source,
                        f"AdGuard's registry lists {_code(f.get('name'))} as deprecated "
                        f"({_code(_filter_label(f))})",
                    )
                )
            continue
        if f.get("deprecated") or f.get("filterId") in IGNORED_UPSTREAM:
            continue
        findings.append(
            Finding(
                "upstream_new",
                _filter_label(f),
                f"{_code(f.get('name'))} -- {_code(f.get('homepage', ''))} -- "
                f"{_code(f.get('subscriptionUrl') or f.get('downloadUrl'))}",
            )
        )
    return findings


def run_check(
    catalog: dict[str, Any],
    parser: types.ModuleType,
    fetch: Fetch,
    baseline: dict[str, dict[str, Any]] | None = None,
) -> Report:
    baseline = baseline or {}
    report = Report()
    sources = catalog.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("catalog has no sources")
    dead_or_blocked = 0
    fetched_by_url: dict[str, Fetched] = (
        {}
    )  # one fetch per URL, however many sources share it
    for source in sources:
        url = source["feed_url"]
        if url not in fetched_by_url:
            fetched_by_url[url] = fetch(url)
        fetched = fetched_by_url[url]
        findings, measured = check_source(source, fetched, parser, baseline)
        report.findings.extend(findings)
        report.checked += 1
        if measured is not None:
            report.measured[source["id"]] = measured
        if fetched.error is not None:
            dead_or_blocked += 1

    registry_fetch = fetch(REGISTRY_URL)
    if registry_fetch.error is not None or registry_fetch.text is None:
        report.registry_ok = False
        if dead_or_blocked == report.checked:
            raise RuntimeError(
                "every feed and the registry failed to fetch: the runner's network, not the catalog"
            )
    else:
        try:
            report.findings.extend(
                diff_registry(sources, json.loads(registry_fetch.text))
            )
        except (ValueError, TypeError, AttributeError) as exc:
            report.registry_ok = False
            report.findings.append(
                Finding(
                    "upstream_new",
                    "registry",
                    f"could not read the registry document: {exc}",
                )
            )
    return report


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

MARKER = "<!-- blocklist-catalog -->"
SECTIONS = (
    ("dead", "Dead feeds"),
    ("not_a_list", "Feeds that now return a web page"),
    ("unparseable", "Feeds that no longer parse"),
    ("shrunken", "Shrunken feeds"),
    ("skipped", "Rising share of skipped rules"),
    ("upstream_retired", "Catalog entries retired upstream"),
    ("upstream_new", "Upstream lists not in the catalog (candidates)"),
)


def render_markdown(report: Report, max_bytes: int = MAX_REPORT_BYTES) -> str:
    """The report as markdown, never longer than ``max_bytes`` (UTF-8).

    Header and section titles always survive; finding rows and then the entry
    count table are cut first, with a line saying how many were left out (the
    full list is in the workflow log, which prints the unbounded report).
    """
    head = [MARKER, "# Blocklist catalog check", ""]
    if not report.findings:
        head.append(
            f"All {report.checked} feeds fetched, parsed and sized as expected."
        )
    else:
        head.append(
            f"Checked {report.checked} feeds in `backend/app/data/dns_blocklist_catalog.json` "
            "against the product's own parser. The catalog is never edited by this check."
        )
    if not report.registry_ok:
        head += ["", "_The AdGuard registry could not be fetched or read this run._"]

    sections: list[tuple[str, list[str]]] = []
    for kind, title in SECTIONS:
        rows = [f for f in report.findings if f.kind == kind]
        if rows:
            sections.append(
                (
                    f"## {title} ({len(rows)})",
                    [f"- {_code(f.source)}: {f.message}" for f in rows],
                )
            )
    table = [
        f"| {_code(sid)} | {m.entries:,} | {m.skipped:,} |"
        for sid, m in sorted(report.measured.items())
    ]
    tail_open = ["", "<details><summary>Entry counts this run</summary>", ""]
    tail_open += ["| source | entries | skipped |", "|---|---:|---:|"]
    tail_close = ["", "</details>", ""]

    def size(lines: list[str]) -> int:
        return len("\n".join(lines).encode("utf-8")) + 1

    # Fixed skeleton first, then rows while they fit. A cut section ends with a
    # note so a truncated issue never reads as complete.
    note_room = 200 * (len(sections) + 1)
    budget = max_bytes - size(head) - size(tail_open + tail_close) - note_room
    budget -= sum(size(["", title, ""]) for title, _ in sections)
    out = list(head)
    for title, rows in sections:
        out += ["", title, ""]
        kept = 0
        for row in rows:
            cost = size([row])
            if cost > budget:
                break
            out.append(row)
            budget -= cost
            kept += 1
        if kept < len(rows):
            out.append(
                f"- _... and {len(rows) - kept} more, not shown (see the workflow log)_"
            )
    out += tail_open
    kept = 0
    for row in table:
        cost = size([row])
        if cost > budget:
            break
        out.append(row)
        budget -= cost
        kept += 1
    if kept < len(table):
        out += ["", f"_... and {len(table) - kept} more sources, not shown._"]
    out += tail_close
    return "\n".join(out)


def baseline_json(report: Report) -> str:
    return json.dumps(
        {
            sid: {"entries": m.entries, "skipped": m.skipped}
            for sid, m in report.measured.items()
        },
        indent=1,
        sort_keys=True,
    )


def load_baseline(path: pathlib.Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}  # an unreadable baseline degrades to "no comparison", not a failure
    return data if isinstance(data, dict) else {}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--catalog", type=pathlib.Path, default=CATALOG_PATH)
    ap.add_argument(
        "--baseline", type=pathlib.Path, help="previous run's baseline JSON"
    )
    ap.add_argument(
        "--write-baseline", type=pathlib.Path, help="write this run's baseline here"
    )
    ap.add_argument(
        "--status-out", type=pathlib.Path, help="write 'clean' or 'findings' here"
    )
    args = ap.parse_args(argv)
    try:
        catalog = json.loads(args.catalog.read_text())
        parser = load_parser(PARSER_PATH)
        report = run_check(catalog, parser, http_fetch, load_baseline(args.baseline))
    except Exception as exc:  # noqa: BLE001 -- anything here means "could not evaluate"
        print(
            f"check_blocklist_catalog: could not run: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2
    # The full report goes to stderr (the workflow log); stdout is the bounded
    # one that becomes the issue body.
    print(render_markdown(report, max_bytes=sys.maxsize), file=sys.stderr)
    print(render_markdown(report))
    if args.write_baseline:
        args.write_baseline.write_text(baseline_json(report))
    if args.status_out:
        args.status_out.write_text("findings" if report.findings else "clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

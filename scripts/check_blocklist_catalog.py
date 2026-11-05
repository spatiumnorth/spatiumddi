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

The baseline (entry counts of the last run) is NOT kept in the repo, so the
repo does not churn. The workflow passes the previous run's artifact in with
``--baseline`` and uploads ``--write-baseline`` for the next one.

Exit codes: 0 always, including when there are findings (they go to the
tracking issue, not to a red CI run); 2 when the check itself could not run
(catalog unreadable, parser unloadable, or every feed AND the registry failed,
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
from unittest import mock

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "backend" / "app" / "data" / "dns_blocklist_catalog.json"
PARSER_PATH = REPO_ROOT / "backend" / "app" / "services" / "dns_blocklist.py"

# Generic: names the tool and the project, no person.
USER_AGENT = "spatiumddi-blocklist-catalog-check/1 (+https://github.com/spatiumnorth/spatiumddi)"
REGISTRY_URL = "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json"
FETCH_TIMEOUT = 60
MAX_BYTES = 150 * 1024 * 1024

# An entry count under this is "something is wrong with the feed" for any list
# in the catalog; the smallest healthy one carries thousands. Override per
# source id below when a list is legitimately small.
GLOBAL_FLOOR = 500
PER_SOURCE_FLOOR: dict[str, int] = {
    # A short, curated list of search-engine hostnames: ~200 entries is healthy.
    "hagezi-nosafesearch": 50,
}
# HostlistsRegistry filterKeys reviewed and declined as catalog additions, so
# they stop being re-reported every month. Add a key here with a reason.
IGNORED_UPSTREAM: dict[str, str] = {}
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


def load_parser() -> types.ModuleType:
    """Load ``backend/app/services/dns_blocklist.py`` without the app.

    The module imports SQLAlchemy and the ORM models at the top for code the
    parser does not use. Importing the real ones would need the backend's
    dependencies and settings; the parser functions touch none of it, so those
    imports are stubbed for the duration of the load. The parser stays the
    product's own code, loaded from source, never copied.
    """
    stubs = {
        name: mock.MagicMock()
        for name in (
            "sqlalchemy",
            "sqlalchemy.ext",
            "sqlalchemy.ext.asyncio",
            "sqlalchemy.orm",
            "app.models",
            "app.models.dns",
        )
    }
    spec = importlib.util.spec_from_file_location("_spatium_dns_blocklist", PARSER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {PARSER_PATH}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules[cls.__module__],
    # so the module must be registered while it executes.
    stubs[module.__name__] = module
    with mock.patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    for name in ("parse_feed_detailed", "ParsedFeed"):
        if not hasattr(module, name):
            raise RuntimeError(f"{PARSER_PATH} no longer defines {name}")
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
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:  # noqa: S310
                raw = resp.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    return Fetched(error=f"larger than {MAX_BYTES // (1024 * 1024)} MiB")
                ctype = resp.headers.get("Content-Type", "")
                return Fetched(text=raw.decode("utf-8", errors="replace"), content_type=ctype)
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
    return head.startswith(("<!doctype html", "<html")) or "<html" in head or "<body" in head


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
        return [Finding("dead", sid, f"`{url}` -- {fetched.error or 'no content'}")], None
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
    entries = len(parsed.domains)
    skipped = sum(parsed.skipped.as_dict().values()) if parsed.skipped is not None else 0
    measured = Measured(entries=entries, skipped=skipped)
    findings: list[Finding] = []

    # Declared format vs the others: a feed that switched syntax parses to ~0
    # under the old declaration while another declaration reads it fine.
    alternatives = {
        alt: len(parser.parse_feed_detailed(text, alt).domains) for alt in ALL_FORMATS if alt != fmt
    }
    best_alt, best_n = max(alternatives.items(), key=lambda kv: kv[1])
    if entries == 0 and best_n == 0:
        findings.append(
            Finding(
                "unparseable",
                sid,
                f"`feed_format: {fmt}` yields 0 entries and so does every other format "
                f"({len(text):,} bytes fetched)",
            )
        )
    elif best_n >= GLOBAL_FLOOR and entries < best_n * FORMAT_MISMATCH_RATIO:
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
    if entries < floor and not (entries == 0 and findings):
        findings.append(
            Finding("shrunken", sid, f"{entries:,} entries, below the floor of {floor:,}")
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

    prev_share = Measured(prev["entries"], prev.get("skipped", 0)).skip_share if prev else 0.0
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
    return url.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")


def diff_registry(catalog_sources: list[dict[str, Any]], registry: dict[str, Any]) -> list[Finding]:
    """New upstream lists, and catalog entries the registry deprecated."""
    filters = registry.get("filters")
    if not isinstance(filters, list) or not filters:
        raise ValueError("registry document carries no 'filters' list")
    by_url: dict[str, dict[str, Any]] = {}
    for f in filters:
        for key in ("subscriptionUrl", "downloadUrl"):
            if f.get(key):
                by_url[_norm_url(f[key])] = f
    catalog_urls = {_norm_url(s["feed_url"]) for s in catalog_sources}
    catalog_homepages = {_norm_url(s["homepage"]) for s in catalog_sources if s.get("homepage")}

    findings: list[Finding] = []
    for s in catalog_sources:
        hit = by_url.get(_norm_url(s["feed_url"]))
        if hit is not None and hit.get("deprecated"):
            findings.append(
                Finding(
                    "upstream_retired",
                    s["id"],
                    f"AdGuard's registry lists '{hit.get('name')}' as deprecated "
                    f"(`{hit.get('filterKey')}`)",
                )
            )
    for f in filters:
        if f.get("deprecated") or f.get("filterKey") in IGNORED_UPSTREAM:
            continue
        urls = {_norm_url(f[k]) for k in ("subscriptionUrl", "downloadUrl") if f.get(k)}
        if urls & catalog_urls:
            continue
        if f.get("homepage") and _norm_url(f["homepage"]) in catalog_homepages:
            continue  # same project, a different variant URL: already represented
        findings.append(
            Finding(
                "upstream_new",
                str(f.get("filterKey", "?")),
                f"**{f.get('name')}** -- {f.get('homepage', '')} -- "
                f"`{f.get('subscriptionUrl') or f.get('downloadUrl')}`",
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
    for source in sources:
        fetched = fetch(source["feed_url"])
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
            report.findings.extend(diff_registry(sources, json.loads(registry_fetch.text)))
        except (ValueError, TypeError, AttributeError) as exc:
            report.registry_ok = False
            report.findings.append(
                Finding("upstream_new", "registry", f"could not read the registry document: {exc}")
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


def render_markdown(report: Report) -> str:
    lines = [MARKER, "# Blocklist catalog check", ""]
    if not report.findings:
        lines.append(f"All {report.checked} feeds fetched, parsed and sized as expected.")
    else:
        lines.append(
            f"Checked {report.checked} feeds in `backend/app/data/dns_blocklist_catalog.json` "
            "against the product's own parser. The catalog is never edited by this check."
        )
        for kind, title in SECTIONS:
            rows = [f for f in report.findings if f.kind == kind]
            if not rows:
                continue
            lines += ["", f"## {title} ({len(rows)})", ""]
            lines += [f"- `{f.source}`: {f.message}" for f in rows]
    if not report.registry_ok:
        lines += ["", "_The AdGuard registry could not be fetched or read this run._"]
    lines += ["", "<details><summary>Entry counts this run</summary>", ""]
    lines += ["| source | entries | skipped |", "|---|---:|---:|"]
    for sid, m in sorted(report.measured.items()):
        lines.append(f"| `{sid}` | {m.entries:,} | {m.skipped:,} |")
    lines += ["", "</details>", ""]
    return "\n".join(lines)


def baseline_json(report: Report) -> str:
    return json.dumps(
        {sid: {"entries": m.entries, "skipped": m.skipped} for sid, m in report.measured.items()},
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
    ap.add_argument("--baseline", type=pathlib.Path, help="previous run's baseline JSON")
    ap.add_argument("--write-baseline", type=pathlib.Path, help="write this run's baseline here")
    ap.add_argument("--status-out", type=pathlib.Path, help="write 'clean' or 'findings' here")
    args = ap.parse_args(argv)
    try:
        catalog = json.loads(args.catalog.read_text())
        parser = load_parser()
        report = run_check(catalog, parser, http_fetch, load_baseline(args.baseline))
    except Exception as exc:  # noqa: BLE001 -- anything here means "could not evaluate"
        print(
            f"check_blocklist_catalog: could not run: {type(exc).__name__}: {exc}", file=sys.stderr
        )
        return 2
    print(render_markdown(report))
    if args.write_baseline:
        args.write_baseline.write_text(baseline_json(report))
    if args.status_out:
        args.status_out.write_text("findings" if report.findings else "clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

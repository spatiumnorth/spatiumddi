"""The monthly blocklist-catalog feed check (#3522).

``scripts/check_blocklist_catalog.py`` fetches every catalog feed and reports
dead / HTML / reformatted / shrunken feeds and the diff against AdGuard's
registry. These tests inject a fake fetch, so nothing touches the network, and
parse with the product's real parser (loaded by the script itself).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "check_blocklist_catalog.py"

# The dev container copies only ``backend/`` into the image: skips there.
pytestmark = pytest.mark.skipif(
    not _SCRIPT.exists(), reason="catalog check script not present in this checkout"
)


@pytest.fixture(scope="module")
def chk() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("check_blocklist_catalog", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def parser(chk: types.ModuleType) -> types.ModuleType:
    return chk.load_parser()


def _hosts(n: int) -> str:
    return "\n".join(f"0.0.0.0 host{i}.example.net" for i in range(n))


def _domains(n: int) -> str:
    return "\n".join(f"d{i}.example.org" for i in range(n))


def _src(sid: str, fmt: str = "hosts") -> dict:
    return {
        "id": sid,
        "feed_url": f"https://feeds.test/{sid}",
        "feed_format": fmt,
        "homepage": f"https://home.test/{sid}",
    }


def _run(chk, parser, sources, pages, baseline=None, registry=None):
    def fetch(url: str):
        if url == chk.REGISTRY_URL:
            return chk.Fetched(text=json.dumps(registry or {"filters": [{"filterKey": "x"}]}))
        page = pages[url.rsplit("/", 1)[1]]
        if isinstance(page, str):
            return chk.Fetched(text=page, content_type="text/plain")
        return page

    return chk.run_check({"sources": sources}, parser, fetch, baseline)


def _kinds(report) -> dict[tuple[str, str], str]:
    return {(f.kind, f.source): f.message for f in report.findings}


def test_healthy_feed_is_clean(chk, parser) -> None:
    rep = _run(chk, parser, [_src("ok")], {"ok": _hosts(1000)})
    assert [f for f in rep.findings if not f.kind.startswith("upstream")] == []
    assert rep.measured["ok"].entries == 1000


def test_dead_url_is_flagged(chk, parser) -> None:
    rep = _run(chk, parser, [_src("gone")], {"gone": chk.Fetched(error="HTTP 410")})
    assert ("dead", "gone") in _kinds(rep)
    assert "HTTP 410" in _kinds(rep)[("dead", "gone")]
    assert "gone" not in rep.measured


def test_html_page_is_flagged_not_parsed(chk, parser) -> None:
    html = "<!DOCTYPE html><html><body>Moved</body></html>" + _hosts(1000)
    rep = _run(chk, parser, [_src("page")], {"page": html})
    assert ("not_a_list", "page") in _kinds(rep)
    assert not [f for f in rep.findings if f.kind in ("shrunken", "unparseable")]


def test_below_floor_is_flagged(chk, parser) -> None:
    rep = _run(chk, parser, [_src("tiny")], {"tiny": _hosts(10)})
    assert ("shrunken", "tiny") in _kinds(rep)


def test_per_source_floor_overrides_global(chk, parser) -> None:
    rep = _run(
        chk,
        parser,
        [_src("hagezi-nosafesearch", "domains")],
        {"hagezi-nosafesearch": _domains(201)},
    )
    assert ("shrunken", "hagezi-nosafesearch") not in _kinds(rep)


def test_shrunk_against_baseline_is_flagged(chk, parser) -> None:
    base = {"big": {"entries": 5000, "skipped": 0}}
    rep = _run(chk, parser, [_src("big")], {"big": _hosts(1000)}, baseline=base)
    assert "down from 5,000" in _kinds(rep)[("shrunken", "big")]
    # Without a baseline the same feed is fine.
    assert ("shrunken", "big") not in _kinds(
        _run(chk, parser, [_src("big")], {"big": _hosts(1000)})
    )


def test_format_that_no_longer_parses_is_flagged(chk, parser) -> None:
    # Declared adblock, but the feed now publishes hosts lines: the adblock
    # parser skips every line while the hosts parser reads them all.
    rep = _run(chk, parser, [_src("moved", "adblock")], {"moved": _hosts(1000)})
    assert ("unparseable", "moved") in _kinds(rep)
    assert "hosts" in _kinds(rep)[("unparseable", "moved")]


def test_garbage_that_parses_in_no_format(chk, parser) -> None:
    rep = _run(chk, parser, [_src("junk")], {"junk": "# nothing here\n! at all\n"})
    assert ("unparseable", "junk") in _kinds(rep)
    assert ("shrunken", "junk") not in _kinds(rep)  # reported once, not twice


def test_skip_share_rising_is_flagged(chk, parser) -> None:
    rules = [f"||ok{i}.example.com^" for i in range(1000)] + [f"/re{i}/" for i in range(600)]
    page = "\n".join(rules)
    assert ("skipped", "ab") in _kinds(_run(chk, parser, [_src("ab", "adblock")], {"ab": page}))
    # A healthy adblock feed (no skips) is not flagged.
    ok = "\n".join(f"||ok{i}.example.com^" for i in range(1000))
    assert ("skipped", "ab") not in _kinds(_run(chk, parser, [_src("ab", "adblock")], {"ab": ok}))


def test_upstream_diff(chk, parser) -> None:
    registry = {
        "filters": [
            {
                "filterId": 901,
                "filterKey": "have",
                "name": "Have",
                "subscriptionUrl": "https://feeds.test/have/",
            },
            {
                "filterId": 902,
                "filterKey": "new",
                "name": "New list",
                "subscriptionUrl": "https://other.test/n",
            },
            {
                "filterId": 903,
                "filterKey": "variant",
                "name": "Variant",
                "homepage": "https://home.test/have",
                "subscriptionUrl": "https://other.test/v",
            },
            {
                "filterId": 904,
                "filterKey": "dead",
                "name": "Old",
                "deprecated": True,
                "subscriptionUrl": "https://feeds.test/old",
            },
            {
                "filterId": 905,
                "filterKey": "skip",
                "name": "Skip me",
                "deprecated": True,
                "subscriptionUrl": "https://z.test/z",
            },
        ]
    }
    srcs = [_src("have"), _src("old")]
    rep = _run(
        chk,
        parser,
        srcs,
        {"have": _hosts(1000), "old": _hosts(1000)},
        registry=registry,
    )
    kinds = _kinds(rep)
    assert ("upstream_new", "902 new") in kinds
    assert (
        "upstream_new",
        "901 have",
    ) not in kinds  # URL match, trailing slash ignored
    assert (
        "upstream_new",
        "903 variant",
    ) not in kinds  # its homepage is ours, and unique
    assert ("upstream_new", "905 skip") not in kinds  # deprecated and not ours
    assert ("upstream_retired", "old") in kinds


def test_shared_homepage_does_not_hide_new_lists(chk, parser) -> None:
    # HaGeZi publishes many registry lists under one homepage. The catalog
    # carrying one of them must not hide a newly published sibling.
    hp = "https://github.com/hagezi/dns-blocklists"
    registry = {
        "filters": [
            {
                "filterId": 911,
                "filterKey": "hz_a",
                "name": "A",
                "homepage": hp,
                "downloadUrl": "https://reg.test/911.txt",
            },
            {
                "filterId": 912,
                "filterKey": "hz_b",
                "name": "B",
                "homepage": hp,
                "downloadUrl": "https://reg.test/912.txt",
            },
        ]
    }
    src = dict(_src("hz"), homepage=hp)
    rep = _run(chk, parser, [src], {"hz": _hosts(1000)}, registry=registry)
    assert ("upstream_new", "911 hz_a") in _kinds(rep)
    assert ("upstream_new", "912 hz_b") in _kinds(rep)


def test_covered_mapping_counts_only_when_the_source_exists(chk, parser, monkeypatch) -> None:
    monkeypatch.setattr(chk, "COVERED_UPSTREAM", {921: "mapped", 922: "not-in-catalog"})
    registry = {
        "filters": [
            {
                "filterId": 921,
                "filterKey": "m",
                "name": "M",
                "downloadUrl": "https://reg.test/1",
                "deprecated": True,
            },
            {
                "filterId": 922,
                "filterKey": "n",
                "name": "N",
                "downloadUrl": "https://reg.test/2",
            },
        ]
    }
    rep = _run(chk, parser, [_src("mapped")], {"mapped": _hosts(1000)}, registry=registry)
    kinds = _kinds(rep)
    assert ("upstream_retired", "mapped") in kinds  # deprecation follows the mapping
    assert (
        "upstream_new",
        "922 n",
    ) in kinds  # mapped to an absent source: still reported


def test_ignored_upstream_is_keyed_by_filter_id(chk, parser) -> None:
    assert chk.IGNORED_UPSTREAM[49]  # HaGeZi Ultimate, declined in #3521
    assert list(chk.IGNORED_UPSTREAM) == sorted(chk.IGNORED_UPSTREAM)
    assert not set(chk.IGNORED_UPSTREAM) & set(chk.COVERED_UPSTREAM)
    registry = {
        "filters": [
            {
                "filterId": 49,
                "filterKey": "hagezi_ultimate",
                "name": "U",
                "downloadUrl": "https://reg.test/49",
            },
        ]
    }
    rep = _run(chk, parser, [_src("a")], {"a": _hosts(1000)}, registry=registry)
    assert not [f for f in rep.findings if f.kind == "upstream_new"]


def test_registry_text_cannot_mention_or_format(chk, parser) -> None:
    registry = {
        "filters": [
            {
                "filterId": 931,
                "filterKey": "x",
                "name": "@someone `**bold**`",
                "downloadUrl": "https://reg.test/x",
            },
        ]
    }
    md = chk.render_markdown(_run(chk, parser, [_src("a")], {"a": _hosts(1000)}, registry=registry))
    line = next(ln for ln in md.splitlines() if "someone" in ln)
    # The name sits inside one code span, so GitHub renders it literally.
    assert "`@someone '**bold**'`" in line


def test_report_is_bounded_with_a_note(chk) -> None:
    rep = chk.Report(checked=1)
    rep.findings = [chk.Finding("upstream_new", f"{i} key{i}", "x" * 300) for i in range(2000)]
    rep.measured = {f"s{i}": chk.Measured(1000) for i in range(500)}
    md = chk.render_markdown(rep)
    assert len(md.encode()) <= chk.MAX_REPORT_BYTES
    assert md.startswith(chk.MARKER)
    assert "more, not shown" in md
    assert md.rstrip().endswith("</details>")
    # Unbounded, nothing is cut.
    assert "not shown" not in chk.render_markdown(rep, max_bytes=10**9)


def test_one_fetch_per_url(chk, parser) -> None:
    calls: list[str] = []

    def fetch(url):
        calls.append(url)
        if url == chk.REGISTRY_URL:
            return chk.Fetched(text=json.dumps({"filters": [{"filterId": 1}]}))
        return chk.Fetched(text=_hosts(1000))

    a, b = _src("a"), dict(_src("b"), feed_url="https://feeds.test/a")
    chk.run_check({"sources": [a, b]}, parser, fetch)
    assert calls.count("https://feeds.test/a") == 1
    assert calls.count(chk.REGISTRY_URL) == 1


def test_malformed_baseline_row_is_ignored(chk, parser) -> None:
    rep = _run(chk, parser, [_src("ok")], {"ok": _hosts(1000)}, baseline={"ok": "junk"})
    assert ("shrunken", "ok") not in _kinds(rep)
    rep = _run(chk, parser, [_src("ok")], {"ok": _hosts(1000)}, baseline={"ok": {}})
    assert rep.measured["ok"].entries == 1000


def test_parser_loads_from_the_real_tree_with_nothing_stubbed(chk) -> None:
    # The real module, through the same loader the workflow uses: it must
    # import only the standard library. If it ever gains an app or
    # third-party import, this fails here instead of the monthly job.
    import subprocess
    import sys

    code = (
        "import sys, importlib.util; "
        f"spec = importlib.util.spec_from_file_location('c', {str(_SCRIPT)!r}); "
        "m = importlib.util.module_from_spec(spec); sys.modules['c'] = m; "
        "spec.loader.exec_module(m); p = m.load_parser(); "
        "print(len(p.parse_feed('0.0.0.0 a.example', 'hosts'))); "
        "print(sorted(k for k in sys.modules if k.split('.')[0] in ('app', 'sqlalchemy')))"
    )
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    ).stdout.split("\n")
    assert out[0] == "1"
    assert out[1] == "[]"


def test_parser_is_the_one_the_app_uses(chk, parser) -> None:
    # dns_blocklist.py re-exports the same functions the script loads.
    text = (_REPO_ROOT / "backend/app/services/dns_blocklist.py").read_text()
    assert "from app.services.dns_blocklist_parse import" in text
    assert chk.PARSER_PATH.name == "dns_blocklist_parse.py"


def test_unloadable_parser_exits_2(chk, tmp_path, monkeypatch, capsys) -> None:
    bad = tmp_path / "dns_blocklist_parse.py"
    bad.write_text("import sqlalchemy_that_is_not_here\n")
    monkeypatch.setattr(chk, "PARSER_PATH", bad)
    with pytest.raises(RuntimeError, match="standard library"):
        chk.load_parser(bad)

    def no_network(url):  # pragma: no cover - must not be reached
        raise AssertionError("fetched before the parser loaded")

    monkeypatch.setattr(chk, "http_fetch", no_network)
    assert chk.main(["--status-out", str(tmp_path / "s")]) == 2
    assert "could not run" in capsys.readouterr().err
    assert not (tmp_path / "s").exists()  # no status: the workflow leaves the issue alone


def test_registry_failure_is_noted_not_fatal(chk, parser) -> None:
    def fetch(url):
        if url == chk.REGISTRY_URL:
            return chk.Fetched(error="HTTP 503")
        return chk.Fetched(text=_hosts(1000))

    rep = chk.run_check({"sources": [_src("a")]}, parser, fetch)
    assert rep.registry_ok is False
    assert "could not be fetched" in chk.render_markdown(rep)


def test_total_network_failure_is_a_script_error(chk, parser) -> None:
    with pytest.raises(RuntimeError):
        chk.run_check({"sources": [_src("a")]}, parser, lambda url: chk.Fetched(error="timed out"))


def test_empty_catalog_is_a_script_error(chk, parser) -> None:
    with pytest.raises(ValueError):
        chk.run_check({"sources": []}, parser, lambda url: chk.Fetched(text=""))


def test_markdown_marker_and_baseline_roundtrip(chk, parser, tmp_path) -> None:
    rep = _run(chk, parser, [_src("ok")], {"ok": _hosts(1000)})
    md = chk.render_markdown(rep)
    assert md.startswith(chk.MARKER)  # the workflow matches the issue on this
    f = tmp_path / "b.json"
    f.write_text(chk.baseline_json(rep))
    assert chk.load_baseline(f)["ok"]["entries"] == 1000
    assert chk.load_baseline(tmp_path / "missing.json") == {}


def test_every_real_catalog_source_has_a_known_format(chk) -> None:
    catalog = json.loads(chk.CATALOG_PATH.read_text())
    for s in catalog["sources"]:
        assert s["feed_format"] in chk.ALL_FORMATS, s["id"]
        assert s["feed_url"].startswith("https://"), s["id"]

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
            {"filterKey": "have", "name": "Have", "subscriptionUrl": "https://feeds.test/have/"},
            {"filterKey": "new", "name": "New list", "subscriptionUrl": "https://other.test/n"},
            {
                "filterKey": "variant",
                "name": "Variant",
                "homepage": "https://home.test/have",
                "subscriptionUrl": "https://other.test/v",
            },
            {
                "filterKey": "dead",
                "name": "Old",
                "deprecated": True,
                "subscriptionUrl": "https://feeds.test/old",
            },
            {
                "filterKey": "skip",
                "name": "Skip me",
                "deprecated": True,
                "subscriptionUrl": "https://z.test/z",
            },
        ]
    }
    srcs = [_src("have"), _src("old")]
    rep = _run(chk, parser, srcs, {"have": _hosts(1000), "old": _hosts(1000)}, registry=registry)
    kinds = _kinds(rep)
    assert ("upstream_new", "new") in kinds
    assert ("upstream_new", "have") not in kinds  # URL match, trailing slash ignored
    assert ("upstream_new", "variant") not in kinds  # same homepage
    assert ("upstream_new", "skip") not in kinds  # deprecated and not ours
    assert ("upstream_retired", "old") in kinds


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

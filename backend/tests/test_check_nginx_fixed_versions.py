"""The nginx affected/fixed-version check (#4816).

``scripts/check_nginx_fixed_versions.py`` reads nginx.org's own list of
affected and fixed versions, because Trivy cannot see nginx.org's Alpine
packages. Tests run against a saved copy of the page
(``scripts/testdata/nginx_security_advisories.html``) so they are offline and
stable, and cover the failure shape that matters most: a page that cannot be
fetched or parsed must exit 3, never 0.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import types

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "check_nginx_fixed_versions.py"
_PAGE = _REPO_ROOT / "scripts" / "testdata" / "nginx_security_advisories.html"

# The dev container copies only ``backend/``; this runs for real in CI.
pytestmark = pytest.mark.skipif(
    not (_SCRIPT.exists() and _PAGE.exists()),
    reason="nginx check script not present in this checkout",
)


@pytest.fixture(scope="module")
def chk() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("check_nginx_fixed_versions", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    path = tmp_path / "versions.json"
    path.write_text(json.dumps({"components": {"nginx": {"version": version}}}))
    return path


def _run(chk: types.ModuleType, tmp_path: pathlib.Path, version: str, page: pathlib.Path) -> int:
    return int(chk.run(_manifest(tmp_path, version), chk.PAGE_URL, page))


def test_pin_inside_affected_range_exits_1(chk, tmp_path, capsys) -> None:
    assert _run(chk, tmp_path, "1.31.8-alpine", _PAGE) == 1
    out = capsys.readouterr().out
    assert "1.31.8" in out and "RESULT affected=" in out


def test_pin_at_or_past_every_fix_exits_0(chk, tmp_path) -> None:
    assert _run(chk, tmp_path, "1.31.10-alpine", _PAGE) == 0
    assert _run(chk, tmp_path, "1.30.8-alpine", _PAGE) == 0


def test_stable_branch_fix_covers_only_its_branch(chk) -> None:
    # "Not vulnerable: 1.31.10+, 1.30.8+"
    assert chk.in_affected((1, 30, 7), "1.21.4-1.31.9")
    assert not chk.is_fixed((1, 30, 7), "1.31.10+, 1.30.8+")
    assert chk.is_fixed((1, 30, 8), "1.31.10+, 1.30.8+")
    assert chk.is_fixed((1, 30, 9), "1.31.10+, 1.30.8+")
    # The pin is on the mainline branch, below the mainline fix.
    assert not chk.is_fixed((1, 31, 9), "1.31.10+, 1.30.8+")
    assert chk.is_fixed((1, 31, 10), "1.31.10+, 1.30.8+")
    # A newer mainline release is covered by the newest term.
    assert chk.is_fixed((1, 32, 0), "1.31.10+, 1.30.8+")
    # A branch with no term of its own is not covered by a stable term.
    assert not chk.is_fixed((1, 29, 9), "1.31.10+, 1.30.8+")


def test_plus_ranges_and_terms(chk) -> None:
    assert chk.is_fixed((1, 9, 10), "1.9.10+, 1.8.1+")
    assert chk.is_fixed((1, 8, 5), "1.9.10+, 1.8.1+")
    assert not chk.is_fixed((1, 8, 0), "1.9.10+, 1.8.1+")
    assert not chk.is_fixed((1, 31, 8), "none")
    assert chk.in_affected((9, 9, 9), "all")
    assert chk.in_affected((1, 26, 0), "1.25.0-1.25.5, 1.26.0")
    assert not chk.in_affected((1, 26, 1), "1.25.0-1.25.5, 1.26.0")
    assert chk.in_affected((1, 25, 5), "1.25.0-1.25.5")
    assert not chk.in_affected((1, 25, 6), "1.25.0-1.25.5")
    # A build for another platform is not the pinned image.
    assert not chk.in_affected((1, 2, 0), "nginx/Windows 0.7.52-1.3.0")


def test_two_ranges_one_entry(chk) -> None:
    text = "1.31.2-1.31.6, 1.30.0-1.30.5"
    assert chk.in_affected((1, 30, 5), text)
    assert chk.in_affected((1, 31, 4), text)
    assert not chk.in_affected((1, 31, 7), text)


def test_unparseable_page_exits_3(chk, tmp_path, capsys) -> None:
    page = tmp_path / "page.html"
    page.write_text("<html><body>maintenance</body></html>")
    assert _run(chk, tmp_path, "1.31.8-alpine", page) == 3
    assert "could not check" in capsys.readouterr().err


def test_fetch_failure_exits_3(chk, tmp_path, monkeypatch) -> None:
    def boom(url: str, timeout: float = 30.0) -> str:
        raise chk.FetchError("network down")

    monkeypatch.setattr(chk, "fetch_page", boom)
    assert int(chk.run(_manifest(tmp_path, "1.31.8-alpine"), chk.PAGE_URL, None)) == 3


def test_unreadable_pin_exits_3(chk, tmp_path) -> None:
    assert _run(chk, tmp_path, "latest", _PAGE) == 3


def test_saved_page_parses_many_entries(chk) -> None:
    entries = chk.parse_page(_PAGE.read_text(encoding="utf-8"))
    assert len(entries) > 50


def test_rated_none_entry_is_not_reported(chk) -> None:
    entries = chk.parse_page(_PAGE.read_text(encoding="utf-8"))
    ancient = [e for e in entries if e.affected == "all" and e.fixed == "none"]
    assert ancient and ancient[0].severity == "none"
    assert ancient[0] not in chk.affecting((1, 31, 8), entries)

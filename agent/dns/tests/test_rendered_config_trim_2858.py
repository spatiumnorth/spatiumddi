"""#2858: the rendered-config push must fit the control plane's limits."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from spatium_dns_agent import admin_pusher as ap


def _tree(root: Path) -> Path:
    r = root / "rendered"
    (r / "zones").mkdir(parents=True)
    (r / "named.conf").write_text('options { directory "x"; };\n')
    (r / "tsig.conf").write_text("# other config\n")
    for i in range(40):  # 40 x 300 KB = ~12 MB of zone data
        (r / "zones" / f"z{i}.db").write_text(f"; zone {i}\n" + "a IN A 192.0.2.1\n" * 18000)
    return r


def test_payload_under_cap_and_marked(tmp_path):
    r = _tree(tmp_path)
    files = ap.trim_rendered_files(ap._walk_rendered(r))
    body = json.dumps({"files": files}).encode()
    assert len(body) < 8 * 1024 * 1024
    paths = {f["path"] for f in files}
    assert {"named.conf", "tsig.conf"} <= paths
    omit = next(f for f in files if f["path"] == ap._OMITTED_FILE)
    assert "zones/" in omit["content"]
    big = [f for f in files if f["path"].startswith("zones/")]
    assert big and all(len(f["content"]) <= ap.RENDERED_FILE_SIZE_MAX for f in big)
    assert any("[truncated by agent]" in f["content"] for f in big)


def test_small_tree_untouched(tmp_path):
    r = tmp_path / "rendered"
    r.mkdir()
    (r / "named.conf").write_text("x\n")
    files = ap.trim_rendered_files(ap._walk_rendered(r))
    assert files == [{"path": "named.conf", "content": "x\n"}]


def test_binary_still_skipped(tmp_path):
    r = tmp_path / "rendered"
    r.mkdir()
    (r / "named.conf").write_text("x\n")
    (r / "weird").write_text("a\x00b")
    assert [f["path"] for f in ap.trim_rendered_files(ap._walk_rendered(r))] == ["named.conf"]


def test_limits_match_backend():
    src = Path(__file__).resolve().parents[3] / "backend/app/api/v1/dns/agents.py"
    if not src.exists():
        pytest.skip("backend not mounted")
    text = src.read_text()
    assert eval(re.search(r"_RENDERED_FILE_SIZE_MAX = (.+?)\s*#", text).group(1)) == (
        ap.RENDERED_FILE_SIZE_MAX
    )
    assert eval(re.search(r"_RENDERED_TOTAL_SIZE_MAX = (.+?)\s*#", text).group(1)) == (
        ap.RENDERED_TOTAL_SIZE_MAX
    )

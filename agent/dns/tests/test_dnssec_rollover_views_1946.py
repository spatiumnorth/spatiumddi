"""A manual rollover reaches every view that holds the zone (#1946).

Under split-horizon BIND loads the zone once per view, and a bare
``rndc dnssec -rollover -key N <zone>`` fails with "zone was found in multiple
views" (verified against BIND 9.20). The agent addresses each view instead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver


class _Res:
    def __init__(self, rc: int = 0, err: str = "") -> None:
        self.returncode = rc
        self.stdout = ""
        self.stderr = err


def _driver(tmp_path: Path, monkeypatch, calls: list[list[str]], fail_view: str | None = None):
    def run(cmd: list[str], *a: Any, **kw: Any) -> _Res:
        calls.append(cmd)
        if fail_view and cmd[-1] == fail_view:
            return _Res(1, "boom")
        return _Res()

    monkeypatch.setattr("spatium_dns_agent.drivers.bind9.shutil.which", lambda name: "/usr/sbin/rndc")
    monkeypatch.setattr("spatium_dns_agent.drivers.bind9.subprocess.run", run)
    monkeypatch.setattr("spatium_dns_agent.drivers.bind9._parse_dnssec_status", lambda text: [])
    monkeypatch.setattr("spatium_dns_agent.drivers.bind9._ds_from_key_dir", lambda zone, key_dir: [])
    d = Bind9Driver.__new__(Bind9Driver)
    d.state_dir = tmp_path
    monkeypatch.setattr(d, "_rndc_base", lambda: ["rndc"], raising=False)
    return d


def _render(tmp_path: Path, files: list[str]) -> None:
    for rel in files:
        p = tmp_path / "rendered" / "zones" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")


_OP = {"op": "dnssec_rollover", "zone_name": "ex.test.", "record": {"key_tag": 11437}}


def test_rollover_in_every_view_that_holds_the_zone(tmp_path: Path, monkeypatch) -> None:
    _render(tmp_path, ["internal/ex.test.db", "external/ex.test.db", "external/other.test.db"])
    calls: list[list[str]] = []
    d = _driver(tmp_path, monkeypatch, calls)
    d._dnssec_rollover(dict(_OP))
    rolls = [c for c in calls if "-rollover" in c]
    assert sorted(c[-3:] for c in rolls) == [
        ["ex.test", "IN", "external"],
        ["ex.test", "IN", "internal"],
    ]
    # The follow-up status read names a view too; a bare name is ambiguous.
    status = [c for c in calls if "-status" in c]
    assert status and status[0][-2] == "IN"


def test_rollover_without_views_uses_the_bare_zone(tmp_path: Path, monkeypatch) -> None:
    _render(tmp_path, ["ex.test.db"])
    calls: list[list[str]] = []
    d = _driver(tmp_path, monkeypatch, calls)
    d._dnssec_rollover(dict(_OP))
    rolls = [c for c in calls if "-rollover" in c]
    assert rolls == [["rndc", "dnssec", "-rollover", "-key", "11437", "ex.test"]]


def test_a_view_that_refuses_fails_the_op(tmp_path: Path, monkeypatch) -> None:
    _render(tmp_path, ["internal/ex.test.db", "external/ex.test.db"])
    calls: list[list[str]] = []
    d = _driver(tmp_path, monkeypatch, calls, fail_view="external")
    with pytest.raises(RuntimeError, match="external"):
        d._dnssec_rollover(dict(_OP))

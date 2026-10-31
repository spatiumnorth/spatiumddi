"""#2942 — a TTL of 0 is a value, not "missing", in the agent's apex paths.

``x or default`` read 0 as unset. Only ``None`` falls back.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.drivers.technitium import TechnitiumDriver

from .test_technitium_render import _seed_token


class _Resp:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


def _technitium(tmp_path: Path, calls: list[dict[str, Any]]) -> TechnitiumDriver:
    d = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(d)
    records = [
        {
            "name": "example.com",
            "type": "SOA",
            "ttl": 900,
            "rData": {
                "primaryNameServer": "ns1.example.com",
                "responsiblePerson": "h.example.com",
                "serial": 1,
                "refresh": 1,
                "retry": 1,
                "expire": 1,
                "minimum": 1,
            },
        },
        {
            "name": "example.com",
            "type": "NS",
            "ttl": 900,
            "rData": {"nameServer": "ns1.example.com"},
        },
    ]

    def call(
        token: str,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        **_k: Any,
    ):
        if path == "zones/records/get":
            return _Resp({"status": "ok", "response": {"records": records}})
        calls.append({"path": path, **(params or {})})
        return _Resp({"status": "ok"})

    d._call = call  # type: ignore[method-assign,assignment]
    return d


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, None), (600, 600)])
def test_technitium_apex_soa_ttl(tmp_path: Path, ttl: int | None, expected: int | None) -> None:
    calls: list[dict[str, Any]] = []
    d = _technitium(tmp_path, calls)
    d._reconcile_zone_apex("tok", "example.com", {"ttl": ttl, "ns": ["ns1.example.com"]})
    soa = [c for c in calls if c.get("type") == "SOA"]
    if expected is None:
        assert soa == []  # nothing declared: the live SOA is left alone
    else:
        assert [c["ttl"] for c in soa] == [expected]


def test_technitium_apex_new_ns_ttl_zero(tmp_path: Path) -> None:
    calls: list[dict[str, Any]] = []
    d = _technitium(tmp_path, calls)
    d._reconcile_zone_apex("tok", "example.com", {"ttl": 0, "ns": ["ns2.example.com"]})
    added = [c for c in calls if c["path"] == "zones/records/add" and c.get("type") == "NS"]
    assert [c["ttl"] for c in added] == [0]


class _Upd:
    def __init__(self) -> None:
        self.added: list[tuple[Any, ...]] = []

    def add(self, *a: Any) -> None:
        self.added.append(a)

    def delete(self, *a: Any) -> None:  # pragma: no cover - not under test
        pass


@pytest.mark.parametrize(("ttl", "expected"), [(0, 0), (None, 3600), (120, 120)])
def test_bind9_apex_fallback_ns_ttl(tmp_path: Path, ttl: int | None, expected: int) -> None:
    d = Bind9Driver(state_dir=tmp_path)
    d._apex_overlay = {  # type: ignore[attr-defined]
        "example.com": {"name": "example.com.", "ns": ["ns9.example.com."], "ttl": ttl}
    }
    d._served_apex_ns = lambda zone: None  # type: ignore[method-assign]
    upd = _Upd()
    # Deleting the last declared NS makes the render fall back to the
    # placeholder NS + glue; both must carry the zone's TTL.
    d._reconcile_apex(upd, "example.com", "@", "NS", [])
    assert upd.added, "expected the fallback NS and glue to be added"
    assert {a[1] for a in upd.added} == {expected}

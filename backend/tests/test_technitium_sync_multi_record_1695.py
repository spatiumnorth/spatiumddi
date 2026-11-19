"""#1695: two records of one type at one name, both missing from a
``technitium_api`` server, are both put back by Sync with Servers, and stay.

Each pushed change carries the complete desired set (stamped since #1760) and
the driver replays it with only member 0 overwriting, so neither push erases
the other. A regression guard: this already holds on main.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.drivers.dns.base import RecordChangeResult, RecordData
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from app.models.dns import DNSRecord, DNSZone
from app.services.dns.pull_from_server import _additive_push
from app.services.technitium.rdata import record_params

_ZONE = "example.com."


def _zone() -> DNSZone:
    return DNSZone(id=uuid.uuid4(), name=_ZONE, group_id=uuid.uuid4())


def _row(zone: DNSZone, name: str, rtype: str, value: str, **kw: Any) -> DNSRecord:
    fqdn = zone.name.rstrip(".") if name == "@" else f"{name}.{zone.name.rstrip('.')}"
    return DNSRecord(
        zone_id=zone.id, name=name, fqdn=fqdn, record_type=rtype, value=value, ttl=300, **kw
    )


class _FakeTechnitium:
    """The one Technitium rule that matters: ``overwrite=true`` clears the
    RRset at (domain, type) before the write."""

    _NOT_RDATA = {"domain", "zone", "type", "ttl", "overwrite"}

    def __init__(self) -> None:
        # (domain, type) -> the rdata params of each member, as sent.
        self.rrsets: dict[tuple[str, str], list[dict[str, Any]]] = {}

    async def call(self, client: Any, path: str, what: str, params: dict[str, Any]) -> Any:
        assert path == "zones/records/add"
        key = (params["domain"], params["type"])
        if params["overwrite"] == "true":
            self.rrsets[key] = []
        self.rrsets.setdefault(key, []).append(
            {k: v for k, v in params.items() if k not in self._NOT_RDATA}
        )
        return {}


class _Session:
    def __init__(self, rows: list[DNSRecord]) -> None:
        self._rows = rows

    async def execute(self, _stmt: Any) -> Any:
        rows = self._rows
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))


class _ViaApiDriver:
    """The real ``technitium_api`` record writer behind a fake daemon."""

    def __init__(self, daemon: _FakeTechnitium, monkeypatch: pytest.MonkeyPatch) -> None:
        self.api = TechnitiumAPIDriver()
        monkeypatch.setattr(TechnitiumAPIDriver, "_call", lambda s, *a: daemon.call(*a))
        monkeypatch.setattr(TechnitiumAPIDriver, "_client", lambda *a, **k: _Ctx())
        monkeypatch.setattr(
            TechnitiumAPIDriver,
            "_load_credentials",
            lambda self, server: {"api_url": "https://t.test", "api_token": "t"},
        )

    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A", "TXT"]}

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        out = []
        for c in changes:
            await self.api.apply_record_change(server, c)
            out.append(RecordChangeResult(ok=True, change=c))
        return out


class _Ctx:
    async def __aenter__(self) -> _Ctx:
        return self

    async def __aexit__(self, *a: Any) -> bool:
        return False


@pytest.mark.parametrize(
    ("rtype", "values"),
    [
        ("A", ["192.0.2.1", "192.0.2.2"]),
        # The issue's own shape: two TXT strings at one name.
        ("TXT", ['"qa1613 one"', '"qa1613 two"']),
    ],
)
async def test_two_missing_records_at_one_name_both_land_and_stay(
    monkeypatch: pytest.MonkeyPatch, rtype: str, values: list[str]
) -> None:
    zone = _zone()
    rows = [_row(zone, "qa", rtype, v) for v in values]
    daemon = _FakeTechnitium()
    driver = _ViaApiDriver(daemon, monkeypatch)
    server = SimpleNamespace(id=uuid.uuid4(), driver="technitium_api")

    def _sent(value: str) -> dict[str, Any]:
        return record_params(rtype, value, origin=_ZONE.rstrip("."))

    # The daemon holds rdata params; read them back as the values they encode.
    by_params = {repr(sorted(_sent(v).items())): v for v in values}

    for _ in range(3):
        served = daemon.rrsets.get(("qa.example.com", rtype), [])
        wire = [
            RecordData(
                name="qa", record_type=rtype, value=by_params[repr(sorted(p.items()))], ttl=300
            )
            for p in served
        ]
        await _additive_push(
            _Session(rows),  # type: ignore[arg-type]
            server,
            driver,
            zone,
            wire,
            rows,
            apply=True,
        )
        assert sorted(
            by_params[repr(sorted(p.items()))] for p in daemon.rrsets[("qa.example.com", rtype)]
        ) == sorted(values)

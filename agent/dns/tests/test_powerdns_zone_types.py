"""PowerDNS agent zone types (#1521): kind / masters mapping + reconcile.

Before this, the driver created every zone as ``kind: Native`` and never
read ``masters``: a secondary served whatever the bundle carried (often
nothing) authoritatively instead of transferring, a zone converted
between types kept its original kind because the update path only
PATCHed rrsets, and a forward zone was dropped from the render with no
log line while its serial was still reported as live.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest
import structlog
import structlog.testing

from spatium_dns_agent.drivers import powerdns as powerdns_mod
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _pdns_masters


@contextmanager
def _capture() -> Iterator[structlog.testing.LogCapture]:
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        yield cap
    finally:
        structlog.reset_defaults()


def _render_zones(tmp_path: Path, zones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver.render({"zones": zones, "options": {}})
    return json.loads((tmp_path / "rendered.new" / "zones.json").read_text())


def _zone(name: str, ztype: str, **extra: Any) -> dict[str, Any]:
    zone: dict[str, Any] = {
        "name": name,
        "type": ztype,
        "ttl": 3600,
        "serial": 42,
        "records": [{"name": "www", "type": "A", "value": "192.0.2.1"}],
    }
    zone.update(extra)
    return zone


# ── render: type → kind / masters ───────────────────────────────────────────


def test_render_primary_is_native_with_records(tmp_path: Path) -> None:
    payload = _render_zones(tmp_path, [_zone("example.com", "primary")])
    assert payload[0]["kind"] == "Native"
    assert payload[0]["masters"] == []
    assert payload[0]["rrsets"], "primary zones ship their records"


def test_render_secondary_is_slave_with_masters_and_no_records(
    tmp_path: Path,
) -> None:
    """A secondary transfers its records; the bundle's copy is not shipped,
    so pdns can never serve it as a stale authoritative copy."""
    payload = _render_zones(
        tmp_path,
        [
            _zone(
                "example.com",
                "secondary",
                masters=["192.0.2.10", "192.0.2.11@5353"],
            )
        ],
    )
    assert payload[0]["kind"] == "Slave"
    # Bundle wire shape is ip@port; the PowerDNS API wants ip:port.
    assert payload[0]["masters"] == ["192.0.2.10", "192.0.2.11:5353"]
    assert payload[0]["rrsets"] == []


def test_render_stub_maps_to_slave(tmp_path: Path) -> None:
    """PowerDNS has no stub kind; a transferring secondary is the closest
    served equivalent — and unlike a forward zone it IS served."""
    payload = _render_zones(
        tmp_path, [_zone("example.com", "stub", masters=["192.0.2.10"])]
    )
    assert payload[0]["kind"] == "Slave"
    assert payload[0]["masters"] == ["192.0.2.10"]


def test_render_forward_zone_is_dropped_loudly(tmp_path: Path) -> None:
    with _capture() as cap:
        payload = _render_zones(tmp_path, [_zone("example.com", "forward")])
    assert payload == []
    events = [e["event"] for e in cap.entries]
    assert "powerdns_forward_zone_not_served" in events


def test_render_secondary_without_masters_is_skipped_loudly(tmp_path: Path) -> None:
    with _capture() as cap:
        payload = _render_zones(tmp_path, [_zone("example.com", "secondary")])
    assert payload == []
    events = [e["event"] for e in cap.entries]
    assert "powerdns_secondary_zone_no_masters_skipped" in events


def test_pdns_masters_drops_unusable_entries() -> None:
    assert _pdns_masters(["192.0.2.1", "not-an-ip", "192.0.2.2@abc", ""]) == [
        "192.0.2.1"
    ]
    assert _pdns_masters(["2001:db8::1@5353"]) == ["[2001:db8::1]:5353"]
    assert _pdns_masters(None) == []


# ── reconcile: create carries kind/masters, update PUTs drift ───────────────


class _Resp:
    def __init__(self, status: int = 200, body: Any = None) -> None:
        self.status_code = status
        self.text = ""
        self._body = body if body is not None else []

    def json(self) -> Any:
        return self._body


class _FakeClient:
    def __init__(self, calls: list, existing: Any) -> None:
        self._calls = calls
        self._existing = existing

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def get(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("GET", url, None))
        return _Resp(200, self._existing)

    def post(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("POST", url, json))
        return _Resp(201, {})

    def put(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("PUT", url, json))
        return _Resp(200, {})

    def patch(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self._calls.append(("PATCH", url, json))
        return _Resp(200, {})

    def delete(self, url: str, headers: Any = None) -> _Resp:
        self._calls.append(("DELETE", url, None))
        return _Resp(200, {})


def _install_fake_client(
    monkeypatch: pytest.MonkeyPatch, existing: Any
) -> list[tuple[str, str, Any]]:
    calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        powerdns_mod,
        "httpx",
        SimpleNamespace(Client=lambda **kw: _FakeClient(calls, existing)),
    )
    return calls


def test_reconcile_create_secondary_posts_kind_and_masters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _install_fake_client(monkeypatch, existing=[])
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver._reconcile_zones(
        "key",
        [
            {
                "name": "example.com.",
                "kind": "Slave",
                "masters": ["192.0.2.10"],
                "rrsets": [],
                "update_acl": [],
                "update_tsig_keys": [],
            }
        ],
    )
    posts = [c for c in calls if c[0] == "POST" and c[1].endswith("/zones")]
    assert posts and posts[0][2]["kind"] == "Slave"
    assert posts[0][2]["masters"] == ["192.0.2.10"]


def test_reconcile_update_puts_kind_when_type_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zone converted primary→secondary in the UI must convert on the
    server too; PATCHing rrsets alone left the old kind in place."""
    calls = _install_fake_client(
        monkeypatch,
        existing=[{"name": "example.com.", "kind": "Native", "masters": []}],
    )
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver._reconcile_zones(
        "key",
        [
            {
                "name": "example.com.",
                "kind": "Slave",
                "masters": ["192.0.2.10"],
                "rrsets": [],
                "update_acl": [],
                "update_tsig_keys": [],
            }
        ],
    )
    puts = [c for c in calls if c[0] == "PUT" and c[1].endswith("/zones/example.com.")]
    assert puts and puts[0][2]["kind"] == "Slave"
    assert puts[0][2]["masters"] == ["192.0.2.10"]


def test_reconcile_update_no_put_when_kind_and_masters_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _install_fake_client(
        monkeypatch,
        existing=[{"name": "example.com.", "kind": "Slave", "masters": ["192.0.2.10"]}],
    )
    driver = PowerDNSDriver(state_dir=tmp_path)
    driver._reconcile_zones(
        "key",
        [
            {
                "name": "example.com.",
                "kind": "Slave",
                "masters": ["192.0.2.10"],
                "rrsets": [],
                "update_acl": [],
                "update_tsig_keys": [],
            }
        ],
    )
    zone_puts = [
        c for c in calls if c[0] == "PUT" and c[1].endswith("/zones/example.com.")
    ]
    assert zone_puts == []

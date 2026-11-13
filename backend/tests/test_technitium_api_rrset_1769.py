"""#1769 — technitium_api record writes: pools, unmanaged values, missing zone.

Fake-client tests over the driver's real request sequence; they assert on the
calls sent to Technitium (``overwrite`` per call), not on helper internals.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.services.dns.record_ops import _change_from_op_row
from tests.test_dns_driver_technitium_api import _change, _driver, _ok, _rrset, _Server

_SRV = _Server({"api_url": "https://x.test", "api_token": "t"})


def _zone_ok() -> Any:
    return _ok({"zone": {"name": "example.com"}, "records": []})


def _adds(fake: Any) -> list[dict[str, Any]]:
    return [c["params"] for c in fake.calls if c["path"] == "/api/zones/records/add"]


@pytest.mark.asyncio
async def test_pool_add_appends_and_never_overwrites(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, fake = _driver(monkeypatch, [_zone_ok(), _ok({})])
    change = _change("create", value="10.0.0.2")
    change = RecordChange(**{**change.__dict__, "rrset_action": "add"})
    await drv.apply_record_change(_SRV, change)
    assert [p["overwrite"] for p in _adds(fake)] == ["false"]


@pytest.mark.asyncio
async def test_create_keeps_unmanaged_values_at_the_name(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, fake = _driver(monkeypatch, [_zone_ok(), _ok({}), _ok({})])
    await drv.apply_record_change(
        _SRV,
        _change("create", record_type="TXT", value="v=spf1 -all", rrset=_rrset("a", "b")),
    )
    assert [p["overwrite"] for p in _adds(fake)] == ["false", "false"]


@pytest.mark.asyncio
async def test_update_still_replaces_the_rrset(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, fake = _driver(monkeypatch, [_zone_ok(), _ok({}), _ok({})])
    await drv.apply_record_change(_SRV, _change("update", rrset=_rrset("10.0.0.1", "10.0.0.2")))
    assert [p["overwrite"] for p in _adds(fake)] == ["true", "false"]


@pytest.mark.asyncio
async def test_cname_create_still_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, fake = _driver(monkeypatch, [_zone_ok(), _ok({})])
    await drv.apply_record_change(
        _SRV, _change("create", record_type="CNAME", value="target.example.com.")
    )
    assert [p["overwrite"] for p in _adds(fake)] == ["true"]


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["create", "update", "delete"])
async def test_missing_zone_is_refused_before_any_write(
    monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    """Technitium answers with the enclosing zone; nothing may be written."""
    drv, fake = _driver(monkeypatch, [_ok({"zone": {"name": "com"}, "records": []})])
    with pytest.raises(CloudDNSError, match="not found on the server"):
        await drv.apply_record_change(_SRV, _change(op))
    assert [c["path"] for c in fake.calls] == ["/api/zones/records/get"]


@pytest.mark.asyncio
async def test_pull_from_a_missing_zone_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, _ = _driver(
        monkeypatch,
        [_ok({"zone": {"name": "example.com"}, "records": []})],
    )
    with pytest.raises(CloudDNSError, match="not found on the server"):
        await drv.pull_zone_records(_SRV, "lab.example.com.")


def test_op_row_replay_carries_rrset_action() -> None:
    class _Row:
        op = "create"
        zone_name = "example.com."
        target_serial = 1
        record = {"name": "www", "type": "A", "value": "10.0.0.1", "rrset_action": "add"}

    change = _change_from_op_row(_Row())  # type: ignore[arg-type]
    assert change is not None and change.rrset_action == "add"
    assert isinstance(change.record, RecordData)

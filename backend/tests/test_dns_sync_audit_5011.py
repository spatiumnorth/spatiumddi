"""The dns-server-sync audit row names the records a server refused (#5011)."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordChangeResult
from app.models.audit import AuditLog
from app.models.dns import DNSRecord
from app.models.settings import PlatformSettings
from app.tasks import dns_pull
from tests.test_dns_sync_serial_3004 import _serve, _zone


class _Refusing:
    def capabilities(self) -> dict[str, Any]:
        return {"record_types": ["A"]}

    async def pull_zone_records(self, *a: Any, **k: Any) -> Any:
        raise AssertionError("faked via pull_zone_records_signed")

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        return [RecordChangeResult(ok=False, change=c, error="REFUSED by server") for c in changes]


async def _setup(db: AsyncSession, monkeypatch: pytest.MonkeyPatch, extra: int) -> None:
    zone, _ = await _zone(db, "technitium_api")
    for i in range(extra):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=f"h{i}",
                fqdn=f"h{i}.example.com.",
                record_type="A",
                value=f"192.0.2.{10 + i}",
                ttl=300,
            )
        )
    db.add(
        PlatformSettings(
            id=1,
            dns_pull_from_server_enabled=True,
            dns_pull_from_server_interval_minutes=1,
            dns_pull_from_server_last_run_at=None,
        )
    )
    await db.commit()
    drv = _Refusing()
    _serve(monkeypatch, drv, [])  # type: ignore[arg-type]
    monkeypatch.setattr(dns_pull, "get_driver", lambda name: drv)


async def _audit(db: AsyncSession) -> list[AuditLog]:
    db.expire_all()
    return list(
        (await db.execute(select(AuditLog).where(AuditLog.action == "dns-server-sync")))
        .scalars()
        .all()
    )


async def test_refused_records_are_named(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _setup(db_session, monkeypatch, 0)
    out = await dns_pull._run_sync()
    assert out["push_errors"] == 1
    (row,) = await _audit(db_session)
    nv = row.new_value
    assert nv["push_errors"] == 1
    (detail,) = nv["push_error_details"]
    assert "example.com." in detail and "ns1" in detail
    assert "www A" in detail and "REFUSED by server" in detail
    assert nv["push_error_details_more"] == 0


async def test_refusals_over_the_cap_are_truncated_and_counted(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _setup(db_session, monkeypatch, 14)  # 15 records, cap is per-zone 10 upstream
    # Several zones' worth of errors is what exceeds 20; emulate with the cap lowered.
    monkeypatch.setattr(dns_pull, "_AUDIT_DETAIL_CAP", 3)
    await dns_pull._run_sync()
    (row,) = await _audit(db_session)
    nv = row.new_value
    assert len(nv["push_error_details"]) == 3
    assert nv["push_error_details_more"] == nv["push_errors"] - 3 > 0


async def test_clean_sync_writes_no_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _setup(db_session, monkeypatch, 0)

    class _Ok(_Refusing):
        async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
            return [RecordChangeResult(ok=True, change=c) for c in changes]

    from app.services.dns import pull_from_server as pfs  # noqa: PLC0415

    drv = _Ok()
    _serve(monkeypatch, drv, [])  # type: ignore[arg-type]
    monkeypatch.setattr(dns_pull, "get_driver", lambda name: drv)
    # Server already serves everything: nothing pushed, nothing refused.
    from tests.test_dns_sync_serial_3004 import _WWW  # noqa: PLC0415

    _serve(monkeypatch, drv, [_WWW])  # type: ignore[arg-type]
    assert pfs is not None
    await dns_pull._run_sync()
    assert await _audit(db_session) == []

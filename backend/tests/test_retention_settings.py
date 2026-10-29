"""#2273 — every data-retention window is a setting the prune tasks honour.

Four columns existed with no API, ``metric_retention_days`` was read by
``prune_metrics`` but never existed, and query / activity log retention was
hard-coded at 24 h. These tests pin the round trip through ``/settings``,
the ranges (incl. the 168 h log cap), and that the two sweeps whose window
was fixed now use the stored value.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.models.logs import DNSQueryLogEntry
from app.models.metrics import DNSMetricSample
from app.models.settings import PlatformSettings
from app.tasks import prune_logs, prune_metrics
from tests.conftest import _test_engine

# field -> (non-default value, defaults, lowest accepted, highest accepted)
RETENTION: dict[str, tuple[int, int, int, int]] = {
    "soft_delete_purge_days": (60, 30, 0, 365),
    "dhcp_lease_history_retention_days": (180, 90, 0, 3650),
    "pcap_retention_days": (14, 7, 1, 90),
    "appliance_revoked_retention_days": (60, 30, 0, 365),
    "metric_retention_days": (30, 7, 1, 365),
    "log_retention_hours": (72, 24, 1, 168),
}


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="superadmin",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _settings_row(db: AsyncSession) -> PlatformSettings:
    row = await db.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db.add(row)
        await db.commit()
    return row


@pytest.mark.asyncio
async def test_defaults_are_todays_hard_coded_windows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    r = await client.get("/api/v1/settings", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    for field, (_, default, _, _) in RETENTION.items():
        assert body[field] == default, field


@pytest.mark.asyncio
@pytest.mark.parametrize("field", sorted(RETENTION))
async def test_retention_setting_round_trips_and_is_audited(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _superadmin(db_session)
    value = RETENTION[field][0]
    r = await client.put("/api/v1/settings", headers=headers, json={field: value})
    assert r.status_code == 200, r.text
    assert r.json()[field] == value

    r = await client.get("/api/v1/settings", headers=headers)
    assert r.json()[field] == value

    db_session.expire_all()
    row = await db_session.get(PlatformSettings, 1)
    assert row is not None and getattr(row, field) == value

    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "platform_settings",
                    AuditLog.resource_id == "retention",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audit) == 1, field
    assert audit[0].result == "success"
    assert audit[0].changed_fields == [field]
    assert audit[0].old_value == {field: RETENTION[field][1]}
    assert audit[0].new_value == {field: value}

    # Sending the same value again is not a change and writes no audit row.
    r = await client.put("/api/v1/settings", headers=headers, json={field: value})
    assert r.status_code == 200
    again = await db_session.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.resource_type == "platform_settings", AuditLog.resource_id == "retention")
    )
    assert again == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("field", sorted(RETENTION))
async def test_retention_range_is_enforced(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    headers = await _superadmin(db_session)
    await _settings_row(db_session)
    _, default, lo, hi = RETENTION[field]
    for bad in (lo - 1, hi + 1):
        r = await client.put("/api/v1/settings", headers=headers, json={field: bad})
        assert r.status_code == 422, f"{field}={bad}: {r.status_code} {r.text}"
    for good in (lo, hi):
        r = await client.put("/api/v1/settings", headers=headers, json={field: good})
        assert r.status_code == 200, f"{field}={good}: {r.text}"
        assert r.json()[field] == good


@pytest.mark.asyncio
async def test_log_retention_is_capped_at_one_week(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    await _settings_row(db_session)
    r = await client.put("/api/v1/settings", headers=headers, json={"log_retention_hours": 169})
    assert r.status_code == 422
    db_session.expire_all()
    row = await db_session.get(PlatformSettings, 1)
    assert row is not None and row.log_retention_hours == 24


async def _dns_server(db: AsyncSession) -> DNSServer:
    grp = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id, name=f"dns-{uuid.uuid4().hex[:6]}", host="127.0.0.1", driver="bind9"
    )
    db.add(server)
    await db.flush()
    return server


async def _qnames(db: AsyncSession, server: DNSServer) -> set[str]:
    rows = await db.execute(
        select(DNSQueryLogEntry.qname).where(DNSQueryLogEntry.server_id == server.id)
    )
    return {q for (q,) in rows}


@pytest.mark.asyncio
async def test_partition_retention_honours_log_retention_hours(db_session: AsyncSession) -> None:
    from app.services.logs import partitions as log_partitions

    row = await _settings_row(db_session)
    row.log_retention_hours = 72
    server = await _dns_server(db_session)
    now = datetime.now(UTC)
    for qname, age in (("30h.example", 30), ("6d.example", 6 * 24)):
        db_session.add(
            DNSQueryLogEntry(
                server_id=server.id, ts=now - timedelta(hours=age), qname=qname, raw=qname
            )
        )
    await db_session.commit()

    hours = await prune_logs.log_retention_hours(db_session)
    assert hours == 72
    async with _test_engine.connect() as conn:
        conn = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await log_partitions.maintain(conn, log_partitions.DNS_QUERY_LOG, hours, now=now)

    # Under the old fixed 24 h window the 30 h row would be gone; the 6 day row
    # sits in a partition wholly past the 72 h window.
    assert await _qnames(db_session, server) == {"30h.example"}


@pytest.mark.asyncio
async def test_prune_metrics_honours_metric_retention_days(db_session: AsyncSession) -> None:
    row = await _settings_row(db_session)
    row.metric_retention_days = 30
    server = await _dns_server(db_session)
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    kept = now - timedelta(days=10)
    gone = now - timedelta(days=40)
    for at in (kept, gone):
        db_session.add(DNSMetricSample(server_id=server.id, bucket_at=at))
    await db_session.commit()

    result = await prune_metrics._sweep_with_session(db_session)

    assert result["retention_days"] == 30
    left = (
        await db_session.execute(
            select(DNSMetricSample.bucket_at).where(DNSMetricSample.server_id == server.id)
        )
    ).scalars()
    # Under the old fixed 7 d window the 10-day-old sample would be gone.
    assert [b.astimezone(UTC) for b in left] == [kept]
    count = await db_session.scalar(select(func.count()).select_from(DNSMetricSample))
    assert count == 1


@pytest.mark.asyncio
async def test_copilot_tool_reports_the_stored_windows(db_session: AsyncSession) -> None:
    from app.services.ai.tools.retention import (
        FindRetentionSettingsArgs,
        find_retention_settings,
    )

    row = await _settings_row(db_session)
    row.log_retention_hours = 48
    row.metric_retention_days = 14
    await db_session.commit()
    out = await find_retention_settings(db_session, None, FindRetentionSettingsArgs())  # type: ignore[arg-type]
    assert out["log_retention_hours"] == 48
    assert out["metric_retention_days"] == 14
    assert out["soft_delete_purge_days"] == 30

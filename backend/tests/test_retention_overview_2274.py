"""Retention overview endpoint + ``find_data_retention`` tool (#2274)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.base import Base
from app.models.nmap import NmapScan
from app.services import retention
from app.services.retention_overview import _entries, build_retention_overview


async def _user(db: AsyncSession, *, superadmin: bool) -> str:
    u = User(
        username=f"ro-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Retention",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    await db.commit()
    return create_access_token(str(u.id))


def test_registry_covers_every_prune_rule_and_names_real_columns() -> None:
    names = {e.table for e in _entries()}
    for rule in retention.RULES:
        assert rule.model.__tablename__ in names
    for e in _entries():
        table = Base.metadata.tables[e.table]
        assert e.ts_column in table.c, (e.table, e.ts_column)


@pytest.mark.asyncio
async def test_endpoint_shape_and_governing_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    db_session.add(
        NmapScan(
            target_ip="10.9.9.9",
            preset="quick",
            command_line="nmap",
            status="completed",
            created_at=datetime.now(UTC) - timedelta(days=3),
        )
    )
    await db_session.commit()
    token = await _user(db_session, superadmin=True)
    resp = await client.get(
        "/api/v1/admin/postgres/retention", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200, resp.text
    rows = {r["table"]: r for r in resp.json()["rows"]}
    nmap = rows["nmap_scan"]
    assert nmap["retention_setting"] == "nmap_scan_retention_days"
    assert nmap["retention_window"] == 90 and nmap["retention_unit"] == "days"
    assert nmap["keeps_forever"] is False
    assert nmap["total_bytes"] > 0 and nmap["estimated_rows"] >= 0
    assert nmap["oldest_row_column"] == "created_at"
    assert rows["audit_log"]["retention_setting"] is None
    assert rows["audit_log"]["keeps_forever"] is True
    assert rows["dns_query_log_entry"]["retention_unit"] == "hours"
    sizes = [r["total_bytes"] for r in resp.json()["rows"]]
    assert sizes == sorted(sizes, reverse=True)


@pytest.mark.asyncio
async def test_oldest_row_read_only_where_indexed(db_session: AsyncSession) -> None:
    rows = {r["table"]: r for r in await build_retention_overview(db_session)}
    # dhcp_lease_history.expired_at only trails a composite index.
    r = rows["dhcp_lease_history"]
    assert r["oldest_row"] is None
    assert "not indexed" in (r["oldest_row_note"] or "")


@pytest.mark.asyncio
async def test_endpoint_is_superadmin_only(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _user(db_session, superadmin=False)
    resp = await client.get(
        "/api/v1/admin/postgres/retention", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403
    assert (await client.get("/api/v1/admin/postgres/retention")).status_code in (401, 403)


@pytest.mark.asyncio
async def test_copilot_tool_registered_default_enabled_and_lists_tables(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.tools.base import REGISTRY
    from app.services.ai.tools.data_retention import (
        FindDataRetentionArgs,
        find_data_retention,
    )

    tool = REGISTRY.get("find_data_retention")
    assert tool is not None and tool.default_enabled is True
    assert tool.permission == "superadmin"
    out = await find_data_retention(db_session, None, FindDataRetentionArgs())  # type: ignore[arg-type]
    assert out["count"] == len(out["tables"]) > 0
    assert {"alert_event", "audit_log"} <= {t["table"] for t in out["tables"]}

"""The agent bundle ships the query-log channel settings (#4594)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.models.settings import PlatformSettings
from app.services.dns.agent_config import render_bundle_body


@pytest.mark.asyncio
async def test_bundle_ships_query_log_channel_settings(db_session: AsyncSession) -> None:
    db_session.add(PlatformSettings(id=1))
    group = DNSServerGroup(id=uuid.UUID(int=0x4594), name="ql-guard", description="")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(
        id=uuid.UUID(int=0x4595),
        agent_id=uuid.UUID(int=0x4596),
        group_id=group.id,
        name="ql-ns1",
        host="192.0.2.53",
        port=53,
        driver="bind9",
        is_primary=True,
        is_enabled=True,
    )
    db_session.add(server)
    db_session.add(
        DNSServerOptions(
            group_id=group.id,
            query_log_enabled=True,
            query_log_severity="dynamic",
            query_log_print_category=False,
            query_log_print_severity=False,
        )
    )
    await db_session.flush()
    opts = (await render_bundle_body(db_session, server)).body["options"]
    assert opts["query_log_enabled"] is True
    assert opts["query_log_severity"] == "dynamic"
    assert opts["query_log_print_category"] is False
    assert opts["query_log_print_severity"] is False

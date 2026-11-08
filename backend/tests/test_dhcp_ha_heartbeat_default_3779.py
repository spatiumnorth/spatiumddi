"""HA heartbeat-delay default (#3779): 2 s, still far below max-response-delay,
and existing groups left at the old 10 s default move with it."""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.server_groups import GroupCreate
from app.drivers.dhcp.base import FailoverConfig
from app.models.dhcp import DHCPServerGroup

_MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "ede3bcd2aff4_dhcp_ha_heartbeat_2s.py"
)


def test_new_group_defaults() -> None:
    col = DHCPServerGroup.__table__.c
    assert col.heartbeat_delay_ms.default.arg == 2000
    body = GroupCreate(name="g")
    assert body.heartbeat_delay_ms == 2000


def test_driver_default_and_kea_constraint() -> None:
    fc = FailoverConfig(
        channel_id="1", channel_name="g", mode="hot-standby", this_server_name="a", peers=()
    )
    assert fc.heartbeat_delay_ms == 2000
    # Kea needs max-response-delay > heartbeat-delay, ideally several times it.
    assert fc.max_response_delay_ms >= 5 * fc.heartbeat_delay_ms


async def test_migration_moves_only_rows_at_the_old_default(db_session: AsyncSession) -> None:
    """Rows at exactly 10000 (the old default every create wrote) move to
    2000; an operator-chosen value is kept. Runs in the test's transaction."""
    spec = importlib.util.spec_from_file_location("m_ede3bcd2aff4", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    ids = {}
    for hb in (10000, 5000, 1500):
        g = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", heartbeat_delay_ms=hb)
        db_session.add(g)
        await db_session.flush()
        ids[hb] = g.id

    def _upgrade(sync_conn) -> None:  # noqa: ANN001
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module.upgrade()

    conn = await db_session.connection()
    await conn.run_sync(_upgrade)

    rows = dict(
        (
            await db_session.execute(
                text("SELECT id, heartbeat_delay_ms FROM dhcp_server_group WHERE id = ANY(:ids)"),
                {"ids": list(ids.values())},
            )
        ).all()
    )
    assert rows[ids[10000]] == 2000
    assert rows[ids[5000]] == 5000
    assert rows[ids[1500]] == 1500

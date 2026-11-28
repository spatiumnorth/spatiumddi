"""#4444: the bindings list ends its order on the binding id."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import ERLBinding
from tests.test_e911_delete_guard_3891 import _admin, _erl
from tests.test_e911_delete_guard_3891 import _subnet as _e911_subnet


@pytest.mark.asyncio
async def test_bindings_list_pages_are_stable_within_one_erl_4444(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    erl = await _erl(db_session)
    for _ in range(6):
        sub = await _e911_subnet(db_session)
        db_session.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=sub.id))
    await db_session.flush()
    stmt_sql = []

    bind = db_session.bind
    sync_engine = getattr(bind, "sync_engine", None)

    def grab(conn, cursor, statement, params, context, executemany):  # type: ignore[no-untyped-def]
        stmt_sql.append(statement)

    assert sync_engine is not None
    event.listen(sync_engine, "before_cursor_execute", grab)
    try:
        r = await client.get("/api/v1/e911/bindings", params={"limit": 3}, headers=h)
    finally:
        event.remove(sync_engine, "before_cursor_execute", grab)
    assert r.status_code == 200, r.text
    listing = [s for s in stmt_sql if "ORDER BY" in s and "erl_binding" in s and "LIMIT" in s]
    assert listing, stmt_sql
    order = listing[-1].split("ORDER BY", 1)[1].split("LIMIT", 1)[0]
    assert order.strip().endswith("erl_binding.id"), order

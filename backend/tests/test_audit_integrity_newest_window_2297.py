"""The audit badge verifies the NEWEST rows, not the oldest (#2297)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.api.v1.audit.router import get_audit_integrity
from app.db import AsyncSessionLocal
from app.models.audit import AuditLog

pytestmark = pytest.mark.asyncio


async def _seed(n: int) -> list[uuid.UUID]:
    ids: list[uuid.UUID] = []
    for i in range(n):
        row = AuditLog(
            user_display_name="probe",
            action="create",
            resource_type="customer",
            resource_id=str(uuid.uuid4()),
            resource_display=f"row-{i}",
        )
        async with AsyncSessionLocal() as s:
            s.add(row)
            await s.commit()
        ids.append(row.id)
    return ids


async def _tamper(row_id: uuid.UUID) -> None:
    # audit_log refuses UPDATE (#2315); tampering takes the table owner
    # switching the guard off first, which is what this models.
    async with AsyncSessionLocal() as s:
        await s.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update"))
        await s.execute(
            text("UPDATE audit_log SET resource_display='edited' WHERE id=:i"), {"i": row_id}
        )
        await s.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update"))
        await s.commit()


async def _badge(max_rows: int, newest: bool):
    async with AsyncSessionLocal() as s:
        return await get_audit_integrity(s, max_rows=max_rows, newest=newest)


async def test_recent_tampering_turns_newest_window_red() -> None:
    ids = await _seed(8)
    await _tamper(ids[-2])
    res = await _badge(3, True)
    assert not res.ok
    assert res.partial is True
    assert res.rows_checked == 3
    assert any(b.audit_id == str(ids[-2]) for b in res.breaks)


async def test_old_tampering_is_outside_newest_window_and_window_is_honest() -> None:
    ids = await _seed(8)
    await _tamper(ids[0])
    res = await _badge(3, True)
    assert res.ok
    assert res.partial is True
    assert res.last_seq - res.first_seq == 2


async def test_window_start_is_anchored_on_the_preceding_row() -> None:
    ids = await _seed(6)
    # Rewrite the prev_hash of the first row in the window.
    async with AsyncSessionLocal() as s:
        await s.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update"))
        await s.execute(
            text("UPDATE audit_log SET prev_hash='deadbeef' WHERE id=:i"), {"i": ids[-3]}
        )
        await s.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update"))
        await s.commit()
    res = await _badge(3, True)
    assert not res.ok
    assert any(b.reason == "prev_hash_mismatch" for b in res.breaks)


async def test_window_covering_whole_table_is_not_partial() -> None:
    await _seed(4)
    res = await _badge(100, True)
    assert res.ok and res.partial is False and res.rows_checked == 4

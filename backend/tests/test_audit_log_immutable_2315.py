"""audit_log refuses UPDATE and DELETE, and the conformity check proves it (#2315).

``audit_log_immutable`` used to count rows, so it passed with the
no-delete trigger dropped, and nothing refused an UPDATE. Every check
test changes the guard inside ``db_session``'s transaction; the
fixture's rollback puts the schema back.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import AsyncSessionLocal
from app.models.audit import AuditLog
from app.services.conformity.checks import (
    STATUS_FAIL,
    STATUS_NOT_APPLICABLE,
    STATUS_PASS,
    check_audit_log_immutable,
)

pytestmark = pytest.mark.asyncio


async def _check(db: AsyncSession, target_kind: str = "platform"):
    return await check_audit_log_immutable(
        db, target=None, target_kind=target_kind, args={}, now=datetime.now(UTC)
    )


async def _insert_row() -> uuid.UUID:
    row = AuditLog(
        user_display_name="probe",
        action="create",
        resource_type="customer",
        resource_id=str(uuid.uuid4()),
        resource_display="original",
    )
    async with AsyncSessionLocal() as s:
        s.add(row)
        await s.commit()
    return row.id


# ── The guard itself ────────────────────────────────────────────────


async def test_insert_still_works() -> None:
    row_id = await _insert_row()
    async with AsyncSessionLocal() as s:
        row = await s.get(AuditLog, row_id)
        assert row is not None
        assert row.resource_display == "original"
        assert row.row_hash


async def test_raw_update_is_refused() -> None:
    row_id = await _insert_row()
    async with AsyncSessionLocal() as s:
        with pytest.raises(DBAPIError, match="UPDATE refused"):
            await s.execute(
                text("UPDATE audit_log SET resource_display = 'edited' WHERE id = :i"),
                {"i": row_id},
            )
        await s.rollback()
    async with AsyncSessionLocal() as s:
        stored = (
            await s.execute(select(AuditLog.resource_display).where(AuditLog.id == row_id))
        ).scalar_one()
    assert stored == "original"


async def test_orm_update_is_refused() -> None:
    row_id = await _insert_row()
    async with AsyncSessionLocal() as s:
        row = await s.get(AuditLog, row_id)
        assert row is not None
        row.resource_display = "edited"
        with pytest.raises(DBAPIError, match="UPDATE refused"):
            await s.commit()


async def test_delete_is_still_refused() -> None:
    row_id = await _insert_row()
    async with AsyncSessionLocal() as s:
        with pytest.raises(DBAPIError, match="append-only"):
            await s.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": row_id})
        await s.rollback()
    async with AsyncSessionLocal() as s:
        assert await s.get(AuditLog, row_id) is not None


# ── The conformity check ────────────────────────────────────────────


async def test_check_passes_with_both_guards(db_session: AsyncSession) -> None:
    out = await _check(db_session)
    assert out.status == STATUS_PASS, out.detail


async def test_check_is_platform_only(db_session: AsyncSession) -> None:
    out = await _check(db_session, target_kind="subnet")
    assert out.status == STATUS_NOT_APPLICABLE


@pytest.mark.parametrize(
    "trigger", ["audit_log_no_update", "audit_log_no_delete"], ids=["update", "delete"]
)
async def test_check_fails_when_a_guard_is_dropped(db_session: AsyncSession, trigger: str) -> None:
    await db_session.execute(text(f"DROP TRIGGER {trigger} ON audit_log"))
    out = await _check(db_session)
    assert out.status == STATUS_FAIL
    assert f"{trigger} (missing)" in out.detail
    assert out.diagnostic["problems"] == {trigger: "missing"}


async def test_check_fails_when_both_guards_are_dropped(db_session: AsyncSession) -> None:
    await db_session.execute(text("DROP TRIGGER audit_log_no_update ON audit_log"))
    await db_session.execute(text("DROP TRIGGER audit_log_no_delete ON audit_log"))
    out = await _check(db_session)
    assert out.status == STATUS_FAIL
    assert set(out.diagnostic["problems"]) == {"audit_log_no_update", "audit_log_no_delete"}


@pytest.mark.parametrize("mode", ["DISABLE", "ENABLE REPLICA"])
async def test_check_fails_when_a_guard_is_disabled(db_session: AsyncSession, mode: str) -> None:
    # ENABLE REPLICA fires only for replication sessions, so an ordinary
    # session's UPDATE goes through: as good as disabled.
    await db_session.execute(text(f"ALTER TABLE audit_log {mode} TRIGGER audit_log_no_update"))
    out = await _check(db_session)
    assert out.status == STATUS_FAIL
    assert out.diagnostic["problems"] == {"audit_log_no_update": "disabled"}


async def test_check_fails_when_a_guard_runs_another_function(
    db_session: AsyncSession,
) -> None:
    await db_session.execute(
        text(
            "CREATE FUNCTION audit_log_noop_2315() RETURNS TRIGGER AS $$ "
            "BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql"
        )
    )
    await db_session.execute(text("DROP TRIGGER audit_log_no_update ON audit_log"))
    await db_session.execute(
        text(
            "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log "
            "FOR EACH ROW EXECUTE FUNCTION audit_log_noop_2315()"
        )
    )
    out = await _check(db_session)
    assert out.status == STATUS_FAIL
    assert "audit_log_noop_2315" in out.diagnostic["problems"]["audit_log_no_update"]


async def test_check_fails_when_a_guard_fires_after_the_change(
    db_session: AsyncSession,
) -> None:
    # An AFTER trigger with the right name and function still raises, but
    # it is not the guard the policy describes; the check holds the shape.
    await db_session.execute(text("DROP TRIGGER audit_log_no_delete ON audit_log"))
    await db_session.execute(
        text(
            "CREATE TRIGGER audit_log_no_delete AFTER DELETE ON audit_log "
            "FOR EACH ROW EXECUTE FUNCTION audit_log_block_delete()"
        )
    )
    out = await _check(db_session)
    assert out.status == STATUS_FAIL
    assert out.diagnostic["problems"] == {"audit_log_no_delete": "not a BEFORE DELETE row trigger"}

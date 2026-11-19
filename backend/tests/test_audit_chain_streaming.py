"""The audit-chain verifier streams and resumes (#2286).

It used to ``.scalars().all()`` the whole ``audit_log``: tens of millions of
ORM objects on an aged install, an OOM-killed worker, and tamper detection
that silently stopped. These tests pin the replacement: keyset pages with the
previous hash carried across the page boundary, a checkpoint the nightly task
resumes from, and a failure that is a failure.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select, text

from app.db import AsyncSessionLocal, engine
from app.models.audit import AuditChainCheckpoint, AuditLog
from app.services.audit_chain import verify_chain
from app.tasks import audit_chain_verify as acv

pytestmark = pytest.mark.asyncio


async def _seed(n: int) -> list[int]:
    """Insert ``n`` audit rows, one transaction each; return their seqs."""
    seqs: list[int] = []
    for i in range(n):
        async with AsyncSessionLocal() as session:
            row = AuditLog(
                user_display_name="stream-probe",
                action="create",
                resource_type="subnet",
                resource_id=str(uuid.uuid4()),
                resource_display=f"row-{i}",
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            seqs.append(row.seq)
    return seqs


async def _sql(stmt: str, **params: object) -> None:
    async with AsyncSessionLocal() as session:
        await session.execute(text(stmt), params)
        await session.commit()


async def _tamper(stmt: str, **params: object) -> None:
    """Edit an audit row on purpose. ``audit_log`` refuses UPDATE (#2315), so
    the guard is switched off inside the same transaction, as a tamperer with
    table-owner rights would."""
    async with AsyncSessionLocal() as session:
        await session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update"))
        await session.execute(text(stmt), params)
        await session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update"))
        await session.commit()


async def _verify(**kw: object):
    async with AsyncSessionLocal() as session:
        return await verify_chain(session, **kw)  # type: ignore[arg-type]


async def _checkpoint() -> AuditChainCheckpoint | None:
    async with AsyncSessionLocal() as session:
        return await session.get(AuditChainCheckpoint, 1)


async def test_clean_chain_verifies_across_many_pages() -> None:
    seqs = await _seed(11)
    result = await _verify(chunk_size=3)
    assert result.ok and result.complete
    assert result.rows_checked == 11
    assert result.last_seq == seqs[-1]


@pytest.mark.parametrize("index", [2, 3, 5, 6])  # last/first rows of 3-row pages
async def test_content_edit_at_a_page_boundary_is_found(index: int) -> None:
    seqs = await _seed(9)
    await _tamper("UPDATE audit_log SET resource_display = 'edited' WHERE seq = :s", s=seqs[index])
    result = await _verify(chunk_size=3)
    assert not result.ok
    assert [(b.seq, b.reason) for b in result.breaks] == [(seqs[index], "row_hash_mismatch")]


async def test_a_deleted_row_at_a_page_boundary_breaks_the_next_link() -> None:
    seqs = await _seed(9)
    # A page ends at seqs[2]; remove the row that opens the next one.
    await _sql("ALTER TABLE audit_log DISABLE TRIGGER USER")
    try:
        await _sql("DELETE FROM audit_log WHERE seq = :s", s=seqs[3])
    finally:
        await _sql("ALTER TABLE audit_log ENABLE TRIGGER USER")
    result = await _verify(chunk_size=3)
    assert [(b.seq, b.reason) for b in result.breaks] == [(seqs[4], "prev_hash_mismatch")]


async def test_the_walk_is_paged_not_loaded_whole() -> None:
    await _seed(10)
    statements: list[str] = []

    def _record(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        if "FROM audit_log" in statement:
            statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _record)
    try:
        result = await _verify(chunk_size=4)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _record)
    assert result.rows_checked == 10
    # 4 + 4 + 2: three bounded pages, every one a keyset query with a LIMIT.
    assert len(statements) == 3
    assert all("LIMIT" in s and "seq >" in s for s in statements)


async def test_resume_checks_only_later_rows() -> None:
    seqs = await _seed(8)
    async with AsyncSessionLocal() as session:
        h = (
            await session.execute(select(AuditLog.row_hash).where(AuditLog.seq == seqs[3]))
        ).scalar_one()
    result = await _verify(start_after=(seqs[3], h), chunk_size=3)
    assert result.ok and result.rows_checked == 4 and result.last_seq == seqs[-1]


async def test_resume_with_the_wrong_hash_is_a_break_at_the_first_row() -> None:
    seqs = await _seed(5)
    result = await _verify(start_after=(seqs[1], "0" * 64))
    assert not result.ok
    assert result.breaks[0].seq == seqs[2]
    assert result.breaks[0].reason == "prev_hash_mismatch"


async def test_a_capped_walk_says_it_is_incomplete() -> None:
    seqs = await _seed(6)
    capped = await _verify(max_rows=4, chunk_size=3)
    assert capped.ok and capped.rows_checked == 4
    assert not capped.complete and capped.last_seq == seqs[3]
    exact = await _verify(max_rows=6, chunk_size=3)
    assert exact.complete


# ── the nightly task ───────────────────────────────────────────────


async def test_task_checkpoints_and_resumes() -> None:
    seqs = await _seed(5)
    first = await acv._async_verify_and_alert()
    assert first == {"ok": True, "rows_checked": 5, "verified_through_seq": seqs[-1]}
    cp = await _checkpoint()
    assert cp is not None and cp.verified_seq == seqs[-1] and cp.full_pass_done_at is not None

    more = await _seed(3)
    second = await acv._async_verify_and_alert()
    assert second["rows_checked"] == 3  # only what was added since
    assert second["verified_through_seq"] == more[-1]


async def test_a_break_is_reported_and_the_checkpoint_stops_before_it() -> None:
    seqs = await _seed(6)
    await acv._async_verify_and_alert()
    more = await _seed(4)
    await _tamper("UPDATE audit_log SET resource_display = 'x' WHERE seq = :s", s=more[1])
    out = await acv._async_verify_and_alert()
    assert out["ok"] is False and out["broken"] == 1
    cp = await _checkpoint()
    # The single page holding the break is not vouched for.
    assert cp is not None and cp.verified_seq == seqs[-1]


async def test_a_stale_full_pass_walks_everything_again() -> None:
    seqs = await _seed(4)
    await acv._async_verify_and_alert()
    # Edit a row BELOW the checkpoint: an incremental run cannot see it...
    await _tamper("UPDATE audit_log SET resource_display = 'x' WHERE seq = :s", s=seqs[0])
    # (the checkpointed row itself is untouched, so the checkpoint stays valid)
    assert (await acv._async_verify_and_alert())["rows_checked"] == 0
    # ...but once the last full pass is a week old the next run re-walks it.
    await _sql(
        "UPDATE audit_chain_checkpoint SET full_pass_done_at = :t",
        t=datetime.now(UTC) - timedelta(days=8),
    )
    out = await acv._async_verify_and_alert()
    assert out["rows_checked"] == 4 and out["ok"] is False


async def test_a_full_pass_dated_in_the_future_cannot_postpone_the_weekly_pass() -> None:
    # Someone who can edit audit_log can edit the checkpoint too. Pushing
    # full_pass_done_at into the future must not keep it from ever ageing
    # past the weekly interval, or an edit below the checkpoint stays unseen.
    seqs = await _seed(4)
    await acv._async_verify_and_alert()
    await _tamper("UPDATE audit_log SET resource_display = 'x' WHERE seq = :s", s=seqs[0])
    await _sql(
        "UPDATE audit_chain_checkpoint SET full_pass_done_at = :t",
        t=datetime.now(UTC) + timedelta(days=3650),
    )
    out = await acv._async_verify_and_alert()
    assert out["rows_checked"] == 4 and out["ok"] is False


async def test_small_clock_skew_on_the_full_pass_time_is_not_a_full_pass() -> None:
    await _seed(3)
    await acv._async_verify_and_alert()
    await _sql(
        "UPDATE audit_chain_checkpoint SET full_pass_done_at = :t",
        t=datetime.now(UTC) + timedelta(minutes=5),
    )
    assert (await acv._async_verify_and_alert())["rows_checked"] == 0


async def test_a_checkpoint_the_table_no_longer_matches_forces_a_full_walk() -> None:
    seqs = await _seed(4)
    await acv._async_verify_and_alert()
    await _sql("UPDATE audit_chain_checkpoint SET verified_hash = :h", h="f" * 64)
    out = await acv._async_verify_and_alert()
    assert out["ok"] is True and out["rows_checked"] == 4
    cp = await _checkpoint()
    assert cp is not None and cp.verified_seq == seqs[-1]


async def test_a_walk_that_dies_is_a_failure_not_a_verified(monkeypatch) -> None:  # noqa: ANN001
    await _seed(6)
    real = acv.verify_chain

    async def _dies_after_first_page(db, **kw):  # noqa: ANN001, ANN003
        kw["chunk_size"] = 2
        orig = kw["on_chunk"]
        calls = 0

        async def _cb(*a):  # noqa: ANN002
            nonlocal calls
            await orig(*a)
            calls += 1
            if calls == 1:
                raise ConnectionError("db went away")

        kw["on_chunk"] = _cb
        return await real(db, **kw)

    monkeypatch.setattr(acv, "verify_chain", _dies_after_first_page)
    with pytest.raises(ConnectionError):
        await acv._async_verify_and_alert()
    cp = await _checkpoint()
    # Progress made before the failure is kept, but the pass is not done.
    assert cp is not None and cp.verified_seq > 0 and cp.full_pass_done_at is None

    monkeypatch.setattr(acv, "verify_chain", real)
    out = await acv._async_verify_and_alert()
    assert out["ok"] is True and out["rows_checked"] == 4  # resumed, not restarted
    cp = await _checkpoint()
    assert cp is not None and cp.full_pass_done_at is not None

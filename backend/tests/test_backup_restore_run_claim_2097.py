"""A restored archive's own ``in_progress`` claim is settled (#2097).

The runner commits its claim before the dump, so every archive a target's
own run writes holds that target ``in_progress``. Restoring it used to put
the claim back with no process behind it: Run now answered 409 and the
schedule skipped the target until the 2 h reap stamped a successful run
``failed``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.audit import AuditLog
from app.models.backup import BackupTarget
from app.services.backup import archive as archive_mod
from app.services.backup import runner as runner_mod
from app.services.backup.archive import read_backup_manifest

NODE = "ddipg-member-1"


def _target(name: str, **kw) -> BackupTarget:
    return BackupTarget(
        name=name,
        kind="local_volume",
        config={},
        schedule_cron="0 2 * * *",
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
        **kw,
    )


async def _run_and_capture(db: AsyncSession, monkeypatch, target: BackupTarget):
    """Run the real runner + real archive builder (pg_dump stubbed) and
    return the written archive's manifest and filename."""
    captured: dict = {}

    async def _dump(path):
        path.write_bytes(b"dump")

    async def _head(_db):
        return "headrev"

    class _Driver:
        def validate_config(self, config) -> None:
            return None

        async def write(self, *, config, filename, archive_bytes) -> None:
            captured["bytes"] = archive_bytes
            captured["filename"] = filename

    monkeypatch.setattr(archive_mod, "_run_pg_dump", _dump)
    monkeypatch.setattr(archive_mod, "_read_alembic_head", _head)
    monkeypatch.setattr("app.config.settings.node_name", NODE)
    monkeypatch.setattr(runner_mod, "get_destination", lambda kind: _Driver())
    monkeypatch.setattr(runner_mod, "decrypt_config_secrets", lambda d, c: c)

    async def _no_sweep(*a, **k):
        return 0

    monkeypatch.setattr(runner_mod, "_retention_sweep", _no_sweep)
    result = await runner_mod.run_backup_for_target(db, target=target, triggered_by="manual")
    assert result["success"]
    return read_backup_manifest(captured["bytes"]), captured["filename"]


def _as_restored(target: BackupTarget, started: datetime) -> None:
    """The row exactly as the archive holds it: the claim, committed
    before the dump."""
    target.last_run_status = "in_progress"
    target.last_run_at = started
    target.last_run_filename = None
    target.last_run_node = None
    target.last_run_bytes = None
    target.last_run_duration_ms = None
    target.last_run_error = None


async def test_restoring_a_targets_own_archive_leaves_it_runnable(
    db_session: AsyncSession, monkeypatch
) -> None:
    target = _target("own")
    db_session.add(target)
    await db_session.flush()
    manifest, filename = await _run_and_capture(db_session, monkeypatch, target)
    claimed_at = manifest["run"]["claimed_at"]
    assert manifest["run"] == {
        "target_id": str(target.id),
        "filename": filename,
        "node": NODE,
        "claimed_at": claimed_at,
    }
    assert datetime.fromisoformat(claimed_at) <= datetime.fromisoformat(manifest["created_at"])

    # The restore: the table comes back holding the claim the run stamped.
    _as_restored(target, datetime.fromisoformat(claimed_at))
    await db_session.flush()
    settled = await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest)
    await db_session.refresh(target)

    assert [s["settled_as"] for s in settled] == ["success"]
    assert target.last_run_status == "success"
    assert target.last_run_filename == filename
    assert target.last_run_node == NODE  # the "on node" text (#1901) comes back
    assert target.last_run_error is None
    assert target.next_run_at is not None  # a scheduled target is not held
    # Run now is not refused.
    assert await runner_mod.claim_backup_run(db_session, target=target, started=datetime.now(UTC))
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == str(target.id),
                    AuditLog.action == "backup_target_run_reconciled",
                )
            )
        )
        .scalars()
        .one()
    )
    assert audit.new_value["settled_as"] == "success"


async def test_without_the_reconcile_the_two_hour_reap_marks_the_run_failed(
    db_session: AsyncSession,
) -> None:
    """The reap, on its own: the stranded claim is stamped ``failed`` once
    2 h old, though the run it stands for succeeded."""
    target = _target("reaped")
    db_session.add(target)
    await db_session.flush()
    _as_restored(target, datetime.now(UTC) - timedelta(hours=3))
    assert runner_mod.backup_run_is_stale(target, datetime.now(UTC))
    assert await runner_mod.reap_stale_backup_run(db_session, target=target)
    assert target.last_run_status == "failed"
    assert "most likely died" in (target.last_run_error or "")


async def test_a_reconciled_claim_is_never_reaped_as_dead(db_session: AsyncSession) -> None:
    target = _target("settled")
    db_session.add(target)
    await db_session.flush()
    started = datetime.now(UTC) - timedelta(hours=3)
    _as_restored(target, started)
    manifest = {
        "created_at": (started + timedelta(seconds=5)).isoformat(),
        "run": {"target_id": str(target.id), "filename": "a.zip", "node": None},
    }
    await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest)
    assert not await runner_mod.reap_stale_backup_run(db_session, target=target)
    assert target.last_run_status == "success"
    assert target.last_run_node is None


async def test_a_claim_made_after_the_archive_is_a_live_run_and_is_left_alone(
    db_session: AsyncSession,
) -> None:
    target = _target("live")
    db_session.add(target)
    await db_session.flush()
    created = datetime.now(UTC) - timedelta(minutes=10)
    _as_restored(target, datetime.now(UTC) - timedelta(seconds=30))
    manifest = {
        "created_at": created.isoformat(),
        "run": {"target_id": str(target.id), "filename": "a.zip", "node": NODE},
    }
    assert await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest) == []
    await db_session.refresh(target)
    assert target.last_run_status == "in_progress"
    assert target.last_run_filename is None
    # And the running process's own terminal stamp still lands.
    target.last_run_status = "success"
    await db_session.flush()
    assert target.last_run_status == "success"


async def test_an_archive_from_another_target_does_not_mark_this_one_done(
    db_session: AsyncSession,
) -> None:
    writer = _target("writer")
    other = _target("other")
    idle = _target("idle", last_run_status="success", last_run_filename="keep.zip")
    db_session.add_all([writer, other, idle])
    await db_session.flush()
    started = datetime.now(UTC) - timedelta(minutes=2)
    # ``other`` was mid-run when ``writer``'s archive was dumped.
    _as_restored(writer, started)
    _as_restored(other, started)
    manifest = {
        "created_at": (started + timedelta(seconds=5)).isoformat(),
        "run": {"target_id": str(writer.id), "filename": "w.zip", "node": NODE},
    }
    settled = await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest)
    assert {s["name"]: s["settled_as"] for s in settled} == {"writer": "success", "other": "failed"}
    await db_session.refresh(other)
    assert other.last_run_status == "failed"
    assert other.last_run_filename is None  # never handed the writer's file
    assert other.next_run_at is not None
    await db_session.refresh(idle)
    assert (idle.last_run_status, idle.last_run_filename) == ("success", "keep.zip")


async def test_an_archive_with_no_recorded_run_settles_claims_as_failed(
    db_session: AsyncSession,
) -> None:
    target = _target("legacy")
    db_session.add(target)
    await db_session.flush()
    started = datetime.now(UTC) - timedelta(minutes=2)
    _as_restored(target, started)
    manifest = {"created_at": (started + timedelta(seconds=5)).isoformat()}
    await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest)
    assert target.last_run_status == "failed"
    assert "outcome was not recorded" in target.last_run_error


async def test_the_writers_claim_is_recognised_exactly_despite_a_stepped_clock(
    db_session: AsyncSession,
) -> None:
    """The clock stepped back between the claim and the dump, so the claim
    reads newer than ``created_at``. The exact ``claimed_at`` still names it
    as the archive's own run."""
    target = _target("stepped")
    db_session.add(target)
    await db_session.flush()
    started = datetime.now(UTC) - timedelta(minutes=5)
    _as_restored(target, started)
    manifest = {
        "created_at": (started - timedelta(seconds=2)).isoformat(),
        "run": {
            "target_id": str(target.id),
            "filename": "s.zip",
            "node": NODE,
            "claimed_at": started.isoformat(),
        },
    }
    settled = await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest)
    assert [s["settled_as"] for s in settled] == ["success"]
    assert (target.last_run_status, target.last_run_filename) == ("success", "s.zip")


async def test_a_new_claim_by_the_writing_target_is_not_taken_for_the_archives(
    db_session: AsyncSession,
) -> None:
    """The writing target's archived claim was reaped and a new run claimed
    it before the reconcile ran: same target, different claim. It is a live
    run and must not be stamped with the archive's success."""
    target = _target("reclaimed")
    db_session.add(target)
    await db_session.flush()
    archived_claim = datetime.now(UTC) - timedelta(hours=3)
    _as_restored(target, datetime.now(UTC) - timedelta(seconds=10))
    manifest = {
        "created_at": (archived_claim + timedelta(seconds=5)).isoformat(),
        "run": {
            "target_id": str(target.id),
            "filename": "old.zip",
            "node": NODE,
            "claimed_at": archived_claim.isoformat(),
        },
    }
    assert await runner_mod.reconcile_restored_run_claims(db_session, manifest=manifest) == []
    await db_session.refresh(target)
    assert target.last_run_status == "in_progress"
    assert target.last_run_filename is None


async def test_an_archive_no_run_wrote_carries_no_run_record(
    db_session: AsyncSession, monkeypatch
) -> None:
    """A manual download (and the pre-restore safety dump) claims no target."""

    async def _dump(path):
        path.write_bytes(b"dump")

    async def _head(_db):
        return "headrev"

    monkeypatch.setattr(archive_mod, "_run_pg_dump", _dump)
    monkeypatch.setattr(archive_mod, "_read_alembic_head", _head)
    archive_bytes, _ = await archive_mod.build_backup_archive(
        db_session, passphrase="hunter2hunter2"
    )
    assert "run" not in read_backup_manifest(archive_bytes)

"""A restore after an acknowledged schema rollback is refused (#4678).

After the rollback the host booted the older slot but the newer release's api
keeps serving. A Full restore then replays the older head, the older
release's waiting worker and beat pass their migration wait before the
restore migrates up, and DNS bundles stop reaching the agents for good.
"""

from __future__ import annotations

import os
import uuid

import asyncpg
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core import restore_gate
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.appliance import slot as slot_service
from app.services.appliance.slot import SlotStatus
from app.services.backup import restore as restore_module
from app.services.upgrades import schema_rollback as sr


def _slots(booted: str | None, *, appliance: bool = True) -> SlotStatus:
    return SlotStatus(
        appliance_mode=appliance,
        current_slot="slot_a",
        durable_default="slot_a",
        is_trial_boot=False,
        upgrade_state="ready",
        upgrade_state_at=None,
        log_tail="",
        slot_a_version=booted,
        slot_b_version="1.0.1",
    )


@pytest.mark.parametrize(
    ("booted", "version", "mixed"),
    [
        ("1.0.0", "1.0.1", True),
        ("1.0.1", "1.0.1", False),
        ("0.0.0-nightly-20261120+abc1234", "nightly-20261120", False),
        (None, "1.0.1", False),
        ("1.0.0", "dev", False),
        ("1.0.0", "", False),
    ],
)
def test_mixed_release_state(booted: str | None, version: str, mixed: bool) -> None:
    assert sr.mixed_release_state(booted, version) is mixed


async def _admin(db: AsyncSession) -> dict[str, str]:
    admin = User(
        username=f"bk{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="bk",
        hashed_password=hash_password("x" * 12),
        is_superadmin=True,
    )
    db.add(admin)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}


@pytest.mark.asyncio
async def test_upload_restore_refused_in_the_mixed_state(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "version", "1.0.1")
    monkeypatch.setattr(slot_service, "get_slot_status", lambda: _slots("1.0.0"))
    resp = await client.post(
        "/api/v1/backup/restore",
        headers=await _admin(db_session),
        files={"archive": ("backup.zip", b"not a zip", "application/zip")},
        data={"passphrase": "not-the-passphrase", "confirmation_phrase": "RESTORE-FROM-BACKUP"},
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert detail["code"] == sr.RESTORE_REFUSAL_CODE
    assert "1.0.0" in detail["message"] and "set-next-boot" in detail["message"]


@pytest.mark.asyncio
async def test_target_restore_refused_in_the_mixed_state(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "version", "1.0.1")
    monkeypatch.setattr(slot_service, "get_slot_status", lambda: _slots("1.0.0"))
    resp = await client.post(
        f"/api/v1/backup/targets/{uuid.uuid4()}/archives/restore",
        headers=await _admin(db_session),
        json={
            "filename": "spatiumddi-backup-20261120.zip",
            "passphrase": "not-the-passphrase",
            "confirmation_phrase": "RESTORE-FROM-BACKUP",
        },
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == sr.RESTORE_REFUSAL_CODE


@pytest.mark.asyncio
async def test_restore_not_refused_when_the_booted_slot_is_the_serving_release(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "version", "1.0.1")
    monkeypatch.setattr(slot_service, "get_slot_status", lambda: _slots("1.0.1"))
    resp = await client.post(
        "/api/v1/backup/restore",
        headers=await _admin(db_session),
        files={"archive": ("backup.zip", b"not a zip", "application/zip")},
        data={"passphrase": "not-the-passphrase", "confirmation_phrase": "RESTORE-FROM-BACKUP"},
    )
    assert resp.status_code != 409 or "code" not in resp.json().get("detail", {})


# ── the wait-for-migrate side ─────────────────────────────────────────


def test_restore_uses_the_gates_lock_key() -> None:
    assert restore_module._RESTORE_LOCK_KEY == restore_gate.RESTORE_LOCK_KEY


@pytest.mark.asyncio
async def test_restore_gate_sees_a_held_restore_lock() -> None:
    dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://", 1)
    assert await restore_gate.restore_in_progress(dsn) is False
    holder = await asyncpg.connect(dsn=dsn)
    try:
        await holder.fetchval("SELECT pg_advisory_lock($1)", restore_gate.RESTORE_LOCK_KEY)
        assert await restore_gate.restore_in_progress(dsn) is True
    finally:
        await holder.close()
    assert await restore_gate.restore_in_progress(dsn) is False


def test_restore_gate_fails_open_without_a_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://nobody:x@127.0.0.1:1/none")
    assert restore_gate.main() == 0
    monkeypatch.delenv("DATABASE_URL")
    assert restore_gate.main() == 0


@pytest.mark.asyncio
async def test_restore_gate_never_takes_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Taking it, even briefly, would refuse a restore starting that instant."""
    queries: list[str] = []

    class _Conn:
        async def fetchval(self, query: str, *args: object) -> bool:
            queries.append(query)
            return False

        async def close(self) -> None:
            pass

    async def _connect(**_: object) -> _Conn:
        return _Conn()

    monkeypatch.setattr(asyncpg, "connect", _connect)
    assert await restore_gate.restore_in_progress("postgresql://x") is False
    assert queries and not any("advisory_lock" in q for q in queries)


def test_restore_gate_signals_a_running_restore_with_its_own_exit_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """3, never 1: the interpreter exits 1 on an import error or a crash, and
    the init container must read that as "cannot tell", which passes."""

    async def _held(_dsn: str) -> bool:
        return True

    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@db/x")
    monkeypatch.setattr(restore_gate, "restore_in_progress", _held)
    assert restore_gate.main() == restore_gate.RESTORE_RUNNING_EXIT == 3

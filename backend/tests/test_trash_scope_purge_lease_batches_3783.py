"""#3783: a scope's permanent delete from the Trash no longer tears its remaining
leases down in the purge's own transaction; it drains them in committed batches
first, and answers 409 with the rest handed to the background task when the
deadline runs out."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.admin import trash
from app.models.dhcp import DHCPLease, DHCPScope
from app.services.dhcp import lease_cleanup
from app.tasks import dhcp_lease_cleanup as lease_tasks
from tests.test_lease_events_trashed_scope_3733 import _estate, _post

_IPS = [f"10.31.1.{h}" for h in range(10, 18)]


async def _leases(db: AsyncSession, scope_id: object) -> int:
    db.expunge_all()
    return (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope_id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_purge_drains_leases_in_batches_not_in_its_own_transaction(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, scope_id, _subnet, admin = await _estate(db_session)
    assert (await _post(client, server, _IPS)).status_code == 200
    queued: list[str] = []
    monkeypatch.setattr(lease_tasks.tear_down_trashed_scope_leases, "delay", queued.append)
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_BATCH", 3)
    # The soft delete gets no inline time, so every lease outlives it.
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_INLINE_DEADLINE_S", 0.0)
    assert (
        await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    ).status_code == 204
    assert await _leases(db_session, scope_id) == len(_IPS)

    # No time for the purge either: 409, the rest is handed on, nothing purged.
    refused = await client.delete(f"/api/v1/admin/trash/dhcp_scope/{scope_id}", headers=admin)
    assert refused.status_code == 409, refused.text
    assert refused.headers.get("retry-after")
    assert queued == [str(scope_id)] * 2  # the soft delete's, then the purge's
    assert await _leases(db_session, scope_id) == len(_IPS)

    # With time, batches drain the leases and the purge itself finds none left.
    monkeypatch.setattr(lease_cleanup, "SCOPE_DELETE_INLINE_DEADLINE_S", 30.0)
    left_in_purge: list[int] = []
    real = trash.delete_leases_for_scope

    async def _spy(db: AsyncSession, sid: object, **kw: object) -> tuple[int, int]:
        left_in_purge.append(await _leases(db_session, sid))
        return await real(db, sid, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(trash, "delete_leases_for_scope", _spy)
    done = await client.delete(f"/api/v1/admin/trash/dhcp_scope/{scope_id}", headers=admin)
    assert done.status_code == 204, done.text
    assert left_in_purge == [0]
    db_session.expunge_all()
    gone = (
        await db_session.execute(
            select(DHCPScope)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert gone is None

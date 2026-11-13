"""#3804: the Trash-restore DDNS republish uses its own small batch, so its
row locks are held for ~2 s rather than 10-15 s, and commits between batches."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from app.tasks import ipam_dns_sync as mod


class _FakeDB:
    def __init__(self) -> None:
        self.commits = 0

    async def get(self, model: Any, pk: Any, **kw: Any) -> Any:
        return SimpleNamespace(id=pk)

    async def rollback(self) -> None:
        pass

    async def commit(self) -> None:
        self.commits += 1


@pytest.mark.asyncio
async def test_republish_batches_are_small_and_commit_each(monkeypatch: Any) -> None:
    import app.api.v1.ipam.router as ipam_router
    import app.services.dns.ddns as ddns

    ids = [uuid.uuid4() for _ in range(55)]
    sizes: list[int] = []

    async def _active(db: Any, sid: Any) -> list[Any]:
        return ids

    async def _lock(db: Any, batch: list[Any], **kw: Any) -> list[Any]:
        sizes.append(len(batch))
        return batch

    async def _reapply(db: Any, subnet: Any, *, locked_ids: Any) -> tuple[int, list[str]]:
        return len(locked_ids), []

    async def _eff(db: Any, subnet: Any) -> Any:
        return SimpleNamespace(enabled=True)

    async def _dns(db: Any, subnet: Any) -> tuple[list[Any], Any, Any]:
        return [], None, None

    monkeypatch.setattr(mod, "active_lease_mirror_ids", _active)
    monkeypatch.setattr(mod, "_reapply_ddns_for_active_leases", _reapply)
    monkeypatch.setattr(ipam_router, "_lock_dns_sync_rows", _lock)
    monkeypatch.setattr(ipam_router, "_resolve_effective_dns", _dns)
    monkeypatch.setattr(ddns, "resolve_effective_ddns", _eff)

    db = _FakeDB()
    fired, _ = await mod.republish_restored_lease_ddns(db, [uuid.uuid4()])
    assert fired == 55
    assert max(sizes) <= mod.RESTORE_REPUBLISH_BATCH_SIZE < mod.SYNC_BATCH_SIZE
    assert sizes == [20, 20, 15]
    assert db.commits == 3

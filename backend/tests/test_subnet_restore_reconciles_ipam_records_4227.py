"""spatiumddi#4227 — a subnet restored from the Trash answers what IPAM holds now.

#3924 reconciled the IPAM-generated records a restored ZONE brings back; a
zone restored while its subnet was in the Trash handed that subnet's records to
the subnet's batch unchanged, and the subnet's own restore brought them back as
they were. The outcome must not depend on which of the two is restored first.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_subnet_trash_retracts_dns_1906 import _address, _admin_headers, _setup
from tests.test_zone_restore_trashed_subnet_records_2732 import _forward_a


async def _trash(client, headers, path):  # type: ignore[no-untyped-def]
    r = await client.delete(path, headers=headers)
    assert r.status_code == 204, r.text


async def _restore(client, headers, kind, rid):  # type: ignore[no-untyped-def]
    r = await client.post(f"/api/v1/admin/trash/{kind}/{rid}/restore", headers=headers)
    assert r.status_code == 200, r.text


async def _scenario(client, db_session, cidr, base, zone_first):  # type: ignore[no-untyped-def]
    headers = await _admin_headers(db_session)
    # Two /25s share one reverse zone, so the trashed subnet's batch carries no
    # zone of its own (the reach #4227 names: a reverse zone it does not own).
    other = cidr.replace(".0/25", ".128/25")
    grp, _s, zone, sid, _ = await _setup(client, db_session, headers, cidr, other, base)
    net = cidr.rsplit(".", 1)[0]
    renamed = await _address(client, headers, sid, f"{net}.10", "old")
    await _address(client, headers, sid, f"{net}.11", "same")
    zone_id = zone.id
    await _trash(client, headers, f"/api/v1/dns/groups/{grp.id}/zones/{zone_id}")
    r = await client.put(
        f"/api/v1/ipam/addresses/{renamed}", headers=headers, json={"hostname": "new"}
    )
    assert r.status_code == 200, r.text
    await _trash(client, headers, f"/api/v1/ipam/subnets/{sid}")
    if zone_first:
        await _restore(client, headers, "dns_zone", zone_id)
        await _restore(client, headers, "subnet", sid)
    else:
        await _restore(client, headers, "subnet", sid)
        await _restore(client, headers, "dns_zone", zone_id)
    out = await _forward_a(db_session, zone_id)
    return out, net


@pytest.mark.asyncio
async def test_zone_then_subnet_restore(client: AsyncClient, db_session: AsyncSession) -> None:
    rows, net = await _scenario(client, db_session, "10.147.1.0/25", "10.147.0.0/16", True)
    live = [r for r in rows if r[2]]
    assert live == [("new", f"{net}.10", True), ("same", f"{net}.11", True)]
    assert not [r for r in rows if r[0] == "old" and r[2]]


@pytest.mark.asyncio
async def test_subnet_then_zone_restore(client: AsyncClient, db_session: AsyncSession) -> None:
    rows, net = await _scenario(client, db_session, "10.147.2.0/25", "10.147.0.0/16", False)
    live = [r for r in rows if r[2]]
    assert live == [("new", f"{net}.10", True), ("same", f"{net}.11", True)]


@pytest.mark.asyncio
async def test_reconcile_failure_falls_back_to_task(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import ipam_dns_sync

    queued: list[list[str]] = []

    class _Task:
        @staticmethod
        def delay(ids: list[str]) -> None:
            queued.append(list(ids))

    async def _boom(*_a, **_k):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    monkeypatch.setattr(ipam_dns_sync, "reconcile_restored_subnet_records", _boom)
    monkeypatch.setattr(ipam_dns_sync, "reconcile_restored_subnet_records_task", _Task)
    headers = await _admin_headers(db_session)
    _g, _s, _z, sid, _ = await _setup(
        client, db_session, headers, "10.147.3.0/25", "10.147.3.128/25", "10.147.0.0/16"
    )
    await _address(client, headers, sid, "10.147.3.10", "f1")
    await _trash(client, headers, f"/api/v1/ipam/subnets/{sid}")
    await _restore(client, headers, "subnet", sid)
    assert queued == [[str(sid)]]

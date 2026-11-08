"""#3787: a subnet restored from the Trash gets the DNS records of the DHCP
lease mirrors that come back with it.

The delete withdraws the A / PTR of the mirrors its scopes' teardown has yet to
remove (#3744), so they are deleted, not trashed, and a restore cannot bring
them back. The restore now hands the subnet to a post-commit task that re-runs
the DDNS policy for every active, unexpired lease mirror.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPScope
from app.models.dns import DNSRecord, DNSRecordOp
from app.models.ipam import IPAddress, Subnet
from app.tasks.ipam_dns_sync import republish_restored_lease_ddns
from tests.test_ddns_lease_rename_1618 import _setup
from tests.test_dhcp_scope_lease_teardown import _make_admin


async def _lease(
    db: AsyncSession,
    server: Any,
    subnet: Subnet,
    ip: str,
    *,
    state: str = "active",
    ttl: int = 3600,
) -> IPAddress:
    scope = (
        await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == subnet.id))
    ).scalar_one()
    end = datetime.now(UTC) + timedelta(seconds=ttl)
    db.add(
        DHCPLease(
            server_id=server.id,
            scope_id=scope.id,
            ip_address=ip,
            mac_address="aa:bb:cc:00:37:87",
            hostname=f"h{ip.split('.')[-1]}",
            state=state,
            expires_at=end,
        )
    )
    row = IPAddress(
        subnet_id=subnet.id,
        address=ip,
        status="dhcp",
        hostname=f"h{ip.split('.')[-1]}",
        auto_from_lease=True,
    )
    db.add(row)
    await db.flush()
    return row


async def _record_types(db: AsyncSession, row_id: Any) -> set[str]:
    return set(
        (await db.execute(select(DNSRecord.record_type).where(DNSRecord.ip_address_id == row_id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_active_mirrors_get_their_a_and_ptr_back(db_session: AsyncSession) -> None:
    server, subnet, zone, _ip = await _setup(db_session, 7)
    sid, gid = subnet.id, zone.group_id
    rows = [await _lease(db_session, server, subnet, f"10.93.7.{n}") for n in (60, 61, 62)]
    ids = [r.id for r in rows]
    await db_session.commit()
    db_session.expire_all()

    fired, wake = await republish_restored_lease_ddns(db_session, [sid])

    assert fired == 3
    assert wake == {str(gid)}
    for rid in ids:
        assert await _record_types(db_session, rid) == {"A", "PTR"}
    ops = (await db_session.execute(select(DNSRecordOp))).scalars().all()
    assert len(ops) == 6 and {o.op for o in ops} == {"create"}

    # Idempotent: a second run (a retried task) queues nothing more.
    again, _ = await republish_restored_lease_ddns(db_session, [sid])
    assert again == 0
    assert len((await db_session.execute(select(DNSRecordOp))).scalars().all()) == 6


@pytest.mark.asyncio
async def test_expired_and_inactive_leases_are_not_published(db_session: AsyncSession) -> None:
    server, subnet, _zone, _ip = await _setup(db_session, 8)
    sid = subnet.id
    live = await _lease(db_session, server, subnet, "10.93.8.60")
    expired = await _lease(db_session, server, subnet, "10.93.8.61", ttl=-60)
    released = await _lease(db_session, server, subnet, "10.93.8.62", state="expired")
    live, expired, released = live.id, expired.id, released.id
    await db_session.commit()
    db_session.expire_all()

    fired, _ = await republish_restored_lease_ddns(db_session, [sid])

    assert fired == 1
    assert await _record_types(db_session, live) == {"A", "PTR"}
    assert await _record_types(db_session, expired) == set()
    assert await _record_types(db_session, released) == set()


@pytest.mark.asyncio
async def test_a_ddns_off_subnet_publishes_nothing(db_session: AsyncSession) -> None:
    server, subnet, _zone, _ip = await _setup(db_session, 9, ddns=False)
    sid = subnet.id
    row = (await _lease(db_session, server, subnet, "10.93.9.60")).id
    await db_session.commit()
    db_session.expire_all()

    fired, wake = await republish_restored_lease_ddns(db_session, [sid])

    assert (fired, wake) == (0, set())
    assert await _record_types(db_session, row) == set()
    assert (await db_session.execute(select(DNSRecordOp))).scalars().all() == []


@pytest.mark.asyncio
async def test_restore_endpoint_hands_the_subnet_to_the_task(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.tasks import ipam_dns_sync

    server, subnet, _zone, _ip = await _setup(db_session, 10)
    await _lease(db_session, server, subnet, "10.93.10.60")
    _admin, token = await _make_admin(db_session)
    batch = uuid.uuid4()
    subnet.deleted_at = datetime.now(UTC)
    subnet.deletion_batch_id = batch
    await db_session.commit()

    queued: list[list[str]] = []
    monkeypatch.setattr(
        ipam_dns_sync.republish_restored_lease_ddns_task,
        "delay",
        lambda ids: queued.append(ids),
    )
    resp = await client.post(
        f"/api/v1/admin/trash/subnet/{subnet.id}/restore",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200, resp.text
    assert queued == [[str(subnet.id)]]

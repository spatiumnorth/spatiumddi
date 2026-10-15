"""#623 — a no-primary zone's stale DNS records are still deletable via Sync DNS.

When a scope / reservation delete removes the IPAM address, its auto-generated A
record becomes stale ("ip-deleted"). If the zone has no primary DNS server, the
wire delete can't be pushed — but the record then exists ONLY in our DB, so there
is no wire state to diverge from and it must still be removable. Previously the
reconcile refused ("no primary configured — wire delete skipped", "0 deleted"),
leaving the stale record un-cleanable in the subnet's DNS view.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ds-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="DNS Sync Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_no_primary_stale_record_is_deletable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)

    # A DNS group with NO server → resolve_primary_server returns None, so the
    # batched wire delete drops (op_row is None) — the "no primary" case.
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="np.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.np.example.",
        admin_email="admin.np.example.",
    )
    db_session.add(zone)
    await db_session.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.70.0.0/16", name="blk")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.70.0.0/24",
        name="sn",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db_session.add(subnet)
    await db_session.flush()

    # A stale auto-generated A record: its IPAM address is already gone
    # (ip_address_id NULL) — exactly the shape a scope/static delete leaves in a
    # zone with no primary DNS server.
    rec = DNSRecord(
        zone_id=zone.id,
        name="ghost",
        fqdn="ghost.np.example.",
        record_type="A",
        value="10.70.0.9",
        auto_generated=True,
        ip_address_id=None,
    )
    db_session.add(rec)
    await db_session.flush()
    rec_id = rec.id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/dns-sync/commit",
        headers=headers,
        json={"delete_stale_record_ids": [str(rec_id)]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Removed from the DB even though there was no primary to push the wire
    # delete to — no "wire delete skipped" error, one record deleted.
    assert body["deleted"] == 1, body
    assert body["errors"] == [], body

    db_session.expire_all()
    assert (
        await db_session.execute(select(DNSRecord).where(DNSRecord.id == rec_id))
    ).scalar_one_or_none() is None


# ── #962 — agent-based zones: pending is dispatched, only failed blocks ───────
#
# Same defect #950 fixed in the DNS bulk-delete route, in this file's commit
# path. Agent-based servers never answer inline — ``enqueue_record_ops_batch``
# queues ``pending`` rows for the agent's next long-poll — and the old
# ``!= "applied"`` gate reported every one of them as "wire delete failed —
# unknown", keeping the row while the agent still removed the record from the
# served zone. The next drift report then listed it as missing-on-server.


async def _agent_zone_subnet(db: AsyncSession) -> tuple[DNSServer, DNSZone, Subnet]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"ab{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.71.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.71.0.0/24",
        name="sn",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    return server, zone, subnet


async def _stale_records(db: AsyncSession, zone: DNSZone, n: int) -> list[uuid.UUID]:
    rows = [
        DNSRecord(
            zone_id=zone.id,
            name=f"stale{i}",
            fqdn=f"stale{i}.{zone.name}",
            record_type="A",
            value=f"10.71.0.{i + 10}",
            auto_generated=True,
            ip_address_id=None,
        )
        for i in range(n)
    ]
    db.add_all(rows)
    await db.flush()
    return [r.id for r in rows]


@pytest.mark.asyncio
async def test_agent_based_stale_delete_removes_the_row_while_the_op_queues(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    server, zone, subnet = await _agent_zone_subnet(db_session)
    server_id = server.id
    ids = await _stale_records(db_session, zone, 2)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/dns-sync/commit",
        headers=headers,
        json={"delete_stale_record_ids": [str(i) for i in ids]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == 2, body
    assert body["errors"] == [], body

    db_session.expire_all()
    left = (await db_session.execute(select(DNSRecord).where(DNSRecord.id.in_(ids)))).scalars()
    assert list(left) == []
    # The wire delete is queued for the agent, not lost: one pending op each.
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server_id)))
        .scalars()
        .all()
    )
    assert sorted(o.op for o in ops) == ["delete", "delete"]
    assert {o.state for o in ops} == {"pending"}


@pytest.mark.asyncio
async def test_agent_based_stale_delete_keeps_the_row_only_when_the_op_failed(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``failed`` is the one state that means a server still serves the record."""
    import app.services.dns.record_ops as record_ops

    headers = await _admin_headers(db_session)
    _server, zone, subnet = await _agent_zone_subnet(db_session)
    ids = await _stale_records(db_session, zone, 2)
    await db_session.commit()

    real = record_ops.enqueue_record_ops_batch
    # The handler loads the stale records without an ORDER BY, so which
    # record the first op belongs to is up to Postgres. Remember the one
    # that failed rather than assuming it is ids[0].
    failed_names: list[str] = []

    async def _first_fails(db, z, ops):  # noqa: ANN001
        rows = await real(db, z, ops)
        rows[0].state = "failed"
        rows[0].last_error = "REFUSED"
        failed_names.append(rows[0].record["name"])
        return rows

    # ``_apply_dns_sync`` imports the name locally at call time, so the module
    # attribute is the seam.
    monkeypatch.setattr(record_ops, "enqueue_record_ops_batch", _first_fails)

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/dns-sync/commit",
        headers=headers,
        json={"delete_stale_record_ids": [str(i) for i in ids]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["deleted"] == 1, body
    assert len(body["errors"]) == 1 and "REFUSED" in body["errors"][0], body

    db_session.expire_all()
    left = (await db_session.execute(select(DNSRecord).where(DNSRecord.id.in_(ids)))).scalars()
    assert [r.name for r in left] == failed_names

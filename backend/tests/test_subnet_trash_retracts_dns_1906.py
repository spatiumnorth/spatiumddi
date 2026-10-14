"""spatiumddi#1906 — trashing a subnet retracts its own auto-generated DNS records.

A soft-deleted subnet kept its addresses, so its A / PTR / gateway PTR kept being
served from a reverse zone kept for a surviving sibling (and from the forward
zone). They are now retracted with the subnet and ride its batch; restore
re-asserts them.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1906-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dns(
    db: AsyncSession, *, driver: str = "bind9"
) -> tuple[DNSServerGroup, DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g1906-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
        host="10.9.9.9",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"purge-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add_all([server, zone])
    await db.flush()
    return grp, server, zone


async def _space_block(db: AsyncSession, network: str) -> tuple[IPSpace, IPBlock]:
    space = IPSpace(name=f"sp1906-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name="b")
    db.add(block)
    await db.flush()
    return space, block


async def _bound_subnet(
    client: AsyncClient,
    headers: dict[str, str],
    space: IPSpace,
    block: IPBlock,
    network: str,
    grp: DNSServerGroup,
    zone: DNSZone,
    **extra: object,
) -> str:
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=headers,
        json={
            "space_id": str(space.id),
            "block_id": str(block.id),
            "network": network,
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(zone.id),
            **extra,
        },
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _address(
    client: AsyncClient, headers: dict[str, str], sid: str, address: str, hostname: str, **extra
) -> str:
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": address, "hostname": hostname, **extra},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _live_records(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, str]]:
    rows = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type, DNSRecord.value)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted(tuple(r) for r in rows)


async def _ops(db: AsyncSession, server: DNSServer) -> list[tuple[str, str, str, str, list[str]]]:
    """(zone, op, name, type, final RRset values) of every op queued for a server."""
    rows = (
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server.id)))
        .scalars()
        .all()
    )
    out = []
    for o in rows:
        members = (o.record.get("rrset") or {}).get("members")
        out.append(
            (
                o.zone_name,
                o.op,
                o.record["name"],
                o.record["type"],
                sorted(m["value"] for m in members or []),
            )
        )
    return sorted(out)


async def _clear_ops(db: AsyncSession) -> None:
    await db.execute(delete(DNSRecordOp))
    await db.commit()


def _record_wakes(monkeypatch: pytest.MonkeyPatch, module: str) -> list[str]:
    woken: list[str] = []

    async def _publish(*channels: str) -> None:
        woken.extend(channels)

    # raising=False: on a build without the wake the patch is a no-op and the
    # test fails on what it is about (the records), not on the patch.
    monkeypatch.setattr(f"{module}.publish_wake", _publish, raising=False)
    return woken


async def _setup(client, db, headers, cidr_a, cidr_b, base):  # type: ignore[no-untyped-def]
    grp, server, zone = await _dns(db)
    space, block = await _space_block(db, base)
    await db.commit()
    a = await _bound_subnet(client, headers, space, block, cidr_a, grp, zone)
    b = await _bound_subnet(client, headers, space, block, cidr_b, grp, zone) if cidr_b else None
    return grp, server, zone, a, b


async def _restore(client, headers, sid):  # type: ignore[no-untyped-def]
    resp = await client.post(f"/api/v1/admin/trash/subnet/{sid}/restore", headers=headers)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_trashing_one_of_two_subnets_sharing_a_reverse_zone_retracts_only_its_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp, server, zone, doomed, sibling = await _setup(
        client, db_session, headers, "10.96.22.0/25", "10.96.22.128/25", "10.96.0.0/16"
    )
    rev = (
        await db_session.execute(select(DNSZone).where(DNSZone.name == "22.96.10.in-addr.arpa."))
    ).scalar_one()
    await _address(client, headers, doomed, "10.96.22.50", "host50")
    await _address(client, headers, sibling, "10.96.22.160", "host160")
    await _clear_ops(db_session)

    resp = await client.delete(f"/api/v1/ipam/subnets/{doomed}", headers=headers)
    assert resp.status_code == 204, resp.text

    # The doomed /25's A, its PTR and its gateway PTR stop being served; the
    # survivor's (and its gateway PTR) are untouched.
    assert await _live_records(db_session, zone.id) == [("host160", "A", "10.96.22.160")]
    assert await _live_records(db_session, rev.id) == [
        ("129", "PTR", f"gateway.{zone.name}"),
        ("160", "PTR", f"host160.{zone.name}"),
    ]
    assert await _ops(db_session, server) == [
        ("22.96.10.in-addr.arpa.", "delete", "1", "PTR", []),
        ("22.96.10.in-addr.arpa.", "delete", "50", "PTR", []),
        (zone.name, "delete", "host50", "A", []),
    ]
    # They sit in the Trash under the subnet's own batch, not deleted.
    subnet_batch = (
        await db_session.execute(
            select(Subnet.deletion_batch_id)
            .where(Subnet.id == uuid.UUID(doomed))
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    trashed = (
        await db_session.execute(
            select(DNSRecord.name, DNSRecord.record_type)
            .where(DNSRecord.deletion_batch_id == subnet_batch)
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).all()
    assert sorted(tuple(r) for r in trashed) == [("1", "PTR"), ("50", "PTR"), ("host50", "A")]

    # Restore brings them back and re-asserts them on the wire.
    await _clear_ops(db_session)
    await _restore(client, headers, doomed)
    assert await _live_records(db_session, zone.id) == [
        ("host160", "A", "10.96.22.160"),
        ("host50", "A", "10.96.22.50"),
    ]
    assert ("50", "PTR", f"host50.{zone.name}") in await _live_records(db_session, rev.id)
    assert await _ops(db_session, server) == [
        ("22.96.10.in-addr.arpa.", "create", "1", "PTR", [f"gateway.{zone.name}"]),
        ("22.96.10.in-addr.arpa.", "create", "50", "PTR", [f"host50.{zone.name}"]),
        (zone.name, "create", "host50", "A", ["10.96.22.50"]),
    ]


@pytest.mark.asyncio
async def test_a_reverse_zone_that_goes_to_trash_with_its_subnet_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A /24 alone: the reverse zone rides the batch with its PTRs (no PTR op
    is queued for a zone that is no longer served) and restores whole; the
    forward-zone A, which no zone retirement covers, is retracted and returns."""
    headers = await _admin_headers(db_session)
    grp, server, zone, sid, _ = await _setup(
        client, db_session, headers, "10.97.5.0/24", None, "10.97.0.0/16"
    )
    await _address(client, headers, sid, "10.97.5.50", "host50")
    rev = (
        await db_session.execute(select(DNSZone).where(DNSZone.name == "5.97.10.in-addr.arpa."))
    ).scalar_one()
    rev_id = rev.id
    await _clear_ops(db_session)

    resp = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert await _live_records(db_session, zone.id) == []
    assert await _ops(db_session, server) == [(zone.name, "delete", "host50", "A", [])]
    gone = (
        await db_session.execute(
            select(DNSZone.deleted_at)
            .where(DNSZone.id == rev_id)
            .execution_options(include_deleted=True, populate_existing=True)
        )
    ).scalar_one()
    assert gone is not None

    await _clear_ops(db_session)
    await _restore(client, headers, sid)
    assert await _live_records(db_session, zone.id) == [("host50", "A", "10.97.5.50")]
    assert ("50", "PTR", f"host50.{zone.name}") in await _live_records(db_session, rev_id)
    # Only the forward record is re-pushed; the zone's own records come back
    # with the zone (it is re-rendered whole).
    assert await _ops(db_session, server) == [(zone.name, "create", "host50", "A", ["10.97.5.50"])]

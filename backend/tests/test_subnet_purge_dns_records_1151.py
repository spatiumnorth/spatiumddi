"""spatiumddi#1151 — a subnet purged for good takes its DNS records with it.

``ip_address.subnet_id`` is ON DELETE CASCADE but ``dns_record.ip_address_id``
is ON DELETE SET NULL, and neither Trash purge path retracted anything first:
the addresses cascaded away and every auto-generated record IPAM had published
for them survived, ``auto_generated`` with ``ip_address_id`` null, still in its
zone and still served (re-driven on nightly-20260923: ``dig host50.<zone> A``
answered 20 s after ``DELETE /admin/trash/subnet/<id>``). The direct permanent
delete (``?permanent=true``) retracted only the primary A ``ip.dns_record_id``
names, so PTRs in a shared or hand-made reverse zone, extra-zone records and
aliases leaked the same way.

All three now withdraw, through the record-op queue, every LIVE auto-generated
record bound to the addresses of the subnets they are about to hard-delete —
and nothing else: hand-made records, a sibling subnet's records, the records of
a subnet still inside the retention window, and a subnet restored from Trash
are all left alone.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import dns_group_channel
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1151-{uuid.uuid4().hex[:8]}",
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
    grp = DNSServerGroup(name=f"g1151-{uuid.uuid4().hex[:6]}")
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
    space = IPSpace(name=f"sp1151-{uuid.uuid4().hex[:8]}", description="")
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


@pytest.mark.asyncio
async def test_purging_a_subnet_from_trash_withdraws_its_records_and_only_its_records(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reproduced path, DELETE /admin/trash/subnet/{id}, on two /25s that
    share one auto-created /24 reverse zone: trashing the first re-links the
    zone to the second (#1066), so the first's PTRs stay live in it — and on
    c13d8eb6 stayed live, ownerless, after the purge too."""
    woken = _record_wakes(monkeypatch, "app.api.v1.admin.trash")
    headers = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.92.0.0/16")
    await db_session.commit()
    doomed = await _bound_subnet(client, headers, space, block, "10.92.22.0/25", grp, zone)
    sibling = await _bound_subnet(client, headers, space, block, "10.92.22.128/25", grp, zone)
    rev = (
        await db_session.execute(select(DNSZone).where(DNSZone.name == "22.92.10.in-addr.arpa."))
    ).scalar_one()
    host50 = await _address(client, headers, doomed, "10.92.22.50", "host50")
    # A round-robin name across the two subnets: the purge must leave the
    # sibling's member standing, so the queued op's final RRset is exactly it.
    await _address(client, headers, doomed, "10.92.22.60", "rr", force=True)
    await _address(client, headers, sibling, "10.92.22.160", "rr", force=True)
    # A record an operator made by hand, even one linked to the address, is
    # not IPAM's to withdraw.
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            name="manual50",
            fqdn=f"manual50.{zone.name}",
            record_type="TXT",
            value="kept by hand",
            auto_generated=False,
            ip_address_id=uuid.UUID(host50),
        )
    )
    await db_session.commit()

    resp = await client.delete(f"/api/v1/ipam/subnets/{doomed}", headers=headers)
    assert resp.status_code == 204, resp.text
    # While the subnet sits in Trash nothing is withdrawn (#1152's copy says
    # so): its A record and its PTRs in the shared zone still answer.
    assert ("host50", "A", "10.92.22.50") in await _live_records(db_session, zone.id)
    assert ("50", "PTR", f"host50.{zone.name}") in await _live_records(db_session, rev.id)
    await _clear_ops(db_session)

    resp = await client.delete(f"/api/v1/admin/trash/subnet/{doomed}", headers=headers)
    assert resp.status_code == 204, resp.text

    assert await _live_records(db_session, zone.id) == [
        ("manual50", "TXT", "kept by hand"),
        ("rr", "A", "10.92.22.160"),
    ]
    assert await _live_records(db_session, rev.id) == [
        ("129", "PTR", f"gateway.{zone.name}"),
        ("160", "PTR", f"rr.{zone.name}"),
    ]
    manual = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.name == "manual50")
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert manual.ip_address_id is None  # the FK's SET NULL, as before
    assert await _ops(db_session, server) == [
        ("22.92.10.in-addr.arpa.", "delete", "1", "PTR", []),
        ("22.92.10.in-addr.arpa.", "delete", "50", "PTR", []),
        ("22.92.10.in-addr.arpa.", "delete", "60", "PTR", []),
        (zone.name, "delete", "host50", "A", []),
        (zone.name, "delete", "rr", "A", ["10.92.22.160"]),
    ]
    assert woken == [dns_group_channel(grp.id)]


@pytest.mark.asyncio
async def test_the_scheduled_purge_withdraws_records_only_for_subnets_past_retention(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other Trash purge path: purge_expired_soft_deletes' Core DELETE."""
    woken = _record_wakes(monkeypatch, "app.tasks.trash_purge")
    headers = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.94.0.0/16")
    await db_session.commit()
    old = await _bound_subnet(client, headers, space, block, "10.94.40.0/24", grp, zone)
    recent = await _bound_subnet(client, headers, space, block, "10.94.41.0/24", grp, zone)
    await _address(client, headers, old, "10.94.40.50", "old50")
    recent_ip = await _address(client, headers, recent, "10.94.41.50", "recent50")
    for sid in (old, recent):
        resp = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
        assert resp.status_code == 204, resp.text
    # Age the whole of OLD's deletion batch (the subnet and the reverse zone
    # that went to the trash with it) past the 30-day window.
    batch_id = (
        await db_session.execute(
            select(Subnet.deletion_batch_id)
            .where(Subnet.id == uuid.UUID(old))
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    aged = datetime.now(UTC) - timedelta(days=31)
    for model in (Subnet, DNSZone, DNSRecord):
        await db_session.execute(
            update(model).where(model.deletion_batch_id == batch_id).values(deleted_at=aged)
        )
    await db_session.commit()
    await _clear_ops(db_session)

    from app.tasks.trash_purge import _sweep

    result = await _sweep()

    assert result["per_type"]["subnet"] == 1
    live = await _live_records(db_session, zone.id)
    assert ("old50", "A", "10.94.40.50") not in live
    assert ("recent50", "A", "10.94.41.50") in live  # inside the window: untouched
    assert result["address_records_retracted"] == 1
    recent_rec = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.name == "recent50")
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert str(recent_rec.ip_address_id) == recent_ip
    assert await _ops(db_session, server) == [(zone.name, "delete", "old50", "A", [])]
    assert woken == [dns_group_channel(grp.id)]


@pytest.mark.asyncio
async def test_permanent_delete_withdraws_shared_zone_ptrs_extra_zone_records_and_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """DELETE /ipam/subnets/{id}?permanent=true retracted only the primary A
    (``ip.dns_record_id``). The PTRs in a reverse zone a surviving sibling
    keeps, the A in an extra zone and the alias were left behind the same
    way."""
    headers = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    extra = DNSZone(
        group_id=grp.id,
        name=f"extra-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(extra)
    space, block = await _space_block(db_session, "10.95.0.0/16")
    await db_session.commit()
    sid = await _bound_subnet(client, headers, space, block, "10.95.30.0/25", grp, zone)
    sibling = await _bound_subnet(client, headers, space, block, "10.95.30.128/25", grp, zone)
    await _address(
        client,
        headers,
        sid,
        "10.95.30.50",
        "web",
        extra_zone_ids=[str(extra.id)],
        aliases=[{"name": "www", "record_type": "CNAME"}],
    )
    rev = (
        await db_session.execute(select(DNSZone).where(DNSZone.name == "30.95.10.in-addr.arpa."))
    ).scalar_one()
    assert ("web", "A", "10.95.30.50") in await _live_records(db_session, extra.id)
    await _clear_ops(db_session)

    resp = await client.delete(
        f"/api/v1/ipam/subnets/{sid}?permanent=true&force=true", headers=headers
    )
    assert resp.status_code == 204, resp.text

    assert await _live_records(db_session, zone.id) == []
    assert await _live_records(db_session, extra.id) == []
    # The shared zone stays, re-linked to the sibling, holding only its PTRs.
    rev_row = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == rev.id).execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert str(rev_row.linked_subnet_id) == sibling
    assert await _live_records(db_session, rev.id) == [("129", "PTR", f"gateway.{zone.name}")]
    assert await _ops(db_session, server) == [
        ("30.95.10.in-addr.arpa.", "delete", "1", "PTR", []),
        ("30.95.10.in-addr.arpa.", "delete", "50", "PTR", []),
        (extra.name, "delete", "web", "A", []),
        (zone.name, "delete", "web", "A", []),
        (zone.name, "delete", "www", "CNAME", []),
    ]


class _RecordingDriver:
    """An agentless (Windows DNS) driver that records what it is handed."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str, str]] = []

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        self.changes.append((change.op, change.record.name, change.record.record_type))

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        from app.drivers.dns.base import RecordChangeResult

        for change in changes:
            await self.apply_record_change(server, change)
        return [RecordChangeResult(ok=True) for _ in changes]


@pytest.mark.asyncio
async def test_purge_from_trash_pushes_the_delete_to_an_agentless_primary(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers = await _admin_headers(db_session)
    grp, _, zone = await _dns(db_session, driver="windows_dns")
    space, block = await _space_block(db_session, "10.96.0.0/16")
    await db_session.commit()
    rec = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: rec)
    sid = await _bound_subnet(client, headers, space, block, "10.96.50.0/24", grp, zone)
    await _address(client, headers, sid, "10.96.50.50", "win50")
    resp = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert resp.status_code == 204, resp.text
    rec.changes.clear()

    resp = await client.delete(f"/api/v1/admin/trash/subnet/{sid}", headers=headers)
    assert resp.status_code == 204, resp.text

    assert rec.changes == [("delete", "win50", "A")]
    assert await _live_records(db_session, zone.id) == []


@pytest.mark.asyncio
async def test_a_subnet_restored_from_trash_keeps_every_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only a hard delete withdraws anything: an address that comes back with
    its subnet is not "really gone"."""
    headers = await _admin_headers(db_session)
    grp, server, zone = await _dns(db_session)
    space, block = await _space_block(db_session, "10.97.0.0/16")
    await db_session.commit()
    sid = await _bound_subnet(client, headers, space, block, "10.97.60.0/24", grp, zone)
    ip_id = await _address(client, headers, sid, "10.97.60.50", "back50")
    await _clear_ops(db_session)

    resp = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert resp.status_code == 204, resp.text
    resp = await client.post(f"/api/v1/admin/trash/subnet/{sid}/restore", headers=headers)
    assert resp.status_code == 200, resp.text

    assert ("back50", "A", "10.97.60.50") in await _live_records(db_session, zone.id)
    assert [op for op in await _ops(db_session, server) if op[1] == "delete"] == []
    ip = (
        await db_session.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert ip.dns_record_id is not None

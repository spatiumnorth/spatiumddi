"""Edit / delete locks on IPAM, DNS and DHCP objects (#3361).

Every assertion goes through the HTTP surface: the lock API, then the ordinary
write routes the lock has to stop.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _user(
    db: AsyncSession, *, superadmin: bool = True, perms: list[dict[str, str]] | None = None
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"lk-{tag}",
        email=f"{tag}@example.test",
        display_name=f"Locker {tag}",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    if perms is not None:
        role = Role(name=f"r-{tag}", description="", permissions=perms)
        group = Group(name=f"g-{tag}", description="")
        group.roles = [role]
        group.users = [user]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _ipam(db: AsyncSession) -> tuple[IPSpace, IPBlock, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.30.0.0/24", name="lan")
    db.add(subnet)
    await db.flush()
    return space, block, subnet


async def _lock(
    client: AsyncClient,
    headers: dict[str, str],
    rtype: str,
    rid: uuid.UUID,
    level: str = "edit",
    reason: str = "change freeze",
) -> Any:
    return await client.put(
        f"/api/v1/locks/{rtype}/{rid}",
        headers=headers,
        json={"level": level, "reason": reason},
    )


# ── The lock API ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lock_needs_the_lock_grant_and_a_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    # ``admin`` on the type does not imply ``lock``.
    writer = await _user(
        db_session, superadmin=False, perms=[{"action": "admin", "resource_type": "subnet"}]
    )
    locker = await _user(
        db_session, superadmin=False, perms=[{"action": "lock", "resource_type": "subnet"}]
    )
    admin = await _user(db_session)
    sid = subnet.id
    await db_session.commit()

    assert (await _lock(client, writer, "subnet", sid)).status_code == 403
    blank = await client.put(
        f"/api/v1/locks/subnet/{sid}", headers=locker, json={"level": "edit", "reason": "  "}
    )
    assert blank.status_code == 422
    ok = await _lock(client, locker, "subnet", sid, "delete", "audit hold")
    assert ok.status_code == 200
    body = ok.json()
    assert body["level"] == "delete" and body["reason"] == "audit hold"
    assert body["locked_by"].startswith("lk-")

    # Unlocking also takes a reason, and the lock grant (or a superadmin).
    assert (
        await client.post(
            f"/api/v1/locks/subnet/{sid}/unlock", headers=writer, json={"reason": "x"}
        )
    ).status_code == 403
    assert (
        await client.post(f"/api/v1/locks/subnet/{sid}/unlock", headers=admin, json={"reason": ""})
    ).status_code == 422
    assert (
        await client.post(
            f"/api/v1/locks/subnet/{sid}/unlock", headers=admin, json={"reason": "freeze over"}
        )
    ).status_code == 204

    actions = [
        (a.action, a.new_value)
        for a in (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_id == str(sid)).order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    ]
    assert [a for a, _ in actions] == ["lock", "unlock"]
    assert actions[1][1] == {"reason": "freeze over"}


@pytest.mark.asyncio
async def test_integration_owned_rows_cannot_be_locked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.30.0.5", status="allocated", auto_from_lease=True
    )
    db_session.add(ip)
    await db_session.flush()
    ip_id = ip.id
    await db_session.commit()
    resp = await _lock(client, admin, "ip_address", ip_id)
    assert resp.status_code == 409
    assert "cannot be locked" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_list_shows_active_locks_only(client: AsyncClient, db_session: AsyncSession) -> None:
    space, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    sid = subnet.id
    quiet = IPSpace(name=f"quiet-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(quiet)
    await db_session.flush()
    spid = quiet.id
    del space
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid)).status_code == 200
    # A lock past its expiry is no lock (#63's change window hook).
    sp = await db_session.get(IPSpace, spid)
    assert sp is not None
    sp.lock_level = "delete"
    sp.locked_by = "someone"
    sp.lock_reason = "old window"
    sp.lock_expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()
    listed = (await client.get("/api/v1/locks", headers=admin)).json()
    assert [(i["resource_type"], i["resource_id"]) for i in listed["items"]] == [
        ("subnet", str(sid))
    ]
    # ... and the expired lock refuses nothing.
    assert (
        await client.delete(f"/api/v1/ipam/spaces/{spid}?permanent=false", headers=admin)
    ).status_code == 204


# ── IPAM ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_edit_lock_freezes_operative_fields_not_annotations(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    sid = subnet.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid, "edit", "PCI freeze")).status_code == 200

    renamed = await client.put(f"/api/v1/ipam/subnets/{sid}", headers=admin, json={"name": "wan"})
    assert renamed.status_code == 423
    detail = renamed.json()["detail"]
    assert detail["code"] == "resource_locked"
    assert detail["level"] == "edit" and detail["reason"] == "PCI freeze"
    assert detail["locked_by"].startswith("lk-")
    assert "name" in detail["fields"]

    # Re-sending the stored value is not a change; annotations stay editable.
    same = await client.put(
        f"/api/v1/ipam/subnets/{sid}",
        headers=admin,
        json={"name": "lan", "description": "owned by net-eng", "tags": {"env": "prod"}},
    )
    assert same.status_code == 200, same.text
    assert same.json()["description"] == "owned by net-eng"


@pytest.mark.asyncio
async def test_delete_lock_leaves_edits_but_blocks_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    sid = subnet.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid, "delete")).status_code == 200

    assert (
        await client.put(f"/api/v1/ipam/subnets/{sid}", headers=admin, json={"name": "wan"})
    ).status_code == 200
    gone = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=admin)
    assert gone.status_code == 423
    assert gone.json()["detail"]["code"] == "resource_locked"
    assert await db_session.get(Subnet, sid) is not None


@pytest.mark.asyncio
async def test_parent_delete_names_the_locked_descendant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space, block, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    sid, bid, spid = subnet.id, block.id, space.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid, "edit")).status_code == 200

    for url in (f"/api/v1/ipam/blocks/{bid}", f"/api/v1/ipam/spaces/{spid}"):
        resp = await client.delete(url, headers=admin)
        assert resp.status_code == 423, url
        children = resp.json()["detail"]["locked_descendants"]
        assert [(c["resource_type"], c["resource_id"]) for c in children] == [("subnet", str(sid))]
        assert "10.30.0.0/24" in resp.json()["detail"]["message"]


@pytest.mark.asyncio
async def test_address_lock_and_the_dns_record_it_publishes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="lock.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.lock.example.",
        admin_email="admin.lock.example.",
    )
    db_session.add(zone)
    await db_session.flush()
    ip = IPAddress(subnet_id=subnet.id, address="10.30.0.20", status="allocated", hostname="web1")
    db_session.add(ip)
    await db_session.flush()
    rec = DNSRecord(
        zone_id=zone.id,
        name="web1",
        fqdn="web1.lock.example.",
        record_type="A",
        value="10.30.0.20",
        ttl=300,
        auto_generated=True,
        ip_address_id=ip.id,
    )
    db_session.add(rec)
    await db_session.flush()
    ip_id, rec_id = ip.id, rec.id
    await db_session.commit()

    # Locking the DNS record (not the address) stops IPAM rewriting or
    # removing it through the sync: the IPAM change is refused, naming it.
    assert (
        await _lock(client, admin, "dns_record", rec_id, "edit", "prod name")
    ).status_code == 200
    rename = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=admin, json={"hostname": "web2"}
    )
    assert rename.status_code == 423
    detail = rename.json()["detail"]
    assert [c["resource_id"] for c in detail["locked_descendants"]] == [str(rec_id)]
    assert "web1" in detail["message"]
    delete = await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=admin)
    assert delete.status_code == 423
    await db_session.refresh(rec)
    assert rec.name == "web1"

    # An annotation edit does not touch the record, so it goes through.
    ok = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=admin, json={"description": "web tier"}
    )
    assert ok.status_code == 200, ok.text

    # A lock on the address itself freezes its hostname.
    assert (await _lock(client, admin, "ip_address", ip_id, "edit")).status_code == 200
    frozen = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=admin, json={"hostname": "web3"}
    )
    assert frozen.status_code == 423
    assert frozen.json()["detail"]["resource_type"] == "ip_address"


@pytest.mark.asyncio
async def test_bulk_edit_and_delete_skip_locked_rows_and_report_them(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    space, block, subnet = await _ipam(db_session)
    other = Subnet(space_id=space.id, block_id=block.id, network="10.31.0.0/24", name="lab")
    db_session.add(other)
    await db_session.flush()
    a = IPAddress(subnet_id=subnet.id, address="10.30.0.7", status="allocated")
    b = IPAddress(subnet_id=subnet.id, address="10.30.0.8", status="allocated")
    db_session.add_all([a, b])
    admin = await _user(db_session)
    await db_session.flush()
    sid, oid, aid, bid = subnet.id, other.id, a.id, b.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid, "edit")).status_code == 200
    assert (await _lock(client, admin, "ip_address", aid, "edit")).status_code == 200

    sub = await client.post(
        "/api/v1/ipam/subnets/bulk-edit",
        headers=admin,
        json={"subnet_ids": [str(sid), str(oid)], "changes": {"name": "renamed"}},
    )
    assert sub.status_code == 200, sub.text
    body = sub.json()
    assert body["updated_count"] == 1
    assert [s["resource_id"] for s in body["skipped_locked"]] == [str(sid)]

    ips = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=admin,
        json={"ip_ids": [str(aid), str(bid)], "changes": {"status": "reserved"}},
    )
    assert ips.status_code == 200, ips.text
    assert ips.json()["updated_count"] == 1
    assert [x["resource_id"] for x in ips.json()["locked"]] == [str(aid)]

    dele = await client.post(
        "/api/v1/ipam/addresses/bulk-delete", headers=admin, json={"ip_ids": [str(aid), str(bid)]}
    )
    assert dele.status_code == 200, dele.text
    assert [x["resource_id"] for x in dele.json()["locked"]] == [str(aid)]
    assert str(aid) in dele.json()["skipped_reasons"]


@pytest.mark.asyncio
async def test_structural_operations_refuse_a_locked_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    admin = await _user(db_session)
    sid = subnet.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid, "edit")).status_code == 200
    resize = await client.post(
        f"/api/v1/ipam/subnets/{sid}/resize", headers=admin, json={"new_cidr": "10.30.0.0/23"}
    )
    assert resize.status_code == 423, resize.text
    split = await client.post(
        f"/api/v1/ipam/subnets/{sid}/split/commit",
        headers=admin,
        json={"new_prefix_length": 25, "confirm_cidr": "10.30.0.0/24"},
    )
    assert split.status_code == 423, split.text


# ── DNS ──────────────────────────────────────────────────────────────────


async def _zone_with_record(db: AsyncSession) -> tuple[DNSServerGroup, DNSZone, DNSRecord]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    rec = DNSRecord(
        zone_id=zone.id,
        name="www",
        fqdn=f"www.{zone.name}",
        record_type="A",
        value="192.0.2.10",
        ttl=300,
    )
    db.add(rec)
    await db.flush()
    return grp, zone, rec


@pytest.mark.asyncio
async def test_record_lock_freezes_value_and_blocks_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, zone, rec = await _zone_with_record(db_session)
    other = DNSRecord(
        zone_id=zone.id,
        name="mail",
        fqdn=f"mail.{zone.name}",
        record_type="A",
        value="192.0.2.11",
        ttl=300,
    )
    db_session.add(other)
    admin = await _user(db_session)
    await db_session.flush()
    gid, zid, rid, oid = grp.id, zone.id, rec.id, other.id
    await db_session.commit()
    base = f"/api/v1/dns/groups/{gid}/zones/{zid}/records"
    assert (await _lock(client, admin, "dns_record", rid, "edit")).status_code == 200

    val = await client.put(f"{base}/{rid}", headers=admin, json={"value": "192.0.2.99"})
    assert val.status_code == 423
    assert val.json()["detail"]["code"] == "resource_locked"
    ttl = await client.put(f"{base}/{rid}", headers=admin, json={"ttl": 60})
    assert ttl.status_code == 423
    tags = await client.put(f"{base}/{rid}", headers=admin, json={"tags": {"owner": "web"}})
    assert tags.status_code == 200, tags.text
    assert (await client.delete(f"{base}/{rid}", headers=admin)).status_code == 423

    bulk = await client.post(
        f"{base}/bulk-delete", headers=admin, json={"record_ids": [str(rid), str(oid)]}
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json()["deleted"] == 1
    skipped = bulk.json()["skipped"]
    assert [(s["record_id"], s["code"]) for s in skipped] == [(str(rid), "resource_locked")]


@pytest.mark.asyncio
async def test_zone_lock_blocks_settings_and_delete_and_zone_delete_names_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, zone, rec = await _zone_with_record(db_session)
    admin = await _user(db_session)
    gid, zid, rid = grp.id, zone.id, rec.id
    await db_session.commit()
    zurl = f"/api/v1/dns/groups/{gid}/zones/{zid}"

    # A locked record keeps its zone from being deleted.
    assert (await _lock(client, admin, "dns_record", rid, "delete")).status_code == 200
    resp = await client.delete(zurl, headers=admin)
    assert resp.status_code == 423
    assert [c["resource_id"] for c in resp.json()["detail"]["locked_descendants"]] == [str(rid)]

    assert (await _lock(client, admin, "dns_zone", zid, "edit")).status_code == 200
    soa = await client.put(zurl, headers=admin, json={"ttl": 120})
    assert soa.status_code == 423
    assert soa.json()["detail"]["resource_type"] == "dns_zone"
    note = await client.put(zurl, headers=admin, json={"tags": {"team": "dns"}})
    assert note.status_code == 200, note.text


# ── DHCP ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dhcp_scope_and_reservation_locks(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    admin = await _user(db_session)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="sc", address_family="ipv4")
    db_session.add(scope)
    await db_session.flush()
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address="10.30.0.50", mac_address="aa:bb:cc:dd:ee:01", hostname="p1"
    )
    db_session.add(st)
    await db_session.flush()
    scope_id, st_id = scope.id, st.id
    await db_session.commit()

    assert (await _lock(client, admin, "dhcp_static", st_id, "edit")).status_code == 200
    mac = await client.put(
        f"/api/v1/dhcp/statics/{st_id}", headers=admin, json={"mac_address": "aa:bb:cc:dd:ee:02"}
    )
    assert mac.status_code == 423
    assert mac.json()["detail"]["resource_type"] == "dhcp_static"
    # The same MAC in another notation is not a change.
    same = await client.put(
        f"/api/v1/dhcp/statics/{st_id}",
        headers=admin,
        json={"mac_address": "AA-BB-CC-DD-EE-01", "description": "printer"},
    )
    assert same.status_code == 200, same.text
    assert (await client.delete(f"/api/v1/dhcp/statics/{st_id}", headers=admin)).status_code == 423

    # A locked reservation keeps its scope from being deleted.
    gone = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=admin)
    assert gone.status_code == 423
    assert [c["resource_id"] for c in gone.json()["detail"]["locked_descendants"]] == [str(st_id)]

    assert (await _lock(client, admin, "dhcp_scope", scope_id, "edit")).status_code == 200
    scope_edit = await client.put(
        f"/api/v1/dhcp/scopes/{scope_id}", headers=admin, json={"lease_time": 7200}
    )
    assert scope_edit.status_code == 423
    pool = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/pools",
        headers=admin,
        json={"start_ip": "10.30.0.100", "end_ip": "10.30.0.120"},
    )
    assert pool.status_code == 423


# ── Lock state on the read models ────────────────────────────────────────


@pytest.mark.asyncio
async def test_read_models_carry_the_lock_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, _, subnet = await _ipam(db_session)
    grp, zone, rec = await _zone_with_record(db_session)
    admin = await _user(db_session)
    sid, gid, zid, rid = subnet.id, grp.id, zone.id, rec.id
    await db_session.commit()
    assert (await _lock(client, admin, "subnet", sid, "delete", "audit hold")).status_code == 200
    assert (await _lock(client, admin, "dns_record", rid, "edit", "prod")).status_code == 200

    db_session.expunge_all()  # the handler reads fresh rows, as a real request would
    got = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=admin)).json()
    assert (got["lock_level"], got["lock_reason"]) == ("delete", "audit hold")
    assert got["locked_by"].startswith("lk-") and got["locked_at"]

    rows = (await client.get(f"/api/v1/dns/groups/{gid}/zones/{zid}/records", headers=admin)).json()
    items = rows["items"] if isinstance(rows, dict) else rows
    assert [(r["id"], r["lock_level"]) for r in items] == [(str(rid), "edit")]

    # An unlocked object reads as unlocked, and an expired lock does too.
    other = (await client.get(f"/api/v1/dns/groups/{gid}", headers=admin)).json()
    assert other["lock_level"] is None
    r = await db_session.get(DNSRecord, rid)
    assert r is not None
    r.lock_expires_at = datetime.now(UTC) - timedelta(seconds=5)
    await db_session.commit()
    rows = (await client.get(f"/api/v1/dns/groups/{gid}/zones/{zid}/records", headers=admin)).json()
    items = rows["items"] if isinstance(rows, dict) else rows
    assert items[0]["lock_level"] is None


# ── Automatic writers skip, request paths refuse ─────────────────────────


@pytest.mark.asyncio
async def test_dns_sync_skips_a_locked_record_for_background_callers(
    db_session: AsyncSession,
) -> None:
    from fastapi import HTTPException

    from app.api.v1.ipam.router import _sync_dns_record

    _, _, subnet = await _ipam(db_session)
    grp, zone, _ = await _zone_with_record(db_session)
    ip = IPAddress(subnet_id=subnet.id, address="10.30.0.40", status="allocated", hostname="old")
    db_session.add(ip)
    await db_session.flush()
    rec = DNSRecord(
        zone_id=zone.id,
        name="old",
        fqdn=f"old.{zone.name}",
        record_type="A",
        value="10.30.0.40",
        ttl=300,
        auto_generated=True,
        ip_address_id=ip.id,
        lock_level="edit",
        locked_by="ops",
        lock_reason="frozen",
    )
    db_session.add(rec)
    await db_session.flush()
    ip.hostname = "renamed"  # what DDNS or an importer would have just written

    # A background path (DDNS, the scheduled sync, an importer) skips the
    # address and leaves the record exactly as it is.
    assert await _sync_dns_record(db_session, ip, subnet, zone_id=zone.id, action="update") is False
    await db_session.refresh(rec)
    assert (rec.name, rec.value) == ("old", "10.30.0.40")
    # A request path is refused, naming the record.
    with pytest.raises(HTTPException) as exc:
        await _sync_dns_record(
            db_session, ip, subnet, zone_id=zone.id, action="update", strict=True
        )
    assert exc.value.status_code == 423
    assert exc.value.detail["locked_descendants"][0]["resource_id"] == str(rec.id)  # type: ignore[index]
    # Removing the address's records is skipped the same way.
    assert await _sync_dns_record(db_session, ip, subnet, action="delete") is False
    assert await db_session.get(DNSRecord, rec.id) is not None


@pytest.mark.asyncio
async def test_zone_file_import_leaves_a_locked_record_and_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp, zone, rec = await _zone_with_record(db_session)
    admin = await _user(db_session)
    gid, zid, rid, zname = grp.id, zone.id, rec.id, zone.name
    await db_session.commit()
    assert (await _lock(client, admin, "dns_record", rid, "edit", "prod name")).status_code == 200
    body = {
        "zone_file": f"$ORIGIN {zname}\n$TTL 300\nwww 600 IN A 192.0.2.10\n",
        "conflict_strategy": "replace",
    }
    resp = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/import/commit", headers=admin, json=body
    )
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["updated"] == 0 and out["deleted"] == 0
    assert any("locked" in line and "prod name" in line for line in out["skipped"])
    record = await db_session.get(DNSRecord, rid)
    assert record is not None
    await db_session.refresh(record)
    assert record.ttl == 300

"""IPAM "Populate from DNS" (#2251): preview, link instead of duplicate,
dynamic records, and no DNS write at all."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

PREVIEW = "/api/v1/ipam/import/dns/preview"
COMMIT = "/api/v1/ipam/import/dns/commit"


async def _user(db: AsyncSession, perms: list[dict] | None = None) -> dict[str, str]:
    user = User(
        username=f"u2251-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=perms is None,
    )
    user.groups = []
    if perms is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:8]}", permissions=perms)
        grp = Group(name=f"g-{uuid.uuid4().hex[:8]}")
        grp.roles = [role]
        user.groups = [grp]
        db.add_all([role, grp])
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


class Rig:
    space_id: uuid.UUID
    block_id: uuid.UUID
    subnet_id: uuid.UUID
    zone_id: uuid.UUID
    zone2_id: uuid.UUID
    zone_name: str


async def _rig(db: AsyncSession) -> Rig:
    r = Rig()
    grp = DNSServerGroup(name=f"g2251-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="windows_dns",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    z1 = DNSZone(
        group_id=grp.id,
        name=f"corp-{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.x.test.",
        admin_email="a.x.test.",
    )
    z2 = DNSZone(
        group_id=grp.id,
        name=f"lab-{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.x.test.",
        admin_email="a.x.test.",
    )
    db.add_all([z1, z2])
    space = IPSpace(name=f"sp2251-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.51.0.0/16", name="b")
    db.add(block)
    await db.flush()
    sn = Subnet(space_id=space.id, block_id=block.id, network="10.51.1.0/24", name="s")
    db.add(sn)
    await db.flush()
    r.space_id, r.block_id, r.subnet_id = space.id, block.id, sn.id
    r.zone_id, r.zone2_id, r.zone_name = z1.id, z2.id, z1.name
    await db.commit()
    return r


def _rec(zone_id: uuid.UUID, zone_name: str, name: str, value: str, **kw: Any) -> DNSRecord:
    return DNSRecord(
        zone_id=zone_id,
        name=name,
        fqdn=f"{name}.{zone_name.rstrip('.')}",
        record_type=kw.pop("rtype", "A"),
        value=value,
        auto_generated=False,
        **kw,
    )


async def _seed(db: AsyncSession, r: Rig) -> dict[str, DNSRecord]:
    recs = {
        "new": _rec(r.zone_id, r.zone_name, "web1", "10.51.1.10"),
        "linkme": _rec(r.zone_id, r.zone_name, "db1", "10.51.1.11"),
        "same": _rec(r.zone_id, r.zone_name, "app1", "10.51.1.12"),
        "clash": _rec(r.zone_id, r.zone_name, "old", "10.51.1.13"),
        "multi_a": _rec(r.zone_id, r.zone_name, "alpha", "10.51.1.14"),
        "multi_b": _rec(r.zone_id, r.zone_name, "beta", "10.51.1.14"),
        "dyn": _rec(r.zone_id, r.zone_name, "pc1", "10.51.1.20", dynamic=True),
        "outside": _rec(r.zone_id, r.zone_name, "far", "192.168.77.5"),
    }
    db.add_all(recs.values())
    await db.flush()
    sid = r.subnet_id
    db.add_all(
        [
            IPAddress(subnet_id=sid, address="10.51.1.11", status="allocated", hostname="db1"),
            IPAddress(
                subnet_id=sid,
                address="10.51.1.12",
                status="allocated",
                hostname="app1",
                dns_record_id=recs["same"].id,
            ),
            IPAddress(subnet_id=sid, address="10.51.1.13", status="allocated", hostname="mine"),
        ]
    )
    await db.commit()
    return recs


def _body(r: Rig, **kw: Any) -> dict[str, Any]:
    return {"subnet_id": str(r.subnet_id), "zone_ids": [str(r.zone_id)], **kw}


def _cat(body: dict, addr: str) -> dict:
    return next(i for i in body["items"] if i["address"] == addr)


@pytest.mark.asyncio
async def test_preview_classifies_every_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session)
    r = await _rig(db_session)
    await _seed(db_session, r)
    resp = await client.post(PREVIEW, headers=h, json=_body(r))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _cat(body, "10.51.1.10")["category"] == "new"
    assert _cat(body, "10.51.1.11")["category"] == "link"
    assert _cat(body, "10.51.1.12")["category"] == "linked"
    c = _cat(body, "10.51.1.13")
    assert (c["category"], c["reason"]) == ("conflict", "hostname_differs")
    c = _cat(body, "10.51.1.14")
    assert (c["category"], c["reason"]) == ("conflict", "several_names")
    assert _cat(body, "10.51.1.20")["category"] == "dynamic"
    assert body["outside"][0]["network"] == "192.168.77.0/24"
    assert body["records_scanned"] == 8


@pytest.mark.asyncio
async def test_commit_links_without_any_dns_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session)
    r = await _rig(db_session)
    recs = await _seed(db_session, r)
    ids = {k: v.id for k, v in recs.items()}
    before = (await db_session.execute(select(func.count()).select_from(DNSRecord))).scalar_one()
    zone_serial = (await db_session.get(DNSZone, r.zone_id)).last_serial  # type: ignore[union-attr]
    resp = await client.post(COMMIT, headers=h, json=_body(r, status="reserved"))
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert (out["created"], out["linked"]) == (1, 1)

    db_session.expire_all()
    new = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.51.1.10"))
    ).scalar_one()
    assert new.status == "reserved" and new.hostname == "web1"
    assert new.dns_record_id == ids["new"] and new.forward_zone_id == r.zone_id
    assert new.import_source == "dns" and new.imported_at is not None
    linked = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.51.1.11"))
    ).scalar_one()
    assert linked.dns_record_id == ids["linkme"] and linked.status == "allocated"
    # The conflicts and the dynamic record were not touched.
    for a in ("10.51.1.13", "10.51.1.14", "10.51.1.20"):
        n = (
            await db_session.execute(
                select(func.count()).select_from(IPAddress).where(IPAddress.address == a)
            )
        ).scalar_one()
        assert n == (1 if a == "10.51.1.13" else 0)
    # No DNS write: same records, no queued op, no serial bump, record not claimed.
    assert (
        await db_session.execute(select(func.count()).select_from(DNSRecord))
    ).scalar_one() == before
    assert (
        await db_session.execute(select(func.count()).select_from(DNSRecordOp))
    ).scalar_one() == 0
    assert (await db_session.get(DNSZone, r.zone_id)).last_serial == zone_serial  # type: ignore[union-attr]
    rec = await db_session.get(DNSRecord, ids["new"])
    assert rec.auto_generated is False and rec.ip_address_id is None  # type: ignore[union-attr]
    # Audited per row and per batch.
    acts = (await db_session.execute(select(AuditLog.action, AuditLog.resource_type))).all()
    assert ("populate_from_dns", "subnet") in acts
    assert acts.count(("create", "ip_address")) >= 1

    # Re-run: everything already linked or held back, nothing new.
    again = await client.post(COMMIT, headers=h, json=_body(r))
    assert (again.json()["created"], again.json()["linked"]) == (0, 0)
    # IPAM now reads the adopted record as in sync, not as a missing twin.
    s = await client.get(f"/api/v1/ipam/subnets/{r.subnet_id}/dns-sync/summary", headers=h)
    assert s.status_code == 200, s.text


@pytest.mark.asyncio
async def test_dynamic_records_follow_the_operators_choice(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session)
    r = await _rig(db_session)
    await _seed(db_session, r)
    ok = await client.post(COMMIT, headers=h, json=_body(r, dynamic_action="dhcp"))
    assert ok.status_code == 200, ok.text
    db_session.expire_all()
    row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.51.1.20"))
    ).scalar_one()
    assert row.status == "dhcp" and row.hostname == "pc1"


@pytest.mark.asyncio
async def test_conflict_resolution_names_the_winner(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session)
    r = await _rig(db_session)
    recs = await _seed(db_session, r)
    ids = {k: v.id for k, v in recs.items()}
    res = {"10.51.1.14": str(ids["multi_b"]), "10.51.1.13": str(ids["clash"])}
    out = await client.post(COMMIT, headers=h, json=_body(r, resolutions=res))
    assert out.status_code == 200, out.text
    db_session.expire_all()
    a = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.51.1.14"))
    ).scalar_one()
    assert a.hostname == "beta" and a.dns_record_id == ids["multi_b"]
    b = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.51.1.13"))
    ).scalar_one()
    assert b.hostname == "old" and b.dns_record_id == ids["clash"]


@pytest.mark.asyncio
async def test_permissions_on_both_ipam_and_dns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    r = await _rig(db_session)
    await _seed(db_session, r)
    # IPAM write without DNS read on the zone: refused.
    h1 = await _user(
        db_session,
        [
            {"action": "write", "resource_type": "subnet"},
            {"action": "read", "resource_type": "ip_space"},
        ],
    )
    resp = await client.post(PREVIEW, headers=h1, json=_body(r))
    assert resp.status_code == 403, resp.text
    # DNS read but only IPAM read: the router gate refuses the write.
    h2 = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "subnet"},
            {"action": "read", "resource_type": "dns_zone"},
        ],
    )
    assert (await client.post(PREVIEW, headers=h2, json=_body(r))).status_code == 403
    assert (await client.post(COMMIT, headers=h2, json=_body(r))).status_code == 403
    # Both: allowed.
    h3 = await _user(
        db_session,
        [
            {"action": "write", "resource_type": "subnet"},
            {"action": "read", "resource_type": "dns_zone"},
        ],
    )
    assert (await client.post(PREVIEW, headers=h3, json=_body(r))).status_code == 200


@pytest.mark.asyncio
async def test_space_scope_matches_most_specific_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session)
    r = await _rig(db_session)
    inner = Subnet(space_id=r.space_id, block_id=r.block_id, network="10.51.1.128/25", name="in")
    db_session.add(inner)
    db_session.add(_rec(r.zone_id, r.zone_name, "deep", "10.51.1.130"))
    await db_session.commit()
    resp = await client.post(PREVIEW, headers=h, json={"space_id": str(r.space_id)})
    assert resp.status_code == 200, resp.text
    assert _cat(resp.json(), "10.51.1.130")["subnet"] == "10.51.1.128/25"

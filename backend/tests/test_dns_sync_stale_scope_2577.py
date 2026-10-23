"""Sync DNS offers and deletes only the subnet's own orphaned records (#2577).

An auto-generated record whose IPAM address was deleted keeps no link back
(``ip_address_id`` is SET NULL). The stale scan reported every such A / AAAA
orphan in the subnet's forward zone as the subnet's own — so a zone shared by
several subnets, or by several spaces, offered all of their orphans for
deletion on any one subnet's Sync DNS, and auto-sync with delete-stale on
deleted them. Three fixes, each pinned here:

* the scan reports an A / AAAA orphan only when its value lies inside the
  subnet (the #1840 PTR narrowing, applied to forward records);
* the commit deletes only IDs the scope's own report lists, whatever the
  request names, and returns the rest as ``skipped_stale_record_ids``;
* auto-sync deletes the narrowed set.

The zone's group has no server, so a delete is DB-only (#623) and needs no
wire op.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings
from app.services.dns.sync_check import (
    compute_space_dns_drift,
    compute_subnet_dns_drift,
)


@dataclass
class _Env:
    headers: dict[str, str]
    space_a: IPSpace
    space_b: IPSpace
    block_a: IPBlock
    sn_a1: Subnet  # space A, 10.77.1.0/24
    sn_a3: Subnet  # space A, 10.77.3.0/24
    sn_b2: Subnet  # space B, 10.77.2.0/24
    zone: DNSZone
    # orphan name → record id
    rec: dict[str, uuid.UUID]


async def _setup(db: AsyncSession) -> _Env:
    user = User(
        username=f"ds-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="DNS Sync Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="shared.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.shared.example.",
        admin_email="admin.shared.example.",
    )
    db.add(zone)
    space_a = IPSpace(name=f"a-{uuid.uuid4().hex[:6]}", description="")
    space_b = IPSpace(name=f"b-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([space_a, space_b])
    await db.flush()
    block_a = IPBlock(space_id=space_a.id, network="10.77.0.0/16", name="blk-a")
    block_b = IPBlock(space_id=space_b.id, network="10.77.0.0/16", name="blk-b")
    db.add_all([block_a, block_b])
    await db.flush()

    def _subnet(space: IPSpace, block: IPBlock, net: str) -> Subnet:
        return Subnet(
            space_id=space.id,
            block_id=block.id,
            network=net,
            name=net,
            dns_zone_id=str(zone.id),
            dns_inherit_settings=False,
        )

    sn_a1 = _subnet(space_a, block_a, "10.77.1.0/24")
    sn_a3 = _subnet(space_a, block_a, "10.77.3.0/24")
    sn_b2 = _subnet(space_b, block_b, "10.77.2.0/24")
    db.add_all([sn_a1, sn_a3, sn_b2])
    await db.flush()

    # Orphaned auto-generated records in the one shared forward zone: one per
    # subnet, plus one whose address no subnet holds.
    orphans = {
        "ghost1": ("A", "10.77.1.9"),
        "ghost2": ("A", "10.77.2.9"),
        "ghost3": ("A", "10.77.3.9"),
        "elsewhere": ("A", "10.99.0.1"),
        "ghost6": ("AAAA", "2001:db8::9"),
    }
    rec: dict[str, uuid.UUID] = {}
    for name, (rtype, value) in orphans.items():
        r = DNSRecord(
            zone_id=zone.id,
            name=name,
            fqdn=f"{name}.shared.example.",
            record_type=rtype,
            value=value,
            auto_generated=True,
            ip_address_id=None,
        )
        db.add(r)
        await db.flush()
        rec[name] = r.id
    await db.commit()
    return _Env(
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
        space_a=space_a,
        space_b=space_b,
        block_a=block_a,
        sn_a1=sn_a1,
        sn_a3=sn_a3,
        sn_b2=sn_b2,
        zone=zone,
        rec=rec,
    )


async def _surviving(db: AsyncSession, env: _Env) -> set[str]:
    db.expire_all()
    ids = set(
        (await db.execute(select(DNSRecord.id).where(DNSRecord.id.in_(env.rec.values()))))
        .scalars()
        .all()
    )
    return {name for name, rid in env.rec.items() if rid in ids}


@pytest.mark.asyncio
async def test_sync_check_reports_only_the_subnets_own_orphans(
    db_session: AsyncSession,
) -> None:
    env = await _setup(db_session)
    for sn, expected in (
        (env.sn_a1, {"ghost1"}),
        (env.sn_a3, {"ghost3"}),
        (env.sn_b2, {"ghost2"}),
    ):
        report = await compute_subnet_dns_drift(db_session, sn.id)
        assert {s.name for s in report.stale} == expected, sn.network
        assert {s.reason for s in report.stale} == {"ip-deleted"}

    # A space aggregate is its own subnets' orphans and no other space's.
    space_report = await compute_space_dns_drift(db_session, env.space_a.id)
    assert sorted(s.name for s in space_report.stale) == ["ghost1", "ghost3"]


@pytest.mark.asyncio
async def test_an_ipv6_orphan_is_reported_by_the_v6_subnet_only(
    db_session: AsyncSession,
) -> None:
    env = await _setup(db_session)
    block6 = IPBlock(space_id=env.space_a.id, network="2001:db8::/48", name="v6")
    db_session.add(block6)
    await db_session.flush()
    sn6 = Subnet(
        space_id=env.space_a.id,
        block_id=block6.id,
        network="2001:db8::/64",
        name="v6",
        dns_zone_id=str(env.zone.id),
        dns_inherit_settings=False,
    )
    db_session.add(sn6)
    await db_session.commit()
    report = await compute_subnet_dns_drift(db_session, sn6.id)
    assert {s.name for s in report.stale} == {"ghost6"}


@pytest.mark.asyncio
async def test_subnet_commit_ignores_other_subnets_orphans(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _setup(db_session)
    sent = [env.rec[n] for n in ("ghost1", "ghost2", "ghost3", "elsewhere")]
    resp = await client.post(
        f"/api/v1/ipam/subnets/{env.sn_a1.id}/dns-sync/commit",
        headers=env.headers,
        json={"delete_stale_record_ids": [str(i) for i in sent]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Its own orphan is still deleted …
    assert body["deleted"] == 1, body
    assert body["errors"] == [], body
    # … and the rest are reported as skipped, not deleted.
    assert set(body["skipped_stale_record_ids"]) == {
        str(env.rec[n]) for n in ("ghost2", "ghost3", "elsewhere")
    }
    assert await _surviving(db_session, env) == {"ghost2", "ghost3", "elsewhere", "ghost6"}


@pytest.mark.asyncio
async def test_space_and_block_commits_ignore_another_spaces_orphans(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _setup(db_session)
    resp = await client.post(
        f"/api/v1/ipam/spaces/{env.space_a.id}/dns-sync/commit",
        headers=env.headers,
        json={"delete_stale_record_ids": [str(env.rec["ghost2"]), str(env.rec["ghost3"])]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] == 1
    assert resp.json()["skipped_stale_record_ids"] == [str(env.rec["ghost2"])]

    resp = await client.post(
        f"/api/v1/ipam/blocks/{env.block_a.id}/dns-sync/commit",
        headers=env.headers,
        json={"delete_stale_record_ids": [str(env.rec["ghost2"]), str(env.rec["ghost1"])]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] == 1
    assert resp.json()["skipped_stale_record_ids"] == [str(env.rec["ghost2"])]

    assert await _surviving(db_session, env) == {"ghost2", "elsewhere", "ghost6"}


@pytest.mark.asyncio
async def test_auto_sync_deletes_only_in_subnet_orphans(
    db_session: AsyncSession,
) -> None:
    from app.tasks.ipam_dns_sync import _run_auto_sync  # noqa: PLC0415

    env = await _setup(db_session)
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_auto_sync_enabled = True
    ps.dns_auto_sync_delete_stale = True
    ps.dns_auto_sync_last_run_at = None
    await db_session.commit()

    result = await _run_auto_sync()
    assert result.get("status") not in ("disabled", "skipped"), result

    # Each subnet deleted its own orphan; the one whose address no subnet
    # holds (and the v6 one, with no v6 subnet) belongs to none of them and is
    # left alone — before #2577 the first subnet to run deleted all five.
    assert await _surviving(db_session, env) == {"elsewhere", "ghost6"}

"""Sync DNS keeps an address in the zone it was put in (#2104).

IPAM lets an operator put an address in a zone other than its subnet's
(Allocate / Edit / Bulk edit offer it), kept in ``ip_address.forward_zone_id``,
and #493 made later edits keep it. Sync DNS worked each address's zone out from
its subnet instead: the preview listed the address's A and PTR as mismatched,
and committing them (the dialog's default, and auto-sync's every run) moved the
host back into the subnet's zone and rewrote its PTR to name it. With no zone on
the subnet at all, the same records were listed stale and deleted.

These run Sync DNS at subnet, block and space scope and through auto-sync, on
an address placed in another zone the way an operator places one (bulk edit),
and assert the preview lists nothing for it and a commit of the default
selection leaves its records, its PTR and its ``forward_zone_id`` where they
are.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.settings import PlatformSettings
from tests.test_ipam_alias_cname_exclusive_2080 import _headers

_SUBNET = "10.104.5.0/24"


class _Env:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.space_id = ""
        self.block_id = ""
        self.sid = ""
        self.zone: DNSZone  # the subnet's zone, Z
        self.other: DNSZone  # the zone the address is put in, T


async def _new_zone(db: AsyncSession, group_id: uuid.UUID, prefix: str) -> DNSZone:
    z = DNSZone(
        group_id=group_id,
        name=f"{prefix}{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.flush()
    return z


async def _setup(client: AsyncClient, db: AsyncSession) -> _Env:
    env = _Env()
    env.headers = await _headers(db)
    grp = DNSServerGroup(name=f"g2104-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    env.zone = await _new_zone(db, grp.id, "z")
    env.other = await _new_zone(db, grp.id, "t")
    space = IPSpace(name=f"sp2104-{uuid.uuid4().hex[:8]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.104.0.0/16", name="b")
    db.add(block)
    await db.flush()
    env.space_id, env.block_id = str(space.id), str(block.id)
    await db.commit()
    resp = await client.post(
        "/api/v1/ipam/subnets",
        headers=env.headers,
        json={
            "space_id": env.space_id,
            "block_id": env.block_id,
            "network": _SUBNET,
            "dns_group_id": str(grp.id),
            "dns_zone_id": str(env.zone.id),
        },
    )
    assert resp.status_code == 201, resp.text
    env.sid = str(resp.json()["id"])
    return env


async def _rows(db: AsyncSession, ip_id: str) -> list[DNSRecord]:
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.ip_address_id == uuid.UUID(ip_id))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )


async def _ip(db: AsyncSession, ip_id: str) -> IPAddress:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _ops_in(db: AsyncSession, zone_id: uuid.UUID) -> int:
    return len(
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.zone_id == zone_id)))
        .scalars()
        .all()
    )


async def _placed(
    client: AsyncClient,
    db: AsyncSession,
    env: _Env,
    addr: str,
    host: str,
    *,
    extra_zone: DNSZone | None = None,
    **body: object,
) -> str:
    """Allocate ``host`` in the subnet's zone, then move it into the other
    zone with Bulk edit, as the operator in the issue did."""
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.sid}/addresses",
        headers=env.headers,
        json={"address": addr, "hostname": host, **body},
    )
    assert r.status_code == 201, r.text
    ip_id = str(r.json()["id"])
    b = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=env.headers,
        json={"ip_ids": [ip_id], "changes": {"dns_zone_id": str(env.other.id)}},
    )
    assert b.status_code == 200, b.text
    await _assert_in_other_zone(db, env, ip_id, host, extra_zone)
    return ip_id


async def _assert_in_other_zone(
    db: AsyncSession, env: _Env, ip_id: str, host: str, extra: DNSZone | None = None
) -> None:
    rows = [r for r in await _rows(db, ip_id) if not r.ip_alias]
    fwd = [
        (r.zone_id, r.name)
        for r in rows
        if r.record_type == "A" and (extra is None or r.zone_id != extra.id)
    ]
    assert fwd == [(env.other.id, host)], fwd
    ptr = [r.value for r in rows if r.record_type == "PTR"]
    assert ptr == [f"{host}.{env.other.name}"], ptr
    ip = await _ip(db, ip_id)
    assert ip.forward_zone_id == env.other.id
    assert ip.fqdn == f"{host}.{env.other.name.rstrip('.')}"


def _for(items: list[dict[str, Any]], ip_id: str) -> list[dict[str, Any]]:
    return [i for i in items if i.get("ip_id") == ip_id]


async def _preview(client: AsyncClient, env: _Env, scope: str) -> dict[str, Any]:
    path = {
        "subnet": f"subnets/{env.sid}",
        "block": f"blocks/{env.block_id}",
        "space": f"spaces/{env.space_id}",
    }[scope]
    r = await client.get(f"/api/v1/ipam/{path}/dns-sync/preview", headers=env.headers)
    assert r.status_code == 200, r.text
    return r.json()


async def _commit_default(
    client: AsyncClient, env: _Env, scope: str, rep: dict[str, Any], also_ip: str
) -> None:
    """Commit what the dialog ticks by default (every row), plus a re-sync of
    the address itself, which is what a "missing" row for it would do."""
    path = {
        "subnet": f"subnets/{env.sid}",
        "block": f"blocks/{env.block_id}",
        "space": f"spaces/{env.space_id}",
    }[scope]
    c = await client.post(
        f"/api/v1/ipam/{path}/dns-sync/commit",
        headers=env.headers,
        json={
            "create_for_ip_ids": sorted({m["ip_id"] for m in rep["missing"]} | {also_ip}),
            "update_record_ids": [m["record_id"] for m in rep["mismatched"]],
            "delete_stale_record_ids": [s["record_id"] for s in rep["stale"]],
        },
    )
    assert c.status_code == 200, c.text
    assert c.json()["errors"] == [], c.text


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["subnet", "block", "space"])
async def test_sync_dns_leaves_an_address_in_its_own_zone(
    client: AsyncClient, db_session: AsyncSession, scope: str
) -> None:
    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.20", "h1")
    # A neighbour in the subnet's zone, so the scope is not trivially empty.
    n = await client.post(
        f"/api/v1/ipam/subnets/{env.sid}/addresses",
        headers=env.headers,
        json={"address": "10.104.5.21", "hostname": "n1"},
    )
    assert n.status_code == 201, n.text

    rep = await _preview(client, env, scope)
    assert _for(rep["mismatched"], ip_id) == []
    assert _for(rep["missing"], ip_id) == []
    assert _for(rep["stale"], ip_id) == []
    assert rep["mismatched"] == [] and rep["missing"] == [] and rep["stale"] == []

    before = await _ops_in(db_session, env.zone.id)
    await _commit_default(client, env, scope, rep, ip_id)
    await _assert_in_other_zone(db_session, env, ip_id, "h1")
    # Nothing was written to, or retracted from, the subnet's zone for it.
    assert await _ops_in(db_session, env.zone.id) == before
    assert (await _preview(client, env, scope))["mismatched"] == []


@pytest.mark.asyncio
async def test_a_record_left_in_the_subnet_zone_is_listed_with_its_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The other direction still reads as drift: the address is in T, but its
    A sits in Z (an import, a restore). The row names the zone the record is
    in, since name and value read the same on both sides, and the commit moves
    it to the address's zone, not the subnet's."""
    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.22", "h2")
    a = next(r for r in await _rows(db_session, ip_id) if r.record_type == "A")
    a.zone_id = env.zone.id
    await db_session.commit()

    rep = await _preview(client, env, "subnet")
    mm = [m for m in rep["mismatched"] if m["record_type"] == "A"]
    assert [(m["record_id"], m["zone_id"], m["zone_name"]) for m in mm] == [
        (str(a.id), str(env.zone.id), env.zone.name)
    ]
    await _commit_default(client, env, "subnet", rep, ip_id)
    await _assert_in_other_zone(db_session, env, ip_id, "h2")


@pytest.mark.asyncio
async def test_a_subnet_with_no_zone_keeps_an_address_with_its_own(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """With no zone on the subnet, the address's A and PTR were listed as
    stale, and committing the default selection deleted them."""
    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.23", "h3")
    sn = await db_session.get(Subnet, uuid.UUID(env.sid))
    assert sn is not None
    sn.dns_zone_id = None
    sn.dns_inherit_settings = False
    await db_session.commit()

    rep = await _preview(client, env, "subnet")
    assert rep["forward_zone_id"] is None
    assert _for(rep["stale"], ip_id) == []
    assert _for(rep["mismatched"], ip_id) == []
    assert _for(rep["missing"], ip_id) == []
    await _commit_default(client, env, "subnet", rep, ip_id)
    await _assert_in_other_zone(db_session, env, ip_id, "h3")


@pytest.mark.asyncio
async def test_an_address_in_its_own_zone_with_an_extra_zone_is_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2107's extra zones, on an address whose primary is not the subnet's
    zone: the host record is checked in its own zone and the extra one."""
    env = await _setup(client, db_session)
    extra = await _new_zone(db_session, env.zone.group_id, "x")
    await db_session.commit()
    ip_id = await _placed(
        client,
        db_session,
        env,
        "10.104.5.24",
        "h4",
        extra_zone_ids=[str(extra.id)],
        extra_zone=extra,
    )
    fwd = sorted(str(r.zone_id) for r in await _rows(db_session, ip_id) if r.record_type == "A")
    assert fwd == sorted([str(env.other.id), str(extra.id)])

    rep = await _preview(client, env, "subnet")
    assert rep["mismatched"] == [] and rep["missing"] == [] and rep["stale"] == []
    await _commit_default(client, env, "subnet", rep, ip_id)
    assert (
        sorted(str(r.zone_id) for r in await _rows(db_session, ip_id) if r.record_type == "A")
        == fwd
    )
    await _assert_in_other_zone(db_session, env, ip_id, "h4", extra)


@pytest.mark.asyncio
async def test_an_address_in_its_own_zone_keeps_its_alias(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2105's alias marker: the alias is neither drift nor moved."""
    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.25", "h5")
    add = await client.post(
        f"/api/v1/ipam/addresses/{ip_id}/aliases",
        headers=env.headers,
        json={"name": "www5", "record_type": "A"},
    )
    assert add.status_code in (200, 201), add.text
    aliases = sorted(
        (r.id, r.zone_id, r.name, r.value) for r in await _rows(db_session, ip_id) if r.ip_alias
    )
    assert [(z, n) for _, z, n, _ in aliases] == [(env.other.id, "www5")]

    rep = await _preview(client, env, "subnet")
    assert rep["mismatched"] == [] and rep["missing"] == [] and rep["stale"] == []
    await _commit_default(client, env, "subnet", rep, ip_id)
    await _assert_in_other_zone(db_session, env, ip_id, "h5")
    assert (
        sorted(
            (r.id, r.zone_id, r.name, r.value) for r in await _rows(db_session, ip_id) if r.ip_alias
        )
        == aliases
    )


@pytest.mark.asyncio
async def test_auto_sync_leaves_an_address_in_its_own_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.tasks.ipam_dns_sync import _run_auto_sync  # noqa: PLC0415

    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.26", "h6")
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_auto_sync_enabled = True
    ps.dns_auto_sync_delete_stale = True
    ps.dns_auto_sync_last_run_at = None
    await db_session.commit()

    before = await _ops_in(db_session, env.zone.id)
    result = await _run_auto_sync()
    assert result.get("status") not in ("disabled", "skipped"), result
    await _assert_in_other_zone(db_session, env, ip_id, "h6")
    assert await _ops_in(db_session, env.zone.id) == before


@pytest.mark.asyncio
async def test_editing_a_reservation_keeps_its_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The same class on the DHCP path: a ``static_dhcp`` row's edit runs
    ``upsert_ipam_for_static``, which re-synced DNS with no zone."""
    env = await _setup(client, db_session)
    dgrp = DHCPServerGroup(name=f"d2104-{uuid.uuid4().hex[:6]}")
    db_session.add(dgrp)
    await db_session.flush()
    db_session.add(
        DHCPServer(
            name=f"d-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=dgrp.id,
        )
    )
    db_session.add(
        DHCPScope(
            group_id=dgrp.id,
            subnet_id=uuid.UUID(env.sid),
            name="scope",
            address_family="ipv4",
        )
    )
    await db_session.commit()

    ip_id = await _placed(
        client,
        db_session,
        env,
        "10.104.5.27",
        "h7",
        status="static_dhcp",
        mac_address="aa:bb:cc:21:04:07",
    )
    ip = await _ip(db_session, ip_id)
    assert ip.static_assignment_id is not None

    for body in (
        {"description": "moved"},
        {"mac_address": "aa:bb:cc:21:04:08"},
        {"hostname": "h7b"},
    ):
        r = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=env.headers, json=body)
        assert r.status_code == 200, r.text
    await _assert_in_other_zone(db_session, env, ip_id, "h7b")


@pytest.mark.asyncio
async def test_auto_sync_on_a_subnet_with_no_zone_deletes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Auto-sync with delete-stale on, on a subnet whose zone was removed: the
    address still has its own zone, so its A and PTR are not stale."""
    from app.tasks.ipam_dns_sync import _run_auto_sync  # noqa: PLC0415

    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.28", "h8")
    sn = await db_session.get(Subnet, uuid.UUID(env.sid))
    assert sn is not None
    sn.dns_zone_id = None
    sn.dns_inherit_settings = False
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dns_auto_sync_enabled = True
    ps.dns_auto_sync_delete_stale = True
    ps.dns_auto_sync_last_run_at = None
    await db_session.commit()

    await _run_auto_sync()
    await _assert_in_other_zone(db_session, env, ip_id, "h8")


@pytest.mark.asyncio
async def test_extra_zones_naming_the_own_or_the_subnet_zone_dedupe(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An address in T whose extra zones list T itself and the subnet's zone Z:
    one host record in each, all in sync, and the commit keeps both."""
    env = await _setup(client, db_session)
    ip_id = await _placed(
        client,
        db_session,
        env,
        "10.104.5.29",
        "h9",
        extra_zone_ids=[str(env.zone.id)],
        extra_zone=env.zone,
    )
    # Bulk edit kept the extras; add T to them as well.
    r = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=env.headers,
        json={"extra_zone_ids": [str(env.zone.id), str(env.other.id)]},
    )
    assert r.status_code == 200, r.text
    fwd = sorted(str(r.zone_id) for r in await _rows(db_session, ip_id) if r.record_type == "A")
    assert fwd == sorted([str(env.other.id), str(env.zone.id)])

    rep = await _preview(client, env, "subnet")
    assert rep["mismatched"] == [] and rep["missing"] == [] and rep["stale"] == []
    await _commit_default(client, env, "subnet", rep, ip_id)
    assert (
        sorted(str(r.zone_id) for r in await _rows(db_session, ip_id) if r.record_type == "A")
        == fwd
    )
    await _assert_in_other_zone(db_session, env, ip_id, "h9", env.zone)


@pytest.mark.asyncio
@pytest.mark.parametrize("subnet_has_zone", [True, False])
async def test_a_deleted_own_zone_falls_back_to_the_subnet(
    client: AsyncClient, db_session: AsyncSession, subnet_has_zone: bool
) -> None:
    """The address's zone is soft-deleted (its A goes to the trash with it).
    With a zone on the subnet the host is published there again and its PTR
    repointed; with none, the PTR naming the deleted zone is stale and goes.
    Nothing live in another zone is touched either way."""
    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.30", "h10")
    if not subnet_has_zone:
        sn = await db_session.get(Subnet, uuid.UUID(env.sid))
        assert sn is not None
        sn.dns_zone_id = None
        sn.dns_inherit_settings = False
        await db_session.commit()
    d = await client.delete(
        f"/api/v1/dns/groups/{env.other.group_id}/zones/{env.other.id}", headers=env.headers
    )
    assert d.status_code == 204, d.text

    rep = await _preview(client, env, "subnet")
    if subnet_has_zone:
        assert [(m["record_type"], m["zone_id"]) for m in _for(rep["missing"], ip_id)] == [
            ("A", str(env.zone.id))
        ]
        assert [m["expected_value"] for m in _for(rep["mismatched"], ip_id)] == [
            f"h10.{env.zone.name}"
        ]
        assert _for(rep["stale"], ip_id) == []
    else:
        assert _for(rep["missing"], ip_id) == []
        assert [(s["record_type"], s["reason"]) for s in _for(rep["stale"], ip_id)] == [
            ("PTR", "no-forward-zone")
        ]
    await _commit_default(client, env, "subnet", rep, ip_id)

    live = [r for r in await _rows(db_session, ip_id) if r.deleted_at is None]
    if subnet_has_zone:
        assert sorted(
            (r.record_type, r.zone_id == env.zone.id) for r in live if r.record_type == "A"
        ) == [("A", True)]
        assert [r.value for r in live if r.record_type == "PTR"] == [f"h10.{env.zone.name}"]
        assert (await _ip(db_session, ip_id)).forward_zone_id == env.zone.id
    else:
        assert live == []


@pytest.mark.asyncio
async def test_reimporting_an_address_keeps_its_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The address importer's overwrite re-publishes on a hostname change; it
    re-synced with no zone and moved the host into the subnet's."""
    env = await _setup(client, db_session)
    ip_id = await _placed(client, db_session, env, "10.104.5.31", "h11")
    r = await client.post(
        "/api/v1/ipam/import/addresses/commit",
        headers=env.headers,
        files={"file": ("a.csv", b"address,hostname\n10.104.5.31,h11b\n", "text/csv")},
        data={"subnet_id": env.sid, "strategy": "overwrite"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["errors"] == [], r.text
    await _assert_in_other_zone(db_session, env, ip_id, "h11b")


@pytest.mark.asyncio
async def test_block_sync_commit_is_audited_with_the_block_network(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A block commit that changes something names the block's network in its
    audit row (the column once got the ``IPv4Network`` and answered 422)."""
    from app.models.audit import AuditLog  # noqa: PLC0415

    env = await _setup(client, db_session)
    n = await client.post(
        f"/api/v1/ipam/subnets/{env.sid}/addresses",
        headers=env.headers,
        json={"address": "10.104.5.32", "hostname": "h12"},
    )
    assert n.status_code == 201, n.text
    # The create published the record; drop it so the commit writes one (a
    # commit that writes nothing records no audit row, #2352).
    for row in await _rows(db_session, n.json()["id"]):
        await db_session.delete(row)
    await db_session.commit()
    c = await client.post(
        f"/api/v1/ipam/blocks/{env.block_id}/dns-sync/commit",
        headers=env.headers,
        json={"create_for_ip_ids": [n.json()["id"]]},
    )
    assert c.status_code == 200, c.text
    assert c.json()["created"] == 1, c.text
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "dns-sync",
                    AuditLog.resource_type == "block",
                    AuditLog.resource_id == env.block_id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert [a.resource_display for a in rows] == ["10.104.0.0/16"]

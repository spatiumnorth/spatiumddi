"""IPAM writes no twin beside a record an operator already wrote (#1867).

The record API refuses a second identical record with a 409 (#1230), but
IPAM's generated records did not pass through it: an address allocated at a
name (and PTR) an operator had written into the zone got an ``auto_generated``
copy beside it. #1379 / #1280 made PowerDNS tolerate such a pair at render
time; this is the other half, so the pair is never stored. The operator's row
is adopted: the address links to it, nothing is created, and deleting the
address leaves the operator's record served.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

PTR_ZONE = "5.97.10.in-addr.arpa."


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u1867-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


class Rig:
    grp: DNSServerGroup
    space: IPSpace
    block: IPBlock
    fwd: DNSZone
    rev: DNSZone
    # Plain values: the ORM objects expire on the commit the tests make.
    grp_id: uuid.UUID
    space_id: uuid.UUID
    block_id: uuid.UUID
    fwd_id: uuid.UUID
    fwd_name: str
    rev_id: uuid.UUID


async def _rig(db: AsyncSession) -> Rig:
    r = Rig()
    r.grp = DNSServerGroup(name=f"g1867-{uuid.uuid4().hex[:6]}")
    db.add(r.grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=r.grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    r.fwd = DNSZone(
        group_id=r.grp.id,
        name=f"example-{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    r.rev = DNSZone(
        group_id=r.grp.id,
        name=PTR_ZONE,
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db.add_all([r.fwd, r.rev])
    r.space = IPSpace(name=f"sp1867-{uuid.uuid4().hex[:8]}", description="")
    db.add(r.space)
    await db.flush()
    r.block = IPBlock(space_id=r.space.id, network="10.97.0.0/16", name="b")
    db.add(r.block)
    await db.flush()
    r.grp_id, r.space_id, r.block_id = r.grp.id, r.space.id, r.block.id
    r.fwd_id, r.fwd_name, r.rev_id = r.fwd.id, r.fwd.name, r.rev.id
    return r


def _manual(zone_id: uuid.UUID, zone_name: str, name: str, rtype: str, value: str) -> DNSRecord:
    base = zone_name.rstrip(".")
    return DNSRecord(
        zone_id=zone_id,
        name=name,
        fqdn=f"{name}.{base}",
        record_type=rtype,
        value=value,
        auto_generated=False,
    )


async def _subnet(
    client: AsyncClient, headers: dict[str, str], r: Rig, *, bound: bool = True
) -> str:
    body: dict[str, Any] = {
        "space_id": str(r.space_id),
        "block_id": str(r.block_id),
        "network": "10.97.5.0/24",
        "skip_reverse_zone": True,
    }
    if bound:
        body["dns_group_id"] = str(r.grp_id)
        body["dns_zone_id"] = str(r.fwd_id)
    resp = await client.post("/api/v1/ipam/subnets", headers=headers, json=body)
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _allocate(
    client: AsyncClient, headers: dict[str, str], sid: str, address: str, hostname: str
) -> str:
    resp = await client.post(
        f"/api/v1/ipam/subnets/{sid}/addresses",
        headers=headers,
        json={"address": address, "hostname": hostname, "force": True},
    )
    assert resp.status_code == 201, resp.text
    return str(resp.json()["id"])


async def _rows(db: AsyncSession, zone_id: uuid.UUID) -> list[tuple[str, str, str, bool]]:
    db.expire_all()
    rs = (
        await db.execute(
            select(DNSRecord.name, DNSRecord.record_type, DNSRecord.value, DNSRecord.auto_generated)
            .where(DNSRecord.zone_id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).all()
    return sorted((str(n), str(t), str(v), bool(a)) for n, t, v, a in rs)


async def _ip(db: AsyncSession, ip_id: str) -> IPAddress:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_allocation_adopts_the_operators_a_and_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's reproduction: one db1 A by hand, then db1 allocated at that
    address. One record, still the operator's; the PTR likewise."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    manual_a = _manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10")
    manual_ptr = _manual(r.rev_id, PTR_ZONE, "10", "PTR", f"db1.{r.fwd_name}")
    manual_a.id = a_id = uuid.uuid4()
    db_session.add_all([manual_a, manual_ptr])
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    # Binding the subnet created the reverse zone link; we use our own zone.
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")

    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]
    ptrs = [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"]
    assert ptrs == [("10", "PTR", f"db1.{r.fwd_name}", False)]
    ip = await _ip(db_session, ip_id)
    assert ip.dns_record_id == a_id
    assert ip.forward_zone_id == r.fwd_id


@pytest.mark.asyncio
async def test_deleting_the_address_leaves_the_operators_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    r = await _rig(db_session)
    db_session.add_all(
        [
            _manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10"),
            _manual(r.rev_id, PTR_ZONE, "10", "PTR", f"db1.{r.fwd_name}"),
        ]
    )
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")
    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]

    resp = await client.delete(f"/api/v1/ipam/addresses/{ip_id}?permanent=true", headers=headers)
    assert resp.status_code == 204, resp.text

    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]
    assert [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"] == [
        ("10", "PTR", f"db1.{r.fwd_name}", False)
    ]


@pytest.mark.asyncio
async def test_a_different_value_still_gets_its_own_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Adoption is for an identical record only: db1 at another address is a
    different RR, which IPAM still writes."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    db_session.add(_manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.99"))
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    await _allocate(client, headers, sid, "10.97.5.10", "db1")

    assert await _rows(db_session, r.fwd_id) == [
        ("db1", "A", "10.97.5.10", True),
        ("db1", "A", "10.97.5.99", False),
    ]


@pytest.mark.asyncio
async def test_a_generated_record_is_not_adopted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Only an operator's record is adopted: a generated one belongs to its
    own owner, whose removal would otherwise retract this address's name."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    gen = _manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10")
    gen.auto_generated = True
    db_session.add(gen)
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")

    assert [row[3] for row in await _rows(db_session, r.fwd_id)] == [True, True]
    assert (await _ip(db_session, ip_id)).dns_record_id is not None


@pytest.mark.asyncio
async def test_bulk_edit_dns_zone_adopts_the_operators_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    r = await _rig(db_session)
    db_session.add(_manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10"))
    await db_session.commit()
    sid = await _subnet(client, headers, r, bound=False)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")
    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]

    resp = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=headers,
        json={"ip_ids": [ip_id], "changes": {"dns_zone_id": str(r.fwd_id)}},
    )
    assert resp.status_code == 200, resp.text

    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]
    assert (await _ip(db_session, ip_id)).forward_zone_id == r.fwd_id


@pytest.mark.asyncio
async def test_ddns_lease_adopts_the_operators_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    r = await _rig(db_session)
    tag = uuid.uuid4().hex[:6]
    subnet = Subnet(
        space_id=r.space_id,
        block_id=r.block_id,
        network="10.97.5.0/24",
        name="sn",
        dns_zone_id=str(r.fwd_id),
        dns_group_ids=[str(r.grp_id)],
        dns_inherit_settings=False,
        ddns_enabled=True,
        ddns_inherit_settings=False,
        ddns_hostname_policy="client_or_generated",
    )
    db_session.add(subnet)
    await db_session.flush()
    dgrp = DHCPServerGroup(name=f"d-{tag}", description="")
    db_session.add(dgrp)
    await db_session.flush()
    server = DHCPServer(
        name=f"k-{tag}", driver="kea", host="10.0.0.2", port=67, server_group_id=dgrp.id
    )
    db_session.add(server)
    db_session.add(DHCPScope(group_id=dgrp.id, subnet_id=subnet.id, is_active=True))
    db_session.add(_manual(r.fwd_id, r.fwd_name, "printer", "A", "10.97.5.50"))
    db_session.add(_manual(r.rev_id, PTR_ZONE, "50", "PTR", f"printer.{r.fwd_name}"))
    await db_session.commit()

    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    ev = {
        "ip_address": "10.97.5.50",
        "mac_address": "aa:bb:cc:dd:18:67",
        "hostname": "printer",
        "state": "active",
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end,
        "expires_at": end,
    }
    db_session.expunge_all()
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": [ev]})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text

    assert await _rows(db_session, r.fwd_id) == [("printer", "A", "10.97.5.50", False)]
    assert [x for x in await _rows(db_session, r.rev_id) if x[0] == "50"] == [
        ("50", "PTR", f"printer.{r.fwd_name}", False)
    ]


async def _patch_hostname(
    client: AsyncClient, headers: dict[str, str], ip_id: str, hostname: str | None
) -> None:
    resp = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}",
        headers=headers,
        json={"hostname": hostname, "force": True},
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_sync_dns_does_not_report_an_adopted_record_missing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The drift check reads only generated rows, so without knowing about
    adoption it reported the adopted A and PTR missing on every check, and
    applying the sync changed nothing."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    db_session.add_all(
        [
            _manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10"),
            _manual(r.rev_id, PTR_ZONE, "10", "PTR", f"db1.{r.fwd_name}"),
        ]
    )
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    await _allocate(client, headers, sid, "10.97.5.10", "db1")

    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["missing"] == 0, body
    assert body["has_drift"] is False, body


@pytest.mark.asyncio
async def test_sync_dns_still_reports_a_genuinely_missing_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The negative control: an operator record at another value does not
    hide a missing one."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    sid = await _subnet(client, headers, r)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")
    db_session.add(_manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.99"))
    # Drop what IPAM wrote, so the A and PTR are missing.
    for rec in (
        await db_session.execute(
            select(DNSRecord).where(DNSRecord.ip_address_id == uuid.UUID(ip_id))
        )
    ).scalars():
        await db_session.delete(rec)
    await db_session.commit()

    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["missing"] == 2, resp.json()


@pytest.mark.asyncio
async def test_renaming_an_adopted_address_leaves_the_operators_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """After adoption, a new hostname is a new record IPAM writes for itself;
    the operator's row keeps its name and value."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    manual_a = _manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10")
    manual_a.id = a_id = uuid.uuid4()
    db_session.add_all([manual_a, _manual(r.rev_id, PTR_ZONE, "10", "PTR", f"db1.{r.fwd_name}")])
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")
    assert (await _ip(db_session, ip_id)).dns_record_id == a_id

    await _patch_hostname(client, headers, ip_id, "db2")

    assert await _rows(db_session, r.fwd_id) == [
        ("db1", "A", "10.97.5.10", False),
        ("db2", "A", "10.97.5.10", True),
    ]
    assert [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"] == [
        ("10", "PTR", f"db1.{r.fwd_name}", False),
        ("10", "PTR", f"db2.{r.fwd_name}", True),
    ]
    ip = await _ip(db_session, ip_id)
    assert ip.dns_record_id not in (None, a_id)

    # Clearing the hostname retracts IPAM's records only.
    await _patch_hostname(client, headers, ip_id, None)
    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]
    assert [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"] == [
        ("10", "PTR", f"db1.{r.fwd_name}", False)
    ]


@pytest.mark.asyncio
async def test_a_generated_record_renamed_onto_the_operators_is_retracted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The in-place case: IPAM's own db0 A and PTR exist, the operator wrote
    db1 at the same address, and the address is renamed to db1. IPAM's rows
    go (by row, so the operator's stay served) and the address adopts the
    operator's, instead of renaming its own into a twin."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    sid = await _subnet(client, headers, r)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db0")
    manual_a = _manual(r.fwd_id, r.fwd_name, "db1", "A", "10.97.5.10")
    manual_a.id = a_id = uuid.uuid4()
    db_session.add_all([manual_a, _manual(r.rev_id, PTR_ZONE, "10", "PTR", f"db1.{r.fwd_name}")])
    await db_session.commit()

    await _patch_hostname(client, headers, ip_id, "db1")

    assert await _rows(db_session, r.fwd_id) == [("db1", "A", "10.97.5.10", False)]
    assert [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"] == [
        ("10", "PTR", f"db1.{r.fwd_name}", False)
    ]
    assert (await _ip(db_session, ip_id)).dns_record_id == a_id


@pytest.mark.asyncio
async def test_a_dotless_ptr_target_is_not_adopted_and_sync_reports_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2045: a PTR target without its trailing dot is served relative to the
    reverse zone, so it is another record. IPAM writes its own PTR, and the
    drift check reports the address missing while only the relative one exists."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    absolute = f"db1.{r.fwd_name}".rstrip(".") + "."
    dotless = absolute.rstrip(".")
    db_session.add(_manual(r.rev_id, PTR_ZONE, "10", "PTR", dotless))
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    ip_id = await _allocate(client, headers, sid, "10.97.5.10", "db1")

    ptrs = [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"]
    assert ("10", "PTR", absolute, True) in ptrs, ptrs
    assert ("10", "PTR", dotless, False) in ptrs, ptrs

    # Drop IPAM's own PTR: only the relative one is left, and it must not
    # satisfy the check.
    for rec in (
        await db_session.execute(
            select(DNSRecord).where(
                DNSRecord.ip_address_id == uuid.UUID(ip_id), DNSRecord.record_type == "PTR"
            )
        )
    ).scalars():
        await db_session.delete(rec)
    await db_session.commit()
    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    # Exactly the PTR: IPAM's A still stands.
    assert resp.json()["missing"] == 1, resp.json()


@pytest.mark.asyncio
async def test_a_ptr_differing_only_in_case_is_adopted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2045: DNS names compare case-insensitively, so an operator PTR naming
    the same host in other letter case is the same served record. Adopted,
    no twin, and Sync DNS reports nothing missing."""
    headers = await _headers(db_session)
    r = await _rig(db_session)
    upper = f"DB1.{r.fwd_name}".upper()
    db_session.add(_manual(r.rev_id, PTR_ZONE, "10", "PTR", upper))
    await db_session.commit()
    sid = await _subnet(client, headers, r)
    await _allocate(client, headers, sid, "10.97.5.10", "db1")

    assert [x for x in await _rows(db_session, r.rev_id) if x[0] == "10"] == [
        ("10", "PTR", upper, False)
    ]
    resp = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/summary", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["missing"] == 0, resp.json()


async def _ptr_group(db: AsyncSession, servers: list[tuple[str, bytes | None]]) -> DNSZone:
    grp = DNSServerGroup(name=f"g2045-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    for driver, creds in servers:
        db.add(
            DNSServer(
                group_id=grp.id,
                driver=driver,
                host="10.9.9.9",
                name=f"ns-{uuid.uuid4().hex[:6]}",
                is_enabled=True,
                credentials_encrypted=creds,
            )
        )
    rev = DNSZone(
        group_id=grp.id,
        name=PTR_ZONE,
        zone_type="primary",
        kind="reverse",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db.add(rev)
    await db.flush()
    db.add(_manual(rev.id, PTR_ZONE, "10", "PTR", "db1.example.test"))
    await db.flush()
    return rev


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("servers", "adopted"),
    [
        # Zone-file readers: the dot-less target is db1.example.test.<zone>.
        ([("bind9", None)], False),
        ([("technitium", None)], False),
        ([("windows_dns", None)], False),  # Path A, RFC 2136 against the origin
        ([], False),  # no server yet: read as the default driver, BIND9
        # PowerDNS refuses the dot-less spelling, so it is never served.
        ([("powerdns", None)], False),
        # Drivers that take the name as given: the same absolute name.
        ([("route53", None)], True),
        ([("cloudflare", None)], True),
        ([("windows_dns", b"x")], True),  # Path B, -PtrDomainName
        # One relative reader serves the wrong name: not adopted.
        ([("route53", None), ("bind9", None)], False),
    ],
)
async def test_a_dotless_ptr_is_adopted_only_where_it_is_served_absolute(
    db_session: AsyncSession, servers: list[tuple[str, bytes | None]], adopted: bool
) -> None:
    """#2045: whether ``db1.example.test`` is the same record as IPAM's
    ``db1.example.test.`` depends on how the zone's servers read it."""
    from app.api.v1.ipam.router import _operator_record_twin

    rev = await _ptr_group(db_session, servers)
    twin = await _operator_record_twin(
        db_session, rev.id, name="10", rtype="PTR", value="db1.example.test."
    )
    assert (twin is not None) is adopted

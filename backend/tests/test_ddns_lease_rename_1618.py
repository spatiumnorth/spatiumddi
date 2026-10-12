"""spatiumddi#1618 — a hostname change on an existing lease reaches DNS.

Both lease ingest paths stamp the client's new hostname onto the
auto-from-lease IPAM row (``_apply_lease_fields`` in the agent lease-events
handler, ``_refresh_lease_owned_row`` in the agentless pull) before they call
``apply_ddns_for_lease``. Its idempotency check compared the resolved name
with ``ipam_row.hostname`` — which already carried the new name — so a
renamed client kept its old A/PTR and the new name was never published. The
check now compares against the name of the record that is actually
published, so a rename goes through ``_sync_dns_record`` (delete at the old
name, create at the new one) while an unchanged name is still a no-op.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.main import app
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dns.ddns import apply_ddns_for_lease

MAC = "aa:bb:cc:dd:16:18"


async def _setup(
    db: AsyncSession, octet: int, *, ddns: bool = True, driver: str = "kea"
) -> tuple[DHCPServer, Subnet, DNSZone, str]:
    """A DDNS subnet bound to a forward + reverse zone in an agent-based DNS
    group (so record ops are queued), and a DHCP server scoped to it."""
    tag = uuid.uuid4().hex[:6]
    grp = DNSServerGroup(name=f"g-{tag}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"ns-{tag}",
            is_primary=True,
            is_enabled=True,
            agent_id=uuid.uuid4(),
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"r{tag}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.r{tag}.example.",
        admin_email=f"admin.r{tag}.example.",
    )
    db.add(zone)
    space = IPSpace(name=f"sp-{tag}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.93.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=f"10.93.{octet}.0/24",
        name="sn",
        dns_zone_id=str(zone.id),
        dns_group_ids=[str(grp.id)],
        dns_inherit_settings=False,
        ddns_enabled=ddns,
        ddns_inherit_settings=False,
        ddns_hostname_policy="client_or_generated",
    )
    db.add(subnet)
    await db.flush()
    db.add(
        DNSZone(
            group_id=grp.id,
            name=f"{octet}.93.10.in-addr.arpa.",
            zone_type="primary",
            kind="reverse",
            primary_ns=f"ns1.r{tag}.example.",
            admin_email=f"admin.r{tag}.example.",
            linked_subnet_id=subnet.id,
        )
    )
    dgrp = DHCPServerGroup(name=f"d-{tag}", description="")
    db.add(dgrp)
    await db.flush()
    server = DHCPServer(
        name=f"k-{tag}", driver=driver, host="10.0.0.2", port=67, server_group_id=dgrp.id
    )
    db.add(server)
    db.add(DHCPScope(group_id=dgrp.id, subnet_id=subnet.id, is_active=True))
    await db.commit()
    return server, subnet, zone, f"10.93.{octet}.50"


def _lease(ip: str, hostname: str) -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "ip_address": ip,
        "mac_address": MAC,
        "hostname": hostname,
        "state": "active",
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end,
        "expires_at": end,
    }


async def _post(client: AsyncClient, db: AsyncSession, server: DHCPServer, ev: dict) -> None:
    # Load rows the way a real request does (see test_dhcp_lease_peer_guard).
    db.expunge_all()
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": [ev]})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


async def _row(db: AsyncSession, subnet_id: Any, ip: str) -> IPAddress:
    db.expunge_all()
    return (
        await db.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == ip)
        )
    ).scalar_one()


async def _records(db: AsyncSession, row: IPAddress) -> dict[str, list[tuple[str, str]]]:
    recs = (
        (await db.execute(select(DNSRecord).where(DNSRecord.ip_address_id == row.id)))
        .scalars()
        .all()
    )
    out: dict[str, list[tuple[str, str]]] = {}
    for r in recs:
        out.setdefault(r.record_type, []).append((r.name, r.value))
    return out


async def _ops(db: AsyncSession, zone_name: str) -> list[tuple[str, str]]:
    rows = (
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.zone_name == zone_name)
                .order_by(DNSRecordOp.created_at)
            )
        )
        .scalars()
        .all()
    )
    return [(o.op, o.record["name"]) for o in rows]


async def _op_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(DNSRecordOp))).scalar_one()


@pytest.mark.asyncio
async def test_agent_lease_rename_moves_the_ddns_records(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, zone, ip = await _setup(db_session, 1)
    zone_name = zone.name

    await _post(client, db_session, server, _lease(ip, "ddns-a"))
    row = await _row(db_session, subnet.id, ip)
    assert await _records(db_session, row) == {
        "A": [("ddns-a", ip)],
        "PTR": [("50", f"ddns-a.{zone_name}")],
    }

    await _post(client, db_session, server, _lease(ip, "ddns-b"))
    row = await _row(db_session, subnet.id, ip)
    assert row.hostname == "ddns-b"
    assert row.fqdn == f"ddns-b.{zone_name.rstrip('.')}"
    assert await _records(db_session, row) == {
        "A": [("ddns-b", ip)],
        "PTR": [("50", f"ddns-b.{zone_name}")],
    }
    rec = await db_session.get(DNSRecord, row.dns_record_id)
    assert rec is not None and rec.name == "ddns-b"
    # The live servers are told: the old name is deleted, the new one created.
    # Two different names, so no same-name delete+create in one batch (#1489).
    fwd = await _ops(db_session, zone_name)
    assert fwd == [("create", "ddns-a"), ("delete", "ddns-a"), ("create", "ddns-b")]


@pytest.mark.asyncio
async def test_agent_lease_same_name_is_still_a_noop(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, _zone, ip = await _setup(db_session, 2)
    await _post(client, db_session, server, _lease(ip, "ddns-a"))
    before = await _op_count(db_session)
    record_id = (await _row(db_session, subnet.id, ip)).dns_record_id
    assert record_id is not None

    # A renewal with the same name queues nothing and keeps the record.
    await _post(client, db_session, server, _lease(ip, "ddns-a"))
    assert await _op_count(db_session) == before
    assert (await _row(db_session, subnet.id, ip)).dns_record_id == record_id


@pytest.mark.asyncio
async def test_ddns_off_still_mirrors_the_new_hostname(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, _zone, ip = await _setup(db_session, 3, ddns=False)
    await _post(client, db_session, server, _lease(ip, "ddns-a"))
    await _post(client, db_session, server, _lease(ip, "ddns-b"))

    row = await _row(db_session, subnet.id, ip)
    assert row.hostname == "ddns-b"
    assert row.dns_record_id is None
    assert await _records(db_session, row) == {}
    assert await _op_count(db_session) == 0


@pytest.mark.asyncio
async def test_manual_row_keeps_its_name_and_gets_no_ddns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, subnet, _zone, ip = await _setup(db_session, 4)
    db_session.add(
        IPAddress(
            subnet_id=subnet.id, address=ip, status="allocated", hostname="printer", mac_address=MAC
        )
    )
    await db_session.commit()

    await _post(client, db_session, server, _lease(ip, "ddns-b"))
    row = await _row(db_session, subnet.id, ip)
    assert row.hostname == "printer"
    assert row.auto_from_lease is False
    assert await _records(db_session, row) == {}


@pytest.mark.asyncio
async def test_pull_lease_rename_moves_the_ddns_records(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agentless pull refreshes the row's hostname the same way
    (``_refresh_lease_owned_row``) before calling DDNS."""
    from app.services.dhcp import pull_leases as pl

    server, subnet, zone, ip = await _setup(db_session, 5, driver="windows_dhcp")
    zone_name = zone.name
    wire: list[dict[str, Any]] = []

    class _Driver:
        async def get_leases(self, _server: DHCPServer) -> list[dict]:
            return [dict(w) for w in wire]

    monkeypatch.setattr(pl, "get_driver", lambda _drv: _Driver())
    monkeypatch.setattr(pl, "is_agentless", lambda _drv: True)

    for name in ("ddns-a", "ddns-b"):
        wire[:] = [{"ip_address": ip, "mac_address": MAC, "hostname": name}]
        srv = await db_session.get(DHCPServer, server.id)
        assert srv is not None
        await pl.pull_leases_from_server(db_session, srv, apply=True)
        await db_session.commit()

    row = await _row(db_session, subnet.id, ip)
    assert row.hostname == "ddns-b"
    assert await _records(db_session, row) == {
        "A": [("ddns-b", ip)],
        "PTR": [("50", f"ddns-b.{zone_name}")],
    }


@pytest.mark.asyncio
async def test_a_row_left_behind_by_the_bug_is_healed(db_session: AsyncSession) -> None:
    """A row the old code already renamed (hostname new, record old) is
    picked up by the next renewal or the DDNS backstop sweep — both pass the
    row's own hostname back in."""
    _server, subnet, _zone, ip = await _setup(db_session, 6)
    row = IPAddress(
        subnet_id=subnet.id, address=ip, status="dhcp", mac_address=MAC, auto_from_lease=True
    )
    db_session.add(row)
    await db_session.flush()
    assert await apply_ddns_for_lease(
        db_session, subnet=subnet, ipam_row=row, client_hostname="ddns-a"
    )
    row.hostname = "ddns-b"  # what _apply_lease_fields left on the row
    await db_session.commit()

    assert await apply_ddns_for_lease(
        db_session, subnet=subnet, ipam_row=row, client_hostname=row.hostname
    )
    await db_session.commit()
    row = await _row(db_session, subnet.id, ip)
    assert (await _records(db_session, row))["A"] == [("ddns-b", ip)]

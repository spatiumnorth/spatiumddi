"""DHCPv6 leases reach the control plane (#1141).

The agent never tailed ``kea-leases6.csv``, and the ingest required a MAC —
a DHCPv4 identity most DHCPv6 leases (identified by DUID + IAID) do not
carry. So no v6 lease was ever stored, mirrored into IPAM, or fed to DDNS.
Also covered: the agent-path IPAM mirror never stamped ``last_seen_at``, so
every Kea-sourced row — v4 as well — read "Seen: Never"; and DHCPv6's
domain-search (option 24) now falls back like the RA's DNSSL.
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
from app.models.dhcp import DHCPLease, DHCPLeaseHistory, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ai.tools.dhcp import FindDHCPLeasesArgs, find_dhcp_leases
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.lease_history import record_lease_history
from app.services.dhcp.normalize import canonical_duid

_DUID = "00:01:00:01:2c:5f:aa:bb:bc:24:11:41:b7:45"


async def _seed(db: AsyncSession) -> tuple[DHCPServer, Subnet, Subnet]:
    space = IPSpace(name=f"v6l-sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    b6 = IPBlock(space_id=space.id, network="2001:db8:83::/48", name="b6")
    b4 = IPBlock(space_id=space.id, network="10.71.0.0/16", name="b4")
    db.add_all([b6, b4])
    await db.flush()
    s6 = Subnet(space_id=space.id, block_id=b6.id, network="2001:db8:83::/64", name="v6")
    s4 = Subnet(space_id=space.id, block_id=b4.id, network="10.71.1.0/24", name="v4")
    db.add_all([s6, s4])
    server = DHCPServer(
        name=f"v6l-kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=547,
        status="active",
    )
    db.add(server)
    await db.flush()
    return server, s6, s4


def _v6(ip: str = "2001:db8:83::100", **over: Any) -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    ev: dict[str, Any] = {
        "ip_address": ip,
        "duid": _DUID,
        "iaid": 1234,
        "hostname": "client1",
        "state": "active",
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end,
        "expires_at": end,
    }
    ev.update(over)
    return ev


async def _post(client: AsyncClient, server: DHCPServer, *events: dict[str, Any]) -> Any:
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        return await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": list(events)})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def _leases(db: AsyncSession, ip: str) -> list[DHCPLease]:
    # populate_existing: the endpoint wrote through another session, so a
    # row already in this identity map would otherwise come back stale.
    stmt = select(DHCPLease).where(DHCPLease.ip_address == ip)
    return list((await db.execute(stmt.execution_options(populate_existing=True))).scalars())


async def _mirror(db: AsyncSession, subnet: Subnet, ip: str) -> IPAddress | None:
    stmt = select(IPAddress).where(IPAddress.subnet_id == subnet.id, IPAddress.address == ip)
    return (await db.execute(stmt.execution_options(populate_existing=True))).scalar_one_or_none()


@pytest.mark.asyncio
async def test_a_v6_lease_without_a_mac_is_stored_and_mirrored(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, s6, _s4 = await _seed(db_session)
    await db_session.commit()

    resp = await _post(client, server, _v6())
    assert resp.status_code == 200, resp.text
    assert resp.json()["upserted"] == 1

    (lease,) = await _leases(db_session, "2001:db8:83::100")
    assert lease.mac_address is None
    assert (lease.duid, lease.iaid) == (_DUID, 1234)

    row = await _mirror(db_session, s6, "2001:db8:83::100")
    assert row is not None, "the v6 lease reached IPAM"
    assert row.status == "dhcp" and row.auto_from_lease
    assert row.hostname == "client1"
    assert row.mac_address is None
    assert row.last_seen_at is not None and row.last_seen_method == "dhcp"


@pytest.mark.asyncio
async def test_a_renewal_updates_the_same_row_and_a_release_tears_the_mirror_down(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, s6, _s4 = await _seed(db_session)
    await db_session.commit()
    assert (await _post(client, server, _v6())).status_code == 200
    # Renewal — and Kea has learned the hardware address meanwhile.
    renew = _v6(mac_address="bc:24:11:41:b7:45")
    assert (await _post(client, server, renew)).status_code == 200
    (lease,) = await _leases(db_session, "2001:db8:83::100")
    assert str(lease.mac_address) == "bc:24:11:41:b7:45", "enrichment kept"
    assert (await _mirror(db_session, s6, "2001:db8:83::100")) is not None

    assert (await _post(client, server, _v6(state="released"))).status_code == 200
    (lease,) = await _leases(db_session, "2001:db8:83::100")
    assert lease.state == "released"
    assert await _mirror(db_session, s6, "2001:db8:83::100") is None


@pytest.mark.asyncio
async def test_another_client_on_the_same_address_is_another_lease(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _s6, _s4 = await _seed(db_session)
    await db_session.commit()
    assert (await _post(client, server, _v6())).status_code == 200
    other = _v6(duid="00:03:00:01:aa:bb:cc:dd:ee:ff", iaid=7)
    assert (await _post(client, server, other)).status_code == 200
    assert len(await _leases(db_session, "2001:db8:83::100")) == 2


@pytest.mark.asyncio
async def test_each_family_needs_its_own_identity(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _s6, _s4 = await _seed(db_session)
    await db_session.commit()
    no_duid = _v6()
    del no_duid["duid"]
    assert (await _post(client, server, no_duid)).status_code == 422
    v4_no_mac = _v6(ip="10.71.1.50")
    del v4_no_mac["duid"]
    assert (await _post(client, server, v4_no_mac)).status_code == 422
    assert (await _post(client, server, _v6(duid="not-a-duid"))).status_code == 422


def test_duids_are_canonicalised_and_bounded() -> None:
    assert canonical_duid("000100012C5FAABBBC241141B745") == _DUID
    assert canonical_duid(" 00-01-00-01-2c-5f-aa-bb-bc-24-11-41-b7-45 ") == _DUID
    for bad in ("", "0001", "00:01:0", "zz:01:02", "00" * 131):
        with pytest.raises(ValueError):
            canonical_duid(bad)


@pytest.mark.asyncio
async def test_a_kea_v4_lease_now_stamps_last_seen_too(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The agent path never stamped ``last_seen_at``; the pull path always
    did. So every Kea-sourced IPAM row read "Seen: Never"."""
    server, _s6, s4 = await _seed(db_session)
    await db_session.commit()
    v4 = _v6(ip="10.71.1.50", mac_address="aa:bb:cc:dd:ee:ff")
    del v4["duid"], v4["iaid"]
    assert (await _post(client, server, v4)).status_code == 200
    row = await _mirror(db_session, s4, "10.71.1.50")
    assert row is not None
    assert row.last_seen_at is not None and row.last_seen_method == "dhcp"


@pytest.mark.asyncio
async def test_a_macless_lease_goes_to_history_and_lists(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``record_lease_history`` stringified the MAC — ``"None"`` is not a
    MACADDR, so the expiry sweep would have 500'd on the first v6 lease —
    and the lease list declared ``mac_address: str``."""
    server, _s6, _s4 = await _seed(db_session)
    await db_session.commit()
    assert (await _post(client, server, _v6())).status_code == 200
    (lease,) = await _leases(db_session, "2001:db8:83::100")
    record_lease_history(db_session, lease, lease_state="expired")
    await db_session.commit()
    hist = (
        await db_session.execute(
            select(DHCPLeaseHistory).where(DHCPLeaseHistory.server_id == server.id)
        )
    ).scalar_one()
    assert hist.mac_address is None and hist.duid == _DUID

    admin = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db_session.add(admin)
    await db_session.commit()
    resp = await client.get(
        f"/api/v1/dhcp/servers/{server.id}/leases",
        headers={"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    items = body["items"] if isinstance(body, dict) else body
    (item,) = [i for i in items if i["ip_address"] == "2001:db8:83::100"]
    assert item["mac_address"] is None and item["duid"] == _DUID and item["iaid"] == 1234


@pytest.mark.asyncio
async def test_the_copilot_finds_a_lease_by_duid(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, _s6, _s4 = await _seed(db_session)
    await db_session.commit()
    assert (await _post(client, server, _v6())).status_code == 200
    # A second client, so an ignored filter cannot pass by returning everything.
    other = _v6(ip="2001:db8:83::101", duid="00:03:00:01:aa:bb:cc:dd:ee:ff", iaid=7)
    assert (await _post(client, server, other)).status_code == 200
    hits = await find_dhcp_leases(
        db_session, None, FindDHCPLeasesArgs(duid="000100012c5faabbbc241141b745")  # type: ignore[arg-type]
    )
    assert [(h["ip_address"], h["mac_address"], h["duid"]) for h in hits] == [
        ("2001:db8:83::100", None, _DUID)
    ]
    assert await find_dhcp_leases(db_session, None, FindDHCPLeasesArgs(duid="x")) == []  # type: ignore[arg-type]


# ── DHCPv6 domain-search (option 24) falls back like the RA DNSSL ──────────


async def _v6_scope(
    db: AsyncSession, *, mode: str = "stateful", options: dict[str, Any] | None = None
) -> DHCPServer:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=547,
        server_group_id=grp.id,
    )
    db.add(srv)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(name="b6", space_id=space.id, network="2001:db8:524::/48")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        name="v6",
        space_id=space.id,
        block_id=block.id,
        network="2001:db8:524::/64",
        domain_name="corp.example.com",
    )
    db.add(subnet)
    await db.flush()
    db.add(
        DHCPScope(
            name="v6-scope",
            group_id=grp.id,
            subnet_id=subnet.id,
            is_active=True,
            address_family="ipv6",
            v6_address_mode=mode,
            options=options or {},
        )
    )
    await db.flush()
    return srv


@pytest.mark.asyncio
async def test_v6_domain_search_defaults_to_the_subnet_domain(db_session: AsyncSession) -> None:
    srv = await _v6_scope(db_session)
    bundle = await build_config_bundle(db_session, srv)
    (scope,) = bundle.scopes
    assert scope.options["domain-search"] == ["corp.example.com"]


@pytest.mark.asyncio
async def test_a_scopes_own_domain_search_wins(db_session: AsyncSession) -> None:
    srv = await _v6_scope(db_session, options={"domain-search": ["lab.example.net"]})
    (scope,) = (await build_config_bundle(db_session, srv)).scopes
    assert scope.options["domain-search"] == ["lab.example.net"]


@pytest.mark.asyncio
async def test_a_slaac_scope_gains_no_option(db_session: AsyncSession) -> None:
    """A SLAAC scope renders no option-data; adding one would only move the
    bundle's ETag."""
    srv = await _v6_scope(db_session, mode="slaac")
    (scope,) = (await build_config_bundle(db_session, srv)).scopes
    assert "domain-search" not in scope.options


@pytest.mark.asyncio
async def test_a_v6_lease_publishes_aaaa_and_ip6_arpa_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """DDNS was never the gap — ``_sync_dns_record`` picks AAAA for an IPv6
    row — but it is only reached through a lease event, and none ever
    arrived for v6. End to end through the ingest."""
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    fwd = DNSZone(
        group_id=grp.id,
        name="v6.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.v6.example.",
        admin_email="admin.v6.example.",
    )
    db_session.add(fwd)
    space = IPSpace(name=f"v6d-sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="2001:db8:83::/48", name="b6")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="2001:db8:83::/64",
        name="v6-ddns",
        dns_zone_id=str(fwd.id),
        dns_inherit_settings=False,
        ddns_enabled=True,
        ddns_inherit_settings=False,
        ddns_hostname_policy="client_or_generated",
    )
    db_session.add(subnet)
    server = DHCPServer(
        name=f"v6d-kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=547,
        status="active",
    )
    db_session.add(server)
    await db_session.commit()

    assert (await _post(client, server, _v6(hostname="laptop6"))).status_code == 200

    row = await _mirror(db_session, subnet, "2001:db8:83::100")
    assert row is not None
    records = {
        r.record_type: r
        for r in (
            await db_session.execute(
                select(DNSRecord)
                .where(DNSRecord.ip_address_id == row.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    }
    assert records["AAAA"].zone_id == fwd.id
    assert records["AAAA"].name == "laptop6"
    # The reverse path creates the subnet's own /64 ip6.arpa zone (#41) and
    # puts the PTR under it — nibble-reversed, the rest of the address.
    ptr_zone = await db_session.get(DNSZone, records["PTR"].zone_id)
    assert ptr_zone is not None
    assert ptr_zone.name == "0.0.0.0.3.8.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
    assert records["PTR"].name == "0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0"

"""Integration mirrors keep the reserved gateway row of their subnets (#3347).

New Subnet, Resize and Edit Subnet (#3317) give a subnet's gateway a reserved
``gateway`` IPAM row, so Next available never offers it. The UniFi and the
firewall-family (Meraki / Fortinet / PAN-OS, via ``firewall_mirror``) mirrors
wrote ``subnet.gateway`` and no row. Docker, OPNsense and Proxmox already
mirror their gateway as an integration-owned reserved row, and the cloud
mirror's subnets are Kubernetes-semantics (no gateway row by design).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.unifi import UnifiController
from app.services.fortinet.client import _FortiInterface, _FortiLease
from app.services.fortinet.reconcile import reconcile_firewall as fortinet_reconcile
from app.services.integration_ownership import release_integration_rows
from app.services.meraki.client import _MerakiNetwork, _MerakiVlan
from app.services.meraki.reconcile import reconcile_org
from app.services.panos.client import _PANInterface, _PANLease
from app.services.panos.reconcile import reconcile_firewall as panos_reconcile
from app.services.unifi import reconcile as unifi_reconcile
from app.services.unifi.client import _UnifiNetwork
from tests import test_fortinet_reconcile as forti_t
from tests import test_panos_reconcile as panos_t
from tests.test_meraki_reconcile import _FakeClient, _make_org, _make_space, _patch_reconcile
from tests.test_unifi_router_name_collision_2140 import _FakeUnifiClient

CIDR = "10.214.20.0/24"

# sync(gateway) runs one reconcile pass reporting that gateway (None: the
# network is gone upstream); returns warnings.
Sync = Callable[[str | None], Awaitable[list[str]]]
# (sync, space id, ownership FK, target id)
Mirror = tuple[Sync, uuid.UUID, str, uuid.UUID]


async def _unifi_sync(db: AsyncSession, mp: pytest.MonkeyPatch) -> Mirror:
    space = IPSpace(name=f"unifi-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    c = UnifiController(
        name=f"c-{uuid.uuid4().hex[:6]}", host="10.0.0.1", mode="local", ipam_space_id=space.id
    )
    db.add(c)
    await db.commit()
    state: dict[str, str | None] = {"gw": None}

    class _Client(_FakeUnifiClient):
        async def list_networks(self, site: str) -> list[_UnifiNetwork]:
            if state["gw"] is None:
                return []
            return [
                _UnifiNetwork(
                    network_id="net-users",
                    name="Users",
                    purpose="corporate",
                    enabled=True,
                    ip_subnet=f"{state['gw']}/24",
                    vlan=20,
                    domain_name=None,
                    dhcpd_enabled=False,
                    dhcpd_start=None,
                    dhcpd_stop=None,
                    dhcpd_leasetime=None,
                )
            ]

    mp.setattr(unifi_reconcile, "UnifiClient", _Client)

    async def sync(gw: str | None) -> list[str]:
        state["gw"] = gw
        summary = await unifi_reconcile.reconcile_controller(db, c)
        assert summary.ok, summary.error
        return summary.warnings

    return sync, space.id, "unifi_controller_id", c.id


async def _meraki_sync(db: AsyncSession, mp: pytest.MonkeyPatch) -> Mirror:
    space = await _make_space(db)
    org = await _make_org(db, space)
    await db.commit()

    async def sync(gw: str | None) -> list[str]:
        vlans = [_MerakiVlan("N1", "Main", "20", "users", CIDR, gw)] if gw else []
        fake = _FakeClient(
            networks=[_MerakiNetwork(id="N1", name="Main", product_types=["appliance"])],
            vlans={"N1": vlans},
        )
        with _patch_reconcile(fake):
            summary = await reconcile_org(db, org)
        assert summary.ok, summary.error
        return summary.warnings

    return sync, space.id, "meraki_org_id", org.id


# DHCP leases the firewall mirrors report alongside the interface (#3347:
# one sitting on the gateway address must not fail the sync).
_LEASES: dict[str, list[str]] = {}


async def _fortinet_sync(db: AsyncSession, mp: pytest.MonkeyPatch) -> Mirror:
    space = await forti_t._make_space(db)
    fw = await forti_t._make_fw(db, space, mirror_interfaces=True, mirror_dhcp_leases=True)
    await db.commit()

    async def sync(gw: str | None) -> list[str]:
        fake = forti_t._FakeClient(
            interfaces=[_FortiInterface("port1", CIDR, gw, "lan")] if gw else [],
            leases=[_FortiLease(a, None, "", "active") for a in _LEASES.get("fortinet", [])],
        )
        with forti_t._patch(fake):
            summary = await fortinet_reconcile(db, fw)
        assert summary.ok, summary.error
        return summary.warnings

    return sync, space.id, "fortinet_firewall_id", fw.id


async def _panos_sync(db: AsyncSession, mp: pytest.MonkeyPatch) -> Mirror:
    space = await panos_t._make_space(db)
    fw = await panos_t._make_fw(db, space, mirror_interfaces=True, mirror_dhcp_leases=True)
    await db.commit()

    async def sync(gw: str | None) -> list[str]:
        fake = panos_t._FakeClient(
            interfaces=[_PANInterface("ethernet1/1", CIDR, gw, "trust")] if gw else [],
            leases=[_PANLease(a, None, "", "active") for a in _LEASES.get("panos", [])],
        )
        with panos_t._patch_client(fake):
            summary = await panos_reconcile(db, fw)
        assert summary.ok, summary.error
        return summary.warnings

    return sync, space.id, "panos_firewall_id", fw.id


async def _rows(db: AsyncSession, space_id: uuid.UUID) -> tuple[Subnet, dict[str, IPAddress]]:
    subnet = (
        await db.execute(select(Subnet).where(Subnet.space_id == space_id, Subnet.network == CIDR))
    ).scalar_one()
    await db.refresh(subnet)
    rows = (
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    return subnet, {str(r.address): r for r in rows}


MIRRORS = [
    ("unifi", _unifi_sync),
    ("meraki", _meraki_sync),
    ("fortinet", _fortinet_sync),
    ("panos", _panos_sync),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_gateway_row_created_and_idempotent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    sync, space_id, _fk, _tid = await factory(db_session, monkeypatch)
    assert await sync("10.214.20.1") == []
    subnet, rows = await _rows(db_session, space_id)
    gw = rows["10.214.20.1"]
    assert (gw.status, gw.hostname) == ("reserved", "gateway")
    assert subnet.allocated_ips == 1
    # A second pass adds nothing and keeps the same row.
    assert await sync("10.214.20.1") == []
    _, again = await _rows(db_session, space_id)
    assert again["10.214.20.1"].id == gw.id and len(again) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_gateway_row_moves_with_the_gateway(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    sync, space_id, _fk, _tid = await factory(db_session, monkeypatch)
    await sync("10.214.20.1")
    assert await sync("10.214.20.254") == []
    subnet, rows = await _rows(db_session, space_id)
    assert str(subnet.gateway) == "10.214.20.254"
    assert set(rows) == {"10.214.20.254"}
    assert rows["10.214.20.254"].status == "reserved"
    assert subnet.allocated_ips == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_gateway_row_never_overwrites_another_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    sync, space_id, _fk, _tid = await factory(db_session, monkeypatch)
    await sync("10.214.20.1")
    subnet, _ = await _rows(db_session, space_id)
    host = IPAddress(
        subnet_id=subnet.id, address="10.214.20.254", status="allocated", hostname="nas"
    )
    db_session.add(host)
    await db_session.commit()

    warnings = await sync("10.214.20.254")
    assert any("10.214.20.254" in w and "nas" in w for w in warnings), warnings
    _, rows = await _rows(db_session, space_id)
    assert rows["10.214.20.254"].hostname == "nas"
    assert rows["10.214.20.254"].status == "allocated"
    assert "10.214.20.1" not in rows  # the old placeholder no longer claims to be the gateway


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_edited_gateway_row_is_left_alone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    """An operator's edit makes the placeholder theirs: the sync neither
    warns about it on every pass nor moves or deletes it."""
    sync, space_id, _fk, _tid = await factory(db_session, monkeypatch)
    await sync("10.214.20.1")
    _, rows = await _rows(db_session, space_id)
    rows["10.214.20.1"].hostname = "core-router"
    rows["10.214.20.1"].status = "allocated"
    rows["10.214.20.1"].user_modified_at = datetime.now(UTC)
    await db_session.commit()

    assert await sync("10.214.20.1") == []
    assert await sync("10.214.20.254") == []
    _, rows = await _rows(db_session, space_id)
    assert rows["10.214.20.1"].hostname == "core-router"
    assert rows["10.214.20.254"].hostname == "gateway"


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_subnet_still_removed_when_its_network_goes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    """The untouched placeholder is not operator content: when the network
    leaves upstream the mirror deletes its subnet (and the row with it)
    instead of keeping it, un-owned, forever (#1558's survivor check)."""
    sync, space_id, fk, _tid = await factory(db_session, monkeypatch)
    await sync("10.214.20.1")
    await sync(None)
    left = (
        await db_session.execute(
            select(Subnet).where(Subnet.space_id == space_id, Subnet.network == CIDR)
        )
    ).scalar_one_or_none()
    assert left is None


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_target_delete_removes_the_subnet(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    sync, space_id, fk, target_id = await factory(db_session, monkeypatch)
    await sync("10.214.20.1")
    summary = await release_integration_rows(db_session, own_fk=fk, target_id=target_id)
    assert summary.subnets_released == 0


FIREWALLS = [("fortinet", _fortinet_sync), ("panos", _panos_sync)]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), FIREWALLS, ids=[m[0] for m in FIREWALLS])
async def test_lease_on_the_gateway_address_does_not_fail_the_sync(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    sync, space_id, _fk, _tid = await factory(db_session, monkeypatch)
    monkeypatch.setitem(_LEASES, name, ["10.214.20.1", "10.214.20.50"])
    warnings = await sync("10.214.20.1")
    assert any("10.214.20.1" in w for w in warnings), warnings
    _, rows = await _rows(db_session, space_id)
    assert rows["10.214.20.1"].hostname == "gateway"
    assert rows["10.214.20.50"].status == "dhcp"


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_gateway_row_recounts_the_parent_block_in_the_same_sync(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    """The block chain follows the subnet recount in the same transaction,
    not at the hourly recount: a block counts the subnet's usable rows plus
    its network and broadcast addresses (#2982)."""
    sync, space_id, _fk, _tid = await factory(db_session, monkeypatch)
    assert await sync("10.214.20.1") == []
    subnet, _ = await _rows(db_session, space_id)
    assert subnet.allocated_ips == 1
    block = await db_session.get(IPBlock, subnet.block_id)
    assert block is not None
    await db_session.refresh(block)
    assert block.allocated_ips == 3

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

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPSpace, Subnet
from app.models.unifi import UnifiController
from app.services.meraki.client import _MerakiNetwork, _MerakiVlan
from app.services.meraki.reconcile import reconcile_org
from app.services.unifi import reconcile as unifi_reconcile
from app.services.unifi.client import _UnifiNetwork
from tests.test_meraki_reconcile import _FakeClient, _make_org, _make_space, _patch_reconcile
from tests.test_unifi_router_name_collision_2140 import _FakeUnifiClient

CIDR = "10.214.20.0/24"

# sync(gateway) runs one reconcile pass reporting that gateway; returns warnings.
Sync = Callable[[str], Awaitable[list[str]]]


async def _unifi_sync(db: AsyncSession, mp: pytest.MonkeyPatch) -> tuple[Sync, uuid.UUID]:
    space = IPSpace(name=f"unifi-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    c = UnifiController(
        name=f"c-{uuid.uuid4().hex[:6]}", host="10.0.0.1", mode="local", ipam_space_id=space.id
    )
    db.add(c)
    await db.commit()
    state = {"gw": ""}

    class _Client(_FakeUnifiClient):
        async def list_networks(self, site: str) -> list[_UnifiNetwork]:
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

    async def sync(gw: str) -> list[str]:
        state["gw"] = gw
        summary = await unifi_reconcile.reconcile_controller(db, c)
        assert summary.ok, summary.error
        return summary.warnings

    return sync, space.id


async def _meraki_sync(db: AsyncSession, mp: pytest.MonkeyPatch) -> tuple[Sync, uuid.UUID]:
    space = await _make_space(db)
    org = await _make_org(db, space)
    await db.commit()

    async def sync(gw: str) -> list[str]:
        fake = _FakeClient(
            networks=[_MerakiNetwork(id="N1", name="Main", product_types=["appliance"])],
            vlans={"N1": [_MerakiVlan("N1", "Main", "20", "users", CIDR, gw)]},
        )
        with _patch_reconcile(fake):
            summary = await reconcile_org(db, org)
        assert summary.ok, summary.error
        return summary.warnings

    return sync, space.id


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


MIRRORS = [("unifi", _unifi_sync), ("meraki", _meraki_sync)]


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "factory"), MIRRORS, ids=[m[0] for m in MIRRORS])
async def test_gateway_row_created_and_idempotent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, name: str, factory
) -> None:
    sync, space_id = await factory(db_session, monkeypatch)
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
    sync, space_id = await factory(db_session, monkeypatch)
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
    sync, space_id = await factory(db_session, monkeypatch)
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

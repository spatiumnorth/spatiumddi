"""#5007 - the DHCP lease pull and the Proxmox / UniFi mirrors write
``ip_mac_history`` like a direct edit does; an unchanged MAC adds no row."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IpMacHistory, IPSpace, Subnet
from app.models.proxmox import ProxmoxNode
from app.models.unifi import UnifiController
from app.services.proxmox.client import (
    _ProxmoxGuest,
    _ProxmoxNetworkIface,
    _ProxmoxNicDef,
)
from tests.test_proxmox_reconcile import _FakeClient, _patch_client

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"


async def _space_subnet(db: AsyncSession, cidr: str = "10.50.0.0/24") -> tuple[IPSpace, Subnet]:
    space = IPSpace(name=f"mh5007-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.50.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=cidr, name="s")
    db.add(subnet)
    await db.flush()
    return space, subnet


async def _history(db: AsyncSession, subnet_id: uuid.UUID, address: str) -> list[IpMacHistory]:
    ip = (
        await db.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet_id, IPAddress.address == address)
        )
    ).scalar_one()
    return list(
        (await db.execute(select(IpMacHistory).where(IpMacHistory.ip_address_id == ip.id)))
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_lease_pull_records_mac_history(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.dhcp import pull_leases as pl

    _, subnet = await _space_subnet(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(grp)
    await db_session.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="windows_dhcp",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db_session.add(srv)
    await db_session.commit()

    leases: list[dict] = []

    class _Drv:
        async def get_leases(self, _s):
            return leases

    monkeypatch.setattr(pl, "get_driver", lambda _d: _Drv())

    async def pull() -> None:
        r = await pl.pull_leases_from_server(db_session, srv, apply=True)
        await db_session.commit()
        assert r.errors == []

    leases[:] = [{"ip_address": "10.50.0.20", "mac_address": MAC_A, "hostname": "h"}]
    await pull()
    rows = await _history(db_session, subnet.id, "10.50.0.20")
    assert [str(r.mac_address) for r in rows] == [MAC_A]

    # Same MAC again: no new row, last_seen untouched.
    seen = rows[0].last_seen
    await pull()
    rows = await _history(db_session, subnet.id, "10.50.0.20")
    assert len(rows) == 1 and rows[0].last_seen == seen

    # A different MAC: second row, first one kept.
    leases[:] = [{"ip_address": "10.50.0.20", "mac_address": MAC_B, "hostname": "h"}]
    await pull()
    rows = await _history(db_session, subnet.id, "10.50.0.20")
    assert sorted(str(r.mac_address) for r in rows) == [MAC_A, MAC_B]


@pytest.mark.asyncio
async def test_proxmox_reconcile_records_mac_history(db_session: AsyncSession) -> None:
    from app.services.proxmox.reconcile import reconcile_node

    space, subnet = await _space_subnet(db_session)
    node = ProxmoxNode(
        name=f"pve-{uuid.uuid4().hex[:6]}",
        host="pve.example.test",
        port=8006,
        verify_tls=False,
        token_id="root@pam!x",
        token_secret_encrypted=b"",
        ipam_space_id=space.id,
    )
    db_session.add(node)
    await db_session.commit()

    def fake(mac: str) -> _FakeClient:
        vm = _ProxmoxGuest(
            node="pve01",
            vmid=100,
            name="db01",
            kind="qemu",
            status="running",
            agent_enabled=True,
            nics=[
                _ProxmoxNicDef(
                    slot="net0", mac=mac, bridge="vmbr0", vlan_tag=None, static_cidr=None
                )
            ],
            runtime_ips_by_mac={mac.lower(): ["10.50.0.50"]},
        )
        return _FakeClient(
            networks={
                "pve01": [
                    _ProxmoxNetworkIface(
                        node="pve01",
                        iface="vmbr0",
                        iface_type="bridge",
                        cidr="10.50.0.1/24",
                        active=True,
                    )
                ]
            },
            qemu={"pve01": [vm]},
        )

    async def run(mac: str) -> None:
        with _patch_client(fake(mac)):
            s = await reconcile_node(db_session, node)
        assert s.ok, s.error
        await db_session.commit()

    await run(MAC_A.upper())
    sid = (
        (
            await db_session.execute(
                select(IPAddress.subnet_id).where(IPAddress.proxmox_node_id == node.id)
            )
        )
        .scalars()
        .first()
    )
    rows = await _history(db_session, sid, "10.50.0.50")
    assert [str(r.mac_address) for r in rows] == [MAC_A]
    seen = rows[0].last_seen

    await run(MAC_A.upper())
    rows = await _history(db_session, sid, "10.50.0.50")
    assert len(rows) == 1 and rows[0].last_seen == seen

    await run(MAC_B.upper())
    rows = await _history(db_session, sid, "10.50.0.50")
    assert sorted(str(r.mac_address) for r in rows) == [MAC_A, MAC_B]


@pytest.mark.asyncio
async def test_unifi_apply_addresses_records_mac_history(db_session: AsyncSession) -> None:
    from app.services.unifi import reconcile as ur

    space, subnet = await _space_subnet(db_session)
    c = UnifiController(
        name=f"c-{uuid.uuid4().hex[:6]}",
        host="u.example.test",
        mode="local",
        ipam_space_id=space.id,
    )
    db_session.add(c)
    await db_session.commit()

    async def run(mac: str) -> None:
        d = ur._DesiredAddress(
            address="10.50.0.60",
            status="unifi-client",
            hostname="cl",
            description="",
            mac=mac,
            network_id=None,
        )
        await ur._apply_addresses(db_session, c, [d], ur.ReconcileSummary(ok=True))
        await db_session.commit()

    await run(MAC_A.upper())
    rows = await _history(db_session, subnet.id, "10.50.0.60")
    assert [str(r.mac_address) for r in rows] == [MAC_A]
    seen = rows[0].last_seen

    await run(MAC_A.upper())
    rows = await _history(db_session, subnet.id, "10.50.0.60")
    assert len(rows) == 1 and rows[0].last_seen == seen

    await run(MAC_B.upper())
    rows = await _history(db_session, subnet.id, "10.50.0.60")
    assert sorted(str(r.mac_address) for r in rows) == [MAC_A, MAC_B]

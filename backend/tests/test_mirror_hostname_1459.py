"""Integration-mirrored names are folded into legal host names (#1459).

Every read-only integration copied an upstream display name ("Vitrinen
Schalter", "John's iPhone", "compose_project.web") into
``IPAddress.hostname``, and IPAM's DNS sync published it as a record owner.
The DNS servers refuse such a record on every attempt. The name is now folded
where each integration builds its desired address, and the original is kept
in the description.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _sync_dns_record
from app.core.dns_names import sanitize_mirrored_hostname
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.proxmox import ProxmoxNode
from app.services.cloud import reconcile as cloud_reconcile
from app.services.docker import reconcile as docker_reconcile
from app.services.firewall_mirror import MirrorAddress
from app.services.kubernetes import reconcile as kubernetes_reconcile
from app.services.netbird import reconcile as netbird_reconcile
from app.services.opnsense import reconcile as opnsense_reconcile
from app.services.proxmox import reconcile as proxmox_reconcile
from app.services.proxmox.client import (
    _ProxmoxClusterInfo,
    _ProxmoxGuest,
    _ProxmoxNetworkIface,
    _ProxmoxNicDef,
    _ProxmoxNodeInfo,
    _ProxmoxVersion,
)
from app.services.tailscale import reconcile as tailscale_reconcile
from app.services.unifi import reconcile as unifi_reconcile

# ── The folding rule ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Vitrinen Schalter", "vitrinen-schalter"),
        ("Sonos Büro", "sonos-buero"),
        ("Schrank_Arbeitszimmer_WLED", "schrank-arbeitszimmer-wled"),
        ("John's iPhone", "johns-iphone"),
        ("Café Écran", "cafe-ecran"),
        ("compose_project.web_1", "compose-project.web-1"),
        ("  -- ", ""),
    ],
)
def test_a_free_text_name_is_folded(raw: str, expected: str) -> None:
    assert sanitize_mirrored_hostname(raw) == expected


@pytest.mark.parametrize(
    "name", ["db01", "DESKTOP-1TUKR8N", "web.default", "host-1.tail1234.ts.net"]
)
def test_a_legal_name_is_kept_as_written(name: str) -> None:
    # Case included: lower-casing a legal name would rename its records.
    assert sanitize_mirrored_hostname(name) == name


def test_a_long_name_is_capped_at_a_legal_length() -> None:
    folded = sanitize_mirrored_hostname("Very Long Name " * 30)
    assert folded
    assert all(len(label) <= 63 for label in folded.split("."))
    assert len(folded) <= 253


# ── Every integration's desired address ──────────────────────────────


def _desired_addresses() -> list[tuple[str, Any, dict[str, Any]]]:
    return [
        (
            "unifi",
            unifi_reconcile._DesiredAddress,
            {"status": "unifi-client", "mac": None, "network_id": None},
        ),
        ("docker", docker_reconcile._DesiredAddress, {"status": "docker-container"}),
        ("proxmox", proxmox_reconcile._DesiredAddress, {"status": "proxmox-vm"}),
        ("opnsense", opnsense_reconcile._DesiredAddress, {"status": "dhcp"}),
        ("kubernetes", kubernetes_reconcile._DesiredAddress, {"status": "kubernetes-node"}),
        ("cloud", cloud_reconcile._DesiredAddress, {"status": "cloud-instance"}),
        ("tailscale", tailscale_reconcile._DesiredAddress, {"custom_fields": {}}),
        ("netbird", netbird_reconcile._DesiredAddress, {"custom_fields": {}}),
        ("firewall-mirror", MirrorAddress, {"mac": None}),
    ]


@pytest.mark.parametrize(
    ("cls", "extra"),
    [(cls, extra) for _, cls, extra in _desired_addresses()],
    ids=[name for name, _, _ in _desired_addresses()],
)
def test_every_mirror_folds_the_name_and_keeps_the_original(
    cls: Any, extra: dict[str, Any]
) -> None:
    d = cls(
        address="10.0.0.5", hostname="Vitrinen Schalter", description="client on site A", **extra
    )
    assert d.hostname == "vitrinen-schalter"
    assert d.description == "client on site A — name: Vitrinen Schalter"


@pytest.mark.parametrize(
    ("cls", "extra"),
    [(cls, extra) for _, cls, extra in _desired_addresses()],
    ids=[name for name, _, _ in _desired_addresses()],
)
def test_every_mirror_leaves_a_legal_name_alone(cls: Any, extra: dict[str, Any]) -> None:
    d = cls(address="10.0.0.5", hostname="DESKTOP-1TUKR8N", description="client", **extra)
    assert d.hostname == "DESKTOP-1TUKR8N"
    assert d.description == "client"


# ── End to end through one reconciler ────────────────────────────────


class _FakeProxmox:
    def __init__(self, guest_name: str) -> None:
        self.guest = _ProxmoxGuest(
            node="pve01",
            vmid=100,
            name=guest_name,
            kind="qemu",
            status="running",
            agent_enabled=True,
            nics=[
                _ProxmoxNicDef(
                    slot="net0",
                    mac="BC:24:11:00:00:01",
                    bridge="vmbr0",
                    vlan_tag=None,
                    static_cidr=None,
                )
            ],
            runtime_ips_by_mac={"bc:24:11:00:00:01": ["10.0.0.50"]},
        )
        self.unreadable_guests: list[str] = []

    async def __aenter__(self) -> _FakeProxmox:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_version(self) -> _ProxmoxVersion:
        return _ProxmoxVersion(version="9.1.9", release="9.1", repoid="xyz")

    async def get_cluster_info(self) -> _ProxmoxClusterInfo:
        return _ProxmoxClusterInfo(cluster_name=None, node_count=1, quorate=None)

    async def list_nodes(self) -> list[_ProxmoxNodeInfo]:
        return [_ProxmoxNodeInfo(node="pve01", status="online")]

    async def list_networks(self, node: str) -> list[_ProxmoxNetworkIface]:
        return [
            _ProxmoxNetworkIface(
                node=node, iface="vmbr0", iface_type="bridge", cidr="10.0.0.1/24", active=True
            )
        ]

    async def list_sdn_subnets(self) -> list[Any]:
        return []

    async def list_sdn_vnets(self) -> list[Any]:
        return []

    async def list_qemu(self, node: str, *, include_stopped: bool) -> list[_ProxmoxGuest]:
        del node, include_stopped
        return [self.guest]

    async def list_lxc(self, node: str, *, include_stopped: bool) -> list[_ProxmoxGuest]:
        del node, include_stopped
        return []


@pytest.mark.asyncio
async def test_a_proxmox_guest_lands_with_a_legal_hostname_and_stays_put(
    db_session: AsyncSession,
) -> None:
    space = IPSpace(name=f"px-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    node = ProxmoxNode(
        name=f"pve-{uuid.uuid4().hex[:6]}",
        host="pve.example.test",
        port=8006,
        verify_tls=False,
        token_id="root@pam!spatiumddi",
        token_secret_encrypted=b"",
        ipam_space_id=space.id,
        mirror_vms=True,
        mirror_lxc=True,
    )
    db_session.add(node)
    await db_session.commit()

    fake = _FakeProxmox("Web Server_01")
    with patch("app.services.proxmox.reconcile.ProxmoxClient", side_effect=lambda **_: fake):
        first = await proxmox_reconcile.reconcile_node(db_session, node)
        second = await proxmox_reconcile.reconcile_node(db_session, node)

    assert first.ok, first.error
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.proxmox_node_id == node.id, IPAddress.status == "proxmox-vm"
            )
        )
    ).scalar_one()
    assert ip.hostname == "web-server-01"
    assert ip.description.endswith("name: Web Server_01")
    # The fold is stable, so the next pass has nothing to change.
    assert second.ok, second.error
    assert second.addresses_updated == 0


# ── The rename away from a legacy illegal name ───────────────────────


async def _zone_and_subnet(db: AsyncSession, driver: str = "bind9") -> tuple[Subnet, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            name=f"ns-{uuid.uuid4().hex[:6]}",
            host="192.0.2.53",
            port=53,
            driver=driver,
            group_id=grp.id,
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name="corp.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.corp.test.",
        admin_email="admin.corp.test.",
    )
    db.add(zone)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.82.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.82.1.0/24",
        name="s",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    db.add(subnet)
    await db.flush()
    return subnet, zone


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", "powerdns", "technitium", "technitium_api"])
async def test_renaming_off_an_illegal_name_sends_no_delete_for_it(
    db_session: AsyncSession, driver: str
) -> None:
    """The old record was refused by the primary, so a delete of it can only
    fail, on every retry. The rename writes the new name and drops the old row."""
    subnet, zone = await _zone_and_subnet(db_session, driver)
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.20", status="allocated", hostname="Vitrinen Schalter"
    )
    db_session.add(ip)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet, backfill_reverse_zone=False)
    await db_session.flush()

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _capture(
        db: AsyncSession, zone: DNSZone, op: str, record: dict[str, Any], **_: Any
    ) -> None:
        sent.append((op, record))

    ip.hostname = "vitrinen-schalter"
    with patch("app.services.dns.record_ops.enqueue_record_op", side_effect=_capture):
        await _sync_dns_record(db_session, ip, subnet, action="update", backfill_reverse_zone=False)
    await db_session.flush()

    assert [(op, r["name"]) for op, r in sent] == [("create", "vitrinen-schalter")]
    names = (
        (
            await db_session.execute(
                select(DNSRecord.name).where(
                    DNSRecord.zone_id == zone.id, DNSRecord.record_type == "A"
                )
            )
        )
        .scalars()
        .all()
    )
    assert names == ["vitrinen-schalter"]


@pytest.mark.asyncio
async def test_renaming_off_an_illegal_name_still_retracts_it_on_windows(
    db_session: AsyncSession,
) -> None:
    """Windows DNS can be set to accept UTF-8 names, so the old record may
    really be there; skipping the retraction would orphan it."""
    subnet, _zone = await _zone_and_subnet(db_session, "windows_dns")
    ip = IPAddress(
        subnet_id=subnet.id, address="10.82.1.22", status="allocated", hostname="Büro Drucker"
    )
    db_session.add(ip)
    await db_session.flush()

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _capture(
        db: AsyncSession, zone: DNSZone, op: str, record: dict[str, Any], **_: Any
    ) -> None:
        sent.append((op, record))

    with patch("app.services.dns.record_ops.enqueue_record_op", side_effect=_capture):
        await _sync_dns_record(db_session, ip, subnet, backfill_reverse_zone=False)
        await db_session.flush()
        sent.clear()
        ip.hostname = "buero-drucker"
        await _sync_dns_record(db_session, ip, subnet, action="update", backfill_reverse_zone=False)

    assert [(op, r["name"]) for op, r in sent] == [
        ("delete", "Büro Drucker"),
        ("create", "buero-drucker"),
    ]


@pytest.mark.asyncio
async def test_renaming_off_a_legal_name_still_retracts_it(db_session: AsyncSession) -> None:
    subnet, _zone = await _zone_and_subnet(db_session)
    ip = IPAddress(subnet_id=subnet.id, address="10.82.1.21", status="allocated", hostname="web01")
    db_session.add(ip)
    await db_session.flush()
    await _sync_dns_record(db_session, ip, subnet, backfill_reverse_zone=False)
    await db_session.flush()

    sent: list[tuple[str, dict[str, Any]]] = []

    async def _capture(
        db: AsyncSession, zone: DNSZone, op: str, record: dict[str, Any], **_: Any
    ) -> None:
        sent.append((op, record))

    ip.hostname = "web02"
    with patch("app.services.dns.record_ops.enqueue_record_op", side_effect=_capture):
        await _sync_dns_record(db_session, ip, subnet, action="update", backfill_reverse_zone=False)

    assert [(op, r["name"]) for op, r in sent] == [("delete", "web01"), ("create", "web02")]

"""The Kubernetes, UniFi, Tailscale and NetBird mirrors reuse a kept subnet (#2790).

A mirrored subnet is kept with no owner when its target is deleted while it
holds operator content (#2287), and, for Kubernetes and UniFi, when its
network leaves the desired set while an address in it survives (#1558).
#2784 made the Docker reconciler reuse such a subnet (#2601). These four
reconcilers created a second subnet with the same CIDR beside it on the next
sync, placed their addresses by the order the database returned the two
rows, and could move an address an operator edited from one to the other.

Each test drives the reconciler's own entry point with its client stubbed:
one subnet per CIDR after a target is deleted and re-added, and after a
network goes and comes back; the target's addresses in its own subnet beside
a twin an earlier build left, whichever row was inserted first; an edited
address left in its subnet.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.kubernetes import KubernetesCluster
from app.models.netbird import NetbirdInstance
from app.models.tailscale import TailscaleTenant
from app.models.unifi import UnifiController
from app.services.integration_ownership import release_integration_rows
from app.services.kubernetes.client import _K8sPod, _K8sService
from app.services.kubernetes.reconcile import reconcile_cluster
from app.services.netbird.client import _NetbirdPeer
from app.services.netbird.reconcile import reconcile_instance
from app.services.tailscale.client import _TailscaleDevice
from app.services.tailscale.reconcile import reconcile_tenant
from app.services.unifi.client import _UnifiClient, _UnifiNetwork, _UnifiSite, _UnifiVersion
from app.services.unifi.reconcile import reconcile_controller


def _n(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


class _Ctx:
    async def __aenter__(self) -> Any:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


# ── One reconciler under test ─────────────────────────────────────────


class _Mirror:
    """A reconciler: its ownership FK, the CIDRs a target mirrors, the
    addresses its upstream reports (address -> CIDR), a fresh target row,
    and one sync with the upstream up or (where the integration has a
    network that can leave) down."""

    fk: str
    cidrs: tuple[str, ...]
    addresses: dict[str, str]

    def edited(self) -> list[str]:
        """One address per CIDR, the one an operator edits."""
        return [next(a for a, c in self.addresses.items() if c == cidr) for cidr in self.cidrs]

    def target(self, space_id: uuid.UUID, name: str) -> Any:
        raise NotImplementedError

    async def sync(self, db: AsyncSession, target: Any, *, up: bool = True) -> Any:
        raise NotImplementedError


class _K8sClient(_Ctx):
    def __init__(self, pods: list[_K8sPod], services: list[_K8sService]) -> None:
        self.pods, self.services = pods, services

    async def list_nodes(self) -> list:
        return []

    async def list_services(self) -> list[_K8sService]:
        return self.services

    async def list_loadbalancer_services(self) -> list:
        return []

    async def list_pods(self) -> list[_K8sPod]:
        return self.pods

    async def list_ingresses(self) -> list:
        return []


class _Kubernetes(_Mirror):
    fk = "kubernetes_cluster_id"
    # The pod CIDR is outside the private ranges, so it gets a wrapper block
    # the cluster owns; the service CIDR nests under the auto-created 10/8.
    cidrs = ("198.19.10.0/24", "10.96.0.0/16")
    addresses = {
        "198.19.10.11": "198.19.10.0/24",
        "198.19.10.12": "198.19.10.0/24",
        "10.96.0.10": "10.96.0.0/16",
        "10.96.0.20": "10.96.0.0/16",
    }

    def target(self, space_id: uuid.UUID, name: str) -> KubernetesCluster:
        return KubernetesCluster(
            name=name,
            api_server_url="https://k8s.example.test:6443",
            ca_bundle_pem="",
            token_encrypted=encrypt_str("faketoken"),
            ipam_space_id=space_id,
            pod_cidr=self.cidrs[0],
            service_cidr=self.cidrs[1],
            mirror_pods=True,
        )

    async def sync(self, db: AsyncSession, target: Any, *, up: bool = True) -> Any:
        # The pod and service CIDRs are the cluster's configuration: a
        # network leaving is the CIDR cleared, with nothing left in it.
        target.pod_cidr, target.service_cidr = self.cidrs if up else ("", "")
        pods = [
            _K8sPod(namespace="default", name=f"pod-{ip}", pod_ip=ip, phase="Running")
            for ip, cidr in self.addresses.items()
            if up and cidr == self.cidrs[0]
        ]
        services = [
            _K8sService(
                namespace="default", name=f"svc-{ip}", cluster_ip=ip, service_type="ClusterIP"
            )
            for ip, cidr in self.addresses.items()
            if up and cidr == self.cidrs[1]
        ]
        fake = _K8sClient(pods, services)
        with patch(
            "app.services.kubernetes.reconcile.KubernetesClient", side_effect=lambda **_: fake
        ):
            return await reconcile_cluster(db, target)


class _UnifiFake(_Ctx):
    def __init__(self, networks: list[_UnifiNetwork], clients: list[_UnifiClient]) -> None:
        self.networks, self.clients = networks, clients

    async def get_version(self) -> _UnifiVersion:
        return _UnifiVersion(version="9.0.1")

    async def list_sites(self) -> list[_UnifiSite]:
        return [_UnifiSite(name="default", desc="Default")]

    async def list_networks(self, site: str) -> list[_UnifiNetwork]:  # noqa: ARG002
        return self.networks

    async def list_active_clients(self, site: str) -> list[_UnifiClient]:  # noqa: ARG002
        return self.clients

    async def list_known_clients(self, site: str) -> list:  # noqa: ARG002
        return []


class _Unifi(_Mirror):
    fk = "unifi_controller_id"
    cidrs = ("198.19.20.0/24", "10.97.0.0/16")
    addresses = {
        "198.19.20.11": "198.19.20.0/24",
        "198.19.20.12": "198.19.20.0/24",
        "10.97.0.10": "10.97.0.0/16",
        "10.97.0.20": "10.97.0.0/16",
    }

    def target(self, space_id: uuid.UUID, name: str) -> UnifiController:
        # An address, not a name: the sync copies a local controller's host
        # into its Router's management_ip, an INET column.
        return UnifiController(name=name, host="192.0.2.10", ipam_space_id=space_id)

    async def sync(self, db: AsyncSession, target: Any, *, up: bool = True) -> Any:
        networks = [
            _UnifiNetwork(
                network_id=f"net-{i}",
                name=f"lan{i}",
                purpose="corporate",
                enabled=True,
                # UniFi's ip_subnet is <gateway>/<prefix>.
                ip_subnet=cidr.replace(".0/", ".1/"),
                vlan=None,
                domain_name=None,
                dhcpd_enabled=False,
                dhcpd_start=None,
                dhcpd_stop=None,
                dhcpd_leasetime=None,
            )
            for i, cidr in enumerate(self.cidrs)
            if up
        ]
        clients = [
            _UnifiClient(
                mac=f"02:00:00:00:00:{n:02x}",
                ip=ip,
                hostname=f"client-{n}",
                name=None,
                network_id=f"net-{self.cidrs.index(cidr)}",
                oui=None,
                fixed_ip=False,
                is_wired=True,
                is_vpn=False,
                is_guest=False,
                last_seen=None,
            )
            for n, (ip, cidr) in enumerate(self.addresses.items())
            if up
        ]
        fake = _UnifiFake(networks, clients)
        with patch("app.services.unifi.reconcile.UnifiClient", side_effect=lambda *_a, **_k: fake):
            return await reconcile_controller(db, target)


class _TailscaleFake(_Ctx):
    def __init__(self, devices: list[_TailscaleDevice]) -> None:
        self.devices = devices

    async def list_devices(self) -> list[_TailscaleDevice]:
        return self.devices


class _Tailscale(_Mirror):
    fk = "tailscale_tenant_id"
    # The tenant's default CGNAT and ULA CIDRs.
    cidrs = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")
    addresses = {
        "100.64.0.11": "100.64.0.0/10",
        "fd7a:115c:a1e0::11": "fd7a:115c:a1e0::/48",
        "100.64.0.12": "100.64.0.0/10",
        "fd7a:115c:a1e0::12": "fd7a:115c:a1e0::/48",
    }

    def target(self, space_id: uuid.UUID, name: str) -> TailscaleTenant:
        return TailscaleTenant(
            name=name, tailnet="-", api_key_encrypted=b"x", ipam_space_id=space_id
        )

    async def sync(self, db: AsyncSession, target: Any, *, up: bool = True) -> Any:
        assert up, "a Tailscale tenant has no network that leaves"
        devices = [
            _TailscaleDevice(
                id=str(n),
                node_id=f"n{n}",
                name=f"host{n}.example.ts.net",
                hostname=f"host{n}",
                addresses=[v4, v6],
                os="linux",
                client_version="1.62.0",
                user="alice@example.com",
                tags=[],
                last_seen=None,
                expires=None,
                key_expiry_disabled=True,
                advertised_routes=[],
                enabled_routes=[],
            )
            for n, (v4, v6) in enumerate(
                (("100.64.0.11", "fd7a:115c:a1e0::11"), ("100.64.0.12", "fd7a:115c:a1e0::12"))
            )
        ]
        fake = _TailscaleFake(devices)
        with (
            patch("app.services.tailscale.reconcile.TailscaleClient", side_effect=lambda **_: fake),
            patch("app.services.tailscale.reconcile.decrypt_str", return_value="tskey-api-fake"),
        ):
            return await reconcile_tenant(db, target)


class _NetbirdFake(_Ctx):
    def __init__(self, peers: list[_NetbirdPeer]) -> None:
        self.peers = peers

    async def list_peers(self) -> list[_NetbirdPeer]:
        return self.peers


class _Netbird(_Mirror):
    fk = "netbird_instance_id"
    # The instance's default overlay CIDR.
    cidrs = ("100.64.0.0/10",)
    addresses = {"100.64.0.21": "100.64.0.0/10", "100.64.0.22": "100.64.0.0/10"}

    def target(self, space_id: uuid.UUID, name: str) -> NetbirdInstance:
        return NetbirdInstance(name=name, api_key_encrypted=b"x", ipam_space_id=space_id)

    async def sync(self, db: AsyncSession, target: Any, *, up: bool = True) -> Any:
        assert up, "a NetBird instance has no network that leaves"
        peers = [
            _NetbirdPeer(id=f"p{n}", name=f"peer-{n}", ip=ip) for n, ip in enumerate(self.addresses)
        ]
        fake = _NetbirdFake(peers)
        with (
            patch("app.services.netbird.reconcile.NetbirdClient", side_effect=lambda **_: fake),
            patch("app.services.netbird.reconcile.decrypt_str", return_value="nbp_fake"),
        ):
            return await reconcile_instance(db, target)


_MIRRORS: dict[str, _Mirror] = {
    "kubernetes": _Kubernetes(),
    "unifi": _Unifi(),
    "tailscale": _Tailscale(),
    "netbird": _Netbird(),
}
# A network of these can leave the desired set and come back (#1558's
# un-claim); a Tailscale or NetBird CIDR is the target's configuration and
# never un-claims its subnet.
_NETWORK_LEAVES = ["kubernetes", "unifi"]


# ── Helpers ───────────────────────────────────────────────────────────


async def _space(db: AsyncSession) -> uuid.UUID:
    space = IPSpace(name=_n("kept-2790"), description="")
    db.add(space)
    await db.flush()
    return space.id


async def _subnets_at(db: AsyncSession, space_id: uuid.UUID, cidr: str) -> list[Subnet]:
    res = await db.execute(
        select(Subnet).where(Subnet.space_id == space_id, Subnet.network == cidr)
    )
    return list(res.scalars().all())


async def _block_ids_at(db: AsyncSession, space_id: uuid.UUID, cidr: str) -> set[uuid.UUID]:
    res = await db.execute(
        select(IPBlock.id).where(IPBlock.space_id == space_id, IPBlock.network == cidr)
    )
    return set(res.scalars().all())


async def _owned(db: AsyncSession, fk: str, target_id: uuid.UUID) -> dict[str, IPAddress]:
    res = await db.execute(select(IPAddress).where(getattr(IPAddress, fk) == target_id))
    return {str(a.address): a for a in res.scalars().all()}


async def _edit(db: AsyncSession, space_id: uuid.UUID, address: str) -> None:
    """An operator edit, stamped as PUT /ipam/addresses/{id} stamps it."""
    res = await db.execute(
        select(IPAddress)
        .join(Subnet, IPAddress.subnet_id == Subnet.id)
        .where(Subnet.space_id == space_id, IPAddress.address == address)
    )
    row = res.scalar_one()
    row.hostname = f"edited-{address}"
    row.user_modified_at = datetime.now(UTC)
    await db.commit()


async def _twins(
    db: AsyncSession, space_id: uuid.UUID, m: _Mirror, target_id: uuid.UUID, *, own_first: bool
) -> dict[str, tuple[uuid.UUID, uuid.UUID]]:
    """Every CIDR the target mirrors as the two rows an earlier build left:
    one the target owns and one kept with no owner, inserted in the order
    given. Returns ``{cidr: (own subnet id, un-owned subnet id)}``."""
    out: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    for cidr in m.cidrs:
        block = IPBlock(space_id=space_id, network=cidr, name=_n("blk"))
        db.add(block)
        await db.flush()
        ids: dict[uuid.UUID | None, uuid.UUID] = {}
        for owner in (target_id, None) if own_first else (None, target_id):
            row = Subnet(
                space_id=space_id,
                block_id=block.id,
                network=cidr,
                name=f"twin {cidr}",
                total_ips=254,
                **{m.fk: owner},
            )
            db.add(row)
            await db.flush()
            ids[owner] = row.id
        out[cidr] = (ids[target_id], ids[None])
    return out


# ── A target deleted and re-added ─────────────────────────────────────


@pytest.mark.parametrize("kind", list(_MIRRORS))
async def test_readd_after_delete_reuses_the_kept_subnet_2790(
    db_session: AsyncSession, kind: str
) -> None:
    """Deleting a target keeps a mirrored subnet that holds operator content,
    with no owner (#2287). Re-adding the target and syncing must not put a
    second subnet (or, for Tailscale and NetBird, a second block) at that
    CIDR beside it: the kept subnet stays the one row there, as it stands,
    and holds the target's addresses."""
    m = _MIRRORS[kind]
    space_id = await _space(db_session)
    target = m.target(space_id, _n(kind))
    db_session.add(target)
    await db_session.commit()
    target_id, name = target.id, target.name
    assert (await m.sync(db_session, target)).ok
    for ip in m.edited():
        await _edit(db_session, space_id, ip)
    kept: dict[str, uuid.UUID] = {}
    blocks: dict[str, set[uuid.UUID]] = {}
    for cidr in m.cidrs:
        [row] = await _subnets_at(db_session, space_id, cidr)
        kept[cidr] = row.id
        blocks[cidr] = await _block_ids_at(db_session, space_id, cidr)

    # Delete the target as its DELETE route does.
    await release_integration_rows(db_session, own_fk=m.fk, target_id=target_id, target_name=name)
    await db_session.delete(target)
    await db_session.commit()
    db_session.expire_all()
    for cidr, sid in kept.items():
        rows = await _subnets_at(db_session, space_id, cidr)
        assert [(r.id, getattr(r, m.fk)) for r in rows] == [(sid, None)], cidr

    readded = m.target(space_id, name)
    db_session.add(readded)
    await db_session.commit()
    readded_id = readded.id
    summary = await m.sync(db_session, readded)
    assert summary.ok, summary.error

    db_session.expire_all()
    for cidr, sid in kept.items():
        rows = await _subnets_at(db_session, space_id, cidr)
        assert [r.id for r in rows] == [sid], f"{cidr}: {len(rows)} subnet rows"
        # Reused as it stands, as the Docker (#2601) and Proxmox (#177)
        # reconcilers reuse an un-owned subnet: not claimed back.
        assert getattr(rows[0], m.fk) is None, cidr
        assert await _block_ids_at(db_session, space_id, cidr) == blocks[cidr], cidr
    assert summary.subnets_created == 0
    assert summary.subnets_matched == len(m.cidrs)

    owned = await _owned(db_session, m.fk, readded_id)
    assert set(owned) == set(m.addresses)
    for ip, row in owned.items():
        assert row.subnet_id == kept[m.addresses[ip]], ip
    for ip in m.edited():
        assert owned[ip].hostname == f"edited-{ip}", ip


# ── A network gone and back ───────────────────────────────────────────


@pytest.mark.parametrize("kind", _NETWORK_LEAVES)
async def test_network_back_reuses_the_unclaimed_subnet_2790(
    db_session: AsyncSession, kind: str
) -> None:
    """A network that leaves the desired set un-claims its subnet when an
    operator-edited row is in it (#1558). When the network comes back, the
    next sync reuses that subnet: one row at the CIDR, holding the target's
    addresses, the edited one with its edit."""
    m = _MIRRORS[kind]
    space_id = await _space(db_session)
    target = m.target(space_id, _n(kind))
    db_session.add(target)
    await db_session.commit()
    target_id = target.id
    assert (await m.sync(db_session, target)).ok
    for ip in m.edited():
        await _edit(db_session, space_id, ip)
    kept: dict[str, uuid.UUID] = {}
    for cidr in m.cidrs:
        [row] = await _subnets_at(db_session, space_id, cidr)
        kept[cidr] = row.id

    assert (await m.sync(db_session, target, up=False)).ok
    db_session.expire_all()
    for cidr, sid in kept.items():
        rows = await _subnets_at(db_session, space_id, cidr)
        assert [(r.id, getattr(r, m.fk)) for r in rows] == [(sid, None)], cidr

    await db_session.refresh(target)
    summary = await m.sync(db_session, target)
    assert summary.ok, summary.error

    db_session.expire_all()
    for cidr, sid in kept.items():
        rows = await _subnets_at(db_session, space_id, cidr)
        assert [r.id for r in rows] == [sid], f"{cidr}: {len(rows)} subnet rows"
    assert summary.subnets_created == 0
    assert summary.subnets_matched == len(m.cidrs)
    owned = await _owned(db_session, m.fk, target_id)
    assert set(owned) == set(m.addresses)
    for ip, row in owned.items():
        assert row.subnet_id == kept[m.addresses[ip]], ip
    for ip in m.edited():
        assert owned[ip].hostname == f"edited-{ip}", ip


# ── Placement beside a twin an earlier build left ─────────────────────


@pytest.mark.parametrize("own_first", [False, True], ids=["unowned-first", "own-first"])
@pytest.mark.parametrize("kind", list(_MIRRORS))
async def test_addresses_go_to_the_targets_own_subnet_beside_a_twin_2790(
    db_session: AsyncSession, kind: str, own_first: bool
) -> None:
    """Where a CIDR already has two rows, the target's addresses go to the
    target's own subnet, whichever row was inserted (and so is returned)
    first."""
    m = _MIRRORS[kind]
    space_id = await _space(db_session)
    target = m.target(space_id, _n(kind))
    db_session.add(target)
    await db_session.flush()
    target_id = target.id
    twins = await _twins(db_session, space_id, m, target_id, own_first=own_first)
    await db_session.commit()

    summary = await m.sync(db_session, target)
    assert summary.ok, summary.error

    db_session.expire_all()
    owned = await _owned(db_session, m.fk, target_id)
    assert {ip: row.subnet_id for ip, row in owned.items()} == {
        ip: twins[cidr][0] for ip, cidr in m.addresses.items()
    }


@pytest.mark.parametrize("own_first", [False, True], ids=["unowned-first", "own-first"])
@pytest.mark.parametrize("kind", list(_MIRRORS))
async def test_an_edited_address_keeps_its_subnet_2790(
    db_session: AsyncSession, kind: str, own_first: bool
) -> None:
    """A row an operator edited (``user_modified_at``) stays in its subnet: a
    sync does not move it, here out of the kept twin into the target's own
    one."""
    m = _MIRRORS[kind]
    space_id = await _space(db_session)
    target = m.target(space_id, _n(kind))
    db_session.add(target)
    await db_session.flush()
    target_id = target.id
    twins = await _twins(db_session, space_id, m, target_id, own_first=own_first)
    for ip in m.edited():
        db_session.add(
            IPAddress(
                subnet_id=twins[m.addresses[ip]][1],
                address=ip,
                status="allocated",
                hostname=f"edited-{ip}",
                user_modified_at=datetime.now(UTC),
                **{m.fk: target_id},
            )
        )
    await db_session.commit()

    summary = await m.sync(db_session, target)
    assert summary.ok, summary.error

    db_session.expire_all()
    owned = await _owned(db_session, m.fk, target_id)
    for ip in m.edited():
        assert owned[ip].subnet_id == twins[m.addresses[ip]][1], ip
        assert owned[ip].hostname == f"edited-{ip}", ip

"""Delete-side mirror guards (#1558, #1554, #1557, #1561).

The fetch-side twins shipped in PR #1597 (a failed / partial fetch must
never look like "empty"); these pin the delete side:

* #1558 — a mirror whose upstream network leaves the desired set must
  not delete the Subnet outright when operator / foreign /
  operator-edited addresses still live in it (``subnet_id`` cascades).
  It un-claims the subnet instead.
* #1554 — IPAM's DNS drift sweep must not treat records owned by an
  integration mirror, the DNS pool pipeline, or ACME as its own stale
  output just because they carry no ``ip_address_id``.
* #1557 — Tailscale / NetBird / OPNsense-Dnsmasq mirrors stored an FQDN
  as the IPAM ``hostname``; publishing appended the zone a second time.
  Only the host label is stored now.
* #1561 — the Kubernetes / Tailscale / NetBird record passes must not
  insert beside a non-owned record at the same name (CNAME conflicts
  included).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.integration_ownership import (
    dns_record_owned_elsewhere,
    subnet_has_surviving_addresses,
)

# ── #1558: the shared survivor predicate ─────────────────────────────


async def _space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"guard-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _subnet(db: AsyncSession, space: IPSpace, cidr: str, **owners: object) -> Subnet:
    block = IPBlock(space_id=space.id, network=cidr, name=f"b-{cidr}")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=cidr,
        name=f"s-{cidr}",
        total_ips=254,
        **owners,
    )
    db.add(subnet)
    await db.flush()
    return subnet


def _addr(subnet: Subnet, address: str, **kw: object) -> IPAddress:
    return IPAddress(subnet_id=subnet.id, address=address, status="used", **kw)


@pytest.mark.asyncio
async def test_survivor_predicate(db_session: AsyncSession) -> None:
    from app.models.unifi import UnifiController

    space = await _space(db_session)
    host = DockerHost(
        name=f"docker-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint="docker.example.test:2376",
        ipam_space_id=space.id,
        client_key_encrypted=b"",
    )
    controller = UnifiController(
        name=f"unifi-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id
    )
    db_session.add_all([host, controller])
    await db_session.flush()
    host_id = host.id

    # Only this integration's own, unedited rows → safe to delete.
    own_only = await _subnet(db_session, space, "10.60.0.0/24", docker_host_id=host_id)
    db_session.add(_addr(own_only, "10.60.0.10", docker_host_id=host_id))
    await db_session.flush()
    assert not await subnet_has_surviving_addresses(db_session, own_only.id, "docker_host_id")

    # Empty subnet → safe to delete.
    empty = await _subnet(db_session, space, "10.61.0.0/24", docker_host_id=host_id)
    assert not await subnet_has_surviving_addresses(db_session, empty.id, "docker_host_id")

    # Operator allocation (no owner FK) → survivor.
    with_operator = await _subnet(db_session, space, "10.62.0.0/24", docker_host_id=host_id)
    db_session.add(_addr(with_operator, "10.62.0.10", docker_host_id=host_id))
    db_session.add(_addr(with_operator, "10.62.0.99"))
    await db_session.flush()
    assert await subnet_has_surviving_addresses(db_session, with_operator.id, "docker_host_id")

    # Another integration's row → survivor.
    foreign = await _subnet(db_session, space, "10.63.0.0/24", docker_host_id=host_id)
    db_session.add(_addr(foreign, "10.63.0.10", unifi_controller_id=controller.id))
    await db_session.flush()
    assert await subnet_has_surviving_addresses(db_session, foreign.id, "docker_host_id")

    # Own row an operator edited → survivor.
    edited = await _subnet(db_session, space, "10.64.0.0/24", docker_host_id=host_id)
    db_session.add(
        _addr(
            edited,
            "10.64.0.10",
            docker_host_id=host_id,
            user_modified_at=datetime.now(UTC),
        )
    )
    await db_session.flush()
    assert await subnet_has_surviving_addresses(db_session, edited.id, "docker_host_id")

    with pytest.raises(ValueError):
        await subnet_has_surviving_addresses(db_session, own_only.id, "subnet_id")


@pytest.mark.asyncio
async def test_docker_subnet_with_operator_address_is_unclaimed_not_deleted(
    db_session: AsyncSession,
) -> None:
    """End to end through the Docker reconciler: the network disappears
    upstream, the subnet holds an operator address, so the subnet (and
    the address) survive with the Docker claim released."""
    from app.services.docker.client import _DockerNetwork
    from app.services.docker.reconcile import reconcile_host

    space = await _space(db_session)
    host = DockerHost(
        name=f"docker-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint="docker.example.test:2376",
        ipam_space_id=space.id,
        client_key_encrypted=b"",
    )
    db_session.add(host)
    await db_session.flush()
    await db_session.commit()

    class _FakeClient:
        def __init__(self, networks):
            self.networks = networks

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def list_networks(self):
            return self.networks

        async def list_containers(self, *, include_stopped):
            del include_stopped
            return []

    def _patch(fake):
        return patch(
            "app.services.docker.reconcile.DockerClient",
            side_effect=lambda **_kw: fake,
        )

    network = _DockerNetwork(
        id="net1",
        name="backend",
        driver="bridge",
        scope="local",
        subnets=[("172.30.0.0/16", "172.30.0.1")],
    )
    with _patch(_FakeClient([network])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.docker_host_id == host.id))
    ).scalar_one()

    operator_addr = _addr(subnet, "172.30.0.50")
    operator_addr.hostname = "operator-box"
    db_session.add(operator_addr)
    await db_session.commit()

    with _patch(_FakeClient([])):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error
    assert summary.subnets_deleted == 0

    await db_session.refresh(subnet)
    assert subnet.docker_host_id is None, "subnet should be handed back, not deleted"
    surviving = (
        await db_session.execute(select(IPAddress).where(IPAddress.id == operator_addr.id))
    ).scalar_one_or_none()
    assert surviving is not None, "operator address must not be cascade-deleted"


# ── #1554: the shared "owned elsewhere" record predicate ─────────────


def _record(**kw: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "kubernetes_cluster_id": None,
        "tailscale_tenant_id": None,
        "netbird_instance_id": None,
        "pool_member_id": None,
        "tags": {},
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_dns_record_owned_elsewhere() -> None:
    assert not dns_record_owned_elsewhere(_record())
    assert dns_record_owned_elsewhere(_record(kubernetes_cluster_id=uuid.uuid4()))
    assert dns_record_owned_elsewhere(_record(tailscale_tenant_id=uuid.uuid4()))
    assert dns_record_owned_elsewhere(_record(netbird_instance_id=uuid.uuid4()))
    assert dns_record_owned_elsewhere(_record(pool_member_id=uuid.uuid4()))
    assert dns_record_owned_elsewhere(_record(tags={"acme_challenge": True}))
    assert not dns_record_owned_elsewhere(_record(tags={"unrelated": True}))
    assert not dns_record_owned_elsewhere(_record(tags=None))


@pytest.mark.asyncio
async def test_drift_sweep_ignores_records_owned_elsewhere(
    db_session: AsyncSession,
) -> None:
    """#1554: an auto-generated record with no ip_address_id in the
    subnet's forward zone is stale only when IPAM sync owns it. A
    Kubernetes Ingress record and an ACME challenge TXT in the same
    zone must not be reported (auto-sync would delete them)."""
    from app.core.crypto import encrypt_str
    from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
    from app.models.kubernetes import KubernetesCluster
    from app.services.dns.sync_check import compute_subnet_dns_drift

    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="corp.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.corp.example.",
        admin_email="admin.corp.example.",
    )
    db_session.add(zone)
    space = await _space(db_session)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.66.0.0/24", name="blk")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.66.0.0/24",
        name="sn",
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    cluster = KubernetesCluster(
        name=f"cluster-{uuid.uuid4().hex[:6]}",
        api_server_url="https://k8s.example.test:6443",
        ca_bundle_pem="",
        token_encrypted=encrypt_str("faketoken"),
        ipam_space_id=space.id,
        dns_group_id=grp.id,
    )
    db_session.add_all([subnet, cluster])
    await db_session.flush()

    def _rec(name: str, rtype: str, **kw: object) -> DNSRecord:
        return DNSRecord(
            zone_id=zone.id,
            name=name,
            fqdn=f"{name}.corp.example",
            record_type=rtype,
            value="10.66.0.9" if rtype == "A" else "challenge-token",
            auto_generated=True,
            **kw,
        )

    stale = _rec("gone-host", "A")
    ingress = _rec("app", "A", kubernetes_cluster_id=cluster.id)
    acme = _rec("_acme-challenge.app", "TXT", tags={"acme_challenge": True})
    db_session.add_all([stale, ingress, acme])
    await db_session.flush()

    report = await compute_subnet_dns_drift(db_session, subnet.id)
    stale_ids = {s.record_id for s in report.stale}
    assert stale.id in stale_ids, "plain IPAM orphan must still be reported stale"
    assert ingress.id not in stale_ids
    assert acme.id not in stale_ids

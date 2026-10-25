"""Tests for the Docker reconciler.

Stub the Docker client since we don't want a real daemon. Same
structure as ``test_kubernetes_reconcile`` — validates smart parent-
block detection, network → subnet creation, container mirroring
(opt-in), default-network filtering, and cascade-delete on host
removal.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.docker import DockerHost
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.docker.client import _DockerContainer, _DockerNetwork
from app.services.docker.reconcile import reconcile_host
from app.services.integration_ownership import release_integration_rows

# ── Fixtures ─────────────────────────────────────────────────────────


async def _make_space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"docker-test-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _make_block(db: AsyncSession, space: IPSpace, network: str) -> IPBlock:
    block = IPBlock(
        space_id=space.id,
        network=network,
        name=f"blk-{uuid.uuid4().hex[:6]}",
    )
    db.add(block)
    await db.flush()
    return block


async def _make_host(
    db: AsyncSession,
    space: IPSpace,
    *,
    mirror_containers: bool = False,
    include_default_networks: bool = False,
    include_stopped: bool = False,
) -> DockerHost:
    host = DockerHost(
        name=f"docker-{uuid.uuid4().hex[:6]}",
        connection_type="tcp",
        endpoint="docker.example.test:2376",
        ipam_space_id=space.id,
        mirror_containers=mirror_containers,
        include_default_networks=include_default_networks,
        include_stopped_containers=include_stopped,
        client_key_encrypted=b"",
    )
    db.add(host)
    await db.flush()
    return host


class _FakeClient:
    def __init__(
        self,
        *,
        networks: list[_DockerNetwork] | None = None,
        containers: list[_DockerContainer] | None = None,
    ) -> None:
        self.networks = networks or []
        self.containers = containers or []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def list_networks(self):
        return self.networks

    async def list_containers(self, *, include_stopped: bool):
        # include_stopped filter is applied by the reconciler via
        # host.include_stopped_containers on the status-check side,
        # so for the fake client we just return everything and trust
        # the reconciler.
        del include_stopped
        return self.containers


def _patch_client(fake: _FakeClient):
    def _ctor(**_kwargs):
        return fake

    return patch(
        "app.services.docker.reconcile.DockerClient",
        side_effect=_ctor,
    )


# ── Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_network_without_parent_creates_wrapper_and_subnet(
    db_session: AsyncSession,
) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ]
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.ok, summary.error
    assert summary.blocks_created == 1
    assert summary.subnets_created == 1

    res = await db_session.execute(select(Subnet).where(Subnet.docker_host_id == host.id))
    sub = res.scalar_one()
    assert str(sub.network) == "172.20.0.0/16"
    assert str(sub.gateway) == "172.20.0.1"
    # Docker subnets use normal LAN semantics — no kubernetes_semantics flag.
    assert sub.kubernetes_semantics is False


@pytest.mark.asyncio
async def test_enclosing_operator_block_skips_wrapper(
    db_session: AsyncSession,
) -> None:
    space = await _make_space(db_session)
    parent = await _make_block(db_session, space, "172.16.0.0/12")
    host = await _make_host(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ]
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.ok
    assert summary.blocks_created == 0

    res = await db_session.execute(select(Subnet).where(Subnet.docker_host_id == host.id))
    sub = res.scalar_one()
    assert sub.block_id == parent.id


@pytest.mark.asyncio
async def test_rfc1918_supernet_auto_created(db_session: AsyncSession) -> None:
    """If no enclosing block exists, the reconciler should create an
    RFC 1918 parent block (unowned) so the docker network nests under
    it rather than creating its own top-level wrapper.
    """
    space = await _make_space(db_session)
    host = await _make_host(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="myapp_default",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ]
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.ok, summary.error

    # A 172.16.0.0/12 parent block exists and is unowned.
    res = await db_session.execute(
        select(IPBlock).where(IPBlock.space_id == space.id, IPBlock.network == "172.16.0.0/12")
    )
    parent = res.scalar_one()
    assert parent.docker_host_id is None
    # No host-owned wrapper at /16 — the subnet nests directly under /12.
    res = await db_session.execute(select(IPBlock).where(IPBlock.docker_host_id == host.id))
    assert list(res.scalars().all()) == []
    # Subnet parent is the /12.
    res = await db_session.execute(select(Subnet).where(Subnet.docker_host_id == host.id))
    sub = res.scalar_one()
    assert sub.block_id == parent.id


@pytest.mark.asyncio
async def test_cgnat_supernet_auto_created(db_session: AsyncSession) -> None:
    """RFC 6598 (100.64/10) should get the same supernet treatment
    even though it isn't strictly RFC 1918 — it shows up in some
    k3s / Tailscale-adjacent clusters.
    """
    space = await _make_space(db_session)
    host = await _make_host(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="tailscale",
                driver="bridge",
                scope="local",
                subnets=[("100.80.0.0/16", "100.80.0.1")],
            )
        ]
    )
    with _patch_client(fake):
        await reconcile_host(db_session, host)

    res = await db_session.execute(
        select(IPBlock).where(IPBlock.space_id == space.id, IPBlock.network == "100.64.0.0/10")
    )
    assert res.scalar_one() is not None


@pytest.mark.asyncio
async def test_default_networks_skipped_by_default(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="default-bridge",
                name="bridge",
                driver="bridge",
                scope="local",
                subnets=[("172.17.0.0/16", "172.17.0.1")],
            ),
            _DockerNetwork(
                id="net1",
                name="myapp_default",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            ),
        ]
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.subnets_created == 1  # only myapp_default


@pytest.mark.asyncio
async def test_default_networks_included_when_opted_in(
    db_session: AsyncSession,
) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, include_default_networks=True)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="default-bridge",
                name="bridge",
                driver="bridge",
                scope="local",
                subnets=[("172.17.0.0/16", "172.17.0.1")],
            )
        ]
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.subnets_created == 1


@pytest.mark.asyncio
async def test_swarm_overlay_networks_always_skipped(
    db_session: AsyncSession,
) -> None:
    """Overlay networks are cluster-wide; mirroring them per host would
    create duplicate IPAM entries on every swarm node."""
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, include_default_networks=True)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="overlay1",
                name="my-overlay",
                driver="overlay",
                scope="swarm",
                subnets=[("10.0.0.0/24", "10.0.0.1")],
            )
        ]
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.subnets_created == 0


@pytest.mark.asyncio
async def test_containers_not_mirrored_by_default(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=False)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ],
        containers=[
            _DockerContainer(
                id="c1",
                name="web",
                image="nginx:latest",
                state="running",
                status="Up 1 hour",
                ip_bindings=[("backend", "172.20.0.5")],
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    # Only the gateway address lands (from the subnet). The
    # container IP does not.
    res = await db_session.execute(
        select(IPAddress).where(
            IPAddress.docker_host_id == host.id,
            IPAddress.status == "docker-container",
        )
    )
    assert list(res.scalars().all()) == []
    assert summary.addresses_created >= 1  # at least the gateway


@pytest.mark.asyncio
async def test_containers_mirrored_when_opted_in(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ],
        containers=[
            _DockerContainer(
                id="c1",
                name="web",
                image="nginx:latest",
                state="running",
                status="Up 1 hour",
                ip_bindings=[("backend", "172.20.0.5")],
                compose_project="myapp",
                compose_service="web",
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    assert summary.ok
    res = await db_session.execute(
        select(IPAddress).where(
            IPAddress.docker_host_id == host.id,
            IPAddress.status == "docker-container",
        )
    )
    row = res.scalar_one()
    assert str(row.address) == "172.20.0.5"
    # Compose labels give us the project/service hostname form.
    assert row.hostname == "myapp.web"


@pytest.mark.asyncio
async def test_stopped_containers_skipped_by_default(
    db_session: AsyncSession,
) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ],
        containers=[
            _DockerContainer(
                id="c1",
                name="old",
                image="x",
                state="exited",
                status="Exited",
                ip_bindings=[("backend", "172.20.0.10")],
            ),
            _DockerContainer(
                id="c2",
                name="new",
                image="x",
                state="running",
                status="Up",
                ip_bindings=[("backend", "172.20.0.11")],
            ),
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_host(db_session, host)

    res = await db_session.execute(
        select(IPAddress).where(
            IPAddress.docker_host_id == host.id,
            IPAddress.status == "docker-container",
        )
    )
    rows = list(res.scalars().all())
    assert [str(r.address) for r in rows] == ["172.20.0.11"]
    assert summary.container_count == 2  # reported, just filtered by state


@pytest.mark.asyncio
async def test_host_delete_cascades(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()

    fake = _FakeClient(
        networks=[
            _DockerNetwork(
                id="net1",
                name="backend",
                driver="bridge",
                scope="local",
                subnets=[("172.20.0.0/16", "172.20.0.1")],
            )
        ],
        containers=[
            _DockerContainer(
                id="c1",
                name="web",
                image="x",
                state="running",
                status="Up",
                ip_bindings=[("backend", "172.20.0.5")],
            )
        ],
    )
    with _patch_client(fake):
        await reconcile_host(db_session, host)

    # Subnet + addresses carry the host FK and should exist. Blocks
    # don't — the /12 supernet is unowned so it's not tied to the host.
    for model, minimum in ((Subnet, 1), (IPAddress, 1)):
        res = await db_session.execute(select(model).where(model.docker_host_id == host.id))
        assert len(list(res.scalars().all())) >= minimum, model.__name__

    host_id = host.id
    await db_session.delete(host)
    await db_session.commit()

    for model in (IPBlock, Subnet, IPAddress):
        res = await db_session.execute(select(model).where(model.docker_host_id == host_id))
        assert list(res.scalars().all()) == [], f"{model.__name__} orphaned"

    # Supernet is unowned and survives host removal.
    res = await db_session.execute(select(IPBlock).where(IPBlock.network == "172.16.0.0/12"))
    assert res.scalar_one() is not None


# ── #2601: one subnet per CIDR when a kept subnet comes back ─────────


def _engine(
    networks: list[tuple[str, str, str]], containers: list[tuple[str, str, str]]
) -> _FakeClient:
    """A fake engine from ``(name, cidr, gateway)`` networks and
    ``(container, network, ip)`` bindings."""
    return _FakeClient(
        networks=[
            _DockerNetwork(
                id=f"net-{name}",
                name=name,
                driver="bridge",
                scope="local",
                subnets=[(cidr, gateway)],
            )
            for name, cidr, gateway in networks
        ],
        containers=[
            _DockerContainer(
                id=f"c-{name}",
                name=name,
                image="x",
                state="running",
                status="Up",
                ip_bindings=[(net, ip)],
            )
            for name, net, ip in containers
        ],
    )


async def _subnets_at(db: AsyncSession, space_id: uuid.UUID, cidr: str) -> list[Subnet]:
    res = await db.execute(
        select(Subnet).where(Subnet.space_id == space_id, Subnet.network == cidr)
    )
    return list(res.scalars().all())


async def _owned_addresses(db: AsyncSession, host_id: uuid.UUID) -> dict[str, IPAddress]:
    res = await db.execute(select(IPAddress).where(IPAddress.docker_host_id == host_id))
    return {str(a.address): a for a in res.scalars().all()}


async def _edit(db: AsyncSession, address: str, hostname: str) -> None:
    """An operator edit, stamped as PUT /ipam/addresses/{id} stamps it."""
    res = await db.execute(select(IPAddress).where(IPAddress.address == address))
    row = res.scalar_one()
    row.hostname = hostname
    row.user_modified_at = datetime.now(UTC)
    await db.commit()


@pytest.mark.asyncio
async def test_readd_after_delete_reuses_the_kept_subnet_2601(
    db_session: AsyncSession,
) -> None:
    """Deleting a target keeps a mirrored subnet that holds operator content,
    with no owner (#2287). Re-adding the target and syncing must not put a
    second subnet with the same CIDR beside it: the kept subnet stays the one
    row at that CIDR and holds the target's addresses."""
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()
    space_id, host_id, name, endpoint = space.id, host.id, host.name, host.endpoint
    engine = _engine(
        [("backend", "198.19.1.0/24", "198.19.1.1"), ("frontend", "172.20.0.0/16", "172.20.0.1")],
        [
            ("web", "backend", "198.19.1.11"),
            ("db", "backend", "198.19.1.12"),
            ("ui", "frontend", "172.20.0.5"),
        ],
    )
    with _patch_client(engine):
        assert (await reconcile_host(db_session, host)).ok
    await _edit(db_session, "198.19.1.11", "edited-web")
    await _edit(db_session, "172.20.0.5", "edited-ui")
    kept = {}
    for cidr in ("198.19.1.0/24", "172.20.0.0/16"):
        [row] = await _subnets_at(db_session, space_id, cidr)
        kept[cidr] = row.id

    # Delete the target as DELETE /docker/hosts/{id} does.
    await release_integration_rows(
        db_session, own_fk="docker_host_id", target_id=host_id, target_name=name
    )
    await db_session.delete(host)
    await db_session.commit()
    db_session.expire_all()
    for cidr, sid in kept.items():
        rows = await _subnets_at(db_session, space_id, cidr)
        assert [(r.id, r.docker_host_id) for r in rows] == [(sid, None)], cidr

    readded = DockerHost(
        name=name,
        connection_type="tcp",
        endpoint=endpoint,
        ipam_space_id=space_id,
        mirror_containers=True,
        client_key_encrypted=b"",
    )
    db_session.add(readded)
    await db_session.commit()
    readded_id = readded.id
    with _patch_client(engine):
        summary = await reconcile_host(db_session, readded)
    assert summary.ok, summary.error

    db_session.expire_all()
    for cidr, sid in kept.items():
        rows = await _subnets_at(db_session, space_id, cidr)
        assert [r.id for r in rows] == [sid], f"{cidr}: {len(rows)} subnet rows"
        # Reused as it stands, as the Proxmox reconciler reuses an
        # operator subnet (#177): not claimed back.
        assert rows[0].docker_host_id is None
    res = await db_session.execute(
        select(IPBlock).where(IPBlock.space_id == space_id, IPBlock.network == "198.19.1.0/24")
    )
    assert len(list(res.scalars().all())) == 1
    assert summary.subnets_created == 0
    assert summary.subnets_matched == 2

    owned = await _owned_addresses(db_session, readded_id)
    assert set(owned) == {"198.19.1.1", "198.19.1.11", "198.19.1.12", "172.20.0.1", "172.20.0.5"}
    for ip, row in owned.items():
        cidr = "198.19.1.0/24" if ip.startswith("198.19.") else "172.20.0.0/16"
        assert row.subnet_id == kept[cidr], ip
    assert owned["198.19.1.11"].hostname == "edited-web"
    assert owned["172.20.0.5"].hostname == "edited-ui"


@pytest.mark.asyncio
async def test_network_back_reuses_the_unclaimed_subnet_2601(
    db_session: AsyncSession,
) -> None:
    """A network that goes away leaves its subnet with no owner when an
    operator-edited row is in it (#1558). When the network comes back, the
    next sync reuses that subnet: one row at the CIDR, holding the
    target's addresses, the edited one with its edit."""
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    await db_session.commit()
    space_id, host_id = space.id, host.id
    up = _engine(
        [("backend", "198.19.2.0/24", "198.19.2.1")],
        [("web", "backend", "198.19.2.11"), ("db", "backend", "198.19.2.12")],
    )
    with _patch_client(up):
        assert (await reconcile_host(db_session, host)).ok
    await _edit(db_session, "198.19.2.11", "edited-web")
    [row] = await _subnets_at(db_session, space_id, "198.19.2.0/24")
    sid = row.id

    with _patch_client(_engine([], [])):
        assert (await reconcile_host(db_session, host)).ok
    db_session.expire_all()
    rows = await _subnets_at(db_session, space_id, "198.19.2.0/24")
    assert [(r.id, r.docker_host_id) for r in rows] == [(sid, None)]

    await db_session.refresh(host)
    with _patch_client(up):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error

    db_session.expire_all()
    rows = await _subnets_at(db_session, space_id, "198.19.2.0/24")
    assert [r.id for r in rows] == [sid], f"{len(rows)} subnet rows"
    assert summary.subnets_created == 0
    assert summary.subnets_matched == 1
    owned = await _owned_addresses(db_session, host_id)
    assert set(owned) == {"198.19.2.1", "198.19.2.11", "198.19.2.12"}
    assert {r.subnet_id for r in owned.values()} == {sid}
    assert owned["198.19.2.11"].hostname == "edited-web"


async def _twins(
    db: AsyncSession, space: IPSpace, host: DockerHost
) -> dict[str, tuple[uuid.UUID, uuid.UUID]]:
    """Two CIDRs an earlier build left as two rows each, a kept one with no
    owner and one the host owns, inserted in both orders so that the order
    the database returns them in cannot decide the outcome.
    Returns ``{cidr: (own subnet id, un-owned subnet id)}``."""
    block = await _make_block(db, space, "198.19.0.0/16")
    out: dict[str, tuple[uuid.UUID, uuid.UUID]] = {}
    for cidr, owners in (
        ("198.19.3.0/24", (None, host.id)),
        ("198.19.4.0/24", (host.id, None)),
    ):
        ids: dict[uuid.UUID | None, uuid.UUID] = {}
        for owner in owners:
            row = Subnet(
                space_id=space.id,
                block_id=block.id,
                network=cidr,
                name=f"twin {cidr}",
                total_ips=254,
                docker_host_id=owner,
            )
            db.add(row)
            await db.flush()
            ids[owner] = row.id
        out[cidr] = (ids[host.id], ids[None])
    return out


@pytest.mark.asyncio
async def test_addresses_go_to_the_hosts_own_subnet_beside_a_twin_2601(
    db_session: AsyncSession,
) -> None:
    """Where a CIDR already has two rows, the host's addresses go to the
    host's own subnet, not to whichever row the database returns first."""
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    twins = await _twins(db_session, space, host)
    await db_session.commit()
    host_id = host.id
    engine = _engine(
        [("n3", "198.19.3.0/24", "198.19.3.1"), ("n4", "198.19.4.0/24", "198.19.4.1")],
        [("a", "n3", "198.19.3.11"), ("b", "n4", "198.19.4.11")],
    )
    with _patch_client(engine):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error

    db_session.expire_all()
    owned = await _owned_addresses(db_session, host_id)
    own3, own4 = twins["198.19.3.0/24"][0], twins["198.19.4.0/24"][0]
    assert {ip: row.subnet_id for ip, row in owned.items()} == {
        "198.19.3.1": own3,
        "198.19.3.11": own3,
        "198.19.4.1": own4,
        "198.19.4.11": own4,
    }


@pytest.mark.asyncio
async def test_an_edited_address_keeps_its_subnet_2601(
    db_session: AsyncSession,
) -> None:
    """A row an operator edited (``user_modified_at``) stays in its subnet:
    a sync does not move it, here out of the kept twin into the host's own
    one."""
    space = await _make_space(db_session)
    host = await _make_host(db_session, space, mirror_containers=True)
    twins = await _twins(db_session, space, host)
    host_id = host.id
    edited = (("198.19.3.0/24", "198.19.3.11"), ("198.19.4.0/24", "198.19.4.11"))
    for cidr, ip in edited:
        db_session.add(
            IPAddress(
                subnet_id=twins[cidr][1],
                address=ip,
                status="docker-container",
                hostname=f"edited-{ip}",
                docker_host_id=host_id,
                user_modified_at=datetime.now(UTC),
            )
        )
    await db_session.commit()
    engine = _engine(
        [("n3", "198.19.3.0/24", "198.19.3.1"), ("n4", "198.19.4.0/24", "198.19.4.1")],
        [("a", "n3", "198.19.3.11"), ("b", "n4", "198.19.4.11")],
    )
    with _patch_client(engine):
        summary = await reconcile_host(db_session, host)
    assert summary.ok, summary.error

    db_session.expire_all()
    owned = await _owned_addresses(db_session, host_id)
    for cidr, ip in edited:
        assert owned[ip].subnet_id == twins[cidr][1], ip
        assert owned[ip].hostname == f"edited-{ip}"

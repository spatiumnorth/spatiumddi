"""Per-endpoint crash containment for the integration sweeps (#333, #1677).

Both sweeps open **one** ``AsyncSession`` and loop every endpoint /
node through ``reconcile_*`` on that shared session. ``reconcile_*``
``db.flush()``-es rows *outside* a try/except before its final commit,
so an unexpected error (duplicate-CIDR ``IntegrityError``, asyncpg type
error, …) leaves the session in a failed-transaction state.

Without an ``await db.rollback()`` in the per-endpoint ``except`` the
**next** endpoint's first query raises ``PendingRollbackError`` — one
bad endpoint poisons the whole sweep. These tests reproduce exactly
that: endpoint / node A poisons the shared session and raises, and the
fix is proven by endpoint / node B reconciling cleanly afterward.

The sweeps build their own engine against ``settings.database_url``
(the per-worker test DB the conftest points the app at), so fixture
rows are committed through ``db_session`` first and the sweep picks
them up on its own session.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.models.cloud import CloudEndpoint
from app.models.ipam import IPSpace
from app.models.proxmox import ProxmoxNode
from app.models.settings import PlatformSettings
from app.services.cloud.reconcile import ReconcileSummary as CloudSummary
from app.services.proxmox.reconcile import ReconcileSummary as ProxmoxSummary
from app.tasks import cloud_sync, proxmox_sync

_PLATFORM_SINGLETON_ID = 1


async def _platform_settings(db: AsyncSession, **flags: bool) -> None:
    ps = await db.get(PlatformSettings, _PLATFORM_SINGLETON_ID)
    if ps is None:
        ps = PlatformSettings(id=_PLATFORM_SINGLETON_ID)
        db.add(ps)
    for key, value in flags.items():
        setattr(ps, key, value)


async def _make_space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"sweep-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _poison_session(db: AsyncSession) -> None:
    """Drive ``db`` into a failed-transaction state, like a real crash would.

    A statement against a non-existent table errors at the DB; once that
    error fires inside the active transaction, SQLAlchemy refuses any
    further work until ``rollback()``. This mirrors the IntegrityError /
    asyncpg-type-error path ``reconcile_*`` can hit mid-flush.
    """
    from sqlalchemy import text  # noqa: PLC0415

    try:
        await db.execute(text("SELECT * FROM __does_not_exist_sweep_test__"))
    except Exception:  # noqa: BLE001 — expected; we just want the session poisoned
        pass


@pytest.mark.asyncio
async def test_cloud_sweep_recovers_after_endpoint_crash(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    await _platform_settings(db_session, integration_cloud_enabled=True)

    def _endpoint() -> CloudEndpoint:
        ep = CloudEndpoint(
            name=f"cloud-{uuid.uuid4().hex[:6]}",
            provider="aws",
            credentials_encrypted=encrypt_dict({"access_key_id": "x", "secret_access_key": "y"}),
            provider_config={},
            regions=["us-east-1"],
            ipam_space_id=space.id,
        )
        db_session.add(ep)
        return ep

    _endpoint()
    _endpoint()
    await db_session.commit()

    # The sweep's SELECT has no ORDER BY, so we can't rely on row order:
    # crash on whichever endpoint is processed *first* and demand the
    # second one reconcile cleanly off the same (now-poisoned-then-rolled-
    # back) session.
    calls: list[uuid.UUID] = []
    reconciled: list[uuid.UUID] = []

    async def _fake_reconcile(db: AsyncSession, endpoint: CloudEndpoint) -> CloudSummary:
        if not calls:
            calls.append(endpoint.id)
            # Poison the shared session, then crash — exactly the gap #333
            # describes (flush failure escaping reconcile_endpoint).
            await _poison_session(db)
            raise RuntimeError("boom: duplicate CIDR")
        # The second endpoint's first real query against the shared session.
        # Before the fix this raises PendingRollbackError because the first
        # left the transaction dirty; after the fix the sweep rolled back.
        await db.execute(select(CloudEndpoint).where(CloudEndpoint.id == endpoint.id))
        reconciled.append(endpoint.id)
        return CloudSummary(ok=True)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "app.services.cloud.reconcile.reconcile_endpoint",
            _fake_reconcile,
        )
        result = await cloud_sync._run_sweep()

    # One endpoint crashed, the other still reconciled cleanly.
    assert result["status"] == "ok"
    assert result["errors"] == 1
    assert result["ok"] == 1
    assert len(calls) == 1 and len(reconciled) == 1
    assert calls[0] != reconciled[0]
    assert any("boom" in msg for msg in result["error_messages"])


@pytest.mark.asyncio
async def test_cloud_sweep_no_rollback_would_poison_next_endpoint(
    db_session: AsyncSession,
) -> None:
    """Regression guard: a poisoned session with no rollback raises on the next query.

    This documents the bug the production fix prevents — it asserts the
    *failure mode* directly, independent of the sweep loop, so a future
    refactor that drops the rollback is caught. Depending on the path
    SQLAlchemy surfaces this as ``PendingRollbackError`` (flush failure)
    or a ``DBAPIError`` wrapping asyncpg's ``InFailedSQLTransactionError``
    (raw statement failure) — both subclass ``SQLAlchemyError``.
    """
    space = await _make_space(db_session)
    await db_session.commit()
    # Capture the id as a plain value: rollback (below) expires the ORM
    # object, so referencing ``space.id`` afterward would itself lazy-load.
    space_id = space.id

    await _poison_session(db_session)
    with pytest.raises(SQLAlchemyError):
        await db_session.execute(select(IPSpace).where(IPSpace.id == space_id))

    # After an explicit rollback the same query works again.
    await db_session.rollback()
    found = (await db_session.execute(select(IPSpace).where(IPSpace.id == space_id))).scalar_one()
    assert found.id == space_id


@pytest.mark.asyncio
async def test_proxmox_sweep_recovers_after_node_crash(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    await _platform_settings(db_session, integration_proxmox_enabled=True)

    def _node() -> ProxmoxNode:
        node = ProxmoxNode(
            name=f"pve-{uuid.uuid4().hex[:6]}",
            host=f"{uuid.uuid4().hex[:6]}.example.test",
            token_id="root@pam!sync",
            token_secret_encrypted=encrypt_dict({"secret": "x"}),
            ipam_space_id=space.id,
        )
        db_session.add(node)
        return node

    _node()
    _node()
    await db_session.commit()

    calls: list[uuid.UUID] = []
    reconciled: list[uuid.UUID] = []

    async def _fake_reconcile(db: AsyncSession, node: ProxmoxNode) -> ProxmoxSummary:
        if not calls:
            calls.append(node.id)
            await _poison_session(db)
            raise RuntimeError("boom: duplicate CIDR")
        await db.execute(select(ProxmoxNode).where(ProxmoxNode.id == node.id))
        reconciled.append(node.id)
        return ProxmoxSummary(ok=True)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "app.services.proxmox.reconcile.reconcile_node",
            _fake_reconcile,
        )
        result = await proxmox_sync._run_sweep()

    assert result["status"] == "ok"
    assert result["errors"] == 1
    assert result["ok"] == 1
    assert len(calls) == 1 and len(reconciled) == 1
    assert calls[0] != reconciled[0]
    assert any("boom" in msg for msg in result["error_messages"])


# ── Every integration sweep, with a real flush failure (#1677) ──────────
#
# A failed flush does more than poison the transaction: SQLAlchemy also
# expires every object on the session, so the sweep's ``except`` can no
# longer read ``target.name`` without hitting the dead transaction
# (``PendingRollbackError``), and the whole sweep dies there.


def _sweep_targets(space_id: uuid.UUID) -> dict[str, tuple]:
    """sweep → (task module, reconcile path, platform flag, target factory)."""
    from app.models.docker import DockerHost  # noqa: PLC0415
    from app.models.fortinet import FortinetFirewall  # noqa: PLC0415
    from app.models.kubernetes import KubernetesCluster  # noqa: PLC0415
    from app.models.meraki import MerakiOrg  # noqa: PLC0415
    from app.models.netbird import NetbirdInstance  # noqa: PLC0415
    from app.models.opnsense import OPNsenseRouter  # noqa: PLC0415
    from app.models.panos import PANOSFirewall  # noqa: PLC0415
    from app.models.tailscale import TailscaleTenant  # noqa: PLC0415
    from app.models.unifi import UnifiController  # noqa: PLC0415
    from app.tasks import (  # noqa: PLC0415
        docker_sync,
        fortinet_sync,
        kubernetes_sync,
        meraki_sync,
        netbird_sync,
        opnsense_sync,
        panos_sync,
        tailscale_sync,
        unifi_sync,
    )

    def _name(prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:6]}"

    return {
        "kubernetes": (
            kubernetes_sync,
            "app.services.kubernetes.reconcile.reconcile_cluster",
            "integration_kubernetes_enabled",
            lambda: KubernetesCluster(
                name=_name("k8s"),
                api_server_url="https://k8s.example.test:6443",
                ca_bundle_pem="",
                token_encrypted=b"x",
                ipam_space_id=space_id,
                pod_cidr="",
                service_cidr="",
            ),
        ),
        "docker": (
            docker_sync,
            "app.services.docker.reconcile.reconcile_host",
            "integration_docker_enabled",
            lambda: DockerHost(
                name=_name("docker"),
                connection_type="tcp",
                endpoint=f"{_name('d')}.example.test:2376",
                ipam_space_id=space_id,
                client_key_encrypted=b"",
            ),
        ),
        "tailscale": (
            tailscale_sync,
            "app.services.tailscale.reconcile.reconcile_tenant",
            "integration_tailscale_enabled",
            lambda: TailscaleTenant(
                name=_name("ts"), tailnet="-", api_key_encrypted=b"", ipam_space_id=space_id
            ),
        ),
        "netbird": (
            netbird_sync,
            "app.services.netbird.reconcile.reconcile_instance",
            "integration_netbird_enabled",
            lambda: NetbirdInstance(name=_name("nb"), ipam_space_id=space_id),
        ),
        "unifi": (
            unifi_sync,
            "app.services.unifi.reconcile.reconcile_controller",
            "integration_unifi_enabled",
            lambda: UnifiController(name=_name("unifi"), ipam_space_id=space_id),
        ),
        "proxmox": (
            proxmox_sync,
            "app.services.proxmox.reconcile.reconcile_node",
            "integration_proxmox_enabled",
            lambda: ProxmoxNode(
                name=_name("pve"),
                host=f"{_name('h')}.example.test",
                token_id="root@pam!sync",
                token_secret_encrypted=encrypt_dict({"secret": "x"}),
                ipam_space_id=space_id,
            ),
        ),
        "cloud": (
            cloud_sync,
            "app.services.cloud.reconcile.reconcile_endpoint",
            "integration_cloud_enabled",
            lambda: CloudEndpoint(
                name=_name("cloud"),
                provider="aws",
                credentials_encrypted=encrypt_dict({"access_key_id": "x"}),
                provider_config={},
                regions=["us-east-1"],
                ipam_space_id=space_id,
            ),
        ),
        "opnsense": (
            opnsense_sync,
            "app.services.opnsense.reconcile.reconcile_router",
            "integration_opnsense_enabled",
            lambda: OPNsenseRouter(
                name=_name("opn"), host=f"{_name('o')}.example.test", ipam_space_id=space_id
            ),
        ),
        "fortinet": (
            fortinet_sync,
            "app.services.fortinet.reconcile.reconcile_firewall",
            "integration_fortinet_enabled",
            lambda: FortinetFirewall(
                name=_name("fgt"), host=f"{_name('f')}.example.test", ipam_space_id=space_id
            ),
        ),
        "panos": (
            panos_sync,
            "app.services.panos.reconcile.reconcile_firewall",
            "integration_panos_enabled",
            lambda: PANOSFirewall(
                name=_name("pan"), host=f"{_name('p')}.example.test", ipam_space_id=space_id
            ),
        ),
        "meraki": (
            meraki_sync,
            "app.services.meraki.reconcile.reconcile_org",
            "integration_meraki_enabled",
            lambda: MerakiOrg(name=_name("meraki"), ipam_space_id=space_id),
        ),
    }


_SWEEPS = [
    "kubernetes",
    "docker",
    "tailscale",
    "netbird",
    "unifi",
    "proxmox",
    "cloud",
    "opnsense",
    "fortinet",
    "panos",
    "meraki",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("sweep", _SWEEPS)
async def test_sweep_survives_flush_failure(db_session: AsyncSession, sweep: str) -> None:
    space = await _make_space(db_session)
    space_name = space.name
    module, reconcile_path, flag, factory = _sweep_targets(space.id)[sweep]
    await _platform_settings(db_session, **{flag: True})
    db_session.add(factory())
    db_session.add(factory())
    await db_session.commit()

    calls: list[uuid.UUID] = []
    reconciled: list[uuid.UUID] = []

    async def _fake_reconcile(db: AsyncSession, target):  # noqa: ANN001
        if not calls:
            calls.append(target.id)
            # What a duplicate insert in the reconciler does: the flush
            # raises IntegrityError and expires every object in ``db``.
            db.add(IPSpace(name=space_name, description=""))
            await db.flush()
        await db.execute(select(type(target)).where(type(target).id == target.id))
        reconciled.append(target.id)
        return CloudSummary(ok=True)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconcile_path, _fake_reconcile)
        result = await module._run_sweep()

    assert result["status"] == "ok"
    assert result["errors"] == 1
    assert result["ok"] == 1
    assert len(calls) == 1 and len(reconciled) == 1
    assert calls[0] != reconciled[0]
    assert any("IntegrityError" in msg or "duplicate" in msg for msg in result["error_messages"])

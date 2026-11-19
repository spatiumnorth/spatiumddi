"""A UniFi controller named like an operator Router still syncs (#2140).

``router.name`` is UNIQUE. The UniFi reconciler created its Router under
the controller's name with no collision check, so a controller sharing a
name with an operator-created Router raised ``uq_router_name`` on every
sync and nothing was ever mirrored. It must neither fail nor adopt the
operator's Router (the VLAN pass deletes VLANs on the Router it owns).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPSpace
from app.models.unifi import UnifiController
from app.models.vlans import VLAN, Router
from app.services.netbox_import.commit import _ensure_router
from app.services.router_naming import pick_unique_router_name
from app.services.unifi import reconcile as unifi_reconcile
from app.services.unifi.client import _UnifiNetwork, _UnifiSite, _UnifiVersion


class _FakeUnifiClient:
    def __init__(self, cfg: object) -> None:  # noqa: ARG002
        pass

    async def __aenter__(self) -> _FakeUnifiClient:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_version(self) -> _UnifiVersion:
        return _UnifiVersion(version="9.0.1")

    async def list_sites(self) -> list[_UnifiSite]:
        return [_UnifiSite(name="default", desc="Default")]

    async def list_networks(self, site: str) -> list[_UnifiNetwork]:  # noqa: ARG002
        return [
            _UnifiNetwork(
                network_id="net-users",
                name="Users",
                purpose="corporate",
                enabled=True,
                ip_subnet="10.214.20.1/24",
                vlan=20,
                domain_name=None,
                dhcpd_enabled=False,
                dhcpd_start=None,
                dhcpd_stop=None,
                dhcpd_leasetime=None,
            )
        ]

    async def list_active_clients(self, site: str) -> list:  # noqa: ARG002
        return []

    async def list_known_clients(self, site: str) -> list:  # noqa: ARG002
        return []


async def _operator_router(db: AsyncSession, name: str) -> tuple[uuid.UUID, uuid.UUID]:
    router = Router(name=name, description="operator's own")
    db.add(router)
    await db.flush()
    vlan = VLAN(router_id=router.id, vlan_id=10, name="ops")
    db.add(vlan)
    await db.flush()
    return router.id, vlan.id


@pytest.mark.asyncio
async def test_controller_named_like_an_operator_router_syncs(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = f"gw-{uuid.uuid4().hex[:6]}.example.net"
    op_router_id, op_vlan_id = await _operator_router(db_session, name)
    space = IPSpace(name=f"unifi-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    controller = UnifiController(name=name, host="10.0.0.1", ipam_space_id=space.id)
    db_session.add(controller)
    await db_session.commit()

    monkeypatch.setattr(unifi_reconcile, "UnifiClient", _FakeUnifiClient)

    summary = await unifi_reconcile.reconcile_controller(db_session, controller)
    assert summary.ok, summary.error
    assert summary.router_name == f"{name} (UniFi)"
    assert summary.routers_created == 1
    assert controller.last_sync_error is None

    owned = (
        await db_session.execute(select(Router).where(Router.unifi_controller_id == controller.id))
    ).scalar_one()
    assert owned.name == f"{name} (UniFi)"
    assert owned.id != op_router_id
    tags = set(
        (await db_session.execute(select(VLAN.vlan_id).where(VLAN.router_id == owned.id)))
        .scalars()
        .all()
    )
    assert tags == {20}

    # The operator's Router and its VLAN are untouched.
    op_router = await db_session.get(Router, op_router_id)
    assert op_router is not None
    assert op_router.name == name
    assert op_router.unifi_controller_id is None
    assert await db_session.get(VLAN, op_vlan_id) is not None

    # A second sync is idempotent — the same Router, no "(UniFi 2)".
    summary2 = await unifi_reconcile.reconcile_controller(db_session, controller)
    assert summary2.ok, summary2.error
    assert summary2.routers_created == 0
    assert summary2.router_name == f"{name} (UniFi)"
    names = set(
        (await db_session.execute(select(Router.name).where(Router.name.like(f"{name}%"))))
        .scalars()
        .all()
    )
    assert names == {name, f"{name} (UniFi)"}
    assert await db_session.get(VLAN, op_vlan_id) is not None


@pytest.mark.asyncio
async def test_pick_unique_router_name(db_session: AsyncSession) -> None:
    base = f"r-{uuid.uuid4().hex[:6]}"
    assert await pick_unique_router_name(db_session, base, tag="UniFi") == base
    db_session.add(Router(name=base))
    await db_session.flush()
    assert await pick_unique_router_name(db_session, base, tag="UniFi") == f"{base} (UniFi)"
    db_session.add(Router(name=f"{base} (UniFi)"))
    await db_session.flush()
    assert await pick_unique_router_name(db_session, base, tag="UniFi") == f"{base} (UniFi 2)"
    # The column is String(255): a long base is cut, never the suffix.
    long = "x" * 255
    db_session.add(Router(name=long))
    await db_session.flush()
    picked = await pick_unique_router_name(db_session, long, tag="UniFi")
    assert len(picked) == 255 and picked.endswith(" (UniFi)")


@pytest.mark.asyncio
async def test_netbox_import_never_adopts_a_unifi_owned_router(db_session: AsyncSession) -> None:
    name = f"core-{uuid.uuid4().hex[:6]}"
    space = IPSpace(name=f"nb-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    controller = UnifiController(name="c", ipam_space_id=space.id)
    db_session.add(controller)
    await db_session.flush()
    unifi_router = Router(name=name, unifi_controller_id=controller.id)
    db_session.add(unifi_router)
    await db_session.commit()

    first = await _ensure_router(db_session, name)
    assert first.id != unifi_router.id
    assert first.name == f"{name} (NetBox)"
    # Re-import finds its own router again rather than minting "(NetBox 2)".
    again = await _ensure_router(db_session, name)
    assert again.id == first.id


@pytest.mark.asyncio
async def test_netbox_import_still_adopts_an_operator_router(db_session: AsyncSession) -> None:
    name = f"core-{uuid.uuid4().hex[:6]}"
    op = Router(name=name)
    db_session.add(op)
    await db_session.commit()
    assert (await _ensure_router(db_session, name)).id == op.id

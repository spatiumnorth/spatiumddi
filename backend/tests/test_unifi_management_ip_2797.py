"""A local UniFi controller added by host name still syncs (#2797).

``Router.management_ip`` is INET; the reconciler wrote ``controller.host``
into it verbatim, so a name failed the insert and rolled back every sync.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPSpace
from app.models.unifi import UnifiController
from app.models.vlans import Router
from app.services.unifi import reconcile as unifi_reconcile
from tests.test_unifi_router_name_collision_2140 import _FakeUnifiClient


async def _sync(db: AsyncSession, mp: pytest.MonkeyPatch, host: str) -> Router:
    space = IPSpace(name=f"unifi-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    c = UnifiController(
        name=f"c-{uuid.uuid4().hex[:6]}", host=host, mode="local", ipam_space_id=space.id
    )
    db.add(c)
    await db.commit()
    mp.setattr(unifi_reconcile, "UnifiClient", _FakeUnifiClient)
    summary = await unifi_reconcile.reconcile_controller(db, c)
    assert summary.ok, summary.error
    assert summary.routers_created == 1
    return (await db.execute(select(Router).where(Router.unifi_controller_id == c.id))).scalar_one()


@pytest.mark.asyncio
async def test_hostname_controller_syncs_with_null_management_ip(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    router = await _sync(db_session, monkeypatch, "unifi.example.net")
    assert router.management_ip is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("host", "expected"),
    [("10.0.0.1", "10.0.0.1"), ("[2001:db8::1]", "2001:db8::1")],
)
async def test_ip_controller_populates_management_ip(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, host: str, expected: str
) -> None:
    router = await _sync(db_session, monkeypatch, host)
    assert str(router.management_ip) == expected

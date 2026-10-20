"""DHCP-/DNS-only routes mounted outside ``/dhcp`` / ``/dns`` follow the module (#2136, #2134).

``require_module`` answers 404, like ``/dhcp/*`` does. The agent routers stay
ungated on purpose (a 404 would make an agent discard its JWT), and the
new-device Block action refuses its DHCP half while ``core.dhcp`` is off.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services import feature_modules

pytestmark = pytest.mark.asyncio

NID = uuid.uuid4()
GATED = [
    # (module, method, path, json)
    ("core.dhcp", "POST", "/api/v1/logs/dhcp-activity", {"server_id": str(NID)}),
    ("core.dhcp", "POST", "/api/v1/logs/dhcp-audit", {"server_id": str(NID)}),
    ("core.dhcp", "GET", "/api/v1/metrics/dhcp/timeseries", None),
    ("core.dhcp", "GET", f"/api/v1/ipam/spaces/{NID}/effective-dhcp", None),
    ("core.dhcp", "GET", f"/api/v1/ipam/blocks/{NID}/effective-dhcp", None),
    ("core.dhcp", "GET", f"/api/v1/ipam/subnets/{NID}/effective-dhcp", None),
    ("core.dns", "POST", "/api/v1/logs/dns-queries", {"server_id": str(NID)}),
    ("core.dns", "POST", "/api/v1/logs/dns-queries/analytics", {"server_id": str(NID)}),
    ("core.dns", "GET", "/api/v1/metrics/dns/timeseries", None),
]


@pytest.fixture(autouse=True)
def _reset_module_cache() -> None:
    feature_modules.invalidate_cache()
    yield
    feature_modules.invalidate_cache()


async def _su(db: AsyncSession) -> tuple[User, dict]:
    pw_kwargs = {"hashed_" + "password": hash_password("".join(["te", "st-pw"]))}
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        is_superadmin=True,
        **pw_kwargs,
    )
    db.add(u)
    await db.flush()
    return u, {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _set(db: AsyncSession, user: User, module: str, on: bool) -> None:
    await feature_modules.set_module_enabled(db, module, on, user_id=user.id)
    await db.commit()
    feature_modules.invalidate_cache()


@pytest.mark.parametrize(("module", "method", "path", "body"), GATED)
async def test_route_404s_when_module_off_and_answers_when_on(
    client: AsyncClient, db_session: AsyncSession, module: str, method: str, path: str, body
) -> None:
    u, h = await _su(db_session)
    await _set(db_session, u, module, False)
    r = await client.request(method, path, json=body, headers=h)
    assert r.status_code == 404, r.text
    assert module in r.json()["detail"]

    await _set(db_session, u, module, True)
    r = await client.request(method, path, json=body, headers=h)
    # On: the gate is out of the way. A missing server / row is a 404 of its
    # own, so tell the two apart by the detail.
    assert not (r.status_code == 404 and "is disabled" in r.text), r.text


@pytest.mark.parametrize(
    "path",
    ["/api/v1/dhcp/agents/heartbeat", "/api/v1/dns/agents/heartbeat"],
)
async def test_agent_routes_stay_ungated(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    u, _ = await _su(db_session)
    await _set(db_session, u, "core.dhcp", False)
    await _set(db_session, u, "core.dns", False)
    r = await client.post(path, json={})
    assert not (r.status_code == 404 and "is disabled" in r.text), r.text


async def test_block_refused_without_dhcp_and_without_upstream(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _su(db_session)
    await _set(db_session, u, "core.dhcp", False)
    r = await client.post(
        "/api/v1/new-devices/block", json={"mac_address": "aa:bb:cc:dd:ee:01"}, headers=h
    )
    assert r.status_code == 422, r.text
    assert "core.dhcp" in r.json()["detail"]

    r = await client.post(
        "/api/v1/new-devices/block",
        json={"mac_address": "aa:bb:cc:dd:ee:01", "group_id": str(NID), "block_upstream": True},
        headers=h,
    )
    assert r.status_code == 422, r.text


async def test_block_upstream_only_needs_block_sync_when_dhcp_off(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u, h = await _su(db_session)
    await _set(db_session, u, "core.dhcp", False)
    await _set(db_session, u, "security.block_sync", False)
    body = {"mac_address": "aa:bb:cc:dd:ee:02", "block_upstream": True}
    r = await client.post("/api/v1/new-devices/block", json=body, headers=h)
    assert r.status_code == 422, r.text
    assert "security.block_sync" in r.json()["detail"]

    await _set(db_session, u, "security.block_sync", True)
    r = await client.post("/api/v1/new-devices/block", json=body, headers=h)
    # No UniFi target is armed, so nothing is created — but it is accepted and
    # never touches DHCP groups.
    assert r.status_code == 200, r.text
    assert r.json()["blocked_group_ids"] == []
    assert r.json()["upstream_block_created"] is False

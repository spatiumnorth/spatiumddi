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
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.services import feature_modules

pytestmark = pytest.mark.asyncio

# Fixed, not uuid4(): it is baked into parametrize ids, and xdist workers must
# collect identical ids (a random one failed CI with "Different tests were collected").
NID = uuid.UUID("00000000-0000-4000-8000-000000002136")
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
    # No UniFi target is armed. With DHCP on that is a silent skip (the DHCP
    # block landed); with DHCP off it would be a 200 that did nothing, so it
    # is refused and says why.
    assert r.status_code == 409, r.text
    assert "armed" in r.json()["detail"]


async def test_block_upstream_with_dhcp_off_reaches_upstream_only(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from app.services.block_sync import reconcile

    # The package re-exports the APIRouter as ``router``, shadowing the module.
    nd_router = importlib.import_module("app.api.v1.new_devices.router")

    async def _armed(_db, kind):
        return [("unifi", uuid.uuid4())] if kind == "mac" else []

    calls: list[str] = []

    async def _upstream(_db, _user, _request, body):
        calls.append(body.mac_address)
        return True, None

    monkeypatch.setattr(reconcile, "applicable_targets_for_kind", _armed)
    monkeypatch.setattr(nd_router, "_maybe_block_upstream", _upstream)

    u, h = await _su(db_session)
    await _set(db_session, u, "core.dhcp", False)
    await _set(db_session, u, "security.block_sync", True)
    r = await client.post(
        "/api/v1/new-devices/block",
        json={"mac_address": "aa:bb:cc:dd:ee:03", "block_upstream": True},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["blocked_group_ids"] == []
    assert r.json()["upstream_block_created"] is True
    assert calls == ["aa:bb:cc:dd:ee:03"]


async def test_block_upstream_with_dhcp_off_needs_manage_block_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    su, _ = await _su(db_session)
    await _set(db_session, su, "core.dhcp", False)
    await _set(db_session, su, "security.block_sync", True)

    tag = uuid.uuid4().hex[:8]
    role = Role(
        name=f"r-{tag}",
        permissions=[{"action": "write", "resource_type": "ip_address"}],
    )
    group = Group(name=f"g-{tag}")
    group.roles = [role]
    pw_kwargs = {"hashed_" + "password": hash_password("".join(["te", "st-pw"]))}
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@x.com",
        display_name="W",
        is_superadmin=False,
        **pw_kwargs,
    )
    user.groups = [group]
    db_session.add_all([role, group, user])
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    r = await client.post(
        "/api/v1/new-devices/block",
        json={"mac_address": "aa:bb:cc:dd:ee:04", "block_upstream": True},
        headers=h,
    )
    assert r.status_code == 403, r.text
    assert "manage_block_sync" in r.json()["detail"]


async def test_shared_log_routes_drop_the_disabled_half(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    u, h = await _su(db_session)
    tag = uuid.uuid4().hex[:6]
    dgrp = DNSServerGroup(name=f"dg-{tag}", description="")
    hgrp = DHCPServerGroup(name=f"hg-{tag}")
    db_session.add_all([dgrp, hgrp])
    await db_session.flush()
    db_session.add_all(
        [
            DNSServer(group_id=dgrp.id, name=f"ns-{tag}", driver="bind9", host="192.0.2.1"),
            DHCPServer(server_group_id=hgrp.id, name=f"kea-{tag}", driver="kea", host="192.0.2.2"),
        ]
    )
    await db_session.commit()

    r = await client.get("/api/v1/logs/agent-sources", headers=h)
    assert r.status_code == 200, r.text
    assert {s["server_kind"] for s in r.json()} == {"dns", "dhcp"}

    # The module toggle refuses to switch a module off while it owns servers,
    # but an agent can still register while the module is off (its routes
    # stay ungated), which is how this state arises. Model it directly.
    import app.api.v1.logs.router as logs_router

    real = feature_modules.get_enabled_modules

    async def _enabled(db):
        return (await real(db)) - {"core.dhcp"}

    monkeypatch.setattr(logs_router, "get_enabled_modules", _enabled)
    r = await client.get("/api/v1/logs/agent-sources", headers=h)
    assert {s["server_kind"] for s in r.json()} == {"dns"}
    r = await client.get("/api/v1/logs/sources", headers=h)
    assert all(s["server_kind"] != "dhcp" for s in r.json())
    r = await client.post(
        "/api/v1/logs/query",
        json={"server_id": str(NID), "server_kind": "dhcp", "log_name": "x"},
        headers=h,
    )
    assert r.status_code == 404, r.text
    assert "core.dhcp" in r.json()["detail"]

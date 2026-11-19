"""A DHCP config change reaches a parked agent long-poll on the wake (#2040).

Two halves, and both have to hold for #358's wake bus to buy anything:

* the parked long-poll must READ the change when it is woken. It keeps one
  session for its whole wait, and a re-query hands back identity-map objects
  without overwriting them, so before the fix a group-level edit (HA mode,
  heartbeat, peer URLs, thread pool, lease cache) rebuilt a byte-identical
  bundle and the agent waited out the long-poll timeout. The scope and class
  cases already passed before the fix; they pin that the expiry keeps them
  working;
* every handler that changes the bundle must PUBLISH the wake. Several paths
  outside ``/dhcp`` stashed one with no collector to publish it, or none at
  all. ``test_agent_wake_route_guard.py`` holds the structural half of that.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as dhcp_agents
from app.core import agent_wake
from app.core.agent_wake import WakeResult, dhcp_group_channel
from app.core.security import create_access_token, hash_password
from app.db import get_db
from app.main import app
from app.models.auth import User
from app.models.dhcp import DHCPClientClass, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp import agent_token as dhcp_tokens
from tests.conftest import _TestSessionLocal

# ── fixtures ──────────────────────────────────────────────────────────────────


async def _estate(db: AsyncSession) -> dict[str, Any]:
    """A Kea HA pair in one group, serving one scope with one client class."""
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", mode="hot-standby")
    db.add(grp)
    await db.flush()
    servers = []
    for label, ip in (("a", "10.9.0.1"), ("b", "10.9.0.2")):
        srv = DHCPServer(
            name=f"{label}-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host=ip,
            port=67,
            server_group_id=grp.id,
            ha_peer_url=f"http://{ip}:8000/",
            agent_id=uuid.uuid4(),
            agent_registered=True,
            agent_approved=True,
            agent_fingerprint="fp",
        )
        db.add(srv)
        servers.append(srv)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.9.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.9.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, name="sc", is_active=True)
    cc = DHCPClientClass(group_id=grp.id, name="phones", match_expression="option[60].hex == 0x01")
    db.add_all([scope, cc])
    await db.flush()
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(servers[0].id), agent_id=str(servers[0].agent_id), fingerprint="fp"
    )
    servers[0].agent_token_hash = dhcp_tokens.hash_token(token)
    await db.commit()
    return {
        "group": grp.id,
        "a": servers[0].id,
        "b": servers[1].id,
        "scope": scope.id,
        "class": cc.id,
        "subnet": subnet.id,
        "token": token,
    }


@pytest.fixture
def fresh_session_per_request() -> Any:
    """Each request gets its own session, as in production.

    The shared ``client`` fixture hands every request the test's one session,
    which is exactly the condition under test — it would make a parked poll and
    the edit share an identity map and hide the bug.
    """

    async def _get_db() -> AsyncGenerator[AsyncSession, None]:
        async with _TestSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = _get_db
    yield
    app.dependency_overrides.clear()


class _FakeWake:
    """Stands in for the Redis subscription: one wake, delivered by the test."""

    def __init__(self) -> None:
        self.parked = asyncio.Event()
        self.fire = asyncio.Event()
        self.waits = 0

    async def wait(self, timeout: float) -> WakeResult:
        self.waits += 1
        if self.waits == 1:
            self.parked.set()
            await asyncio.wait_for(self.fire.wait(), timeout=timeout)
            return WakeResult.WAKE
        # No second wake comes: a poll that missed the first one waits out
        # its deadline and answers 304, which is the bug's signature.
        await asyncio.sleep(timeout)
        return WakeResult.TIMEOUT


# ── edits a parked poll must see ──────────────────────────────────────────────


async def _thread_pool(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServerGroup, ids["group"])).kea_thread_pool_size = 7  # type: ignore[union-attr]


async def _lease_cache(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServerGroup, ids["group"])).lease_cache_threshold = 0.5  # type: ignore[union-attr]


async def _heartbeat(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServerGroup, ids["group"])).heartbeat_delay_ms = 4321  # type: ignore[union-attr]


async def _ha_mode(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServerGroup, ids["group"])).mode = "load-balancing"  # type: ignore[union-attr]


async def _peer_url(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPServer, ids["b"])).ha_peer_url = "http://10.9.0.22:8000/"  # type: ignore[union-attr]


async def _scope_lease(db: AsyncSession, ids: dict[str, Any]) -> None:
    (await db.get(DHCPScope, ids["scope"])).lease_time = 1234  # type: ignore[union-attr]


async def _client_class(db: AsyncSession, ids: dict[str, Any]) -> None:
    cc = await db.get(DHCPClientClass, ids["class"])
    cc.match_expression = "option[60].hex == 0x02"  # type: ignore[union-attr]


def _server(b: dict[str, Any]) -> Any:
    return b["server"]


def _failover(b: dict[str, Any]) -> Any:
    return b["failover"]


EDITS: list[tuple[str, Callable[..., Awaitable[None]], Callable[[dict[str, Any]], Any], Any]] = [
    ("group-thread-pool", _thread_pool, lambda b: _server(b)["kea_thread_pool_size"], 7),
    ("group-lease-cache", _lease_cache, lambda b: _server(b)["lease_cache_threshold"], 0.5),
    ("group-ha-heartbeat", _heartbeat, lambda b: _failover(b)["heartbeat_delay_ms"], 4321),
    ("group-ha-mode", _ha_mode, lambda b: _failover(b)["mode"], "load-balancing"),
    (
        "peer-ha-url",
        _peer_url,
        lambda b: sorted(p["url"] for p in _failover(b)["peers"]),
        ["http://10.9.0.1:8000/", "http://10.9.0.22:8000/"],
    ),
    ("scope-lease-time", _scope_lease, lambda b: b["scopes"][0]["lease_time"], 1234),
    (
        "client-class",
        _client_class,
        lambda b: b["client_classes"][0]["match_expression"],
        "option[60].hex == 0x02",
    ),
]


@pytest.mark.parametrize(
    ("edit", "read", "expected"),
    [pytest.param(e, r, x, id=name) for name, e, r, x in EDITS],
)
async def test_a_parked_long_poll_sees_the_edit_on_the_first_wake(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
    edit: Callable[..., Awaitable[None]],
    read: Callable[[dict[str, Any]], Any],
    expected: Any,
) -> None:
    ids = await _estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    fake = _FakeWake()

    @asynccontextmanager
    async def _subscription(_channels: Any) -> AsyncIterator[_FakeWake]:
        yield fake

    monkeypatch.setattr(dhcp_agents, "wake_subscription", _subscription)
    # Short enough that a poll which ignores the wake fails fast; long enough
    # that the edit + wake below land well inside it.
    monkeypatch.setattr(dhcp_agents, "LONGPOLL_TIMEOUT_SECONDS", 6)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get("/api/v1/dhcp/agents/config", headers=headers)
        assert first.status_code == 200, first.text
        etag = first.json()["etag"]
        assert read(first.json()["bundle"]) != expected

        fake.waits = 0
        fake.parked.clear()
        poll = asyncio.create_task(
            ac.get(
                "/api/v1/dhcp/agents/config",
                headers={**headers, "If-None-Match": f'"{etag}"'},
            )
        )
        await asyncio.wait_for(fake.parked.wait(), timeout=5)

        # Another request's commit, on its own session.
        async with _TestSessionLocal() as other:
            await edit(other, ids)
            await other.commit()
        fake.fire.set()

        resp = await asyncio.wait_for(poll, timeout=15)

    assert resp.status_code == 200, (
        f"the parked poll answered {resp.status_code} after {fake.waits} wait(s): "
        "it rebuilt the bundle from stale identity-map rows and missed the wake"
    )
    assert fake.waits == 1, "the change must ride the first wake, not the next tick"
    body = resp.json()
    assert body["etag"] != etag
    assert read(body["bundle"]) == expected


_MULTI_PASS = {"group-thread-pool", "peer-ha-url", "scope-lease-time"}


class _IdleThenFire(_FakeWake):
    """``idle`` wakes that change nothing, then the one the test fires."""

    def __init__(self, idle: int) -> None:
        super().__init__()
        self.idle = idle

    async def wait(self, timeout: float) -> WakeResult:
        self.waits += 1
        if self.waits <= self.idle:
            return WakeResult.WAKE
        if self.waits == self.idle + 1:
            self.parked.set()
            await asyncio.wait_for(self.fire.wait(), timeout=timeout)
            return WakeResult.WAKE
        await asyncio.sleep(timeout)
        return WakeResult.TIMEOUT


@pytest.mark.parametrize(
    ("edit", "read", "expected"),
    [pytest.param(e, r, x, id=name) for name, e, r, x in EDITS if name in _MULTI_PASS],
)
async def test_several_idle_wakes_then_the_edit(
    db_session: AsyncSession,
    fresh_session_per_request: None,
    monkeypatch: pytest.MonkeyPatch,
    edit: Callable[..., Awaitable[None]],
    read: Callable[[dict[str, Any]], Any],
    expected: Any,
) -> None:
    """Each pass expires the session. Several in a row must neither trip a lazy
    load on an expired instance (``MissingGreenlet``, a 500 that stops the group
    converging) nor stop the pass after them seeing the change."""
    ids = await _estate(db_session)
    headers = {"Authorization": f"Bearer {ids['token']}"}
    fake = _IdleThenFire(idle=4)

    @asynccontextmanager
    async def _subscription(_channels: Any) -> AsyncIterator[_FakeWake]:
        yield fake

    monkeypatch.setattr(dhcp_agents, "wake_subscription", _subscription)
    monkeypatch.setattr(dhcp_agents, "LONGPOLL_TIMEOUT_SECONDS", 6)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get("/api/v1/dhcp/agents/config", headers=headers)
        assert first.status_code == 200, first.text
        etag = first.json()["etag"]
        fake.waits = 0
        poll = asyncio.create_task(
            ac.get(
                "/api/v1/dhcp/agents/config",
                headers={**headers, "If-None-Match": f'"{etag}"'},
            )
        )
        await asyncio.wait_for(fake.parked.wait(), timeout=5)
        async with _TestSessionLocal() as other:
            await edit(other, ids)
            await other.commit()
        fake.fire.set()
        resp = await asyncio.wait_for(poll, timeout=15)

    assert resp.status_code == 200, resp.text
    assert fake.waits == 5
    assert read(resp.json()["bundle"]) == expected


# ── handlers publish the wake ────────────────────────────────────────────────


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every channel published, without touching Redis."""
    seen: list[str] = []

    async def _publish(*channels: str) -> None:
        seen.extend(channels)

    monkeypatch.setattr(agent_wake, "publish_wake", _publish)
    from app.api.v1.admin import feature_modules as fm_router

    # raising=False: the name is new with #2040, and the negative control runs
    # this fixture against code that predates it.
    monkeypatch.setattr(fm_router, "publish_wake", _publish, raising=False)
    return seen


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"w2040-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Wake Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_a_group_edit_publishes_on_the_group_channel(
    client: AsyncClient, db_session: AsyncSession, published: list[str]
) -> None:
    ids = await _estate(db_session)
    headers = await _admin_headers(db_session)
    resp = await client.put(
        f"/api/v1/dhcp/server-groups/{ids['group']}",
        json={"kea_thread_pool_size": 3},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert dhcp_group_channel(ids["group"]) in published


async def test_a_subnet_edit_wakes_the_groups_serving_it(
    client: AsyncClient, db_session: AsyncSession, published: list[str]
) -> None:
    """RA and the DHCPv6 domain search read the subnet's DNS servers and
    domain name; the E911 options read its VLAN and site."""
    ids = await _estate(db_session)
    headers = await _admin_headers(db_session)
    resp = await client.put(
        f"/api/v1/ipam/subnets/{ids['subnet']}",
        json={"description": "renumbered"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert dhcp_group_channel(ids["group"]) in published


async def test_an_e911_binding_wakes_the_dhcp_groups(
    client: AsyncClient, db_session: AsyncSession, published: list[str]
) -> None:
    """Options 99 / 123 are rendered from the ERL a subnet resolves to."""
    ids = await _estate(db_session)
    headers = await _admin_headers(db_session)
    erl = await client.post("/api/v1/e911/erls", json={"name": "Room 101"}, headers=headers)
    assert erl.status_code == 201, erl.text
    assert published == [], "an unbound ERL is in no bundle"

    binding = await client.post(
        "/api/v1/e911/bindings",
        json={"erl_id": erl.json()["id"], "rule_kind": "subnet", "subnet_id": str(ids["subnet"])},
        headers=headers,
    )
    assert binding.status_code == 201, binding.text
    assert dhcp_group_channel(ids["group"]) in published

    published.clear()
    resp = await client.patch(
        f"/api/v1/e911/erls/{erl.json()['id']}", json={"a1": "ON"}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert dhcp_group_channel(ids["group"]) in published

    published.clear()
    resp = await client.delete(f"/api/v1/e911/bindings/{binding.json()['id']}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert dhcp_group_channel(ids["group"]) in published


async def test_a_feature_module_toggle_wakes_the_dhcp_groups(
    client: AsyncClient, db_session: AsyncSession, published: list[str]
) -> None:
    """``network.e911`` and ``ipv6.router_advertisements`` gate bundle blocks."""
    ids = await _estate(db_session)
    headers = await _admin_headers(db_session)
    resp = await client.patch(
        "/api/v1/admin/feature-modules/network.e911", json={"enabled": False}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert dhcp_group_channel(ids["group"]) in published


async def test_a_new_device_block_wakes_the_group(
    client: AsyncClient, db_session: AsyncSession, published: list[str]
) -> None:
    """The handler always stashed the wake; nothing was there to publish it."""
    ids = await _estate(db_session)
    headers = await _admin_headers(db_session)
    resp = await client.post(
        "/api/v1/new-devices/block",
        json={"mac_address": "aa:bb:cc:dd:ee:01", "group_id": str(ids["group"])},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert dhcp_group_channel(ids["group"]) in published


async def test_a_copilot_static_reservation_wakes_the_group(
    db_session: AsyncSession, published: list[str]
) -> None:
    """``/ai`` mounts no collector, so an op's own wake has to be collected at
    the dispatch site."""
    from starlette.requests import Request

    from app.api.v1.ai.proposals import apply_proposal
    from app.models.ai import AIOperationProposal
    from app.services.ai import operations

    ids = await _estate(db_session)
    user = User(
        username=f"w2040-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Wake Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.commit()
    proposal = AIOperationProposal(
        session_id=None,
        user_id=user.id,
        operation="create_dhcp_static",
        args={
            "scope_id": str(ids["scope"]),
            "ip_address": "10.9.1.50",
            "mac_address": "aa:bb:cc:dd:ee:02",
        },
        preview_text="preview",
        expires_at=operations.expires_at_default(),
    )
    db_session.add(proposal)
    await db_session.commit()
    await db_session.refresh(proposal)

    request = Request({"type": "http", "method": "POST", "path": "/", "headers": []})
    resp = await apply_proposal(proposal.id, user, db_session, request)
    assert resp.ok is True, resp
    assert dhcp_group_channel(ids["group"]) in published

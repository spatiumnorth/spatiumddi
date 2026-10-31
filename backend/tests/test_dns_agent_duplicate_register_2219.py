"""#2219 — two DNS agents on one identity no longer trade re-registrations.

Both processes of a duplicate pair (#2044: a cloned VM, two containers on one
state dir) authenticate as the one server, against its one
``agent_jwt_hash``. A token minted for either one replaces the other's hash:
the other gets 401 on its next request, re-registers, and stales the first
one's token — forever (``heartbeat_will_rebootstrap`` churn on both).

Pinned here: the refused half of the pair (displaced, owner still polling) is
refused at registration as it is at poll, with the same 409, and mints
nothing; its heartbeat does not rotate the token either. So the owner's token
stays valid and the pair settles. The refusal still records the duplicate
episode for the server chip and alert. An agent that sends no instance id
(older than #2219) registers as before, a new process still takes over, and
the survivor registers once the owner has gone quiet.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import agents as agents_api
from app.config import settings
from app.models.dns import DNSServer
from app.services.dns import agent_instance

KEY = "psk-2219"
REGISTER_URL = "/api/v1/dns/agents/register"
HEARTBEAT_URL = "/api/v1/dns/agents/heartbeat"
CONFIG_URL = "/api/v1/dns/agents/config"
INSTANCE = "X-Spatium-Agent-Instance"


@pytest.fixture(autouse=True)
def _setup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DNS_AGENT_KEY", KEY)
    monkeypatch.setattr(agents_api, "LONGPOLL_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback", True)
    monkeypatch.setattr(settings, "dns_agent_bundle_inline_fallback_after_seconds", 0)


@dataclass
class _Agent:
    """One agent process: shared identity (agent_id), its own instance id."""

    instance: str | None
    agent_id: str
    group: str
    token: str = ""
    registrations: int = 0
    refusals: int = 0
    log: list[str] = field(default_factory=list)

    def body(self) -> dict[str, object]:
        return {
            "hostname": "ns-2219",
            "driver": "bind9",
            "roles": ["authoritative"],
            "group_name": self.group,
            "fingerprint": "fp-2219",
            "agent_id": self.agent_id,
            "version": "2026.10.30-1",
        }

    def headers(self) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self.token}"}
        if self.instance is not None:
            h[INSTANCE] = self.instance
        return h

    async def register(self, client: AsyncClient) -> int:
        h = {"X-DNS-Agent-Key": KEY}
        if self.instance is not None:
            h[INSTANCE] = self.instance
        r = await client.post(REGISTER_URL, headers=h, json=self.body())
        if r.status_code == 200:
            self.token = r.json()["agent_token"]
            self.registrations += 1
        elif r.status_code == 409:
            assert r.headers[agents_api.DUPLICATE_INSTANCE_HEADER] == "1"
            self.refusals += 1
        return r.status_code

    async def heartbeat(self, client: AsyncClient) -> int:
        """What the agent does: a 401 re-registers; a rotation is adopted."""
        r = await client.post(HEARTBEAT_URL, headers=self.headers(), json={})
        self.log.append(f"hb:{r.status_code}")
        if r.status_code == 200:
            if r.json().get("rotated_token"):
                self.token = r.json()["rotated_token"]
        elif r.status_code == 401:
            await self.register(client)
        return r.status_code

    async def poll(self, client: AsyncClient) -> int:
        r = await client.get(CONFIG_URL, headers=self.headers())
        self.log.append(f"poll:{r.status_code}")
        if r.status_code == 401:
            await self.register(client)
        return r.status_code


def _pair(instances: tuple[str | None, str | None]) -> tuple[_Agent, _Agent]:
    agent_id = str(uuid.uuid4())
    group = f"g2219-{uuid.uuid4().hex[:6]}"
    return _Agent(instances[0], agent_id, group), _Agent(instances[1], agent_id, group)


async def _server(db: AsyncSession, agent_id: str) -> DNSServer:
    return (
        await db.execute(
            select(DNSServer)
            .where(DNSServer.agent_id == uuid.UUID(agent_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _duplicate_pair(client: AsyncClient) -> tuple[_Agent, _Agent]:
    """A owns the server first; B (same identity) starts later and takes it
    over. A's token is stale from B's registration, and A is displaced."""
    a, b = _pair(("agent-a", "agent-b"))
    assert await a.register(client) == 200
    assert await a.poll(client) == 200
    assert await b.register(client) == 200  # a new process: allowed
    assert await b.poll(client) == 200  # newest arrival owns the server
    return a, b


@pytest.mark.asyncio
async def test_a_duplicate_pair_settles_instead_of_trading_registrations(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every heartbeat asks for a rotation (the worst case: a token always
    near expiry). Before #2219 each rotation or re-registration by one process
    staled the other's token, and the pair re-registered every round."""
    monkeypatch.setattr(agents_api, "needs_rotation", lambda payload: True)
    a, b = await _duplicate_pair(client)
    regs_before = a.registrations + b.registrations

    for _ in range(6):
        await a.heartbeat(client)
        await a.poll(client)
        await b.heartbeat(client)
        await b.poll(client)

    # No registration succeeded after the pair formed: the owner was never
    # staled, and the refused process was told so rather than given a token.
    assert a.registrations + b.registrations == regs_before, (a.log, b.log)
    assert "hb:401" not in b.log and "poll:401" not in b.log, b.log
    assert b.registrations == 1
    assert a.refusals >= 1
    # The owner's token still works.
    assert await b.heartbeat(client) == 200

    srv = await _server(db_session, a.agent_id)
    assert srv.agent_instance == "agent-b"
    # The refusal at registration is recorded like a refused poll (#2044).
    assert srv.duplicate_agent_last_at is not None
    assert srv.duplicate_agent_ip


@pytest.mark.asyncio
async def test_a_refused_registration_mints_nothing_and_keeps_the_chip_current(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, b = await _duplicate_pair(client)
    srv = await _server(db_session, a.agent_id)
    hash_before = srv.agent_jwt_hash
    # The episode has lasted long enough to report.
    srv.duplicate_agent_first_at = datetime.now(UTC) - timedelta(minutes=3)
    srv.duplicate_agent_last_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    assert await a.register(client) == 409
    srv = await _server(db_session, a.agent_id)
    assert srv.agent_jwt_hash == hash_before
    assert agent_instance.duplicate_active(srv)
    # Re-registration did not change who owns the row.
    assert srv.agent_instance == "agent-b"
    assert await b.poll(client) in (200, 304)


@pytest.mark.asyncio
async def test_a_shared_token_is_not_rotated_by_the_refused_process(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two containers on one state dir share the token file as well. The
    refused one's heartbeat must not rotate it out from under the owner."""
    monkeypatch.setattr(agents_api, "needs_rotation", lambda payload: True)
    a, b = _pair(("agent-a", "agent-b"))
    assert await a.register(client) == 200
    b.token = a.token
    assert await a.poll(client) == 200
    assert await b.poll(client) == 200  # B owns, A displaced

    r = await client.post(HEARTBEAT_URL, headers=a.headers(), json={})
    assert r.status_code == 200
    assert r.json()["rotated_token"] is None
    # The owner's (shared) token is still the live one, and the owner rotates.
    r = await client.post(HEARTBEAT_URL, headers=b.headers(), json={})
    assert r.status_code == 200
    assert r.json()["rotated_token"]


@pytest.mark.asyncio
async def test_an_agent_without_an_instance_id_registers_as_before(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An agent older than #2219 sends no instance id on registration: it
    cannot be told apart, and registers exactly as it always did."""
    a, b = await _duplicate_pair(client)
    legacy = _Agent(None, a.agent_id, a.group)
    assert await legacy.register(client) == 200
    assert legacy.token
    assert await legacy.heartbeat(client) == 200
    # A brand-new identity with an instance id registers too.
    fresh, _ = _pair(("agent-new", None))
    assert await fresh.register(client) == 200


@pytest.mark.asyncio
async def test_the_survivor_registers_once_the_owner_has_gone_quiet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, b = await _duplicate_pair(client)
    assert await a.register(client) == 409
    srv = await _server(db_session, a.agent_id)
    srv.agent_instance_seen_at = (
        datetime.now(UTC) - agent_instance.OWNER_GONE_AFTER - timedelta(seconds=5)
    )
    await db_session.commit()

    assert await a.register(client) == 200
    assert await a.poll(client) == 200
    srv = await _server(db_session, a.agent_id)
    assert srv.agent_instance == "agent-a"

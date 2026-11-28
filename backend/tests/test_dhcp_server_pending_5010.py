"""#5010 — a new agentless DHCP server reads ``pending`` until its first
health check, which then sets ``active`` or ``unreachable``."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPServer
from app.tasks import dhcp_health
from tests.test_dhcp_agentless_no_open_txn_4775 import _install

_CREDS = {"username": "u", "password": "p"}


async def _token(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"p-{uuid.uuid4().hex[:6]}",
        email=f"p-{uuid.uuid4().hex[:6]}@example.test",
        display_name="p",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.fixture
def queued(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        dhcp_health.check_dhcp_server_health, "delay", lambda sid: calls.append(sid)
    )
    return calls


async def _create(client: AsyncClient, h: dict[str, str], driver: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": f"s-{uuid.uuid4().hex[:6]}",
        "driver": driver,
        "host": "192.0.2.9",
    }
    if driver == "windows_dhcp":
        body["windows_credentials"] = _CREDS
    r = await client.post("/api/v1/dhcp/servers", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_agentless_create_is_pending_and_queues_a_check(
    client: AsyncClient, db_session: AsyncSession, queued: list[str]
) -> None:
    h = await _token(db_session)
    created = await _create(client, h, "windows_dhcp")
    assert created["status"] == "pending"
    assert queued == [created["id"]]
    listed = (await client.get("/api/v1/dhcp/servers", headers=h)).json()
    assert [s["status"] for s in listed if s["id"] == created["id"]] == ["pending"]


@pytest.mark.asyncio
async def test_agent_based_create_unchanged(
    client: AsyncClient, db_session: AsyncSession, queued: list[str]
) -> None:
    h = await _token(db_session)
    created = await _create(client, h, "kea")
    assert created["status"] == "active"
    assert queued == []


@pytest.mark.asyncio
@pytest.mark.parametrize(("ok", "expected"), [(True, "active"), (False, "unreachable")])
async def test_first_health_check_settles_pending(
    client: AsyncClient,
    db_session: AsyncSession,
    queued: list[str],
    monkeypatch: pytest.MonkeyPatch,
    ok: bool,
    expected: str,
) -> None:
    h = await _token(db_session)
    created = await _create(client, h, "windows_dhcp")
    _install(monkeypatch, dhcp_health)

    class _Drv:
        async def health_check(self, server: Any) -> tuple[bool, str]:
            return ok, "" if ok else "down"

    monkeypatch.setattr(dhcp_health, "get_driver", lambda _n: _Drv())
    await dhcp_health._check_health(uuid.UUID(created["id"]))
    db_session.expire_all()
    row = await db_session.get(DHCPServer, uuid.UUID(created["id"]))
    assert row is not None and row.status == expected

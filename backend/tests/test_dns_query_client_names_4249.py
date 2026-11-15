"""Logs → DNS Queries resolves client addresses to host names (#4249).

``resolve_clients`` is opt-in: ``none`` does no lookups, ``ipam`` reads the
host name from one chosen IP space (only rows the caller may read), ``ptr``
asks the platform's reverse-DNS resolvers and caches the answer.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dns import DNSServer, DNSServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.logs import DNSQueryLogEntry

pytestmark = pytest.mark.asyncio

_NOW = datetime.now(UTC)


def _tag() -> str:
    return uuid.uuid4().hex[:6]


async def _user(db: AsyncSession, permissions: list[dict] | None) -> str:
    u = User(
        username=f"u-{_tag()}",
        email=f"{_tag()}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=permissions is None,
    )
    db.add(u)
    await db.flush()
    if permissions is not None:
        role = Role(name=f"r-{_tag()}", description="", permissions=permissions)
        db.add(role)
        await db.flush()
        grp = Group(name=f"g-{_tag()}", description="")
        grp.roles = [role]
        grp.users = [u]
        db.add(grp)
        await db.flush()
    return create_access_token(str(u.id))


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _logs(db: AsyncSession, ips: list[str]) -> DNSServer:
    g = DNSServerGroup(name=f"g-{_tag()}")
    db.add(g)
    await db.flush()
    srv = DNSServer(group_id=g.id, name=f"s-{_tag()}", driver="bind9", host="192.0.2.1")
    db.add(srv)
    await db.flush()
    for i, ip in enumerate(ips):
        db.add(
            DNSQueryLogEntry(
                server_id=srv.id,
                ts=_NOW - timedelta(minutes=i + 1),
                client_ip=ip,
                client_port=5000 + i,
                qname="x.test",
                qtype="A",
                raw="query: x.test IN A",
            )
        )
    await db.commit()
    return srv


async def _space(db: AsyncSession, addrs: dict[str, str]) -> tuple[IPSpace, dict[str, IPAddress]]:
    space = IPSpace(name=f"sp-{_tag()}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    sn = Subnet(space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="s")
    db.add(sn)
    await db.flush()
    rows = {}
    for ip, host in addrs.items():
        rows[ip] = IPAddress(subnet_id=sn.id, address=ip, hostname=host, status="allocated")
        db.add(rows[ip])
    await db.commit()
    return space, rows


async def _post(client: AsyncClient, token: str, **body: Any) -> Any:
    return await client.post("/api/v1/logs/dns-queries", json=body, headers=_h(token))


async def test_ipam_resolves_only_from_chosen_space(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _logs(db_session, ["10.0.0.5", "10.0.0.6"])
    space_a, _ = await _space(db_session, {"10.0.0.5": "alpha"})
    await _space(db_session, {"10.0.0.5": "other-space", "10.0.0.6": "beta"})
    token = await _user(db_session, None)
    await db_session.commit()

    r = await _post(client, token, resolve_clients="ipam", ip_space_id=str(space_a.id))
    assert r.status_code == 200, r.text
    by_ip = {e["client_ip"]: e for e in r.json()["events"]}
    assert by_ip["10.0.0.5"]["client_name"] == "alpha"
    assert by_ip["10.0.0.5"]["client_name_source"] == "ipam"
    assert by_ip["10.0.0.6"]["client_name"] is None
    assert by_ip["10.0.0.6"]["client_name_source"] is None


async def test_ipam_needs_a_space(client: AsyncClient, db_session: AsyncSession) -> None:
    await _logs(db_session, ["10.0.0.5"])
    token = await _user(db_session, None)
    await db_session.commit()
    r = await _post(client, token, resolve_clients="ipam")
    assert r.status_code == 422


async def test_ipam_skips_addresses_the_caller_cannot_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _logs(db_session, ["10.0.0.5", "10.0.0.6"])
    space, rows = await _space(db_session, {"10.0.0.5": "alpha", "10.0.0.6": "beta"})
    token = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "server", "resource_id": str(srv.id)},
            {
                "action": "read",
                "resource_type": "ip_address",
                "resource_id": str(rows["10.0.0.5"].id),
            },
        ],
    )
    await db_session.commit()
    r = await _post(client, token, resolve_clients="ipam", ip_space_id=str(space.id))
    assert r.status_code == 200, r.text
    by_ip = {e["client_ip"]: e["client_name"] for e in r.json()["events"]}
    assert by_ip == {"10.0.0.5": "alpha", "10.0.0.6": None}


async def test_none_does_no_lookups(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.logs import client_names

    async def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("resolver called")

    monkeypatch.setattr(client_names, "resolve_ptr", boom)
    await _logs(db_session, ["10.0.0.5"])
    token = await _user(db_session, None)
    await db_session.commit()
    r = await _post(client, token)
    assert r.status_code == 200
    assert r.json()["events"][0]["client_name"] is None


async def test_ptr_uses_resolver_and_caches(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.logs import client_names

    calls: list[str] = []

    async def fake(ip: str, resolver: Any) -> str | None:
        calls.append(ip)
        return "host-" + ip.replace(".", "-") + ".corp.test" if ip == "10.0.0.5" else None

    monkeypatch.setattr(client_names, "resolve_ptr", fake)
    await _logs(db_session, ["10.0.0.5", "10.0.0.5", "10.0.0.6"])
    token = await _user(db_session, None)
    await db_session.commit()

    r = await _post(client, token, resolve_clients="ptr")
    assert r.status_code == 200, r.text
    by_ip = {e["client_ip"]: e for e in r.json()["events"]}
    assert by_ip["10.0.0.5"]["client_name"] == "host-10-0-0-5.corp.test"
    assert by_ip["10.0.0.5"]["client_name_source"] == "ptr"
    assert by_ip["10.0.0.6"]["client_name"] is None
    assert sorted(calls) == ["10.0.0.5", "10.0.0.6"]  # distinct, one lookup each

    r2 = await _post(client, token, resolve_clients="ptr")
    assert r2.status_code == 200
    assert sorted(calls) == ["10.0.0.5", "10.0.0.6"]  # second call: all cached


async def test_ptr_skips_public_addresses(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.logs import client_names

    calls: list[str] = []

    async def fake(ip: str, resolver: Any) -> str | None:
        calls.append(ip)
        return "h-" + ip

    monkeypatch.setattr(client_names, "resolve_ptr", fake)
    await _logs(
        db_session, ["8.8.8.8", "10.0.0.5", "100.64.0.9", "fd00::5", "2001:4860:4860::8888"]
    )
    token = await _user(db_session, None)
    await db_session.commit()
    r = await _post(client, token, resolve_clients="ptr")
    assert r.status_code == 200, r.text
    assert sorted(calls) == ["10.0.0.5", "100.64.0.9", "fd00::5"]
    by_ip = {e["client_ip"]: e["client_name"] for e in r.json()["events"]}
    assert by_ip["8.8.8.8"] is None
    assert by_ip["2001:4860:4860::8888"] is None
    assert by_ip["10.0.0.5"] == "h-10.0.0.5"

"""A resource-scoped API token is held to its subnet or zone on EVERY route
keyed on one (GHSA-46mq-mpwf-xxwv).

GHSA-wr8j and GHSA-46mq were both the same defect: a handler keyed on a
subnet, address or zone that never re-checked the token's per-instance
binding, so a token bound to subnet A or zone A read (and could write) B.
The fix is a router-level dependency (``app.api.token_path_scope``) instead
of a check each handler must remember, and this test is its guard: it walks
every GET route under ``/api/v1/ipam`` and ``/api/v1/dns`` whose path names
``{subnet_id}``, ``{address_id}`` or ``{zone_id}`` and asserts a token bound
to the other instance is refused. A route added later is covered with no edit
here, and one that slips past the guard fails this test.

Server-keyed lists (zone-state, pending-ops) can't be refused outright, since
the server is not the token's resource; they narrow their rows instead, which
the last two tests pin.
"""

from __future__ import annotations

import re
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

_PARAM = re.compile(r"\{(\w+)(?::\w+)?\}")
_KEYED = {"subnet_id", "address_id", "zone_id"}


async def _owner(db: AsyncSession) -> User:
    user = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token User",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _token(db: AsyncSession, owner: User, grants: list[dict]) -> str:
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    return raw


async def _fixtures(db: AsyncSession) -> dict:
    tag = uuid.uuid4().hex[:6]
    space = IPSpace(name=f"sp-{tag}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.66.0.0/16", name=f"blk-{tag}")
    db.add(block)
    await db.flush()
    sub_a = Subnet(space_id=space.id, block_id=block.id, network="10.66.1.0/24", name="a")
    sub_b = Subnet(space_id=space.id, block_id=block.id, network="10.66.2.0/24", name="b")
    db.add_all([sub_a, sub_b])
    await db.flush()
    addr_b = IPAddress(subnet_id=sub_b.id, address="10.66.2.5", hostname=f"b-{tag}")
    db.add(addr_b)
    group = DNSServerGroup(name=f"g-{tag}", description="")
    db.add(group)
    await db.flush()
    zone_a = DNSZone(group_id=group.id, name=f"a-{tag}.test", kind="forward")
    zone_b = DNSZone(group_id=group.id, name=f"b-{tag}.test", kind="forward")
    db.add_all([zone_a, zone_b])
    await db.flush()
    return {
        "sub_a": sub_a,
        "sub_b": sub_b,
        "addr_b": addr_b,
        "group": group,
        "zone_a": zone_a,
        "zone_b": zone_b,
    }


def _keyed_get_routes(app) -> list[str]:
    # The OpenAPI document, not ``app.routes``: included routers are nested
    # objects there, while the document lists every path the app serves.
    out = []
    for path, ops in app.openapi()["paths"].items():
        if "get" not in ops:
            continue
        if not (path.startswith("/api/v1/ipam") or path.startswith("/api/v1/dns")):
            continue
        if path.startswith("/api/v1/dns/agents"):
            continue  # agent JWT surface, not user tokens
        if set(_PARAM.findall(path)) & _KEYED:
            out.append(path)
    return sorted(out)


def _fill(path: str, ids: dict[str, str]) -> str:
    return _PARAM.sub(lambda m: ids.get(m.group(1), str(uuid.uuid4())), path)


@pytest.mark.asyncio
async def test_every_keyed_route_refuses_a_token_bound_elsewhere(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.main import app

    f = await _fixtures(db_session)
    owner = await _owner(db_session)
    subnet_tok = await _token(
        db_session,
        owner,
        [
            {"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)},
        ],
    )
    zone_tok = await _token(
        db_session,
        owner,
        [
            {"action": "*", "resource_type": "dns_zone", "resource_id": str(f["zone_a"].id)},
        ],
    )
    await db_session.commit()

    ids = {
        "subnet_id": str(f["sub_b"].id),
        "address_id": str(f["addr_b"].id),
        "zone_id": str(f["zone_b"].id),
        "group_id": str(f["group"].id),
    }
    routes = _keyed_get_routes(app)
    assert len(routes) > 20, f"route discovery found only {len(routes)} routes"

    leaks = []
    for path in routes:
        params = set(_PARAM.findall(path))
        tok = zone_tok if "zone_id" in params else subnet_tok
        r = await client.get(_fill(path, ids), headers={"Authorization": f"Bearer {tok}"})
        if r.status_code != 403:
            leaks.append(f"{path} -> {r.status_code}")
    assert not leaks, "token bound to another instance was not refused:\n" + "\n".join(leaks)


@pytest.mark.asyncio
async def test_a_session_is_not_refused_by_the_guard(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f = await _fixtures(db_session)
    owner = await _owner(db_session)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {create_access_token(str(owner.id))}"}
    assert (
        await client.get(f"/api/v1/ipam/subnets/{f['sub_b'].id}/reconciliation", headers=hdr)
    ).status_code == 200
    assert (
        await client.get(
            f"/api/v1/dns/groups/{f['group'].id}/zones/{f['zone_b'].id}/update-acl", headers=hdr
        )
    ).status_code == 200


@pytest.mark.asyncio
async def test_server_zone_state_narrows_to_the_tokens_zones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f = await _fixtures(db_session)
    server = DNSServer(
        group_id=f["group"].id, name=f"s-{uuid.uuid4().hex[:6]}", driver="bind9", host="192.0.2.1"
    )
    db_session.add(server)
    owner = await _owner(db_session)
    raw = await _token(
        db_session,
        owner,
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(f["zone_a"].id)}],
    )
    await db_session.commit()
    r = await client.get(
        f"/api/v1/dns/servers/{server.id}/zone-state", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text
    names = {z["zone_name"] for z in r.json()["zones"]}
    assert names == {f["zone_a"].name}, f"zone-scoped token saw {names}"


@pytest.mark.asyncio
async def test_server_pending_ops_narrow_to_the_tokens_zones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.dns import DNSRecordOp

    f = await _fixtures(db_session)
    server = DNSServer(
        group_id=f["group"].id, name=f"s-{uuid.uuid4().hex[:6]}", driver="bind9", host="192.0.2.1"
    )
    db_session.add(server)
    await db_session.flush()
    for zone in (f["zone_a"], f["zone_b"]):
        db_session.add(
            DNSRecordOp(
                server_id=server.id,
                zone_name=zone.name,
                op="create",
                state="pending",
                record={"name": "h", "type": "A", "value": "10.0.0.1"},
            )
        )
    owner = await _owner(db_session)
    raw = await _token(
        db_session,
        owner,
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(f["zone_a"].id)}],
    )
    await db_session.commit()
    r = await client.get(
        f"/api/v1/dns/servers/{server.id}/pending-ops", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert {i["zone_name"] for i in body["items"]} == {f["zone_a"].name}
    assert sum(body["counts"].values()) == 1

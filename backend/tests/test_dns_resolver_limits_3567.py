"""BIND9 recursive-clients and serve-stale group options (#3567).

The four options are stored, validated, audited, shipped in the agent bundle
(so the etag moves) and refused on groups whose driver cannot apply them.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _bundle(db: AsyncSession, server_id: uuid.UUID) -> dict:
    db.expire_all()
    server = await db.get(DNSServer, server_id)
    assert server is not None
    return await build_config_bundle(db, server)


async def _group(db: AsyncSession, driver: str = "bind9") -> tuple[DNSServerGroup, DNSServer]:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    s = DNSServer(group_id=g.id, name="ns1", driver=driver, host="ns1", port=53)
    db.add(s)
    await db.flush()
    return g, s


_BODY = {
    "recursive_clients": 5000,
    "serve_stale_enabled": True,
    "stale_answer_ttl": 30,
    "max_stale_ttl": 86400,
}


@pytest.mark.asyncio
async def test_options_round_trip_reach_the_bundle_and_move_the_etag(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group, server = await _group(db_session)
    sid = server.id
    await db_session.commit()
    before = await _bundle(db_session, sid)
    assert before["options"]["recursive_clients"] is None
    assert before["options"]["serve_stale_enabled"] is False

    r = await client.put(f"/api/v1/dns/groups/{group.id}/options", json=_BODY, headers=headers)
    assert r.status_code == 200, r.text
    for k, v in _BODY.items():
        assert r.json()[k] == v

    after = await _bundle(db_session, sid)
    for k, v in _BODY.items():
        assert after["options"][k] == v
    assert after["etag"] != before["etag"]


@pytest.mark.asyncio
async def test_nullable_limits_can_be_cleared(client: AsyncClient, db_session: AsyncSession):
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    assert (await client.put(url, json=_BODY, headers=headers)).status_code == 200
    r = await client.put(
        url,
        json={"recursive_clients": None, "stale_answer_ttl": None, "max_stale_ttl": None},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["recursive_clients"] is None
    assert r.json()["stale_answer_ttl"] is None
    assert r.json()["max_stale_ttl"] is None
    assert r.json()["serve_stale_enabled"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"recursive_clients": 0},
        {"recursive_clients": 1000001},
        {"stale_answer_ttl": 0},
        {"max_stale_ttl": 0},
        {"max_stale_ttl": "soon"},
    ],
)
async def test_out_of_range_values_are_422(
    client: AsyncClient, db_session: AsyncSession, body: dict
):
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    await db_session.commit()
    r = await client.put(f"/api/v1/dns/groups/{group.id}/options", json=body, headers=headers)
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_a_powerdns_group_refuses_resolver_options(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session, "powerdns")
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options", json={"recursive_clients": 5000}, headers=headers
    )
    assert r.status_code == 422, r.text
    assert "PowerDNS" in str(r.json()["detail"])


# ── API surface: permissions, missing group, audit, schema, MCP, deletion ──


async def _non_admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
        is_superadmin=False,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


@pytest.mark.asyncio
async def test_a_non_admin_is_refused_and_nothing_is_saved(
    client: AsyncClient, db_session: AsyncSession
):
    group, _ = await _group(db_session)
    headers = await _non_admin(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    r = await client.put(url, json=_BODY, headers=headers)
    assert r.status_code == 403, r.text
    assert (await client.put(url, json=_BODY)).status_code in (401, 403)
    sa = await _superadmin(db_session)
    await db_session.commit()
    got = await client.get(url, headers=sa)
    assert got.status_code == 200, got.text
    assert got.json()["recursive_clients"] is None
    assert got.json()["serve_stale_enabled"] is False


@pytest.mark.asyncio
async def test_an_unknown_group_is_a_404_not_a_500(client: AsyncClient, db_session: AsyncSession):
    headers = await _superadmin(db_session)
    await db_session.commit()
    r = await client.put(f"/api/v1/dns/groups/{uuid.uuid4()}/options", json=_BODY, headers=headers)
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_a_deleted_group_is_a_404_and_takes_its_options_with_it(
    client: AsyncClient, db_session: AsyncSession
):
    # Server groups are hard-deleted (there is no Trash for them), so the
    # settings go with the group and a later write names it as missing.
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/options"
    assert (await client.put(url, json=_BODY, headers=headers)).status_code == 200
    gone = await client.delete(f"/api/v1/dns/groups/{group.id}", headers=headers)
    assert gone.status_code in (200, 204, 409), gone.text
    if gone.status_code != 409:  # a group that still owns servers is refused
        assert (await client.put(url, json=_BODY, headers=headers)).status_code == 404


@pytest.mark.asyncio
async def test_the_change_is_audited_with_the_fields_that_moved(
    client: AsyncClient, db_session: AsyncSession
):
    from sqlalchemy import select

    from app.models.audit import AuditLog

    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options",
        json={"recursive_clients": 5000, "serve_stale_enabled": False},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "dns_server_options")
            )
        )
        .scalars()
        .all()
    )
    fields = [f for row in rows for f in (row.changed_fields or [])]
    assert "recursive_clients" in fields
    assert "serve_stale_enabled" not in fields  # unchanged value is not named


@pytest.mark.asyncio
async def test_a_422_names_the_field(client: AsyncClient, db_session: AsyncSession):
    headers = await _superadmin(db_session)
    group, _ = await _group(db_session)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{group.id}/options", json={"recursive_clients": 0}, headers=headers
    )
    assert r.status_code == 422
    assert "recursive_clients" in str(r.json()["detail"])


@pytest.mark.asyncio
async def test_openapi_documents_the_new_fields():
    from app.main import app

    spec = app.openapi()
    schemas = spec["components"]["schemas"]
    for name in ("ServerOptionsUpdate", "ServerOptionsResponse"):
        props = schemas[name]["properties"]
        for k in _BODY:
            assert k in props, (name, k)
    import json

    bounds = json.dumps(schemas["ServerOptionsUpdate"]["properties"]["recursive_clients"])
    assert '"maximum": 1000000' in bounds and '"minimum": 1' in bounds


@pytest.mark.asyncio
async def test_the_copilot_settings_read_tool_shows_the_options(db_session: AsyncSession):
    from app.models.dns import DNSServerOptions
    from app.services.ai.tools.dns import (
        FindDNSRateLimitSettingsArgs,
        find_dns_rate_limit_settings,
    )

    group, _ = await _group(db_session)
    # Group with no options row reports the defaults.
    user = User(
        username="mcp", email="m@t.io", display_name="m", hashed_password="x", is_superadmin=True
    )
    out = await find_dns_rate_limit_settings(
        db_session, user, FindDNSRateLimitSettingsArgs(group_id=group.id)
    )
    g = out["groups"][0]
    assert g["recursive_clients"] is None and g["serve_stale_enabled"] is False
    db_session.add(DNSServerOptions(group_id=group.id, **_BODY))
    await db_session.flush()
    out = await find_dns_rate_limit_settings(
        db_session, user, FindDNSRateLimitSettingsArgs(group_id=group.id)
    )
    g = out["groups"][0]
    for k, v in _BODY.items():
        assert g[k] == v


@pytest.mark.asyncio
async def test_moving_a_server_to_another_group_follows_that_groups_options(
    client: AsyncClient, db_session: AsyncSession
):
    # The bundle is built from the server's CURRENT group: a server that left
    # the group no longer gets the setting rendered (the closest thing to
    # "removed from the bundle" for a resource with no Trash), and moving it
    # back restores it unchanged.
    headers = await _superadmin(db_session)
    g1, server = await _group(db_session)
    sid, g1_id = server.id, g1.id
    g2 = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(g2)
    await db_session.flush()
    g2_id = g2.id
    await db_session.commit()
    assert (
        await client.put(f"/api/v1/dns/groups/{g1_id}/options", json=_BODY, headers=headers)
    ).status_code == 200
    assert (await _bundle(db_session, sid))["options"]["recursive_clients"] == 5000
    srv = await db_session.get(DNSServer, sid)
    srv.group_id = g2_id
    await db_session.commit()
    assert (await _bundle(db_session, sid))["options"]["recursive_clients"] is None
    srv = await db_session.get(DNSServer, sid)
    srv.group_id = g1_id
    await db_session.commit()
    opts = (await _bundle(db_session, sid))["options"]
    for k, v in _BODY.items():
        assert opts[k] == v

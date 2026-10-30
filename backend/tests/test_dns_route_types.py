"""#3073: each DNS route needs a grant on the type it serves.

The DNS router's gate used to admit a request on a type-level grant of ANY
DNS type (``dns_group``, ``dns_zone``, ``dns_record``), and the handlers did
not re-check their own type, so a role holding only ``{read, dns_group}`` or
``{read, dns_record}`` listed every zone, server and group. Now
``_DNS_ROUTE_TYPES`` maps each route to the type(s) it needs (and
``_DNS_TOOLS_ROUTE_TYPES`` the two ``/dns/tools`` routes).

Two halves: the route maps are complete (a route added later fails here until
it is classified, and stays closed meanwhile), and the API, the Copilot tools
and a zone-bound API token are held to them.
"""

from __future__ import annotations

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import dns_tools
from app.api.v1.ai import mcp as mcp_mod
from app.api.v1.dns.router import _DNS_GATE, _DNS_ROUTE_TYPES
from app.core.permissions import mount_route_key
from app.core.security import create_access_token, generate_api_token, hash_password
from app.main import app
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes

_DNS_TYPES = {"dns_group", "dns_zone", "dns_record"}
_MAPS = (
    (_DNS_GATE, _DNS_ROUTE_TYPES),
    (dns_tools._DNS_TOOLS_GATE, dns_tools._DNS_TOOLS_ROUTE_TYPES),
)

# ── the map ─────────────────────────────────────────────────────────────────


def _gated_route_keys(gate: object) -> set[str]:
    keys: set[str] = set()
    for r in _iter_routes(app.routes):
        if not r.path.startswith("/api/v1/dns"):
            continue
        if not any(c is gate for c in _dependency_calls(r.dependant)):
            continue
        for m in r.methods:
            if m not in ("HEAD", "OPTIONS"):
                keys.add(mount_route_key(m, r.path, "/dns"))
    return keys


def test_every_gated_dns_route_is_classified() -> None:
    requires = getattr(_DNS_GATE, "spatium_route_requires", None)
    assert requires is not None, "the DNS gate is not given _DNS_ROUTE_TYPES"
    assert requires("GET", "/api/v1/dns/groups/{group_id}/zones") == ["dns_zone"]
    keys = _gated_route_keys(_DNS_GATE)
    # A walker that finds nothing makes this vacuous.
    assert len(keys) > 80
    for gate, mapping in _MAPS:
        missing = sorted(_gated_route_keys(gate) - mapping.keys())
        assert not missing, (
            "DNS routes with no entry in their route-type map (_DNS_ROUTE_TYPES in "
            "app/api/v1/dns/router.py, _DNS_TOOLS_ROUTE_TYPES in app/api/v1/dns_tools.py); "
            "until classified they admit nobody. Map each to the type(s) it serves:\n"
            + "\n".join(missing)
        )


def test_the_request_and_the_route_table_give_one_key() -> None:
    # A request carries its route's router-relative template, app.routes the
    # mounted one. ``/dnssec`` starts with ``/dns``, which is not the mount.
    for rel in ("/groups/{group_id}/zones/{zone_id}/dnssec/info", "/dnssec-policies"):
        assert mount_route_key("GET", rel, "/dns") == f"GET {rel}"
        assert mount_route_key("GET", f"/api/v1/dns{rel}", "/dns") == f"GET {rel}"


def test_the_maps_name_only_served_routes_and_dns_types() -> None:
    for gate, mapping in _MAPS:
        stale = sorted(mapping.keys() - _gated_route_keys(gate))
        assert not stale, "route-type entries no route serves:\n" + "\n".join(stale)
        unknown = sorted(
            f"{k}: {t}" for k, ts in mapping.items() for t in ts if t not in _DNS_TYPES
        )
        assert not unknown, "types outside the DNS set:\n" + "\n".join(unknown)
        assert all(mapping.values()), "a route mapped to no type"


# ── the API ─────────────────────────────────────────────────────────────────


async def _holder(db: AsyncSession, permissions: list[dict]) -> dict:
    user = User(
        username=f"drt-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="dns route types",
        hashed_password=hash_password("password123"),
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _tree(db: AsyncSession) -> dict[str, uuid.UUID]:
    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"g-{tag}", description="")
    db.add(group)
    await db.flush()
    zones = []
    for label in ("a", "b"):
        zone = DNSZone(group_id=group.id, name=f"rt{label}-{tag}.test.", kind="forward")
        db.add(zone)
        await db.flush()
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name="www",
                fqdn=f"www.{zone.name}",
                record_type="A",
                value="192.0.2.44",
            )
        )
        zones.append(zone)
    await db.flush()
    return {"group": group.id, "zone": zones[0].id, "zone_b": zones[1].id}


def _urls(t: dict[str, uuid.UUID]) -> dict[str, list[str]]:
    g, z = t["group"], t["zone"]
    base = f"/api/v1/dns/groups/{g}"
    return {
        "dns_group": [
            "/api/v1/dns/groups",
            base,
            f"{base}/servers",
            f"{base}/views",
            f"{base}/acls",
            f"{base}/options",
        ],
        "dns_zone": [
            f"{base}/zones",
            f"{base}/zones/{z}",
            f"{base}/zones/{z}/dnssec/info",
        ],
        "dns_record": [
            f"{base}/records",
            f"{base}/zones/{z}/records",
        ],
    }


def read(*types: str) -> list[dict]:
    return [{"action": "read", "resource_type": rt} for rt in types]


@pytest.mark.asyncio
@pytest.mark.parametrize("held", ["dns_group", "dns_zone", "dns_record"])
async def test_each_dns_type_reads_its_own_routes_only(
    db_session: AsyncSession, client: AsyncClient, held: str
) -> None:
    t = await _tree(db_session)
    h = await _holder(db_session, read(held))
    await db_session.commit()

    for rtype, urls in _urls(t).items():
        want = 200 if rtype == held else 403
        for url in urls:
            r = await client.get(url, headers=h)
            assert r.status_code == want, f"{held} → {url}: {r.status_code} {r.text[:200]}"


@pytest.mark.asyncio
async def test_a_route_carrying_two_types_needs_both(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)
    zone_only = await _holder(db_session, read("dns_zone"))
    record_only = await _holder(db_session, read("dns_record"))
    both = await _holder(db_session, read("dns_zone", "dns_record"))
    await db_session.commit()

    url = f"/api/v1/dns/groups/{t['group']}/zones/{t['zone']}/export"
    assert (await client.get(url, headers=zone_only)).status_code == 403
    assert (await client.get(url, headers=record_only)).status_code == 403
    r = await client.get(url, headers=both)
    assert r.status_code == 200, r.text
    assert "192.0.2.44" in r.text


@pytest.mark.asyncio
async def test_a_record_write_needs_dns_record(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)
    zone_admin = await _holder(
        db_session,
        [{"action": "admin", "resource_type": "dns_zone"}],
    )
    record_admin = await _holder(
        db_session,
        [{"action": "admin", "resource_type": "dns_record"}],
    )
    await db_session.commit()

    url = f"/api/v1/dns/groups/{t['group']}/zones/{t['zone']}/records"
    body = {"name": "new", "record_type": "A", "value": "192.0.2.45"}
    r = await client.post(url, json=body, headers=zone_admin)
    assert r.status_code == 403, r.text
    r = await client.post(url, json=body, headers=record_admin)
    assert r.status_code in (200, 201), r.text


@pytest.mark.asyncio
async def test_dns_tools_need_dns_record(db_session: AsyncSession, client: AsyncClient) -> None:
    group_reader = await _holder(db_session, read("dns_group"))
    record_reader = await _holder(db_session, read("dns_record"))
    await db_session.commit()

    url = "/api/v1/dns/tools/default-resolvers"
    assert (await client.get(url, headers=group_reader)).status_code == 403
    assert (await client.get(url, headers=record_reader)).status_code == 200


@pytest.mark.asyncio
async def test_an_unrelated_grant_reaches_no_dns_route(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)
    h = await _holder(db_session, read("dns_blocklist"))
    await db_session.commit()
    for urls in _urls(t).values():
        for url in urls:
            assert (await client.get(url, headers=h)).status_code == 403, url


# ── a zone-bound API token ──────────────────────────────────────────────────


async def _token(db: AsyncSession, grants: list[dict]) -> dict:
    owner = User(
        username=f"tok-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Token User",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(owner)
    await db.flush()
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
    return {"Authorization": f"Bearer {raw}"}


@pytest.mark.asyncio
async def test_a_zone_bound_token_keeps_reaching_its_zone_and_its_records(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # The token names only its zone; the gate lets it through on the group
    # the zone sits in and the records it holds, as the any-of gate did, and
    # the handlers narrow it to that zone.
    t = await _tree(db_session)
    h = await _token(
        db_session,
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(t["zone"])}],
    )
    await db_session.commit()

    g, z, zb = t["group"], t["zone"], t["zone_b"]
    base = f"/api/v1/dns/groups/{g}"
    r = await client.get(f"{base}/zones", headers=h)
    assert r.status_code == 200, r.text
    assert {row["id"] for row in r.json()} == {str(z)}

    r = await client.get(f"{base}/zones/{z}/records", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    rows = body["items"] if isinstance(body, dict) else body
    assert [row["value"] for row in rows] == ["192.0.2.44"]

    r = await client.get(f"{base}/records", headers=h)
    assert r.status_code == 200, r.text
    assert {row["zone_id"] for row in r.json()["items"]} == {str(z)}

    r = await client.get(f"{base}/zones/{zb}/records", headers=h)
    assert r.status_code == 403, r.text


# ── the Copilot / MCP tools ─────────────────────────────────────────────────


async def _tool_user(db: AsyncSession, permissions: list[dict]) -> User:
    u = User(
        username=f"mcp-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="MCP",
        hashed_password=hash_password("x"),
        is_active=True,
    )
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
    group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
    group.roles = [role]
    u.groups = [group]
    db.add_all([role, group, u])
    await db.commit()
    return u


async def _call(db: AsyncSession, user: User, name: str, args: dict | None = None) -> dict:
    frame = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    }
    return await mcp_mod._dispatch_one(frame, db, user)


def _denied(resp: dict) -> bool:
    if "error" in resp:
        return True
    return bool(resp.get("result", {}).get("isError"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "needs"),
    [
        ("list_dns_server_groups", "dns_group"),
        ("list_dns_zones", "dns_zone"),
        ("query_dns_records", "dns_record"),
    ],
)
async def test_dns_tools_check_their_own_type(
    db_session: AsyncSession, tool: str, needs: str
) -> None:
    t = await _tree(db_session)
    await db_session.commit()
    for held in sorted(_DNS_TYPES):
        user = await _tool_user(db_session, read(held))
        resp = await _call(db_session, user, tool)
        if held == needs:
            assert not _denied(resp), f"{held} → {tool}: {resp}"
        else:
            assert _denied(resp), f"{held} → {tool}: {resp}"
            assert "192.0.2.44" not in json.dumps(resp)
            assert str(t["zone"]) not in json.dumps(resp)

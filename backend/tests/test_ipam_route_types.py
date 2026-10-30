"""#3058: each IPAM route needs a grant on the type it serves.

The IPAM router's gate used to admit a request on a type-level grant of ANY
IPAM type, and the read handlers did not re-check their own type, so a role
holding only ``{read, nat_mapping}`` or ``{read, custom_field}`` read every
space, block, subnet and address. Now ``_IPAM_ROUTE_TYPES`` maps each route to
the type(s) it needs.

Two halves: the route map is complete (a route added later fails here until it
is classified, and stays closed to type-level grants meanwhile), and the API
refuses the reads it should.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam.router import _IPAM_GATE, _IPAM_GATE_TYPES, _IPAM_ROUTE_TYPES
from app.core.permissions import route_key
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from tests.test_builtin_roles_match_routes import _dependency_calls, _iter_routes

# ── the map ─────────────────────────────────────────────────────────────────


def _gated_route_keys() -> set[str]:
    keys: set[str] = set()
    for r in _iter_routes(app.routes):
        if not r.path.startswith("/api/v1/ipam"):
            continue
        if not any(c is _IPAM_GATE for c in _dependency_calls(r.dependant)):
            continue
        for m in r.methods:
            if m not in ("HEAD", "OPTIONS"):
                keys.add(route_key(m, r.path))
    return keys


def test_every_gated_ipam_route_is_classified() -> None:
    # The gate enforces the map, rather than "any IPAM type".
    requires = getattr(_IPAM_GATE, "spatium_route_requires", None)
    assert requires is not None, "the IPAM gate is not given _IPAM_ROUTE_TYPES"
    assert requires("GET", "/api/v1/ipam/spaces") == ["ip_space"]
    keys = _gated_route_keys()
    # A walker that finds nothing makes this vacuous.
    assert len(keys) > 100
    missing = sorted(keys - _IPAM_ROUTE_TYPES.keys())
    assert not missing, (
        "IPAM routes with no entry in _IPAM_ROUTE_TYPES (app/api/v1/ipam/router.py); "
        "until classified they admit no type-level grant at all. Map each to the "
        "type(s) it serves:\n" + "\n".join(missing)
    )


def test_the_map_names_only_served_routes_and_ipam_types() -> None:
    stale = sorted(_IPAM_ROUTE_TYPES.keys() - _gated_route_keys())
    assert not stale, "_IPAM_ROUTE_TYPES entries no route serves:\n" + "\n".join(stale)
    unknown = sorted(
        f"{k}: {t}"
        for k, types in _IPAM_ROUTE_TYPES.items()
        for t in types
        if t not in _IPAM_GATE_TYPES
    )
    assert not unknown, "types outside the IPAM set:\n" + "\n".join(unknown)
    assert all(_IPAM_ROUTE_TYPES.values()), "a route mapped to no type"


# ── the API ─────────────────────────────────────────────────────────────────


async def _holder(db: AsyncSession, permissions: list[dict]) -> dict:
    user = User(
        username=f"rt-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@t.io",
        display_name="route types",
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
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.30.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.30.1.0/24", name="s")
    db.add(subnet)
    await db.flush()
    addr = IPAddress(subnet_id=subnet.id, address="10.30.1.10", status="allocated")
    db.add(addr)
    await db.flush()
    return {"space": space.id, "block": block.id, "subnet": subnet.id, "addr": addr.id}


def _core_reads(t: dict[str, uuid.UUID]) -> list[str]:
    return [
        "/api/v1/ipam/spaces",
        f"/api/v1/ipam/spaces/{t['space']}",
        "/api/v1/ipam/blocks",
        f"/api/v1/ipam/blocks/{t['block']}",
        f"/api/v1/ipam/blocks/{t['block']}/free-space",
        "/api/v1/ipam/subnets",
        f"/api/v1/ipam/subnets/{t['subnet']}",
        f"/api/v1/ipam/subnets/{t['subnet']}/addresses",
        f"/api/v1/ipam/subnets/{t['subnet']}/effective-fields",
        f"/api/v1/ipam/addresses/{t['addr']}",
        "/api/v1/ipam/addresses/search?q=10.30",
        "/api/v1/ipam/reports/stale-ips",
        f"/api/v1/ipam/export?space_id={t['space']}",
    ]


@pytest.mark.asyncio
async def test_nat_mapping_read_opens_nat_and_nothing_else(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)
    h = await _holder(db_session, [{"action": "read", "resource_type": "nat_mapping"}])
    await db_session.commit()

    r = await client.get("/api/v1/ipam/nat-mappings", headers=h)
    assert r.status_code == 200, r.text
    for url in _core_reads(t):
        r = await client.get(url, headers=h)
        assert r.status_code == 403, f"{url}: {r.status_code} {r.text[:200]}"


@pytest.mark.asyncio
async def test_custom_field_read_opens_no_ipam_read(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)
    h = await _holder(db_session, [{"action": "read", "resource_type": "custom_field"}])
    await db_session.commit()

    # Its own surface (the custom-field definitions) still answers.
    r = await client.get("/api/v1/custom-fields", headers=h)
    assert r.status_code == 200, r.text
    for url in _core_reads(t):
        r = await client.get(url, headers=h)
        assert r.status_code == 403, f"{url}: {r.status_code} {r.text[:200]}"


@pytest.mark.asyncio
async def test_each_core_type_reads_its_own_routes(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)

    def read(*types: str) -> list[dict]:
        return [{"action": "read", "resource_type": rt} for rt in types]

    space = await _holder(db_session, read("ip_space"))
    block = await _holder(db_session, read("ip_block"))
    subnet = await _holder(db_session, read("subnet"))
    addr = await _holder(db_session, read("ip_address"))
    sub_addr = await _holder(db_session, read("subnet", "ip_address"))
    await db_session.commit()

    async def code(url: str, h: dict) -> int:
        return (await client.get(url, headers=h)).status_code

    s, b, n, a = t["space"], t["block"], t["subnet"], t["addr"]
    assert await code("/api/v1/ipam/spaces", space) == 200
    assert await code(f"/api/v1/ipam/spaces/{s}", space) == 200
    assert await code("/api/v1/ipam/blocks", space) == 403
    assert await code("/api/v1/ipam/subnets", space) == 403

    assert await code("/api/v1/ipam/blocks", block) == 200
    assert await code(f"/api/v1/ipam/blocks/{b}", block) == 200
    assert await code("/api/v1/ipam/spaces", block) == 403
    # A block's free space is its subnets' occupancy inverted.
    assert await code(f"/api/v1/ipam/blocks/{b}/free-space", block) == 403

    assert await code("/api/v1/ipam/subnets", subnet) == 200
    assert await code(f"/api/v1/ipam/subnets/{n}", subnet) == 200
    assert await code("/api/v1/ipam/spaces", subnet) == 403
    # A subnet read reaches that subnet's addresses through the subnet, as a
    # grant scoped to it does (#2438); the address routes need ip_address.
    assert await code(f"/api/v1/ipam/subnets/{n}/addresses", subnet) == 200
    assert await code(f"/api/v1/ipam/addresses/{a}", subnet) == 403
    assert await code("/api/v1/ipam/addresses/search?q=10.30", subnet) == 403
    assert await code("/api/v1/ipam/reports/stale-ips", subnet) == 403

    assert await code(f"/api/v1/ipam/addresses/{a}", addr) == 200
    assert await code("/api/v1/ipam/addresses/search?q=10.30", addr) == 200
    assert await code("/api/v1/ipam/reports/stale-ips", addr) == 200
    assert await code("/api/v1/ipam/subnets", addr) == 403
    assert await code(f"/api/v1/ipam/subnets/{n}/addresses", addr) == 403

    # An export carries the space and its blocks as well.
    assert await code(f"/api/v1/ipam/export?space_id={s}", sub_addr) == 403


@pytest.mark.asyncio
async def test_nat_mapping_write_opens_no_core_write(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    t = await _tree(db_session)
    h = await _holder(
        db_session,
        [{"action": a, "resource_type": "nat_mapping"} for a in ("read", "write", "delete")],
    )
    await db_session.commit()

    n, a = t["subnet"], t["addr"]
    for method, url, body in (
        ("POST", "/api/v1/ipam/spaces", {"name": "x"}),
        ("POST", f"/api/v1/ipam/subnets/{n}/addresses", {"address": "10.30.1.20"}),
        ("PUT", f"/api/v1/ipam/addresses/{a}", {"description": "x"}),
        ("POST", f"/api/v1/ipam/addresses/{a}/profile", {}),
        ("POST", f"/api/v1/ipam/blocks/{t['block']}/plan-allocation", {"items": []}),
        ("DELETE", f"/api/v1/ipam/addresses/{a}", None),
    ):
        r = await client.request(method, url, json=body, headers=h)
        assert r.status_code == 403, f"{method} {url}: {r.status_code} {r.text[:200]}"


@pytest.mark.asyncio
async def test_builtin_viewer_and_ipam_editor_read_everything(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    from app.main import _BUILTIN_ROLES

    t = await _tree(db_session)
    viewer = await _holder(db_session, list(_BUILTIN_ROLES["Viewer"][1]))
    editor = await _holder(db_session, list(_BUILTIN_ROLES["IPAM Editor"][1]))
    auditor = await _holder(db_session, list(_BUILTIN_ROLES["Auditor"][1]))
    await db_session.commit()

    for h in (viewer, editor, auditor):
        for url in _core_reads(t):
            r = await client.get(url, headers=h)
            assert r.status_code == 200, f"{url}: {r.status_code} {r.text[:200]}"


# ── the copilot / MCP tools ─────────────────────────────────────────────────


def _in_memory_user(*types: str) -> User:
    role = Role(name="r", permissions=[{"action": "read", "resource_type": rt} for rt in types])
    group = Group(name="g")
    group.roles = [role]
    user = User(username="u", is_active=True, is_superadmin=False)
    user.groups = [group]
    return user


def test_ipam_copilot_tools_take_their_own_type() -> None:
    from app.services.ai.tools import REGISTRY
    from app.services.ai.tools.base import tool_permission_allows

    own = {
        "list_ip_spaces": "ip_space",
        "list_ip_blocks": "ip_block",
        "list_subnets": "subnet",
        "get_subnet_summary": "subnet",
        "find_subnet_reconciliation": "subnet",
        "find_ip": "ip_address",
        "find_ip_addresses": "ip_address",
        "find_stale_ips": "ip_address",
        "find_ip_hygiene_findings": "ip_address",
        "count_devices_by_vendor": "ip_address",
        "find_devices_by_vendor": "ip_address",
    }
    for name, rtype in own.items():
        tool = REGISTRY.get(name)
        assert tool is not None, name
        assert tool_permission_allows(_in_memory_user(rtype), tool.permission), name
        for other in (
            "nat_mapping",
            "custom_field",
            *(t for t in _IPAM_GATE_TYPES[:4] if t != rtype),
        ):
            assert not tool_permission_allows(
                _in_memory_user(other), tool.permission
            ), f"{name} answers a caller holding only read on {other}"


# ── template apply writes the block / subnet it is stamped onto ─────────────


@pytest.mark.asyncio
async def test_template_apply_needs_write_on_its_target(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    # ``manage_ipam_templates`` is the right to author templates. Applying one
    # rewrites a block's or subnet's settings (and can carve subnets into a
    # block), so it also needs write on that block or subnet.
    from app.models.ipam import IPAMTemplate

    t = await _tree(db_session)
    sub_tpl = IPAMTemplate(name=f"st-{uuid.uuid4().hex[:6]}", applies_to="subnet", ddns_ttl=321)
    blk_tpl = IPAMTemplate(name=f"bt-{uuid.uuid4().hex[:6]}", applies_to="block", ddns_ttl=321)
    db_session.add_all([sub_tpl, blk_tpl])
    tpl_only = await _holder(
        db_session,
        [{"action": "admin", "resource_type": "manage_ipam_templates"}],
    )
    tpl_and_subnet = await _holder(
        db_session,
        [
            {"action": "admin", "resource_type": "manage_ipam_templates"},
            {"action": "write", "resource_type": "subnet"},
        ],
    )
    await db_session.commit()

    async def apply(tpl: IPAMTemplate, body: dict, h: dict) -> int:
        r = await client.post(f"/api/v1/ipam/templates/{tpl.id}/apply", json=body, headers=h)
        return r.status_code

    subnet_body = {"subnet_id": str(t["subnet"])}
    block_body = {"block_id": str(t["block"])}
    assert await apply(sub_tpl, subnet_body, tpl_only) == 403
    assert await apply(blk_tpl, block_body, tpl_only) == 403
    for tpl in (sub_tpl, blk_tpl):
        r = await client.post(f"/api/v1/ipam/templates/{tpl.id}/reapply-all", headers=tpl_only)
        assert r.status_code == 403, r.text
    # Nothing was stamped.
    await db_session.refresh(await db_session.get(Subnet, t["subnet"]))
    assert (await db_session.get(Subnet, t["subnet"])).ddns_ttl != 321

    # With write on subnets the subnet template applies; the block one still
    # needs write on the block.
    assert await apply(sub_tpl, subnet_body, tpl_and_subnet) == 200
    assert await apply(blk_tpl, block_body, tpl_and_subnet) == 403

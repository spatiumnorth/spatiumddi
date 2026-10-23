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
the server is not the token's resource; they narrow their rows instead.

The later tests extend the same walk to ids named in the query string, to
routes keyed on a block or space (refused unless the container holds one of
the token's subnets), and to every IPAM read keyed on nothing narrower than a
block or space, which must say nothing about a subnet outside the grant.
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

    found = []
    for path in routes:
        params = set(_PARAM.findall(path))
        tok = zone_tok if "zone_id" in params else subnet_tok
        r = await client.get(_fill(path, ids), headers={"Authorization": f"Bearer {tok}"})
        if r.status_code != 403:
            found.append(f"{path} -> {r.status_code}")
    assert not found, "token bound to another instance was not refused:\n" + "\n".join(found)


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


# ── Query-keyed, block- and space-keyed routes, and the reports ─────────────
#
# The guard above reads path parameters. A subnet or zone named in the QUERY
# (``?subnet_id=`` on a report) filters just as a path id selects, and a block
# or space is not a grantable resource, so a route keyed on one used to answer
# a subnet-bound token about every subnet inside it. These tests walk the
# route table rather than a list, so a route added later is covered without
# an edit here.

_CONTAINER_KEYS = {"block_id", "space_id"}
_QUERY_KEYS = _KEYED | _CONTAINER_KEYS


def _scope_routes(app) -> list[tuple[str, str, dict]]:
    out = []
    for path, ops in app.openapi()["paths"].items():
        if not (path.startswith("/api/v1/ipam") or path.startswith("/api/v1/dns")):
            continue
        if path.startswith("/api/v1/dns/agents"):
            continue
        for method, op in ops.items():
            out.append((path, method, op))
    return sorted(out, key=lambda r: (r[0], r[1]))


def _query_names(op: dict) -> set[str]:
    return {p["name"] for p in op.get("parameters", []) if p.get("in") == "query"}


async def _container_fixtures(db: AsyncSession) -> dict:
    """Space ``inside`` holds block ``inside`` with a granted subnet A and an
    ungranted subnet B (adjacent /24s, so the pair is aggregable); space
    ``outside`` holds block ``outside`` with subnet C only. Subnet B carries
    every kind of row the reports and the drift preview list, under markers
    a response would have to contain to be describing it."""
    from datetime import UTC, datetime, timedelta

    from app.models.oui import OUIVendor
    from app.models.settings import PlatformSettings

    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"cg-{tag}", description="")
    db.add(group)
    await db.flush()
    zone = DNSZone(group_id=group.id, name=f"z-{tag}.test", kind="forward")
    db.add(zone)
    await db.flush()

    space = IPSpace(name=f"in-{tag}", description="")
    other_space = IPSpace(name=f"out-{tag}", description="")
    db.add_all([space, other_space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name=f"in-{tag}")
    other_block = IPBlock(space_id=other_space.id, network="10.78.0.0/16", name=f"out-{tag}")
    db.add_all([block, other_block])
    await db.flush()
    sub_a = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="a")
    sub_b = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.77.0.0/24",
        name=f"farsubnet-{tag}",
        dns_inherit_settings=False,
        dns_group_ids=[str(group.id)],
        dns_zone_id=str(zone.id),
    )
    sub_c = Subnet(space_id=other_space.id, block_id=other_block.id, network="10.78.1.0/24")
    db.add_all([sub_a, sub_b, sub_c])
    await db.flush()

    now = datetime.now(UTC)
    mac_prefix = "aabbcc"
    addr_a = IPAddress(subnet_id=sub_a.id, address="10.77.1.5", hostname=f"own-{tag}")
    stale_b = IPAddress(
        subnet_id=sub_b.id,
        address="10.77.0.5",
        hostname=f"farhost-{tag}",
        status="allocated",
        mac_address="aa:bb:cc:00:00:05",
        last_seen_at=now - timedelta(days=200),
    )
    responding_b = IPAddress(
        subnet_id=sub_b.id, address="10.77.0.9", status="available", last_seen_at=now
    )
    db.add_all([addr_a, stale_b, responding_b])

    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.oui_lookup_enabled = True
    if await db.get(OUIVendor, mac_prefix) is None:
        db.add(OUIVendor(prefix=mac_prefix, vendor_name="Farvendor"))
    await db.flush()
    return {
        "group": group,
        "zone": zone,
        "space": space,
        "other_space": other_space,
        "block": block,
        "other_block": other_block,
        "sub_a": sub_a,
        "sub_b": sub_b,
        "sub_c": sub_c,
        "addr_a": addr_a,
        "addr_b": stale_b,
        "markers": [
            str(sub_b.id),
            str(stale_b.id),
            str(responding_b.id),
            "10.77.0.0/24",
            "10.77.0.5",
            "10.77.0.9",
            f"farhost-{tag}",
            "farsubnet-",
        ],
    }


#: Required query parameters some routes take, so the sweep reaches the
#: handler instead of stopping at a 422.
_REQUIRED_QUERY_DEFAULTS = {"prefix_len": "28", "vendor_search": "farvendor"}


@pytest.mark.asyncio
async def test_every_query_keyed_route_refuses_an_id_outside_the_grant(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.main import app

    f = await _container_fixtures(db_session)
    g = await _fixtures(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [
            {"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)},
            {"action": "*", "resource_type": "dns_zone", "resource_id": str(g["zone_a"].id)},
        ],
    )
    await db_session.commit()

    # Path ids inside the grant, so only the query parameter can be refused.
    inside = {
        "subnet_id": str(f["sub_a"].id),
        "address_id": str(f["addr_a"].id),
        "zone_id": str(g["zone_a"].id),
        "group_id": str(g["group"].id),
        "block_id": str(f["block"].id),
        "space_id": str(f["space"].id),
    }
    outside = {
        "subnet_id": str(f["sub_b"].id),
        "address_id": str(f["addr_b"].id),
        "zone_id": str(g["zone_b"].id),
        "block_id": str(f["other_block"].id),
        "space_id": str(f["other_space"].id),
    }
    checked = 0
    found = []
    for path, method, op in _scope_routes(app):
        if method != "get":
            continue
        keyed = _query_names(op) & _QUERY_KEYS
        for name in sorted(keyed):
            params = {k: v for k, v in _REQUIRED_QUERY_DEFAULTS.items() if k in _query_names(op)}
            params[name] = outside[name]
            r = await client.get(
                _fill(path, inside), params=params, headers={"Authorization": f"Bearer {tok}"}
            )
            checked += 1
            if r.status_code != 403:
                found.append(f"GET {path}?{name}= -> {r.status_code}")
    assert checked >= 5, f"route discovery found only {checked} query-keyed routes"
    assert not found, "a query id outside the token's grant was not refused:\n" + "\n".join(found)


@pytest.mark.asyncio
async def test_every_block_or_space_route_refuses_one_holding_none_of_the_tokens_subnets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.main import app

    f = await _container_fixtures(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)}],
    )
    await db_session.commit()

    ids = {"block_id": str(f["other_block"].id), "space_id": str(f["other_space"].id)}
    routes = [
        (path, method)
        for path, method, _ in _scope_routes(app)
        if set(_PARAM.findall(path)) & _CONTAINER_KEYS and not set(_PARAM.findall(path)) & _KEYED
    ]
    assert len(routes) > 20, f"route discovery found only {len(routes)} routes"
    found = []
    for path, method in routes:
        r = await client.request(
            method.upper(),
            _fill(path, ids),
            json={},
            headers={"Authorization": f"Bearer {tok}"},
        )
        if r.status_code != 403:
            found.append(f"{method.upper()} {path} -> {r.status_code}")
    assert not found, "a block or space outside the token's grant was not refused:\n" + "\n".join(
        found
    )


@pytest.mark.asyncio
async def test_block_space_and_report_reads_say_nothing_about_an_ungranted_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every IPAM GET keyed on nothing narrower than a block or space — the
    block's own previews and every report — run for a token bound to subnet
    A in a block that also holds subnet B. Nothing about B may come back.
    A session sees B on the routes that list it, which proves the fixture
    reaches them."""
    from app.main import app

    f = await _container_fixtures(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)}],
    )
    # A separate user: the test client shares one DB session, so the token
    # request's user object (with its grants attached) would otherwise be
    # reused for the session request.
    admin = await _owner(db_session)
    await db_session.commit()
    session = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}

    ids = {"block_id": str(f["block"].id), "space_id": str(f["space"].id)}
    routes = []
    for path, method, op in _scope_routes(app):
        if method != "get" or not path.startswith("/api/v1/ipam"):
            continue
        if not set(_PARAM.findall(path)) <= _CONTAINER_KEYS:
            continue
        routes.append((path, op))

    found = []
    seen_by_session = set()
    for path, op in routes:
        params = {k: v for k, v in _REQUIRED_QUERY_DEFAULTS.items() if k in _query_names(op)}
        url = _fill(path, ids)
        r = await client.get(url, params=params, headers={"Authorization": f"Bearer {tok}"})
        hit = [m for m in f["markers"] if m in r.text]
        if r.status_code < 400 and hit:
            found.append(f"GET {path} -> {r.status_code} {hit}")
        rs = await client.get(url, params=params, headers=session)
        if any(m in rs.text for m in f["markers"]):
            seen_by_session.add(path)
    assert not found, "a subnet-bound token read an ungranted subnet's data:\n" + "\n".join(found)

    # The routes this change narrows must actually have been exercised.
    for must in (
        "/api/v1/ipam/blocks/{block_id}/dns-sync/preview",
        "/api/v1/ipam/spaces/{space_id}/dns-sync/preview",
        "/api/v1/ipam/blocks/{block_id}/aggregation-suggestions",
        "/api/v1/ipam/reports/stale-ips",
        "/api/v1/ipam/reports/hygiene",
        "/api/v1/ipam/reports/vendors/devices",
    ):
        assert must in seen_by_session, f"fixture did not reach {must}"


@pytest.mark.asyncio
async def test_vendor_rollup_counts_only_the_tokens_subnets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f = await _container_fixtures(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)}],
    )
    await db_session.commit()
    r = await client.get("/api/v1/ipam/reports/vendors", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    assert r.json()["total_macs_seen"] == 0


@pytest.mark.asyncio
async def test_free_space_queries_refuse_a_subnet_bound_token_inside_its_own_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Free space is a fact about every subnet in the block and cannot be
    narrowed, so it is refused even where the block holds the token's
    subnet. A session is unaffected."""
    f = await _container_fixtures(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)}],
    )
    admin = await _owner(db_session)  # see the note in the test above
    await db_session.commit()
    b, s = f["block"].id, f["space"].id
    calls = [
        ("GET", f"/api/v1/ipam/blocks/{b}/free-space", None, None),
        ("GET", f"/api/v1/ipam/blocks/{b}/available-subnets", {"prefix_len": "28"}, None),
        (
            "POST",
            f"/api/v1/ipam/blocks/{b}/plan-allocation",
            None,
            {"items": [{"count": 1, "prefix_len": 28}]},
        ),
        ("POST", f"/api/v1/ipam/spaces/{s}/find-free", None, {"prefix_length": 28}),
        ("POST", f"/api/v1/ipam/blocks/{b}/resize/preview", None, {"new_cidr": "10.76.0.0/15"}),
    ]
    session = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    for method, url, params, body in calls:
        r = await client.request(
            method, url, params=params, json=body, headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 403, f"{method} {url} -> {r.status_code} {r.text}"
        rs = await client.request(method, url, params=params, json=body, headers=session)
        assert rs.status_code == 200, f"session {method} {url} -> {rs.status_code} {rs.text}"


@pytest.mark.asyncio
async def test_a_subnet_bound_token_still_reaches_its_own_block_space_and_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The other side of the refusals above: a block or space holding the
    token's subnet is admitted, and so is every block above it (the subnet
    sits in a nested block here, so the parent chain is walked), and the
    token's own subnet named in the query string is not refused."""
    tag = uuid.uuid4().hex[:6]
    space = IPSpace(name=f"own-{tag}", description="")
    db_session.add(space)
    await db_session.flush()
    top = IPBlock(space_id=space.id, network="10.91.0.0/16", name=f"top-{tag}")
    db_session.add(top)
    await db_session.flush()
    mid = IPBlock(
        space_id=space.id, parent_block_id=top.id, network="10.91.0.0/20", name=f"mid-{tag}"
    )
    db_session.add(mid)
    await db_session.flush()
    leaf = IPBlock(
        space_id=space.id, parent_block_id=mid.id, network="10.91.1.0/24", name=f"leaf-{tag}"
    )
    db_session.add(leaf)
    await db_session.flush()
    sub = Subnet(space_id=space.id, block_id=leaf.id, network="10.91.1.0/25", name="own")
    db_session.add(sub)
    await db_session.flush()
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "subnet", "resource_id": str(sub.id)}],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {tok}"}

    calls = [
        (f"/api/v1/ipam/spaces/{space.id}/dns-sync/preview", None),
        (f"/api/v1/ipam/spaces/{space.id}/effective-dns", None),
        ("/api/v1/ipam/blocks", {"space_id": str(space.id)}),
        ("/api/v1/ipam/subnets", {"space_id": str(space.id)}),
        ("/api/v1/ipam/reports/stale-ips", {"subnet_id": str(sub.id)}),
        ("/api/v1/ipam/addresses/search", {"subnet_id": str(sub.id), "q": "10.91"}),
    ]
    for b in (top, mid, leaf):
        calls += [
            # (``GET /blocks/{id}`` itself checks an ``ip_block`` grant, which
            # no token can hold today, so it is not in this list.)
            (f"/api/v1/ipam/blocks/{b.id}/dns-sync/preview", None),
            (f"/api/v1/ipam/blocks/{b.id}/aggregation-suggestions", None),
            (f"/api/v1/ipam/blocks/{b.id}/effective-dns", None),
            ("/api/v1/ipam/subnets", {"block_id": str(b.id)}),
            ("/api/v1/ipam/reports/stale-ips", {"block_id": str(b.id)}),
        ]
    for url, params in calls:
        r = await client.get(url, params=params, headers=hdr)
        assert r.status_code == 200, f"GET {url} {params} -> {r.status_code} {r.text}"


@pytest.mark.asyncio
async def test_stale_ip_deprecate_skips_rows_outside_the_tokens_subnets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f = await _container_fixtures(db_session)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)}],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {tok}"}
    r = await client.post(
        "/api/v1/ipam/reports/stale-ips/deprecate",
        json={"ip_ids": [str(f["addr_b"].id)]},
        headers=hdr,
    )
    assert r.status_code == 200, r.text
    assert r.json()["deprecated_count"] == 0
    r = await client.post(
        "/api/v1/ipam/reports/stale-ips/deprecate", json={"all_matching": True}, headers=hdr
    )
    assert r.status_code == 422, r.text  # nothing in the token's subnets is stale
    await db_session.refresh(f["addr_b"])
    assert f["addr_b"].status == "allocated"


@pytest.mark.asyncio
async def test_delegation_needs_a_grant_on_the_parent_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"dg-{tag}", description="")
    db_session.add(group)
    await db_session.flush()
    parent = DNSZone(group_id=group.id, name=f"p-{tag}.test.", kind="forward")
    child = DNSZone(group_id=group.id, name=f"c.p-{tag}.test.", kind="forward")
    db_session.add_all([parent, child])
    await db_session.flush()
    owner = await _owner(db_session)
    child_only = await _token(
        db_session,
        owner,
        [{"action": "*", "resource_type": "dns_zone", "resource_id": str(child.id)}],
    )
    both = await _token(
        db_session,
        owner,
        [
            {"action": "*", "resource_type": "dns_zone", "resource_id": str(child.id)},
            {"action": "*", "resource_type": "dns_zone", "resource_id": str(parent.id)},
        ],
    )
    await db_session.commit()
    base = f"/api/v1/dns/groups/{group.id}/zones/{child.id}"
    r = await client.get(
        f"{base}/delegation-preview", headers={"Authorization": f"Bearer {child_only}"}
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        f"{base}/delegate-from-parent", headers={"Authorization": f"Bearer {child_only}"}
    )
    assert r.status_code == 403, r.text
    r = await client.get(f"{base}/delegation-preview", headers={"Authorization": f"Bearer {both}"})
    assert r.status_code == 200, r.text
    assert r.json()["has_parent"] is True


@pytest.mark.asyncio
async def test_pending_ops_tell_same_named_zones_in_two_views_apart(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.dns import DNSView
    from app.services.dns.record_ops import enqueue_record_op

    tag = uuid.uuid4().hex[:6]
    group = DNSServerGroup(name=f"vg-{tag}", description="")
    db_session.add(group)
    await db_session.flush()
    inner = DNSView(group_id=group.id, name="internal")
    outer = DNSView(group_id=group.id, name="external")
    db_session.add_all([inner, outer])
    await db_session.flush()
    name = f"same-{tag}.test."
    zone_in = DNSZone(group_id=group.id, view_id=inner.id, name=name, kind="forward")
    zone_out = DNSZone(group_id=group.id, view_id=outer.id, name=name, kind="forward")
    server = DNSServer(
        group_id=group.id,
        name=f"s-{tag}",
        driver="bind9",
        host="192.0.2.1",
        is_primary=True,
        is_enabled=True,
    )
    db_session.add_all([zone_in, zone_out, server])
    await db_session.flush()
    await enqueue_record_op(
        db_session, zone_in, "create", {"name": "in", "type": "A", "value": "10.0.0.1", "ttl": 60}
    )
    await enqueue_record_op(
        db_session,
        zone_out,
        "create",
        {"name": "out", "type": "A", "value": "10.0.0.2", "ttl": 60},
    )
    owner = await _owner(db_session)
    raw = await _token(
        db_session,
        owner,
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(zone_in.id)}],
    )
    await db_session.commit()
    r = await client.get(
        f"/api/v1/dns/servers/{server.id}/pending-ops", headers={"Authorization": f"Bearer {raw}"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert [i["record"]["name"] for i in body["items"]] == ["in"]
    assert sum(body["counts"].values()) == 1


@pytest.mark.asyncio
async def test_block_and_space_writes_refuse_a_zone_the_token_holds_no_grant_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A block's or space's zone binding is inherited by every subnet under
    it. ``ip_block`` / ``ip_space`` are not grantable today, so the grants
    here are written straight to the row: the check must already hold for
    the day they are."""
    g = await _fixtures(db_session)
    space = IPSpace(name=f"zs-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.88.0.0/16", name="zb")
    db_session.add(block)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [
            {"action": "*", "resource_type": "ip_block", "resource_id": "*"},
            {"action": "*", "resource_type": "ip_space", "resource_id": "*"},
            {"action": "*", "resource_type": "dns_zone", "resource_id": str(g["zone_a"].id)},
        ],
    )
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {tok}"}
    foreign = str(g["zone_b"].id)

    r = await client.post(
        "/api/v1/ipam/blocks",
        json={"space_id": str(space.id), "network": "10.89.0.0/16", "dns_zone_id": foreign},
        headers=hdr,
    )
    assert r.status_code == 403, r.text
    r = await client.put(
        f"/api/v1/ipam/blocks/{block.id}", json={"dns_zone_id": foreign}, headers=hdr
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        "/api/v1/ipam/spaces",
        json={"name": f"zs2-{uuid.uuid4().hex[:6]}", "dns_additional_zone_ids": [foreign]},
        headers=hdr,
    )
    assert r.status_code == 403, r.text
    r = await client.put(
        f"/api/v1/ipam/spaces/{space.id}", json={"dns_zone_id": foreign}, headers=hdr
    )
    assert r.status_code == 403, r.text

    # The granted zone is accepted.
    r = await client.put(
        f"/api/v1/ipam/blocks/{block.id}", json={"dns_zone_id": str(g["zone_a"].id)}, headers=hdr
    )
    assert r.status_code == 200, r.text


# ── Routes outside the IPAM and DNS routers ─────────────────────────────────
#
# A report or metrics series mounted elsewhere passed its coarse gate on the
# resource TYPE a token is bound to and then answered for every subnet, zone
# or server. Outside the IPAM and DNS routers a bound token is now refused,
# except on the few routes that narrow to its grants themselves.

#: Routes outside the IPAM and DNS routers that still serve a bound token,
#: because they narrow their answer to its grants or say nothing about the
#: estate.
_SERVES_A_BOUND_TOKEN = {
    "/api/v1/auth/me",
    "/api/v1/auth/me/permissions",
    "/api/v1/search",
    "/api/v1/search/types",
    "/api/v1/ai/mcp",
}

#: Responses that stream until the client goes away.
_STREAMS = ("/stream",)


async def _bound_token_fixtures(db: AsyncSession) -> tuple[dict, dict, str]:
    """Subnet B (in A's block) at 99 % so every ranking lists it first, zone B
    beside zone A, and a token bound to subnet A and zone A only."""
    f = await _container_fixtures(db)
    g = await _fixtures(db)
    f["sub_b"].utilization_percent = 99.0
    f["sub_b"].allocated_ips = 250
    f["sub_b"].total_ips = 254
    owner = await _owner(db)
    tok = await _token(
        db,
        owner,
        [
            {"action": "*", "resource_type": "subnet", "resource_id": str(f["sub_a"].id)},
            {"action": "*", "resource_type": "dns_zone", "resource_id": str(g["zone_a"].id)},
        ],
    )
    return f, g, tok


@pytest.mark.asyncio
async def test_a_bound_token_is_refused_by_every_route_outside_the_scoped_routers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every authenticated GET outside ``/api/v1/ipam`` and ``/api/v1/dns``
    refuses a bound token, other than the routes that narrow to its
    grants. None of them, refused or not, returns anything about subnet B or
    zone B."""
    from app.main import app

    f, g, tok = await _bound_token_fixtures(db_session)
    await db_session.commit()
    markers = [*f["markers"], g["zone_b"].name, str(g["zone_b"].id)]
    ids = {
        "subnet_id": str(f["sub_a"].id),
        "address_id": str(f["addr_a"].id),
        "zone_id": str(g["zone_a"].id),
        "group_id": str(g["group"].id),
        "block_id": str(f["block"].id),
        "space_id": str(f["space"].id),
    }
    hdr = {"Authorization": f"Bearer {tok}"}

    checked = 0
    served = []
    leaked = []
    for path, ops in sorted(app.openapi()["paths"].items()):
        if "get" not in ops or path.startswith(("/api/v1/ipam", "/api/v1/dns")):
            continue
        if path.endswith(_STREAMS):
            continue
        url = _fill(path, ids)
        params = {
            k: v for k, v in _REQUIRED_QUERY_DEFAULTS.items() if k in _query_names(ops["get"])
        }
        if (await client.get(url, params=params)).status_code != 401:
            continue  # not an authenticated route (or gated before auth)
        r = await client.get(url, params=params, headers=hdr)
        checked += 1
        if r.status_code < 400 and any(m in r.text for m in markers):
            leaked.append(f"GET {path} -> {r.status_code}")
        # 401: an agent surface, which takes no user credential at all.
        if path not in _SERVES_A_BOUND_TOKEN and r.status_code not in (401, 403):
            served.append(f"GET {path} -> {r.status_code}")
    assert checked > 100, f"route discovery found only {checked} authenticated routes"
    assert not leaked, "a bound token read ungranted data:\n" + "\n".join(leaked)
    assert not served, "a bound token was served outside the scoped routers:\n" + "\n".join(served)


@pytest.mark.asyncio
async def test_top_subnets_report_refuses_a_subnet_bound_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f, _g, tok = await _bound_token_fixtures(db_session)
    await db_session.commit()
    r = await client.get(
        "/api/v1/reports/top-subnets-by-utilization", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 403, r.text
    assert "10.77.0.0/24" not in r.text


@pytest.mark.asyncio
async def test_top_subnets_report_unchanged_for_a_session_and_an_unbound_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f, _g, _tok = await _bound_token_fixtures(db_session)
    admin = await _owner(db_session)
    other = await _owner(db_session)
    plain = await _token(db_session, other, [])
    await db_session.commit()
    for hdr in (
        {"Authorization": f"Bearer {create_access_token(str(admin.id))}"},
        {"Authorization": f"Bearer {plain}"},
    ):
        r = await client.get("/api/v1/reports/top-subnets-by-utilization", headers=hdr)
        assert r.status_code == 200, r.text
        assert str(f["sub_b"].id) in {row["id"] for row in r.json()["rows"]}


@pytest.mark.asyncio
async def test_dns_timeseries_refuses_a_zone_bound_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    g = await _fixtures(db_session)
    server = DNSServer(
        group_id=g["group"].id, name=f"s-{uuid.uuid4().hex[:6]}", driver="bind9", host="192.0.2.1"
    )
    db_session.add(server)
    owner = await _owner(db_session)
    tok = await _token(
        db_session,
        owner,
        [{"action": "read", "resource_type": "dns_zone", "resource_id": str(g["zone_a"].id)}],
    )
    admin = await _owner(db_session)
    await db_session.commit()
    for params in ({}, {"server_id": str(server.id)}):
        r = await client.get(
            "/api/v1/metrics/dns/timeseries",
            params=params,
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 403, r.text
    session = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    r = await client.get("/api/v1/metrics/dns/timeseries", headers=session)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_routes_that_narrow_to_the_grant_still_serve_a_bound_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    f, _g, tok = await _bound_token_fixtures(db_session)
    await db_session.commit()
    hdr = {"Authorization": f"Bearer {tok}"}

    assert (await client.get("/api/v1/auth/me/permissions", headers=hdr)).status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=hdr)).status_code == 200
    assert (await client.get("/api/v1/ai/mcp", headers=hdr)).status_code == 200
    found = await client.get("/api/v1/search", params={"q": "10.77"}, headers=hdr)
    assert found.status_code == 200, found.text
    assert "10.77.0.0/24" not in found.text
    # Inside the scoped routers the token keeps working on its own subnet.
    own = await client.get(f"/api/v1/ipam/subnets/{f['sub_a'].id}", headers=hdr)
    assert own.status_code == 200, own.text


@pytest.mark.asyncio
async def test_prometheus_metrics_refuse_a_bound_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _f, _g, tok = await _bound_token_fixtures(db_session)
    other = await _owner(db_session)
    plain = await _token(db_session, other, [])
    await db_session.commit()
    r = await client.get("/metrics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401, r.text
    r = await client.get("/metrics", headers={"Authorization": f"Bearer {plain}"})
    assert r.status_code == 200, r.text

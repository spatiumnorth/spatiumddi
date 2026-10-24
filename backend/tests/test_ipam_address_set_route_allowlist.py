"""An address-set delegate reaches an allow-list of IPAM routes, nothing else.

The IPAM router's coarse gate admits a caller holding only a grant scoped to
one address set (the Address Set Editor role, #103) so that it can reach the
per-address check (``_user_can_write_ip``) the address routes apply. The gate
cannot see which set the grant names, so the allow-list of routes it admits
such a caller on is the whole boundary of that admit: every listed route must
check each address it touches against the caller's set ranges, and every other
mutating IPAM route must refuse the caller at the gate.

The two structural tests below enumerate the router's mutating routes, so a
route added later fails here until it is either refused or listed with its own
per-address check.
"""

from __future__ import annotations

import inspect
import io
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.ipam import io_router as ipam_io_router
from app.api.v1.ipam import router as ipam_router
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.address_set import AddressSet
from app.models.auth import Group, Role, User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

_MUTATING = ("POST", "PUT", "PATCH", "DELETE")

# The names through which an allow-listed handler reaches the per-address
# check. Each helper is itself checked to call ``user_can_write_ip``.
_PER_ROW_CHECKS = ("_user_can_write_ip", "user_can_write_ip")
_PER_ROW_HELPERS = {
    "_require_ip_writable": ipam_router._require_ip_writable,
    "_address_import_write_gate": ipam_io_router._address_import_write_gate,
}


# ── route table ────────────────────────────────────────────────────────────


def _iter_routes(routes: Any) -> Iterator[Any]:
    for r in routes:
        if hasattr(r, "effective_candidates"):
            yield from _iter_routes(r.effective_candidates())
        elif getattr(r, "dependant", None) is not None and hasattr(r, "methods"):
            yield r


def _dependency_calls(dependant: Any) -> Iterator[Any]:
    for d in dependant.dependencies:
        yield d.call
        yield from _dependency_calls(d)


def _gated_mutating_routes() -> list[tuple[str, str, Any]]:
    """``(key, full_path, endpoint)`` for every mutating route behind the IPAM
    router's coarse gate, keyed the way the gate keys its allow-list."""
    out: list[tuple[str, str, Any]] = []
    for r in _iter_routes(app.routes):
        if not any(c is ipam_router._IPAM_GATE for c in _dependency_calls(r.dependant)):
            continue
        for method in sorted(r.methods):
            if method not in _MUTATING:
                continue
            key = f"{method} {r.path.split('/ipam', 1)[-1]}"
            out.append((key, r.path, r.endpoint))
    return out


def test_the_route_table_is_found() -> None:
    # Guard the guard: an empty table would pass every test below.
    keys = {k for k, _p, _e in _gated_mutating_routes()}
    assert len(keys) > 40
    assert "PUT /addresses/{address_id}" in keys
    assert "POST /import/addresses/commit" in keys


def test_allowlist_names_only_real_gated_routes() -> None:
    keys = {k for k, _p, _e in _gated_mutating_routes()}
    stale = sorted(ipam_router._ADDRESS_SET_ROUTES - keys)
    assert not stale, f"allow-listed routes that do not exist behind the gate: {stale}"


def test_allowlisted_routes_check_every_address_against_the_set() -> None:
    """Every route an address-set delegate may reach applies the per-address
    set check itself, directly or through a helper that does."""
    for name, helper in _PER_ROW_HELPERS.items():
        src = inspect.getsource(helper)
        assert "user_can_write_ip(" in src, f"{name} no longer applies the per-address check"
    missing = []
    for key, _path, endpoint in _gated_mutating_routes():
        if key not in ipam_router._ADDRESS_SET_ROUTES:
            continue
        src = inspect.getsource(endpoint)
        names = (*_PER_ROW_CHECKS, *_PER_ROW_HELPERS)
        if not any(f"{n}(" in src for n in names):
            missing.append(key)
    assert not missing, f"allow-listed routes without the per-address set check: {missing}"


# ── fixtures ───────────────────────────────────────────────────────────────


async def _user(db: AsyncSession, permissions: list[dict], *, superadmin: bool = False) -> str:
    user = User(
        username=f"as-{uuid.uuid4().hex[:8]}",
        email=f"as-{uuid.uuid4().hex[:8]}@t.io",
        display_name="as",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    else:
        user.groups = []
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _world(db: AsyncSession) -> dict[str, Any]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.9.9.9",
            name=f"ns-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"d{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add_all([zone, space])
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.5.0/24",
        name="s",
        dns_group_ids=[str(grp.id)],
        dns_zone_id=str(zone.id),
        dns_inherit_settings=False,
    )
    sibling = Subnet(space_id=space.id, block_id=block.id, network="10.0.4.0/24", name="s2")
    db.add_all([subnet, sibling])
    await db.flush()
    aset = AddressSet(
        name="mine",
        subnet_id=subnet.id,
        range_kind="contiguous",
        start_address="10.0.5.50",
        end_address="10.0.5.99",
    )
    inside = IPAddress(
        subnet_id=subnet.id, address="10.0.5.60", hostname="inside", status="allocated"
    )
    outside = IPAddress(
        subnet_id=subnet.id,
        address="10.0.5.10",
        hostname="outside",
        mac_address="aa:bb:cc:00:00:10",
        status="allocated",
    )
    foreign = IPAddress(
        subnet_id=sibling.id, address="10.0.4.10", hostname="foreign", status="allocated"
    )
    db.add_all([aset, inside, outside, foreign])
    await db.flush()
    return {
        "zone": zone,
        "space": space,
        "block": block,
        "subnet": subnet,
        "sibling": sibling,
        "set": aset,
        "inside": inside,
        "outside": outside,
        "foreign": foreign,
    }


async def _delegate(db: AsyncSession, w: dict[str, Any]) -> str:
    return await _user(
        db,
        [{"action": "admin", "resource_type": "address_set", "resource_id": str(w["set"].id)}],
    )


def _concrete(path: str) -> str:
    return "/".join(
        str(uuid.uuid4()) if part.startswith("{") and part.endswith("}") else part
        for part in path.split("/")
    )


# ── every other mutating route refuses the delegate at the gate ───────────


@pytest.mark.asyncio
async def test_delegate_is_refused_at_the_gate_on_every_unlisted_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _delegate(db_session, w)
    await db_session.commit()

    admitted = []
    for key, path, _endpoint in _gated_mutating_routes():
        if key in ipam_router._ADDRESS_SET_ROUTES:
            continue
        method = key.split(" ", 1)[0]
        r = await client.request(method, _concrete(path), headers=_h(token), json={})
        detail = r.json().get("detail") if r.status_code == 403 else None
        # The coarse gate's own refusal names the types it accepts; a 403 from
        # inside a handler means the gate let the delegate through.
        if not (isinstance(detail, str) and "on one of" in detail):
            admitted.append((key, r.status_code))
    assert not admitted, f"routes that admit an address-set delegate: {admitted}"


@pytest.mark.asyncio
async def test_no_grant_is_refused_everywhere(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _world(db_session)
    token = await _user(db_session, [])
    await db_session.commit()
    for key, path, _endpoint in _gated_mutating_routes():
        method = key.split(" ", 1)[0]
        r = await client.request(method, _concrete(path), headers=_h(token), json={})
        assert r.status_code == 403, (key, r.status_code, r.text)


# ── behaviour on the routes the report named ──────────────────────────────


@pytest.mark.asyncio
async def test_delegate_aliases_only_on_addresses_inside_its_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _delegate(db_session, w)
    admin = await _user(db_session, [], superadmin=True)
    await db_session.commit()

    # Outside the set, in the delegate's own subnet: refused, nothing written.
    r = await client.post(
        f"/api/v1/ipam/addresses/{w['outside'].id}/aliases",
        headers=_h(token),
        json={"name": "web-out", "record_type": "CNAME"},
    )
    assert r.status_code == 403, r.text
    # In another subnet entirely: refused.
    r = await client.post(
        f"/api/v1/ipam/addresses/{w['foreign'].id}/aliases",
        headers=_h(token),
        json={"name": "web-far", "record_type": "CNAME"},
    )
    assert r.status_code == 403, r.text
    names = (
        (await db_session.execute(select(DNSRecord.name).where(DNSRecord.zone_id == w["zone"].id)))
        .scalars()
        .all()
    )
    assert "web-out" not in names
    assert "web-far" not in names

    # An alias someone else put on an address outside the set cannot be removed.
    r = await client.post(
        f"/api/v1/ipam/addresses/{w['outside'].id}/aliases",
        headers=_h(admin),
        json={"name": "keep", "record_type": "CNAME"},
    )
    assert r.status_code == 201, r.text
    keep_id = r.json()["id"]
    r = await client.delete(
        f"/api/v1/ipam/addresses/{w['outside'].id}/aliases/{keep_id}", headers=_h(token)
    )
    assert r.status_code == 403, r.text
    rec = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.id == uuid.UUID(keep_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    assert rec is not None and getattr(rec, "deleted_at", None) is None

    # Inside the set: add and remove both work.
    r = await client.post(
        f"/api/v1/ipam/addresses/{w['inside'].id}/aliases",
        headers=_h(token),
        json={"name": "web-in", "record_type": "CNAME"},
    )
    assert r.status_code == 201, r.text
    r = await client.delete(
        f"/api/v1/ipam/addresses/{w['inside'].id}/aliases/{r.json()['id']}", headers=_h(token)
    )
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_delegate_is_refused_on_profile_and_planning_previews(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _delegate(db_session, w)
    await db_session.commit()
    for method, path, body in (
        ("POST", f"/addresses/{w['inside'].id}/profile", {}),
        ("POST", f"/blocks/{w['block'].id}/plan-allocation", {"prefix_lengths": [26]}),
        ("POST", f"/spaces/{w['space'].id}/find-free", {"prefix_length": 26}),
        ("POST", "/import/preview-json", {"space_id": str(w["space"].id), "subnets": []}),
    ):
        r = await client.request(method, f"/api/v1/ipam{path}", headers=_h(token), json=body)
        assert r.status_code == 403, (path, r.status_code, r.text)


@pytest.mark.asyncio
async def test_bulk_allocate_preview_needs_a_set_on_the_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _delegate(db_session, w)
    await db_session.commit()
    body = {
        "range_start": "10.0.4.40",
        "range_end": "10.0.4.45",
        "hostname_template": "h{n}",
    }
    r = await client.post(
        f"/api/v1/ipam/subnets/{w['sibling'].id}/bulk-allocate/preview",
        headers=_h(token),
        json=body,
    )
    assert r.status_code == 403, r.text

    # Own subnet: 10.0.5.45-49 are outside the set, 10.0.5.50-54 inside.
    body.update(range_start="10.0.5.45", range_end="10.0.5.54")
    r = await client.post(
        f"/api/v1/ipam/subnets/{w['subnet'].id}/bulk-allocate/preview",
        headers=_h(token),
        json=body,
    )
    assert r.status_code == 200, r.text
    assert r.json()["conflicts_no_perm"] == 5
    assert r.json()["will_create"] == 5


def _csv(*rows: str) -> dict[str, tuple[str, io.BytesIO, str]]:
    data = ("address,hostname\n" + "\n".join(rows) + "\n").encode()
    return {"file": ("a.csv", io.BytesIO(data), "text/csv")}


@pytest.mark.asyncio
async def test_address_import_preview_matches_the_commit_gate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _delegate(db_session, w)
    await db_session.commit()

    # A subnet the delegate holds no set on: refused before the file is read.
    r = await client.post(
        "/api/v1/ipam/import/addresses/preview",
        headers=_h(token),
        files=_csv("10.0.4.10,x"),
        data={"subnet_id": str(w["sibling"].id), "strategy": "overwrite"},
    )
    assert r.status_code == 403, r.text

    # Its own subnet: a row outside the set is an error and the existing row
    # there is not shown; a row inside the set previews normally.
    r = await client.post(
        "/api/v1/ipam/import/addresses/preview",
        headers=_h(token),
        files=_csv("10.0.5.10,renamed", "10.0.5.60,renamed-in"),
        data={"subnet_id": str(w["subnet"].id), "strategy": "overwrite"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "outside" not in r.text
    assert "aa:bb:cc:00:00:10" not in r.text
    assert [row["network"] for row in body["errors"]] == ["10.0.5.10"]
    assert [row["network"] for row in body["updates"]] == ["10.0.5.60"]


@pytest.mark.asyncio
async def test_delegate_still_edits_addresses_inside_its_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _delegate(db_session, w)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/ipam/addresses/{w['inside'].id}",
        headers=_h(token),
        json={"description": "mine"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["description"] == "mine"
    r = await client.put(
        f"/api/v1/ipam/addresses/{w['outside'].id}",
        headers=_h(token),
        json={"description": "not mine"},
    )
    assert r.status_code == 403, r.text
    r = await client.post(
        f"/api/v1/ipam/subnets/{w['subnet'].id}/addresses",
        headers=_h(token),
        json={"address": "10.0.5.70", "hostname": "new-in"},
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        "/api/v1/ipam/addresses/bulk-edit",
        headers=_h(token),
        json={"ip_ids": [str(w["inside"].id)], "changes": {"description": "bulk"}},
    )
    assert r.status_code == 200, r.text
    r = await client.delete(f"/api/v1/ipam/addresses/{w['inside'].id}", headers=_h(token))
    assert r.status_code == 204, r.text

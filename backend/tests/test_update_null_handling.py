"""Explicit-null semantics on update endpoints (#1563, #1564).

Two symmetric defects, one contract (``app.core.update_nulls``):

* #1564 — handlers that applied ``exclude_unset=True`` + blanket
  setattr let an explicit null reach a NOT NULL column and answered
  an unhandled 500. Null for a non-nullable field must be a 422.
* #1563 — handlers that built changes with ``exclude_none=True``
  dropped an explicit null for a *nullable* field, so the UI's
  "clear" returned 200 and kept the old value. Null for a clearable
  field must actually set the column to NULL.

The endpoint tests below cover a representative slice of the migrated
handlers (domain + VLAN router for #1564, DNS zone / view + DHCP pool
for #1563), each with the repo-standard success / unauthorized /
validation-error cases; the helper tests pin the contract itself for
every other migrated handler.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.core.update_nulls import resolve_update_changes
from app.models.auth import User
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServerGroup
from app.models.dns import DNSServerGroup, DNSView, DNSZone
from app.models.domain import Domain
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.vlans import Router

# ── The shared helper ────────────────────────────────────────────────────


class _Body(BaseModel):
    name: str | None = None
    nickname: str | None = None
    unmanaged: str | None = None


def test_helper_null_clears_clearable_and_rejects_non_nullable() -> None:
    body = _Body(name="x", nickname=None)
    changes = resolve_update_changes(body, clearable={"nickname"}, non_nullable={"name"})
    assert changes == {"name": "x", "nickname": None}

    with pytest.raises(HTTPException) as exc:
        resolve_update_changes(_Body(name=None), clearable={"nickname"}, non_nullable={"name"})
    assert exc.value.status_code == 422
    assert "name" in str(exc.value.detail)


def test_helper_drops_null_for_unlisted_field_and_omitted_fields() -> None:
    # A null for a field in neither set keeps the old exclude_none
    # behaviour (dropped, not cleared) — a partial-body client that
    # serialises unmanaged optionals as null must not wipe them.
    assert resolve_update_changes(_Body(unmanaged=None), clearable={"nickname"}) == {}
    assert resolve_update_changes(_Body(), clearable={"nickname"}) == {}


# ── Endpoint fixtures ────────────────────────────────────────────────────


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# ── #1564: NOT NULL null → 422 ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_domain_update_null_name_is_422_not_500(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    domain = Domain(name="example.com")
    db_session.add(domain)
    await db_session.commit()

    for payload in ({"name": None}, {"expected_nameservers": None}, {"tags": None}):
        r = await client.put(f"/api/v1/domains/{domain.id}", json=payload, headers=headers)
        assert r.status_code == 422, (payload, r.status_code, r.text)

    # A nullable FK still clears.
    r = await client.put(
        f"/api/v1/domains/{domain.id}", json={"customer_id": None}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["customer_id"] is None

    # Unauthorized: no token at all.
    r = await client.put(f"/api/v1/domains/{domain.id}", json={"name": "x.com"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_router_update_null_name_is_422_and_null_vendor_clears(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    router_row = Router(name="r1", vendor="cisco")
    db_session.add(router_row)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/vlans/routers/{router_row.id}", json={"name": None}, headers=headers
    )
    assert r.status_code == 422, r.text

    r = await client.put(
        f"/api/v1/vlans/routers/{router_row.id}", json={"vendor": None}, headers=headers
    )
    assert r.status_code == 200, r.text
    assert r.json()["vendor"] is None


# ── #1563: nullable null actually clears ────────────────────────────────


@pytest.mark.asyncio
async def test_zone_update_null_clears_domain_and_view_links(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    domain = Domain(name="linked.example.com")
    db_session.add_all([grp, domain])
    await db_session.flush()
    view = DNSView(group_id=grp.id, name="internal")
    db_session.add(view)
    await db_session.flush()
    zone = DNSZone(
        group_id=grp.id,
        name="zone.example.com.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.com.",
        admin_email="admin.example.com.",
        domain_id=domain.id,
        view_id=view.id,
        notify_enabled="no",
    )
    db_session.add(zone)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        json={"domain_id": None, "view_id": None, "notify_enabled": None},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["domain_id"] is None
    assert body["view_id"] is None
    assert body["notify_enabled"] is None

    # …and a null for a NOT NULL zone column is a 422, not a 500.
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        json={"name": None},
        headers=headers,
    )
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_view_update_null_allow_query_reverts_to_inherit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    view = DNSView(group_id=grp.id, name="internal", allow_query=["192.0.2.0/24"])
    db_session.add(view)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/views/{view.id}",
        json={"allow_query": None},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["allow_query"] is None

    r = await client.put(f"/api/v1/dns/groups/{grp.id}/views/{view.id}", json={"allow_query": None})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_dhcp_pool_update_null_clears_class_restriction(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin_headers(db_session)
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.62.0.0/24", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.62.0.0/24", name="s")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([subnet, group])
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope-a")
    db_session.add(scope)
    await db_session.flush()
    pool = DHCPPool(
        scope_id=scope.id,
        name="pool-a",
        start_ip="10.62.0.10",
        end_ip="10.62.0.19",
        pool_type="dynamic",
        class_restriction="printers",
        lease_time_override=3600,
    )
    db_session.add(pool)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/pools/{pool.id}",
        json={"class_restriction": None, "lease_time_override": None},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["class_restriction"] is None
    assert body["lease_time_override"] is None

    r = await client.put(f"/api/v1/dhcp/pools/{pool.id}", json={"name": None}, headers=headers)
    assert r.status_code == 422, r.text

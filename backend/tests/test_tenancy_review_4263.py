"""Tenant-boundary holes found in review (#4263).

* a tenant user named any DNS zone on an address and the record was written
  into it, although DNS zones stay install-wide in phase 1;
* a tenant user set ``ddns_domain_override``, which picks the zone DDNS
  publishes leases into by domain name, install-wide;
* a role held by a tenant-bound group could be edited into ``*`` / ``*``,
  making every member an effective superadmin no tenant confines;
* the tenant filter's loader criteria broke the soft-delete hook's rewrite of
  WHERE-only FROMs, so a tenant session counted trashed rows.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import Group, Role
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, Subnet
from app.services.tenancy import set_session_scope
from tests._tenancy_helpers import Side, bearer, make_side, make_user, reset_scope, send


@pytest.fixture
async def two(db_session: AsyncSession) -> tuple[Side, Side]:
    a = await make_side(db_session, "Acme")
    b = await make_side(db_session, "Beta")
    reset_scope(db_session)
    return a, b


async def _shared_zone(db: AsyncSession, name: str = "shared.test.") -> DNSZone:
    grp = DNSServerGroup(name=f"g-{name}", description="")
    db.add(grp)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name=name, kind="forward")
    db.add(zone)
    await db.commit()
    return zone


async def _records_in(db: AsyncSession, zone: DNSZone) -> list[str]:
    reset_scope(db)
    rows = await db.execute(select(DNSRecord.name).where(DNSRecord.zone_id == zone.id))
    return list(rows.scalars())


async def test_tenant_user_cannot_publish_into_an_unassigned_zone(
    client: AsyncClient, db_session, two
):
    a, _ = two
    zone = await _shared_zone(db_session)
    zid = str(zone.id)
    base = f"/api/v1/ipam/subnets/{a.subnet.id}"
    cases = [
        (
            "POST",
            f"{base}/addresses",
            {"address": "10.50.1.20", "hostname": "www", "dns_zone_id": zid},
        ),
        (
            "POST",
            f"{base}/addresses",
            {"address": "10.50.1.21", "hostname": "www2", "extra_zone_ids": [zid]},
        ),
        ("PUT", f"/api/v1/ipam/addresses/{a.address.id}", {"dns_zone_id": zid}),
        ("POST", f"{base}/next", {"hostname": "mail", "dns_zone_id": zid}),
    ]
    for method, path, body in cases:
        r = await send(client, db_session, method, path, a.headers, json=body)
        assert r.status_code == 403, (path, body, r.status_code, r.text)
        assert "tenant" in r.text
    assert await _records_in(db_session, zone) == []


async def test_tenant_user_still_publishes_into_the_subnets_own_zone(
    client: AsyncClient, db_session, two
):
    a, _ = two
    zone = await _shared_zone(db_session, "acme.test.")
    reset_scope(db_session)
    sn = await db_session.get(Subnet, a.subnet.id)
    sn.dns_zone_id = str(zone.id)
    sn.dns_inherit_settings = False
    await db_session.commit()
    r = await send(
        client,
        db_session,
        "POST",
        f"/api/v1/ipam/subnets/{a.subnet.id}/addresses",
        a.headers,
        json={"address": "10.50.1.30", "hostname": "app", "dns_zone_id": str(zone.id)},
    )
    assert r.status_code == 201, r.text
    assert "app" in await _records_in(db_session, zone)


async def test_tenant_user_cannot_set_a_ddns_domain_override(client: AsyncClient, db_session, two):
    a, _ = two
    for path in (
        f"/api/v1/ipam/subnets/{a.subnet.id}",
        f"/api/v1/ipam/blocks/{a.block.id}",
        f"/api/v1/ipam/spaces/{a.space.id}",
    ):
        r = await send(
            client,
            db_session,
            "PUT",
            path,
            a.headers,
            json={"ddns_domain_override": "victim.test", "ddns_inherit_settings": False},
        )
        assert r.status_code == 403, (path, r.status_code, r.text)
    reset_scope(db_session)
    sn = await db_session.get(Subnet, a.subnet.id)
    assert sn.ddns_domain_override is None


async def test_role_of_a_tenant_group_cannot_become_superadmin(
    client: AsyncClient, db_session, two
):
    a, _ = two
    admin = await make_user(db_session, superadmin=True)
    await db_session.commit()
    reset_scope(db_session)
    group = (
        await db_session.execute(select(Group).where(Group.tenant_id == a.tenant.id))
    ).scalar_one()
    role = group.roles[0]
    r = await send(
        client,
        db_session,
        "PUT",
        f"/api/v1/roles/{role.id}",
        bearer(admin),
        json={
            "permissions": [{"action": "*", "resource_type": "*"}],
            "stepup_password": "x" * 12,
        },
    )
    assert r.status_code == 422, r.text
    assert "tenant" in r.text
    reset_scope(db_session)
    fresh = await db_session.get(Role, role.id)
    assert not any(p.get("action") == "*" for p in fresh.permissions)


async def test_tenant_session_never_counts_trashed_rows(db_session, two):
    a, _ = two
    db_session.add(
        Subnet(
            space_id=a.space.id,
            block_id=a.block.id,
            network="10.50.7.0/24",
            name="gone",
            deleted_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    where_only = select(func.count()).where(Subnet.space_id == a.space.id)
    correlated = select(IPBlock.id).where(
        exists().where(Subnet.block_id == IPBlock.id, Subnet.name == "gone")
    )
    for scope in (None, frozenset({a.tenant.id})):
        db_session.expunge_all()
        set_session_scope(db_session.sync_session, scope)
        assert (await db_session.execute(where_only)).scalar_one() == 1, scope
        assert (await db_session.execute(correlated)).all() == [], scope
    reset_scope(db_session)

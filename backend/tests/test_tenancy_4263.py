"""Multi-tenancy phase 1 (#4263): the tenant boundary on IP spaces."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPSpace, Subnet
from app.services.tenancy import set_session_scope
from tests._tenancy_helpers import Side, bearer, get, make_side, make_user, reset_scope, send


@pytest.fixture
async def two(db_session: AsyncSession) -> tuple[Side, Side]:
    a = await make_side(db_session, "Acme")
    b = await make_side(db_session, "Beta")
    reset_scope(db_session)
    return a, b


async def test_lists_show_only_own_tenant(client: AsyncClient, db_session, two):
    a, b = two
    for path, key in (
        ("/api/v1/ipam/spaces", "id"),
        ("/api/v1/ipam/blocks", "id"),
        ("/api/v1/ipam/subnets", "id"),
    ):
        r = await get(client, db_session, path, a.headers)
        assert r.status_code == 200, (path, r.text)
        ids = {row[key] for row in r.json()}
        assert str(a.space.id) in ids or str(a.block.id) in ids or str(a.subnet.id) in ids
        assert str(b.space.id) not in ids and str(b.block.id) not in ids
        assert str(b.subnet.id) not in ids


async def test_global_admin_sees_both(client: AsyncClient, db_session, two):
    a, b = two
    admin = await make_user(db_session, superadmin=True)
    await db_session.commit()
    r = await get(client, db_session, "/api/v1/ipam/spaces", bearer(admin))
    ids = {row["id"] for row in r.json()}
    assert {str(a.space.id), str(b.space.id)} <= ids


async def test_cross_tenant_id_is_404_not_403(client: AsyncClient, db_session, two):
    a, b = two
    for path in (
        f"/api/v1/ipam/spaces/{b.space.id}",
        f"/api/v1/ipam/blocks/{b.block.id}",
        f"/api/v1/ipam/subnets/{b.subnet.id}",
        f"/api/v1/ipam/addresses/{b.address.id}",
        f"/api/v1/ipam/subnets/{b.subnet.id}/addresses",
        f"/api/v1/ipam/blocks/{b.block.id}/free-space",
    ):
        r = await get(client, db_session, path, a.headers)
        assert r.status_code == 404, (path, r.status_code, r.text)
    # a nonexistent id answers the same way, so existence is not revealed
    r = await get(
        client,
        db_session,
        "/api/v1/ipam/subnets/00000000-0000-0000-0000-000000000001",
        a.headers,
    )
    assert r.status_code == 404


async def test_address_search_is_confined(client: AsyncClient, db_session, two):
    a, b = two
    r = await get(client, db_session, "/api/v1/ipam/addresses/search?q=host", a.headers)
    assert r.status_code == 200, r.text
    assert "beta-host" not in r.text and "acme-host" in r.text
    # same IP in both tenants: only the caller's row comes back
    r = await get(client, db_session, "/api/v1/ipam/addresses/search?q=10.50.1.10", a.headers)
    rows = r.json()
    assert [str(a.address.id)] == [
        x["id"]
        for x in (rows if isinstance(rows, list) else rows.get("items", rows.get("results", [])))
    ]


async def test_global_search_is_confined(client: AsyncClient, db_session, two):
    a, b = two
    r = await get(client, db_session, "/api/v1/search?q=Beta", a.headers)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 0 and "Beta-" not in r.text
    r = await get(client, db_session, "/api/v1/search?q=Acme", a.headers)
    assert r.json()["total"] >= 1
    # install-wide types are not searched for a tenant user at all
    r = await get(client, db_session, "/api/v1/search/types", a.headers)
    assert {t["type"] for t in r.json()} <= {"ip_address", "subnet", "block", "space"}


async def test_unaware_routes_are_refused(client: AsyncClient, db_session, two):
    a, _ = two
    for path in ("/api/v1/dns/groups", "/api/v1/dhcp/servers", "/api/v1/audit", "/api/v1/users"):
        r = await get(client, db_session, path, a.headers)
        assert r.status_code == 403, (path, r.status_code)


async def test_write_cannot_target_other_tenant(client: AsyncClient, db_session, two):
    a, b = two
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/blocks",
        a.headers,
        json={"space_id": str(b.space.id), "network": "192.168.0.0/16", "name": "x"},
    )
    assert r.status_code == 404, r.text
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/subnets",
        a.headers,
        json={
            "space_id": str(b.space.id),
            "block_id": str(b.block.id),
            "network": "10.50.9.0/24",
            "name": "x",
        },
    )
    assert r.status_code == 404, r.text
    r = await send(
        client,
        db_session,
        "PUT",
        f"/api/v1/ipam/subnets/{b.subnet.id}",
        a.headers,
        json={"name": "pwn"},
    )
    assert r.status_code == 404
    r = await send(client, db_session, "DELETE", f"/api/v1/ipam/subnets/{b.subnet.id}", a.headers)
    assert r.status_code == 404
    reset_scope(db_session)
    sn = (await db_session.execute(select(Subnet).where(Subnet.id == b.subnet.id))).scalar_one()
    assert sn.name == "Beta-subnet"


async def test_create_space_lands_in_callers_tenant(client: AsyncClient, db_session, two):
    a, b = two
    r = await send(
        client, db_session, "POST", "/api/v1/ipam/spaces", a.headers, json={"name": "Lab"}
    )
    assert r.status_code == 201, r.text
    assert r.json()["tenant_id"] == str(a.tenant.id)
    # same name as an existing space of the same tenant: 409; of another tenant: fine
    r = await send(
        client, db_session, "POST", "/api/v1/ipam/spaces", a.headers, json={"name": "Corporate"}
    )
    assert r.status_code == 409
    # naming another tenant is refused as not found
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/spaces",
        a.headers,
        json={"name": "Steal", "tenant_id": str(b.tenant.id)},
    )
    assert r.status_code == 404


async def test_tenant_user_cannot_assign_dns_or_dhcp(client: AsyncClient, db_session, two):
    a, _ = two
    r = await send(
        client,
        db_session,
        "PUT",
        f"/api/v1/ipam/spaces/{a.space.id}",
        a.headers,
        json={"dns_zone_id": "00000000-0000-0000-0000-000000000002"},
    )
    assert r.status_code in (403, 404, 422), r.text
    assert r.status_code != 200


async def test_same_space_name_in_two_tenants_and_untenanted(db_session, two):
    reset_scope(db_session)
    db_session.add(IPSpace(name="Corporate", description=""))
    await db_session.commit()
    rows = (
        (await db_session.execute(select(IPSpace).where(IPSpace.name == "Corporate")))
        .scalars()
        .all()
    )
    assert len(rows) == 3


async def test_trashed_rows_of_other_tenant_do_not_leak(client: AsyncClient, db_session, two):
    a, b = two
    admin = await make_user(db_session, superadmin=True)
    await db_session.commit()
    r = await send(
        client, db_session, "DELETE", f"/api/v1/ipam/subnets/{b.subnet.id}", bearer(admin)
    )
    assert r.status_code in (200, 204), r.text
    r = await get(client, db_session, "/api/v1/ipam/subnets", a.headers)
    assert str(b.subnet.id) not in r.text
    # Even a read that asks for trashed rows is confined to the session's tenant.
    reset_scope(db_session)
    set_session_scope(db_session.sync_session, frozenset({a.tenant.id}))
    rows = (
        (await db_session.execute(select(Subnet.id).execution_options(include_deleted=True)))
        .scalars()
        .all()
    )
    reset_scope(db_session)
    assert str(b.subnet.id) not in {str(x) for x in rows}
    assert a.subnet.id in rows


async def test_trash_views_are_refused_to_tenant_users(client: AsyncClient, db_session, two):
    a, _ = two
    r = await get(client, db_session, "/api/v1/admin/trash", a.headers)
    assert r.status_code == 403


async def test_exports_are_confined(client: AsyncClient, db_session, two):
    a, b = two
    for fmt in ("csv", "json"):
        r = await get(
            client,
            db_session,
            f"/api/v1/ipam/export?space_id={a.space.id}&format={fmt}&include_addresses=true",
            a.headers,
        )
        assert r.status_code == 200, r.text
        assert "acme-host" in r.text and "Beta" not in r.text and "beta-host" not in r.text
        r = await get(
            client, db_session, f"/api/v1/ipam/export?space_id={b.space.id}&format={fmt}", a.headers
        )
        assert r.status_code in (403, 404), (fmt, r.status_code, r.text[:200])
    r = await get(client, db_session, f"/api/v1/ipam/export.pdf?subnet_id={b.subnet.id}", a.headers)
    assert r.status_code in (403, 404), r.status_code
    r = await get(client, db_session, f"/api/v1/ipam/export.pdf?subnet_id={a.subnet.id}", a.headers)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


async def test_import_into_other_tenant_is_not_found(client: AsyncClient, db_session, two):
    a, b = two
    csv = b"network,name\n10.77.0.0/16,imported\n"
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/import/preview",
        a.headers,
        files={"file": ("x.csv", csv, "text/csv")},
        data={"space_id": str(b.space.id)},
    )
    assert r.status_code == 404, r.text
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/import/addresses/commit",
        a.headers,
        files={"file": ("x.csv", b"address,hostname\n10.50.1.77,evil\n", "text/csv")},
        data={"subnet_id": str(b.subnet.id)},
    )
    assert r.status_code in (403, 404), r.text
    reset_scope(db_session)
    n = (
        (await db_session.execute(select(IPAddress).where(IPAddress.hostname == "evil")))
        .scalars()
        .all()
    )
    assert n == []


async def test_bulk_operations_skip_other_tenant_rows(client: AsyncClient, db_session, two):
    a, b = two
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/subnets/bulk-edit",
        a.headers,
        json={"subnet_ids": [str(b.subnet.id)], "changes": {"description": "pwn"}},
    )
    assert r.status_code in (200, 404), r.text
    if r.status_code == 200:
        assert r.json()["updated_count"] == 0
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/addresses/bulk-delete",
        a.headers,
        json={"ids": [str(b.address.id)]},
    )
    assert r.status_code in (200, 404, 422), r.text
    reset_scope(db_session)
    sn = (await db_session.execute(select(Subnet).where(Subnet.id == b.subnet.id))).scalar_one()
    assert sn.description != "pwn"
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.id == b.address.id))
    ).scalar_one_or_none() is not None


async def test_plans_and_history_and_reports(client: AsyncClient, db_session, two):
    a, b = two
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/plans",
        a.headers,
        json={
            "name": "p",
            "space_id": str(b.space.id),
            "tree": {"id": "r", "network": "10.9.0.0/16"},
        },
    )
    assert r.status_code == 404, r.text
    r = await send(
        client,
        db_session,
        "POST",
        "/api/v1/ipam/plans",
        a.headers,
        json={
            "name": "p",
            "space_id": str(a.space.id),
            "tree": {"id": "r", "network": "10.9.0.0/16"},
        },
    )
    assert r.status_code in (200, 201), r.text
    r = await get(
        client, db_session, f"/api/v1/ipam/subnets/{b.subnet.id}/utilization-history", a.headers
    )
    assert r.status_code == 404
    for path in (
        "/api/v1/ipam/reports/stale-ips?include_never_seen=true",
        "/api/v1/ipam/reports/hygiene",
        "/api/v1/ipam/addresses/search/ids?q=host",
    ):
        r = await get(client, db_session, path, a.headers)
        assert r.status_code == 200, (path, r.text)
        assert "Beta" not in r.text and str(b.address.id) not in r.text


async def test_dns_and_dhcp_assignment_is_refused_at_flush(client: AsyncClient, db_session, two):
    from app.models.dns import DNSServerGroup

    a, _ = two
    grp = DNSServerGroup(name="shared-dns")
    db_session.add(grp)
    await db_session.commit()
    r = await send(
        client,
        db_session,
        "PUT",
        f"/api/v1/ipam/spaces/{a.space.id}",
        a.headers,
        json={"dns_group_ids": [str(grp.id)]},
    )
    assert r.status_code == 403, r.text
    assert "DNS or DHCP" in r.text


async def test_install_with_no_tenants_is_unchanged(client: AsyncClient, db_session):
    admin = await make_user(db_session, superadmin=True)
    plain = await make_user(db_session)  # ordinary group, no tenant
    await db_session.commit()
    for n, h in enumerate((bearer(admin), bearer(plain))):
        r = await send(
            client, db_session, "POST", "/api/v1/ipam/spaces", h, json={"name": f"s-{n}"}
        )
        assert r.status_code == 201 and r.json()["tenant_id"] is None
    r = await get(client, db_session, "/api/v1/dns/groups", bearer(plain))
    assert r.status_code != 403 or "tenant" not in r.text

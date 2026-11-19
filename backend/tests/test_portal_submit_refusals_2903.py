"""The request portal refuses at submit what the REST create refuses (#2903-#2905)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.ipam import IPAddress, Subnet
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_self_service_requests import (
    MODULE,
    REQUESTER_PERMS,
    _auth,
    _enable_module,
    _user,
)


async def _requester(db: AsyncSession) -> str:
    await _enable_module(db, MODULE)
    _, token = await _user(db, name="req", permissions=REQUESTER_PERMS)
    return token


async def _submit(client: AsyncClient, token: str, kind: str, args: dict):
    return await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={"kind": kind, "args": args, "justification": "please"},
    )


async def _no_rows(db: AsyncSession) -> None:
    assert await db.scalar(select(func.count()).select_from(ChangeRequest)) == 0


@pytest.mark.asyncio
async def test_held_address_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.60.0.50", status="allocated"))
    await db_session.flush()
    ok = await _submit(
        client, tok, "ip_address", {"subnet_id": str(subnet.id), "address": "10.60.0.51"}
    )
    assert ok.status_code == 201, ok.text
    resp = await _submit(
        client, tok, "ip_address", {"subnet_id": str(subnet.id), "address": "10.60.0.50"}
    )
    assert resp.status_code == 409, resp.text
    assert await db_session.scalar(select(func.count()).select_from(ChangeRequest)) == 1


@pytest.mark.asyncio
async def test_static_dhcp_without_mac_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    resp = await _submit(
        client,
        tok,
        "ip_address",
        {"subnet_id": str(subnet.id), "address": "10.60.0.60", "status": "static_dhcp"},
    )
    assert resp.status_code == 422, resp.text
    await _no_rows(db_session)


@pytest.mark.asyncio
async def test_multicast_subnet_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    mc = Subnet(
        space_id=subnet.space_id, block_id=subnet.block_id, network="239.1.1.0/24", kind="multicast"
    )
    db_session.add(mc)
    await db_session.flush()
    resp = await _submit(
        client, tok, "ip_address", {"subnet_id": str(mc.id), "address": "239.1.1.20"}
    )
    assert resp.status_code == 422, resp.text
    assert "multicast subnet" in resp.text
    await _no_rows(db_session)


async def _two_statics(db: AsyncSession) -> DHCPScope:
    scope, _, _ = await _estate(db)
    db.add_all(
        [
            DHCPStaticAssignment(
                scope_id=scope.id, ip_address="10.60.0.40", mac_address="02:00:5e:00:00:01"
            ),
            DHCPStaticAssignment(
                scope_id=scope.id, ip_address="10.60.0.41", mac_address="02:00:5e:00:00:02"
            ),
        ]
    )
    await db.flush()
    return scope


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ip,mac",
    [
        ("10.60.0.40", "02:00:5e:00:00:99"),  # IP collision
        ("10.60.0.99", "02:00:5e:00:00:02"),  # MAC collision
        ("10.60.0.40", "02:00:5e:00:00:02"),  # IP matches one, MAC another
    ],
)
async def test_reservation_collisions_refused(
    client: AsyncClient, db_session: AsyncSession, ip: str, mac: str
) -> None:
    tok = await _requester(db_session)
    scope = await _two_statics(db_session)
    resp = await _submit(
        client,
        tok,
        "dhcp_reservation",
        {"scope_id": str(scope.id), "ip_address": ip, "mac_address": mac},
    )
    assert resp.status_code == 409, resp.text
    await _no_rows(db_session)


@pytest.mark.asyncio
async def test_clean_reservation_accepted(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    scope = await _two_statics(db_session)
    resp = await _submit(
        client,
        tok,
        "dhcp_reservation",
        {"scope_id": str(scope.id), "ip_address": "10.60.0.98", "mac_address": "02:00:5e:00:00:98"},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_copilot_preview_does_not_raise_on_two_row_conflict(
    db_session: AsyncSession,
) -> None:
    from app.core.security import hash_password
    from app.models.auth import User
    from app.services.ai import operations

    scope = await _two_statics(db_session)
    user = User(
        username=f"c-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    op = operations.get_operation("create_dhcp_static")
    args = op.args_model(
        scope_id=str(scope.id), ip_address="10.60.0.40", mac_address="02:00:5e:00:00:02"
    )
    preview = await op.preview(db_session, user, args)
    assert preview.ok and "already exists" in preview.preview_text


# ── validation-pass additions ─────────────────────────────────────────────


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    _, token = await _user(db, name="adm", superadmin=True)
    return _auth(token)


@pytest.mark.asyncio
async def test_mac_in_other_scope_does_not_name_that_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The submit 409 must not carry the id of a scope the requester may not read."""
    tok = await _requester(db_session)
    scope, _, block = await _estate(db_session)
    other_subnet = Subnet(
        space_id=block.space_id,
        block_id=block.id,
        network="10.61.0.0/24",
        name="other",
    )
    db_session.add(other_subnet)
    await db_session.flush()
    other = DHCPScope(
        group_id=scope.group_id, subnet_id=other_subnet.id, name="other", address_family="ipv4"
    )
    db_session.add(other)
    await db_session.flush()
    db_session.add(
        DHCPStaticAssignment(
            scope_id=other.id, ip_address="10.61.0.5", mac_address="02:00:5e:00:00:77"
        )
    )
    await db_session.flush()
    resp = await _submit(
        client,
        tok,
        "dhcp_reservation",
        {"scope_id": str(scope.id), "ip_address": "10.60.0.5", "mac_address": "02:00:5e:00:00:77"},
    )
    assert resp.status_code == 409, resp.text
    assert str(other.id) not in resp.text
    assert "already reserved in this group" in resp.json()["detail"]
    await _no_rows(db_session)


@pytest.mark.asyncio
async def test_rest_static_invalid_ip_keeps_its_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The same-IP check runs after the parse: a malformed IP is still 'Invalid IP'."""
    scope = await _two_statics(db_session)
    auth_headers = await _admin_headers(db_session)
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/statics",
        headers=auth_headers,
        json={"ip_address": "not-an-ip", "mac_address": "02:00:5e:00:00:55"},
    )
    assert resp.status_code == 422, resp.text
    assert "Invalid IP" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_rest_static_same_ip_and_edit_in_place(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """REST create of a held IP is an explicit 409; editing a static's MAC
    without moving its IP is not refused by its own row (``exclude_id``)."""
    scope = await _two_statics(db_session)
    auth_headers = await _admin_headers(db_session)
    await db_session.commit()
    dup = await client.post(
        f"/api/v1/dhcp/scopes/{scope.id}/statics",
        headers=auth_headers,
        json={"ip_address": "10.60.0.40", "mac_address": "02:00:5e:00:00:56"},
    )
    assert dup.status_code == 409, dup.text
    assert dup.json()["detail"] == "IP 10.60.0.40 is already reserved in this scope"

    st = await db_session.scalar(
        select(DHCPStaticAssignment).where(DHCPStaticAssignment.mac_address == "02:00:5e:00:00:01")
    )
    assert st is not None
    upd = await client.put(
        f"/api/v1/dhcp/statics/{st.id}",
        headers=auth_headers,
        json={"ip_address": "10.60.0.40", "mac_address": "02:00:5e:00:00:57"},
    )
    assert upd.status_code == 200, upd.text


@pytest.mark.asyncio
async def test_apply_refuses_multicast_without_hostname(db_session: AsyncSession) -> None:
    """A request queued before submit learned the rule still cannot land (#2905)."""
    from app.services.ai import operations

    _, subnet, _ = await _estate(db_session)
    mc = Subnet(
        space_id=subnet.space_id, block_id=subnet.block_id, network="239.1.2.0/24", kind="multicast"
    )
    db_session.add(mc)
    await db_session.flush()
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_ip_address")
    args = op.args_model(subnet_id=str(mc.id), address="239.1.2.20")
    with pytest.raises(ValueError, match="multicast"):
        await op.apply(db_session, admin, args)
    assert (
        await db_session.scalar(
            select(func.count()).select_from(IPAddress).where(IPAddress.subnet_id == mc.id)
        )
        == 0
    )


async def _zone_with_record(db: AsyncSession, *, in_two_views: bool = False):
    from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone

    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name=f"z{uuid.uuid4().hex[:6]}.example.")
    db.add(zone)
    await db.flush()
    views: list = [None]
    if in_two_views:
        v1 = DNSView(group_id=grp.id, name="a")
        v2 = DNSView(group_id=grp.id, name="b")
        db.add_all([v1, v2])
        await db.flush()
        views = [v1.id, v2.id]
    for vid in views:
        db.add(
            DNSRecord(
                zone_id=zone.id,
                view_id=vid,
                name="h",
                fqdn=f"h.{zone.name}",
                record_type="A",
                value="10.0.0.9",
            )
        )
    await db.flush()
    return zone


@pytest.mark.asyncio
async def test_identical_dns_record_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    tok = await _requester(db_session)
    zone = await _zone_with_record(db_session)
    ok = await _submit(
        client,
        tok,
        "dns_record",
        {"zone_id": str(zone.id), "name": "h2", "record_type": "A", "value": "10.0.0.9"},
    )
    assert ok.status_code == 201, ok.text
    resp = await _submit(
        client,
        tok,
        "dns_record",
        {"zone_id": str(zone.id), "name": "h", "record_type": "A", "value": "10.0.0.9"},
    )
    assert resp.status_code == 409, resp.text
    assert "identical" in resp.json()["detail"]
    assert await db_session.scalar(select(func.count()).select_from(ChangeRequest)) == 1


@pytest.mark.asyncio
async def test_dns_preview_survives_the_record_in_two_views(db_session: AsyncSession) -> None:
    """The preview's identical-record probe ignores views, so two view copies
    matched it twice and ``scalar_one_or_none`` raised — a 500 at submit."""
    from app.services.ai import operations

    zone = await _zone_with_record(db_session, in_two_views=True)
    admin, _ = await _user(db_session, name="adm", superadmin=True)
    op = operations.get_operation("create_dns_record")
    args = op.args_model(zone_id=str(zone.id), name="h", record_type="A", value="10.0.0.9")
    preview = await op.preview(db_session, admin, args)
    assert preview.ok, preview.detail

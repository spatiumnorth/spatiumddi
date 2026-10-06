"""Server-side DHCP reservation sync for IPAM rows (#1628).

A ``static_dhcp`` IPAM row with a MAC used to reach the rendered Kea
bundle only when the *browser* chained a second ``createStatic`` call
after saving the address — so API-created and imported rows sat in IPAM
with no ``DHCPStaticAssignment`` behind them until each was opened and
re-saved by hand. The reservation is now synced server-side
(``sync_static_for_ipam_row``) on address create / update / allocate
and in the address importer; these tests pin that behaviour, including
the warning-instead-of-guessing contract for ambiguous scopes.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.ipam_io.importer import commit_address_import, preview_address_import
from app.services.ipam_io.parser import ParsedPayload

NETWORK = "10.80.0.0/24"
MAC = "aa:bb:cc:dd:ee:01"


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"s-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Sync Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _subnet(db: AsyncSession) -> Subnet:
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="root")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=NETWORK, name="lan")
    db.add(subnet)
    await db.flush()
    return subnet


async def _scope(db: AsyncSession, subnet: Subnet) -> DHCPScope:
    group = DHCPServerGroup(name=f"s-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    db.add(
        DHCPServer(
            name=f"s-{uuid.uuid4().hex[:6]}",
            driver="kea",
            host="127.0.0.1",
            server_group_id=group.id,
        )
    )
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="scope", address_family="ipv4")
    db.add(scope)
    await db.flush()
    return scope


async def _statics(db: AsyncSession) -> list[DHCPStaticAssignment]:
    res = await db.execute(select(DHCPStaticAssignment))
    return list(res.scalars().all())


async def _static_audits(db: AsyncSession) -> list[AuditLog]:
    """Audit rows for the reservation itself (#1629 review).

    ``sync_static_for_ipam_row`` must write the same rows the statics
    endpoints write — resource ``dhcp_static_assignment`` — for every
    reservation create / update / delete it performs.
    """
    res = await db.execute(
        select(AuditLog)
        .where(AuditLog.resource_type == "dhcp_static_assignment")
        .order_by(AuditLog.seq)
    )
    return list(res.scalars().all())


@pytest.mark.asyncio
async def test_api_create_static_dhcp_creates_reservation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _admin(db_session)
    admin_id = user.id
    subnet = await _subnet(db_session)
    scope = await _scope(db_session, subnet)
    subnet_id, scope_id = subnet.id, scope.id
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        headers=headers,
        json={
            "address": "10.80.0.50",
            "hostname": "printer1",
            "status": "static_dhcp",
            "mac_address": MAC,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["dhcp_static_warning"] is None

    db_session.expire_all()
    statics = await _statics(db_session)
    assert len(statics) == 1
    st = statics[0]
    assert st.scope_id == scope_id
    assert str(st.ip_address) == "10.80.0.50"
    assert str(st.mac_address) == MAC
    # The reservation creation is audited as a reservation (#1629).
    audits = await _static_audits(db_session)
    assert len(audits) == 1
    assert audits[0].action == "create"
    assert audits[0].resource_id == str(st.id)
    assert audits[0].resource_display == f"{MAC}->10.80.0.50"
    assert audits[0].user_id == admin_id
    row = await db_session.get(IPAddress, uuid.UUID(body["id"]))
    assert row is not None
    assert row.static_assignment_id == str(st.id)
    assert st.ip_address_id == row.id


@pytest.mark.asyncio
async def test_api_create_static_dhcp_without_scope_warns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    subnet = await _subnet(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=headers,
        json={
            "address": "10.80.0.51",
            "hostname": "printer2",
            "status": "static_dhcp",
            "mac_address": MAC,
        },
    )
    # The row is created; only the reservation is missing, and the
    # response says so instead of failing or silently skipping it.
    assert resp.status_code == 201, resp.text
    assert "No DHCP scope" in (resp.json()["dhcp_static_warning"] or "")
    db_session.expire_all()
    assert await _statics(db_session) == []


@pytest.mark.asyncio
async def test_api_create_static_dhcp_with_two_scopes_warns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    subnet = await _subnet(db_session)
    await _scope(db_session, subnet)
    await _scope(db_session, subnet)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=headers,
        json={
            "address": "10.80.0.52",
            "hostname": "printer3",
            "status": "static_dhcp",
            "mac_address": MAC,
        },
    )
    assert resp.status_code == 201, resp.text
    assert "2 DHCP scopes" in (resp.json()["dhcp_static_warning"] or "")
    db_session.expire_all()
    assert await _statics(db_session) == []


@pytest.mark.asyncio
async def test_api_create_static_dhcp_mac_conflict_warns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    subnet = await _subnet(db_session)
    scope = await _scope(db_session, subnet)
    subnet_id, scope_id = subnet.id, scope.id
    await db_session.commit()

    taken = await client.post(
        f"/api/v1/dhcp/scopes/{scope_id}/statics",
        headers=headers,
        json={"ip_address": "10.80.0.60", "mac_address": MAC},
    )
    assert taken.status_code == 201, taken.text

    # The create endpoint's own collision gate fires first: a MAC the
    # group already reserves is a soft collision the operator confirms
    # with force — after which the sync must still refuse to duplicate
    # the reservation and say so on the response.
    body = {
        "address": "10.80.0.61",
        "hostname": "printer4",
        "status": "static_dhcp",
        "mac_address": MAC,
    }
    warn = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses", headers=headers, json=body
    )
    assert warn.status_code == 409, warn.text
    assert warn.json()["detail"]["requires_confirmation"] is True

    resp = await client.post(
        f"/api/v1/ipam/subnets/{subnet_id}/addresses",
        headers=headers,
        json={**body, "force": True},
    )
    assert resp.status_code == 201, resp.text
    assert "conflicting DHCP reservation" in (resp.json()["dhcp_static_warning"] or "")
    db_session.expire_all()
    statics = await _statics(db_session)
    assert len(statics) == 1
    assert str(statics[0].ip_address) == "10.80.0.60"


@pytest.mark.asyncio
async def test_api_update_keeps_reservation_in_step(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _admin(db_session)
    subnet = await _subnet(db_session)
    await _scope(db_session, subnet)
    await db_session.commit()

    created = await client.post(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses",
        headers=headers,
        json={
            "address": "10.80.0.53",
            "hostname": "printer5",
            "status": "static_dhcp",
            "mac_address": MAC,
        },
    )
    assert created.status_code == 201, created.text
    row_id = created.json()["id"]

    # MAC change lands on the linked reservation.
    new_mac = "aa:bb:cc:dd:ee:02"
    updated = await client.put(
        f"/api/v1/ipam/addresses/{row_id}",
        headers=headers,
        json={"mac_address": new_mac},
    )
    assert updated.status_code == 200, updated.text
    db_session.expire_all()
    statics = await _statics(db_session)
    assert len(statics) == 1
    assert str(statics[0].mac_address) == new_mac
    # The MAC change is audited as a reservation update (#1629).
    audits = await _static_audits(db_session)
    assert [a.action for a in audits] == ["create", "update"]
    assert audits[1].resource_id == str(statics[0].id)
    assert "mac_address" in (audits[1].changed_fields or [])
    assert audits[1].resource_display == f"{new_mac}->10.80.0.53"

    # Flipping the row away from static_dhcp removes the reservation.
    flipped = await client.put(
        f"/api/v1/ipam/addresses/{row_id}",
        headers=headers,
        json={"status": "allocated"},
    )
    assert flipped.status_code == 200, flipped.text
    db_session.expire_all()
    assert await _statics(db_session) == []
    # …and the reservation removal is audited as a delete (#1629).
    audits = await _static_audits(db_session)
    assert [a.action for a in audits] == ["create", "update", "delete"]
    assert audits[2].resource_display == f"{new_mac}->10.80.0.53"


@pytest.mark.asyncio
async def test_import_creates_reservation_and_preview_flags_it(
    db_session: AsyncSession,
) -> None:
    user, _ = await _admin(db_session)
    importer_id = user.id
    subnet = await _subnet(db_session)
    scope = await _scope(db_session, subnet)
    subnet_id, scope_id = subnet.id, scope.id
    await db_session.commit()

    payload = ParsedPayload(
        addresses=[
            {
                "address": "10.80.0.106",
                "hostname": "khhems01ap",
                "status": "static_dhcp",
                "mac_address": "00:c0:8f:88:5f:06",
            }
        ]
    )

    preview = await preview_address_import(db_session, payload, subnet_id=subnet_id)
    assert len(preview.creates) == 1
    assert preview.creates[0].details.get("dhcp_static_sync") is True
    assert "dhcp_static_warning" not in preview.creates[0].details

    result = await commit_address_import(
        db_session, payload, current_user=user, subnet_id=subnet_id
    )
    await db_session.commit()
    assert result.created == 1
    assert result.dhcp_synced == 1
    assert result.dhcp_warnings == []

    db_session.expire_all()
    statics = await _statics(db_session)
    assert len(statics) == 1
    assert statics[0].scope_id == scope_id
    assert str(statics[0].ip_address) == "10.80.0.106"
    assert str(statics[0].mac_address) == "00:c0:8f:88:5f:06"
    # Imported reservations are audited too, attributed to the importer.
    audits = await _static_audits(db_session)
    assert len(audits) == 1
    assert audits[0].action == "create"
    assert audits[0].resource_id == str(statics[0].id)
    assert audits[0].user_id == importer_id


@pytest.mark.asyncio
async def test_import_without_scope_warns_in_preview_and_result(
    db_session: AsyncSession,
) -> None:
    user, _ = await _admin(db_session)
    subnet = await _subnet(db_session)
    subnet_id = subnet.id
    await db_session.commit()

    payload = ParsedPayload(
        addresses=[
            {
                "address": "10.80.0.107",
                "hostname": "khhems02ap",
                "status": "static_dhcp",
                "mac_address": "00:c0:8f:88:5f:07",
            }
        ]
    )

    preview = await preview_address_import(db_session, payload, subnet_id=subnet_id)
    assert len(preview.creates) == 1
    assert "No DHCP scope" in (preview.creates[0].details.get("dhcp_static_warning") or "")

    result = await commit_address_import(
        db_session, payload, current_user=user, subnet_id=subnet_id
    )
    await db_session.commit()
    assert result.created == 1
    assert result.dhcp_synced == 0
    assert len(result.dhcp_warnings) == 1
    assert "No DHCP scope" in result.dhcp_warnings[0]
    db_session.expire_all()
    assert await _statics(db_session) == []

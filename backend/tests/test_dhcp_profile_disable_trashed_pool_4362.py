"""Disabling a PXE / phone profile counts pools in the Trash, and a restore
refuses a pool whose class is no longer rendered (#4362; the Disable half of
#3928's fix, which only covered Delete and Save)."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPhoneProfile, DHCPPhoneProfileScope, DHCPPool
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.services.dhcp.class_refs import phone_class_name
from tests.test_dhcp_phone_profiles import _make_group_server_scope
from tests.test_dhcp_pxe_vendor_match_validation import _headers


async def _pxe_with_trashed_pool(client: AsyncClient, db: AsyncSession):
    h = await _headers(db)
    grp, _srv, scope = await _make_group_server_scope(db)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles",
        headers=h,
        json={
            "name": "px",
            "next_server": "10.0.0.5",
            "matches": [
                {"vendor_class_match": "PXEClient", "arch_codes": [7], "boot_filename": "a.efi"}
            ],
        },
    )
    assert r.status_code == 201, r.text
    prof = r.json()
    scope.pxe_profile_id = uuid.UUID(prof["id"])
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.20.10",
            end_ip="10.0.20.50",
            pool_type="dynamic",
            class_restriction=f"pxe-{prof['id'][:8]}-{prof['matches'][0]['id'][:8]}",
        )
    )
    await db.commit()
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    return h, prof, scope


async def test_pxe_disable_refused_while_a_trashed_scope_pool_names_the_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, prof, _scope = await _pxe_with_trashed_pool(client, db_session)
    r = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_phone_disable_refused_while_a_trashed_scope_pool_names_the_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _srv, scope = await _make_group_server_scope(db_session)
    prof = DHCPPhoneProfile(
        group_id=grp.id, name="poly", enabled=True, vendor_class_match="Polycom", option_set=[]
    )
    db_session.add(prof)
    await db_session.flush()
    db_session.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=scope.id))
    db_session.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.21.10",
            end_ip="10.0.21.50",
            pool_type="dynamic",
            class_restriction=phone_class_name(prof.id),
        )
    )
    await db_session.commit()
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    r = await client.put(
        f"/api/v1/dhcp/phone-profiles/{prof.id}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_restore_refused_when_the_pools_class_is_no_longer_rendered(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, prof, scope = await _pxe_with_trashed_pool(client, db_session)
    # The state the Disable guard now prevents, reached directly (e.g. data
    # from before the fix): the profile is disabled while the scope is trashed.
    from app.models.dhcp import DHCPPXEProfile

    row = await db_session.get(DHCPPXEProfile, prof["id"])
    row.enabled = False
    await db_session.commit()
    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope.id}/restore", headers=h)
    assert r.status_code == 409, r.text
    assert "disabled" in r.text
    # Nothing came back: the scope is still in the Trash.
    await db_session.refresh(scope)
    assert scope.deleted_at is not None


async def _phone_with_pool(db: AsyncSession):
    h = await _headers(db)
    grp, _srv, scope = await _make_group_server_scope(db)
    prof = DHCPPhoneProfile(
        group_id=grp.id, name="poly", enabled=True, vendor_class_match="Polycom", option_set=[]
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=scope.id))
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.21.10",
            end_ip="10.0.21.50",
            pool_type="dynamic",
            class_restriction=phone_class_name(prof.id),
        )
    )
    await db.commit()
    return h, prof, scope


async def test_restore_refused_when_the_phone_class_is_no_longer_rendered(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, prof, scope = await _phone_with_pool(db_session)
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    prof.enabled = False
    await db_session.commit()
    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope.id}/restore", headers=h)
    assert r.status_code == 409, r.text
    assert "disabled" in r.text
    await db_session.refresh(scope)
    assert scope.deleted_at is not None


# ── Device policy (the third site) ───────────────────────────────────────


async def _policy_with_pool(db: AsyncSession):
    h = await _headers(db)
    grp, _srv, scope = await _make_group_server_scope(db)
    pol = DHCPDevicePolicy(
        group_id=grp.id, name="pol", class_name="spatium-device-abc", device_classes=["Printer"]
    )
    db.add(pol)
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.22.10",
            end_ip="10.0.22.50",
            pool_type="dynamic",
            class_restriction="spatium-device-abc",
        )
    )
    await db.commit()
    return h, pol, scope


async def test_device_policy_disable_refused_with_a_live_pool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pol, _scope = await _policy_with_pool(db_session)
    r = await client.put(
        f"/api/v1/dhcp/device-policies/{pol.id}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 409, r.text
    assert "spatium-device-abc" in r.json()["detail"]


async def test_device_policy_disable_refused_with_only_a_trashed_pool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pol, scope = await _policy_with_pool(db_session)
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    r = await client.put(
        f"/api/v1/dhcp/device-policies/{pol.id}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 409, r.text
    assert "in Trash" in r.json()["detail"]


async def test_device_policy_disable_allowed_when_nothing_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pol, scope = await _policy_with_pool(db_session)
    await db_session.execute(
        DHCPPool.__table__.update()
        .where(DHCPPool.scope_id == scope.id)
        .values(class_restriction=None)
    )
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dhcp/device-policies/{pol.id}", headers=h, json={"enabled": False}
    )
    assert r.status_code == 200, r.text


async def test_restore_refused_when_the_device_policy_class_is_disabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pol, scope = await _policy_with_pool(db_session)
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)).status_code == 204
    pol.enabled = False
    await db_session.commit()
    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope.id}/restore", headers=h)
    assert r.status_code == 409, r.text
    assert "disabled" in r.text
    await db_session.refresh(scope)
    assert scope.deleted_at is not None


# ── Activating a scope brings its pools back (#4367) ─────────────────────


async def _deactivate(client: AsyncClient, h, scope) -> None:
    r = await client.put(f"/api/v1/dhcp/scopes/{scope.id}", headers=h, json={"is_active": False})
    assert r.status_code == 200, r.text


async def _activate(client: AsyncClient, h, scope):
    return await client.put(f"/api/v1/dhcp/scopes/{scope.id}", headers=h, json={"is_active": True})


async def test_activation_refused_when_the_phone_class_is_disabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, prof, scope = await _phone_with_pool(db_session)
    await _deactivate(client, h, scope)
    prof.enabled = False
    await db_session.commit()
    r = await _activate(client, h, scope)
    assert r.status_code == 409, r.text
    assert "disabled" in r.text
    await db_session.refresh(scope)
    assert scope.is_active is False


async def test_activation_ok_when_the_phone_class_is_enabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _prof, scope = await _phone_with_pool(db_session)
    await _deactivate(client, h, scope)
    r = await _activate(client, h, scope)
    assert r.status_code == 200, r.text


async def test_activation_refused_when_the_pxe_class_is_disabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.dhcp import DHCPPXEProfile

    h = await _headers(db_session)
    grp, _srv, scope = await _make_group_server_scope(db_session)
    r = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles",
        headers=h,
        json={
            "name": "px",
            "next_server": "10.0.0.5",
            "matches": [
                {"vendor_class_match": "PXEClient", "arch_codes": [7], "boot_filename": "a.efi"}
            ],
        },
    )
    prof = r.json()
    scope.pxe_profile_id = uuid.UUID(prof["id"])
    db_session.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.20.10",
            end_ip="10.0.20.50",
            pool_type="dynamic",
            class_restriction=f"pxe-{prof['id'][:8]}-{prof['matches'][0]['id'][:8]}",
        )
    )
    await db_session.commit()
    await _deactivate(client, h, scope)
    row = await db_session.get(DHCPPXEProfile, prof["id"])
    row.enabled = False
    await db_session.commit()
    r = await _activate(client, h, scope)
    assert r.status_code == 409, r.text
    assert "disabled" in r.text
    row.enabled = True
    await db_session.commit()
    assert (await _activate(client, h, scope)).status_code == 200


async def test_activation_refused_when_the_device_policy_class_is_disabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, pol, scope = await _policy_with_pool(db_session)
    await _deactivate(client, h, scope)
    pol.enabled = False
    await db_session.commit()
    r = await _activate(client, h, scope)
    assert r.status_code == 409, r.text
    assert "disabled" in r.text
    pol.enabled = True
    await db_session.commit()
    assert (await _activate(client, h, scope)).status_code == 200

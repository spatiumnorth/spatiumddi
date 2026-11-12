"""A class delete counts pools sitting in the Trash (#3928).

Deleting a scope trashes its pools with it, and a restore brings them back with
their ``class_restriction``. The reference guard used to count live pools only,
so the class could be deleted meanwhile and the restored pool would name a class
nothing defines (Kea never matches it).
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPClientClass, DHCPPool
from tests.test_dhcp_phone_profiles import _make_group_server_scope
from tests.test_dhcp_pxe_vendor_match_validation import _headers


async def _trashed_pool_scope(client: AsyncClient, db: AsyncSession):
    h = await _headers(db)
    _grp, _srv, scope = await _make_group_server_scope(db)
    cc = DHCPClientClass(
        group_id=scope.group_id, name="quarantine", match_expression="option[60].text == 'x'"
    )
    db.add(cc)
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.9.10",
            end_ip="10.0.9.50",
            pool_type="dynamic",
            class_restriction="quarantine",
        )
    )
    await db.commit()
    scope_name = scope.name
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)
    assert r.status_code == 204, r.text
    return h, cc, scope_name


async def test_client_class_delete_refused_while_a_trashed_scope_pool_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, cc, scope_name = await _trashed_pool_scope(client, db_session)
    r = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "quarantine" in detail and scope_name in detail and "in Trash" in detail


async def test_client_class_delete_allowed_once_nothing_names_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    _grp, _srv, scope = await _make_group_server_scope(db_session)
    cc = DHCPClientClass(
        group_id=scope.group_id, name="unused", match_expression="option[60].text == 'x'"
    )
    db_session.add(cc)
    await db_session.commit()
    r = await client.delete(f"/api/v1/dhcp/client-classes/{cc.id}", headers=h)
    assert r.status_code == 204, r.text

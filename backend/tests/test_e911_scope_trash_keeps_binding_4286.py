"""#4286: a scope (or its subnet) sent to the Trash keeps the E911 binding on a reservation's row.

#4038 kept the address row but deactivated its binding, so the location read
"0 active bindings" while the scope sat in the Trash. Now the soft delete leaves
a bound reservation's row exactly as it is (static_dhcp, binding active), the
restore finds it there, and a permanent delete that would take the binding is
refused with a 409 naming it.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope
from app.models.e911 import ERLBinding
from tests.test_dhcp_static_readdress_live_lease import (
    OLD,
    _group,
    _reservation,
    _row,
    _scope,
    _superadmin_token,
)
from tests.test_e911_address_row_bindings_3899 import _bind_ip, _erl, _ip_binding_rows


async def _setup(db: AsyncSession, *, bound: bool = True):
    grp, _ = await _group(db, servers=0)
    subnet, scope = await _scope(db, grp)
    await _reservation(db, scope)
    erl = await _erl(db)
    if bound:
        await _bind_ip(db, erl, await _row(db, subnet, OLD))
    await db.commit()
    return subnet, scope, erl


async def _active(db: AsyncSession, erl_id) -> int:
    res = await db.execute(
        select(ERLBinding)
        .where(ERLBinding.erl_id == erl_id, ERLBinding.is_active.is_(True))
        .execution_options(populate_existing=True)
    )
    return len(res.scalars().all())


@pytest.mark.asyncio
async def test_soft_scope_delete_keeps_the_binding_and_restore_too(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, scope, erl = await _setup(db_session)
    scope_id, erl_id = scope.id, erl.id

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)
    assert r.status_code == 204, r.text
    (row,) = await _ip_binding_rows(db_session, erl)
    assert str(row.address) == OLD and row.status == "static_dhcp"
    assert await _active(db_session, erl_id) == 1

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{scope_id}/restore", headers=h)
    assert r.status_code == 200, r.text
    (row,) = await _ip_binding_rows(db_session, erl)
    assert row.status == "static_dhcp" and row.static_assignment_id is not None
    assert await _active(db_session, erl_id) == 1


@pytest.mark.asyncio
async def test_scope_without_a_bound_reservation_still_drops_its_mirror(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, scope, _erl_ = await _setup(db_session, bound=False)
    subnet_id = subnet.id
    r = await client.delete(f"/api/v1/dhcp/scopes/{scope.id}", headers=h)
    assert r.status_code == 204, r.text
    db_session.expire_all()
    s = await db_session.get(type(subnet), subnet_id)
    assert await _row(db_session, s, OLD) is None


@pytest.mark.asyncio
async def test_subnet_to_the_trash_keeps_the_reservations_binding(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    subnet, _scope_, erl = await _setup(db_session)
    erl_id = erl.id
    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=h)
    assert r.status_code == 204, r.text
    (row,) = await _ip_binding_rows(db_session, erl)
    assert str(row.address) == OLD and row.status == "static_dhcp"
    assert await _active(db_session, erl_id) == 1


@pytest.mark.asyncio
async def test_permanent_scope_delete_and_trash_purge_refuse_naming_the_binding(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    _subnet, scope, erl = await _setup(db_session)
    scope_id, erl_name, erl_id = scope.id, erl.name, erl.id

    r = await client.delete(f"/api/v1/dhcp/scopes/{scope_id}?permanent=true", headers=h)
    assert r.status_code == 409, r.text
    assert OLD in r.json()["detail"] and erl_name in r.json()["detail"]
    db_session.expire_all()
    assert await db_session.get(DHCPScope, scope_id) is not None

    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)).status_code == 204
    r = await client.delete(f"/api/v1/admin/trash/dhcp_scope/{scope_id}", headers=h)
    assert r.status_code == 409, r.text
    assert OLD in r.json()["detail"] and erl_name in r.json()["detail"]
    assert await _active(db_session, erl_id) == 1


@pytest.mark.asyncio
async def test_nightly_sweep_holds_back_a_trashed_scope_with_a_bound_reservation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from sqlalchemy import text

    from app.models.settings import PlatformSettings
    from app.tasks.trash_purge import _sweep

    h = {"Authorization": f"Bearer {await _superadmin_token(db_session)}"}
    _subnet, scope, erl = await _setup(db_session)
    scope_id, erl_id = scope.id, erl.id
    if (await db_session.execute(select(PlatformSettings).limit(1))).scalar_one_or_none() is None:
        db_session.add(PlatformSettings())
        await db_session.commit()
    assert (await client.delete(f"/api/v1/dhcp/scopes/{scope_id}", headers=h)).status_code == 204
    await db_session.execute(
        text("UPDATE dhcp_scope SET deleted_at = now() - interval '400 days' WHERE id = :i"),
        {"i": scope_id},
    )
    await db_session.execute(
        text("UPDATE dhcp_static_assignment SET deleted_at = now() - interval '400 days'")
    )
    await db_session.commit()

    await _sweep()
    db_session.expire_all()
    assert await _active(db_session, erl_id) == 1
    row = (await db_session.execute(select(DHCPScope).where(DHCPScope.id == scope_id))).first()
    assert row is None  # hidden by the soft-delete filter, still present below
    n = (
        await db_session.execute(
            text("SELECT count(*) FROM dhcp_scope WHERE id = :i"), {"i": scope_id}
        )
    ).scalar_one()
    assert n == 1

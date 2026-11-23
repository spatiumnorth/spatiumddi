"""A queued permanent delete approved by a non-superadmin stays pending (#4790).

The permanent branch needs a superadmin. That refusal is about THIS approver, so
it must leave the request pending for a superadmin (as #3646 did for DHCP
reservations) rather than ending it ``failed`` for good, and the queue must not
offer Approve to an approver the server will refuse.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from app.models.ipam import Subnet
from tests.test_approval_workflows import (
    _auth,
    _enable_delete_subnet_policy,
    _enable_module,
    _subnet,
    _user,
)

_APPROVE = {"action": "approve", "resource_type": "change_request"}
_DELETE = {"action": "delete", "resource_type": "subnet"}


async def _queue_permanent(client: AsyncClient, db: AsyncSession) -> tuple[Subnet, str]:
    await _enable_module(db)
    await _enable_delete_subnet_policy(db)
    subnet = await _subnet(db)
    _, etoken = await _user(db, name="editor", permissions=[_DELETE])
    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}?permanent=true&force=true", headers=_auth(etoken)
    )
    assert r.status_code == 202, r.text
    return subnet, r.json()["change_request_id"]


@pytest.mark.asyncio
async def test_non_superadmin_approver_leaves_request_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    subnet, cr_id = await _queue_permanent(client, db_session)
    _, atoken = await _user(db_session, name="approver", permissions=[_APPROVE, _DELETE])

    row = next(
        x
        for x in (await client.get("/api/v1/change-requests", headers=_auth(atoken))).json()
        if x["id"] == cr_id
    )
    assert row["can_approve"] is False
    assert "superadmin" in row["approve_blocked_reason"]

    r = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atoken), json={}
    )
    assert r.status_code == 403, r.text
    assert "superadmin approver" in r.json()["detail"]

    db_session.expire_all()
    cr = await db_session.get(ChangeRequest, uuid.UUID(cr_id))
    assert cr is not None and cr.state == "pending"

    # A superadmin can still approve it, and it applies.
    _, satoken = await _user(db_session, name="sa-approver", superadmin=True)
    row = next(
        x
        for x in (await client.get("/api/v1/change-requests", headers=_auth(satoken))).json()
        if x["id"] == cr_id
    )
    assert row["can_approve"] is True
    r = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(satoken), json={}
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "executed"
    db_session.expire_all()
    assert await db_session.get(Subnet, subnet.id) is None


@pytest.mark.asyncio
async def test_apply_refuses_non_superadmin_as_permission_error(
    db_session: AsyncSession,
) -> None:
    """The apply's own refusal is the kind the spine leaves pending."""
    from app.services.ai import operations
    from app.services.ai.operations import OperationPermissionError

    subnet = await _subnet(db_session)
    user, _ = await _user(db_session, name="approver", permissions=[_APPROVE, _DELETE])
    op = operations.get_operation("delete_subnet")
    assert op is not None
    args = op.args_model(subnet_id=subnet.id, force=True, permanent=True)
    with pytest.raises(OperationPermissionError):
        await op.apply(db_session, user, args)

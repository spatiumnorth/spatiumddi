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


# ── The direct (not queued) path keeps its 403 ────────────────────────────────
#
# The routes call ``op.apply`` themselves when nothing queues the request. The
# apply now raises an ``OperationPermissionError``, which no route translates
# (a bare ``PermissionError`` is a 500), so the gate refuses first.


@pytest.mark.asyncio
@pytest.mark.parametrize("module_on", [False, True], ids=["module-off", "module-on-no-policy"])
async def test_direct_permanent_delete_by_non_superadmin_is_403(
    client: AsyncClient, db_session: AsyncSession, module_on: bool
) -> None:
    from app.models.ipam import IPBlock, IPSpace

    if module_on:
        await _enable_module(db_session)
    subnet = await _subnet(db_session)
    block = await db_session.get(IPBlock, subnet.block_id)
    space = await db_session.get(IPSpace, subnet.space_id)
    assert block is not None and space is not None
    subnet_id, block_id, space_id = subnet.id, block.id, space.id
    _, token = await _user(
        db_session,
        name="editor",
        permissions=[
            _DELETE,
            {"action": "delete", "resource_type": "ip_block"},
            {"action": "delete", "resource_type": "ip_space"},
        ],
    )
    await db_session.commit()
    for url in (
        f"/api/v1/ipam/subnets/{subnet_id}?permanent=true&force=true",
        f"/api/v1/ipam/blocks/{block_id}?permanent=true",
        f"/api/v1/ipam/spaces/{space_id}?permanent=true",
    ):
        r = await client.delete(url, headers=_auth(token))
        assert r.status_code == 403, (url, r.status_code, r.text)
        assert r.json()["detail"] == "Superadmin required", url
    db_session.expire_all()
    assert await db_session.get(Subnet, subnet_id) is not None


@pytest.mark.asyncio
async def test_proposal_apply_permanent_delete_by_non_superadmin_is_403(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.ai import AIOperationProposal
    from app.services.ai import operations

    subnet = await _subnet(db_session)
    subnet_id = subnet.id
    user, token = await _user(db_session, name="editor", permissions=[_DELETE])
    row = AIOperationProposal(
        session_id=None,
        user_id=user.id,
        operation="delete_subnet",
        args={"subnet_id": str(subnet_id), "force": True, "permanent": True},
        preview_text="p",
        expires_at=operations.expires_at_default(),
    )
    db_session.add(row)
    await db_session.commit()
    r = await client.post(f"/api/v1/ai/proposals/{row.id}/apply", headers=_auth(token), json={})
    assert r.status_code == 403, r.text
    db_session.expire_all()
    assert await db_session.get(Subnet, subnet_id) is not None

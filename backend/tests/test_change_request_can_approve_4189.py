"""The change-request list says per row whether the caller may approve (#4189).

``can_approve`` is computed with the approve endpoint's own check
(``approval_refusal``), so the queue never offers Approve to an approver the
server then refuses.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_approval_workflows import (
    _auth,
    _enable_delete_subnet_policy,
    _enable_module,
    _subnet,
    _user,
)

_APPROVE = {"action": "approve", "resource_type": "change_request"}
_DELETE = {"action": "delete", "resource_type": "subnet"}


async def _queue(client: AsyncClient, db: AsyncSession) -> tuple[str, str]:
    await _enable_module(db)
    await _enable_delete_subnet_policy(db)
    subnet = await _subnet(db)
    _, rtoken = await _user(db, name="requester", permissions=[_DELETE])
    r = await client.delete(f"/api/v1/ipam/subnets/{subnet.id}", headers=_auth(rtoken))
    return r.json()["change_request_id"], rtoken


async def _row(client: AsyncClient, token: str, cr_id: str) -> dict:
    r = await client.get("/api/v1/change-requests", headers=_auth(token))
    assert r.status_code == 200, r.text
    return next(x for x in r.json() if x["id"] == cr_id)


@pytest.mark.asyncio
async def test_can_approve_false_without_operation_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    cr_id, _ = await _queue(client, db_session)
    _, atoken = await _user(db_session, name="approver-noperm", permissions=[_APPROVE])
    row = await _row(client, atoken, cr_id)
    assert row["can_approve"] is False
    assert row["approve_blocked_reason"] == "Permission denied: need 'delete' on 'subnet'"
    # The endpoint refuses with the same words.
    r = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atoken), json={}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == row["approve_blocked_reason"]


@pytest.mark.asyncio
async def test_can_approve_true_with_operation_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    cr_id, rtoken = await _queue(client, db_session)
    _, atoken = await _user(db_session, name="approver", permissions=[_APPROVE, _DELETE])
    row = await _row(client, atoken, cr_id)
    assert row["can_approve"] is True
    assert row["approve_blocked_reason"] is None
    # The requester sees their own row, never approvable by them.
    own = await client.get(f"/api/v1/change-requests/{cr_id}", headers=_auth(rtoken))
    assert own.json()["can_approve"] is False
    assert "own" in own.json()["approve_blocked_reason"]

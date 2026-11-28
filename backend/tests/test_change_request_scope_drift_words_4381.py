"""A scope-drift refusal names what the approver can do, not what it may not (#4381)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress
from tests.test_approval_workflows import (
    _auth,
    _enable_delete_subnet_policy,
    _enable_module,
    _subnet,
    _user,
)

_APPROVE = {"action": "approve", "resource_type": "change_request"}
_DELETE = {"action": "delete", "resource_type": "subnet"}


@pytest.mark.asyncio
async def test_scope_drift_refusal_names_reject_not_cancel(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    await _enable_delete_subnet_policy(db_session)
    subnet = await _subnet(db_session, "10.24.9.0/24")
    _, rtoken = await _user(db_session, name="requester", permissions=[_DELETE])
    # A permanent delete needs a superadmin approver (#4790); the words under
    # test are the scope-changed refusal, which that approver still gets.
    _, atoken = await _user(
        db_session, name="approver", permissions=[_APPROVE, _DELETE], superadmin=True
    )
    r = await client.delete(
        f"/api/v1/ipam/subnets/{subnet.id}?permanent=true&force=true", headers=_auth(rtoken)
    )
    assert r.status_code == 202, r.text
    cr_id = r.json()["change_request_id"]
    db_session.add(IPAddress(subnet_id=subnet.id, address="10.24.9.10", status="allocated"))
    await db_session.commit()

    r2 = await client.post(
        f"/api/v1/change-requests/{cr_id}/approve", headers=_auth(atoken), json={}
    )
    assert r2.status_code == 409, r2.text
    detail = r2.json()["detail"]
    assert "scope changed" in detail
    assert "Reject it" in detail
    assert "requester" in detail
    # The approver may not cancel; the words must not send it there.
    assert not detail.lower().startswith("cancel")
    assert "— cancel and re-submit" not in detail

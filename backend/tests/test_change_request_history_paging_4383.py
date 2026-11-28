"""The admin change-request list filters several states and reports a total (#4383)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from tests.test_approval_workflows import _auth, _enable_module, _user

_APPROVE = {"action": "approve", "resource_type": "change_request"}


def _cr(user_id: uuid.UUID, state: str, i: int) -> ChangeRequest:
    return ChangeRequest(
        origin="gate",
        operation="delete_subnet",
        resource_type="subnet",
        resource_display=f"r{i}",
        args={},
        preview_text=f"p{i}",
        requested_by_user_id=user_id,
        requested_by_display="u",
        risk_reason="x",
        state=state,
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )


@pytest.mark.asyncio
async def test_list_filters_several_states_and_reports_total(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    user, token = await _user(db_session, name="admin-ish", permissions=[_APPROVE])
    states = ["pending", "executed", "rejected", "cancelled", "executed", "pending", "failed"]
    for i, st in enumerate(states):
        db_session.add(_cr(user.id, st, i))
    await db_session.commit()

    decided = "executed,rejected,failed,expired,cancelled"
    first = await client.get(
        "/api/v1/change-requests", headers=_auth(token), params={"state": decided, "limit": 3}
    )
    assert first.status_code == 200, first.text
    assert first.headers["x-total-count"] == "5"
    assert len(first.json()) == 3
    assert all(r["state"] != "pending" for r in first.json())
    rest = await client.get(
        "/api/v1/change-requests",
        headers=_auth(token),
        params={"state": decided, "limit": 3, "offset": 3},
    )
    assert len(rest.json()) == 2
    assert not {r["id"] for r in first.json()} & {r["id"] for r in rest.json()}
    # A single state still works, and the total counts that filter.
    one = await client.get(
        "/api/v1/change-requests", headers=_auth(token), params={"state": "pending"}
    )
    assert one.headers["x-total-count"] == "2"

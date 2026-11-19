"""The request list says per row whether the caller may approve (#4241, #4242).

``can_approve`` / ``approve_blocked_reason`` come from the approve endpoint's
own check, so an approver who holds Change Approver but not the operation's own
permission is not offered an enabled Approve, and a request whose requester's
account was deleted says what the approver can do instead of "cancel".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from tests.test_request_resource_picker import REQUESTER_PERMS, _auth, _enable_module, _user

_APPROVE = {"action": "approve", "resource_type": "change_request"}

# operation -> the permission the approver must hold to provision it
_OPS = {
    "allocate_subnet": ("write", "subnet"),
    "create_ip_address": ("write", "subnet"),
    "create_dns_record": ("write", "dns_record"),
    "create_dhcp_static": ("write", "dhcp_static"),
}


async def _pending(db: AsyncSession, operation: str, requester_id: object) -> str:
    cr = ChangeRequest(
        origin="portal",
        operation=operation,
        resource_type="x",
        resource_display=operation,
        args={},
        preview_text="p",
        requested_by_user_id=requester_id,
        requested_by_display="someone",
        risk_reason="portal",
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )
    db.add(cr)
    await db.commit()
    return str(cr.id)


async def _rows(client: AsyncClient, token: str) -> dict[str, dict]:
    r = await client.get("/api/v1/requests", headers=_auth(token))
    assert r.status_code == 200, r.text
    return {x["id"]: x for x in r.json()}


@pytest.mark.asyncio
async def test_can_approve_follows_the_operations_own_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    requester, _ = await _user(db_session, permissions=REQUESTER_PERMS)
    ids = {op: await _pending(db_session, op, requester.id) for op in _OPS}
    _, plain = await _user(db_session, permissions=REQUESTER_PERMS + [_APPROVE])
    _, full = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [_APPROVE]
        + [{"action": a, "resource_type": t} for a, t in _OPS.values()],
    )

    blocked = await _rows(client, plain)
    allowed = await _rows(client, full)
    for op, (action, rtype) in _OPS.items():
        row = blocked[ids[op]]
        assert row["can_approve"] is False, op
        assert row["approve_blocked_reason"] == (
            f"Permission denied: need '{action}' on '{rtype}'"
        ), op
        assert allowed[ids[op]]["can_approve"] is True, op
        assert allowed[ids[op]]["approve_blocked_reason"] is None, op
    # The press is refused with the very words the row carried.
    r = await client.post(
        f"/api/v1/requests/{ids['create_dhcp_static']}/approve", headers=_auth(plain), json={}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == blocked[ids["create_dhcp_static"]]["approve_blocked_reason"]


@pytest.mark.asyncio
async def test_deleted_requester_row_says_reject_not_cancel(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    cr_id = await _pending(db_session, "create_dns_record", None)
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [_APPROVE, {"action": "write", "resource_type": "dns_record"}],
    )
    row = (await _rows(client, token))[cr_id]
    assert row["can_approve"] is False
    reason = row["approve_blocked_reason"]
    assert "Reject it" in reason
    assert "cancel" not in reason.lower()
    r = await client.post(f"/api/v1/requests/{cr_id}/approve", headers=_auth(token), json={})
    assert r.status_code == 409
    assert r.json()["detail"] == reason

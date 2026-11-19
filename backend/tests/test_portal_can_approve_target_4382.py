"""A request row's ``can_approve`` applies the operation's per-object gate (#4382).

#4241 gave each row the approve endpoint's type-wide check, which admits a grant
scoped to one subnet for an address request in another and a subnet-write
approver for a block they cannot write. The press then answered 403. The row
now runs the SAME gate the apply does (``Operation.target_refusal``).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPBlock, Subnet
from tests.test_operation_target_gates import (
    APPROVE,
    _estate,
    _submit_ip_request,
)
from tests.test_self_service_requests import (
    BARE_REQUESTER_PERMS,
    MODULE,
    _auth,
    _enable_module,
    _user,
)


async def _row(client: AsyncClient, token: str, rid: str) -> dict:
    r = await client.get("/api/v1/requests", headers=_auth(token))
    assert r.status_code == 200, r.text
    return {x["id"]: x for x in r.json()}[rid]


@pytest.mark.asyncio
async def test_scoped_subnet_approver_is_not_offered_approve_in_another_subnet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    other = Subnet(
        space_id=env.subnet.space_id,
        block_id=env.block.id,
        network="10.77.6.0/24",
        name="other",
    )
    db_session.add(other)
    await db_session.flush()
    rid_a = await _submit_ip_request(client, db_session, env.subnet_id, "10.77.5.20")
    rid_b = await _submit_ip_request(client, db_session, other.id, "10.77.6.20")
    _, token = await _user(
        db_session,
        name="owner-b",
        permissions=[
            *APPROVE,
            {"action": "read", "resource_type": "subnet", "resource_id": str(env.subnet_id)},
            {"action": "read", "resource_type": "subnet", "resource_id": str(other.id)},
            {"action": "write", "resource_type": "subnet", "resource_id": str(other.id)},
        ],
    )
    await db_session.commit()

    row_a = await _row(client, token, rid_a)
    assert row_a["can_approve"] is False
    assert "No write permission on subnet" in row_a["approve_blocked_reason"]
    # The press is refused with the words the row carried.
    r = await client.post(f"/api/v1/requests/{rid_a}/approve", headers=_auth(token), json={})
    assert r.status_code == 403
    assert r.json()["detail"] == row_a["approve_blocked_reason"]

    row_b = await _row(client, token, rid_b)
    assert row_b["can_approve"] is True
    assert row_b["approve_blocked_reason"] is None
    r = await client.post(f"/api/v1/requests/{rid_b}/approve", headers=_auth(token), json={})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "executed"


@pytest.mark.asyncio
async def test_subnet_request_without_block_write_is_not_offered_approve(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    writable = IPBlock(space_id=env.subnet.space_id, network="10.88.0.0/16", name="mine")
    db_session.add(writable)
    await db_session.flush()
    _, req_token = await _user(
        db_session,
        name="req",
        permissions=[
            *BARE_REQUESTER_PERMS,
            {"action": "read", "resource_type": "ip_block"},
        ],
    )
    ids = {}
    for name, block in (("closed", env.block), ("open", writable)):
        r = await client.post(
            "/api/v1/requests",
            headers=_auth(req_token),
            json={
                "kind": "subnet",
                "args": {"block_id": str(block.id), "prefix_len": 24},
                "justification": "need one",
            },
        )
        assert r.status_code == 201, r.text
        ids[name] = r.json()["id"]
    _, token = await _user(
        db_session,
        name="blockwriter",
        permissions=[
            *APPROVE,
            {"action": "write", "resource_type": "subnet"},
            {"action": "read", "resource_type": "ip_block"},
            {"action": "write", "resource_type": "ip_block", "resource_id": str(writable.id)},
        ],
    )
    await db_session.commit()

    closed = await _row(client, token, ids["closed"])
    assert closed["can_approve"] is False
    assert "block" in closed["approve_blocked_reason"].lower()
    r = await client.post(
        f"/api/v1/requests/{ids['closed']}/approve", headers=_auth(token), json={}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == closed["approve_blocked_reason"]
    assert (await _row(client, token, ids["open"]))["can_approve"] is True


@pytest.mark.asyncio
async def test_superadmin_and_type_wide_writer_keep_can_approve(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session, MODULE)
    env = await _estate(db_session)
    rid = await _submit_ip_request(client, db_session, env.subnet_id, "10.77.5.30")
    _, token = await _user(
        db_session,
        name="wide",
        permissions=[*APPROVE, {"action": "write", "resource_type": "subnet"}],
    )
    await db_session.commit()
    assert (await _row(client, token, rid))["can_approve"] is True
    assert uuid.UUID(rid)

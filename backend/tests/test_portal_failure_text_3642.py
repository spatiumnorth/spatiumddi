"""A failed portal request's text is composed for the requester (#3642).

* collision warnings do not name the address, subnet or pool bounds they found;
* a target the requester can no longer read is answered as an unknown id;
* a non-HTTP exception at apply is worded, not stored as ``str(exc)``;
* the operation arguments carry the column-width bounds, so an over-long
  value is refused at submit instead of reaching the database.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.services.ai import operations
from tests.test_self_service_requests import (
    BARE_REQUESTER_PERMS,
    _auth,
    _block,
    _enable_module,
    _patched_apply,
    _pending_ip_request,
    _user,
)

WARNINGS = {
    "warnings": [
        {
            "kind": "fqdn_collision",
            "fqdn": "web.example.com",
            "existing_ip": "10.99.9.9",
            "existing_subnet": "10.99.9.0/24",
        },
        {
            "kind": "mac_collision",
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "existing_ip": "10.99.9.8",
            "existing_subnet": "10.99.9.0/24",
        },
        {
            "kind": "dynamic_pool",
            "address": "10.77.0.10",
            "pool_start": "10.77.0.5",
            "pool_end": "10.77.0.99",
        },
    ],
    "requires_confirmation": True,
}


async def _approve(client: AsyncClient, req_id: str, token: str) -> dict:
    resp = await client.post(
        f"/api/v1/requests/{req_id}/approve", headers=_auth(token), json={"decision_note": "go"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "failed"
    return body


@pytest.mark.asyncio
async def test_collision_warnings_name_nothing_the_requester_cannot_read(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    req_id, token, _, _ = await _pending_ip_request(client, db_session)
    _patched_apply(monkeypatch, HTTPException(status_code=409, detail=WARNINGS))
    err = (await _approve(client, req_id, token))["error"]
    assert "web.example.com" in err
    for leaked in ("10.99.9.9", "10.99.9.8", "10.99.9.0/24", "10.77.0.5", "10.77.0.99"):
        assert leaked not in err


@pytest.mark.asyncio
async def test_unreadable_target_is_answered_as_unknown(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    req_id, token, subnet, _ = await _pending_ip_request(client, db_session)
    subnet_id, network = subnet.id, str(subnet.network)
    # The requester lost read on subnets after submitting.
    from sqlalchemy import select

    from app.models.change_request import ChangeRequest

    cr = (await db_session.execute(select(ChangeRequest))).scalars().one()
    requester = cr.requested_by_user_id
    from app.models.auth import User

    user = await db_session.get(User, requester)
    assert user is not None
    for g in user.groups:
        for role in g.roles:
            role.permissions = [
                p for p in role.permissions if p["resource_type"] not in ("subnet", "ip_block")
            ]
            flag_modified(role, "permissions")
    await db_session.commit()
    _patched_apply(
        monkeypatch,
        HTTPException(status_code=409, detail=f"Address already used in {network}"),
    )
    err = (await _approve(client, req_id, token))["error"]
    assert network not in err
    assert err == f"Subnet {subnet_id} not found"


@pytest.mark.asyncio
async def test_database_error_at_apply_is_worded(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    req_id, token, _, _ = await _pending_ip_request(client, db_session)
    _patched_apply(
        monkeypatch,
        RuntimeError(
            "(asyncpg.exceptions.StringDataRightTruncationError) value too long for type"
            " character varying(255) [SQL: INSERT INTO subnet ...]"
        ),
    )
    err = (await _approve(client, req_id, token))["error"]
    assert "INSERT" not in err and "asyncpg" not in err and "varying" not in err
    assert "internal error" in err


@pytest.mark.asyncio
async def test_over_long_subnet_name_is_refused_at_submit(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    block = await _block(db_session, "10.88.0.0/16")
    _, token = await _user(
        db_session,
        name="req",
        permissions=[
            *BARE_REQUESTER_PERMS,
            {"action": "read", "resource_type": "ip_block"},
        ],
    )
    resp = await client.post(
        "/api/v1/requests",
        headers=_auth(token),
        json={
            "kind": "subnet",
            "args": {"block_id": str(block.id), "prefix_len": 24, "name": "x" * 300},
        },
    )
    assert resp.status_code == 422, resp.text
    assert "name" in str(resp.json()["detail"])


def test_operation_args_carry_column_width_bounds() -> None:
    for name, field, bound in (
        ("allocate_subnet", "name", 255),
        ("create_dns_record", "name", 255),
        ("create_dhcp_static", "hostname", 255),
        ("create_ip_address", "hostname", 255),
        ("create_ip_address", "fqdn", 512),
    ):
        info = operations._OPERATIONS[name].args_model.model_fields[field]
        assert any(getattr(m, "max_length", None) == bound for m in info.metadata), (name, field)

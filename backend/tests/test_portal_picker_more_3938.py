"""#3938 — the New request pickers flag ``truncated`` whenever a further
readable match exists past the page, not only when the scan cap was hit."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_request_resource_picker import (
    REQUESTER_PERMS,
    _auth,
    _enable_module,
    _subnets,
    _user,
)


@pytest.mark.asyncio
async def test_picker_says_when_more_readable_rows_match_than_it_shows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    await _subnets(db_session, [f"10.{i}.0.0/24" for i in range(21)])
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "subnet"}],
    )
    await db_session.commit()
    url = "/api/v1/requests/resource-options"

    body = (await client.get(url, headers=_auth(token), params={"resource": "subnet"})).json()
    assert len(body["options"]) == 20
    assert body["truncated"] is True

    # Room for all of them: nothing is cut, so nothing is flagged.
    body = (
        await client.get(url, headers=_auth(token), params={"resource": "subnet", "limit": 50})
    ).json()
    assert len(body["options"]) == 21
    assert body["truncated"] is False


@pytest.mark.asyncio
async def test_picker_exactly_at_the_limit_is_not_flagged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    await _subnets(db_session, [f"10.{i}.0.0/24" for i in range(20)])
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "subnet"}],
    )
    await db_session.commit()
    body = (
        await client.get(
            "/api/v1/requests/resource-options",
            headers=_auth(token),
            params={"resource": "subnet"},
        )
    ).json()
    assert len(body["options"]) == 20
    assert body["truncated"] is False

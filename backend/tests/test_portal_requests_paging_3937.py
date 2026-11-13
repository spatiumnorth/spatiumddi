"""#3937 — ``GET /requests`` pages with ``offset`` and reports ``X-Total-Count``."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_request import ChangeRequest
from tests.test_request_resource_picker import REQUESTER_PERMS, _auth, _enable_module, _user


@pytest.mark.asyncio
async def test_request_list_pages_and_reports_the_total(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    approver, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "approve", "resource_type": "change_request"}],
    )
    for i in range(7):
        db_session.add(
            ChangeRequest(
                origin="portal",
                operation="create_subnet",
                resource_type="subnet",
                resource_display=f"r{i}",
                args={},
                preview_text=f"p{i}",
                requested_by_user_id=approver.id,
                requested_by_display="u",
                risk_reason="portal",
                expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            )
        )
    await db_session.commit()

    first = await client.get("/api/v1/requests", headers=_auth(token), params={"limit": 3})
    assert first.status_code == 200, first.text
    assert first.headers["x-total-count"] == "7"
    assert len(first.json()) == 3
    last = await client.get(
        "/api/v1/requests", headers=_auth(token), params={"limit": 3, "offset": 6}
    )
    assert last.headers["x-total-count"] == "7"
    assert len(last.json()) == 1
    seen = {r["id"] for r in first.json()} | {
        r["id"]
        for r in (
            await client.get(
                "/api/v1/requests", headers=_auth(token), params={"limit": 3, "offset": 3}
            )
        ).json()
    }
    assert len(seen) == 6
    assert not seen & {r["id"] for r in last.json()}

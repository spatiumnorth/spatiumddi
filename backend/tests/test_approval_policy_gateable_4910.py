"""The editor reads what a policy can be saved for from the server (#4910)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_approval_workflows import _auth, _user


@pytest.mark.asyncio
async def test_gateable_pairs_listed_and_all_saveable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, name="root", superadmin=True)
    r = await client.get("/api/v1/change-requests/policies/gateable", headers=_auth(token))
    assert r.status_code == 200, r.text
    pairs = r.json()
    assert {"action": "admin", "resource_type": "manage_block_sync"} in pairs
    assert {"action": "delete", "resource_type": "subnet"} in pairs
    assert not {p["action"] for p in pairs} & {"bulk_delete", "bulk_edit", "factory_reset"}
    # Every pair offered is one the server then accepts.
    for i, p in enumerate(pairs):
        c = await client.post(
            "/api/v1/change-requests/policies",
            headers=_auth(token),
            json={"name": f"p{i}", **p},
        )
        assert c.status_code == 201, (p, c.text)


@pytest.mark.asyncio
async def test_gateable_pairs_superadmin_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, name="plain")
    r = await client.get("/api/v1/change-requests/policies/gateable", headers=_auth(token))
    assert r.status_code == 403

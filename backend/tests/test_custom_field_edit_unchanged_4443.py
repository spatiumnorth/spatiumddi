"""#4443: an edit does not re-validate a custom-field value the row already holds."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_custom_field_multi_select_date_4288 import _define, _setup, _subnet


@pytest.mark.asyncio
async def test_edit_not_blocked_by_option_removed_from_definition_4443(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sp, blk = await _setup(db_session)
    r = await _define(client, headers, "sites", "multi_select", ["a", "b"])
    fid = r.json()["id"]
    sub = await _subnet(client, headers, sp, blk, "10.1.0.0/24", sites=["a", "b"])
    assert sub.status_code == 201, sub.text
    sid = sub.json()["id"]
    r = await client.put(f"/api/v1/custom-fields/{fid}", headers=headers, json={"options": ["a"]})
    assert r.status_code == 200, r.text
    # Full dict resent unchanged, plus a rename: not blocked.
    upd = await client.put(
        f"/api/v1/ipam/subnets/{sid}",
        headers=headers,
        json={"name": "renamed", "custom_fields": {"sites": ["a", "b"]}},
    )
    assert upd.status_code == 200, upd.text
    # Changing the value to a removed option is still refused.
    bad = await client.put(
        f"/api/v1/ipam/subnets/{sid}", headers=headers, json={"custom_fields": {"sites": ["b"]}}
    )
    assert bad.status_code == 422, bad.text

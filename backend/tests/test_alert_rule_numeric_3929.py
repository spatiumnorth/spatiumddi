"""#3929 — a non-numeric threshold is a 422, never stored as the default."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from .test_alert_rule_param_validation_2746 import _body, _hdr

pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("field", ["threshold_percent", "min_free_addresses"])
async def test_non_numeric_value_is_422(
    client: AsyncClient, db_session: AsyncSession, field: str
) -> None:
    h = await _hdr(db_session)
    r = await client.post(
        "/api/v1/alerts/rules", json=_body("subnet_utilization", **{field: "85-"}), headers=h
    )
    assert r.status_code == 422, r.text
    ok = await client.post(
        "/api/v1/alerts/rules", json=_body("subnet_utilization", threshold_percent=80), headers=h
    )
    r2 = await client.patch(
        f"/api/v1/alerts/rules/{ok.json()['id']}", json={field: "85-"}, headers=h
    )
    assert r2.status_code == 422, r2.text

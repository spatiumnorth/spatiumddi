"""#3901: every ERL answer carries the real binding_count, not the default 0."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import ERLBinding
from tests.test_e911_delete_guard_3891 import _admin, _erl, _subnet


@pytest.mark.asyncio
async def test_every_erl_answer_reports_its_bindings(client: AsyncClient, db_session: AsyncSession):
    h = await _admin(db_session)
    erl = await _erl(db_session)
    sub = await _subnet(db_session)
    db_session.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=sub.id))
    await db_session.flush()

    got = await client.get(f"/api/v1/e911/erls/{erl.id}", headers=h)
    assert got.json()["binding_count"] == 1

    patched = await client.patch(f"/api/v1/e911/erls/{erl.id}", json={"notes": "x"}, headers=h)
    assert patched.status_code == 200, patched.text
    assert patched.json()["binding_count"] == 1

    verdict = await client.post(
        f"/api/v1/e911/erls/{erl.id}/validation", json={"state": "validated"}, headers=h
    )
    assert verdict.status_code == 200, verdict.text
    assert verdict.json()["binding_count"] == 1

    loc = await client.get("/api/v1/e911/location", params={"ip": "10.47.1.5"}, headers=h)
    assert loc.status_code == 200, loc.text
    body = loc.json()
    assert body["found"] is True and body["erl"]["id"] == str(erl.id)
    assert body["erl"]["binding_count"] == 1

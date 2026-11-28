"""The requester's re-run preview is composed under the requester's reads.

A name that clashes with a record the requester cannot read is worded
generically for them; the approver's view keeps the full text.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_operation_create_ip_dns_2900 import _subnet_with_zone, _user
from tests.test_portal_address_cname_3647 import _body, _cname, _requester_hdr


@pytest.mark.asyncio
async def test_requester_current_preview_does_not_name_unreadable_clash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, appr = await _subnet_with_zone(db_session, client, admin)
    hdr = await _requester_hdr(db_session)
    resp = await client.post("/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.70", "late"))
    assert resp.status_code == 201, resp.text
    rid = resp.json()["id"]
    await _cname(db_session, zone.id, "late")
    await db_session.commit()

    url = f"/api/v1/requests/{rid}/current-preview"
    mine = (await client.get(url, headers=hdr)).json()
    assert mine["ok"] is False
    assert "target.example.org" not in mine["detail"]

    theirs = (await client.get(url, headers=appr)).json()
    assert theirs["ok"] is False and "target.example.org" in theirs["detail"]

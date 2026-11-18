"""#3935 — a decision on a request already decided elsewhere is a plain 409.

The refusal used to quote the schema ("change request <uuid> is 'executed',
expected 'pending'" / "state='cancelled'"); it now says what happened, who did
it and when, in the Requests page's own words.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_operation_create_ip_dns_2900 import _subnet_with_zone, _user
from tests.test_portal_address_cname_3647 import _body, _requester_hdr


async def _submit(client: AsyncClient, hdr: dict, sid: str, address: str) -> str:
    resp = await client.post("/api/v1/requests", headers=hdr, json=_body(sid, address, "h"))
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _plain(detail: str, rid: str) -> None:
    assert rid not in detail
    assert "state=" not in detail and "expected" not in detail and "'" not in detail


@pytest.mark.asyncio
async def test_decisions_on_a_decided_request_are_refused_in_plain_words(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.core.security import create_access_token

    admin = await _user(db_session, "admin")
    sid, _zone, _ = await _subnet_with_zone(db_session, client, admin)
    hdr = await _requester_hdr(db_session)
    appr = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}

    # Withdrawn by the requester, then approved / rejected.
    r1 = await _submit(client, hdr, sid, "10.98.5.50")
    assert (
        await client.post(f"/api/v1/requests/{r1}/cancel", headers=hdr, json={})
    ).status_code == 200
    resp = await client.post(f"/api/v1/requests/{r1}/approve", headers=appr, json={})
    assert resp.status_code == 409, resp.text
    _plain(resp.json()["detail"], r1)
    assert "already cancelled" in resp.json()["detail"]
    resp = await client.post(f"/api/v1/requests/{r1}/reject", headers=appr, json={})
    assert resp.status_code == 409, resp.text
    _plain(resp.json()["detail"], r1)

    # Provisioned elsewhere, then withdrawn by the requester.
    r2 = await _submit(client, hdr, sid, "10.98.5.51")
    assert (
        await client.post(f"/api/v1/requests/{r2}/approve", headers=appr, json={})
    ).status_code == 200
    resp = await client.post(f"/api/v1/requests/{r2}/cancel", headers=hdr, json={})
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    _plain(detail, r2)
    assert "approved and provisioned" in detail and " by " in detail and " at " in detail

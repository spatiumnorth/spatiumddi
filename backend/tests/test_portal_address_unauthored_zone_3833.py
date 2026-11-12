"""#3833 — an address request in a subnet bound to a non-primary zone promises no record.

IPAM writes records only into a zone it serves as primary (#1633), so the
request must not say "publishes A ..." for a forward / secondary zone.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_operation_create_ip_dns_2900 import _subnet_with_zone, _user
from tests.test_portal_address_cname_3647 import _body, _requester_hdr


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", ["forward", "secondary"])
async def test_request_says_no_record_for_unauthored_zone(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    zone.zone_type = zone_type
    await db_session.flush()
    hdr = await _requester_hdr(db_session)
    resp = await client.post(
        "/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.30", "web01")
    )
    assert resp.status_code == 201, resp.text
    text = resp.text
    assert "publishes" not in text
    assert "no A record is published" in text
    assert f"is a {zone_type} zone" in text


@pytest.mark.asyncio
async def test_fqdn_refusal_does_not_claim_publication(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    zone.zone_type = "forward"
    await db_session.flush()
    hdr = await _requester_hdr(db_session)
    body = {
        "kind": "ip_address",
        "args": {"subnet_id": sid, "address": "10.98.5.31", "fqdn": "web02.example.org"},
        "justification": "need it",
    }
    resp = await client.post("/api/v1/requests", headers=hdr, json=body)
    assert resp.status_code == 400, resp.text
    assert "is not a name in" in resp.text
    assert "publishes in" not in resp.text

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


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", ["forward", "secondary", "stub"])
async def test_approve_creates_address_without_a_record(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    """Approval executes: address + fqdn kept, no record written, no refusal."""
    import uuid

    from sqlalchemy import func, select

    from app.core.security import create_access_token
    from app.models.dns import DNSRecord
    from app.models.ipam import IPAddress

    admin = await _user(db_session, "admin")
    sid, zone, _ = await _subnet_with_zone(db_session, client, admin)
    zone.zone_type = zone_type
    await db_session.flush()
    hdr = await _requester_hdr(db_session)
    resp = await client.post(
        "/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.32", "web03")
    )
    assert resp.status_code == 201, resp.text
    rid = resp.json()["id"]
    appr = {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}
    resp = await client.post(
        f"/api/v1/requests/{rid}/approve", headers=appr, json={"decision_note": "ok"}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "executed", resp.text
    ip = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.subnet_id == uuid.UUID(sid), IPAddress.address == "10.98.5.32"
            )
        )
    ).scalar_one()
    assert ip.dns_record_id is None
    n = await db_session.scalar(
        select(func.count()).select_from(DNSRecord).where(DNSRecord.zone_id == zone.id)
    )
    assert n == 0

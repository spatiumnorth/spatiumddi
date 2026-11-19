"""#3934 — the Approve dialog reads what approving does NOW.

The stored preview names the zone the subnet was bound to at submit; the
approval publishes into the zone it is bound to at the press. The
``current-preview`` route re-runs the preview so the dialog can say so.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSZone
from app.models.ipam import Subnet
from tests.test_operation_create_ip_dns_2900 import _subnet_with_zone, _user
from tests.test_portal_address_cname_3647 import _body, _requester_hdr


@pytest.mark.asyncio
async def test_current_preview_follows_a_rebound_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, zone1, appr = await _subnet_with_zone(db_session, client, admin)
    hdr = await _requester_hdr(db_session)
    resp = await client.post(
        "/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.60", "movehost")
    )
    assert resp.status_code == 201, resp.text
    rid = resp.json()["id"]
    assert zone1.name.rstrip(".") in resp.json()["preview_text"]

    url = f"/api/v1/requests/{rid}/current-preview"
    same = (await client.get(url, headers=appr)).json()
    assert same["ok"] is True and same["changed"] is False

    zone2 = DNSZone(
        group_id=zone1.group_id,
        name=f"z3934-{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(zone2)
    await db_session.flush()
    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None
    subnet.dns_zone_id = str(zone2.id)
    await db_session.commit()

    now = (await client.get(url, headers=appr)).json()
    assert now["ok"] is True and now["changed"] is True
    assert f"movehost.{zone2.name.rstrip('.')}" in now["preview_text"]
    assert zone1.name.rstrip(".") not in now["preview_text"]
    # The stored text is untouched.
    stored = (await client.get(f"/api/v1/requests/{rid}", headers=appr)).json()
    assert zone1.name.rstrip(".") in stored["preview_text"]


@pytest.mark.asyncio
async def test_current_preview_reports_a_request_that_cannot_be_applied(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, "admin")
    sid, _zone, appr = await _subnet_with_zone(db_session, client, admin)
    hdr = await _requester_hdr(db_session)
    rid = (
        await client.post("/api/v1/requests", headers=hdr, json=_body(sid, "10.98.5.61", "gone"))
    ).json()["id"]
    subnet = await db_session.get(Subnet, uuid.UUID(sid))
    assert subnet is not None
    await db_session.delete(subnet)
    await db_session.commit()
    body = (await client.get(f"/api/v1/requests/{rid}/current-preview", headers=appr)).json()
    assert body["ok"] is False and body["detail"]

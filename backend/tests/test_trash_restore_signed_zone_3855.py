"""#3855 — a signed zone restored from the Trash is held to the #1762
single-signer rule. A server may join the group while the signed zone is in the
Trash (it is not counted), so the restore must refuse rather than bring the zone
back signed into a group of two signing servers.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSZone
from tests.test_dnssec_single_signer import _group, _headers, _zone


async def _trash_signed_zone(client, db, headers):
    g, _ = await _group(db, servers=1)
    z = _zone(g.id, name=f"t{uuid.uuid4().hex[:6]}.example.", signed=True)
    db.add(z)
    await db.commit()
    resp = await client.delete(f"/api/v1/dns/groups/{g.id}/zones/{z.id}", headers=headers)
    assert resp.status_code == 204, resp.text
    return g, z


@pytest.mark.asyncio
async def test_restore_signed_zone_refused_when_group_gained_a_second_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    g, z = await _trash_signed_zone(client, db_session, headers)
    db_session.add(DNSServer(group_id=g.id, driver="bind9", host="10.0.9.9", name="second"))
    await db_session.commit()

    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{z.id}/restore", headers=headers)
    assert resp.status_code in (409, 422), resp.text
    assert "DNSSEC" in resp.text and "2 DNS servers" in resp.text

    # Still in the Trash, not live.
    got = await client.get(f"/api/v1/dns/groups/{g.id}/zones/{z.id}", headers=headers)
    assert got.status_code == 404


@pytest.mark.asyncio
async def test_restore_signed_zone_still_works_in_a_single_server_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    g, z = await _trash_signed_zone(client, db_session, headers)
    resp = await client.post(f"/api/v1/admin/trash/dns_zone/{z.id}/restore", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["restored"] == 1
    row = await db_session.get(DNSZone, z.id)
    await db_session.refresh(row)
    assert row.dnssec_enabled is True

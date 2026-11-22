"""#4708 — a forward / stub zone cannot be restored from the Trash into a group
that runs PowerDNS (#4570 refused every other path)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from tests.test_zone_forward_transport import _headers


async def _trashed(client, db, headers, driver, zone_type):
    g = DNSServerGroup(name=f"g{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    z = DNSZone(
        group_id=g.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type=zone_type,
        kind="forward",
        forwarders=["9.9.9.9"] if zone_type == "forward" else [],
        masters=["192.0.2.1"] if zone_type == "stub" else [],
    )
    db.add(z)
    await db.commit()
    r = await client.delete(f"/api/v1/dns/groups/{g.id}/zones/{z.id}", headers=headers)
    assert r.status_code == 204, r.text
    # The server joins while the zone is in the Trash.
    db.add(DNSServer(group_id=g.id, driver=driver, host="10.0.9.9", name="s1"))
    await db.commit()
    return z


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", ["forward", "stub"])
async def test_restore_refused_on_powerdns_group(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    headers = await _headers(db_session)
    z = await _trashed(client, db_session, headers, "powerdns", zone_type)
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{z.id}/restore", headers=headers)
    assert r.status_code == 409, r.text
    assert "PowerDNS" in r.text and zone_type in r.text
    got = await client.get(f"/api/v1/dns/groups/{z.group_id}/zones/{z.id}", headers=headers)
    assert got.status_code == 404


@pytest.mark.asyncio
async def test_restore_master_zone_on_powerdns_ok(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    z = await _trashed(client, db_session, headers, "powerdns", "primary")
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{z.id}/restore", headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_type", ["forward", "stub"])
async def test_restore_ok_on_bind9_group(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    headers = await _headers(db_session)
    z = await _trashed(client, db_session, headers, "bind9", zone_type)
    r = await client.post(f"/api/v1/admin/trash/dns_zone/{z.id}/restore", headers=headers)
    assert r.status_code == 200, r.text

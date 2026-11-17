"""Sync with server answers how many of the zone's records already matched (#3671).

The dialog's push section reads "Skipped, DB already matches server". The figure
was a literal 0 in the console because the answer carried no such count. It is
``push_skipped_matching``: the DB rows the push scan found on the server, from
the same comparison that picks the rows to push.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import RecordData
from app.models.auth import User
from app.models.dns import DNSRecord
from app.services.dns.pull_from_server import sync_zone_with_server
from tests.test_dns_sync_serial_3004 import _WWW, _Driver, _serve, _zone

_FTP = RecordData(name="ftp", record_type="A", value="192.0.2.6", ttl=300)


async def _add_ftp(db: AsyncSession, zone_id: uuid.UUID) -> None:
    db.add(
        DNSRecord(
            zone_id=zone_id,
            name="ftp",
            fqdn="ftp.example.com.",
            record_type="A",
            value="192.0.2.6",
            ttl=300,
        )
    )
    await db.commit()


async def _post(client: AsyncClient, db: AsyncSession, group_id, zone_id) -> dict:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    token = create_access_token(str(user.id))
    resp = await client.post(
        f"/api/v1/dns/groups/{group_id}/zones/{zone_id}/sync-with-server",
        json={"apply": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_a_zone_that_fully_matches_reports_every_record_skipped(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, _ = await _zone(db_session, "bind9")
    await _add_ftp(db_session, zone.id)
    group_id, zone_id = zone.group_id, zone.id
    _serve(monkeypatch, _Driver(), [_WWW, _FTP])

    body = await _post(client, db_session, group_id, zone_id)

    assert body["existing_in_db"] == 2
    assert (body["push_candidates"], body["pushed"]) == (0, 0)
    assert body["push_skipped_matching"] == 2


async def test_a_mixed_zone_skips_the_matches_and_pushes_the_rest(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, _ = await _zone(db_session, "bind9")
    await _add_ftp(db_session, zone.id)
    group_id, zone_id = zone.group_id, zone.id
    _serve(monkeypatch, _Driver(), [_WWW])

    body = await _post(client, db_session, group_id, zone_id)

    assert body["push_skipped_matching"] == 1
    assert (body["push_candidates"], body["pushed"]) == (1, 1)


async def test_agentless_push_counts_the_matches_too(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone, (ns1,) = await _zone(db_session, "technitium_api")
    await _add_ftp(db_session, zone.id)
    _serve(monkeypatch, _Driver(), [_WWW])

    result = await sync_zone_with_server(db_session, zone, apply=True, server=ns1)

    assert (result.push.already_matched, result.push.pushed) == (1, 1)

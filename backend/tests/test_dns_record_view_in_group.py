"""A record's view_id must be a view of the zone's own group (#2501).

A foreign view id put an id into the set the renderer matches the group's
views against, so every operator view skipped the zone and it stopped being
served, with the API answering success.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSView
from tests.test_dns_record_cname_alone import _admin, _post, _row, _url, _zone

DETAIL = "view_id does not name a view in this zone's server group"


async def _setup(db: AsyncSession):
    _u, headers = await _admin(db)
    zone = await _zone(db)
    other = await _zone(db)
    foreign = DNSView(group_id=other.group_id, name="foreign")
    own = DNSView(group_id=zone.group_id, name="own")
    db.add_all([foreign, own])
    await db.commit()
    return headers, zone, foreign, own


async def test_create_with_a_foreign_view_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone, foreign, _own = await _setup(db_session)
    r = await _post(
        client,
        zone,
        headers,
        name="www",
        record_type="A",
        value="10.0.0.1",
        view_id=str(foreign.id),
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == DETAIL


async def test_create_with_an_own_view_is_201(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone, _foreign, own = await _setup(db_session)
    r = await _post(
        client,
        zone,
        headers,
        name="www",
        record_type="A",
        value="10.0.0.1",
        view_id=str(own.id),
    )
    assert r.status_code == 201, r.text


async def test_update_to_a_foreign_view_is_422_and_unrelated_edit_ok(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone, foreign, own = await _setup(db_session)
    rec = await _row(db_session, zone, "www", "A", "10.0.0.1", view_id=own.id)
    await db_session.commit()
    bad = await client.put(
        f"{_url(zone)}/{rec.id}", headers=headers, json={"view_id": str(foreign.id)}
    )
    assert bad.status_code == 422, bad.text
    assert bad.json()["detail"] == DETAIL
    ok = await client.put(f"{_url(zone)}/{rec.id}", headers=headers, json={"ttl": 600})
    assert ok.status_code == 200, ok.text
    clear = await client.put(f"{_url(zone)}/{rec.id}", headers=headers, json={"view_id": None})
    assert clear.status_code == 200, clear.text


async def test_bulk_create_with_a_foreign_view_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone, foreign, own = await _setup(db_session)
    recs = [
        {"name": "a", "record_type": "A", "value": "10.0.0.1", "view_id": str(own.id)},
        {"name": "b", "record_type": "A", "value": "10.0.0.2", "view_id": str(foreign.id)},
    ]
    r = await client.post(f"{_url(zone)}/bulk-create", headers=headers, json={"records": recs})
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == DETAIL


async def test_a_record_view_other_than_the_zones_pinned_view_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, zone, _foreign, own = await _setup(db_session)
    pinned = DNSView(group_id=zone.group_id, name="pinned")
    db_session.add(pinned)
    await db_session.flush()
    zone.view_id = pinned.id
    await db_session.commit()
    r = await _post(
        client,
        zone,
        headers,
        name="www",
        record_type="A",
        value="10.0.0.1",
        view_id=str(own.id),
    )
    assert r.status_code == 422, r.text
    ok = await _post(
        client,
        zone,
        headers,
        name="www",
        record_type="A",
        value="10.0.0.1",
        view_id=str(pinned.id),
    )
    assert ok.status_code == 201, ok.text

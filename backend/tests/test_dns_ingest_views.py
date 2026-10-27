"""Ingest reports under split-horizon are filed under the view they read.

The BIND9 agent reads each dynamic zone back off the live daemon and posts
what it found to ``/dns/agents/ingested-records``. With views, the same zone
name can be one zone row per view, each with its own records. A report is
filed under the zone row whose copy it read: when the report names its view,
under the row that view holds; when it names none, only when the group holds a
single row of that name. Otherwise nothing is filed, so one view's records are
never mirrored into another view's zone.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _auth_agent
from app.main import app
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone

ZONE = "corp.example.com"
LOW_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
HIGH_ID = uuid.UUID("ffffffff-ffff-4fff-bfff-ffffffffffff")


async def _group(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name="ns1",
        driver="bind9",
        host="10.0.0.53",
        port=53,
        is_enabled=True,
        is_primary=True,
    )
    db.add(server)
    await db.flush()
    return group, server


def _view(group: DNSServerGroup, name: str, order: int, vid: uuid.UUID) -> DNSView:
    return DNSView(id=vid, group_id=group.id, name=name, order=order, match_clients=["any"])


def _zone(group: DNSServerGroup, view: DNSView | None) -> DNSZone:
    return DNSZone(
        group_id=group.id,
        view_id=view.id if view is not None else None,
        name=ZONE + ".",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
    )


async def _post(
    client: AsyncClient,
    server: DNSServer,
    records: list[dict[str, Any]],
    view_name: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"zone_name": ZONE, "records": records}
    if view_name is not None:
        body["view_name"] = view_name
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        r = await client.post("/api/v1/dns/agents/ingested-records", json=body)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert r.status_code == 200, r.text
    return r.json()


async def _mirrors(db: AsyncSession, zone: DNSZone) -> list[str]:
    rows = (
        (
            await db.execute(
                select(DNSRecord).where(
                    DNSRecord.zone_id == zone.id, DNSRecord.import_source == "ddns_external"
                )
            )
        )
        .scalars()
        .all()
    )
    return sorted(r.name for r in rows)


def _rec(name: str, value: str = "192.0.2.10") -> dict[str, Any]:
    return {"name": name, "record_type": "A", "value": value, "ttl": 300}


async def _two_view_zones(
    db: AsyncSession,
) -> tuple[DNSServer, DNSZone, DNSZone]:
    """The zone in view ``inside`` (lower id, first in order) and in view
    ``outside``, with no shared copy. ``outside`` holds a managed ``wb``."""
    group, server = await _group(db)
    inside = _view(group, "inside", 10, LOW_ID)
    outside = _view(group, "outside", 20, HIGH_ID)
    db.add_all([inside, outside])
    await db.flush()
    z_in, z_out = _zone(group, inside), _zone(group, outside)
    db.add_all([z_in, z_out])
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=z_out.id,
            name="wb",
            fqdn=f"wb.{ZONE}.",
            record_type="A",
            value="198.51.100.7",
        )
    )
    await db.commit()
    return server, z_in, z_out


@pytest.mark.asyncio
async def test_a_report_naming_no_view_is_not_filed_when_the_name_is_in_two_views(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The read could be either view's copy, so it is filed under neither:
    the other view's records (managed ``wb`` and an RFC 2136 ``b5``) are not
    mirrored into the ``inside`` zone, whose row has the lower view id."""
    server, z_in, z_out = await _two_view_zones(db_session)

    out = await _post(client, server, [_rec("wb", "198.51.100.7"), _rec("b5")])

    assert out["skipped"] == "view_ambiguous"
    assert await _mirrors(db_session, z_in) == []
    assert await _mirrors(db_session, z_out) == []


@pytest.mark.asyncio
async def test_a_report_naming_its_view_is_filed_under_that_views_zone_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, z_in, z_out = await _two_view_zones(db_session)

    out = await _post(client, server, [_rec("wb", "198.51.100.7"), _rec("b5")], "outside")

    assert out["added"] == 1  # wb is managed there, b5 is learned
    assert await _mirrors(db_session, z_out) == ["b5"]
    assert await _mirrors(db_session, z_in) == []

    out = await _post(client, server, [_rec("a7")], "inside")
    assert out["added"] == 1
    assert await _mirrors(db_session, z_in) == ["a7"]
    assert await _mirrors(db_session, z_out) == ["b5"]


@pytest.mark.asyncio
async def test_a_report_naming_a_view_the_group_does_not_render_is_not_filed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, z_in, z_out = await _two_view_zones(db_session)

    out = await _post(client, server, [_rec("b5")], "gone")

    assert out["skipped"] == "view_not_read"
    assert await _mirrors(db_session, z_in) == []
    assert await _mirrors(db_session, z_out) == []


@pytest.mark.asyncio
async def test_a_shared_zone_in_two_views_is_filed_as_before(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """One zone row rendered into every view: any copy read is a copy of that
    row, so a report naming no view is filed under it."""
    group, server = await _group(db_session)
    db_session.add_all([_view(group, "inside", 10, LOW_ID), _view(group, "outside", 20, HIGH_ID)])
    await db_session.flush()
    shared = _zone(group, None)
    db_session.add(shared)
    await db_session.commit()

    out = await _post(client, server, [_rec("dc01")])

    assert out["added"] == 1
    assert await _mirrors(db_session, shared) == ["dc01"]


@pytest.mark.asyncio
async def test_a_shared_zone_files_only_the_report_from_its_read_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Each view holds its own copy of a shared zone. Only the copy the control
    plane reads (the first operator view) is filed, so two views' reports do
    not take turns adding and removing the zone's mirror rows."""
    group, server = await _group(db_session)
    db_session.add_all([_view(group, "inside", 10, LOW_ID), _view(group, "outside", 20, HIGH_ID)])
    await db_session.flush()
    shared = _zone(group, None)
    db_session.add(shared)
    await db_session.commit()

    out = await _post(client, server, [_rec("only-outside")], "outside")
    assert out["skipped"] == "view_not_read"
    assert await _mirrors(db_session, shared) == []

    out = await _post(client, server, [_rec("dc01")], "inside")
    assert out["added"] == 1
    assert await _mirrors(db_session, shared) == ["dc01"]


@pytest.mark.asyncio
async def test_a_shared_copy_beside_a_view_copy_is_not_guessed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A shared row whose view-scoped records keep it in ``inside`` only, plus
    a row pinned to ``outside``: two rows of the name, so a report naming no
    view is filed under neither (it used to go to the shared row)."""
    group, server = await _group(db_session)
    inside = _view(group, "inside", 10, LOW_ID)
    outside = _view(group, "outside", 20, HIGH_ID)
    db_session.add_all([inside, outside])
    await db_session.flush()
    shared, pinned = _zone(group, None), _zone(group, outside)
    db_session.add_all([shared, pinned])
    await db_session.flush()
    db_session.add(
        DNSRecord(
            zone_id=shared.id,
            view_id=inside.id,
            name="wa",
            fqdn=f"wa.{ZONE}.",
            record_type="A",
            value="10.1.1.1",
        )
    )
    await db_session.commit()

    out = await _post(client, server, [_rec("b5")])
    assert out["skipped"] == "view_ambiguous"
    assert await _mirrors(db_session, shared) == []
    assert await _mirrors(db_session, pinned) == []

    out = await _post(client, server, [_rec("b5")], "outside")
    assert out["added"] == 1
    assert await _mirrors(db_session, pinned) == ["b5"]
    assert await _mirrors(db_session, shared) == []


@pytest.mark.asyncio
async def test_a_zone_in_one_view_only_is_filed_under_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group, server = await _group(db_session)
    inside = _view(group, "inside", 10, LOW_ID)
    db_session.add_all([inside, _view(group, "outside", 20, HIGH_ID)])
    await db_session.flush()
    pinned = _zone(group, inside)
    db_session.add(pinned)
    await db_session.commit()

    out = await _post(client, server, [_rec("a7")])
    assert out["added"] == 1
    assert await _mirrors(db_session, pinned) == ["a7"]

    out = await _post(client, server, [_rec("a7"), _rec("a8")], "inside")
    assert out["added"] == 1
    assert await _mirrors(db_session, pinned) == ["a7", "a8"]


@pytest.mark.asyncio
async def test_a_group_without_views_is_unchanged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group, server = await _group(db_session)
    flat = _zone(group, None)
    db_session.add(flat)
    await db_session.commit()

    out = await _post(client, server, [_rec("dc01")])
    assert out["added"] == 1
    assert await _mirrors(db_session, flat) == ["dc01"]

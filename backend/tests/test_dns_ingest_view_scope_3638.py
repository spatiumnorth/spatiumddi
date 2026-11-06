"""A learned record stays in the view whose copy it was written to (#3638).

Under split-horizon each view loads its own copy of a dynamic zone, and an
RFC 2136 update lands in one copy. The agent reads each view's copy back and
names the view in its report. The mirror row the control plane files for a
record learned that way carries that view when the zone renders into more than
one view, so the bundle renders it into that view's copy only. A pinned zone
renders into its pin alone among the operator views, whatever view its records
name.
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
from app.services.dns import config_bundle as preview
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.tsig import transfer_view_name

ZONE = "corp.example.com"
INSIDE_ID = uuid.UUID("00000000-0000-4000-8000-000000000001")
OUTSIDE_ID = uuid.UUID("ffffffff-ffff-4fff-bfff-ffffffffffff")


async def _group(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer, DNSView, DNSView]:
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
    inside = DNSView(
        id=INSIDE_ID, group_id=group.id, name="inside", order=10, match_clients=["10.0.0.0/8"]
    )
    outside = DNSView(
        id=OUTSIDE_ID, group_id=group.id, name="outside", order=20, match_clients=["any"]
    )
    db.add_all([server, inside, outside])
    await db.flush()
    return group, server, inside, outside


def _zone(group: DNSServerGroup, view: DNSView | None = None) -> DNSZone:
    return DNSZone(
        group_id=group.id,
        view_id=view.id if view is not None else None,
        name=ZONE + ".",
        zone_type="primary",
        kind="forward",
        dynamic_update_enabled=True,
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
    )


def _record(zone: DNSZone, name: str, value: str, **kw: Any) -> DNSRecord:
    return DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{ZONE}",
        record_type="A",
        value=value,
        **kw,
    )


def _rec(name: str, value: str = "192.0.2.10") -> dict[str, Any]:
    return {"name": name, "record_type": "A", "value": value, "ttl": 300}


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


async def _mirrors(db: AsyncSession, zone: DNSZone) -> dict[str, uuid.UUID | None]:
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
    return {r.name: r.view_id for r in rows}


async def _served(db: AsyncSession, server: DNSServer) -> dict[str, set[str]]:
    """Per view, the record names the agent bundle renders into the zone."""
    srv = server
    bundle = await build_config_bundle(db, srv)
    out: dict[str, set[str]] = {}
    for copy in bundle["zones"]:
        if copy["name"].rstrip(".") == ZONE:
            out[copy["view_name"]] = {r["name"] for r in copy["records"]}
    return out


async def _previewed(db: AsyncSession, server: DNSServer) -> dict[str, set[str]]:
    """The same, from the control plane's own preview bundle."""
    srv = server
    bundle = await preview.build_config_bundle(db, srv)
    return {
        str(z.view_name): {r.name for r in z.records}
        for z in bundle.zones
        if z.name.rstrip(".") == ZONE
    }


@pytest.mark.asyncio
async def test_a_record_learned_in_one_views_copy_is_served_in_that_view_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group, server, inside, _outside = await _group(db_session)
    zone = _zone(group)  # unpinned: one copy in each view
    db_session.add(zone)
    await db_session.flush()
    db_session.add(_record(zone, "www", "192.0.2.80"))
    await db_session.commit()

    out = await _post(client, server, [_rec("www", "192.0.2.80"), _rec("dc01")], "inside")

    assert out["added"] == 1
    assert await _mirrors(db_session, zone) == {"dc01": INSIDE_ID}
    served = await _served(db_session, server)
    # The zone still renders into both views: a learned record never moves it.
    assert served == {"inside": {"www", "dc01"}, "outside": {"www"}}
    assert await _previewed(db_session, server) == served
    assert await transfer_view_name(db_session, zone) == "inside"

    # The next report from the same copy keeps the row, matched in its view.
    out = await _post(client, server, [_rec("www", "192.0.2.80"), _rec("dc01")], "inside")
    assert out["added"] == 0 and out["removed"] == 0
    assert await _mirrors(db_session, zone) == {"dc01": INSIDE_ID}

    # And one without it drops it.
    out = await _post(client, server, [_rec("www", "192.0.2.80")], "inside")
    assert out["removed"] == 1
    assert await _mirrors(db_session, zone) == {}


@pytest.mark.asyncio
async def test_a_report_never_matches_or_drops_a_row_learned_in_another_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group, server, inside, outside = await _group(db_session)
    zone = _zone(group)
    db_session.add(zone)
    await db_session.flush()
    db_session.add(
        _record(zone, "kept", "192.0.2.20", view_id=OUTSIDE_ID, import_source="ddns_external")
    )
    await db_session.commit()

    out = await _post(client, server, [_rec("kept", "192.0.2.20")], "inside")

    # ``inside``'s copy holding the same value is its own learned record, not
    # the ``outside`` row; and the ``outside`` row is not that copy's to drop.
    assert out["added"] == 1 and out["removed"] == 0
    rows = (
        (
            await db_session.execute(
                select(DNSRecord.view_id).where(
                    DNSRecord.zone_id == zone.id, DNSRecord.name == "kept"
                )
            )
        )
        .scalars()
        .all()
    )
    assert sorted(str(v) for v in rows) == sorted([str(INSIDE_ID), str(OUTSIDE_ID)])

    out = await _post(client, server, [], "inside")
    assert out["removed"] == 1
    assert await _mirrors(db_session, zone) == {"kept": OUTSIDE_ID}


@pytest.mark.asyncio
async def test_a_report_without_a_view_is_filed_unscoped_as_before(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An agent built before the view field: same rows as before the change."""
    group, server, _inside, _outside = await _group(db_session)
    zone = _zone(group)
    db_session.add(zone)
    await db_session.commit()

    out = await _post(client, server, [_rec("dc01")])

    assert out["added"] == 1
    assert await _mirrors(db_session, zone) == {"dc01": None}
    out = await _post(client, server, [])
    assert out["removed"] == 1


@pytest.mark.asyncio
async def test_a_zone_in_a_single_view_keeps_learned_rows_unscoped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    group, server, inside, _outside = await _group(db_session)
    zone = _zone(group, inside)
    db_session.add(zone)
    await db_session.commit()

    out = await _post(client, server, [_rec("dc01")], "inside")

    assert out["added"] == 1
    assert await _mirrors(db_session, zone) == {"dc01": None}
    assert await _served(db_session, server) == {"inside": {"dc01"}}


@pytest.mark.asyncio
async def test_a_pinned_zone_renders_into_its_pin_only(
    db_session: AsyncSession,
) -> None:
    """A record scoped to another view (left by a re-pin, or restored from the
    Trash) does not carry the zone into that view."""
    group, server, inside, outside = await _group(db_session)
    zone = _zone(group, inside)
    db_session.add(zone)
    await db_session.flush()
    db_session.add_all(
        [
            _record(zone, "shared", "192.0.2.1"),
            _record(zone, "stale", "192.0.2.2", view_id=OUTSIDE_ID),
        ]
    )
    await db_session.commit()

    served = await _served(db_session, server)
    assert served == {"inside": {"shared"}}
    assert await _previewed(db_session, server) == served
    assert await transfer_view_name(db_session, zone) == "inside"

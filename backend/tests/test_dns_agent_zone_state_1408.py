"""#1408 — a DNS agent's zone-state report lands.

``POST /api/v1/dns/agents/zone-state`` stripped the trailing dot from every
reported zone name and looked the stripped names up against zone names stored
with the dot (``lab.example.test.``), so nothing matched. Every entry was
skipped as an unknown zone, the answer was ``{"updated": 0}`` with a 200, and
``dns_server_zone_state`` stayed empty, so ``GET .../server-state`` showed
``current_serial: null`` for every zone on every server. Seen live on
single-node builds of nightly-2026.09.30 (f838ab85): on the stock build every
server-state read came back null, and with three DNS fixes that leave this
handler alone, six reports in five minutes were all answered 200 and the table
stayed empty. The lookup was not scoped to the reporting server's group
either, so once names matched, another group's zone of the same name could
take the report.

The agent reports exactly the names its bundle carries (``agent_config``
ships the stored name). They now land on the reporting server's own zones,
a name two views of the group both hold is skipped rather than guessed, and
what was skipped is counted in the answer.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import _auth_agent
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerZoneState, DNSView, DNSZone


async def _group(db: AsyncSession) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g1408-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp


async def _server(db: AsyncSession, grp: DNSServerGroup) -> DNSServer:
    srv = DNSServer(
        group_id=grp.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        driver="bind9",
        host="10.0.0.53",
        port=53,
    )
    db.add(srv)
    await db.flush()
    return srv


async def _zone(
    db: AsyncSession,
    grp: DNSServerGroup,
    name: str,
    *,
    serial: int = 2026100201,
    view: DNSView | None = None,
) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        view_id=view.id if view is not None else None,
        name=name,
        zone_type="primary",
        kind="forward",
        last_serial=serial,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _report(
    client: AsyncClient, db: AsyncSession, server: DNSServer, zones: list[tuple[str, int]]
) -> dict[str, Any]:
    """The agent's report, through the real route (``sync._report_zone_state``'s shape)."""
    db.expunge_all()  # the request must load its rows like production does
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post(
            "/api/v1/dns/agents/zone-state",
            json={"zones": [{"zone_name": name, "serial": serial} for name, serial in zones]},
        )
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


async def _state(db: AsyncSession, server_id: uuid.UUID, zone_id: uuid.UUID):
    return (
        await db.execute(
            select(DNSServerZoneState)
            .where(
                DNSServerZoneState.server_id == server_id,
                DNSServerZoneState.zone_id == zone_id,
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def _token(db: AsyncSession) -> str:
    user = User(
        username=f"u1408-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_a_report_with_the_bundles_own_zone_names_lands_a_row_per_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's case: the names as the bundle ships them, trailing dot and
    all. Each lands a row, and the zone's server-state view reads it back."""
    token = await _token(db_session)
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    lab = await _zone(db_session, grp, "lab.example.test.", serial=2026100204)
    corp = await _zone(db_session, grp, "corp.example.test.", serial=2026100201)
    ids = (srv.id, grp.id, lab.id, corp.id)
    await db_session.commit()
    srv_id, grp_id, lab_id, corp_id = ids

    body = await _report(
        client, db_session, srv, [("lab.example.test.", 2026100204), ("corp.example.test.", 7)]
    )

    assert body == {"updated": 2, "skipped": 0}
    lab_state = await _state(db_session, srv_id, lab_id)
    corp_state = await _state(db_session, srv_id, corp_id)
    assert lab_state is not None and lab_state.current_serial == 2026100204
    assert corp_state is not None and corp_state.current_serial == 7
    assert lab_state.reported_at is not None

    r = await client.get(
        f"/api/v1/dns/groups/{grp_id}/zones/{lab_id}/server-state",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    view = r.json()
    (entry,) = [s for s in view["servers"] if s["server_id"] == str(srv_id)]
    assert entry["current_serial"] == 2026100204
    assert entry["reported_at"] is not None
    assert view["in_sync"] is True


@pytest.mark.asyncio
async def test_a_name_reported_without_its_trailing_dot_lands_too(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    zone = await _zone(db_session, grp, "lab.example.test.")
    srv_id, zone_id = srv.id, zone.id
    await db_session.commit()

    body = await _report(client, db_session, srv, [("LAB.example.test", 41)])

    assert body == {"updated": 1, "skipped": 0}
    state = await _state(db_session, srv_id, zone_id)
    assert state is not None and state.current_serial == 41


@pytest.mark.asyncio
async def test_a_second_report_moves_the_row(client: AsyncClient, db_session: AsyncSession) -> None:
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    zone = await _zone(db_session, grp, "lab.example.test.")
    srv_id, zone_id = srv.id, zone.id
    await db_session.commit()

    await _report(client, db_session, srv, [("lab.example.test.", 5)])
    first = await _state(db_session, srv_id, zone_id)
    assert first is not None
    first_at: datetime = first.reported_at
    await _report(client, db_session, srv, [("lab.example.test.", 6)])

    again = await _state(db_session, srv_id, zone_id)
    assert again is not None and again.current_serial == 6
    assert again.reported_at >= first_at
    rows = (
        (
            await db_session.execute(
                select(DNSServerZoneState).where(DNSServerZoneState.zone_id == zone_id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_the_same_name_in_another_group_is_not_the_reporting_servers(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A server reports the zones of its own group. Another group's zone of
    the same name is another zone."""
    mine = await _group(db_session)
    other = await _group(db_session)
    srv = await _server(db_session, mine)
    own = await _zone(db_session, mine, "shared.example.test.")
    foreign = await _zone(db_session, other, "shared.example.test.")
    srv_id, own_id, foreign_id = srv.id, own.id, foreign.id
    await db_session.commit()

    body = await _report(client, db_session, srv, [("shared.example.test.", 9)])

    assert body == {"updated": 1, "skipped": 0}
    own_state = await _state(db_session, srv_id, own_id)
    assert own_state is not None and own_state.current_serial == 9
    assert await _state(db_session, srv_id, foreign_id) is None


@pytest.mark.asyncio
async def test_a_zone_the_bundle_renders_into_two_views_lands_once(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A global zone renders into every view, so the bundle (and the agent's
    report) carries it once per view: one zone, one row."""
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    db_session.add_all(
        [DNSView(group_id=grp.id, name="inside"), DNSView(group_id=grp.id, name="outside")]
    )
    zone = await _zone(db_session, grp, "lab.example.test.")
    srv_id, zone_id = srv.id, zone.id
    await db_session.commit()

    body = await _report(
        client, db_session, srv, [("lab.example.test.", 12), ("lab.example.test.", 12)]
    )

    assert body == {"updated": 1, "skipped": 0}
    state = await _state(db_session, srv_id, zone_id)
    assert state is not None and state.current_serial == 12


@pytest.mark.asyncio
async def test_a_name_two_views_of_the_group_both_hold_is_skipped_not_guessed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two zones of one name, each pinned to its own view: the report names
    neither view, so which serial is whose cannot be told. Nothing is
    written to either, and the skip is counted."""
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    inside = DNSView(group_id=grp.id, name="inside")
    outside = DNSView(group_id=grp.id, name="outside")
    db_session.add_all([inside, outside])
    await db_session.flush()
    a = await _zone(db_session, grp, "split.example.test.", view=inside)
    b = await _zone(db_session, grp, "split.example.test.", view=outside)
    srv_id, a_id, b_id = srv.id, a.id, b.id
    await db_session.commit()

    body = await _report(
        client, db_session, srv, [("split.example.test.", 3), ("split.example.test.", 4)]
    )

    assert body == {"updated": 0, "skipped": 2}
    assert await _state(db_session, srv_id, a_id) is None
    assert await _state(db_session, srv_id, b_id) is None


@pytest.mark.asyncio
async def test_an_unknown_zone_is_counted_as_skipped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A zone deleted from the control plane while the agent still serves it
    is skipped, as before, but no longer silently."""
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    zone = await _zone(db_session, grp, "lab.example.test.")
    srv_id, zone_id = srv.id, zone.id
    await db_session.commit()

    body = await _report(
        client, db_session, srv, [("gone.example.test.", 1), ("lab.example.test.", 2)]
    )

    assert body == {"updated": 1, "skipped": 1}
    state = await _state(db_session, srv_id, zone_id)
    assert state is not None and state.current_serial == 2


@pytest.mark.asyncio
async def test_a_zone_state_report_marks_no_bundle_dirty(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The report now writes ``dns_server_zone_state``, which no bundle
    renders: it must not mark the group's bundles for a re-render (#1111,
    the #1122 review's "quiet writers")."""
    grp = await _group(db_session)
    srv = await _server(db_session, grp)
    await _zone(db_session, grp, "lab.example.test.")
    srv_id = srv.id
    await db_session.commit()
    before = (
        await db_session.execute(select(DNSServer.bundle_dirty_seq).where(DNSServer.id == srv_id))
    ).scalar_one()

    body = await _report(client, db_session, srv, [("lab.example.test.", 3)])

    assert body == {"updated": 1, "skipped": 0}
    after = (
        await db_session.execute(select(DNSServer.bundle_dirty_seq).where(DNSServer.id == srv_id))
    ).scalar_one()
    assert after == before

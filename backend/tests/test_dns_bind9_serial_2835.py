"""#2835 — a new zone is numbered from the start, and a BIND9 server's sync
state compares the serial named serves.

* A zone used to be created at ``last_serial`` 0, which the agents serve at
  their placeholder 1 until the first change. A primary zone now starts at
  today's ``YYYYMMDD00``, and that is the serial its bundle carries. A
  secondary's serial is its primary's, not ours, and stays 0.
* The BIND9 agent now reports the serial named serves instead of the one the
  op carried. When named counted an update itself (1, 2, 3, …) the zone reads
  out of sync, and our serial is left where it is (only PowerDNS adopts one).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSZone
from app.services.dns.agent_config import build_config_bundle
from tests.test_dns_agent_zone_state_1408 import _report
from tests.test_dns_zone_soa_timers import _group_with_server, _headers, _zone_via_api


def _today_bases(before: datetime) -> set[int]:
    """Today's ``YYYYMMDD00``, either side of a midnight the test might straddle."""
    return {int(t.strftime("%Y%m%d")) * 100 for t in (before, datetime.now(UTC))}


@pytest.mark.asyncio
async def test_a_new_zone_starts_at_todays_serial_and_ships_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    before = datetime.now(UTC)
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)

    zone = await _zone_via_api(client, headers, grp)

    assert zone["last_serial"] in _today_bases(before)
    bundle = await build_config_bundle(db_session, server)
    (shipped,) = [z for z in bundle["zones"] if z["id"] == zone["id"]]
    assert shipped["serial"] == zone["last_serial"], "the render serves the serial we hold"


@pytest.mark.asyncio
async def test_a_new_secondary_is_not_numbered(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, _server = await _group_with_server(db_session)

    zone = await _zone_via_api(client, headers, grp, zone_type="secondary", masters=["192.0.2.53"])

    assert zone["last_serial"] == 0


@pytest.mark.asyncio
async def test_a_zone_built_outside_the_api_is_numbered_too(db_session: AsyncSession) -> None:
    """Auto-created reverse zones, importers and integrations build the row
    themselves; the column default numbers them all."""
    before = datetime.now(UTC)
    grp, _server = await _group_with_server(db_session)
    zone = DNSZone(group_id=grp.id, name=f"r{uuid.uuid4().hex[:6]}.example.test.")
    db_session.add(zone)
    await db_session.flush()
    assert zone.last_serial in _today_bases(before)


async def _in_sync(client: AsyncClient, headers: dict[str, str], grp_id, zone_id) -> dict:
    r = await client.get(
        f"/api/v1/dns/groups/{grp_id}/zones/{zone_id}/server-state", headers=headers
    )
    assert r.status_code == 200, r.text
    body: dict = r.json()
    return body


@pytest.mark.asyncio
async def test_a_bind9_zone_reads_in_sync_only_at_the_serial_named_serves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, server = await _group_with_server(db_session)
    zone = await _zone_via_api(client, headers, grp)
    target = int(zone["last_serial"])  # type: ignore[call-overload]
    grp_id, zone_id = grp.id, zone["id"]

    # named counted the updates itself (the issue: served 3)
    await _report(client, db_session, server, [(str(zone["name"]), 3)])
    state = await _in_sync(client, headers, grp_id, zone_id)
    assert state["in_sync"] is False
    (entry,) = state["servers"]
    assert entry["current_serial"] == 3
    assert state["target_serial"] == target, "a BIND9 report never moves our serial"

    # named serves ours: the update carried it
    await _report(client, db_session, server, [(str(zone["name"]), target)])
    state = await _in_sync(client, headers, grp_id, zone_id)
    assert state["in_sync"] is True

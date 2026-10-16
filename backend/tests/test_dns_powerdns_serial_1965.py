"""PowerDNS serial ownership, control-plane half (#1965, #1967, #1968).

* #1968 — a PowerDNS server never serves a serial below the one it held, so
  after the upgrade it can serve one AHEAD of the control plane's. Its zone-state
  report moves ``last_serial`` up to it (forward only, primary zones, PowerDNS
  servers only), so the next bump starts above what the server holds and the zone
  can read in sync.
* #1967 — a secondary that reports serial 0 holds no data; its target is 0 too,
  so equality read it as in sync while the server answered REFUSED.
* the control plane's ``pdns.conf`` mirror declares ``primary`` / ``secondary``.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.powerdns import render_pdns_conf
from app.models.audit import AuditLog
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from tests.test_dns_agent_zone_state_1408 import _report, _token


async def _setup(
    db: AsyncSession, driver: str, zone_type: str = "primary", serial: int = 2026101600
):
    grp = DNSServerGroup(name=f"g1965-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    srv = DNSServer(
        group_id=grp.id, name=f"ns-{uuid.uuid4().hex[:6]}", driver=driver, host="10.0.0.53", port=53
    )
    db.add(srv)
    zone = DNSZone(
        group_id=grp.id,
        name="lab.example.test.",
        zone_type=zone_type,
        kind="forward",
        last_serial=serial,
    )
    db.add(zone)
    await db.flush()
    return grp, srv, zone


async def _last_serial(db: AsyncSession, zone_id: uuid.UUID) -> int:
    return (
        await db.execute(
            select(DNSZone.last_serial)
            .where(DNSZone.id == zone_id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_a_powerdns_server_serving_a_later_serial_moves_the_zones_serial_up(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, srv, zone = await _setup(db_session, "powerdns")
    zone_id = zone.id
    await db_session.commit()

    await _report(client, db_session, srv, [("lab.example.test.", 2026101604)])

    assert await _last_serial(db_session, zone_id) == 2026101604
    audit = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "dns.zone.serial_adopted",
                    AuditLog.resource_id == str(zone_id),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audit) == 1 and audit[0].new_value["serial"] == 2026101604


@pytest.mark.asyncio
async def test_a_lower_or_equal_reported_serial_never_lowers_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, srv, zone = await _setup(db_session, "powerdns", serial=2026101605)
    zone_id = zone.id
    await db_session.commit()

    await _report(client, db_session, srv, [("lab.example.test.", 2026101601)])
    assert await _last_serial(db_session, zone_id) == 2026101605
    await _report(client, db_session, srv, [("lab.example.test.", 2026101605)])
    assert await _last_serial(db_session, zone_id) == 2026101605


@pytest.mark.asyncio
async def test_a_bind9_server_never_moves_the_zones_serial(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, srv, zone = await _setup(db_session, "bind9")
    zone_id = zone.id
    await db_session.commit()
    await _report(client, db_session, srv, [("lab.example.test.", 2026101699)])
    assert await _last_serial(db_session, zone_id) == 2026101600


@pytest.mark.asyncio
async def test_a_secondary_zone_is_not_adopted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A secondary's serial is the primary's, never ours to take."""
    _, srv, zone = await _setup(db_session, "powerdns", zone_type="secondary", serial=0)
    zone_id = zone.id
    await db_session.commit()
    await _report(client, db_session, srv, [("lab.example.test.", 55)])
    assert await _last_serial(db_session, zone_id) == 0


@pytest.mark.asyncio
async def test_a_secondary_that_never_transferred_is_not_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _token(db_session)
    grp, srv, zone = await _setup(db_session, "powerdns", zone_type="secondary", serial=0)
    ids = (grp.id, srv.id, zone.id)
    await db_session.commit()
    grp_id, srv_id, zone_id = ids
    h = {"Authorization": f"Bearer {token}"}

    await _report(client, db_session, srv, [("lab.example.test.", 0)])
    r = await client.get(f"/api/v1/dns/groups/{grp_id}/zones/{zone_id}/server-state", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["in_sync"] is False
    r = await client.get(f"/api/v1/dns/servers/{srv_id}/zone-state", headers=h)
    (entry,) = r.json()["zones"]
    assert entry["in_sync"] is False and entry["current_serial"] == 0


@pytest.mark.asyncio
async def test_a_bind9_secondary_reporting_zero_is_left_as_it_was(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """BIND9 agents report the bundle's serial (0 for a secondary), so 0 says
    nothing about a transfer there."""
    token = await _token(db_session)
    _, srv, zone = await _setup(db_session, "bind9", zone_type="secondary", serial=0)
    srv_id = srv.id
    await db_session.commit()
    await _report(client, db_session, srv, [("lab.example.test.", 0)])
    r = await client.get(
        f"/api/v1/dns/servers/{srv_id}/zone-state", headers={"Authorization": f"Bearer {token}"}
    )
    (entry,) = r.json()["zones"]
    assert entry["in_sync"] is True


def test_the_control_plane_pdns_conf_mirror_declares_primary_and_secondary() -> None:
    lines = render_pdns_conf(api_key="k").splitlines()
    assert "primary=yes" in lines and "secondary=yes" in lines

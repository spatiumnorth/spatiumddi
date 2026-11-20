"""#4566 — a signed zone whose DS set changed says so.

A PowerDNS zone re-created by the reconcile (a lost LMDB volume, a replaced
node) is now signed again by the agent, with new keys, and the agent reports
the new DS. The control plane stored the report silently, so the zone looked
exactly as before while the parent still held a DS that no longer matched.
The change is now an audit row and ``dnssec_ds_changed_at`` on the DNSSEC
info the zone's card reads.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import DNSSECStateBatch, DNSSECStateReport, agent_dnssec_state
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone
from app.services.dns.record_ops import clear_dnssec_key_state

OLD = "1001 13 2 " + "ab" * 32
NEW = "2002 13 2 " + "cd" * 32


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"ds-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    u.groups = []
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _signed_zone(db: AsyncSession) -> tuple[DNSServer, DNSZone]:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    server = DNSServer(
        group_id=g.id, driver="powerdns", host="10.0.0.1", name="pdns1", is_primary=True
    )
    zone = DNSZone(
        group_id=g.id,
        name=f"t{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="a.example.",
        dnssec_enabled=True,
    )
    db.add_all([server, zone])
    await db.flush()
    return server, zone


async def _report(db: AsyncSession, server: DNSServer, zone: DNSZone, *ds: str) -> None:
    batch = DNSSECStateBatch(zones=[DNSSECStateReport(zone_name=zone.name, ds_records=list(ds))])
    assert await agent_dnssec_state(batch, db, (server, {})) == {"updated": 1}
    await db.refresh(zone)


async def _changes(db: AsyncSession, zone: DNSZone) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.action == "dns.zone.dnssec_ds_changed",
                    AuditLog.resource_id == str(zone.id),
                )
            )
        )
        .scalars()
        .all()
    )


async def _info(client: AsyncClient, db: AsyncSession, zone: DNSZone) -> dict:
    r = await client.get(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/dnssec/info",
        headers=await _headers(db),
    )
    assert r.status_code == 200, r.text
    return dict(r.json())


@pytest.mark.asyncio
async def test_a_resigned_zone_reports_that_its_ds_changed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone = await _signed_zone(db_session)
    await _report(db_session, server, zone, OLD)
    assert (await _info(client, db_session, zone))["dnssec_ds_changed_at"] is None
    assert await _changes(db_session, zone) == []

    # The zone was re-created on the server and signed with new keys.
    await _report(db_session, server, zone, NEW)

    info = await _info(client, db_session, zone)
    assert info["dnssec_ds_records"] == [NEW]
    assert info["dnssec_ds_changed_at"] is not None
    (row,) = await _changes(db_session, zone)
    assert row.old_value == {"ds_records": [OLD]}
    assert row.new_value["ds_records"] == [NEW]
    assert row.new_value["server"] == "pdns1"
    assert "parent" in row.new_value["warning"]


@pytest.mark.asyncio
async def test_the_same_ds_reported_again_is_not_a_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Every structural apply re-posts the DS, in whatever order."""
    server, zone = await _signed_zone(db_session)
    await _report(db_session, server, zone, OLD, NEW)
    await _report(db_session, server, zone, NEW, OLD)

    assert await _changes(db_session, zone) == []
    assert (await _info(client, db_session, zone))["dnssec_ds_changed_at"] is None


@pytest.mark.asyncio
async def test_a_fresh_sign_after_an_unsign_is_a_first_ds_again(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, zone = await _signed_zone(db_session)
    await _report(db_session, server, zone, OLD)
    await _report(db_session, server, zone, NEW)
    assert (await _info(client, db_session, zone))["dnssec_ds_changed_at"] is not None

    await clear_dnssec_key_state(db_session, zone)  # what every unsign path does
    await db_session.flush()
    third = "3003 13 2 " + "ef" * 32
    await _report(db_session, server, zone, third)

    assert len(await _changes(db_session, zone)) == 1
    assert (await _info(client, db_session, zone))["dnssec_ds_changed_at"] is None

"""A DNS group that loses its primary keeps delivering record writes (#2276).

``delete_server`` was a plain delete: deleting the group's ``is_primary``
server left the group with none, ``resolve_primary_server`` returned None, and
``enqueue_record_op`` logged ``record_op_dropped_no_primary`` and returned —
BEFORE the per-server agent fan-out, so the surviving agents got nothing
either. The record write itself committed and the API answered 200.

Pinned here, on the stored state (op rows per server, the ``is_primary``
flag), not on the code path:

* deleting the primary over the API elects a successor, and the next record
  write over the API queues an op for every surviving server;
* an agent-based group with no primary flag at all still fans out;
* an agentless group with no primary flag writes through one server rather
  than returning nothing;
* a group already in the broken state is healed by the 60 s beat sweep.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.record_ops import enqueue_record_op
from tests.test_dns_server_group_move import _auth, _group, _server, _superadmin

# ``created_at`` is ``server_default=now()``: rows flushed in one transaction
# share it, and the election's tie-break is then the (random) id. Tests that
# name the oldest survivor stamp the order explicitly.
_T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _at(n: int) -> datetime:
    return _T0 + timedelta(minutes=n)


async def _zone(db: AsyncSession, group: DNSServerGroup) -> DNSZone:
    z = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(z)
    await db.flush()
    return z


async def _op_servers(db: AsyncSession, zone: DNSZone) -> set[uuid.UUID]:
    rows = (
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.zone_name == zone.name)))
        .scalars()
        .all()
    )
    return {r.server_id for r in rows}


async def _primaries(db: AsyncSession, group_id: uuid.UUID) -> list[uuid.UUID]:
    db.expire_all()
    return list(
        (
            await db.execute(
                select(DNSServer.id).where(
                    DNSServer.group_id == group_id, DNSServer.is_primary.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_deleting_the_primary_keeps_record_writes_flowing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root2276")
    grp = await _group(db_session, "g2276")
    ns1 = await _server(db_session, grp, "ns1", is_primary=True, created_at=_at(0))
    ns2 = await _server(db_session, grp, "ns2", created_at=_at(1))
    ns3 = await _server(db_session, grp, "ns3", created_at=_at(2))
    zone = await _zone(db_session, grp)
    await db_session.commit()
    ns1_id, ns2_id, ns3_id, gid, zid = ns1.id, ns2.id, ns3.id, grp.id, zone.id

    resp = await client.delete(f"/api/v1/dns/groups/{gid}/servers/{ns1_id}", headers=_auth(token))
    assert resp.status_code == 204, resp.text

    # Exactly one primary among the survivors — the oldest.
    assert await _primaries(db_session, gid) == [ns2_id]

    resp = await client.post(
        f"/api/v1/dns/groups/{gid}/zones/{zid}/records",
        json={"name": "web", "record_type": "A", "value": "10.0.0.50"},
        headers=_auth(token),
    )
    assert resp.status_code in (200, 201), resp.text
    db_session.expire_all()
    zone = await db_session.get(DNSZone, zid)
    assert zone is not None
    assert await _op_servers(db_session, zone) == {ns2_id, ns3_id}


@pytest.mark.asyncio
async def test_agent_group_with_no_primary_still_fans_out(db_session: AsyncSession) -> None:
    grp = await _group(db_session, "g2276-noprimary")
    a = await _server(db_session, grp, "a")
    b = await _server(db_session, grp, "b")
    zone = await _zone(db_session, grp)
    await db_session.commit()

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "web", "type": "A", "value": "10.0.0.50"}
    )
    await db_session.flush()

    assert op is not None
    assert await _op_servers(db_session, zone) == {a.id, b.id}


@pytest.mark.asyncio
async def test_agentless_group_with_no_primary_writes_through_one_server(
    db_session: AsyncSession,
) -> None:
    """The write must land somewhere, not return None behind a 200. Nothing is
    committed, so the post-commit provider dispatch (#1539) never runs."""
    grp = await _group(db_session, "g2276-agentless")
    first = await _server(
        db_session, grp, "dc1", driver="windows_dns", host="10.0.0.1", created_at=_at(0)
    )
    await _server(db_session, grp, "dc2", driver="windows_dns", host="10.0.0.2", created_at=_at(1))
    zone = await _zone(db_session, grp)
    await db_session.flush()

    with patch("app.services.dns.record_ops._defer_agentless"):
        op = await enqueue_record_op(
            db_session, zone, "create", {"name": "web", "type": "A", "value": "10.0.0.50"}
        )
    assert op is not None
    assert op.server_id == first.id
    assert await _op_servers(db_session, zone) == {first.id}
    await db_session.rollback()


@pytest.mark.asyncio
async def test_beat_sweep_heals_a_group_left_without_a_primary(
    db_session: AsyncSession,
) -> None:
    from app.services.dns.record_ops import heal_primaryless_groups

    broken = await _group(db_session, "g2276-broken")
    paused = await _server(db_session, broken, "p", maintenance_mode=True)
    usable = await _server(db_session, broken, "u")
    healthy = await _group(db_session, "g2276-healthy")
    keep = await _server(db_session, healthy, "k", is_primary=True)
    await _server(db_session, healthy, "k2")
    await _group(db_session, "g2276-empty")
    await db_session.commit()
    broken_id, paused_id, usable_id = broken.id, paused.id, usable.id
    healthy_id, keep_id = healthy.id, keep.id

    assert await heal_primaryless_groups(db_session) == 1
    await db_session.commit()
    healed = await _primaries(db_session, broken_id)
    assert healed == [usable_id]
    assert paused_id not in healed
    assert await _primaries(db_session, healthy_id) == [keep_id]

    # Idempotent.
    assert await heal_primaryless_groups(db_session) == 0


@pytest.mark.asyncio
async def test_revoking_the_appliance_that_owned_the_primary_elects_a_successor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The appliance revoke deletes the appliance's DNS server rows (#197) —
    the other way a group loses its primary. It must elect among the servers
    left, never one of the rows it is deleting."""
    from tests.test_appliance_delete_dependents import (
        _make_superadmin,
        _seed_appliance,
        _seed_dns_server,
    )

    password = "test-pw-2276"
    _, token = await _make_superadmin(db_session, password=password)
    grp = await _group(db_session, "g2276-revoke")
    appliance = await _seed_appliance(db_session, hostname="ddi-2276-a")
    owned = await _seed_dns_server(db_session, grp, "ddi-2276-a")
    owned.is_primary = True
    survivor = await _seed_dns_server(db_session, grp, "ddi-2276-b")
    await db_session.commit()
    gid, survivor_id = grp.id, survivor.id

    resp = await client.request(
        "DELETE",
        f"/api/v1/appliance/appliances/{appliance.id}",
        headers={"Authorization": f"Bearer {token}"},
        json={"password": password},
    )
    assert resp.status_code == 200, resp.text
    assert await _primaries(db_session, gid) == [survivor_id]

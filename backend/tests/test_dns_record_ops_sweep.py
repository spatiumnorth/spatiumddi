"""#964 — the zone-scoped ``DNSRecordOp`` sweep lives in ONE helper, and its
name-scoping under split-horizon is a documented decision, not an accident.

``DNSRecordOp`` carries ``(server_id, zone_name)`` and no view discriminator,
while ``DNSZone`` is unique on ``(group_id, view_id, name)`` — so two zones
of the same name in sibling views share a queue. ``queued_zone_ops_where``
records why that is accepted: with views present the bundle build ships no
ops at all (records ride the structural fingerprint and every queued op is
retired as ``applied``), so a sibling's op the sweep discards was never going
to reach the agent. These tests pin:

  * the helper's behaviour — queued states swept, history kept, other
    groups untouched, the count agrees with the sweep;
  * the documented over-sweep, so a future change to it is deliberate;
  * that the mechanism the decision rests on still holds — a group with
    views dispatches no ops and retires the queue;
  * that no module outside ``record_ops`` carries a copy of the predicate
    or spells the queued-state tuple by hand.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.record_ops import (
    QUEUED_OP_STATES,
    count_queued_zone_ops,
    sweep_zone_ops,
)

_APP = Path(__file__).resolve().parents[1] / "app"
# The one module allowed to spell the predicate / the state tuple.
_OWNER = _APP / "services" / "dns" / "record_ops.py"


async def _group_with_servers(db: AsyncSession, n: int) -> tuple[DNSServerGroup, list[DNSServer]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    servers = [
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host=f"10.0.0.{i + 1}",
            name=f"srv{i}-{uuid.uuid4().hex[:4]}",
            is_primary=(i == 0),
            is_enabled=True,
        )
        for i in range(n)
    ]
    db.add_all(servers)
    await db.flush()
    return grp, servers


async def _zone(
    db: AsyncSession, grp: DNSServerGroup, name: str, view_id: uuid.UUID | None = None
) -> DNSZone:
    zone = DNSZone(
        group_id=grp.id,
        view_id=view_id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{name}",
        admin_email=f"admin.{name}",
    )
    db.add(zone)
    await db.flush()
    return zone


def _op(server: DNSServer, zone_name: str, state: str) -> DNSRecordOp:
    return DNSRecordOp(
        server_id=server.id,
        zone_name=zone_name,
        op="create",
        record={"name": "www", "type": "A", "value": "10.0.0.1"},
        state=state,
    )


async def _states(db: AsyncSession, server: DNSServer) -> list[str]:
    rows = (
        (
            await db.execute(
                select(DNSRecordOp)
                .where(DNSRecordOp.server_id == server.id)
                .order_by(DNSRecordOp.state)
            )
        )
        .scalars()
        .all()
    )
    return sorted(o.state for o in rows)


@pytest.mark.asyncio
async def test_sweep_discards_queued_keeps_history_and_other_groups(
    db_session: AsyncSession,
) -> None:
    grp, (a, b) = await _group_with_servers(db_session, 2)
    other_grp, (c,) = await _group_with_servers(db_session, 1)
    zone = await _zone(db_session, grp, f"z{uuid.uuid4().hex[:6]}.example.")
    other = await _zone(db_session, grp, f"o{uuid.uuid4().hex[:6]}.example.")
    for state in ("pending", "in_flight", "applied", "failed"):
        db_session.add(_op(a, zone.name, state))
    db_session.add(_op(b, zone.name, "pending"))  # second server, SAME group
    db_session.add(_op(a, other.name, "pending"))  # a different zone, same server
    db_session.add(_op(c, zone.name, "pending"))  # same zone name, ANOTHER group
    await db_session.flush()

    assert set(QUEUED_OP_STATES) == {"pending", "in_flight"}
    assert await count_queued_zone_ops(db_session, zone, grp.id) == 3
    # Every server of the group — a sweep that reached only the primary would
    # leave the secondaries' queues behind (the #934 fan-out bug).
    assert await sweep_zone_ops(db_session, zone, grp.id) == 3

    assert await _states(db_session, a) == ["applied", "failed", "pending"]  # other zone's
    assert await _states(db_session, b) == []
    assert await _states(db_session, c) == ["pending"]
    assert await count_queued_zone_ops(db_session, zone, other_grp.id) == 1


@pytest.mark.asyncio
async def test_sweep_is_name_scoped_across_sibling_views_by_decision(
    db_session: AsyncSession,
) -> None:
    """The documented over-sweep (#964), for ops that name no view (NULL: queued
    before #2242 or in a flat group). Under split-horizon the same name
    exists once per view and the op queue cannot tell them apart — and does
    not need to, because a group with views ships no ops (next test). If this
    starts failing because the sweep became view-exact, update the decision in
    ``queued_zone_ops_where`` in the same change."""
    grp, (a,) = await _group_with_servers(db_session, 1)
    internal = DNSView(group_id=grp.id, name="internal", order=0)
    external = DNSView(group_id=grp.id, name="external", order=1)
    db_session.add_all([internal, external])
    await db_session.flush()
    name = f"split{uuid.uuid4().hex[:6]}.example."
    z_int = await _zone(db_session, grp, name, view_id=internal.id)
    z_ext = await _zone(db_session, grp, name, view_id=external.id)
    assert z_int.id != z_ext.id and z_int.name == z_ext.name
    db_session.add(_op(a, name, "pending"))
    db_session.add(_op(a, name, "in_flight"))
    await db_session.flush()

    assert await count_queued_zone_ops(db_session, z_int, grp.id) == 2
    assert await sweep_zone_ops(db_session, z_int, grp.id) == 2
    assert await count_queued_zone_ops(db_session, z_ext, grp.id) == 0


@pytest.mark.asyncio
async def test_a_group_with_views_ships_no_ops_and_retires_its_queue(
    db_session: AsyncSession,
) -> None:
    """The invariant the #964 decision rests on. If a future change makes ops
    view-aware and starts dispatching them under split-horizon, this fails and
    the sweep's name-scoping must be revisited in the same change."""
    grp, (a,) = await _group_with_servers(db_session, 1)
    view = DNSView(group_id=grp.id, name="internal", order=0)
    db_session.add(view)
    await db_session.flush()
    zone = await _zone(db_session, grp, f"v{uuid.uuid4().hex[:6]}.example.", view_id=view.id)
    db_session.add(
        DNSRecord(
            zone_id=zone.id, name="www", fqdn=f"www.{zone.name}", record_type="A", value="10.0.0.1"
        )
    )
    db_session.add(_op(a, zone.name, "pending"))
    db_session.add(_op(a, zone.name, "in_flight"))
    await db_session.flush()

    bundle = await build_config_bundle(db_session, a)
    assert bundle["pending_record_ops"] == []
    assert await _states(db_session, a) == ["applied", "applied"]


def test_no_module_outside_record_ops_spells_the_sweep_or_the_state_tuple() -> None:
    """Three sites in two files carried the same three-clause predicate
    verbatim (#951 copied it from zone_move), and two more hand-spelled the
    queued-state tuple. Both now live in ``record_ops``; a re-inlined copy
    anywhere under ``app/`` — not just the files that had one — would fork the
    #964 decision silently."""
    sweep = re.compile(r"sa_delete\(DNSRecordOp\)")
    # A zone-name match on its own is a read (acme dns01 polls its TXT op by
    # zone + serial); it is the queued-STATE clause beside it that makes a
    # sweep or count predicate.
    queued_predicate = re.compile(
        r"DNSRecordOp\.zone_name\s*==[\s\S]{0,200}DNSRecordOp\.state\.in_"
    )
    state_tuple = re.compile(r"""\(\s*["']pending["']\s*,\s*["']in_flight["']\s*\)""")
    offenders: list[str] = []
    for path in sorted(_APP.rglob("*.py")):
        if path == _OWNER:
            continue
        src = path.read_text(encoding="utf-8")
        rel = path.relative_to(_APP).as_posix()
        # server_move sweeps by SERVER, deliberately (a server leaving a group
        # takes its whole queue with it) — the one allowed delete outside the
        # owner, and it must stay zone-blind.
        if sweep.search(src) and rel != "services/dns/server_move.py":
            offenders.append(f"{rel}: sa_delete(DNSRecordOp) outside record_ops")
        if queued_predicate.search(src):
            offenders.append(f"{rel}: zone-scoped queued-ops predicate (use record_ops)")
        if state_tuple.search(src):
            offenders.append(f"{rel}: hand-spelled queued-state tuple (use QUEUED_OP_STATES)")
    assert offenders == [], offenders
    for rel in ("services/dns/zone_move.py", "services/ai/operations_risky.py"):
        assert "sweep_zone_ops" in (_APP / rel).read_text(encoding="utf-8"), rel


@pytest.mark.asyncio
async def test_soft_deleting_a_zone_sweeps_its_queued_ops(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The default (soft) zone delete is the moment the zone leaves the bundle,
    so its queued ops become unapplyable then — not only on ``?permanent``.
    Left behind, each op was shipped up to five times against a zone the agent
    no longer serves and then parked as ``failed`` forever (review of #964)."""
    user = User(
        username=f"sw-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Sweep Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    grp, (a,) = await _group_with_servers(db_session, 1)
    zone = await _zone(db_session, grp, f"sd{uuid.uuid4().hex[:6]}.example.")
    db_session.add(_op(a, zone.name, "pending"))
    db_session.add(_op(a, zone.name, "in_flight"))
    db_session.add(_op(a, zone.name, "applied"))
    await db_session.commit()
    server_id, zone_id, group_id = a.id, zone.id, grp.id

    resp = await client.delete(f"/api/v1/dns/groups/{group_id}/zones/{zone_id}", headers=headers)
    assert resp.status_code == 204, resp.text

    db_session.expire_all()
    rows = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.server_id == server_id)))
        .scalars()
        .all()
    )
    assert sorted(o.state for o in rows) == ["applied"]
    trashed = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone_id).execution_options(include_deleted=True)
        )
    ).scalar_one()
    assert trashed.deleted_at is not None

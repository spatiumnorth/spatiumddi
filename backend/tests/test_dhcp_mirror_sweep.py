"""#620 — the orphaned-reservation-mirror sweep.

A reservation owns an ``ip_address`` row at ``status="static_dhcp"``, back-linked
by id. When a path destroys the reservation without releasing that mirror, the
address is left neither allocated nor free nor reclaimable — and invisibly so:
every release path looks the mirror up by the reservation's *current* id and
matches nothing, so no amount of clicking in the UI frees it. The paths are
fixed (#618, #620), but the failure mode is bad enough to be worth a backstop.

The sweep therefore has to be sharp in both directions: it must free provable
residue, and it must not touch anything an operator could have made by hand.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import sweep_orphaned_static_mirrors, upsert_ipam_for_static


async def _fixture(db: AsyncSession) -> tuple[DHCPScope, Subnet]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.30.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.30.0.0/24", name="sn")
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    return scope, subnet


async def _reservation(
    db: AsyncSession, scope: DHCPScope, *, ip: str = "10.30.0.10"
) -> DHCPStaticAssignment:
    st = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address=ip,
        mac_address="aa:bb:cc:00:00:01",
        hostname="printer",
        description="",
    )
    db.add(st)
    await db.flush()
    await upsert_ipam_for_static(db, scope, st)
    await db.flush()
    return st


async def _mirror(db: AsyncSession, subnet: Subnet, ip: str) -> IPAddress | None:
    return (
        await db.execute(
            select(IPAddress).where(IPAddress.subnet_id == subnet.id, IPAddress.address == ip)
        )
    ).scalar_one_or_none()


@pytest.mark.asyncio
async def test_sweep_frees_a_mirror_whose_reservation_vanished(
    db_session: AsyncSession,
) -> None:
    """The residue: reservation gone from the table, mirror still holding the
    address at static_dhcp. Exactly what the pre-#620 Core-DELETE left behind."""
    scope, subnet = await _fixture(db_session)
    st = await _reservation(db_session, scope)
    # Destroy the reservation the way a Core DELETE does — no per-row Python, so
    # nothing releases the mirror.
    await db_session.execute(
        DHCPStaticAssignment.__table__.delete().where(DHCPStaticAssignment.id == st.id)
    )
    await db_session.flush()

    stranded = await _mirror(db_session, subnet, "10.30.0.10")
    assert stranded is not None
    assert stranded.status == "static_dhcp"  # stuck: not allocated, not free

    freed = await sweep_orphaned_static_mirrors(db_session)
    await db_session.commit()

    assert freed == 1
    # Deleted outright, not left at "available": a persisted freed row still
    # renders as a line in the subnet table and still counts toward utilization
    # (#618). The address folds back into a free gap.
    assert await _mirror(db_session, subnet, "10.30.0.10") is None


@pytest.mark.asyncio
async def test_sweep_leaves_a_live_reservations_mirror_alone(
    db_session: AsyncSession,
) -> None:
    """The thing the sweep must never do."""
    scope, subnet = await _fixture(db_session)
    st = await _reservation(db_session, scope)
    await db_session.commit()

    freed = await sweep_orphaned_static_mirrors(db_session)
    await db_session.commit()

    assert freed == 0
    mirror = await _mirror(db_session, subnet, "10.30.0.10")
    assert mirror is not None
    assert mirror.status == "static_dhcp"
    assert mirror.static_assignment_id == str(st.id)


@pytest.mark.asyncio
async def test_sweep_ignores_a_hand_made_static_dhcp_row(
    db_session: AsyncSession,
) -> None:
    """A ``static_dhcp`` row with a NULL back-link is reachable by hand — an
    operator can set that status themselves. A sweeper that deletes hand-made
    rows would be worse than the bug it fixes, so the predicate requires a
    non-NULL back-link that resolves to nothing: provable residue, nothing else."""
    _scope, subnet = await _fixture(db_session)
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.30.0.99",
            status="static_dhcp",
            description="set by hand",
        )
    )
    await db_session.commit()

    freed = await sweep_orphaned_static_mirrors(db_session)
    await db_session.commit()

    assert freed == 0
    survivor = await _mirror(db_session, subnet, "10.30.0.99")
    assert survivor is not None
    assert survivor.description == "set by hand"


@pytest.mark.asyncio
async def test_sweep_frees_a_mirror_of_a_soft_deleted_reservation_losslessly(
    db_session: AsyncSession,
) -> None:
    """A reservation in the Trash has already had its mirror removed (#618) and
    gets it re-created on restore, so a mirror still pointing at a soft-deleted
    one is residue too. But the reservation is still around to hold the
    operator's columns — snapshot them onto it, so the restore stays lossless."""
    from datetime import UTC, datetime

    scope, subnet = await _fixture(db_session)
    st = await _reservation(db_session, scope)
    mirror = await _mirror(db_session, subnet, "10.30.0.10")
    assert mirror is not None
    mirror.description = "rack 4, port 12"
    mirror.tags = {"owner": "lab"}
    st.deleted_at = datetime.now(UTC)  # scope batch soft-delete, mirror left behind
    await db_session.commit()

    freed = await sweep_orphaned_static_mirrors(db_session)
    await db_session.commit()

    assert freed == 1
    assert await _mirror(db_session, subnet, "10.30.0.10") is None
    # The operator's columns rode onto the retained reservation, so restoring the
    # scope brings them back rather than resurrecting a blank row.
    await db_session.refresh(st)
    assert st.ipam_metadata_snapshot == {"description": "rack 4, port 12", "tags": {"owner": "lab"}}


@pytest.mark.asyncio
async def test_sweep_is_idempotent(db_session: AsyncSession) -> None:
    """It runs hourly on every install forever; a second pass must be a no-op."""
    scope, subnet = await _fixture(db_session)
    st = await _reservation(db_session, scope)
    await db_session.execute(
        DHCPStaticAssignment.__table__.delete().where(DHCPStaticAssignment.id == st.id)
    )
    await db_session.flush()

    assert await sweep_orphaned_static_mirrors(db_session) == 1
    await db_session.commit()
    assert await sweep_orphaned_static_mirrors(db_session) == 0
    await db_session.commit()


def _patch_sweep(monkeypatch: pytest.MonkeyPatch, db: AsyncSession, counts: list[int]) -> None:
    from contextlib import asynccontextmanager

    import app.tasks.dhcp_mirror_sweep as sw

    @asynccontextmanager
    async def _ts():  # type: ignore[no-untyped-def]
        yield db

    async def _enabled(*_a, **_k):  # type: ignore[no-untyped-def]
        return True

    async def _static(*_a, **_k):  # type: ignore[no-untyped-def]
        return 0

    it = iter(counts)

    async def _lease(*_a, **_k):  # type: ignore[no-untyped-def]
        return next(it)

    monkeypatch.setattr(sw, "task_session", _ts)
    monkeypatch.setattr(sw, "is_module_enabled", _enabled)
    monkeypatch.setattr(sw, "sweep_orphaned_static_mirrors", _static)
    monkeypatch.setattr(sw, "sweep_orphaned_lease_mirrors", _lease)
    monkeypatch.setattr(sw, "_MAX_PER_RUN", 2)


async def _last_sweep_audit(db: AsyncSession):  # type: ignore[no-untyped-def]
    from app.models.audit import AuditLog

    return (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.action == "dhcp-mirror-sweep")
            .order_by(AuditLog.timestamp.desc())
            .limit(1)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_sweep_audit_not_capped_when_it_freed_everything(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.dhcp_mirror_sweep as sw

    _patch_sweep(monkeypatch, db_session, [2, 2, 1])  # 5 freed, last batch short
    assert await sw._sweep() == 5
    row = await _last_sweep_audit(db_session)
    assert row.new_value == {"mirrors_freed": 5, "capped": False}
    assert row.resource_display == "orphaned DHCP mirrors (reservation + lease)"


@pytest.mark.asyncio
async def test_sweep_audit_capped_when_budget_runs_out(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.tasks.dhcp_mirror_sweep as sw

    _patch_sweep(monkeypatch, db_session, [2, 2])
    monkeypatch.setattr(sw, "_LEASE_SWEEP_BUDGET_S", -1.0)  # already expired
    assert await sw._sweep() == 2
    row = await _last_sweep_audit(db_session)
    assert row.new_value["capped"] is True

"""#3627 follow-up: a restore pre-locks the zones its re-mirrored reservations
publish into.

Trash deletes a reservation's address row and its A / PTR records, so when the
trashed subnet's addresses are all DHCP reservations (or only the scope is
trashed) no record names the forward zone. The restore's pre-lock found the
linked reverse zone alone, and the re-mirror (``remirror_scope_statics``) then
took the forward zone while holding the reverse one: the opposite of the
lease-events handler, which takes forward then reverse by id. The autouse
row-lock guard (``tests/_row_lock_order_guard.py``) records that inversion and
fails the test that made it.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.admin import trash as trash_router
from app.core.security import hash_password
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, Subnet
from tests.test_lease_events_insert_order_3480 import _ddns_subnet
from tests.test_lock_order_3617 import _hold_first_call, _no_deadlock, _race


@pytest.fixture
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    """Sessions of their own, each on its own connection."""
    eng = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        yield eng
    finally:
        await eng.dispose()


async def _trashed_reservations(
    db: AsyncSession, *, trash_subnet: bool
) -> tuple[Subnet, DHCPScope, DNSZone, DNSZone, User]:
    subnet, _block = await _ddns_subnet(db)
    fwd = (
        await db.execute(select(DNSZone).where(DNSZone.id == uuid.UUID(subnet.dns_zone_id)))
    ).scalar_one()
    rev = (
        await db.execute(select(DNSZone).where(DNSZone.linked_subnet_id == subnet.id))
    ).scalar_one()
    assert fwd.id < rev.id  # the suite makes zone ids ascend in creation order
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    batch, now = uuid.uuid4(), datetime.now(UTC)
    scope = DHCPScope(
        group_id=grp.id,
        subnet_id=subnet.id,
        is_active=True,
        deleted_at=now,
        deletion_batch_id=batch,
    )
    db.add(scope)
    await db.flush()
    for n in (10, 11):
        db.add(
            DHCPStaticAssignment(
                scope_id=scope.id,
                ip_address=f"10.31.1.{n}",
                mac_address=f"aa:bb:cc:31:01:{n}",
                hostname=f"h{n}",
                deleted_at=now,
                deletion_batch_id=batch,
            )
        )
    if trash_subnet:
        subnet.deleted_at, subnet.deletion_batch_id = now, batch
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    return subnet, scope, fwd, rev, user


@pytest.mark.asyncio
async def test_scope_statics_zones_are_found_before_any_record_exists(
    db_session: AsyncSession,
) -> None:
    from app.services.lock_order import zone_ids_for_scope_statics, zone_ids_for_subnets

    subnet, scope, fwd, rev, _user = await _trashed_reservations(db_session, trash_subnet=True)
    # Nothing names the forward zone: the old pre-lock's whole input.
    assert await zone_ids_for_subnets(db_session, [subnet.id]) == {rev.id}
    assert await zone_ids_for_scope_statics(db_session, [scope.id]) == {fwd.id, rev.id}


@pytest.mark.asyncio
@pytest.mark.parametrize("trash_subnet", [True, False], ids=["subnet", "scope-only"])
async def test_restore_of_reservations_takes_forward_zone_before_reverse(
    db_session: AsyncSession, trash_subnet: bool
) -> None:
    """Fails (via the row-lock guard) when the pre-lock takes the reverse zone
    alone and the re-mirror then asks for the lower-id forward zone."""
    subnet, scope, fwd, _rev, user = await _trashed_reservations(
        db_session, trash_subnet=trash_subnet
    )
    row_type, row_id = ("subnet", subnet.id) if trash_subnet else ("dhcp_scope", scope.id)

    await trash_router.restore_row(row_type, row_id, db_session, user)

    assert (
        await db_session.execute(select(IPAddress.address).where(IPAddress.subnet_id == subnet.id))
    ).all(), "the reservations' address rows are re-created"
    names = (
        (await db_session.execute(select(DNSRecord.name).where(DNSRecord.zone_id == fwd.id)))
        .scalars()
        .all()
    )
    assert sorted(names) == ["h10", "h11"]


@pytest.mark.asyncio
@pytest.mark.parametrize("trash_subnet", [True, False], ids=["subnet", "scope-only"])
async def test_restore_of_reservations_and_a_ddns_writer_do_not_deadlock(
    db_session: AsyncSession,
    engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    trash_subnet: bool,
) -> None:
    """The ddi-pg walk's case 1 on two real sessions. The restore is held just
    before its re-mirror; a writer that takes the forward zone then the reverse
    one by id (the lease-events DDNS publish) is started then. Unfixed, the
    restore holds the reverse zone alone, the writer takes the forward zone and
    waits for the reverse, and the re-mirror's ask for the forward zone closes
    the cycle (40P01). Fixed, the restore already holds both."""
    from app.services.lock_order import lock_zone_rows

    subnet, scope, fwd, rev, user = await _trashed_reservations(
        db_session, trash_subnet=trash_subnet
    )
    row_type, row_id = ("subnet", subnet.id) if trash_subnet else ("dhcp_scope", scope.id)
    fwd_id, rev_id, user_id = fwd.id, rev.id, user.id

    holder: dict[str, AsyncSession] = {}
    reached = asyncio.Event()
    log: list[str] = []
    _hold_first_call(monkeypatch, trash_router, "remirror_scope_statics", holder, reached, log)

    async def _restore() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            holder["db"] = db
            u = await db.get(User, user_id)
            await trash_router.restore_row(row_type, row_id, db, u)

    async def _writer() -> None:
        async with AsyncSession(engine, expire_on_commit=False) as db:
            await lock_zone_rows(db, [fwd_id, rev_id])
            await db.commit()

    _no_deadlock(await _race(_restore, _writer, reached), log)

    names = (
        (
            await db_session.execute(
                select(DNSRecord.name)
                .where(DNSRecord.zone_id == fwd_id)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert sorted(names) == ["h10", "h11"]


@pytest.mark.asyncio
async def test_scope_statics_zones_include_an_incumbent_rows_own_zone(
    db_session: AsyncSession,
) -> None:
    """A scope trashed on its own leaves its subnet live, and an operator may
    allocate a reservation's address in the meantime, in a zone other than the
    subnet's and with no name (so no record names that zone). The re-mirror
    takes that row over and publishes the reservation's name into the row's
    own zone (``address_own_forward_zone_id``), so the pre-lock has to take it
    too; a transient row at the address would resolve the subnet's zone only."""
    from app.services.lock_order import zone_ids_for_scope_statics

    subnet, scope, fwd, rev, _user = await _trashed_reservations(db_session, trash_subnet=False)
    other = DNSZone(
        group_id=fwd.group_id,
        name=f"o{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db_session.add(other)
    await db_session.flush()
    db_session.add(
        IPAddress(
            subnet_id=subnet.id,
            address="10.31.1.10",
            status="allocated",
            hostname="",
            forward_zone_id=other.id,
        )
    )
    await db_session.commit()

    assert await zone_ids_for_scope_statics(db_session, [scope.id]) == {
        fwd.id,
        rev.id,
        other.id,
    }
    # The premise: the re-mirror does publish into the row's own zone.
    await trash_router.restore_row("dhcp_scope", scope.id, db_session, _user)
    names = (
        (await db_session.execute(select(DNSRecord.name).where(DNSRecord.zone_id == other.id)))
        .scalars()
        .all()
    )
    assert names == ["h10"]

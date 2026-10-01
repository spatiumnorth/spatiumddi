"""IPAM mirror lifecycle for DHCP static reservations (#618).

A reservation owns an ``ip_address`` row: ``status="static_dhcp"``, back-linked
via ``IPAddress.static_assignment_id``, so the subnet view shows the
reservation alongside regular addresses and a dynamic pool can't hand the
address out from under it.

These helpers used to live inside ``api/v1/dhcp/statics.py`` and were therefore
only reachable from the per-reservation CRUD handlers. The paths that destroy
reservations *wholesale* skipped them, because those paths delete through FK
CASCADE (or a Core ``DELETE``) and run no per-row Python. The result was an
``ip_address`` row stranded at ``status="static_dhcp"`` pointing at a
reservation Postgres had already removed: not allocated, not free, not
reclaimable by any sweeper.

They live here so those paths can reuse them without importing an HTTP router.
Wired in as of #618:

* scope permanent-delete (``ai.operations_risky._apply_delete_scope``)
* trash permanent-delete (``api.v1.admin.trash.permanent_delete_from_trash``)
* the nightly purge sweep (``tasks.trash_purge``)
* DHCP server-group delete (``ai.operations_risky._apply_delete_group``)
* DHCP-import ``overwrite`` (``services.dhcp_import.commit``)

``services.dhcp.pull_leases._upsert_scope`` — the Windows scope reconciler —
used to be the one path that destroyed reservations without coming through
here: it Core-DELETEd every reservation under a scope and re-inserted them from
the wire, stranding the mirror of any reservation an operator had created in
the UI. #620 fixed it by making that reconciler diff-merge instead of replace,
so a reservation keeps its id across polls and its mirror's back-link stays
valid. It calls ``upsert_ipam_for_static`` only for reservations that actually
changed (a schedule-driven detach/re-attach would have torn down and recreated
the forward A record on every pass), and ``remove_ipam_for_static`` for the ones
that genuinely vanished from the server.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPScope, DHCPStaticAssignment
from app.models.ipam import IPAddress, Subnet
from app.services.dhcp.ipam_mirror import insert_ipam_mirror_row
from app.services.dhcp.lease_cleanup import _resolve_lease_subnet_id

logger = structlog.get_logger(__name__)

__all__ = [
    "LeaseHandover",
    "detach_ipam_for_static",
    "publish_handover_ddns",
    "remirror_scope_statics",
    "remove_ipam_for_scope_statics",
    "remove_ipam_for_static",
    "sweep_orphaned_static_mirrors",
    "upsert_ipam_for_static",
]


# Operator-authored columns on the ``ip_address`` mirror that a wholesale
# reservation delete would otherwise lose (the DHCP-derived columns —
# status / hostname / mac / back-links — are re-derived from the static on
# restore, so they're excluded). ``uuid`` / ``datetime`` / ``date`` values are
# JSON-encoded to ISO strings on snapshot and parsed back on restore.
_OPERATOR_MIRROR_FIELDS: tuple[str, ...] = (
    "description",
    "tags",
    "custom_fields",
    "owner_user_id",
    "owner_group_id",
    "managed_by",
    "role",
    "reserved_until",
    "decom_date",
)


def _snapshot_operator_fields(row: IPAddress) -> dict[str, Any] | None:
    """Capture the operator-authored columns of ``row`` as a JSON-safe dict.

    Returns ``None`` when every field is at its empty/default value, so we
    don't persist a snapshot that carries nothing.
    """
    snap: dict[str, Any] = {}
    for field in _OPERATOR_MIRROR_FIELDS:
        val = getattr(row, field, None)
        if val in (None, "", {}, []):
            continue
        if isinstance(val, uuid.UUID):
            snap[field] = str(val)
        elif isinstance(val, (datetime, date)):
            snap[field] = val.isoformat()
        else:
            snap[field] = val
    return snap or None


def _restore_operator_fields(row: IPAddress, snapshot: dict[str, Any]) -> None:
    """Re-apply a :func:`_snapshot_operator_fields` dict onto a fresh mirror row."""
    for field, val in snapshot.items():
        if field not in _OPERATOR_MIRROR_FIELDS:
            continue
        try:
            if field in ("owner_user_id", "owner_group_id") and isinstance(val, str):
                setattr(row, field, uuid.UUID(val))
            elif field == "reserved_until" and isinstance(val, str):
                setattr(row, field, datetime.fromisoformat(val))
            elif field == "decom_date" and isinstance(val, str):
                setattr(row, field, date.fromisoformat(val))
            else:
                setattr(row, field, val)
        except (ValueError, TypeError):
            # A malformed snapshot value must never break restore.
            continue


async def upsert_ipam_for_static(
    db: AsyncSession,
    scope: DHCPScope,
    st: DHCPStaticAssignment,
    *,
    action: str = "create",
) -> None:
    """Create or update the IPAM row mirroring a static DHCP assignment.

    The static is the source of truth for hostname/MAC; IPAM reflects it with
    ``status='static_dhcp'`` and a back-link via ``static_assignment_id`` so the
    subnet view shows the reservation alongside regular addresses.
    """
    ip_str = str(st.ip_address)
    # Release any previous IPAM row this static was pointing at (its address
    # changed). Freeing the row it left behind — rather than downgrading it to
    # ``allocated``, which is what this did before #620 — because an
    # ``allocated`` row with no owner is reclaimed by NOTHING: the orphan sweep
    # only looks at ``static_dhcp`` rows, and the lease-mirror path skips rows it
    # doesn't own. Every reservation re-address leaked its old address into a
    # permanently-allocated ghost, and the Windows reconciler now re-addresses
    # reservations on its own, so a renumber on the server would leak one address
    # per reservation. Deleting the row also snapshots the operator's columns
    # onto the reservation, which the restore below re-applies at the new
    # address — so a move carries them across instead of stranding them.
    prior = await db.execute(select(IPAddress).where(IPAddress.static_assignment_id == str(st.id)))
    for row in prior.scalars().all():
        if str(row.address) == ip_str:
            continue
        if row.status == "static_dhcp":
            await _delete_mirror_row(db, row, st)
        else:
            # Not ours to delete — an operator re-purposed the row's status. Just
            # drop the back-link so it can't dangle.
            row.static_assignment_id = None
    # Find or create the IPAM row for this IP within the scope's subnet.
    res = await db.execute(
        select(IPAddress).where(IPAddress.subnet_id == scope.subnet_id, IPAddress.address == ip_str)
    )
    row = res.scalar_one_or_none()
    if row is None:
        # #564 — a concurrent Kea agent lease-event / Sync-DHCP writer
        # may have already mirrored a dynamic lease at this IP. Insert
        # inside a savepoint so the unique-violation self-heals into the
        # incumbent row (which we then overwrite to static_dhcp — the
        # static is the source of truth) instead of 500-ing on
        # uq_ip_address_subnet_address.
        candidate = IPAddress(subnet_id=scope.subnet_id, address=ip_str, status="static_dhcp")
        row, _created = await insert_ipam_mirror_row(db, candidate)
    # Assigned outright, not ``st.hostname or row.hostname``: the reservation is
    # the source of truth for the hostname (as it already is for the MAC, right
    # below), and the ``or`` made an empty one unrepresentable — clearing a
    # reservation's name left the mirror on the old name and re-published the
    # stale A record off it, with no number of polls able to converge them.
    row.hostname = st.hostname
    row.mac_address = str(st.mac_address)
    row.status = "static_dhcp"
    row.static_assignment_id = str(st.id)
    # Restore any operator-authored columns captured when this reservation's
    # mirror was deleted (lossless Trash restore, #630), then clear the
    # snapshot so it can't go stale or re-apply on a later ordinary edit.
    if st.ipam_metadata_snapshot:
        _restore_operator_fields(row, st.ipam_metadata_snapshot)
        st.ipam_metadata_snapshot = None
    await db.flush()
    st.ip_address_id = row.id
    # Fire DNS sync so forward/reverse records follow the static.
    from app.api.v1.ipam.router import _sync_dns_record  # noqa: PLC0415

    subnet_row = await db.get(Subnet, scope.subnet_id)
    if subnet_row is not None and row.hostname:
        try:
            await _sync_dns_record(db, row, subnet_row, action=action)
        except Exception:  # noqa: BLE001 — DNS sync is best-effort
            pass


async def detach_ipam_for_static(
    db: AsyncSession,
    st: DHCPStaticAssignment,
    *,
    to_status: str = "available",
) -> list[LeaseHandover]:
    """Release the IPAM row back to ``available`` when the static is removed.

    Also tears down the forward A (DNS sync with action=delete).

    The row is freed to ``available`` (not ``allocated``): the IP no longer
    holds a reservation, and — crucially — a leftover ``allocated`` /
    ``auto_from_lease=False`` row is skipped by the agent's lease-mirror refresh
    (it only re-mirrors ``available`` or ``auto_from_lease`` rows), so it would
    shadow a future dynamic lease at that IP AND never be reaped. ``available``
    lets a new lease reclaim the row (#478).

    Unless a lease already holds the address (#1274). The reserved client's
    grant usually arrives while the row is still ``static_dhcp``, which the
    lease mirror leaves alone, and the agent sends a lease again only on its
    own start, a control-plane recovery or the client's renewal — hours at the
    default lifetime. Freeing the row showed a live device's address as free
    until then, for the next-free allocation to hand to a second device. When
    the product's lease table holds an active lease on the address in this
    row's subnet, the row becomes that lease's mirror instead: the row the
    lease-event ingest would have produced had the lease arrived after the
    delete.

    ``to_status="reserved"`` is the opt-in "hold the address in IPAM after the
    DHCP config is gone" variant — the caller must be an explicitly destructive
    path that asked for it. A held row stays held whatever holds the address;
    the lease mirror leaves a reserved row alone as well.

    Returns the rows handed to a live lease. Their DDNS records are the
    caller's to publish with ``publish_handover_ddns``, and only once the
    reservation itself is deleted: DDNS lets a reservation's hostname win, so
    publishing while it still exists would put its name back on the row.
    """
    from app.api.v1.ipam.router import _sync_dns_record  # noqa: PLC0415

    handovers: list[LeaseHandover] = []

    res = await db.execute(select(IPAddress).where(IPAddress.static_assignment_id == str(st.id)))
    for row in res.scalars().all():
        subnet_row = await db.get(Subnet, row.subnet_id)
        if subnet_row is not None:
            try:
                await _sync_dns_record(db, row, subnet_row, action="delete")
            except Exception:  # noqa: BLE001 — DNS sync is best-effort
                pass
        row.static_assignment_id = None
        if row.status == "static_dhcp":
            lease = await _live_lease_at(db, row) if to_status == "available" else None
            if lease is not None:
                _mirror_lease_onto(row, lease)
                if subnet_row is not None:
                    handovers.append(LeaseHandover(subnet_row, row, lease))
            else:
                row.status = to_status
    return handovers


@dataclass(frozen=True)
class LeaseHandover:
    """A row ``detach_ipam_for_static`` handed to the lease that holds it."""

    subnet: Subnet
    row: IPAddress
    lease: DHCPLease


async def publish_handover_ddns(db: AsyncSession, handovers: list[LeaseHandover]) -> None:
    """Publish the lease's DDNS records for rows that just became its mirror.

    The reservation's own A / PTR were torn down at the detach, and the
    ingest runs ``apply_ddns_for_lease`` whenever it takes a row over, so
    without this the mirror would sit in IPAM with no DNS until the client's
    next renewal (the same wait #1274 removes for IPAM). A no-op when the
    subnet's DDNS is off. Call it only after the reservation is deleted and
    flushed; see ``detach_ipam_for_static``. Best-effort, like the ingest's
    call: a DNS failure never undoes the IPAM hand-over, and the next lease
    event or sweep reconciles it.
    """
    from app.services.dns.ddns import apply_ddns_for_lease  # noqa: PLC0415

    for h in handovers:
        try:
            await apply_ddns_for_lease(
                db, subnet=h.subnet, ipam_row=h.row, client_hostname=h.lease.hostname
            )
        except Exception as exc:  # noqa: BLE001 — see the docstring
            logger.warning(
                "dhcp_static_delete_lease_ddns_failed",
                address=str(h.row.address),
                error=str(exc),
            )


async def _live_lease_at(
    db: AsyncSession, row: IPAddress, *, now: datetime | None = None
) -> DHCPLease | None:
    """The active lease the product holds on ``row``'s address in ``row``'s subnet.

    Active means what the rest of the lease code means by it
    (``lease_cleanup.peer_holds_active_lease``): state ``active`` and not past
    its expiry, so a lease the expiry sweep has not reached yet claims nothing.
    The subnet is resolved the way the lease teardown resolves it — the lease's
    scope first, the longest prefix for a legacy lease with no scope — because
    the same address in another IP space is another network. Under HA each
    server reports its own copy of a lease; the most recently seen one wins.
    """
    if now is None:
        now = datetime.now(UTC)
    leases = (
        (
            await db.execute(
                select(DHCPLease)
                .where(
                    DHCPLease.ip_address == row.address,
                    DHCPLease.state == "active",
                    or_(DHCPLease.expires_at.is_(None), DHCPLease.expires_at > now),
                )
                .order_by(DHCPLease.last_seen_at.desc())
            )
        )
        .scalars()
        .all()
    )
    for lease in leases:
        if await _resolve_lease_subnet_id(db, lease) == row.subnet_id:
            return lease
    return None


def _mirror_lease_onto(row: IPAddress, lease: DHCPLease) -> None:
    """Make ``row`` the IPAM mirror of ``lease``.

    The fields the lease-event ingest stamps on a row it takes over
    (``_apply_lease_fields`` in ``api/v1/dhcp/agents.py``), taken from the
    stored lease rather than an event. The sighting is the lease's own report;
    a later sighting already on the row (a discovery sweep) is kept.
    """
    row.hostname = (lease.hostname or row.hostname or "")[:253]
    row.mac_address = lease.mac_address or row.mac_address
    row.status = "dhcp"
    row.auto_from_lease = True
    row.dhcp_lease_id = str(lease.id)
    if row.last_seen_at is None or lease.last_seen_at > row.last_seen_at:
        row.last_seen_at = lease.last_seen_at
        row.last_seen_method = "dhcp"


async def remove_ipam_for_static(db: AsyncSession, st: DHCPStaticAssignment) -> int:
    """DELETE the IPAM mirror row(s) for a reservation (not just free them).

    ``detach_ipam_for_static`` sets ``status="available"`` and keeps the row.
    But a persisted ``available`` row still renders as an explicit line in the
    IPAM subnet table (the frontend paints one row per address; "free" is the
    *absence* of a row), so a former reservation kept lingering visibly after
    its scope was deleted — and kept counting toward the subnet's utilization.
    This deletes the ``ip_address`` mirror so the IP folds back into a
    "N free · click to allocate" gap and drops out of the allocated count.

    Tears down the forward/reverse DNS first (same as the detach path). Used by
    the wholesale reservation-removal paths (scope / group / import / purge).
    Returns the number of rows removed.
    """
    res = await db.execute(select(IPAddress).where(IPAddress.static_assignment_id == str(st.id)))
    removed = 0
    for row in res.scalars().all():
        await _delete_mirror_row(db, row, st)
        removed += 1
    return removed


async def _delete_mirror_row(
    db: AsyncSession, row: IPAddress, st: DHCPStaticAssignment | None
) -> None:
    """Tear down a mirror row's DNS and delete it.

    ``st`` is the reservation the row mirrors, when we still have it — the
    orphan sweep calls this for rows whose reservation is *gone*, so it passes
    ``None`` and simply skips the parts that need one.
    """
    from app.api.v1.ipam.router import _sync_dns_record  # noqa: PLC0415

    if st is not None:
        # Snapshot operator-authored columns onto the (soft-deleted, retained)
        # reservation before we hard-delete the mirror, so a Trash restore is
        # lossless (#630). The last mirror row wins — there is realistically one.
        snapshot = _snapshot_operator_fields(row)
        if snapshot is not None:
            st.ipam_metadata_snapshot = snapshot
        # Clear the forward FK before the delete so the ORM's in-memory ``st``
        # doesn't hang onto a stale id (the DB FK is ON DELETE SET NULL).
        if st.ip_address_id == row.id:
            st.ip_address_id = None

    subnet_row = await db.get(Subnet, row.subnet_id)
    if subnet_row is not None:
        try:
            await _sync_dns_record(db, row, subnet_row, action="delete")
        except Exception:  # noqa: BLE001 — DNS sync is best-effort
            pass
    await db.delete(row)


async def sweep_orphaned_static_mirrors(db: AsyncSession, *, limit: int = 500) -> int:
    """Free ``ip_address`` rows stuck at ``static_dhcp`` with no live reservation.

    The safety net under every path that destroys a reservation. Those paths are
    all supposed to release the mirror first (#618 wired the ones that didn't,
    #620 fixed the Windows reconciler that re-created reservations under new ids
    and orphaned theirs). But the failure mode is nasty and silent — the address
    is left neither allocated nor free nor reclaimable by any sweeper, and no
    amount of clicking in the UI frees it, because every release path looks the
    mirror up by the *current* reservation id and matches nothing — so it is
    worth being able to recover from without an operator noticing first, and
    without another one-shot repair migration (``d7b3f2a9c15e`` was the last
    one). This is that migration's step 1, made recurring.

    Deliberately narrow. Only rows carrying a **non-NULL** back-link that
    resolves to no live reservation are touched: that state is unreachable by
    any legitimate flow, so it is provably residue. A ``static_dhcp`` row with a
    NULL back-link is left alone — an operator can set that status by hand, and
    a sweeper that deletes hand-made rows is worse than the bug it fixes.

    "Live" excludes soft-deleted reservations, matching ``d7b3f2a9c15e``: a
    scope in the Trash has already had its mirrors removed (#618) and gets them
    re-created on restore, so a mirror still pointing at a soft-deleted
    reservation is residue too — and when that reservation is still around to
    hold it, the operator's columns are snapshotted onto it first, so the
    restore stays lossless.

    Returns the number of mirror rows freed.
    """
    # Two indexed queries rather than one correlated NOT EXISTS. The obvious
    # anti-join has to compare a uuid column against a varchar one, and the
    # ``cast(reservation.id AS text)`` that makes that typecheck also makes the
    # reservation table's primary-key index unusable — so Postgres re-scans it
    # for every candidate row, on a task that runs hourly forever and finds
    # nothing on a healthy install. Resolving the back-links in a second query
    # keyed on the uuid column keeps the PK index in play.
    candidates = (
        (
            await db.execute(
                select(IPAddress)
                .where(
                    IPAddress.status == "static_dhcp",
                    IPAddress.static_assignment_id.is_not(None),
                )
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    if not candidates:
        return 0

    # A back-link that doesn't parse as a uuid can name no reservation at all, so
    # it is residue by definition — keep it in the candidate set (mapped to None)
    # rather than letting it slip through the liveness check unexamined.
    parsed: list[tuple[IPAddress, uuid.UUID | None]] = [
        (row, _parse_uuid(row.static_assignment_id)) for row in candidates
    ]
    wanted = {static_id for _row, static_id in parsed if static_id is not None}

    # Core ``__table__`` so the ORM's soft-delete filter doesn't silently inject a
    # second ``deleted_at IS NULL`` — the liveness predicate is explicit here and
    # needs to stay that way.
    sa_tbl = DHCPStaticAssignment.__table__
    live: set[uuid.UUID] = set()
    if wanted:
        live = {
            row_id
            for (row_id,) in (
                await db.execute(
                    select(sa_tbl.c.id).where(
                        sa_tbl.c.id.in_(wanted),
                        sa_tbl.c.deleted_at.is_(None),
                    )
                )
            ).all()
        }

    freed = 0
    for row, static_id in parsed:
        if static_id is not None and static_id in live:
            continue
        await _delete_mirror_row(db, row, await _load_reservation_any(db, row.static_assignment_id))
        freed += 1
    return freed


def _parse_uuid(raw: str | None) -> uuid.UUID | None:
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except (ValueError, TypeError):
        return None


async def _load_reservation_any(
    db: AsyncSession, raw_id: str | None
) -> DHCPStaticAssignment | None:
    """Load a reservation by its back-link string, soft-deleted ones included.

    Returns ``None`` when the id doesn't parse or names no row at all — which is
    the common case for the sweep, whose whole subject is back-links pointing at
    reservations that no longer exist.
    """
    static_id = _parse_uuid(raw_id)
    if static_id is None:
        return None
    return (
        await db.execute(
            select(DHCPStaticAssignment)
            .where(DHCPStaticAssignment.id == static_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()


async def remove_ipam_for_scope_statics(db: AsyncSession, scope_id: uuid.UUID) -> int:
    """DELETE the IPAM mirror of every reservation under ``scope_id``.

    The delete-the-row, scope-wide counterpart to ``remove_ipam_for_static``
    (see it for why deleting, not freeing, is required). Uses
    ``include_deleted`` because the reservations may already be soft-deleted as
    part of their scope's batch by the time this runs. Returns the number of
    mirror rows removed.
    """
    res = await db.execute(
        select(DHCPStaticAssignment)
        .where(DHCPStaticAssignment.scope_id == scope_id)
        .execution_options(include_deleted=True)
    )
    removed = 0
    for st in res.scalars().all():
        removed += await remove_ipam_for_static(db, st)
    return removed


async def remirror_scope_statics(db: AsyncSession, scope: DHCPScope) -> int:
    """Re-create the IPAM mirror for each of a restored scope's reservations.

    Counterpart to ``remove_ipam_for_scope_statics``: soft-deleting a scope now
    deletes its ``static_dhcp`` mirror rows, so a Trash restore has to put them
    back. ``upsert_ipam_for_static`` re-creates the row (status + back-link) and
    re-syncs DNS; its #564 savepoint self-heal reclaims the IP if it was taken
    during the Trash window (the static is the source of truth). Call AFTER the
    batch has been un-stamped so the statics are visible. Returns the count.
    """
    res = await db.execute(
        select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
    )
    statics = list(res.scalars().all())
    for st in statics:
        await upsert_ipam_for_static(db, scope, st, action="create")
    return len(statics)

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

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

import structlog
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mac import canonicalize_mac
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPScope, DHCPStaticAssignment
from app.models.ipam import IPAddress, Subnet
from app.services.dhcp.ipam_mirror import insert_ipam_mirror_row
from app.services.dhcp.lease_cleanup import _resolve_lease_subnet_id

logger = structlog.get_logger(__name__)

__all__ = [
    "IPAMStaticSync",
    "LeaseHandover",
    "candidate_scopes_for_ipam_row",
    "detach_ipam_for_static",
    "publish_handover_ddns",
    "remirror_scope_statics",
    "remove_ipam_for_scope_statics",
    "remove_ipam_for_static",
    "sweep_orphaned_static_mirrors",
    "sync_static_for_ipam_row",
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
    # When a live lease still holds the address left behind, the address
    # becomes that lease's row instead of free (#1302, ``_release_moved_row``).
    handovers: list[LeaseHandover] = []
    prior = await db.execute(select(IPAddress).where(IPAddress.static_assignment_id == str(st.id)))
    for row in prior.scalars().all():
        if str(row.address) == ip_str:
            continue
        if row.status == "static_dhcp":
            handover = await _release_moved_row(db, row, st)
            if handover is not None:
                handovers.append(handover)
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
    # A row taken over here may be a lease's mirror: the address a client
    # leases, pinned to that client, or one #1274 / #1302 handed to the live
    # lease. Its lease flags go with it (#1404). The lease-event ingest takes
    # ``auto_from_lease`` as "this row is mine", so a reservation's row that
    # kept it was turned back into a ``dhcp`` row by the client's next lease
    # event, and deleted by the lease's release or expiry, while the
    # reservation stood.
    row.auto_from_lease = False
    row.dhcp_lease_id = None
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
    # Last, with the reservation already at its new address: DDNS lets a
    # reservation's hostname win, and none sits at the address handed over.
    await publish_handover_ddns(db, handovers)


async def _release_moved_row(
    db: AsyncSession, row: IPAddress, st: DHCPStaticAssignment
) -> LeaseHandover | None:
    """Release a reservation's row at the address it has just moved away from.

    The row is deleted, as it always was: the operator's columns move with the
    reservation. But the reserved client keeps its lease on the old address
    until it next talks to the server, and its grant arrived while the row was
    ``static_dhcp``, which the lease mirror leaves alone, so after the delete
    nothing re-derived the address until the agent sent that lease again — the
    client's renewal, the lease's expiry, an agent restart. Until then IPAM
    showed a live device's address as free, for the next-free allocation to
    hand to a second device (#1302, the re-address sibling of #1274).

    So when the product's lease table holds an active lease on the address in
    this row's subnet, the address gets that lease's mirror: a new row, as the
    lease-event ingest would create it had the lease arrived after the move,
    and nothing of the reservation's (its name, its DNS records, the
    operator's columns) carried onto it. Returns the hand-over, whose DDNS the
    caller publishes once the reservation is at its new address.
    """
    lease = await _live_lease_at(db, row)
    subnet_id, address = row.subnet_id, row.address
    await _delete_mirror_row(db, row, st)
    if lease is None:
        return None
    # The delete has to reach the database before the insert:
    # (subnet_id, address) is unique (uq_ip_address_subnet_address).
    await db.flush()
    candidate = IPAddress(subnet_id=subnet_id, address=str(address))
    _mirror_lease_onto(candidate, lease)
    mirror, created = await insert_ipam_mirror_row(db, candidate)
    if not created:
        # A concurrent writer's row won the insert. Take it over only when
        # the ingest would: a free row, or one a lease already owns.
        if not (mirror.status == "available" or mirror.auto_from_lease):
            return None
        _mirror_lease_onto(mirror, lease)
    subnet_row = await db.get(Subnet, subnet_id)
    if subnet_row is None:
        return None
    return LeaseHandover(subnet_row, mirror, lease)


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
    """A row handed to the lease that holds its address: a reservation's row
    when the reservation is deleted (``detach_ipam_for_static``, #1274), or a
    new row at the address a reservation moved away from
    (``upsert_ipam_for_static``, #1302)."""

    subnet: Subnet
    row: IPAddress
    lease: DHCPLease


async def publish_handover_ddns(db: AsyncSession, handovers: list[LeaseHandover]) -> None:
    """Publish the lease's DDNS records for rows that just became its mirror.

    The reservation's own A / PTR were torn down at the detach, and the
    ingest runs ``apply_ddns_for_lease`` whenever it takes a row over, so
    without this the mirror would sit in IPAM with no DNS until the client's
    next renewal (the same wait #1274 removes for IPAM). A no-op when the
    subnet's DDNS is off. Call it only once no reservation sits at the address
    any more — deleted and flushed (``detach_ipam_for_static``) or moved
    elsewhere (``upsert_ipam_for_static``). Best-effort, like the ingest's
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


# ── IPAM → DHCP direction (#1628) ─────────────────────────────────────────────
#
# Everything above flows reservation → IPAM. The paths that *start* in IPAM —
# address create / update, and the IPAM address importer — used to create only
# the ``ip_address`` row: a row at ``status="static_dhcp"`` with a MAC but no
# ``DHCPStaticAssignment`` behind it, so the address never reached the rendered
# Kea bundle until an operator opened the row in the UI and saved it again
# (the frontend's second, chained ``createStatic`` call was the only thing
# that ever created the reservation, and the importer never made it at all).
# ``sync_static_for_ipam_row`` is the reverse direction: it keeps a
# reservation in step with an IPAM row, reusing the statics create path's
# internals — ``push_static_change`` for the driver write-through,
# ``upsert_ipam_for_static`` for the back-link, and ``collect_wake`` so the
# serving group re-renders.


@dataclass(frozen=True)
class IPAMStaticSync:
    """Outcome of :func:`sync_static_for_ipam_row`.

    ``action`` is ``"create"`` / ``"update"`` / ``"delete"`` when a
    reservation was changed, else ``None``. ``warning`` is a human-readable
    reason no reservation was created/updated (ambiguous scope, conflict) —
    the row itself is *not* an error, so callers surface it as a warning
    rather than failing the IPAM write.
    """

    static: DHCPStaticAssignment | None = None
    scope: DHCPScope | None = None
    action: str | None = None
    warning: str | None = None


async def candidate_scopes_for_ipam_row(db: AsyncSession, row: IPAddress) -> list[DHCPScope]:
    """The DHCP scopes that could serve a reservation for ``row``.

    Scopes on the row's subnet whose address family matches the row's
    address. Zero or one is unambiguous; more than one means the subnet is
    served by several groups and there is no way to know which one the
    operator meant — callers must not guess.
    """
    try:
        family = "ipv6" if ipaddress.ip_address(str(row.address)).version == 6 else "ipv4"
    except ValueError:
        return []
    res = await db.execute(
        select(DHCPScope).where(
            DHCPScope.subnet_id == row.subnet_id,
            DHCPScope.address_family == family,
        )
    )
    return list(res.scalars().all())


async def _linked_static_for_row(db: AsyncSession, row: IPAddress) -> DHCPStaticAssignment | None:
    """The live reservation linked to ``row``, by either back-link direction."""
    conds = [DHCPStaticAssignment.ip_address_id == row.id]
    linked_id = _parse_uuid(row.static_assignment_id)
    if linked_id is not None:
        conds.append(DHCPStaticAssignment.id == linked_id)
    res = await db.execute(select(DHCPStaticAssignment).where(or_(*conds)))
    return res.scalars().first()


def _audit_static_change(
    db: AsyncSession,
    user: User | None,
    action: str,
    *,
    static_id: uuid.UUID,
    mac: str,
    ip: str,
    changed_fields: list[str] | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
) -> None:
    """Write the same audit row the statics endpoints write (#1629 review).

    ``sync_static_for_ipam_row`` creates / updates / deletes reservations
    on behalf of an IPAM save or an import; without a row of their own
    those reservation changes left no trail as a reservation
    (non-negotiable #4). Mirrors ``api/v1/dhcp/statics.py``: resource
    type ``dhcp_static_assignment``, display ``<mac>-><ip>``, attributed
    to the acting user (``system`` when there is none).
    """
    from app.api.v1.dhcp._audit import write_audit  # noqa: PLC0415

    write_audit(
        db,
        user=user,
        action=action,
        resource_type="dhcp_static_assignment",
        resource_id=str(static_id),
        resource_display=f"{mac}->{ip}",
        changed_fields=changed_fields,
        old_value=old_value,
        new_value=new_value,
    )


def _static_audit_value(
    st: DHCPStaticAssignment, scope_id: uuid.UUID, row: IPAddress
) -> dict[str, Any]:
    """The reservation snapshot an audit row carries, statics-shaped."""
    return {
        "scope_id": str(scope_id),
        "ip_address": str(st.ip_address),
        "mac_address": str(st.mac_address),
        "hostname": st.hostname or "",
        "description": st.description or "",
        "ip_address_id": str(row.id),
    }


def _dhcp_permission_warning(
    acting_user: User | None, action: str, row: IPAddress, *, verb: str
) -> str | None:
    """The warning when the acting user may not touch reservations (#1629).

    The statics endpoints gate on ``dhcp_static`` (router-level
    ``require_resource_permission("dhcp_static")``: ``write`` for
    create/update, ``delete`` for remove). The IPAM-side sync performs
    the same reservation writes, so it applies the same gate
    (GHSA-44ph-jfwp-2888): without the grant, warn and change nothing —
    an IPAM write alone must not create, re-point or delete a Kea
    reservation. ``acting_user is None`` means a system/internal caller
    with no user to gate (the in-repo callers all pass the acting
    user). Callers must pass the *request's* user object (``user=``),
    not only an id: a fresh load loses the API-token narrowing
    (``_api_token_resource_grants``) the permission check intersects.
    """
    if acting_user is None:
        return None
    from app.core.permissions import user_has_permission  # noqa: PLC0415

    if user_has_permission(acting_user, action, "dhcp_static"):
        return None
    return (
        f"No '{action}' permission on DHCP reservations (dhcp_static) — "
        f"the reservation for {row.address} was not {verb}. "
        "Ask a DHCP administrator to make the change, or have the grant added."
    )


async def sync_static_for_ipam_row(
    db: AsyncSession,
    row: IPAddress,
    *,
    created_by_user_id: uuid.UUID | None = None,
    user: User | None = None,
) -> IPAMStaticSync:
    """Keep the DHCP reservation for an IPAM row in step with the row (#1628).

    A row that *is* a reservation — ``status="static_dhcp"`` with a MAC —
    gets exactly one ``DHCPStaticAssignment``: created on the subnet's sole
    matching-family scope, updated in place (MAC / hostname / description)
    when one is already linked, and adopted when an identical unlinked one
    already sits on that scope. A row that stops being a reservation has its
    linked reservation pushed out and deleted. More than one candidate
    scope, or a conflicting reservation (same MAC elsewhere in the group,
    same IP pinned to another MAC), creates nothing and returns a warning.

    Every reservation write is gated on the acting user's ``dhcp_static``
    permission (``write`` to create/update, ``delete`` to remove), the
    same gate the statics endpoints enforce; without it the sync warns
    and changes nothing (#1629, GHSA-44ph-jfwp-2888). A reservation's
    description is only overwritten by a description the IPAM row
    actually carries — a tags-only save of a DHCP-side reservation's
    mirror row must not clear it (#1629 walk).

    Driver push + agent wake mirror ``api/v1/dhcp/statics.py``; a Windows /
    cloud push failure propagates so the caller's transaction rolls back,
    exactly as it does on the statics endpoints.
    """
    from app.core.agent_wake import collect_wake, dhcp_group_channel  # noqa: PLC0415
    from app.services.dhcp.windows_writethrough import push_static_change  # noqa: PLC0415

    # The acting user for the audit rows: an explicit ``user`` wins;
    # callers that only pass ``created_by_user_id`` (the IPAM router and
    # the importer) still get their reservation changes attributed by
    # loading that user.
    acting_user = user
    if acting_user is None and created_by_user_id is not None:
        acting_user = await db.get(User, created_by_user_id)
    elif acting_user is not None and created_by_user_id is None:
        created_by_user_id = acting_user.id

    linked = await _linked_static_for_row(db, row)
    is_reservation = row.status == "static_dhcp" and bool(row.mac_address)

    if not is_reservation:
        if linked is None:
            return IPAMStaticSync()
        scope = await db.get(DHCPScope, linked.scope_id)
        perm_warning = _dhcp_permission_warning(acting_user, "delete", row, verb="removed")
        if perm_warning is not None:
            return IPAMStaticSync(static=linked, scope=scope, warning=perm_warning)
        await push_static_change(db, linked, action="delete")
        if scope is not None:
            collect_wake(dhcp_group_channel(scope.group_id))
        # The row is the caller's to keep (it merely changed status) — do NOT
        # detach_ipam_for_static here, which would free the row itself.
        row.static_assignment_id = None
        deleted_id, deleted_mac, deleted_ip = (
            linked.id,
            str(linked.mac_address),
            str(linked.ip_address),
        )
        await db.delete(linked)
        await db.flush()
        _audit_static_change(
            db,
            acting_user,
            "delete",
            static_id=deleted_id,
            mac=deleted_mac,
            ip=deleted_ip,
        )
        return IPAMStaticSync(static=None, scope=scope, action="delete")

    try:
        mac = canonicalize_mac(str(row.mac_address))
    except ValueError:
        return IPAMStaticSync(warning=f"Invalid MAC address {row.mac_address!r}")

    if linked is not None:
        scope = await db.get(DHCPScope, linked.scope_id)
        if scope is None:
            return IPAMStaticSync(warning="Linked DHCP reservation's scope no longer exists")
        # A MAC the group already reserves under another row would collide
        # in the rendered bundle; leave the reservation untouched and warn.
        clash = await _static_mac_clash(db, scope, mac, exclude_id=linked.id)
        if clash is not None:
            return IPAMStaticSync(
                static=linked,
                scope=scope,
                warning=f"MAC {mac} is already reserved in this DHCP group (scope {clash.scope_id})",
            )
        prev_mac, prev_ip = str(linked.mac_address), str(linked.ip_address)
        prev_hostname, prev_description = linked.hostname or "", linked.description or ""
        # #1629 walk — copy only a description the row actually carries.
        # A reservation made on the DHCP side carries a description its
        # IPAM mirror row never had; a tags-only IPAM save copied the
        # row's empty description over it and cleared it in Kea.
        effective_description = row.description or prev_description
        changed = (
            prev_mac != mac
            or prev_ip != str(row.address)
            or prev_hostname != (row.hostname or "")
            or prev_description != effective_description
        )
        if not changed and row.static_assignment_id == str(linked.id):
            return IPAMStaticSync(static=linked, scope=scope)
        perm_warning = _dhcp_permission_warning(acting_user, "write", row, verb="updated")
        if perm_warning is not None:
            return IPAMStaticSync(static=linked, scope=scope, warning=perm_warning)
        changed_fields: list[str] = []
        if prev_ip != str(row.address):
            changed_fields.append("ip_address")
        if prev_mac != mac:
            changed_fields.append("mac_address")
        if prev_hostname != (row.hostname or ""):
            changed_fields.append("hostname")
        if prev_description != effective_description:
            changed_fields.append("description")
        if not changed_fields:
            # Only the back-link was missing; upsert below restores it.
            changed_fields = ["ip_address_id"]
        old_value = {
            "scope_id": str(scope.id),
            "ip_address": prev_ip,
            "mac_address": prev_mac,
            "hostname": prev_hostname,
            "description": prev_description,
            "ip_address_id": str(row.id),
        }
        linked.ip_address = str(row.address)
        linked.mac_address = mac
        linked.hostname = row.hostname or ""
        linked.description = effective_description
        await db.flush()
        if changed:
            await push_static_change(
                db, linked, action="update", prev_mac=prev_mac, prev_ip=prev_ip
            )
            collect_wake(dhcp_group_channel(scope.group_id))
        await upsert_ipam_for_static(db, scope, linked, action="update")
        _audit_static_change(
            db,
            acting_user,
            "update",
            static_id=linked.id,
            mac=str(linked.mac_address),
            ip=str(linked.ip_address),
            changed_fields=changed_fields,
            old_value=old_value,
            new_value=_static_audit_value(linked, scope.id, row),
        )
        return IPAMStaticSync(static=linked, scope=scope, action="update")

    # Create / adopt path — gate before any scope or conflict work so a
    # caller without the grant learns nothing and changes nothing.
    perm_warning = _dhcp_permission_warning(acting_user, "write", row, verb="created or updated")
    if perm_warning is not None:
        return IPAMStaticSync(warning=perm_warning)

    scopes = await candidate_scopes_for_ipam_row(db, row)
    if not scopes:
        return IPAMStaticSync(
            warning=(
                f"No DHCP scope serves {row.address} — no reservation was created. "
                "Create a scope for this subnet to pin the reservation."
            )
        )
    if len(scopes) > 1:
        return IPAMStaticSync(
            warning=(
                f"{len(scopes)} DHCP scopes serve this subnet — not guessing which one "
                f"should hold the reservation for {row.address}; no reservation was created."
            )
        )
    scope = scopes[0]

    # An identical reservation already on the scope (created from the DHCP
    # side but never back-linked, e.g. a pre-#1628 row) is adopted, not
    # duplicated — the (scope, ip) / (scope, mac) unique indexes would
    # reject a second one anyway.
    existing = (
        (
            await db.execute(
                select(DHCPStaticAssignment).where(
                    DHCPStaticAssignment.scope_id == scope.id,
                    or_(
                        DHCPStaticAssignment.ip_address == str(row.address),
                        DHCPStaticAssignment.mac_address == mac,
                    ),
                )
            )
        )
        .scalars()
        .first()
    )
    if existing is not None:
        if str(existing.ip_address) == str(row.address) and str(existing.mac_address) == mac:
            await upsert_ipam_for_static(db, scope, existing, action="update")
            _audit_static_change(
                db,
                acting_user,
                "update",
                static_id=existing.id,
                mac=str(existing.mac_address),
                ip=str(existing.ip_address),
                changed_fields=["ip_address_id"],
                new_value=_static_audit_value(existing, scope.id, row),
            )
            return IPAMStaticSync(static=existing, scope=scope, action="update")
        return IPAMStaticSync(
            scope=scope,
            warning=(
                f"A conflicting DHCP reservation already exists on this scope for "
                f"{row.address} / {mac}; no reservation was created."
            ),
        )
    clash = await _static_mac_clash(db, scope, mac, exclude_id=None)
    if clash is not None:
        return IPAMStaticSync(
            scope=scope,
            warning=f"MAC {mac} is already reserved in this DHCP group (scope {clash.scope_id})",
        )

    st = DHCPStaticAssignment(
        scope_id=scope.id,
        ip_address=str(row.address),
        mac_address=mac,
        hostname=row.hostname or "",
        description=row.description or "",
        ip_address_id=row.id,
        created_by_user_id=created_by_user_id,
    )
    db.add(st)
    await db.flush()
    await push_static_change(db, st, action="create")
    collect_wake(dhcp_group_channel(scope.group_id))
    await upsert_ipam_for_static(db, scope, st, action="create")
    _audit_static_change(
        db,
        acting_user,
        "create",
        static_id=st.id,
        mac=str(st.mac_address),
        ip=str(st.ip_address),
        new_value=_static_audit_value(st, scope.id, row),
    )
    return IPAMStaticSync(static=st, scope=scope, action="create")


async def _static_mac_clash(
    db: AsyncSession, scope: DHCPScope, mac: str, *, exclude_id: uuid.UUID | None
) -> DHCPStaticAssignment | None:
    """Another live reservation in ``scope``'s group already holding ``mac``.

    Mirrors the MAC half of ``statics._conflict_check`` (uniqueness is
    group-wide there because Kea renders one config per group).
    """
    res = await db.execute(
        select(DHCPStaticAssignment)
        .join(DHCPScope, DHCPStaticAssignment.scope_id == DHCPScope.id)
        .where(DHCPScope.group_id == scope.group_id, DHCPStaticAssignment.mac_address == mac)
    )
    for other in res.scalars().all():
        if exclude_id is not None and other.id == exclude_id:
            continue
        return other
    return None

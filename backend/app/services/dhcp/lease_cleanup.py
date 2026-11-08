"""Teardown for dynamic DHCP leases and their IPAM mirrors.

A pulled/dynamic lease owns two rows: the ``DHCPLease`` row itself and — when
its IP falls inside a managed subnet — an ``IPAddress`` mirror at
``status="dhcp"`` / ``auto_from_lease=True``. Three places used to inline the
same teardown (revoke DDNS → delete the mirror → stamp ``removed`` history →
delete the lease):

* the ``pull_leases`` absence-delete branch,
* the single-lease ``delete_lease`` endpoint,
* (new) scope deletion, which never tore leases down at all — a scope's leases
  have only a nullable ``ON DELETE SET NULL`` backlink to the scope, so deleting
  the scope left the lease + mirror stranded (and still counting toward IPAM
  utilization).

``purge_lease`` is the one shared teardown; ``delete_leases_for_scope`` fans it
out over a scope's leases. The subnet resolvers live here too (moved off
``tasks.dhcp_lease_cleanup`` so a service no longer imports *up* from a task;
the task re-exports them for its own sweep).

Transaction discipline: nothing here commits or flushes — the caller owns the
transaction so lease teardown lands atomically with the scope stamp / audit —
except ``tear_down_scope_leases``, which runs after a scope soft-delete has
committed and commits one batch at a time (#3733).
"""

from __future__ import annotations

import ipaddress
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer
from app.models.ipam import IPAddress, Subnet
from app.services.dhcp.lease_history import record_lease_history
from app.services.dns.record_ops import purge_trashed_address_records
from app.services.integration_ownership import INTEGRATION_OWNERSHIP_FKS
from app.services.ipam.utilization import recount_subnets_and_blocks

logger = structlog.get_logger(__name__)

# Sentinel so ``purge_lease`` can tell "caller already resolved the subnet (even
# if to None)" from "not provided, resolve it now". The pull path passes the
# subnet it already computed; the scope / endpoint paths let us resolve.
_UNSET: Any = object()


async def _load_subnet_cache(
    db: AsyncSession,
) -> list[tuple[uuid.UUID, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Load ``(subnet_id, parsed_network)`` for every subnet ONCE per sweep.

    ``_resolve_lease_subnet_id`` used to run a full ``SELECT id, network
    FROM subnet`` for every stale lease when it lacked a scope backlink —
    O(stale_leases × subnets) round-trips + reparse per lease. Loading the
    list once (and pre-parsing each CIDR) keeps the longest-prefix fallback
    at a single query per sweep, mirroring the pull-leases path. Unparseable
    networks are dropped up front so the per-lease loop stays clean.
    """
    cache: list[tuple[uuid.UUID, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for sid, network in (await db.execute(select(Subnet.id, Subnet.network))).all():
        try:
            cache.append((sid, ipaddress.ip_network(str(network), strict=False)))
        except (ValueError, TypeError):
            continue
    return cache


async def _resolve_lease_subnet_id(
    db: AsyncSession,
    lease: DHCPLease,
    subnet_cache: (
        list[tuple[uuid.UUID, ipaddress.IPv4Network | ipaddress.IPv6Network]] | None
    ) = None,
) -> uuid.UUID | None:
    """Find the IPAM subnet that owns this lease's address.

    SpatiumDDI allows overlapping private ranges across IPSpaces/VRFs, so
    the same address (e.g. 10.0.0.50) can be a valid auto_from_lease
    mirror in multiple subnets. Scope the mirror cleanup to the lease's
    own subnet so expiring one subnet's lease can't drop another's
    mirror. Prefer the lease's scope FK (DHCPScope.subnet_id); fall back
    to longest-prefix match over ``subnet_cache`` when the lease has no
    scope backlink. Both ingestion paths now stamp ``scope_id`` (Windows
    pull always did; Kea lease-events since #844), so the space-ambiguous
    CIDR fallback only covers legacy rows and shrinks as they refresh.
    The sweep passes a cache loaded ONCE per run; the single-lease delete
    path leaves it None and we load it on demand.
    """
    if lease.scope_id is not None:
        subnet_id = (
            await db.execute(select(DHCPScope.subnet_id).where(DHCPScope.id == lease.scope_id))
        ).scalar_one_or_none()
        if subnet_id is not None:
            return subnet_id

    try:
        addr = ipaddress.ip_address(str(lease.ip_address))
    except (ValueError, TypeError):
        return None
    if subnet_cache is None:
        subnet_cache = await _load_subnet_cache(db)
    best: tuple[int, uuid.UUID] | None = None
    for sid, net in subnet_cache:
        if addr in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, sid)
    return best[1] if best else None


async def peer_holds_active_lease(db: AsyncSession, lease: DHCPLease, *, now: datetime) -> bool:
    """Does ANOTHER server in ``lease``'s server group still hold this address? (#1110)

    Every server reports its own leases, so a failover or HA pair — which
    replicates lease state between partners — produces one ``dhcp_lease`` row
    per partner for the same address, while the IPAM mirror and the DDNS
    records it published are shared: one row, one A/PTR, for the address.
    Tearing those down because ONE partner stopped reporting the lease (a
    replication lag, a partner mid-restart, an absence-delete on a poll that
    only reached one side) takes them away while the other partner is still
    serving the client — and its next poll recreates both, so the symptom is
    DDNS records flapping rather than a clean failure.

    A peer counts only while its row is ``active`` and not past its expiry:
    a dead partner's frozen rows must not keep a mirror alive forever.

    Scoped to the server group, not to the address alone. Scopes in one
    group cannot overlap (#844), so the same address within a group is the
    same allocation; the same address in another group is a different
    network (VRF semantics) and must not keep this one's mirror alive.
    """
    group_id = (
        select(DHCPServer.server_group_id).where(DHCPServer.id == lease.server_id).scalar_subquery()
    )
    res = await db.execute(
        select(DHCPLease.id)
        .join(DHCPServer, DHCPServer.id == DHCPLease.server_id)
        .where(
            DHCPLease.ip_address == lease.ip_address,
            DHCPLease.server_id != lease.server_id,
            DHCPLease.state == "active",
            or_(DHCPLease.expires_at.is_(None), DHCPLease.expires_at > now),
            # NULL group → ``= NULL`` is never true → no peers, as it should be.
            DHCPServer.server_group_id == group_id,
        )
        .limit(1)
    )
    return res.first() is not None


async def another_client_holds_address(
    db: AsyncSession, lease: DHCPLease, *, now: datetime
) -> bool:
    """Does another lease ON THE SAME SERVER still hold ``lease``'s address? (#1318)

    A server reports one lease row per address and client, so once an
    address has moved from one client to the next the server has two rows
    for it: the old client's, ended, and the new client's, active. The IPAM
    mirror and the DDNS records belong to the address, so an event that ends
    the OLD client's lease must not take them from the new one.

    That event arrives late every time the agent replays its lease file. It
    re-reads the whole file on every start, so the old client's grant and
    release of the address are delivered again after the address has changed
    hands. The release used to delete the new client's mirror, and the
    address was missing from IPAM until the replay reached the new client's
    own grant.

    A row counts only while it is ``active`` and not past its expiry, the
    rule :func:`peer_holds_active_lease` applies to the other servers of the
    group.
    """
    res = await db.execute(
        select(DHCPLease.id)
        .where(
            DHCPLease.server_id == lease.server_id,
            DHCPLease.ip_address == lease.ip_address,
            DHCPLease.id != lease.id,
            DHCPLease.state == "active",
            or_(DHCPLease.expires_at.is_(None), DHCPLease.expires_at > now),
        )
        .limit(1)
    )
    return res.first() is not None


async def address_still_held(db: AsyncSession, lease: DHCPLease, *, now: datetime) -> bool:
    """Does anything besides ``lease`` still hold its address?

    Either a partner server of the group (:func:`peer_holds_active_lease`,
    #1110) or another client on the same server
    (:func:`another_client_holds_address`, #1318). The IPAM mirror and its
    DDNS records belong to the address, so every path that tears them down
    when a lease ends asks this one question: the lease-event release, the
    expiry sweep and :func:`purge_lease`.
    """
    return await peer_holds_active_lease(db, lease, now=now) or await another_client_holds_address(
        db, lease, now=now
    )


async def purge_lease(
    db: AsyncSession,
    lease: DHCPLease,
    *,
    subnet_id: uuid.UUID | None | Any = _UNSET,
    now: datetime | None = None,
    spare_if_peer_holds: bool = True,
    touched_subnets: set[uuid.UUID] | None = None,
) -> bool:
    """Tear one lease + its ``auto_from_lease`` IPAM mirror down.

    Order (matches the pull_leases absence-delete branch):
      1. resolve the lease's subnet (scope-FK first, else longest-prefix) —
         unless the caller already resolved it and passed ``subnet_id=`` (the
         pull path, keeping its O(1) per-poll cache),
      2. find the mirror ``IPAddress`` scoped to ``(subnet_id, address)``,
      3. revoke any DDNS the mirror published (best-effort; a DNS hiccup must
         never block the delete) BEFORE deleting the mirror,
      4. delete the mirror,
      5. stamp ``removed`` lease history (reads the lease's fields, so before
         the delete),
      6. delete the lease row.

    Steps 2–4 are skipped while anything else still holds an active lease on
    the address (``address_still_held``): another server in the group
    (#1110), or another client on this server (#1318). The mirror and its
    DNS records belong to the address, not to this copy of the lease. ``spare_if_peer_holds=False`` is for callers removing
    every copy at once — scope deletion — where the peer that would spare
    the mirror is itself being deleted in the same call; the mirror has to
    go, and relying on the order of deletes and autoflush to get there
    would be an accident rather than a rule.

    Removing a mirror changes its subnet's (and blocks') utilization (#3345).
    A batch caller passes ``touched_subnets`` and recounts once itself with
    ``recount_subnets_and_blocks``; with none, the single teardown recounts
    its own subnet before returning.

    Returns whether an IPAM mirror row was removed. Does not commit.

    The lease row is locked before the mirror and its zones (#3617, the order
    in ``app.services.lock_order``): it was only written at the end, after
    them. A caller tearing several leases down locks all of their rows first
    (they are then locked here again for free).
    """
    from app.services.lock_order import lock_lease_rows  # noqa: PLC0415

    if now is None:
        now = datetime.now(UTC)
    if lease.id is not None:
        await lock_lease_rows(db, DHCPLease.id == lease.id)
    sid = await _resolve_lease_subnet_id(db, lease) if subnet_id is _UNSET else subnet_id

    mirror_removed = False
    if sid is not None and spare_if_peer_holds and await address_still_held(db, lease, now=now):
        logger.info(
            "dhcp_purge_lease_mirror_kept_peer_holds",
            ip=str(lease.ip_address),
            server=str(lease.server_id),
        )
        sid = None
    if sid is not None:
        mirror = (
            await db.execute(
                select(IPAddress).where(
                    IPAddress.subnet_id == sid,
                    IPAddress.address == lease.ip_address,
                    IPAddress.auto_from_lease.is_(True),
                )
            )
        ).scalar_one_or_none()
        if mirror is not None:
            # Read in the Trash too: a subnet delete tears its scopes' leases
            # down after the subnet is stamped (#3744).
            subnet = (
                await db.execute(
                    select(Subnet).where(Subnet.id == sid).execution_options(include_deleted=True)
                )
            ).scalar_one_or_none()
            if subnet is not None:
                # Revoke DDNS BEFORE deleting the mirror — it reads
                # dns_record_id / hostname off the row. Best-effort.
                try:
                    from app.services.dns.ddns import revoke_ddns_for_lease  # noqa: PLC0415

                    await revoke_ddns_for_lease(db, subnet=subnet, ipam_row=mirror)
                except Exception as exc:  # noqa: BLE001 — DDNS revoke is best-effort
                    logger.warning(
                        "dhcp_purge_lease_ddns_revoke_failed",
                        ip=str(lease.ip_address),
                        error=str(exc),
                    )
            await purge_trashed_address_records(db, [mirror.id])  # #3186
            await db.delete(mirror)
            mirror_removed = True
            if touched_subnets is not None:
                touched_subnets.add(sid)

    # Stamp history before the row goes away. ``removed`` signals
    # "operator/server purged the lease" vs ``expired`` (time-based sweep).
    record_lease_history(db, lease, lease_state="removed", expired_at=now)
    await db.delete(lease)
    if mirror_removed and touched_subnets is None and sid is not None:
        await recount_subnets_and_blocks(db, [sid])
    return mirror_removed


async def delete_leases_for_scope(
    db: AsyncSession,
    scope_id: uuid.UUID,
    *,
    touched_subnets: set[uuid.UUID] | None = None,
) -> tuple[int, int]:
    """Purge every dynamic lease that belongs to ``scope_id``.

    Enumerates strictly by ``DHCPLease.scope_id`` (all states). A scope is
    unique on ``(group_id, subnet_id)``, so two groups can each own a scope on
    the same subnet — matching by IP-in-subnet instead would let one group's
    delete purge another group's lease. Callers run this while the scope is
    still live (before the soft-delete stamp / ``db.delete(scope)``), so
    ``scope_id`` still points at it; the post-delete race (a poll that nulled
    ``scope_id``) is handled by the pull-leases zero-wire floor guard.

    The freed mirrors move their subnets' counters (#3345). A caller tearing
    several scopes down in one transaction passes ``touched_subnets`` and
    recounts once itself, last, with ``recount_subnets_and_blocks``: a recount
    per scope would lock one scope's subnet and block chain before the next
    scope's subnet, out of the one order every recount takes (#3354). With
    none, this recounts what it freed before returning.

    Returns ``(leases_removed, mirrors_removed)`` for audit / preview.
    """
    # #3617: every lease row first, then the subnet's lease mirrors, then
    # the zones their DDNS lives in, each in id order, before the per-lease
    # teardown writes any of them (``app.services.lock_order``).
    from app.services.lock_order import lock_lease_rows, lock_zones_for_subnets  # noqa: PLC0415

    await lock_lease_rows(db, DHCPLease.scope_id == scope_id)
    leases = list(
        (await db.execute(select(DHCPLease).where(DHCPLease.scope_id == scope_id))).scalars().all()
    )
    scope_subnet_id = (
        await db.execute(
            select(DHCPScope.subnet_id)
            .where(DHCPScope.id == scope_id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    if leases and scope_subnet_id is not None:
        await db.execute(
            select(IPAddress.id)
            .where(IPAddress.subnet_id == scope_subnet_id, IPAddress.auto_from_lease.is_(True))
            .order_by(IPAddress.id)
            .with_for_update()
        )
        await lock_zones_for_subnets(db, [scope_subnet_id])
    now = datetime.now(UTC)
    leases_removed = 0
    mirrors_removed = 0
    touched: set[uuid.UUID] = set() if touched_subnets is None else touched_subnets
    for lease in leases:
        # Every copy of every lease in the scope is going, so no copy's peer
        # outlives it — see ``purge_lease(spare_if_peer_holds=...)``.
        if await purge_lease(
            db, lease, now=now, spare_if_peer_holds=False, touched_subnets=touched
        ):
            mirrors_removed += 1
        leases_removed += 1
    if touched_subnets is None:
        await recount_subnets_and_blocks(db, touched)  # #3345
    return leases_removed, mirrors_removed


# Leases torn down per transaction by a scope soft-delete (#3733). Each batch
# locks its lease rows, then the address rows and zones their teardown writes,
# purges them and commits, so a lease-events batch that renews one of them waits
# for one batch (about 100 ms a lease with DDNS on), never for the whole scope.
SCOPE_DELETE_BATCH = 25

# Wall-clock budget for the teardown a scope soft-delete runs in its request,
# once the scope is in the Trash. Kept well under the 30 s statement limit
# (asyncpg ``command_timeout``) and typical proxy timeouts: at 20 s the walked
# deletes answered in 23-30 s (#3772). Unlike the server delete's bound
# (#2290, whose remainder cascades away), the rest here goes to a task. ``app.tasks.dhcp_lease_cleanup.tear_down_trashed_scope_leases``
# tears the rest down, enqueued when the request stops short and run again by
# the lease sweep for any scope in the Trash that still has leases.
SCOPE_DELETE_INLINE_DEADLINE_S = 10.0


async def scope_lease_counts(db: AsyncSession, scope_id: uuid.UUID) -> tuple[int, int]:
    """``(leases, lease mirrors)`` a scope delete tears down: the scope's lease
    rows, and the ``auto_from_lease`` rows of its subnet at their addresses.
    Counted for the audit row before the teardown runs (#3733)."""
    leases = (
        await db.execute(
            select(func.count()).select_from(DHCPLease).where(DHCPLease.scope_id == scope_id)
        )
    ).scalar_one()
    subnet_id = (
        select(DHCPScope.subnet_id)
        .where(DHCPScope.id == scope_id)
        .execution_options(include_deleted=True)
        .scalar_subquery()
    )
    mirrors = (
        await db.execute(
            select(func.count())
            .select_from(IPAddress)
            .where(
                IPAddress.subnet_id == subnet_id,
                IPAddress.auto_from_lease.is_(True),
                IPAddress.address.in_(
                    select(DHCPLease.ip_address).where(DHCPLease.scope_id == scope_id)
                ),
            )
            .execution_options(include_deleted=True)
        )
    ).scalar_one()
    return leases, mirrors


async def tear_down_scope_leases(
    db: AsyncSession,
    scope_id: uuid.UUID,
    *,
    deadline_s: float | None = None,
) -> tuple[int, int, bool]:
    """Tear down the leases of a scope in the Trash, one committed batch at a
    time (#3733). Returns ``(leases_removed, mirrors_removed, done)``.

    ``delete_leases_for_scope`` locks every lease row of the scope first and
    holds them, with the scope's mirrors and zones, to the caller's commit
    (#3617). Inside a scope delete that is the whole teardown, about 100 ms a
    lease with DDNS on: every lease-events batch renewing one of the scope's
    leases waited for it, and the API cut those waits at 30 s. Here each batch
    of ``SCOPE_DELETE_BATCH`` leases takes the #3617 order inside its own
    transaction (the lease rows by id, then the address rows and zones of
    their mirrors' records, ``lock_zones_for_lease_mirrors``), tears them down
    and commits.

    Runs only while the scope is in the Trash, since the lease-events handler
    takes no event for a scope there: no batch can bring a lease back behind
    the teardown. It stops when the scope is restored (the next events
    re-populate its leases) or purged (the purge tears the rest down itself).
    ``done`` is False only when ``deadline_s`` ran out first.

    COMMITS each batch: the caller commits its own work before calling.
    """
    from app.services.lock_order import lock_zones_for_lease_mirrors  # noqa: PLC0415

    deadline = None if deadline_s is None else time.monotonic() + deadline_s
    leases_removed = 0
    mirrors_removed = 0
    while True:
        scope = (
            await db.execute(
                select(DHCPScope.subnet_id, DHCPScope.deleted_at)
                .where(DHCPScope.id == scope_id)
                .execution_options(include_deleted=True)
            )
        ).one_or_none()
        if scope is None or scope.deleted_at is None:
            await db.commit()  # ends the read; a rollback would expire the caller's rows
            return leases_removed, mirrors_removed, True
        if deadline is not None and time.monotonic() >= deadline:
            await db.commit()  # ends the read; a rollback would expire the caller's rows
            return leases_removed, mirrors_removed, False
        ids = (
            (
                await db.execute(
                    select(DHCPLease.id)
                    .where(DHCPLease.scope_id == scope_id)
                    .order_by(DHCPLease.id)
                    .limit(SCOPE_DELETE_BATCH)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        if not ids:
            await db.commit()  # ends the read; a rollback would expire the caller's rows
            return leases_removed, mirrors_removed, True
        await lock_zones_for_lease_mirrors(db, ids)
        batch = list(
            (
                await db.execute(
                    select(DHCPLease).where(DHCPLease.id.in_(ids)).order_by(DHCPLease.id)
                )
            )
            .scalars()
            .all()
        )
        now = datetime.now(UTC)
        touched: set[uuid.UUID] = set()
        for lease in batch:
            # Every lease of the scope is going, so no copy's peer outlives
            # it (as in ``delete_leases_for_scope``). The subnet is passed:
            # the scope-FK resolver no longer sees a scope in the Trash.
            if await purge_lease(
                db,
                lease,
                subnet_id=scope.subnet_id,
                now=now,
                spare_if_peer_holds=False,
                touched_subnets=touched,
            ):
                mirrors_removed += 1
            leases_removed += 1
        await recount_subnets_and_blocks(db, touched, include_deleted=True)  # #3345
        await db.commit()


async def trashed_scopes_with_leases(
    db: AsyncSession, *, limit: int = 100, trashed_before: datetime | None = None
) -> list[uuid.UUID]:
    """Scopes in the Trash that still have lease rows, oldest delete first
    (#3733): what a scope delete's own teardown left behind, its follow-up
    task lost or the scope larger than one task run. ``trashed_before``
    leaves out the scopes trashed since then, whose own teardown may still
    be running."""
    conditions = [
        DHCPScope.deleted_at.is_not(None),
        exists().where(DHCPLease.scope_id == DHCPScope.id),
    ]
    if trashed_before is not None:
        conditions.append(DHCPScope.deleted_at < trashed_before)
    rows = await db.execute(
        select(DHCPScope.id)
        .where(*conditions)
        .order_by(DHCPScope.deleted_at, DHCPScope.id)
        .limit(limit)
        .execution_options(include_deleted=True)
    )
    return list(rows.scalars().all())


# Leases torn down per round trip by ``delete_leases_for_server``. Each
# batch is flushed and its ORM rows expunged so a server holding 100k
# leases never has them all in the identity map at once.
SERVER_DELETE_BATCH = 500

# Hard cap on leases torn down inline by a server delete. The per-lease
# teardown measures ~15 ms (20k leases took 274 s on a dev box), so an
# unbounded loop would run a 100k-lease delete for ~25 min inside the HTTP
# request. Past the cap the rest cascade away with the server and their
# mirrors are healed by the hourly ``sweep_orphaned_lease_mirrors``.
SERVER_DELETE_INLINE_MAX = 1000

# Wall-clock budget for the same inline teardown. The count cap alone assumed
# ~15 ms a lease, but with DDNS on a teardown measured 87-102 ms, so 1,000
# leases ran past the 60 s proxy read timeout (504) while the delete carried on.
# Time is the real bound; the count cap stays as an upper limit. Well under 60 s.
SERVER_DELETE_INLINE_DEADLINE_S = 20.0


async def delete_leases_for_server(
    db: AsyncSession,
    server_id: uuid.UUID,
    *,
    max_leases: int = SERVER_DELETE_INLINE_MAX,
    deadline_s: float = SERVER_DELETE_INLINE_DEADLINE_S,
) -> tuple[int, int]:
    """Purge every lease held by ``server_id`` before the server row goes (#2290).

    ``dhcp_lease.server_id`` cascades on delete, so removing a server used to
    silently drop its leases — and with them the only handle the expiry sweep
    has on the ``auto_from_lease`` IPAM mirrors and the DDNS A/PTR records
    they published. Those were then stranded permanently.

    This is the same per-lease teardown the expiry / absence-delete paths use
    (:func:`purge_lease`), *with* ``spare_if_peer_holds=True``: an HA / failover
    partner (#1110) or another client on the server that still holds an active
    lease on the address keeps the shared mirror and its DNS.

    DDNS retraction is a ``DNSRecordOp`` enqueue (agent-based) or a post-commit
    apply (agentless), not an inline server call, so it is safe to run in the
    request; batching bounds memory and flushes so the per-lease peer checks
    see earlier batches' deletes. The caller owns the transaction.

    At most ``max_leases`` are torn down here, and none are started after
    ``deadline_s`` seconds (bounded request time); the remainder is left for the orphan sweep once the cascade removes them.

    Returns ``(leases_removed, mirrors_removed)``.
    """
    now = datetime.now(UTC)
    deadline = time.monotonic() + deadline_s
    subnet_cache = await _load_subnet_cache(db)
    leases_removed = 0
    mirrors_removed = 0
    touched: set[uuid.UUID] = set()
    capped = False
    # #3617: the rows this call may tear down, locked by id before the first
    # mirror is: batch by batch, each batch's leases came after the last
    # batch's mirrors (``app.services.lock_order``). Ids only, so the
    # identity map still holds one batch at a time.
    from app.services.lock_order import lock_zones_for_lease_mirrors  # noqa: PLC0415

    locked_lease_ids = (
        (
            await db.execute(
                select(DHCPLease.id)
                .where(DHCPLease.server_id == server_id)
                .order_by(DHCPLease.id)
                .limit(max_leases)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    # #3687: and the zones of the mirrors' records, trashed ones too, before
    # the first purge: lease i's purge deletes its trashed records in any
    # zone, and a later lease's revoke then locks and bumps its own.
    await lock_zones_for_lease_mirrors(db, locked_lease_ids)
    while leases_removed < max_leases:
        batch = list(
            (
                await db.execute(
                    select(DHCPLease)
                    .where(DHCPLease.server_id == server_id)
                    .order_by(DHCPLease.id)
                    .limit(min(SERVER_DELETE_BATCH, max_leases - leases_removed))
                )
            )
            .scalars()
            .all()
        )
        if not batch:
            break
        for lease in batch:
            if time.monotonic() >= deadline:
                capped = True
                break
            sid = await _resolve_lease_subnet_id(db, lease, subnet_cache)
            if await purge_lease(db, lease, subnet_id=sid, now=now, touched_subnets=touched):
                mirrors_removed += 1
            leases_removed += 1
        await db.flush()
        for lease in batch:
            db.expunge(lease)
        if capped:
            break
    else:
        capped = True
    await recount_subnets_and_blocks(db, touched)  # #3345
    if capped:
        remaining = (
            await db.execute(
                select(func.count()).select_from(DHCPLease).where(DHCPLease.server_id == server_id)
            )
        ).scalar_one()
        logger.warning(
            "dhcp_server_delete_lease_teardown_capped",
            server=str(server_id),
            torn_down=leases_removed,
            remaining=remaining,
        )
    return leases_removed, mirrors_removed


# Integration reconcilers also write ``status="dhcp"`` / ``auto_from_lease``
# rows, with no ``dhcp_lease`` behind them at all — they are told apart by
# their owner FK, which the orphan sweep must leave alone. The FK list is the
# shared one, so a new integration is covered here without a second edit.
_INTEGRATION_OWNER_COLUMNS = tuple(sorted(INTEGRATION_OWNERSHIP_FKS))

ORPHAN_MIRROR_GRACE = timedelta(hours=1)


async def sweep_orphaned_lease_mirrors(db: AsyncSession, *, limit: int = 500) -> int:
    """Free ``status="dhcp"`` / ``auto_from_lease`` mirrors no lease backs (#2290).

    Heals installs already stranded by a server delete (and any other path that
    drops lease rows without their mirror). A mirror is residue only when NO
    ``dhcp_lease`` row, on any server and in any state, carries its address —
    so an HA peer's lease, or an expired-but-not-yet-pruned one, keeps it
    (the expiry sweep owns those). Rows owned by an integration reconciler are
    skipped, and so is anything seen within ``ORPHAN_MIRROR_GRACE`` so a mirror
    mid-flight with its lease write is never raced.

    Returns the number of mirror rows freed. Does not commit; recounts the
    touched subnets and their blocks in the same transaction (#3345).
    """
    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.services.dns.ddns import revoke_ddns_for_lease  # noqa: PLC0415
    from app.services.lock_order import (  # noqa: PLC0415
        address_ids_of_records,
        lock_addresses_before,
        lock_zones_for_addresses,
    )

    cutoff = datetime.now(UTC) - ORPHAN_MIRROR_GRACE
    conds = [getattr(IPAddress, c).is_(None) for c in _INTEGRATION_OWNER_COLUMNS]
    rows = (
        (
            await db.execute(
                select(IPAddress)
                .where(
                    IPAddress.status == "dhcp",
                    IPAddress.auto_from_lease.is_(True),
                    or_(IPAddress.last_seen_at.is_(None), IPAddress.last_seen_at < cutoff),
                    ~exists().where(DHCPLease.ip_address == IPAddress.address),
                    *conds,
                )
                .options(selectinload(IPAddress.subnet))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    # #3687: every zone the batch's records sit in, trashed ones too, before
    # the first purge; the per-row revoke below then locks nothing new.
    # #3690: after the address rows the sweep writes (the mirrors, and any
    # row linked to a record it deletes), ascending id, as a permanent zone
    # delete takes them (#3691); holding a zone and then writing one of them
    # deadlocks with it.
    row_ids = sorted(row.id for row in rows)

    async def _written() -> set[Any]:
        record_ids = (
            (
                await db.execute(
                    select(DNSRecord.id)
                    .where(
                        DNSRecord.ip_address_id.in_(row_ids),
                        DNSRecord.auto_generated.is_(True),
                    )
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
        return set(row_ids) | await address_ids_of_records(db, record_ids)

    async def _zones() -> None:
        await lock_zones_for_addresses(db, retracting=rows)

    if rows:
        await lock_addresses_before(db, _written, _zones)
    await purge_trashed_address_records(db, [row.id for row in rows])  # #3186
    for row in rows:
        if row.subnet is not None:
            try:
                await revoke_ddns_for_lease(db, subnet=row.subnet, ipam_row=row)
            except Exception as exc:  # noqa: BLE001 — DDNS revoke is best-effort
                logger.warning(
                    "dhcp_orphan_mirror_ddns_revoke_failed",
                    ip=str(row.address),
                    error=str(exc),
                )
        await db.delete(row)
    # #3345 — the freed mirrors no longer count toward their subnets.
    await recount_subnets_and_blocks(db, {row.subnet_id for row in rows})
    return len(rows)


__all__ = [
    "delete_leases_for_server",
    "sweep_orphaned_lease_mirrors",
    "address_still_held",
    "another_client_holds_address",
    "delete_leases_for_scope",
    "peer_holds_active_lease",
    "purge_lease",
    "scope_lease_counts",
    "tear_down_scope_leases",
    "trashed_scopes_with_leases",
    "_load_subnet_cache",
    "_resolve_lease_subnet_id",
]

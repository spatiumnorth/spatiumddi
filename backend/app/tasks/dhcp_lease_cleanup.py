"""Sweep expired DHCP leases and their mirrored IPAM rows.

Also the backstop the other way round (#2580): an ``available`` IPAM row whose
address a live lease holds becomes that lease's mirror
(``_remirror_live_leases``).

Lease events from the agent already mirror active leases into IPAM (status='dhcp',
auto_from_lease=True) and remove them on explicit expired/released events. But
agents can miss events (container restart, lease_cmds hook drop), so we also
run a periodic sweep: any lease whose ``expires_at < now - grace`` gets marked
expired and its IPAM row (if auto_from_lease) removed.
"""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.celery_app import celery_app
from app.db import task_session
from app.models.audit import AuditLog
from app.models.dhcp import DHCPLease
from app.models.ipam import IPAddress

# The subnet resolvers now live in services/dhcp/lease_cleanup.py (so a service no
# longer imports *up* from a task — servers.py:delete_lease used to); the sweep
# imports them back here.
from app.services.dhcp.lease_cleanup import (
    _load_subnet_cache,
    _resolve_lease_subnet_id,
    address_still_held,
)
from app.services.dhcp.lease_history import record_lease_history
from app.services.dhcp.normalize import norm_ip
from app.services.dns.record_ops import purge_trashed_address_records
from app.services.feature_modules import is_module_enabled
from app.services.ipam.utilization import recount_subnets_and_blocks
from app.tasks.module_gate import module_gated

logger = structlog.get_logger(__name__)

# How long past expires_at before we clean up. Covers small clock skew and
# the agent's lease-event batch interval.
EXPIRY_GRACE = timedelta(minutes=5)

# How long a lease may sit in ``expired`` before the row itself is hard-deleted.
# Agent-based (Kea) drivers have no absence-delete reconciler — pull_leases only
# runs for agentless drivers, and the agent's expired-event branch drops just
# the IPAM mirror — so expired lease rows would otherwise linger in the DHCP
# view forever (#478). Kept generous so a recent expiry stays visible for a day;
# lease *history* is permanent regardless, so deleting the live row loses
# nothing and a renewal just creates a fresh active row.
EXPIRED_DELETE_GRACE = timedelta(hours=24)


def _write_order(subnet_id: Any, address: Any) -> tuple[str, int, int, str]:
    """(subnet id string, address version, int address): lease-events' order (#3601)."""
    key = str(subnet_id) if subnet_id is not None else ""
    ip = norm_ip(str(address))
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (key, 0, 0, ip)
    return (key, addr.version, int(addr), ip)


# Bind parameters per statement in the mirror lookups below. An expiry backlog
# (a control plane down for a day) can hold tens of thousands of addresses, and
# asyncpg refuses a statement with more than 32,767 parameters.
_MIRROR_LOOKUP_CHUNK = 1000


async def _lock_mirror_rows(db: AsyncSession, keys: set[tuple[Any, str]]) -> list[IPAddress]:
    """The ``auto_from_lease`` mirrors at ``keys`` ((subnet id, address)), row-locked.

    Locked in id order, like the lease-events handler and
    ``static_ipam.lock_static_rows``, so concurrent lockers never wait on each
    other in a cycle (#3605). The ids are read first and locked in ascending
    chunks, which keeps the whole lock order ascending however many chunks it
    takes. A row that stopped matching in between (taken over by a reservation,
    say) is dropped by the locked read; one created in between belongs to a
    lease that is live again, and is not ours to delete.
    """
    by_subnet: dict[Any, list[str]] = {}
    for subnet_id, address in keys:
        by_subnet.setdefault(subnet_id, []).append(address)
    ids: set[Any] = set()
    for subnet_id, addresses in by_subnet.items():
        addresses.sort()
        for i in range(0, len(addresses), _MIRROR_LOOKUP_CHUNK):
            id_res = await db.execute(
                select(IPAddress.id).where(
                    IPAddress.subnet_id == subnet_id,
                    IPAddress.address.in_(addresses[i : i + _MIRROR_LOOKUP_CHUNK]),
                    IPAddress.auto_from_lease.is_(True),
                )
            )
            ids.update(id_res.scalars().all())
    ordered = sorted(ids)
    rows: list[IPAddress] = []
    for i in range(0, len(ordered), _MIRROR_LOOKUP_CHUNK):
        res = await db.execute(
            select(IPAddress)
            .where(
                IPAddress.id.in_(ordered[i : i + _MIRROR_LOOKUP_CHUNK]),
                IPAddress.auto_from_lease.is_(True),
            )
            .options(selectinload(IPAddress.subnet))
            .order_by(IPAddress.id)
            .with_for_update(of=IPAddress)
            .execution_options(populate_existing=True)
        )
        rows.extend(
            r for r in res.scalars().all() if (r.subnet_id, norm_ip(str(r.address))) in keys
        )
    return rows


async def _sweep() -> tuple[int, int]:
    cutoff = datetime.now(UTC) - EXPIRY_GRACE
    async with task_session() as db:
        # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
        # do no work (and open no driver connections) when it is.
        if not await is_module_enabled(db, "core.dhcp"):
            return (0, 0)
        # Find any active-marked lease whose actual expiry passed the grace.
        # #3605: row-locked, in id order, before anything else is written. A
        # lease-events batch updates its lease rows first (one flush, which
        # writes them in primary-key order) and only then locks mirror rows and
        # zones, so taking the lease rows in that same order up front means a
        # batch and the sweep never hold one lease row each that the other
        # wants. The sweep used to update them one by one, in no fixed order,
        # interleaved with its mirror deletes. The lock also closes a lost
        # update: a batch that renews a lease while the sweep waits on it
        # commits first, the row no longer matches ``expires_at < cutoff`` when
        # the lock is granted, and the sweep leaves it alone instead of
        # stamping the renewed lease ``expired``.
        #
        # #3624 — the second pass's rows (``expired`` past the longer grace)
        # are locked in the same statement, not when their DELETE flushes. That
        # flush came after the DDNS revokes below, which hold zone rows: a
        # lease-events batch renewing one of those leases holds its row, then
        # wants the zone to publish the renewal, while the sweep held the zone
        # and wanted the row — 40P01. One statement keeps every lease lock
        # ahead of the mirror and zone locks, and in one id order.
        delete_cutoff = datetime.now(UTC) - EXPIRED_DELETE_GRACE
        res = await db.execute(
            select(DHCPLease)
            .where(
                DHCPLease.expires_at.is_not(None),
                or_(
                    and_(DHCPLease.state == "active", DHCPLease.expires_at < cutoff),
                    and_(DHCPLease.state == "expired", DHCPLease.expires_at < delete_cutoff),
                ),
            )
            .order_by(DHCPLease.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        locked = list(res.scalars().all())
        cleaned = 0
        touched_subnets: set[Any] = set()  # recounted once below (#3345)
        # Lazy-import the DDNS revoke to keep this task light when
        # DDNS is off. The helper itself no-ops when the subnet is not
        # ddns_enabled, so calling it unconditionally is cheap.
        from app.services.dns.ddns import revoke_ddns_for_lease  # noqa: PLC0415

        now_ts = datetime.now(UTC)
        # Load the subnet list once for the longest-prefix fallback in
        # _resolve_lease_subnet_id instead of re-querying per stale lease.
        subnet_cache = await _load_subnet_cache(db)

        # #3605: one total order, shared with the lease-events handler (#3601):
        # lease rows by id (above); the mirror rows they delete locked FOR
        # UPDATE by id BEFORE any DDNS work; then DDNS + deletes in
        # (subnet, version, address) order. Unordered, the sweep interleaved a
        # lease's DDNS revoke (which bumps a zone's serial row and holds it to
        # commit) with that lease's mirror delete, while a lease-events batch
        # held the mirror rows and then wanted the zone rows: a lock cycle,
        # 40P01, one side answered 500.
        resolved: list[tuple[DHCPLease, Any]] = []
        for lease in locked:
            if lease.state != "active":
                continue  # already expired: only the second pass wants it
            resolved.append((lease, await _resolve_lease_subnet_id(db, lease, subnet_cache)))
        resolved.sort(key=lambda pair: _write_order(pair[1], pair[0].ip_address))

        # The leases behind each mirror to tear down, keyed by (subnet, address).
        candidates: dict[tuple[Any, str], list[DHCPLease]] = {}
        for lease, subnet_id in resolved:
            # Stamp lease history before flipping state. ``expired`` is
            # the time-based sweep label (vs ``removed`` from the
            # pull-leases absence-delete branch) so consumers can tell
            # the two apart.
            record_lease_history(db, lease, lease_state="expired", expired_at=now_ts)
            lease.state = "expired"
            # Remove the mirrored IPAM row if auto_from_lease — but only
            # within this lease's owning subnet. An address-only lookup
            # would delete same-address mirrors in other subnets too.
            if subnet_id is None:
                continue
            candidates.setdefault((subnet_id, norm_ip(str(lease.ip_address))), []).append(lease)

        rows = await _lock_mirror_rows(db, set(candidates))
        rows.sort(key=lambda r: _write_order(r.subnet_id, r.address))
        for row in rows:
            # #1110 — a failover / HA partner still holding an active,
            # unexpired lease on the address owns the shared mirror and DDNS
            # now; this server's copy aging out does not free the address.
            # The partner that renewed it has the newer expiry, and this
            # row is the stale one — typically because this server has
            # stopped being polled.
            #
            # #1318 — nor does another client's lease on this same server:
            # a row left ``active`` past its expiry for an address that has
            # since gone to a new client (Kea reused it without a release
            # line for the old one) must not take the new client's mirror.
            #
            # #3605 — asked only now, with the mirror row locked. The lock may
            # have waited on a lease-events batch that renewed the address on
            # a partner; asked before the wait, the answer was "free", and
            # the sweep deleted the mirror that batch had just refreshed.
            # A batch still to come must take this row's lock before it can
            # commit, so it finds the row gone and inserts a fresh mirror for
            # its renewal, as for any new lease.
            held_at = datetime.now(UTC)
            still_held = False
            for lease in candidates[(row.subnet_id, norm_ip(str(row.address)))]:
                if await address_still_held(db, lease, now=held_at):
                    still_held = True
                    break
            if still_held:
                continue
            subnet = row.subnet
            if subnet is not None:
                try:
                    await revoke_ddns_for_lease(db, subnet=subnet, ipam_row=row)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "dhcp_lease_cleanup_ddns_revoke_failed",
                        ip=str(row.address),
                        error=str(exc),
                    )
            await purge_trashed_address_records(db, [row.id])  # #3186
            await db.delete(row)
            touched_subnets.add(row.subnet_id)
            cleaned += 1

        # Second pass — hard-delete leases that have sat in ``expired`` past the
        # longer grace so they stop lingering in the DHCP view (#478). History
        # was already stamped when the lease flipped to expired, and the mirror
        # was dropped above / by the agent, so this only removes the dead row.
        # Taken from the rows locked above (#3624): every one is ``expired``
        # by now, including a lease the first pass has just expired, as before.
        deleted = 0
        for lease in locked:
            if lease.expires_at is not None and lease.expires_at < delete_cutoff:
                await db.delete(lease)
                deleted += 1

        # The sweep writes no audit row, so it never waits for the audit-chain
        # lock and need not take it before the row locks (#3345).
        await recount_subnets_and_blocks(db, touched_subnets, audit_lock=False)
        await db.commit()
        return cleaned, deleted


# Cap on rows the re-mirror pass hands over per run, so a backlog (a long run
# of dropped lease batches) cannot become one long transaction holding row
# locks on ``ip_address``. The rest go on the next tick; the pass is idempotent.
REMIRROR_MAX_PER_RUN = 500


async def _remirror_live_leases() -> int:
    """Hand ``available`` rows that a live lease holds to that lease (#2580).

    The backstop for an address left ``available`` beside its live lease: a
    reservation DELETE that raced the lease report (closed at the source by
    row locks, but this costs nothing to keep) or a lease batch the agent
    dropped after a refused POST. Its own transaction, after the expiry pass,
    so a lease that pass just expired claims nothing here. A healthy install
    finds nothing and writes nothing, not even an audit row.
    """
    from app.services.dhcp.static_ipam import (  # noqa: PLC0415
        publish_handover_ddns,
        remirror_available_rows_with_live_leases,
    )

    async with task_session() as db:
        if not await is_module_enabled(db, "core.dhcp"):
            return 0
        handovers = await remirror_available_rows_with_live_leases(db, limit=REMIRROR_MAX_PER_RUN)
        if not handovers:
            await db.rollback()
            return 0
        await db.flush()
        await recount_subnets_and_blocks(db, {h.row.subnet_id for h in handovers})  # #3345
        await publish_handover_ddns(db, handovers)
        # A status change on an address is a mutation, and mutations are
        # audited (non-negotiable #4). One row per run, naming the addresses.
        db.add(
            AuditLog(
                user_display_name="<system>",
                auth_source="system",
                action="dhcp-lease-remirror",
                resource_type="platform",
                resource_id="dhcp-lease-remirror",
                resource_display="available addresses held by a live lease",
                result="success",
                new_value={
                    "rows_remirrored": len(handovers),
                    "capped": len(handovers) >= REMIRROR_MAX_PER_RUN,
                    "addresses": [str(h.row.address) for h in handovers[:50]],
                },
            )
        )
        await db.commit()
        return len(handovers)


async def _run_both() -> tuple[tuple[int, int], int]:
    return await _sweep(), await _remirror_live_leases()


@celery_app.task(name="app.tasks.dhcp_lease_cleanup.sweep_expired_leases")
@module_gated("core.dhcp")
def sweep_expired_leases() -> dict[str, int]:
    (cleaned, deleted), remirrored = asyncio.run(_run_both())
    if remirrored:
        # Warning, not info: since the row locks of #2580 only a lease batch
        # the agent dropped should leave an address here, which wants finding.
        logger.warning("dhcp_lease_sweep_remirrored_available_rows", rows=remirrored)
    logger.info(
        "dhcp_lease_sweep_complete",
        ipam_rows_removed=cleaned,
        expired_leases_deleted=deleted,
        ipam_rows_remirrored=remirrored,
    )
    return {
        "ipam_rows_removed": cleaned,
        "expired_leases_deleted": deleted,
        "ipam_rows_remirrored": remirrored,
    }

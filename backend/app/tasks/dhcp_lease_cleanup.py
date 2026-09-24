"""Sweep expired DHCP leases and their mirrored IPAM rows.

Lease events from the agent already mirror active leases into IPAM (status='dhcp',
auto_from_lease=True) and remove them on explicit expired/released events. But
agents can miss events (container restart, lease_cmds hook drop), so we also
run a periodic sweep: any lease whose ``expires_at < now - grace`` gets marked
expired and its IPAM row (if auto_from_lease) removed.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.celery_app import celery_app
from app.db import task_session
from app.models.dhcp import DHCPLease
from app.models.ipam import IPAddress

# The subnet resolvers now live in services/dhcp/lease_cleanup.py (so a service no
# longer imports *up* from a task — servers.py:delete_lease used to); the sweep
# imports them back here.
from app.services.dhcp.lease_cleanup import (
    _load_subnet_cache,
    _resolve_lease_subnet_id,
    peer_holds_active_lease,
)
from app.services.dhcp.lease_history import record_lease_history
from app.services.feature_modules import is_module_enabled

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


async def _sweep() -> tuple[int, int]:
    cutoff = datetime.now(UTC) - EXPIRY_GRACE
    async with task_session() as db:
        # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
        # do no work (and open no driver connections) when it is.
        if not await is_module_enabled(db, "core.dhcp"):
            return (0, 0)
        # Find any active-marked lease whose actual expiry passed the grace.
        res = await db.execute(
            select(DHCPLease).where(
                DHCPLease.state == "active",
                DHCPLease.expires_at.is_not(None),
                DHCPLease.expires_at < cutoff,
            )
        )
        cleaned = 0
        # Lazy-import the DDNS revoke to keep this task light when
        # DDNS is off. The helper itself no-ops when the subnet is not
        # ddns_enabled, so calling it unconditionally is cheap.
        from app.services.dns.ddns import revoke_ddns_for_lease  # noqa: PLC0415

        now_ts = datetime.now(UTC)
        # Load the subnet list once for the longest-prefix fallback in
        # _resolve_lease_subnet_id instead of re-querying per stale lease.
        subnet_cache = await _load_subnet_cache(db)
        for lease in res.scalars().all():
            # Stamp lease history before flipping state. ``expired`` is
            # the time-based sweep label (vs ``removed`` from the
            # pull-leases absence-delete branch) so consumers can tell
            # the two apart.
            record_lease_history(db, lease, lease_state="expired", expired_at=now_ts)
            lease.state = "expired"
            # #1110 — a failover / HA partner still holding an active,
            # unexpired lease on the address owns the shared mirror and DDNS
            # now; this server's copy aging out does not free the address.
            # The partner that renewed it has the newer expiry, and this
            # row is the stale one — typically because this server has
            # stopped being polled.
            if await peer_holds_active_lease(db, lease, now=now_ts):
                continue
            # Remove the mirrored IPAM row if auto_from_lease — but only
            # within this lease's owning subnet. An address-only lookup
            # would delete same-address mirrors in other subnets too.
            subnet_id = await _resolve_lease_subnet_id(db, lease, subnet_cache)
            if subnet_id is None:
                continue
            ipam_res = await db.execute(
                select(IPAddress)
                .where(
                    IPAddress.subnet_id == subnet_id,
                    IPAddress.address == lease.ip_address,
                    IPAddress.auto_from_lease.is_(True),
                )
                .options(selectinload(IPAddress.subnet))
            )
            for row in ipam_res.scalars().all():
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
                await db.delete(row)
                cleaned += 1

        # Second pass — hard-delete leases that have sat in ``expired`` past the
        # longer grace so they stop lingering in the DHCP view (#478). History
        # was already stamped when the lease flipped to expired, and the mirror
        # was dropped above / by the agent, so this only removes the dead row.
        delete_cutoff = datetime.now(UTC) - EXPIRED_DELETE_GRACE
        stale = await db.execute(
            select(DHCPLease).where(
                DHCPLease.state == "expired",
                DHCPLease.expires_at.is_not(None),
                DHCPLease.expires_at < delete_cutoff,
            )
        )
        deleted = 0
        for lease in stale.scalars().all():
            await db.delete(lease)
            deleted += 1

        await db.commit()
        return cleaned, deleted


@celery_app.task(name="app.tasks.dhcp_lease_cleanup.sweep_expired_leases")
def sweep_expired_leases() -> dict[str, int]:
    cleaned, deleted = asyncio.run(_sweep())
    logger.info(
        "dhcp_lease_sweep_complete",
        ipam_rows_removed=cleaned,
        expired_leases_deleted=deleted,
    )
    return {"ipam_rows_removed": cleaned, "expired_leases_deleted": deleted}

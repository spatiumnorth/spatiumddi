"""Auto-profile dispatch — enqueue an nmap scan when a fresh DHCP
lease lands in a profile-enabled subnet.

Three guards stand between a lease and a scan:

1. **Subnet opt-in.** ``Subnet.auto_profile_on_dhcp_lease`` is the
   master switch. Default off — operators must explicitly enable
   profiling per subnet because nmap traffic is loud.
2. **First-sight + refresh.** Skip if the IP was profiled within the
   subnet's ``auto_profile_refresh_days`` window. Wi-Fi clients that
   roam APs and pull a fresh lease every few minutes shouldn't
   re-trigger a scan each time.
3. **Per-subnet concurrency cap.** A /24 of churning DHCP clients
   could otherwise fan out into hundreds of simultaneous nmap
   processes. We count queued+running scans whose ``ip_address_id``
   resolves to an IP in the same subnet, and bail early if that
   exceeds ``MAX_CONCURRENT_PROFILES_PER_SUBNET``.

The dispatch itself reuses the existing operator-driven nmap path
(``NmapScan`` row + ``run_scan_task.delay``); finalisation in
``services.nmap.runner.run_scan`` handles stamping
``last_profiled_at`` + ``last_profile_scan_id`` back on the
``IPAddress``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, Subnet
from app.models.nmap import NmapScan
from app.services.feature_modules import is_module_enabled
from app.services.ipam.probe_policy import resolve_probe_policy
from app.services.nmap.runner import PRESETS

logger = structlog.get_logger(__name__)


class ProbeSuppressed(Exception):
    """The target subnet is marked do-not-probe (#722).

    Distinct from the concurrency-cap ``ValueError`` because the two
    mean opposite things to a caller: the cap is transient and worth
    retrying, this is a deliberate standing refusal. The message is the
    resolved verdict's, so the operator's own reason reaches the UI.
    """


# Cap on simultaneous active profile scans per subnet. A small number
# is intentional — these are background scans triggered by lease
# events, and a renewal storm shouldn't swamp the worker pool.
# Operator-driven scans count toward the cap too (we'd rather defer
# the next auto-profile than queue ahead of a human-triggered scan).
MAX_CONCURRENT_PROFILES_PER_SUBNET = 4

# Every scan this module dispatches is an nmap scan, so it answers to the
# nmap feature module (#2279).
NMAP_MODULE_ID = "tools.nmap"


async def _count_in_flight_profiles(db: AsyncSession, subnet_id) -> int:
    """Count queued+running scans whose IP belongs to this subnet.

    The IP→subnet join is required because ``NmapScan.target_ip`` is
    a free-form string and could be a hostname. We only count scans
    that have a resolved ``ip_address_id`` linking back to a real
    row in this subnet — that matches the path auto-profile takes
    when it dispatches.
    """
    stmt = (
        select(func.count(NmapScan.id))
        .join(IPAddress, NmapScan.ip_address_id == IPAddress.id)
        .where(
            IPAddress.subnet_id == subnet_id,
            NmapScan.status.in_(("queued", "running")),
        )
    )
    result = await db.execute(stmt)
    return int(result.scalar() or 0)


def _within_refresh_window(last_profiled_at: datetime | None, refresh_days: int) -> bool:
    """True if a previous profile is recent enough to skip re-scanning.

    ``refresh_days <= 0`` disables the dedupe window — every lease
    re-triggers. We don't expose 0 in the UI because it's mostly a
    foot-gun, but the logic supports it for tests / debug.
    """
    if last_profiled_at is None:
        return False
    if refresh_days <= 0:
        return False
    cutoff = datetime.now(UTC) - timedelta(days=refresh_days)
    return last_profiled_at >= cutoff


async def maybe_enqueue_for_lease(
    db: AsyncSession,
    *,
    subnet: Subnet,
    ipam_row: IPAddress,
) -> NmapScan | None:
    """Decide whether to scan, and if so, dispatch via Celery.

    Returns the dispatched ``NmapScan`` row (already added + flushed
    so the caller's commit will persist it), or ``None`` when one of
    the guards rejected the lease. Caller owns the commit; this
    function never commits or rolls back so it composes cleanly with
    the lease-event handler's existing transaction.

    Errors are logged and swallowed: profiling is opportunistic, and
    a failed dispatch shouldn't break the lease ingestion path.
    """
    try:
        if not getattr(subnet, "auto_profile_on_dhcp_lease", False):
            return None

        # The subnet flag outlives the module (#2279): an operator who turns
        # nmap off expects no scans, and the subnet setting that asked for
        # them is no longer even visible to switch off.
        if not await is_module_enabled(db, NMAP_MODULE_ID):
            logger.debug(
                "auto_profile_skip_module_disabled",
                subnet=str(subnet.id),
                ip=str(ipam_row.address),
            )
            return None

        # Fragile-device suppression (#722). Checked before the refresh
        # window, not after: this is the one guard that must not be
        # bypassable by tuning the others, and a suppressed subnet should
        # never reach the "how recently did we scan" question at all.
        probe = await resolve_probe_policy(db, subnet)
        if probe.blocked:
            logger.info(
                "auto_profile_skip_do_not_probe",
                subnet=str(subnet.id),
                ip=str(ipam_row.address),
                source=probe.source,
            )
            return None

        if _within_refresh_window(ipam_row.last_profiled_at, subnet.auto_profile_refresh_days):
            logger.debug(
                "auto_profile_skip_refresh_window",
                subnet=str(subnet.id),
                ip=str(ipam_row.address),
                last_profiled_at=(
                    ipam_row.last_profiled_at.isoformat() if ipam_row.last_profiled_at else None
                ),
                refresh_days=subnet.auto_profile_refresh_days,
            )
            return None

        in_flight = await _count_in_flight_profiles(db, subnet.id)
        if in_flight >= MAX_CONCURRENT_PROFILES_PER_SUBNET:
            logger.info(
                "auto_profile_skip_cap_reached",
                subnet=str(subnet.id),
                ip=str(ipam_row.address),
                in_flight=in_flight,
                cap=MAX_CONCURRENT_PROFILES_PER_SUBNET,
            )
            return None

        preset = subnet.auto_profile_preset
        if preset not in PRESETS:
            logger.warning(
                "auto_profile_unknown_preset",
                subnet=str(subnet.id),
                preset=preset,
            )
            preset = "service_version"

        # Lease handler invokes us mid-transaction with a freshly
        # added (id-less) IPAddress; flush so we can stamp the FK.
        if ipam_row.id is None:
            await db.flush()

        scan = NmapScan(
            target_ip=str(ipam_row.address),
            ip_address_id=ipam_row.id,
            preset=preset,
            status="queued",
        )
        db.add(scan)
        # Flush so we know the scan id before dispatch — the celery
        # task takes a string id and the row needs to be visible to
        # the worker before it picks the task up. Caller commits.
        await db.flush()

        # Dispatch lazily — top-level import would create a Celery →
        # SQLAlchemy → models → router → ... cycle that's hard to
        # untangle in the lease-event hot path.
        from app.tasks.nmap import run_scan_task

        run_scan_task.delay(str(scan.id))

        logger.info(
            "auto_profile_dispatched",
            subnet=str(subnet.id),
            ip=str(ipam_row.address),
            scan_id=str(scan.id),
            preset=preset,
        )
        return scan
    except Exception as exc:  # noqa: BLE001 — never break the caller
        logger.warning(
            "auto_profile_dispatch_failed",
            subnet=str(getattr(subnet, "id", None)),
            ip=str(getattr(ipam_row, "address", None)),
            error=str(exc),
        )
        return None


async def enqueue_now(
    db: AsyncSession,
    *,
    ipam_row: IPAddress,
    preset: str | None = None,
) -> NmapScan:
    """Operator-triggered "Re-profile now" dispatch.

    Bypasses the refresh-window guard — the operator just told us to
    scan again — but still respects the per-subnet concurrency cap.
    Caller owns the commit.

    Raises ``ValueError`` if the cap is exceeded so the API endpoint
    can return a 429-style response, and :class:`ProbeSuppressed` when
    the subnet is marked do-not-probe (#722) — a distinct type because
    that one is not a "try again in a moment" condition. Picks the
    subnet's configured preset by default; an override can be passed for
    ad-hoc scans.

    "The operator just told us to scan again" is why the refresh window
    is bypassed, and exactly why the do-not-probe flag is *not*: the
    operator who clicked Re-profile is usually not the one who wrote the
    vendor bulletin onto the subnet.
    """
    subnet = await db.get(Subnet, ipam_row.subnet_id)
    if subnet is None:
        raise ValueError(f"subnet {ipam_row.subnet_id} not found")

    probe = await resolve_probe_policy(db, subnet)
    if probe.blocked:
        raise ProbeSuppressed(probe.message(action="Profiling"))

    in_flight = await _count_in_flight_profiles(db, subnet.id)
    if in_flight >= MAX_CONCURRENT_PROFILES_PER_SUBNET:
        raise ValueError(
            f"per-subnet profile concurrency cap ({MAX_CONCURRENT_PROFILES_PER_SUBNET}) "
            f"reached — {in_flight} profile scans already queued or running"
        )

    chosen = preset or subnet.auto_profile_preset
    if chosen not in PRESETS:
        chosen = "service_version"

    scan = NmapScan(
        target_ip=str(ipam_row.address),
        ip_address_id=ipam_row.id,
        preset=chosen,
        status="queued",
    )
    db.add(scan)
    await db.flush()

    from app.tasks.nmap import run_scan_task

    run_scan_task.delay(str(scan.id))

    logger.info(
        "auto_profile_enqueue_now",
        subnet=str(subnet.id),
        ip=str(ipam_row.address),
        scan_id=str(scan.id),
        preset=chosen,
    )
    return scan


__all__ = [
    "MAX_CONCURRENT_PROFILES_PER_SUBNET",
    "ProbeSuppressed",
    "enqueue_now",
    "maybe_enqueue_for_lease",
]

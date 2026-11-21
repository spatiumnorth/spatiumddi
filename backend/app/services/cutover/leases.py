"""DHCP lease handover — Phase 3b of the Windows cutover (issue #756).

The DHCP importer (#129) deliberately carries scopes, pools, options and
*reservations* across and stops there: leases are ephemeral state, and an
importer that invents reservations out of them would be lying about operator
intent. A **cutover** is the one moment where that trade flips. At the instant
the managed scope starts answering, Kea's lease database is empty — so the
first client to renew is handed a fresh address out of the pool while it is
still using, and still answering on, the one Windows gave it. On a busy
subnet that is a wave of duplicate-address complaints during the exact window
an operator is least able to absorb them.

This module closes that gap: it reads the live Windows lease set and turns
each one into a :class:`DHCPStaticAssignment` on the managed scope, so a
renewing client gets **the address it already holds**. The reservations are
stamped ``import_source="windows_cutover"`` so they are trivially identifiable
afterwards — an operator who wants the addresses back in the dynamic pool can
find and drop exactly this set once leases have naturally churned.

Three things are load-bearing here:

* **Scope selection is by subnet CIDR.** The driver's neutral lease dict
  (``WindowsDHCPReadOnlyDriver.get_leases``) carries no scope id, so
  containment in the managed scope's subnet is what decides whether a lease
  belongs to this item. Every lease the server reported still gets an explicit
  disposition in the plan rather than silently vanishing — an operator
  reviewing a handover should be able to account for the whole lease table.
* **Nothing is created that would contradict an existing reservation.** The
  ``uq_dhcp_static_scope_mac`` / ``uq_dhcp_static_scope_ip`` partial unique
  indexes are on *live* rows, so a duplicate is an ``IntegrityError`` at flush
  and not a silent no-op. Duplicates are classified up front, and the commit
  re-checks against live DB state rather than trusting a stale preview.
* **Each create gets its own savepoint.** One reservation that cannot be
  written (a racing operator edit, an IPAM mirror collision) must never roll
  back the ones that already succeeded — same ledger idiom the importers use.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.core.dns_names import sanitize_hostname
from app.drivers.dhcp.windows import WindowsDHCPReadOnlyDriver
from app.models.auth import User
from app.models.cutover import CutoverItem
from app.models.dhcp import DHCPScope, DHCPServer, DHCPStaticAssignment
from app.models.ipam import Subnet
from app.services.cutover.canonical import LeaseHandoverEntry, LeaseHandoverPlan
from app.services.dhcp.static_ipam import upsert_ipam_for_static
from app.services.dhcp_import.options import normalise_mac

logger = structlog.get_logger(__name__)

#: Provenance stamped on every reservation this module creates. 15 characters,
#: so it fits ``DHCPStaticAssignment.import_source`` (``String(20)``), and it is
#: distinct from the importer's ``windows_dhcp`` on purpose: these rows were
#: synthesised from *leases* at cutover, not read from the server's config.
CUTOVER_IMPORT_SOURCE = "windows_cutover"

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

__all__ = [
    "CUTOVER_IMPORT_SOURCE",
    "commit_lease_handover",
    "preview_lease_handover",
]


async def _scope_network(db: AsyncSession, scope: DHCPScope) -> tuple[Subnet, _IPNetwork]:
    """Resolve the managed scope's IPAM subnet and its parsed CIDR."""
    subnet = await db.get(Subnet, scope.subnet_id)
    if subnet is None:
        raise ValueError(
            f"DHCP scope {scope.id} points at IPAM subnet {scope.subnet_id}, which no longer "
            "exists — re-link the scope before handing leases over."
        )
    try:
        network = ipaddress.ip_network(str(subnet.network), strict=False)
    except ValueError as exc:
        raise ValueError(f"IPAM subnet {subnet.network!r} is not a parseable CIDR: {exc}") from exc
    return subnet, network


async def _live_reservation_maps(
    db: AsyncSession, scope_id: Any
) -> tuple[dict[str, str], dict[str, str]]:
    """Return ``(mac → ip, ip → mac)`` for the scope's **live** reservations.

    Soft-deleted rows are excluded by the global filter, which is exactly right:
    the unique indexes these maps guard against are themselves partial on
    ``deleted_at IS NULL``, so a trashed reservation holds no slot.
    """
    rows = (
        await db.execute(
            select(DHCPStaticAssignment.mac_address, DHCPStaticAssignment.ip_address).where(
                DHCPStaticAssignment.scope_id == scope_id
            )
        )
    ).all()
    mac_to_ip: dict[str, str] = {}
    ip_to_mac: dict[str, str] = {}
    for mac, ip in rows:
        if mac is None:  # DUID-only DHCPv6 reservation (#3900): not a MAC-keyed v4 handover
            continue
        mac_s = str(mac).lower()
        ip_s = str(ip)
        mac_to_ip[mac_s] = ip_s
        ip_to_mac[ip_s] = mac_s
    return mac_to_ip, ip_to_mac


def _in_network(ip: str, network: _IPNetwork) -> bool:
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def _classify(
    *,
    ip: str,
    mac: str,
    network: _IPNetwork,
    mac_to_ip: dict[str, str],
    ip_to_mac: dict[str, str],
) -> tuple[str, str]:
    """Decide one lease's disposition. Returns ``(action, reason)``.

    ``mac_to_ip`` / ``ip_to_mac`` describe the reservations that already exist
    (or are already planned) on the managed scope, so the caller can feed
    planned rows back in and catch duplicates *within* one handover as well as
    against the database.
    """
    if not _in_network(ip, network):
        return "skip", f"{ip} is outside the managed scope's subnet {network} — another scope"

    reserved_ip = mac_to_ip.get(mac)
    reserved_mac = ip_to_mac.get(ip)

    if reserved_ip == ip:
        # Same MAC, same IP: the reservation the handover would create is
        # already there (a re-run, or the importer brought it across).
        return "skip", "already reserved on the managed scope with this address"
    if reserved_ip is not None:
        return (
            "conflict",
            f"MAC is already reserved to {reserved_ip} on this scope; the Windows lease says {ip}",
        )
    if reserved_mac is not None:
        return (
            "conflict",
            f"{ip} is already reserved to MAC {reserved_mac} on this scope",
        )
    return "create", ""


async def preview_lease_handover(
    db: AsyncSession,
    *,
    source_server: DHCPServer,
    scope: DHCPScope,
    source_scope_id: str,
) -> LeaseHandoverPlan:
    """Build the handover plan without writing anything.

    Pulls the live lease table off the Windows server (``get_leases`` already
    filters to the states Windows considers live) and classifies every lease
    against the managed scope: ``create`` for one that will become a
    reservation, ``skip`` for one that belongs to a different scope / is
    already reserved / has no usable MAC, ``conflict`` for one whose MAC or
    address is already spoken for by a *different* reservation.

    ``source_scope_id`` is only used for reporting and a sanity warning — the
    driver's neutral lease dict has no scope id, so subnet containment is what
    actually selects this scope's leases.
    """
    _subnet, network = await _scope_network(db, scope)
    plan = LeaseHandoverPlan(scope_cidr=str(network), source_scope_id=source_scope_id)

    declared = (source_scope_id or "").strip()
    if declared and declared != str(network.network_address):
        plan.warnings.append(
            f"The Windows scope id on this item is {declared}, but the managed scope's subnet is "
            f"{network}. Leases are selected by subnet containment, so double-check the item is "
            "pointing at the right scope."
        )

    driver = WindowsDHCPReadOnlyDriver()
    leases = await driver.get_leases(source_server)
    if not leases:
        plan.warnings.append(
            f"{source_server.name} reported no active leases. If the scope is busy, check the "
            "service account can read leases before treating this as a clean handover."
        )

    mac_to_ip, ip_to_mac = await _live_reservation_maps(db, scope.id)
    # Planned rows fold into the same maps so two leases in one pull can't both
    # claim a MAC or an address and then collide at flush time.
    planned_mac_to_ip: dict[str, str] = dict(mac_to_ip)
    planned_ip_to_mac: dict[str, str] = dict(ip_to_mac)

    foreign = 0
    unusable_mac = 0
    for lease in leases:
        ip = str(lease.get("ip_address") or "").strip()
        mac = normalise_mac(lease.get("mac_address") or lease.get("client_id"))
        hostname = sanitize_hostname(lease.get("hostname"))
        if not ip:
            continue
        if mac is None:
            unusable_mac += 1
            plan.entries.append(
                LeaseHandoverEntry(
                    ip_address=ip,
                    mac_address=str(lease.get("mac_address") or lease.get("client_id") or ""),
                    hostname=hostname,
                    action="skip",
                    reason="no usable MAC address on the lease — nothing to key a reservation on",
                )
            )
            continue

        action, reason = _classify(
            ip=ip,
            mac=mac,
            network=network,
            mac_to_ip=planned_mac_to_ip,
            ip_to_mac=planned_ip_to_mac,
        )
        if action == "skip" and not _in_network(ip, network):
            foreign += 1
        if action == "create":
            planned_mac_to_ip[mac] = ip
            planned_ip_to_mac[ip] = mac
        plan.entries.append(
            LeaseHandoverEntry(
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                action=action,  # type: ignore[arg-type]  # narrowed by _classify
                reason=reason,
            )
        )

    if foreign:
        plan.warnings.append(
            f"{foreign} lease(s) belong to other scopes on {source_server.name} and are listed "
            "as skipped. Hand those over from their own cutover items."
        )
    if unusable_mac:
        plan.warnings.append(
            f"{unusable_mac} lease(s) carry a client id that is not a MAC address and cannot "
            "become a reservation."
        )
    if plan.conflict_count:
        plan.warnings.append(
            f"{plan.conflict_count} lease(s) contradict a reservation that already exists on the "
            "managed scope. Resolve those by hand — the handover will not overwrite them."
        )
    return plan


async def commit_lease_handover(
    db: AsyncSession,
    *,
    source_server: DHCPServer,
    scope: DHCPScope,
    item: CutoverItem,
    plan: LeaseHandoverPlan,
    current_user: User,
) -> LeaseHandoverPlan:
    """Write the ``create`` entries of ``plan`` as reservations on ``scope``.

    Each row is written inside its own ``db.begin_nested()`` savepoint together
    with its IPAM mirror, so one failure fails exactly one entry and the rest of
    the batch still lands. The per-entry outcome is recorded back onto the
    ``LeaseHandoverEntry`` (``result`` / ``error``) and the rollup onto
    ``item.lease_handover``.

    The plan is re-validated against **live** DB state as it goes rather than
    trusted: an operator may have added a reservation between the preview and
    the commit, and the unique indexes would turn that into an
    ``IntegrityError`` at flush.

    Does not commit — the calling router owns the transaction (and the audit
    row, and the timeline event).
    """
    _subnet, network = await _scope_network(db, scope)
    mac_to_ip, ip_to_mac = await _live_reservation_maps(db, scope.id)

    now = datetime.now(UTC)
    description = f"Carried over from {source_server.name} at cutover"
    created = skipped = failed = 0

    for entry in plan.entries:
        if entry.action != "create":
            entry.result = "skipped"
            skipped += 1
            continue

        action, reason = _classify(
            ip=entry.ip_address,
            mac=entry.mac_address,
            network=network,
            mac_to_ip=mac_to_ip,
            ip_to_mac=ip_to_mac,
        )
        if action != "create":
            # State moved under the preview — record why and move on.
            entry.action = action  # type: ignore[assignment]  # narrowed by _classify
            entry.reason = reason
            entry.result = "skipped"
            skipped += 1
            continue

        st = DHCPStaticAssignment(
            scope_id=scope.id,
            ip_address=entry.ip_address,
            mac_address=entry.mac_address,
            hostname=entry.hostname or "",
            description=description,
            # ``client_id`` deliberately left NULL. The Kea driver renders it as
            # the DHCP option-61 client-identifier a client must present for the
            # reservation to match; Windows' ClientId is just the hardware
            # address in dash form, so copying it across would narrow the match
            # to clients sending an option 61 they mostly do not send — the
            # precise failure this handover exists to prevent. hw-address alone
            # is the reliable key.
            import_source=CUTOVER_IMPORT_SOURCE,
            imported_at=now,
            created_by_user_id=current_user.id,
        )
        try:
            async with db.begin_nested():
                db.add(st)
                await db.flush()
                await upsert_ipam_for_static(db, scope, st, action="create")
        except Exception as exc:  # noqa: BLE001 — one bad row must not sink the batch
            entry.result = "failed"
            entry.error = str(exc)
            failed += 1
            logger.warning(
                "cutover_lease_handover_row_failed",
                scope_id=str(scope.id),
                ip=entry.ip_address,
                mac=entry.mac_address,
                error=str(exc),
            )
            continue

        entry.result = "created"
        created += 1
        mac_to_ip[entry.mac_address] = entry.ip_address
        ip_to_mac[entry.ip_address] = entry.mac_address

    plan.created = created
    plan.skipped = skipped
    plan.failed = failed
    item.lease_handover = {
        "created": created,
        "skipped": skipped,
        "failed": failed,
        "at": now.isoformat(),
    }
    # A clean run is the DHCP half of "pre-flight done" — the managed scope now
    # knows every address currently in use. A run with failures leaves the stage
    # alone so the operator is not told the pre-flight finished.
    if failed == 0 and item.stage in {"pending", "parity_checked"}:
        item.stage = "preflight_done"

    if created:
        # New reservations change the rendered scope, so the group's parked
        # agents should re-read rather than wait out the safety tick. Advisory
        # only — the config-bundle ETag stays the source of truth.
        collect_wake(dhcp_group_channel(scope.group_id))

    logger.info(
        "cutover_lease_handover_committed",
        plan_id=str(item.plan_id),
        item_id=str(item.id),
        scope_id=str(scope.id),
        created=created,
        skipped=skipped,
        failed=failed,
    )
    return plan

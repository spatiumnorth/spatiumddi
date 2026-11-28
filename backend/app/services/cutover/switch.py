"""The switch itself, and its reversal — Phase 3c of the cutover (issue #756).

Everything up to here is reversible bookkeeping. This module is the moment the
migration becomes visible to clients, so it is deliberately the smallest,
least clever code in the package:

* **It re-derives the blocker set before it does anything.** A parity report or
  a readiness check from twenty minutes ago is a claim about the past. The
  blockers are recomputed against live state and a ``severity == "block"``
  entry refuses the switch outright, ``force`` or not. That refusal is the
  whole reason the package exists — the headline hazard is cutting over an
  AD-integrated zone whose dynamic updates are "Secure only", because GSS-TSIG
  is unimplemented (#444) and a domain controller that cannot re-register its
  SRV records turns a DNS migration into a domain outage.
* **DHCP is switched in one order and only that order.** The Windows scope is
  deactivated *first*, then the managed scope is activated. Two DHCP servers
  answering for one subnet hand out conflicting addresses within seconds, so a
  window where both are live is worse than a window where neither is. If the
  managed side then fails to come up, the Windows scope is put back.
* **The commit is sequenced by this module, not by the caller.** Both DHCP
  paths pair an irreversible WinRM call with a database write, so *where* the
  transaction commits relative to that call decides what a crash leaves behind.
  The router hands in a ``finalize`` callable (write the audit row, commit) and
  this module decides when to invoke it — see ``_cutover_dhcp`` /
  ``_rollback_dhcp``. Committing at the wrong point is how a failed transaction
  ends with both servers answering, which is the one outcome the ordering above
  exists to prevent.
* **DNS is not switched here at all.** There is no server-side flag we own:
  which server answers for a zone is decided by the delegation at the parent
  (or by what the resolvers forward to), and both live outside SpatiumDDI. So
  the DNS path records the transition and returns the instructions. It never
  touches the Windows zone — deleting or disabling the old zone before the
  delegation has actually moved removes the thing that is still serving.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.drivers.dhcp.windows import WindowsDHCPReadOnlyDriver
from app.models.auth import User
from app.models.cutover import CutoverEvent, CutoverItem, CutoverPlan
from app.models.dhcp import DHCPScope, DHCPServer
from app.models.dns import DNSZone
from app.services.cutover.canonical import BLOCKER_POOL_CLASS_UNAVAILABLE, Blocker, blocking

logger = structlog.get_logger(__name__)

__all__ = ["CutoverBlocked", "execute_cutover", "execute_rollback"]


class CutoverBlocked(ValueError):
    """Raised when readiness refuses the switch. The router maps this to 409.

    ``blockers`` carries the offending entries so the response can render them
    verbatim — every :class:`~app.services.cutover.canonical.Blocker` message is
    written to state the fix, and a bare "not ready" would throw that away.
    """

    def __init__(self, message: str, blockers: list[Blocker]) -> None:
        super().__init__(message)
        self.blockers = blockers

    def as_dict(self) -> dict[str, Any]:
        return {"error": str(self), "blockers": [b.as_dict() for b in self.blockers]}


# ── shared helpers ────────────────────────────────────────────────────


async def _require_scope(db: AsyncSession, item: CutoverItem) -> DHCPScope:
    if item.scope_id is None:
        raise ValueError(
            f"Cutover item {item.source_ref!r} is not linked to a managed DHCP scope. "
            "Link it to the SpatiumDDI scope that will take over before cutting over."
        )
    scope = await db.get(DHCPScope, item.scope_id)
    if scope is None:
        raise ValueError(
            f"The managed DHCP scope for {item.source_ref!r} no longer exists. "
            "Re-link the item to a live scope."
        )
    return scope


async def _require_zone(db: AsyncSession, item: CutoverItem) -> DNSZone:
    if item.zone_id is None:
        raise ValueError(
            f"Cutover item {item.source_ref!r} is not linked to a managed DNS zone. "
            "Import or create the zone in SpatiumDDI and link it before cutting over."
        )
    zone = await db.get(DNSZone, item.zone_id)
    if zone is None:
        raise ValueError(
            f"The managed DNS zone for {item.source_ref!r} no longer exists. "
            "Re-link the item to a live zone."
        )
    return zone


async def _require_source_dhcp_server(db: AsyncSession, plan: CutoverPlan) -> DHCPServer:
    if plan.source_dhcp_server_id is None:
        raise ValueError(
            "This plan has no source Windows DHCP server set, so there is nothing to deactivate. "
            "Set it on the plan before cutting a DHCP scope over."
        )
    server = await db.get(DHCPServer, plan.source_dhcp_server_id)
    if server is None:
        raise ValueError("The plan's source Windows DHCP server row no longer exists.")
    if server.driver != "windows_dhcp":
        raise ValueError(
            f"Source DHCP server {server.name!r} uses the {server.driver!r} driver. "
            "The cutover switch only drives Windows DHCP."
        )
    return server


def _record_event(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    kind: str,
    summary: str,
    detail: dict[str, Any],
    current_user: User,
) -> CutoverEvent:
    """Append one timeline row. Not committed — the router owns the transaction."""
    event = CutoverEvent(
        plan_id=plan.id,
        item_id=item.id,
        at=datetime.now(UTC),
        kind=kind,
        summary=summary[:512],
        detail=detail,
        user_id=current_user.id,
        user_display_name=current_user.display_name,
    )
    db.add(event)
    return event


def _dns_switch_instructions(zone: DNSZone) -> list[str]:
    """The operator-side steps that actually move DNS traffic.

    Generated here rather than pulled from :mod:`app.services.cutover.runbook`
    because these are per-item and returned inline with the switch result; the
    runbook renders the whole plan as a document.
    """
    name = zone.name.rstrip(".")
    return [
        f"Repoint the delegation for {name}: update the NS records at the parent zone "
        "(or at the registrar, for a public zone) to the SpatiumDDI-managed name servers.",
        f"If {name} is only resolved internally, update the conditional forwarder / stub zone "
        "on every recursive resolver that currently forwards it to the Windows server.",
        "Update any DHCP option 6 (dns-servers) values that still hand clients the Windows "
        "server's address, and any statically-configured resolvers.",
        f"Leave the Windows zone in place and serving. It is the fallback until the "
        f"{zone.ttl}s TTL has expired everywhere and the new answers are confirmed.",
        "Confirm with the shadow comparison and a spot-check from an external resolver "
        "before ticking the decommission checklist.",
    ]


def _dns_rollback_instructions(zone: DNSZone) -> list[str]:
    name = zone.name.rstrip(".")
    return [
        f"Revert the delegation for {name} to the Windows name servers at the parent zone "
        "(or at the registrar).",
        "Revert the conditional forwarder / stub zone on every recursive resolver you changed.",
        "Revert any DHCP option 6 (dns-servers) values changed for the switch.",
    ]


# ── the switch ────────────────────────────────────────────────────────


async def execute_cutover(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    current_user: User,
    force: bool = False,
    #: Called once the module has reached the point where the transaction is
    #: safe to seal — writes the audit row and commits. Sequencing it is this
    #: module's job, not the caller's; see the module docstring.
    finalize: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Cut one item over from Windows to SpatiumDDI.

    Blockers are **re-evaluated against live state** first (via
    :func:`app.services.cutover.readiness.refresh_blockers`, which also persists
    them onto the item). Any blocker with ``severity == "block"`` raises
    :class:`CutoverBlocked` and the switch does not happen.

    ``force=True`` acknowledges the ``severity == "warn"`` entries and nothing
    else. It can **never** bypass a ``block`` — most importantly not
    ``ad_secure_dynamic_update``, which is refused because GSS-TSIG is
    unimplemented (#444) and cutting such a zone over breaks AD's own dynamic
    registration. There is no flag, anywhere, that turns that refusal off.

    Does not commit and writes no ``AuditLog`` row — the calling router owns the
    transaction and the audit trail. A :class:`CutoverEvent` *is* appended here,
    because the timeline entry describes what this function did (including a
    compensating rollback the router cannot see).
    """
    from app.services.cutover.readiness import refresh_blockers  # noqa: PLC0415

    blockers = await refresh_blockers(db, plan=plan, item=item)
    hard = blocking(blockers)
    if hard:
        raise CutoverBlocked(
            f"{item.source_ref} is not ready to cut over: "
            + "; ".join(b.message for b in hard[:3]),
            hard,
        )
    warnings = [b for b in blockers if b.severity == "warn"]
    if warnings and not force:
        raise CutoverBlocked(
            f"{item.source_ref} has {len(warnings)} warning(s) that must be acknowledged: "
            + "; ".join(b.message for b in warnings[:3]),
            warnings,
        )

    if item.kind == "dhcp_scope":
        return await _cutover_dhcp(
            db,
            plan=plan,
            item=item,
            current_user=current_user,
            acknowledged=warnings,
            finalize=finalize,
        )
    if item.kind == "dns_zone":
        return await _cutover_dns(
            db,
            plan=plan,
            item=item,
            current_user=current_user,
            acknowledged=warnings,
            finalize=finalize,
        )
    raise ValueError(f"Unsupported cutover item kind {item.kind!r}")


async def _cutover_dhcp(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    current_user: User,
    acknowledged: list[Blocker],
    finalize: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Deactivate the Windows scope, then activate the managed one.

    The order is the entire point. Between the two steps the subnet has *no*
    DHCP server, which costs renewing clients nothing (they hold their lease
    until half its lifetime elapses) and is measured in the seconds one WinRM
    round-trip takes. The reverse order would leave both servers answering,
    which hands two clients the same address.
    """
    scope = await _require_scope(db, item)
    source_server = await _require_source_dhcp_server(db, plan)
    driver = WindowsDHCPReadOnlyDriver()
    actions: list[str] = []

    # #4376 — re-check at the point of no return: the preflight verdict can be
    # stale, and once Windows is down a refusal here would leave the subnet
    # with no DHCP at all.
    from app.api.v1.dhcp.pools import scope_activation_class_problems  # noqa: PLC0415

    problems = await scope_activation_class_problems(db, scope)
    if problems:
        raise CutoverBlocked(
            f"{item.source_ref} is not ready to cut over: the managed scope cannot be "
            f"activated: {problems[0]}",
            [Blocker(BLOCKER_POOL_CLASS_UNAVAILABLE, "block", msg) for msg in problems],
        )

    await driver.set_scope_state(source_server, item.source_ref, active=False)
    actions.append(f"Deactivated scope {item.source_ref} on {source_server.name}")
    logger.info(
        "cutover_dhcp_source_deactivated",
        plan_id=str(plan.id),
        item_id=str(item.id),
        server=source_server.name,
        scope_id=item.source_ref,
    )

    try:
        scope.is_active = True
        await db.flush()
        collect_wake(dhcp_group_channel(scope.group_id))
        # Commit here, inside the guard. The Windows scope is already down; if
        # sealing the managed scope's activation fails, the database rolls back
        # to "managed inactive" while the subnet has no DHCP at all — so the
        # compensation below has to cover a failed commit exactly as it covers a
        # failed flush.
        if finalize is not None:
            await finalize()
    except Exception:
        # Compensate: the Windows scope is already down and the managed one did
        # not come up, so the subnet currently has no DHCP at all. Put the old
        # server back before surfacing the failure. Best-effort — if the
        # compensation itself fails there is nothing further we can do from
        # here, and the original error is the one worth reporting.
        try:
            await driver.set_scope_state(source_server, item.source_ref, active=True)
            logger.warning(
                "cutover_dhcp_compensated",
                plan_id=str(plan.id),
                item_id=str(item.id),
                scope_id=item.source_ref,
                detail="managed scope activation failed; Windows scope re-activated",
            )
        except Exception as comp_exc:  # noqa: BLE001 — report, never mask the original
            logger.error(
                "cutover_dhcp_compensation_failed",
                plan_id=str(plan.id),
                item_id=str(item.id),
                scope_id=item.source_ref,
                error=str(comp_exc),
                detail="subnet may currently have NO active DHCP server — re-activate by hand",
            )
        raise

    actions.append(f"Activated the managed scope for {scope.id} in SpatiumDDI")

    now = datetime.now(UTC)
    item.stage = "cut_over"
    item.cut_over_at = now
    item.rolled_back_at = None

    result: dict[str, Any] = {
        "kind": item.kind,
        "source_ref": item.source_ref,
        "stage": item.stage,
        "cut_over_at": now.isoformat(),
        "actions": actions,
        "instructions": [
            "Watch the DHCP activity log for the first renewals landing on the managed server.",
            "Leave the Windows scope deactivated (not deleted) until the longest lease has "
            "expired — deactivated is what makes the rollback a single call.",
        ],
        "recovery_estimate_seconds": scope.lease_time,
        "acknowledged_warnings": [b.as_dict() for b in acknowledged],
    }
    _record_event(
        db,
        plan=plan,
        item=item,
        kind="cutover",
        summary=(
            f"Cut DHCP scope {item.source_ref} over: deactivated on {source_server.name}, "
            "activated in SpatiumDDI"
        ),
        detail=result,
        current_user=current_user,
    )
    return result


async def _cutover_dns(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    current_user: User,
    acknowledged: list[Blocker],
    finalize: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Record the DNS transition and hand back the operator instructions.

    There is no server-side switch to perform: the Windows zone keeps serving
    (on purpose — it is the fallback), the managed zone is already serving, and
    what decides which one clients reach is the delegation at the parent or the
    forwarder on the resolvers. Both are outside SpatiumDDI, so the honest
    action here is to stamp the transition and tell the operator exactly what to
    change.
    """
    zone = await _require_zone(db, item)
    now = datetime.now(UTC)
    item.stage = "cut_over"
    item.cut_over_at = now
    item.rolled_back_at = None

    result: dict[str, Any] = {
        "kind": item.kind,
        "source_ref": item.source_ref,
        "stage": item.stage,
        "cut_over_at": now.isoformat(),
        "actions": [
            f"Recorded the cutover of {zone.name} — the Windows zone was left untouched and "
            "keeps serving as the fallback."
        ],
        "instructions": _dns_switch_instructions(zone),
        # What a rollback costs: once the delegation is reverted, resolvers stop
        # using the SpatiumDDI answers after at most the zone's current TTL —
        # which is what the pre-flight TTL reduction exists to shrink.
        "recovery_estimate_seconds": zone.ttl,
        "ttl_lowered_at": item.ttl_lowered_at.isoformat() if item.ttl_lowered_at else None,
        "acknowledged_warnings": [b.as_dict() for b in acknowledged],
    }
    if item.ttl_lowered_at is None:
        result.setdefault("warnings", []).append(
            "TTLs were never lowered for this zone, so a rollback propagates at the zone's "
            f"full {zone.ttl}s TTL. Run the TTL pre-flight before the next item."
        )
    _record_event(
        db,
        plan=plan,
        item=item,
        kind="cutover",
        summary=f"Cut DNS zone {zone.name} over — delegation change is operator-side",
        detail=result,
        current_user=current_user,
    )
    logger.info(
        "cutover_dns_recorded",
        plan_id=str(plan.id),
        item_id=str(item.id),
        zone=zone.name,
    )
    # No external side effect on the DNS side — the switch is a delegation
    # change the operator makes elsewhere — so the commit point is simply after
    # the DB writes.
    if finalize is not None:
        await finalize()

    return result


# ── the reversal ──────────────────────────────────────────────────────


async def execute_rollback(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    current_user: User,
    #: Called once the module has reached the point where the transaction is
    #: safe to seal — writes the audit row and commits. Sequencing it is this
    #: module's job, not the caller's; see the module docstring.
    finalize: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Reverse a cutover.

    Deliberately does **not** re-evaluate blockers: a rollback is the escape
    hatch, and gating it on readiness would mean the state that made the switch
    go wrong is also the state that stops you undoing it.

    Does not commit and writes no ``AuditLog`` row — the router owns both. A
    :class:`CutoverEvent` is appended.
    """
    if item.kind == "dhcp_scope":
        return await _rollback_dhcp(
            db, plan=plan, item=item, current_user=current_user, finalize=finalize
        )
    if item.kind == "dns_zone":
        return await _rollback_dns(
            db, plan=plan, item=item, current_user=current_user, finalize=finalize
        )
    raise ValueError(f"Unsupported cutover item kind {item.kind!r}")


async def _rollback_dhcp(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    current_user: User,
    finalize: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Deactivate the managed scope, then re-activate the Windows one.

    Mirror image of the cutover ordering, for the same reason: a gap with no
    DHCP server is survivable, an overlap with two is not.
    """
    scope = await _require_scope(db, item)
    source_server = await _require_source_dhcp_server(db, plan)
    driver = WindowsDHCPReadOnlyDriver()
    actions: list[str] = []

    now = datetime.now(UTC)
    scope.is_active = False
    item.stage = "rolled_back"
    item.rolled_back_at = now
    # Clear the cutover stamp. ``readiness._is_cut_over`` short-circuits on it to
    # stop a completed item looking permanently unready, so leaving it set on a
    # rolled-back item would suppress the pre-switch blockers for good — most
    # importantly ``managed_scope_active``, the one that refuses a retry while
    # both servers are live on the same subnet. Mirrors the cutover path, which
    # clears ``rolled_back_at`` for the same reason.
    item.cut_over_at = None
    await db.flush()
    collect_wake(dhcp_group_channel(scope.group_id))
    actions.append("Deactivated the managed scope in SpatiumDDI")

    # Seal the managed-side deactivation BEFORE touching Windows. This ordering
    # is the whole point: if the commit fails now, nothing has been done to
    # Windows and the database rolls back to the cut-over state — consistent. If
    # we committed after the WinRM call instead, a failed commit would leave the
    # database saying "managed active" while Windows had already been brought
    # back up, and both would answer for the subnet. A brief window with no DHCP
    # is survivable; an overlap is not.
    if finalize is not None:
        await finalize()

    try:
        await driver.set_scope_state(source_server, item.source_ref, active=True)
    except Exception:
        # The managed scope is down and Windows did not come back up. Re-activate
        # the managed side so *something* serves the subnet, then surface the
        # original failure. Best-effort, same reasoning as the cutover path.
        try:
            scope.is_active = True
            await db.flush()
            # The managed-side deactivation was already committed above, so this
            # correction is a new transaction and needs its own commit — a flush
            # alone would be discarded when the request unwinds.
            await db.commit()
            collect_wake(dhcp_group_channel(scope.group_id))
            logger.warning(
                "cutover_rollback_compensated",
                plan_id=str(plan.id),
                item_id=str(item.id),
                scope_id=item.source_ref,
                detail="Windows re-activation failed; managed scope left active",
            )
        except Exception as comp_exc:  # noqa: BLE001 — report, never mask the original
            logger.error(
                "cutover_rollback_compensation_failed",
                plan_id=str(plan.id),
                item_id=str(item.id),
                scope_id=item.source_ref,
                error=str(comp_exc),
                detail="subnet may currently have NO active DHCP server — re-activate by hand",
            )
        raise

    actions.append(f"Re-activated scope {item.source_ref} on {source_server.name}")

    result: dict[str, Any] = {
        "kind": item.kind,
        "source_ref": item.source_ref,
        "stage": item.stage,
        "rolled_back_at": now.isoformat(),
        "actions": actions,
        "instructions": [
            "Reservations created by the lease handover are still on the managed scope. They are "
            "stamped import_source=windows_cutover and are harmless while the scope is inactive; "
            "delete them only if you do not intend to retry the cutover.",
        ],
        "recovery_estimate_seconds": 0,
    }
    _record_event(
        db,
        plan=plan,
        item=item,
        kind="rollback",
        summary=(
            f"Rolled DHCP scope {item.source_ref} back: deactivated in SpatiumDDI, "
            f"re-activated on {source_server.name}"
        ),
        detail=result,
        current_user=current_user,
    )
    return result


async def _rollback_dns(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    current_user: User,
    finalize: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Restore the pre-flight TTLs and hand back the revert instructions.

    As with the cutover, the traffic-moving step is the delegation and lives
    outside SpatiumDDI. What *is* ours is the TTL snapshot, which is restored
    here so the zone goes back to the values it had before the migration
    lowered them.
    """
    from app.services.cutover.preflight import restore_ttl_preflight  # noqa: PLC0415

    zone = await _require_zone(db, item)
    restored = 0
    if item.ttl_snapshot:
        restored = await restore_ttl_preflight(db, zone=zone, item=item, current_user=current_user)

    now = datetime.now(UTC)
    item.stage = "rolled_back"
    item.rolled_back_at = now
    # Clear the cutover stamp. ``readiness._is_cut_over`` short-circuits on it to
    # stop a completed item looking permanently unready, so leaving it set on a
    # rolled-back item would suppress the pre-switch blockers for good — most
    # importantly ``managed_scope_active``, the one that refuses a retry while
    # both servers are live on the same subnet. Mirrors the cutover path, which
    # clears ``rolled_back_at`` for the same reason.
    item.cut_over_at = None

    result: dict[str, Any] = {
        "kind": item.kind,
        "source_ref": item.source_ref,
        "stage": item.stage,
        "rolled_back_at": now.isoformat(),
        "actions": (
            [f"Restored the pre-flight TTL snapshot ({restored} record(s)) on {zone.name}"]
            if restored
            else ["No TTL snapshot to restore — TTLs were never lowered for this zone."]
        ),
        "instructions": _dns_rollback_instructions(zone),
        "records_restored": restored,
        "recovery_estimate_seconds": zone.ttl,
    }
    _record_event(
        db,
        plan=plan,
        item=item,
        kind="rollback",
        summary=f"Rolled DNS zone {zone.name} back — {restored} TTL(s) restored",
        detail=result,
        current_user=current_user,
    )
    logger.info(
        "cutover_dns_rolled_back",
        plan_id=str(plan.id),
        item_id=str(item.id),
        zone=zone.name,
        records_restored=restored,
    )
    # No external side effect on the DNS side — the switch is a delegation
    # change the operator makes elsewhere — so the commit point is simply after
    # the DB writes.
    if finalize is not None:
        await finalize()

    return result

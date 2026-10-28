"""Is this item safe to cut over yet? (#756)

Every reason an item is *not* ready is a :class:`~app.services.cutover.canonical.Blocker`
with a stable code and one of two severities. ``warn`` is advisory and can be
acknowledged with ``force=true``; ``block`` refuses the cutover outright and
cannot be forced, ever.

**The one that matters is** ``ad_secure_dynamic_update``. A Windows zone set to
AD "Secure only" dynamic updates accepts registrations exclusively over
GSS-TSIG. SpatiumDDI does not implement GSS-TSIG yet (#444), so the moment that
zone is served from here instead, every domain controller and domain-joined
client silently fails to register — no error the operator will see, just an
Active Directory that stops resolving itself. That is the difference between a
DNS migration and a domain outage, so it is a hard block and
:func:`normalize_dynamic_update` is written to be paranoid about detecting it:
Windows' ``DynamicUpdate`` arrives from ``ConvertTo-Json`` either as the string
(``None`` / ``NonsecureAndSecure`` / ``Secure``) or as the raw enum integer
(``0`` / ``1`` / ``2``), and both forms are handled. An AD-integrated zone whose
mode cannot be interpreted at all is treated as ``Secure``, because "we could
not tell" must not read as "it is fine".

:func:`refresh_blockers` deliberately performs a **live** read of the source
Windows server rather than trusting anything cached on the item. The whole guard
is worthless if an operator can flip a zone to "Secure only" on Windows after
the last parity run and still be allowed to cut over. It persists the result
onto ``item.blockers`` but does not commit — the caller owns the transaction.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import get_driver as get_dhcp_driver
from app.drivers.dns import get_driver as get_dns_driver
from app.models.cutover import CutoverItem, CutoverPlan
from app.models.dhcp import DHCPScope, DHCPServer
from app.models.dns import DNSServer, DNSZone
from app.models.ipam import Subnet
from app.services.cutover.canonical import (
    BLOCKER_AD_NONSECURE_DDNS,
    BLOCKER_AD_SECURE_DDNS,
    BLOCKER_LEASE_HANDOVER_PENDING,
    BLOCKER_MANAGED_SCOPE_ACTIVE,
    BLOCKER_MISSING_REVERSE_ZONE,
    BLOCKER_NO_SOURCE_SERVER,
    BLOCKER_NO_TARGET_SCOPE,
    BLOCKER_NO_TARGET_ZONE,
    BLOCKER_PARITY_DIFFERENCES,
    BLOCKER_PARITY_NOT_VERIFIED,
    BLOCKER_SOURCE_SCOPE_INACTIVE,
    BLOCKER_SOURCE_SCOPE_MISSING,
    BLOCKER_SOURCE_ZONE_MISSING,
    BLOCKER_TARGET_GROUP_NO_SERVERS,
    BLOCKER_TARGET_ZONE_VIEW_SCOPED,
    BLOCKER_ZONE_IS_AD_INTEGRATED,
    Blocker,
)
from app.services.cutover.parity import match_source_scope

logger = structlog.get_logger(__name__)


# ── Windows DynamicUpdate normalisation ────────────────────────────────

#: The ``DnsZoneDynamicUpdate`` enum as PowerShell serialises it when
#: ``ConvertTo-Json`` decides the property is numeric rather than a string.
#: Which of the two shapes you get depends on the Windows / PowerShell build,
#: so both are handled rather than assumed.
_DYNAMIC_UPDATE_BY_INT: dict[int, str] = {
    0: "none",
    1: "nonsecure_and_secure",
    2: "secure",
}

#: Keyed on the mode name with every non-alphanumeric character stripped, so
#: ``"NonsecureAndSecure"``, ``"nonsecure and secure"`` and
#: ``"Nonsecure_And_Secure"`` all land on the same entry.
_DYNAMIC_UPDATE_BY_TEXT: dict[str, str] = {
    "none": "none",
    "nonsecureandsecure": "nonsecure_and_secure",
    "secure": "secure",
}


def normalize_dynamic_update(raw: Any) -> str | None:
    """Canonicalise Windows' ``DynamicUpdate`` value.

    Returns ``"none"``, ``"nonsecure_and_secure"``, ``"secure"``, or ``None``
    when the value is absent or in a shape we do not recognise. Callers must
    treat ``None`` as *unknown*, never as *safe* — see
    :func:`evaluate_dns_item`, which escalates an unknown mode on an
    AD-integrated zone to a hard block.

    Accepts both wire shapes (see ``_DYNAMIC_UPDATE_BY_INT``) plus a numeric
    string, and compares text case-insensitively.
    """
    # ``bool`` is an ``int`` subclass, and ``True`` would otherwise decode as
    # ``NonsecureAndSecure``. A boolean here is nonsense, so report unknown.
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return _DYNAMIC_UPDATE_BY_INT.get(raw)
    if isinstance(raw, float):
        return _DYNAMIC_UPDATE_BY_INT.get(int(raw)) if raw.is_integer() else None

    text = str(raw).strip()
    if not text:
        return None
    if text.isascii() and text.isdigit():
        return _DYNAMIC_UPDATE_BY_INT.get(int(text))
    squashed = "".join(ch for ch in text.lower() if ch.isalnum())
    return _DYNAMIC_UPDATE_BY_TEXT.get(squashed)


# ── shared blocker helpers ─────────────────────────────────────────────


def _is_cut_over(item: CutoverItem) -> bool:
    """Has the switch already happened for this item?

    Several checks describe the *pre*-switch posture (the managed scope must be
    inactive, leases must still be handed over). Once the item is cut over those
    are satisfied-by-having-happened, and leaving them in place would make a
    completed item permanently look unready.
    """
    return item.cut_over_at is not None or item.stage == "cut_over"


#: Why a stored parity report with this status proves nothing, phrased for the
#: operator. Anything not listed here falls back to a generic line. Mirrors the
#: ``status`` vocabulary documented on
#: :class:`~app.services.cutover.canonical.ParityReport`.
_PARITY_STATUS_REASON: dict[str, str] = {
    "error": "the source server could not be read",
    "unmatched": "the object exists on only one of the two servers",
    "unverified": "the source returned a result that cannot be trusted as an answer",
}


def _parity_blockers(item: CutoverItem) -> list[Blocker]:
    """Turn the last stored parity report into readiness verdicts.

    Never having run a parity check, and having run one that did not produce a
    trustworthy answer, are the same thing from here: nobody has demonstrated
    the two sides agree, so the cutover is refused. Actual differences are only
    a warning — an operator who has reviewed them and decided they are
    acceptable can force past.
    """
    last = item.last_parity
    if not isinstance(last, dict):
        return [
            Blocker(
                BLOCKER_PARITY_NOT_VERIFIED,
                "block",
                "No parity check has been run for this item. Run one so the "
                "SpatiumDDI copy can be compared against what Windows is serving "
                "right now.",
            )
        ]

    status = str(last.get("status") or "unknown")
    if status != "ok":
        reason = _PARITY_STATUS_REASON.get(status, f"it finished with status {status!r}")
        detail = str(last.get("error") or "no detail was recorded")
        return [
            Blocker(
                BLOCKER_PARITY_NOT_VERIFIED,
                "block",
                f"The last parity check proved nothing because {reason}: {detail}. "
                "Fix that and re-run it — an item whose parity is unverified cannot "
                "be cut over.",
            )
        ]

    count = int(last.get("difference_count") or 0)
    if count:
        return [
            Blocker(
                BLOCKER_PARITY_DIFFERENCES,
                "warn",
                f"The last parity check found {count} difference(s) between Windows and "
                "SpatiumDDI. Reconcile them, or acknowledge them and force the cutover "
                "if they are intentional.",
            )
        ]
    return []


# ── DNS ────────────────────────────────────────────────────────────────


async def evaluate_dns_item(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    zone: DNSZone | None,
    source_zone_meta: dict[str, Any] | None,
) -> list[Blocker]:
    """Readiness verdicts for one ``dns_zone`` item.

    ``source_zone_meta`` is one entry from
    :meth:`app.drivers.dns.windows.WindowsDNSDriver.pull_zones_from_server` —
    ``{"name", "zone_type", "is_ad_integrated", "is_reverse_lookup",
    "dynamic_update"}``. ``None`` means the zone was not found on the source
    server *or* the source could not be read; either way the AD dynamic-update
    mode is unverified, which is a hard block.
    """
    blockers: list[Blocker] = []

    if plan.source_dns_server_id is None:
        blockers.append(
            Blocker(
                BLOCKER_NO_SOURCE_SERVER,
                "block",
                "The plan has no source Windows DNS server. Set one so parity and the "
                "AD dynamic-update check can run against the zone this item migrates.",
            )
        )
    elif source_zone_meta is None:
        blockers.append(
            Blocker(
                BLOCKER_SOURCE_ZONE_MISSING,
                "block",
                f"Zone {item.source_ref!r} could not be read from the source Windows DNS "
                "server, so its dynamic-update mode is unverified. Re-run Discover to "
                "confirm the zone name, or remove this item.",
            )
        )

    if source_zone_meta is not None:
        mode = normalize_dynamic_update(source_zone_meta.get("dynamic_update"))
        ad_integrated = bool(source_zone_meta.get("is_ad_integrated"))

        if mode == "secure":
            logger.warning(
                "cutover.readiness.ad_secure_dynamic_update",
                plan=str(plan.id),
                item=str(item.id),
                zone=item.source_ref,
            )
            blockers.append(
                Blocker(
                    BLOCKER_AD_SECURE_DDNS,
                    "block",
                    f"Zone {item.source_ref!r} uses Active Directory 'Secure only' dynamic "
                    "updates. SpatiumDDI cannot accept GSS-TSIG updates yet (#444), so "
                    "after the switch domain controllers and domain-joined clients would "
                    "silently fail to register their records and AD would stop resolving "
                    "itself. Either set the zone's dynamic-update mode on Windows to "
                    "'Nonsecure and secure' before cutting over, or leave this zone on "
                    "Windows and migrate the rest. This cannot be forced.",
                )
            )
        elif mode is None and ad_integrated:
            blockers.append(
                Blocker(
                    BLOCKER_AD_SECURE_DDNS,
                    "block",
                    f"The dynamic-update mode of AD-integrated zone {item.source_ref!r} "
                    f"could not be interpreted (Windows reported "
                    f"{source_zone_meta.get('dynamic_update')!r}). It is treated as "
                    "'Secure only' rather than assumed safe, because migrating a "
                    "GSS-TSIG zone breaks Active Directory. Check the zone in DNS "
                    "Manager and re-run Discover.",
                )
            )
        elif mode == "nonsecure_and_secure":
            blockers.append(
                Blocker(
                    BLOCKER_AD_NONSECURE_DDNS,
                    "warn",
                    f"Zone {item.source_ref!r} accepts nonsecure dynamic updates. Clients "
                    "registering into it will keep working after the switch only if the "
                    "target zone also allows dynamic updates — enable them on the "
                    "SpatiumDDI zone first.",
                )
            )

        if ad_integrated:
            blockers.append(
                Blocker(
                    BLOCKER_ZONE_IS_AD_INTEGRATED,
                    "warn",
                    f"Zone {item.source_ref!r} is Active Directory-integrated, so it "
                    "replicates between domain controllers and other DCs will keep "
                    "serving it after the switch. Confirm the delegation / forwarder "
                    "change reaches every resolver, and plan the AD-side removal "
                    "separately (see the decommission checklist).",
                )
            )

    if zone is None:
        blockers.append(
            Blocker(
                BLOCKER_NO_TARGET_ZONE,
                "block",
                "This item has no SpatiumDDI zone linked. Import the Windows zone (or "
                "link the existing one) before cutting over — there is nothing here to "
                "answer queries.",
            )
        )
        return blockers

    server_count = (
        await db.execute(
            select(func.count())
            .select_from(DNSServer)
            .where(DNSServer.group_id == zone.group_id, DNSServer.is_enabled.is_(True))
        )
    ).scalar_one()
    if not server_count:
        blockers.append(
            Blocker(
                BLOCKER_TARGET_GROUP_NO_SERVERS,
                "block",
                "The target DNS server group has no enabled servers, so nothing would "
                "answer for this zone after the switch. Add or enable a server in the "
                "group first.",
            )
        )

    if zone.view_id is not None:
        blockers.append(
            Blocker(
                BLOCKER_TARGET_ZONE_VIEW_SCOPED,
                "warn",
                "The target zone is scoped to a DNS view, so only clients matching that "
                "view's match-clients list will receive it. Confirm the view covers "
                "every client the Windows zone serves today.",
            )
        )

    # A forward zone whose group has no reverse zone at all means PTR records
    # have nowhere to live once this zone is authoritative here — DDNS PTR
    # updates and reverse lookups that work today would quietly stop. Only
    # checked for forward zones, and only as a warning: plenty of estates
    # legitimately run without reverse DNS.
    if source_zone_meta is not None and not source_zone_meta.get("is_reverse_lookup"):
        reverse_count = (
            await db.execute(
                select(func.count())
                .select_from(DNSZone)
                .where(
                    DNSZone.group_id == zone.group_id,
                    DNSZone.kind == "reverse",
                    DNSZone.deleted_at.is_(None),
                )
            )
        ).scalar_one()
        if not reverse_count:
            blockers.append(
                Blocker(
                    BLOCKER_MISSING_REVERSE_ZONE,
                    "warn",
                    "The target DNS server group holds no reverse zone, so PTR records "
                    "for this zone's hosts have nowhere to go after the switch. Import "
                    "or create the matching in-addr.arpa / ip6.arpa zone if reverse "
                    "lookups matter here.",
                )
            )

    blockers.extend(_parity_blockers(item))
    return blockers


# ── DHCP ───────────────────────────────────────────────────────────────


async def evaluate_dhcp_item(
    db: AsyncSession,
    *,
    plan: CutoverPlan,
    item: CutoverItem,
    scope: DHCPScope | None,
    source_scope: dict[str, Any] | None,
) -> list[Blocker]:
    """Readiness verdicts for one ``dhcp_scope`` item.

    ``source_scope`` is one entry from
    :meth:`app.drivers.dhcp.windows.WindowsDHCPReadOnlyDriver.get_scopes` —
    ``{"scope_id", "subnet_cidr", "lease_time", "is_active", "pools",
    "statics", …}``, or ``None`` when the scope was not found on the source
    server or the source could not be read.
    """
    blockers: list[Blocker] = []
    cut_over = _is_cut_over(item)

    if plan.source_dhcp_server_id is None:
        blockers.append(
            Blocker(
                BLOCKER_NO_SOURCE_SERVER,
                "block",
                "The plan has no source Windows DHCP server. Set one so parity can run "
                "and so the switch has a server to deactivate the old scope on.",
            )
        )
    elif source_scope is None:
        blockers.append(
            Blocker(
                BLOCKER_SOURCE_SCOPE_MISSING,
                "block",
                f"Scope {item.source_ref!r} could not be read from the source Windows "
                "DHCP server, so the switch has nothing to deactivate and both servers "
                "could end up answering. Re-run Discover, or remove this item.",
            )
        )
    elif not source_scope.get("is_active"):
        blockers.append(
            Blocker(
                BLOCKER_SOURCE_SCOPE_INACTIVE,
                "warn",
                f"The Windows scope {item.source_ref!r} is already inactive, so the "
                "switch will have nothing to turn off. Confirm clients are not being "
                "served from somewhere else before activating the managed scope.",
            )
        )

    if scope is None:
        blockers.append(
            Blocker(
                BLOCKER_NO_TARGET_SCOPE,
                "block",
                "This item has no SpatiumDDI scope linked. Import the Windows scope (or "
                "link the existing one) before cutting over — there is nothing here to "
                "hand out addresses.",
            )
        )
        return blockers

    server_count = (
        await db.execute(
            select(func.count())
            .select_from(DHCPServer)
            .where(DHCPServer.server_group_id == scope.group_id)
        )
    ).scalar_one()
    if not server_count:
        blockers.append(
            Blocker(
                BLOCKER_TARGET_GROUP_NO_SERVERS,
                "block",
                "The target DHCP server group has no servers, so nothing would hand out "
                "addresses after the switch. Add a server to the group first.",
            )
        )

    if scope.is_active and not cut_over:
        blockers.append(
            Blocker(
                BLOCKER_MANAGED_SCOPE_ACTIVE,
                "block",
                "The managed scope is already active while the Windows scope is still "
                "serving, so two DHCP servers can answer the same subnet and hand out "
                "conflicting addresses. Deactivate the SpatiumDDI scope — the parallel "
                "run must be structurally unreachable to clients — and let the cutover "
                "activate it.",
            )
        )

    if item.lease_handover is None and not cut_over:
        blockers.append(
            Blocker(
                BLOCKER_LEASE_HANDOVER_PENDING,
                "warn",
                "Live Windows leases have not been handed over as reservations, so "
                "clients renewing against the managed server would be offered a "
                "different address than the one they hold. Run the lease handover "
                "first, or accept the re-addressing.",
            )
        )

    blockers.extend(_parity_blockers(item))
    return blockers


# ── Live refresh ───────────────────────────────────────────────────────


async def _pull_source_zone_meta(
    source_server: DNSServer, source_ref: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Live-read the source zone's metadata.

    Returns ``(meta, error)``. ``(None, None)`` means the server answered and
    genuinely does not host the zone; ``(None, "…")`` means we could not ask.
    """
    try:
        driver = get_dns_driver(source_server.driver)
    except ValueError as exc:
        return None, str(exc)

    if not hasattr(driver, "pull_zones_from_server"):
        return None, (
            f"DNS driver {source_server.driver!r} cannot list zones, so the zone's "
            "dynamic-update mode cannot be verified."
        )

    try:
        zones: list[dict[str, Any]] = await driver.pull_zones_from_server(source_server)
    except Exception as exc:  # noqa: BLE001 — surfaced as a blocker, never raised
        logger.warning(
            "cutover.readiness.zone_pull_failed",
            server=str(source_server.id),
            driver=source_server.driver,
            zone=source_ref,
            error=str(exc),
        )
        return None, str(exc)

    want = (source_ref or "").rstrip(".").lower()
    for entry in zones:
        if str(entry.get("name") or "").rstrip(".").lower() == want:
            return entry, None
    return None, None


async def _pull_source_scope(
    source_server: DHCPServer, source_ref: str, subnet_cidr: str
) -> tuple[dict[str, Any] | None, str | None]:
    """Live-read the source scope. Same ``(entry, error)`` contract as above."""
    try:
        driver = get_dhcp_driver(source_server.driver)
    except ValueError as exc:
        return None, str(exc)

    if not hasattr(driver, "get_scopes"):
        return None, (
            f"DHCP driver {source_server.driver!r} cannot list scopes, so the source "
            "scope's state cannot be verified."
        )

    try:
        scopes: list[dict[str, Any]] = await driver.get_scopes(source_server)
    except Exception as exc:  # noqa: BLE001 — surfaced as a blocker, never raised
        logger.warning(
            "cutover.readiness.scope_pull_failed",
            server=str(source_server.id),
            driver=source_server.driver,
            scope=source_ref,
            error=str(exc),
        )
        return None, str(exc)

    return match_source_scope(scopes, subnet_cidr=subnet_cidr, source_scope_id=source_ref), None


def _annotate_unreadable_source(blockers: list[Blocker], code: str, error: str) -> None:
    """Replace a "not found on the source" message with the real transport error.

    ``evaluate_*`` cannot tell the two apart from a ``None`` payload, but they
    need different fixes: a missing zone means remove the item, an unreachable
    server means fix WinRM. Only the message changes — the code and the ``block``
    severity stay, because either way the item is unverified.
    """
    for blocker in blockers:
        if blocker.code == code:
            blocker.message = (
                "The source Windows server could not be read, so this item is "
                f"unverified: {error}. Fix the connection and re-check before cutting "
                "over."
            )


async def refresh_blockers(
    db: AsyncSession, *, plan: CutoverPlan, item: CutoverItem
) -> list[Blocker]:
    """Re-evaluate ``item`` against live source state and persist the verdict.

    Reads the source Windows server for real on every call — a zone flipped to
    "Secure only" after the last parity run must still be caught. Writes the
    result to ``item.blockers`` and **does not commit**: the caller owns the
    transaction, so a cutover handler can refresh, refuse, and roll back its own
    unit of work without leaving a half-written item behind.
    """
    if item.kind == "dns_zone":
        blockers = await _refresh_dns_blockers(db, plan=plan, item=item)
    elif item.kind == "dhcp_scope":
        blockers = await _refresh_dhcp_blockers(db, plan=plan, item=item)
    else:
        raise ValueError(f"Unsupported cutover item kind {item.kind!r}")

    item.blockers = [b.as_dict() for b in blockers]
    db.add(item)

    logger.info(
        "cutover.readiness.refreshed",
        plan=str(plan.id),
        item=str(item.id),
        kind=item.kind,
        source_ref=item.source_ref,
        blocking=sum(1 for b in blockers if b.severity == "block"),
        warnings=sum(1 for b in blockers if b.severity == "warn"),
    )
    return blockers


async def _refresh_dns_blockers(
    db: AsyncSession, *, plan: CutoverPlan, item: CutoverItem
) -> list[Blocker]:
    zone: DNSZone | None = None
    if item.zone_id is not None:
        zone = (
            await db.execute(select(DNSZone).where(DNSZone.id == item.zone_id))
        ).scalar_one_or_none()

    source_server: DNSServer | None = None
    if plan.source_dns_server_id is not None:
        source_server = (
            await db.execute(select(DNSServer).where(DNSServer.id == plan.source_dns_server_id))
        ).scalar_one_or_none()

    meta: dict[str, Any] | None = None
    source_error: str | None = None
    if source_server is not None:
        meta, source_error = await _pull_source_zone_meta(source_server, item.source_ref)

    blockers = await evaluate_dns_item(db, plan=plan, item=item, zone=zone, source_zone_meta=meta)
    if source_error:
        _annotate_unreadable_source(blockers, BLOCKER_SOURCE_ZONE_MISSING, source_error)
    return blockers


async def _refresh_dhcp_blockers(
    db: AsyncSession, *, plan: CutoverPlan, item: CutoverItem
) -> list[Blocker]:
    scope: DHCPScope | None = None
    if item.scope_id is not None:
        scope = (
            await db.execute(select(DHCPScope).where(DHCPScope.id == item.scope_id))
        ).scalar_one_or_none()

    source_server: DHCPServer | None = None
    if plan.source_dhcp_server_id is not None:
        source_server = (
            await db.execute(select(DHCPServer).where(DHCPServer.id == plan.source_dhcp_server_id))
        ).scalar_one_or_none()

    # The CIDR is how the source scope is matched; without the scope (and so
    # without a subnet) we fall back to matching on the scope id alone, which
    # ``match_source_scope`` handles.
    subnet_cidr = ""
    if scope is not None:
        subnet = (
            await db.execute(select(Subnet).where(Subnet.id == scope.subnet_id))
        ).scalar_one_or_none()
        if subnet is not None:
            subnet_cidr = str(subnet.network)

    source: dict[str, Any] | None = None
    source_error: str | None = None
    if source_server is not None:
        source, source_error = await _pull_source_scope(source_server, item.source_ref, subnet_cidr)

    blockers = await evaluate_dhcp_item(db, plan=plan, item=item, scope=scope, source_scope=source)
    if source_error:
        _annotate_unreadable_source(blockers, BLOCKER_SOURCE_SCOPE_MISSING, source_error)
    return blockers


__all__ = [
    "evaluate_dhcp_item",
    "evaluate_dns_item",
    "normalize_dynamic_update",
    "refresh_blockers",
]

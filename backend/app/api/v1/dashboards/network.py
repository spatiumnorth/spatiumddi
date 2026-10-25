"""Network dashboard tab summary (issue #107).

Aggregates signals from the 2026.05.03-1 / 2026.05.05-1 network
modeling work into one rollup payload so the dashboard tab can
hydrate from a single React Query.

Headline counts:

* ASN drift (``asn.whois_state="drift"``)
* RPKI ROAs in ``state="expiring_soon"``
* RPKI ROAs in ``state="expired"``
* Circuits past ``term_end_date`` (excluding ``status="decom"``)
* Circuits with ``status in ("suspended", "decom")``
* Service-catalog rows with at least one orphan resource
* Overlay networks impacted by any down circuit

Plus up to N detail rows per panel — the dashboard renders these
in a "top failing" panel and click-throughs go to the canonical
admin page.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_any_permission, user_has_permission
from app.models.asn import ASN, ASNRpkiRoa
from app.models.circuit import Circuit
from app.models.network_service import NetworkService, NetworkServiceResource
from app.models.overlay import OverlayNetwork, OverlaySite

router = APIRouter()


# ── Schemas ─────────────────────────────────────────────────────────


class ASNDriftRow(BaseModel):
    id: str
    number: int
    name: str | None
    holder_org: str | None
    previous_holder: str | None


class RpkiRoaRow(BaseModel):
    id: str
    asn_id: str
    asn_number: int | None
    prefix: str
    max_length: int | None
    valid_to: datetime | None
    state: str


class CircuitRow(BaseModel):
    id: str
    name: str
    status: str
    transport: str | None
    term_end_date: str | None
    customer_id: str | None
    provider_id: str | None


class OrphanServiceRow(BaseModel):
    service_id: str
    service_name: str
    resource_kind: str
    resource_id: str


class OverlayImpactRow(BaseModel):
    id: str
    name: str
    site_count: int
    note: str


class NetworkDashboardSummary(BaseModel):
    """Headline counts + top-N detail rows per panel.

    ``generated_at`` is the server clock at query time so the front
    end can render a "fresh as of …" hint instead of relying on
    React Query's wall-clock guess.
    """

    generated_at: datetime

    asn_drift_count: int
    rpki_expiring_count: int
    rpki_expired_count: int
    # Total ROAs tracked + when the pull last touched one. Lets the panel
    # distinguish a real all-clear from stale or absent data (#942).
    rpki_total_count: int
    rpki_last_checked_at: datetime | None
    circuit_term_expiring_count: int
    circuit_status_changed_count: int
    service_orphan_count: int
    overlay_impacted_count: int

    asn_drift: list[ASNDriftRow]
    rpki_expiring: list[RpkiRoaRow]
    circuit_alerts: list[CircuitRow]
    orphan_services: list[OrphanServiceRow]
    overlay_impact: list[OverlayImpactRow]


# Top-N caps per detail panel. The dashboard never paginates these —
# the panel is a heads-up, the admin page is for full triage.
_DETAIL_LIMIT = 10


# Statuses that count as "needs operator attention" for the circuit
# panel. ``decom`` is the official end-of-life flag operators set;
# ``suspended`` is mid-incident. Both surface here because operators
# want eyes on either.
_CIRCUIT_NOTABLE_STATUSES: frozenset[str] = frozenset({"suspended", "decom"})


# ── Detail builders ─────────────────────────────────────────────────


async def _resolve_asn_number(db: Any, asn_id: Any) -> int | None:
    """Best-effort ASN.number lookup for the RPKI panel display."""
    asn = await db.get(ASN, asn_id)
    return int(asn.number) if asn is not None else None


# ── Route ───────────────────────────────────────────────────────────


@router.get(
    "/network/summary",
    response_model=NetworkDashboardSummary,
    # The rollup draws on ASNs, circuits, services and overlays, so it needs
    # read on at least one of the resource types those routers gate on.
    dependencies=[
        Depends(
            require_any_permission(
                ("read", "manage_asns"),
                ("read", "circuit"),
                ("read", "network_service"),
                ("read", "overlay_network"),
            )
        )
    ],
)
async def network_summary(db: DB, current_user: CurrentUser) -> NetworkDashboardSummary:
    """Single-shot rollup for the Network dashboard tab.

    Each panel is filled only for a caller who may read its resource type
    through that resource's own router; the others come back empty, so the
    rollup never shows more than those routes would.
    """
    now = datetime.now(UTC)

    # ASN drift — count + detail.
    drift_rows = (
        (
            await db.execute(
                select(ASN).where(ASN.whois_state == "drift").order_by(ASN.modified_at.desc())
            )
        )
        .scalars()
        .all()
    )
    asn_drift = [
        ASNDriftRow(
            id=str(r.id),
            number=int(r.number),
            name=r.name or None,
            holder_org=r.holder_org or None,
            previous_holder=(
                r.whois_data.get("previous_holder") if isinstance(r.whois_data, dict) else None
            ),
        )
        for r in drift_rows[:_DETAIL_LIMIT]
    ]
    asn_drift_count = len(drift_rows)

    # RPKI expiring + expired — count both, surface the expiring soon
    # rows in the panel since they're the actionable bucket.
    expiring_rows = (
        (
            await db.execute(
                select(ASNRpkiRoa)
                .where(ASNRpkiRoa.state == "expiring_soon")
                .order_by(ASNRpkiRoa.valid_to.asc())
            )
        )
        .scalars()
        .all()
    )
    expired_rows = (
        (await db.execute(select(ASNRpkiRoa).where(ASNRpkiRoa.state == "expired"))).scalars().all()
    )
    # Freshness of the underlying pull (#942). Without this the panel
    # cannot tell "nothing is expiring" from "the refresh task died
    # three weeks ago and these counts are fiction" — and those want
    # opposite responses from the operator. Reported, never inferred:
    # the frontend decides what counts as stale.
    rpki_total_count = (await db.execute(select(func.count()).select_from(ASNRpkiRoa))).scalar_one()
    rpki_last_checked_at = (
        await db.execute(select(func.max(ASNRpkiRoa.last_checked_at)))
    ).scalar_one()
    rpki_expiring: list[RpkiRoaRow] = []
    for r in expiring_rows[:_DETAIL_LIMIT]:
        asn_number = await _resolve_asn_number(db, r.asn_id)
        rpki_expiring.append(
            RpkiRoaRow(
                id=str(r.id),
                asn_id=str(r.asn_id),
                asn_number=asn_number,
                prefix=str(r.prefix),
                max_length=r.max_length,
                valid_to=r.valid_to,
                state=r.state,
            )
        )

    # Circuit term expiring + status flipped to suspended/decom. Active
    # circuits past their term are operator-noteworthy regardless of
    # status; we surface them under "circuit alerts" alongside any
    # ``suspended`` / ``decom`` rows so the panel is one consolidated
    # heads-up.
    today = now.date()
    expiring_circuits = list(
        (
            await db.execute(
                select(Circuit)
                .where(Circuit.deleted_at.is_(None))
                .where(Circuit.term_end_date.is_not(None))
                .where(Circuit.term_end_date < today)  # end date is inclusive
                .where(Circuit.status != "decom")
            )
        )
        .scalars()
        .all()
    )
    notable_status_circuits = list(
        (
            await db.execute(
                select(Circuit)
                .where(Circuit.deleted_at.is_(None))
                .where(Circuit.status.in_(_CIRCUIT_NOTABLE_STATUSES))
            )
        )
        .scalars()
        .all()
    )
    # Merge + dedupe by id.
    seen_circuit_ids: set[str] = set()
    merged_circuits: list[Circuit] = []
    for c in expiring_circuits + notable_status_circuits:
        if str(c.id) in seen_circuit_ids:
            continue
        seen_circuit_ids.add(str(c.id))
        merged_circuits.append(c)
    circuit_alerts = [
        CircuitRow(
            id=str(c.id),
            name=c.name,
            status=c.status,
            transport=c.transport_class or None,
            term_end_date=(c.term_end_date.isoformat() if c.term_end_date else None),
            customer_id=str(c.customer_id) if c.customer_id else None,
            provider_id=str(c.provider_id) if c.provider_id else None,
        )
        for c in merged_circuits[:_DETAIL_LIMIT]
    ]
    circuit_term_expiring_count = len(expiring_circuits)
    circuit_status_changed_count = len(notable_status_circuits)

    # Service-resource orphan walk — mirrors the alerts.py pattern
    # but cheaper (only joins through service rows that aren't soft-
    # deleted, only walks for the existence check, doesn't open
    # AlertEvent rows). Returns the (service, resource) pairs.
    svc_link_rows = list(
        (
            await db.execute(
                select(NetworkServiceResource, NetworkService.name)
                .join(NetworkService, NetworkServiceResource.service_id == NetworkService.id)
                .where(NetworkService.deleted_at.is_(None))
            )
        ).all()
    )
    orphan_services: list[OrphanServiceRow] = []
    seen_service_ids: set[str] = set()
    for link, service_name in svc_link_rows:
        # Only flag a service if its target row is missing — we use
        # the alert-evaluator's resolver shape but skip the per-kind
        # model lookup here (the alert evaluator owns the
        # authoritative pass and writes events). For the dashboard
        # we surface every link whose target_kind is unknown OR
        # whose parent service is missing — both are "needs
        # attention" signals. Operator triage happens on the
        # service detail page.
        from app.services.alerts import _ORPHAN_RESOURCE_MODELS  # noqa: PLC0415

        model = _ORPHAN_RESOURCE_MODELS.get(link.resource_kind)
        if model is None:
            seen_service_ids.add(str(link.service_id))
            if len(orphan_services) < _DETAIL_LIMIT:
                orphan_services.append(
                    OrphanServiceRow(
                        service_id=str(link.service_id),
                        service_name=service_name,
                        resource_kind=link.resource_kind,
                        resource_id=str(link.resource_id),
                    )
                )
            continue
        target = await db.get(model, link.resource_id)
        is_orphan = target is None or getattr(target, "deleted_at", None) is not None
        if is_orphan:
            seen_service_ids.add(str(link.service_id))
            if len(orphan_services) < _DETAIL_LIMIT:
                orphan_services.append(
                    OrphanServiceRow(
                        service_id=str(link.service_id),
                        service_name=service_name,
                        resource_kind=link.resource_kind,
                        resource_id=str(link.resource_id),
                    )
                )
    service_orphan_count = len(seen_service_ids)

    # Overlay impact — for every enabled overlay, count sites whose
    # preferred-circuit chain contains at least one circuit currently
    # in ``suspended`` / ``decom``. Surfaces overlays whose
    # convergence path is (likely) degraded without running the full
    # ``/simulate`` engine on every overlay (which can be expensive
    # at scale).
    overlay_rows = (
        (await db.execute(select(OverlayNetwork).where(OverlayNetwork.deleted_at.is_(None))))
        .scalars()
        .all()
    )
    notable_circuit_ids: set[str] = {str(c.id) for c in notable_status_circuits}
    overlay_impact: list[OverlayImpactRow] = []
    for ov in overlay_rows:
        sites = list(
            (await db.execute(select(OverlaySite).where(OverlaySite.overlay_network_id == ov.id)))
            .scalars()
            .all()
        )
        impacted_sites = 0
        for s in sites:
            chain = s.preferred_circuits if isinstance(s.preferred_circuits, list) else []
            if any(str(cid) in notable_circuit_ids for cid in chain):
                impacted_sites += 1
        if impacted_sites > 0:
            overlay_impact.append(
                OverlayImpactRow(
                    id=str(ov.id),
                    name=ov.name,
                    site_count=len(sites),
                    note=(
                        f"{impacted_sites} of {len(sites)} site(s) reference a "
                        f"suspended / decom circuit in their preferred chain"
                    ),
                )
            )
    overlay_impact = overlay_impact[:_DETAIL_LIMIT]
    overlay_impacted_count = sum(1 for _ in overlay_impact)

    summary = NetworkDashboardSummary(
        generated_at=now,
        asn_drift_count=asn_drift_count,
        rpki_expiring_count=len(expiring_rows),
        rpki_expired_count=len(expired_rows),
        rpki_total_count=rpki_total_count,
        rpki_last_checked_at=rpki_last_checked_at,
        circuit_term_expiring_count=circuit_term_expiring_count,
        circuit_status_changed_count=circuit_status_changed_count,
        service_orphan_count=service_orphan_count,
        overlay_impacted_count=overlay_impacted_count,
        asn_drift=asn_drift,
        rpki_expiring=rpki_expiring,
        circuit_alerts=circuit_alerts,
        orphan_services=orphan_services,
        overlay_impact=overlay_impact,
    )
    return _mask_unreadable_panels(summary, current_user)


def _mask_unreadable_panels(summary: NetworkDashboardSummary, user: Any) -> NetworkDashboardSummary:
    """Empty every panel ``user`` may not read (ASN + RPKI share ``manage_asns``)."""
    if not user_has_permission(user, "read", "manage_asns"):
        summary.asn_drift_count = 0
        summary.asn_drift = []
        summary.rpki_expiring_count = 0
        summary.rpki_expired_count = 0
        summary.rpki_total_count = 0
        summary.rpki_last_checked_at = None
        summary.rpki_expiring = []
    if not user_has_permission(user, "read", "circuit"):
        summary.circuit_term_expiring_count = 0
        summary.circuit_status_changed_count = 0
        summary.circuit_alerts = []
    if not user_has_permission(user, "read", "network_service"):
        summary.service_orphan_count = 0
        summary.orphan_services = []
    if not user_has_permission(user, "read", "overlay_network"):
        summary.overlay_impacted_count = 0
        summary.overlay_impact = []
    return summary

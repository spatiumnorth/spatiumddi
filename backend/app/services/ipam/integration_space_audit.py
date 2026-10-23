"""Find operator IPAM rows an integration mirror took from another space (#2577).

Before #2577, seven integration reconcilers (UniFi, Docker, Kubernetes,
Proxmox, Tailscale, NetBird, Cloud) looked up existing ``IPAddress`` rows by
bare address across EVERY IP space. An operator row at an address the
integration also saw was adopted (the integration's FK stamped, and
``user_modified_at`` set), re-parented into the integration's own space, and
could later be deleted. The reconcilers are now space-scoped
(``app.services.integration_ownership.addresses_in_space``); this module
finds the damage an earlier build left behind so an operator can repair it.

It is read-only on purpose. The row's original subnet is not recorded
anywhere — the IPAM create audit row carries the request body, and the
subnet was a path parameter — so an automatic restore would have to guess,
and a wrong guess moves a row a second time. What this reports instead is
the evidence, and where the row could plausibly go back to; the repair is a
human decision (``docs/TROUBLESHOOTING.md``, "Integration took IP addresses
from another IP space").

A row is reported when it carries an integration FK AND either:

* **outside_target_space** — its subnet is not in the space its integration
  targets. Since #2577 the next sync of that target releases such a row
  (a pure mirror row is deleted, anything else un-claimed in place), so these
  only appear between an upgrade and the target's next sync; or
* it has **operator-origin evidence** — an IPAM ``create`` audit row for its
  id (``operator_create_audit``), or it is older than the integration target
  that owns it (``created_before_target``), which an integration-created row
  cannot be — AND some subnet in ANOTHER space contains its address.

Operator origin plus an overlapping subnet elsewhere is NOT evidence of a
cross-space move on its own: an operator row adopted inside the integration's
own space looks exactly the same whenever the range also exists in another
space. ``likely_cross_space`` is therefore set only on positive evidence that
the row lived in another space:

* ``dhcp_reservation_in_other_space`` — a DHCP reservation linked to the row
  belongs to a scope whose subnet is in another space. Reservations are made
  on the operator's own scope and nothing moves them;
* ``predates_its_space_subnets`` — the row is older than every subnet of its
  current space that contains its address, while a subnet in another space
  that contains it is older than the row. A row cannot be created before the
  subnet it is created in, so it was moved, and nothing in its own space was
  there to hold it. (A subnet split in the row's own space can also produce
  this; it is evidence, not proof.)

A row with operator origin and an overlapping subnet elsewhere but neither
piece of evidence is still listed, with ``needs_review`` set: it may be a
stolen row created after the integration's setup, or an ordinary same-space
adoption. Confirm with whoever owns the address before moving anything.
``include_same_space=True`` also lists operator-origin rows with no
overlapping subnet elsewhere at all.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import String, and_, cast, exists, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.models.audit import AuditLog
from app.models.dhcp import DHCPScope, DHCPStaticAssignment
from app.models.ipam import IPAddress, IPSpace, Subnet
from app.services.integration_ownership import INTEGRATION_OWNERSHIP, ownership_target_model


def _target_models() -> dict[str, Any]:
    """Ownership FK → the target model it points at."""
    return {fk: ownership_target_model(fk) for fk in INTEGRATION_OWNERSHIP}


TARGET_MODELS: dict[str, Any] = _target_models()

EVIDENCE_OPERATOR_CREATE = "operator_create_audit"
EVIDENCE_CREATED_BEFORE_TARGET = "created_before_target"
EVIDENCE_OUTSIDE_TARGET_SPACE = "outside_target_space"
EVIDENCE_DHCP_RESERVATION_OTHER_SPACE = "dhcp_reservation_in_other_space"
EVIDENCE_PREDATES_SPACE_SUBNETS = "predates_its_space_subnets"

REVIEW_REASON = (
    "operator-origin row whose address is also inside a subnet of another space, "
    "with no evidence it was moved from there: it may be an ordinary adoption in "
    "the integration's own space. Confirm with the address's owner before moving it."
)


@dataclass
class HomeCandidate:
    """A subnet in another space that contains the row's address — where the
    row may have been taken from."""

    subnet_id: uuid.UUID
    network: str
    space_id: uuid.UUID
    space_name: str
    address_free: bool  # no row currently holds the address there


@dataclass
class SuspectRow:
    ip_address_id: uuid.UUID
    address: str
    hostname: str | None
    status: str
    integration: str
    target_id: uuid.UUID
    target_name: str
    target_space_ids: list[uuid.UUID]
    current_subnet_id: uuid.UUID
    current_subnet: str
    current_space_id: uuid.UUID
    current_space_name: str
    created_at: datetime
    user_modified_at: datetime | None
    created_by: str | None
    evidence: list[str] = field(default_factory=list)
    likely_cross_space: bool = False
    needs_review: bool = False
    review_reason: str | None = None
    home_candidates: list[HomeCandidate] = field(default_factory=list)


def _target_spaces(target: Any) -> list[uuid.UUID]:
    spaces = [target.ipam_space_id]
    public = getattr(target, "public_space_id", None)
    if public is not None and public not in spaces:
        spaces.append(public)
    return spaces


def _operator_create_audit() -> Any:
    """An IPAM ``create`` audit row for this address id. The profile-scan
    endpoint also writes ``create`` against an ip_address id (for the scan,
    not the row), so its ``profile_scan …`` display is excluded."""
    return and_(
        AuditLog.resource_type == "ip_address",
        AuditLog.resource_id == cast(IPAddress.id, String),
        AuditLog.action == "create",
        AuditLog.user_id.is_not(None),
        not_(AuditLog.resource_display.like("profile\\_scan %")),
    )


@dataclass
class AuditResult:
    rows: list[SuspectRow]
    truncated: bool


async def audit_cross_space_adoptions(
    db: AsyncSession,
    *,
    include_same_space: bool = False,
    limit: int = 500,
) -> AuditResult:
    """Integration-owned rows that look like operator rows taken from another
    IP space. Read-only; see the module docstring for the rules.

    Every rule is applied in SQL, so ``limit`` caps real findings and
    ``truncated`` is true exactly when more findings exist than were
    returned."""
    found: list[SuspectRow] = []
    truncated = False
    space_names = {sid: name for sid, name in (await db.execute(select(IPSpace.id, IPSpace.name)))}

    for fk, model in TARGET_MODELS.items():
        remaining = limit - len(found)
        fk_col = getattr(IPAddress, fk)
        public_col = getattr(model, "public_space_id", None)
        # Never NULL: a Cloud endpoint with no public space compares false on
        # that arm rather than NULL, which would hide every row in a foreign
        # space from ``not_(in_target_space)``.
        in_target_space = (
            or_(
                Subnet.space_id == model.ipam_space_id,
                and_(public_col.is_not(None), Subnet.space_id == public_col),
            )
            if public_col is not None
            else Subnet.space_id == model.ipam_space_id
        )
        outside = not_(in_target_space)
        has_audit = exists().where(_operator_create_audit())
        operator_origin = or_(has_audit, IPAddress.created_at < model.created_at)

        home = aliased(Subnet)
        overlaps_elsewhere = exists().where(
            home.network.op(">>=")(IPAddress.address), home.space_id != Subnet.space_id
        )
        older_home = exists().where(
            home.network.op(">>=")(IPAddress.address),
            home.space_id != Subnet.space_id,
            home.created_at <= IPAddress.created_at,
        )
        same = aliased(Subnet)
        older_own = exists().where(
            same.network.op(">>=")(IPAddress.address),
            same.space_id == Subnet.space_id,
            same.created_at <= IPAddress.created_at,
        )
        predates_space = and_(not_(older_own), older_home)
        scope_subnet = aliased(Subnet)
        dhcp_elsewhere = exists().where(
            or_(
                DHCPStaticAssignment.ip_address_id == IPAddress.id,
                cast(DHCPStaticAssignment.id, String) == IPAddress.static_assignment_id,
            ),
            DHCPStaticAssignment.scope_id == DHCPScope.id,
            DHCPScope.subnet_id == scope_subnet.id,
            scope_subnet.space_id != Subnet.space_id,
        )
        created_by = (
            select(AuditLog.user_display_name)
            .where(_operator_create_audit())
            .order_by(AuditLog.timestamp.asc())
            .limit(1)
            .scalar_subquery()
        )
        reported = [outside, and_(operator_origin, overlaps_elsewhere)]
        if include_same_space:
            reported.append(operator_origin)
        stmt = (
            select(
                IPAddress,
                Subnet.network,
                Subnet.space_id,
                model,
                has_audit.label("has_audit"),
                created_by.label("created_by"),
                outside.label("outside"),
                overlaps_elsewhere.label("overlaps"),
                dhcp_elsewhere.label("dhcp_elsewhere"),
                predates_space.label("predates_space"),
            )
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .join(model, fk_col == model.id)
            .where(or_(*reported))
            .order_by(IPAddress.address, IPAddress.id)
            .limit(remaining + 1)
        )
        batch = (await db.execute(stmt)).all()
        if len(batch) > remaining:
            truncated = True
            batch = batch[:remaining]

        homes = await _home_candidates(
            db, [(r[0].id, r[2]) for r in batch if r.overlaps], space_names
        )
        for (
            ip,
            network,
            space_id,
            target,
            has_audit_v,
            created_by_v,
            is_outside,
            overlaps,
            dhcp_v,
            predates_v,
        ) in batch:
            evidence: list[str] = []
            if is_outside:
                evidence.append(EVIDENCE_OUTSIDE_TARGET_SPACE)
            if has_audit_v:
                evidence.append(EVIDENCE_OPERATOR_CREATE)
            if ip.created_at < target.created_at:
                evidence.append(EVIDENCE_CREATED_BEFORE_TARGET)
            operator_origin_v = bool(has_audit_v) or ip.created_at < target.created_at
            if overlaps and dhcp_v:
                evidence.append(EVIDENCE_DHCP_RESERVATION_OTHER_SPACE)
            if overlaps and predates_v:
                evidence.append(EVIDENCE_PREDATES_SPACE_SUBNETS)
            likely = bool(overlaps) and operator_origin_v and bool(dhcp_v or predates_v)
            review = bool(overlaps) and operator_origin_v and not likely and not is_outside
            found.append(
                SuspectRow(
                    ip_address_id=ip.id,
                    address=str(ip.address),
                    hostname=ip.hostname,
                    status=ip.status,
                    integration=INTEGRATION_OWNERSHIP[fk],
                    target_id=target.id,
                    target_name=target.name,
                    target_space_ids=_target_spaces(target),
                    current_subnet_id=ip.subnet_id,
                    current_subnet=str(network),
                    current_space_id=space_id,
                    current_space_name=space_names.get(space_id, ""),
                    created_at=ip.created_at,
                    user_modified_at=ip.user_modified_at,
                    created_by=created_by_v,
                    evidence=evidence,
                    likely_cross_space=likely,
                    needs_review=review,
                    review_reason=REVIEW_REASON if review else None,
                    home_candidates=homes.get(ip.id, []),
                )
            )
        if truncated:
            break
    return AuditResult(rows=found, truncated=truncated)


async def find_cross_space_adoptions(
    db: AsyncSession,
    *,
    include_same_space: bool = False,
    limit: int = 500,
) -> list[SuspectRow]:
    """``audit_cross_space_adoptions`` without the truncation flag."""
    result = await audit_cross_space_adoptions(
        db, include_same_space=include_same_space, limit=limit
    )
    return result.rows


async def _home_candidates(
    db: AsyncSession,
    rows: list[tuple[uuid.UUID, Any]],
    space_names: dict[Any, str],
) -> dict[uuid.UUID, list[HomeCandidate]]:
    """Subnets in another space containing each row's address — one query
    for every row of a batch rather than one per row."""
    if not rows:
        return {}
    ids = [ip_id for ip_id, _ in rows]
    home = aliased(Subnet)
    current = aliased(Subnet)
    holder = aliased(IPAddress)
    occupied = exists().where(holder.subnet_id == home.id, holder.address == IPAddress.address)
    result = await db.execute(
        select(IPAddress.id, home.id, home.network, home.space_id, occupied.label("occupied"))
        .join(current, IPAddress.subnet_id == current.id)
        .join(
            home,
            and_(home.network.op(">>=")(IPAddress.address), home.space_id != current.space_id),
        )
        .where(IPAddress.id.in_(ids))
        .order_by(IPAddress.id, home.network)
    )
    out: dict[uuid.UUID, list[HomeCandidate]] = {}
    for ip_id, sid, net, space, taken in result.all():
        out.setdefault(ip_id, []).append(
            HomeCandidate(
                subnet_id=sid,
                network=str(net),
                space_id=space,
                space_name=space_names.get(space, ""),
                address_free=not taken,
            )
        )
    return out


def suspect_to_dict(row: SuspectRow) -> dict[str, Any]:
    return {
        "ip_address_id": str(row.ip_address_id),
        "address": row.address,
        "hostname": row.hostname,
        "status": row.status,
        "integration": row.integration,
        "target_id": str(row.target_id),
        "target_name": row.target_name,
        "target_space_ids": [str(s) for s in row.target_space_ids],
        "current_subnet_id": str(row.current_subnet_id),
        "current_subnet": row.current_subnet,
        "current_space_id": str(row.current_space_id),
        "current_space_name": row.current_space_name,
        "created_at": row.created_at.isoformat(),
        "user_modified_at": row.user_modified_at.isoformat() if row.user_modified_at else None,
        "created_by": row.created_by,
        "evidence": row.evidence,
        "likely_cross_space": row.likely_cross_space,
        "needs_review": row.needs_review,
        "review_reason": row.review_reason,
        "home_candidates": [
            {
                "subnet_id": str(h.subnet_id),
                "network": h.network,
                "space_id": str(h.space_id),
                "space_name": h.space_name,
                "address_free": h.address_free,
            }
            for h in row.home_candidates
        ],
    }


__all__ = [
    "EVIDENCE_CREATED_BEFORE_TARGET",
    "EVIDENCE_DHCP_RESERVATION_OTHER_SPACE",
    "EVIDENCE_PREDATES_SPACE_SUBNETS",
    "EVIDENCE_OPERATOR_CREATE",
    "EVIDENCE_OUTSIDE_TARGET_SPACE",
    "REVIEW_REASON",
    "TARGET_MODELS",
    "AuditResult",
    "HomeCandidate",
    "SuspectRow",
    "audit_cross_space_adoptions",
    "find_cross_space_adoptions",
    "suspect_to_dict",
]

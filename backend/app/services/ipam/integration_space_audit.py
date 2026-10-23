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
  targets. The fixed reconcilers never touch such a row again, so it stays
  frozen where it is until someone decides; or
* it has **operator-origin evidence** — an IPAM ``create`` audit row for its
  id (``operator_create_audit``), or it is older than the integration target
  that owns it (``created_before_target``), which an integration-created row
  cannot be — AND some subnet in ANOTHER space contains its address
  (``likely_cross_space``). Without that last condition this is an ordinary
  same-space adoption, the documented behaviour; pass
  ``include_same_space=True`` to list those too.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import String, and_, cast, exists, not_, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

import app.models  # noqa: F401  — registers every mapper TARGET_MODELS resolves
from app.models.audit import AuditLog
from app.models.base import Base
from app.models.ipam import IPAddress, IPSpace, Subnet
from app.services.integration_ownership import INTEGRATION_OWNERSHIP


def _target_models() -> dict[str, Any]:
    """Ownership FK → the target model it points at, read off the column's
    foreign key so a new integration is covered without a second list."""
    by_table = {m.class_.__tablename__: m.class_ for m in Base.registry.mappers}
    out: dict[str, Any] = {}
    for fk in INTEGRATION_OWNERSHIP:
        (ref,) = IPAddress.__table__.c[fk].foreign_keys
        out[fk] = by_table[ref.column.table.name]
    return out


TARGET_MODELS: dict[str, Any] = _target_models()

EVIDENCE_OPERATOR_CREATE = "operator_create_audit"
EVIDENCE_CREATED_BEFORE_TARGET = "created_before_target"
EVIDENCE_OUTSIDE_TARGET_SPACE = "outside_target_space"


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
    return exists().where(
        AuditLog.resource_type == "ip_address",
        AuditLog.resource_id == cast(IPAddress.id, String),
        AuditLog.action == "create",
        AuditLog.user_id.is_not(None),
        not_(AuditLog.resource_display.like("profile\\_scan %")),
    )


async def find_cross_space_adoptions(
    db: AsyncSession,
    *,
    include_same_space: bool = False,
    limit: int = 500,
) -> list[SuspectRow]:
    """Integration-owned rows that look like operator rows taken from another
    IP space. Read-only; see the module docstring for the rules."""
    found: list[SuspectRow] = []
    space_names = {sid: name for sid, name in (await db.execute(select(IPSpace.id, IPSpace.name)))}

    for fk, model in TARGET_MODELS.items():
        if len(found) >= limit:
            break
        fk_col = getattr(IPAddress, fk)
        public_col = getattr(model, "public_space_id", None)
        in_target_space = (
            or_(Subnet.space_id == model.ipam_space_id, Subnet.space_id == public_col)
            if public_col is not None
            else Subnet.space_id == model.ipam_space_id
        )
        operator_audit = _operator_create_audit()
        stmt = (
            select(
                IPAddress,
                Subnet.network,
                Subnet.space_id,
                model,
                operator_audit.label("has_create_audit"),
            )
            .join(Subnet, IPAddress.subnet_id == Subnet.id)
            .join(model, fk_col == model.id)
            .where(
                or_(
                    not_(in_target_space),
                    operator_audit,
                    IPAddress.created_at < model.created_at,
                )
            )
            .order_by(IPAddress.address)
            .limit(limit * 4)
        )
        for ip, network, space_id, target, has_audit in (await db.execute(stmt)).all():
            evidence: list[str] = []
            target_spaces = _target_spaces(target)
            outside = space_id not in target_spaces
            if outside:
                evidence.append(EVIDENCE_OUTSIDE_TARGET_SPACE)
            if has_audit:
                evidence.append(EVIDENCE_OPERATOR_CREATE)
            if ip.created_at < target.created_at:
                evidence.append(EVIDENCE_CREATED_BEFORE_TARGET)
            operator_origin = bool(has_audit) or ip.created_at < target.created_at

            homes = await _home_candidates(db, ip, space_id, space_names)
            likely = operator_origin and bool(homes)
            if not (outside or likely or (include_same_space and operator_origin)):
                continue
            found.append(
                SuspectRow(
                    ip_address_id=ip.id,
                    address=str(ip.address),
                    hostname=ip.hostname,
                    status=ip.status,
                    integration=INTEGRATION_OWNERSHIP[fk],
                    target_id=target.id,
                    target_name=target.name,
                    target_space_ids=target_spaces,
                    current_subnet_id=ip.subnet_id,
                    current_subnet=str(network),
                    current_space_id=space_id,
                    current_space_name=space_names.get(space_id, ""),
                    created_at=ip.created_at,
                    user_modified_at=ip.user_modified_at,
                    created_by=await _created_by(db, ip.id) if has_audit else None,
                    evidence=evidence,
                    likely_cross_space=likely,
                    home_candidates=homes,
                )
            )
            if len(found) >= limit:
                break
    return found


async def _home_candidates(
    db: AsyncSession, ip: IPAddress, current_space_id: Any, space_names: dict[Any, str]
) -> list[HomeCandidate]:
    addr = cast(str(ip.address), INET)
    occupied = exists().where(and_(IPAddress.subnet_id == Subnet.id, IPAddress.address == addr))
    rows = (
        await db.execute(
            select(Subnet.id, Subnet.network, Subnet.space_id, occupied.label("occupied"))
            .where(Subnet.network.op(">>=")(addr))
            .where(Subnet.space_id != current_space_id)
            .order_by(Subnet.network)
        )
    ).all()
    return [
        HomeCandidate(
            subnet_id=sid,
            network=str(net),
            space_id=space,
            space_name=space_names.get(space, ""),
            address_free=not taken,
        )
        for sid, net, space, taken in rows
    ]


async def _created_by(db: AsyncSession, ip_id: uuid.UUID) -> str | None:
    return (
        await db.execute(
            select(AuditLog.user_display_name)
            .where(
                AuditLog.resource_type == "ip_address",
                AuditLog.resource_id == str(ip_id),
                AuditLog.action == "create",
                AuditLog.user_id.is_not(None),
            )
            .order_by(AuditLog.timestamp.asc())
            .limit(1)
        )
    ).scalar_one_or_none()


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
    "EVIDENCE_OPERATOR_CREATE",
    "EVIDENCE_OUTSIDE_TARGET_SPACE",
    "TARGET_MODELS",
    "HomeCandidate",
    "SuspectRow",
    "find_cross_space_adoptions",
    "suspect_to_dict",
]

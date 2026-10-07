"""Operator-Copilot tools for E911 dispatchable location (#972).

Read-only, all gated on the ``network.e911`` feature module so they stay
in lock-step with the feature surface.

**No ``propose_*`` write tools — an explicit decision under
non-negotiable #13.** A wrong ERL binding misroutes an ambulance, which is
exactly the broad-blast-radius shape the guidance keeps off the copilot.
Creating and repointing bindings stays in the UI, where it leaves an audit
row attributable to a person.

``find_e911_location`` is default-enabled because "where is extension
4412's phone" is the demonstration this whole feature exists for. It
returns the same provenance the REST surface does — confidence, the rule
that matched, and why a more precise answer was refused — so the copilot
cannot present a degraded answer as a confident one.

One thing this module deliberately does NOT do: write an
``e911_resolution_log`` row. The log records third-party lookups against
the HTTP surface; a copilot answer is already captured in the chat
transcript and the row would attribute the query to the platform rather
than to whoever asked.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.e911 import (
    DISPATCHABLE_DETAIL_COLUMNS,
    EmergencyResponseLocation,
    ERLBinding,
)
from app.models.ipam import Subnet
from app.services.ai.tools.base import register_tool
from app.services.e911.resolver import resolve_location
from app.services.search.ranking import escape_like

_MODULE = "network.e911"


def _as_uuid(raw: str | None) -> uuid.UUID | None:
    """Parse an id the model handed us, or None.

    A raw string compared against a UUID column raises 22P02, and an
    aborted transaction inside a chat turn takes out every later tool call
    — so a malformed id narrows nothing rather than failing the turn. The
    repo-wide convention for model-supplied ids.
    """
    if not raw:
        return None
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        return None


def _address_line(erl: EmergencyResponseLocation) -> str:
    """A one-line human rendering, for a chat answer.

    Deliberately assembled here rather than stored: the columns are the
    source of truth and a cached string would drift from them. Ordered the
    way a dispatcher reads an address — the interior detail first, because
    "Room 312" is the part the caller needs.
    """
    interior = " ".join(
        part
        for part in (
            f"Bldg {erl.bld}" if erl.bld else "",
            f"Floor {erl.flr}" if erl.flr else "",
            f"Room {erl.room}" if erl.room else "",
            f"Unit {erl.unit}" if erl.unit else "",
            f"Seat {erl.seat}" if erl.seat else "",
        )
        if part
    )
    street = " ".join(
        part
        for part in (erl.hno or "", erl.prd or "", erl.rd or erl.a6 or "", erl.sts or "")
        if part
    )
    locality = ", ".join(part for part in (erl.a3 or "", erl.a1 or "", erl.pc or "") if part)
    return " — ".join(part for part in (interior, street, locality) if part)


def _erl_dict(erl: EmergencyResponseLocation) -> dict[str, Any]:
    return {
        "id": str(erl.id),
        "name": erl.name,
        "address": _address_line(erl),
        "building": erl.bld,
        "floor": erl.flr,
        "room": erl.room,
        "seat": erl.seat,
        "elins": list(erl.elins or []),
        "validation_state": erl.validation_state,
        "validated_at": erl.validated_at.isoformat() if erl.validated_at else None,
        "is_dispatchable": any(getattr(erl, c) for c in DISPATCHABLE_DETAIL_COLUMNS),
    }


class FindE911LocationArgs(BaseModel):
    ip: str | None = Field(default=None, description="The device's IP address.")
    mac: str | None = Field(default=None, description="The device's MAC, in any common separator.")
    chassis_id: str | None = Field(
        default=None,
        description="LLDP chassis-id. A Cisco phone's chassis-id is its MAC.",
    )
    port_id: str | None = Field(
        default=None, description="LLDP port-id. Only meaningful with chassis_id."
    )


@register_tool(
    name="find_e911_location",
    permission=("read", "e911_location"),
    description=(
        "Resolve a phone's dispatchable location (which building, floor and "
        "room it is in) from its IP, MAC, or LLDP chassis+port. Use this for "
        "'where is this phone', 'which room is 10.20.3.44 in', or to check "
        "what a 911 call from a device would report. Always returns WHY it "
        "believes the answer: `confidence` is `observed` when the most "
        "specific applicable rule fired, `degraded` when a more precise "
        "answer existed and was REFUSED because its switch-port evidence was "
        "stale (a stale precise location is worse than a fresh coarse one), "
        "and `none` when no location rule matched at all. Never present a "
        "`degraded` answer as confident — report the `degraded_reason`."
    ),
    args_model=FindE911LocationArgs,
    category="network",
    module=_MODULE,
    # Read-only, no secrets, no device access. Default ON because this is
    # the question the feature exists to answer.
    default_enabled=True,
)
async def find_e911_location(
    db: AsyncSession, user: User, args: FindE911LocationArgs
) -> dict[str, Any]:
    _ = user
    if not any((args.ip, args.mac, args.chassis_id)):
        return {"error": "give at least one of ip, mac, or chassis_id"}
    resolution = await resolve_location(
        db,
        ip=args.ip,
        mac=args.mac,
        chassis_id=args.chassis_id,
        port_id=args.port_id,
    )
    return {
        "identity_kind": resolution.identity_kind,
        "identity_value": resolution.identity_value,
        "found": resolution.found,
        "confidence": resolution.confidence,
        "rule_matched": resolution.rule_matched,
        "degraded_reason": resolution.degraded_reason,
        "observed_at": (resolution.observed_at.isoformat() if resolution.observed_at else None),
        "evidence_age_seconds": resolution.evidence_age_seconds,
        "erl": _erl_dict(resolution.erl) if resolution.erl else None,
        "evidence": [
            {
                "kind": e.kind,
                "observed_at": e.observed_at.isoformat() if e.observed_at else None,
                "age_seconds": e.age_seconds,
                "freshness_window_seconds": e.window_seconds,
                "stale": e.stale,
                "detail": e.detail,
            }
            for e in resolution.evidence
        ],
    }


class FindERLsArgs(BaseModel):
    q: str | None = Field(
        default=None,
        description="Substring on name, building, floor, room, street or city.",
    )
    site_id: str | None = Field(default=None, description="Restrict to one site.")
    validation_state: str | None = Field(
        default=None, description="unvalidated / validated / rejected."
    )
    dispatchable: bool | None = Field(
        default=None,
        description=(
            "True = only ERLs carrying detail beyond the street door. False = "
            "only the street-address-only ones, which is the RAY BAUM'S gap."
        ),
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_erls",
    permission=("read", "e911_location"),
    description=(
        "List Emergency Response Locations — the dispatchable locations a 911 "
        "call can report — with their civic address, ELINs, how many network "
        "bindings point at each, and whether the address has been validated "
        "by the operator's E911 provider. Use this for 'what locations do we "
        "have for Building A', 'which ERLs are unvalidated', or 'which ERLs "
        "are only a street address'. SpatiumDDI records a provider's "
        "validation verdict and never decides it, so `unvalidated` means "
        "nobody has confirmed the address rather than that it is wrong."
    ),
    args_model=FindERLsArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def find_erls(db: AsyncSession, user: User, args: FindERLsArgs) -> list[dict[str, Any]]:
    _ = user
    stmt = select(EmergencyResponseLocation)
    site_id = _as_uuid(args.site_id)
    if site_id is not None:
        stmt = stmt.where(EmergencyResponseLocation.site_id == site_id)
    if args.validation_state:
        stmt = stmt.where(EmergencyResponseLocation.validation_state == args.validation_state)
    if args.dispatchable is not None:
        detail = or_(
            *[
                getattr(EmergencyResponseLocation, c).is_not(None)
                for c in DISPATCHABLE_DETAIL_COLUMNS
            ]
        )
        stmt = stmt.where(detail if args.dispatchable else ~detail)
    if args.q:
        # escape_like — a model that echoes a user's "50%" would otherwise
        # match every row (#879).
        needle = f"%{escape_like(args.q)}%"
        stmt = stmt.where(
            or_(
                EmergencyResponseLocation.name.ilike(needle),
                EmergencyResponseLocation.bld.ilike(needle),
                EmergencyResponseLocation.flr.ilike(needle),
                EmergencyResponseLocation.room.ilike(needle),
                EmergencyResponseLocation.rd.ilike(needle),
                EmergencyResponseLocation.a3.ilike(needle),
            )
        )
    rows = list(
        (await db.execute(stmt.order_by(EmergencyResponseLocation.name).limit(args.limit)))
        .scalars()
        .all()
    )
    # One query for the counts, not one per row — the N+1 the #917 sweep
    # found in the vendor-device lookup.
    counts: dict[Any, int] = {}
    if rows:
        counts = {
            erl_id: int(n)
            for erl_id, n in (
                await db.execute(
                    select(ERLBinding.erl_id, func.count(ERLBinding.id))
                    .where(ERLBinding.erl_id.in_([r.id for r in rows]))
                    .group_by(ERLBinding.erl_id)
                )
            ).all()
        }
    return [
        {
            **_erl_dict(erl),
            "site_id": str(erl.site_id) if erl.site_id else None,
            "binding_count": counts.get(erl.id, 0),
            "is_active": erl.is_active,
        }
        for erl in rows
    ]


class CountUnboundVoiceSubnetsArgs(BaseModel):
    site_id: str | None = Field(default=None, description="Restrict to one site.")


@register_tool(
    name="count_e911_unbound_voice_subnets",
    permission=("read", "e911_location"),
    description=(
        "Count and list the voice subnets that cannot reach an Emergency "
        "Response Location by any rule — their own binding, their VLAN's, or "
        "their site's default. This is the RAY BAUM'S Act §506 gap: a 911 "
        "call from one of these carries no dispatchable location, and the "
        "duty is on the enterprise, not the carrier. Use this for 'are we "
        "E911 compliant', 'which voice networks have no location', or before "
        "an audit. Zero is the answer you want."
    ),
    args_model=CountUnboundVoiceSubnetsArgs,
    category="network",
    module=_MODULE,
    default_enabled=True,
)
async def count_e911_unbound_voice_subnets(
    db: AsyncSession, user: User, args: CountUnboundVoiceSubnetsArgs
) -> dict[str, Any]:
    _ = user
    stmt = select(Subnet).where(Subnet.subnet_role == "voice")
    site_id = _as_uuid(args.site_id)
    if site_id is not None:
        stmt = stmt.where(Subnet.site_id == site_id)
    subnets = list((await db.execute(stmt)).scalars().all())
    if not subnets:
        return {
            "voice_subnets": 0,
            "unbound": 0,
            "subnets": [],
            "note": "no subnet is tagged subnet_role='voice'",
        }

    # Every binding that could serve a voice subnet, in one query. The
    # per-subnet loop below is then pure set arithmetic — resolving each
    # subnet individually would be one query per subnet on a page an
    # operator refreshes.
    bound = (
        await db.execute(
            select(ERLBinding.subnet_id, ERLBinding.vlan_ref_id, ERLBinding.site_id)
            .join(
                EmergencyResponseLocation,
                EmergencyResponseLocation.id == ERLBinding.erl_id,
            )
            .where(
                ERLBinding.is_active.is_(True),
                EmergencyResponseLocation.is_active.is_(True),
                ERLBinding.rule_kind.in_(("subnet", "vlan", "site_default")),
            )
        )
    ).all()
    by_subnet = {r[0] for r in bound if r[0] is not None}
    by_vlan = {r[1] for r in bound if r[1] is not None}
    by_site = {r[2] for r in bound if r[2] is not None}

    unbound = [
        s
        for s in subnets
        if s.id not in by_subnet
        and (s.vlan_ref_id is None or s.vlan_ref_id not in by_vlan)
        and (s.site_id is None or s.site_id not in by_site)
    ]
    return {
        "voice_subnets": len(subnets),
        "unbound": len(unbound),
        "subnets": [
            {
                "id": str(s.id),
                "network": str(s.network),
                "name": s.name,
                "site_id": str(s.site_id) if s.site_id else None,
            }
            for s in unbound[:100]
        ],
    }

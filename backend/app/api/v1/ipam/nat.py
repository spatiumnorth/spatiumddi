"""NAT mapping CRUD.

NAT mappings are operator-curated metadata describing 1:1 NAT, PAT,
or hide-NAT bindings between internal and external IPs. SpatiumDDI
doesn't render or push the rules anywhere — the value is purely
visibility: an IP row in IPAM gets a ``nat_mapping_count`` field so
operators can see at a glance whether an address is one side of a
known mapping, with a tooltip listing the names.

Three kinds:

  * ``1to1`` — static one-to-one. Requires ``internal_ip`` AND
    ``external_ip``; forbids port ranges.
  * ``pat``  — port-based NAT. Requires ``internal_ip`` AND
    ``external_ip`` AND at least one of the port range pairs.
  * ``hide`` — many-to-one masquerade. Requires ``internal_subnet_id``
    AND ``external_ip``; forbids port ranges.

Validation is enforced at the Pydantic schema level so the API never
gets to write a half-formed row. Audit goes through the standard
``write_audit`` helper for parity with the rest of IPAM.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET

from app.api.deps import DB, CurrentUser
from app.api.pagination import MAX_PAGE
from app.api.v1.dhcp._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.ipam import IPAddress, NATMapping, Subnet

router = APIRouter(
    prefix="/nat-mappings",
    tags=["ipam"],
    dependencies=[Depends(require_resource_permission("nat_mapping"))],
)

_VALID_KINDS = frozenset({"1to1", "pat", "hide"})
_VALID_PROTOS = frozenset({"tcp", "udp", "any"})


def _validate_port(value: int | None, name: str) -> int | None:
    if value is None:
        return None
    if not (0 <= value <= 65535):
        raise ValueError(f"{name} must be in 0..65535")
    return value


class NATMappingBase(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    kind: str
    internal_ip: str | None = None
    internal_subnet_id: uuid.UUID | None = None
    internal_port_start: int | None = None
    internal_port_end: int | None = None
    external_ip: str | None = None
    external_port_start: int | None = None
    external_port_end: int | None = None
    protocol: str = "any"
    device_label: str | None = None
    description: str | None = None
    tags: list[Any] = []
    custom_fields: dict[str, Any] = {}

    @field_validator("kind")
    @classmethod
    def _kind_valid(cls, v: str) -> str:
        if v not in _VALID_KINDS:
            raise ValueError(f"kind must be one of {sorted(_VALID_KINDS)}")
        return v

    @field_validator("internal_ip", "external_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        # Validate here so a malformed literal is a 422, not an asyncpg
        # DataError → 500 when it reaches the INET column / CAST (#511).
        if v is None or not v.strip():
            return None
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"not a valid IP address: {v!r}") from None

    @field_validator("protocol")
    @classmethod
    def _proto_valid(cls, v: str) -> str:
        if v not in _VALID_PROTOS:
            raise ValueError(f"protocol must be one of {sorted(_VALID_PROTOS)}")
        return v

    @field_validator(
        "internal_port_start", "internal_port_end", "external_port_start", "external_port_end"
    )
    @classmethod
    def _port_range(cls, v: int | None) -> int | None:
        return _validate_port(v, "port")

    @model_validator(mode="after")
    def _shape(self) -> NATMappingBase:
        kind = self.kind
        ports_present = any(
            p is not None
            for p in (
                self.internal_port_start,
                self.internal_port_end,
                self.external_port_start,
                self.external_port_end,
            )
        )

        if kind == "1to1":
            if not self.internal_ip or not self.external_ip:
                raise ValueError("kind='1to1' requires internal_ip and external_ip")
            if ports_present:
                raise ValueError("kind='1to1' does not allow port ranges")
        elif kind == "pat":
            if not self.internal_ip or not self.external_ip:
                raise ValueError("kind='pat' requires internal_ip and external_ip")
            if not ports_present:
                raise ValueError("kind='pat' requires at least one port range")
        elif kind == "hide":
            if not self.internal_subnet_id or not self.external_ip:
                raise ValueError("kind='hide' requires internal_subnet_id and external_ip")
            if ports_present:
                raise ValueError("kind='hide' does not allow port ranges")

        # Range sanity — start ≤ end when both set.
        for s, e, label in (
            (self.internal_port_start, self.internal_port_end, "internal"),
            (self.external_port_start, self.external_port_end, "external"),
        ):
            if s is not None and e is not None and s > e:
                raise ValueError(f"{label}_port_start must be <= {label}_port_end")
        return self


class NATMappingCreate(NATMappingBase):
    pass


class NATMappingUpdate(BaseModel):
    """All fields optional — PATCH-style update.

    Validation of the kind-specific shape happens after the merge in the
    handler, so partial updates that toggle ``kind`` still get fully
    validated. Validating the patch alone would force callers to re-send
    every field on every change.
    """

    name: str | None = None
    kind: str | None = None
    internal_ip: str | None = None
    internal_subnet_id: uuid.UUID | None = None
    internal_port_start: int | None = None
    internal_port_end: int | None = None
    external_ip: str | None = None
    external_port_start: int | None = None
    external_port_end: int | None = None
    protocol: str | None = None
    device_label: str | None = None
    description: str | None = None
    tags: list[Any] | None = None
    custom_fields: dict[str, Any] | None = None

    @field_validator("kind")
    @classmethod
    def _kind_valid(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_KINDS:
            raise ValueError(f"kind must be one of {sorted(_VALID_KINDS)}")
        return v

    @field_validator("internal_ip", "external_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        # 422 on a malformed literal, not a DataError → 500 at the INET column (#511).
        if v is None or not v.strip():
            return None
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError(f"not a valid IP address: {v!r}") from None

    @field_validator("protocol")
    @classmethod
    def _proto_valid(cls, v: str | None) -> str | None:
        if v is not None and v not in _VALID_PROTOS:
            raise ValueError(f"protocol must be one of {sorted(_VALID_PROTOS)}")
        return v


class NATMappingResponse(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    internal_ip: str | None
    internal_ip_address_id: uuid.UUID | None
    internal_subnet_id: uuid.UUID | None
    # Display labels for the internal subnet on hide-NAT mappings — without
    # them the UI can only show the bare UUID, which is useless for operators.
    # Populated by ``_serialize_nat_*`` helpers; never read from a column.
    internal_subnet_cidr: str | None = None
    internal_subnet_name: str | None = None
    internal_port_start: int | None
    internal_port_end: int | None
    external_ip: str | None
    external_ip_address_id: uuid.UUID | None
    external_port_start: int | None
    external_port_end: int | None
    protocol: str
    device_label: str | None
    description: str | None
    tags: list[Any]
    custom_fields: dict[str, Any]
    created_at: datetime
    modified_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("internal_ip", "external_ip", mode="before")
    @classmethod
    def _coerce_inet(cls, v: Any) -> Any:
        return str(v) if v is not None else v


async def _serialize_one(db: Any, row: NATMapping) -> NATMappingResponse:
    """Serialize one mapping with the internal subnet display fields filled."""
    resp = NATMappingResponse.model_validate(row)
    if row.internal_subnet_id is not None:
        sn = await db.get(Subnet, row.internal_subnet_id)
        if sn is not None:
            resp.internal_subnet_cidr = str(sn.network)
            resp.internal_subnet_name = sn.name or None
    return resp


async def _serialize_many(db: Any, rows: list[NATMapping]) -> list[NATMappingResponse]:
    """Batch-load subnets so listing N mappings is one extra SELECT, not N."""
    sn_ids = {r.internal_subnet_id for r in rows if r.internal_subnet_id is not None}
    subnets: dict[uuid.UUID, Subnet] = {}
    if sn_ids:
        sn_rows = (await db.execute(select(Subnet).where(Subnet.id.in_(sn_ids)))).scalars().all()
        subnets = {sn.id: sn for sn in sn_rows}
    out: list[NATMappingResponse] = []
    for row in rows:
        resp = NATMappingResponse.model_validate(row)
        if row.internal_subnet_id is not None:
            sn = subnets.get(row.internal_subnet_id)
            if sn is not None:
                resp.internal_subnet_cidr = str(sn.network)
                resp.internal_subnet_name = sn.name or None
        out.append(resp)
    return out


# ── Helpers ────────────────────────────────────────────────────────────────


async def _resolve_ip_to_address_id(
    db: Any, ip_str: str | None, *, subnet_id: uuid.UUID | None = None
) -> uuid.UUID | None:
    """Look up the IPAddress row whose ``address`` matches the literal IP.

    Returns the UUID if exactly one row matches, ``None`` if the IP isn't
    tracked in IPAM. The INET ``host()`` cast on both sides handles
    netmask-suffixed forms (``10.0.0.5/32``) so an exact-match lookup
    works regardless of how the operator typed it.

    The same address can exist in several IP spaces (#2577). When
    ``subnet_id`` is given the lookup is confined to that subnet's space;
    otherwise an address found in more than one space is ambiguous and
    left unlinked (``None``) — the string stays authoritative — rather
    than attaching the mapping to whichever space's row came back first.
    """

    if not ip_str:
        return None
    try:
        stmt = (
            select(IPAddress.id, Subnet.space_id)
            .join(Subnet, Subnet.id == IPAddress.subnet_id)
            .where(func.host(IPAddress.address) == func.host(cast(ip_str, INET)))
        )
        if subnet_id is not None:
            space_subq = select(Subnet.space_id).where(Subnet.id == subnet_id).scalar_subquery()
            stmt = stmt.where(Subnet.space_id == space_subq)
        rows = (await db.execute(stmt.limit(2))).all()
    except Exception:
        # Bad IP literal — let pydantic validation surface it elsewhere.
        return None
    if len(rows) != 1:
        return None
    return rows[0][0]


async def _check_external_conflict(
    db: Any,
    *,
    kind: str,
    external_ip: str | None,
    external_port_start: int | None,
    external_port_end: int | None,
    protocol: str,
    exclude_id: uuid.UUID | None = None,
) -> NATMapping | None:
    """Detect an existing 1to1/pat mapping claiming the same external slot.

    Two ``1to1`` mappings on the same external IP collide. A ``pat``
    overlapping a ``1to1`` on the same external IP also collides — the
    1to1 owns every port. Two ``pat`` mappings collide only when their
    external port ranges overlap on the same protocol. Returns the
    conflicting row if any, else None.
    """

    if not external_ip or kind not in ("1to1", "pat"):
        return None

    base = select(NATMapping).where(
        NATMapping.external_ip == cast(external_ip, INET),
        NATMapping.kind.in_(("1to1", "pat")),
    )
    if exclude_id is not None:
        base = base.where(NATMapping.id != exclude_id)

    rows = (await db.execute(base)).scalars().all()
    for other in rows:
        # 1to1 on either side claims all ports.
        if kind == "1to1" or other.kind == "1to1":
            return other
        # Both pat — protocol must match (or one side is "any") and
        # port ranges must overlap.
        if other.protocol != "any" and protocol != "any" and other.protocol != protocol:
            continue
        a_lo = external_port_start or 0
        a_hi = external_port_end or external_port_start or 65535
        b_lo = other.external_port_start or 0
        b_hi = other.external_port_end or other.external_port_start or 65535
        if a_lo <= b_hi and b_lo <= a_hi:
            return other
    return None


class NATMappingPage(BaseModel):
    total: int
    page: int
    per_page: int
    items: list[NATMappingResponse]


@router.get("", response_model=NATMappingPage)
async def list_nat_mappings(
    db: DB,
    _: CurrentUser,
    kind: str | None = Query(None),
    internal_ip: str | None = Query(None),
    external_ip: str | None = Query(None),
    q: str | None = Query(None, description="Substring match on name / description"),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    per_page: int = Query(50, ge=1, le=500),
) -> NATMappingPage:
    base = select(NATMapping)
    if kind is not None:
        if kind not in _VALID_KINDS:
            raise HTTPException(
                status_code=422, detail=f"kind must be one of {sorted(_VALID_KINDS)}"
            )
        base = base.where(NATMapping.kind == kind)
    for _label, _val in (("internal_ip", internal_ip), ("external_ip", external_ip)):
        # Validate the filter literal — comparing the INET column against a
        # malformed string casts it and raises a DataError → 500 (#511).
        if _val is not None:
            try:
                ipaddress.ip_address(_val.strip())
            except ValueError as exc:
                raise HTTPException(
                    status_code=422, detail=f"{_label} must be a valid IP address"
                ) from exc
    if internal_ip is not None:
        base = base.where(NATMapping.internal_ip == internal_ip.strip())
    if external_ip is not None:
        base = base.where(NATMapping.external_ip == external_ip.strip())
    if q:
        like = f"%{q}%"
        base = base.where(
            cast(NATMapping.name, String).ilike(like)
            | cast(func.coalesce(NATMapping.description, ""), String).ilike(like)
        )

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        (
            await db.execute(
                base.order_by(NATMapping.name).offset((page - 1) * per_page).limit(per_page)
            )
        )
        .scalars()
        .all()
    )
    return NATMappingPage(
        total=int(total or 0),
        page=page,
        per_page=per_page,
        items=await _serialize_many(db, list(rows)),
    )


@router.post("", response_model=NATMappingResponse, status_code=status.HTTP_201_CREATED)
async def create_nat_mapping(
    body: NATMappingCreate, db: DB, user: CurrentUser
) -> NATMappingResponse:
    conflict = await _check_external_conflict(
        db,
        kind=body.kind,
        external_ip=body.external_ip,
        external_port_start=body.external_port_start,
        external_port_end=body.external_port_end,
        protocol=body.protocol,
    )
    if conflict is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"External IP {body.external_ip} already claimed by "
                f"NAT mapping {conflict.name!r} ({conflict.kind})"
            ),
        )

    row = NATMapping(**body.model_dump())
    # Auto-resolve string IPs to IPAM rows when known. Strings stay
    # authoritative; the FK is just for fast joins + cascade-on-delete.
    row.internal_ip_address_id = await _resolve_ip_to_address_id(
        db, body.internal_ip, subnet_id=body.internal_subnet_id
    )
    row.external_ip_address_id = await _resolve_ip_to_address_id(db, body.external_ip)
    db.add(row)
    await db.flush()
    write_audit(
        db,
        user=user,
        action="create",
        resource_type="nat_mapping",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value=body.model_dump(mode="json"),
    )
    await db.commit()
    await db.refresh(row)
    return await _serialize_one(db, row)


@router.get("/{mapping_id}", response_model=NATMappingResponse)
async def get_nat_mapping(mapping_id: uuid.UUID, db: DB, _: CurrentUser) -> NATMappingResponse:
    row = await db.get(NATMapping, mapping_id)
    if row is None:
        raise HTTPException(status_code=404, detail="NAT mapping not found")
    return await _serialize_one(db, row)


@router.patch("/{mapping_id}", response_model=NATMappingResponse)
async def update_nat_mapping(
    mapping_id: uuid.UUID, body: NATMappingUpdate, db: DB, user: CurrentUser
) -> NATMappingResponse:
    row = await db.get(NATMapping, mapping_id)
    if row is None:
        raise HTTPException(status_code=404, detail="NAT mapping not found")

    patch = body.model_dump(exclude_unset=True)
    if not patch:
        return await _serialize_one(db, row)

    # Build the merged-state shape and re-run kind-aware validation so a
    # partial update that toggles ``kind`` still gets the full check.
    merged = {
        "name": patch.get("name", row.name),
        "kind": patch.get("kind", row.kind),
        "internal_ip": patch.get(
            "internal_ip", str(row.internal_ip) if row.internal_ip is not None else None
        ),
        "internal_subnet_id": patch.get("internal_subnet_id", row.internal_subnet_id),
        "internal_port_start": patch.get("internal_port_start", row.internal_port_start),
        "internal_port_end": patch.get("internal_port_end", row.internal_port_end),
        "external_ip": patch.get(
            "external_ip", str(row.external_ip) if row.external_ip is not None else None
        ),
        "external_port_start": patch.get("external_port_start", row.external_port_start),
        "external_port_end": patch.get("external_port_end", row.external_port_end),
        "protocol": patch.get("protocol", row.protocol),
        "device_label": patch.get("device_label", row.device_label),
        "description": patch.get("description", row.description),
        "tags": patch.get("tags", row.tags),
        "custom_fields": patch.get("custom_fields", row.custom_fields),
    }
    try:
        NATMappingBase.model_validate(merged)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    conflict = await _check_external_conflict(
        db,
        kind=merged["kind"],
        external_ip=merged["external_ip"],
        external_port_start=merged["external_port_start"],
        external_port_end=merged["external_port_end"],
        protocol=merged["protocol"],
        exclude_id=row.id,
    )
    if conflict is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"External IP {merged['external_ip']} already claimed by "
                f"NAT mapping {conflict.name!r} ({conflict.kind})"
            ),
        )

    for key, value in patch.items():
        setattr(row, key, value)

    # Re-resolve FK if either IP changed (or was cleared).
    if "internal_ip" in patch:
        row.internal_ip_address_id = await _resolve_ip_to_address_id(
            db, patch["internal_ip"], subnet_id=row.internal_subnet_id
        )
    if "external_ip" in patch:
        row.external_ip_address_id = await _resolve_ip_to_address_id(db, patch["external_ip"])

    write_audit(
        db,
        user=user,
        action="update",
        resource_type="nat_mapping",
        resource_id=str(row.id),
        resource_display=row.name,
        changed_fields=list(patch.keys()),
        new_value=patch,
    )
    await db.commit()
    await db.refresh(row)
    return await _serialize_one(db, row)


@router.get("/by-ip/{ip_address_id}", response_model=list[NATMappingResponse])
async def list_nat_mappings_for_ip(
    ip_address_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[NATMappingResponse]:
    """Every NAT mapping that touches a given IPAM address.

    Matches on the FK first (cheap join) and falls back to the INET
    string for legacy rows that pre-date the FK or were created with
    an external_ip outside IPAM. Both internal and external sides
    counted; the IP can play either role in a NAT pair.
    """

    ip = await db.get(IPAddress, ip_address_id)
    if ip is None:
        raise HTTPException(status_code=404, detail="IP address not found")

    addr_str = str(ip.address)
    inet_lit = cast(addr_str, INET)
    rows = (
        (
            await db.execute(
                select(NATMapping)
                .where(
                    or_(
                        NATMapping.internal_ip_address_id == ip_address_id,
                        NATMapping.external_ip_address_id == ip_address_id,
                        NATMapping.internal_ip == inet_lit,
                        NATMapping.external_ip == inet_lit,
                    )
                )
                .order_by(NATMapping.name)
            )
        )
        .scalars()
        .all()
    )
    return await _serialize_many(db, list(rows))


@router.get("/by-subnet/{subnet_id}", response_model=list[NATMappingResponse])
async def list_nat_mappings_for_subnet(
    subnet_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[NATMappingResponse]:
    """Every NAT mapping that references an IP inside this subnet's CIDR.

    Combines:
      * mappings with ``internal_subnet_id == subnet_id`` (hide-NAT pinned to subnet)
      * mappings whose ``internal_ip`` is contained by the subnet's network
      * mappings whose ``external_ip`` is contained by the subnet's network
        (#2617) — the address rows' "NAT n" badge counts both sides, so the
        tab has to list both or it contradicts the badge.
    """

    subnet = await db.get(Subnet, subnet_id)
    if subnet is None:
        raise HTTPException(status_code=404, detail="Subnet not found")

    cidr_lit = cast(str(subnet.network), INET)
    rows = (
        (
            await db.execute(
                select(NATMapping)
                .where(
                    or_(
                        NATMapping.internal_subnet_id == subnet_id,
                        and_(
                            NATMapping.internal_ip.is_not(None),
                            NATMapping.internal_ip.op("<<=")(cidr_lit),
                        ),
                        and_(
                            NATMapping.external_ip.is_not(None),
                            NATMapping.external_ip.op("<<=")(cidr_lit),
                        ),
                    )
                )
                .order_by(NATMapping.name)
            )
        )
        .scalars()
        .all()
    )
    return await _serialize_many(db, list(rows))


@router.delete("/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_nat_mapping(mapping_id: uuid.UUID, db: DB, user: CurrentUser) -> None:
    row = await db.get(NATMapping, mapping_id)
    if row is None:
        raise HTTPException(status_code=404, detail="NAT mapping not found")
    write_audit(
        db,
        user=user,
        action="delete",
        resource_type="nat_mapping",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.delete(row)
    await db.commit()

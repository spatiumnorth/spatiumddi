"""Rows keyed to a subnet that a split / merge must carry or name (#3957).

Split and merge build NEW subnet rows and delete the old ones. Rows hanging
off the old subnet by ``ON DELETE CASCADE`` (address sets, the OT zone) went
with it, and the ``ON DELETE SET NULL`` links (circuit ends, NAT internal
subnet, BACnet / DICOM device subnet, overlay-site loopback, the auto reverse
zone's link) were silently cut. The address rows, DNS bindings and DHCP scope
are handled by the services themselves; everything else lives here, once, so
both services and both previews agree.

Policy:

* Address sets: kept, with their id (RBAC grants name the set by id). A split
  keeps a set whole on the child holding it; a contiguous set straddling a
  child boundary is clipped per child (the original row keeps the first
  piece), an explicit set is partitioned by child. A merge re-points every set
  to the merged subnet; two sets with one name would violate
  ``uq_address_set_subnet_name`` so that is a merge conflict.
* OT zone: a split puts the zone on every child (the original row on the
  first); a merge keeps one zone, and refuses when the sources carry zones at
  different Purdue levels.
* Links: re-pointed. A merge targets the merged subnet exactly; a split has
  only the parent's network address to go on, so they follow the first child
  and the preview says so.

Not handled (a reconciler / ingest owns them): PAN-OS and BGP looking-glass
subnet matches, which are re-derived. E911 bindings are #3899.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.address_set import AddressSet
from app.models.bacnet import BACnetDevice
from app.models.circuit import Circuit
from app.models.dicom import DICOMApplicationEntity
from app.models.dns import DNSZone
from app.models.ipam import NATMapping
from app.models.ot import OTZone
from app.models.overlay import OverlaySite

# (label, model, column) for every SET NULL link we re-point.
LINKS: tuple[tuple[str, Any, str], ...] = (
    ("circuit A-end", Circuit, "a_end_subnet_id"),
    ("circuit Z-end", Circuit, "z_end_subnet_id"),
    ("NAT mapping", NATMapping, "internal_subnet_id"),
    ("BACnet device", BACnetDevice, "subnet_id"),
    ("DICOM application entity", DICOMApplicationEntity, "subnet_id"),
    ("overlay site loopback", OverlaySite, "loopback_subnet_id"),
    ("auto reverse zone link", DNSZone, "linked_subnet_id"),
)


@dataclass
class Dependents:
    address_sets: list[AddressSet] = field(default_factory=list)
    ot_zones: list[OTZone] = field(default_factory=list)
    links: dict[str, int] = field(default_factory=dict)


async def load_dependents(db: AsyncSession, subnet_ids: list[uuid.UUID]) -> Dependents:
    out = Dependents()
    out.address_sets = list(
        (await db.execute(select(AddressSet).where(AddressSet.subnet_id.in_(subnet_ids))))
        .scalars()
        .all()
    )
    out.ot_zones = list(
        (await db.execute(select(OTZone).where(OTZone.subnet_id.in_(subnet_ids)))).scalars().all()
    )
    for label, model, col in LINKS:
        n = (
            await db.scalar(
                select(func.count()).select_from(model).where(getattr(model, col).in_(subnet_ids))
            )
        ) or 0
        if n:
            out.links[label] = out.links.get(label, 0) + int(n)
    return out


def _ip(value: Any) -> Any:
    return ipaddress.ip_address(str(value))


def _set_pieces(aset: AddressSet, child_nets: list[Any]) -> list[tuple[int, dict[str, Any]]]:
    """Per child index, the range fields of this set clipped to that child."""
    pieces: list[tuple[int, dict[str, Any]]] = []
    if aset.range_kind == "explicit":
        buckets: dict[int, list[str]] = {}
        for raw in aset.explicit_addresses or []:
            try:
                addr = _ip(raw)
            except ValueError:
                continue
            for i, net in enumerate(child_nets):
                if addr.version == net.version and addr in net:
                    buckets.setdefault(i, []).append(str(raw))
                    break
        for i in sorted(buckets):
            pieces.append((i, {"explicit_addresses": buckets[i]}))
        return pieces
    if aset.start_address is None or aset.end_address is None:
        return [(0, {})]
    start, end = _ip(aset.start_address), _ip(aset.end_address)
    for i, net in enumerate(child_nets):
        if start.version != net.version:
            continue
        lo, hi = max(start, net[0]), min(end, net[-1])
        if lo <= hi:
            pieces.append((i, {"start_address": str(lo), "end_address": str(hi)}))
    return pieces


def split_warnings(dep: Dependents, child_nets: list[Any]) -> list[str]:
    out: list[str] = []
    if dep.address_sets:
        multi = sum(1 for a in dep.address_sets if len(_set_pieces(a, child_nets)) > 1)
        msg = (
            f"{len(dep.address_sets)} address set(s) on the parent move onto the child "
            "that holds their addresses, keeping their id and access grants."
        )
        if multi:
            msg += (
                f" {multi} span more than one child and are divided: the original set "
                "keeps the first piece and each other child gets a copy of the rest."
            )
        out.append(msg)
    if dep.ot_zones:
        out.append(
            "The parent's OT zone (Purdue level and cell) is kept on the first child "
            "and copied onto every other child."
        )
    if dep.links:
        what = ", ".join(f"{n} {k}" for k, n in sorted(dep.links.items()))
        out.append(
            f"Links to the parent ({what}) are re-pointed to the first child; "
            "review them afterwards."
        )
    return out


async def carry_for_split(
    db: AsyncSession, parent_id: uuid.UUID, child_nets: list[Any], children: list[Any]
) -> None:
    dep = await load_dependents(db, [parent_id])
    for aset in dep.address_sets:
        pieces = _set_pieces(aset, child_nets)
        if not pieces:  # nothing of it falls in a child: keep it on the first
            aset.subnet_id = children[0].id
            continue
        for n, (idx, fields) in enumerate(pieces):
            if n == 0:
                aset.subnet_id = children[idx].id
                for k, v in fields.items():
                    setattr(aset, k, v)
                continue
            db.add(
                AddressSet(
                    name=aset.name,
                    description=aset.description,
                    subnet_id=children[idx].id,
                    customer_id=aset.customer_id,
                    site_id=aset.site_id,
                    range_kind=aset.range_kind,
                    start_address=fields.get("start_address"),
                    end_address=fields.get("end_address"),
                    explicit_addresses=fields.get("explicit_addresses", []),
                    tags=dict(aset.tags or {}),
                    custom_fields=dict(aset.custom_fields or {}),
                )
            )
    for zone in dep.ot_zones:
        for child in children[1:]:
            db.add(
                OTZone(
                    subnet_id=child.id,
                    purdue_level=zone.purdue_level,
                    cell_area=zone.cell_area,
                    name=zone.name,
                    description=zone.description,
                    tags=dict(zone.tags or {}),
                )
            )
        zone.subnet_id = children[0].id
    await db.flush()
    await _repoint_links(db, [parent_id], children[0].id)


async def _repoint_links(db: AsyncSession, old_ids: list[uuid.UUID], new_id: uuid.UUID) -> None:
    for _label, model, col in LINKS:
        await db.execute(
            update(model)
            .where(getattr(model, col).in_(old_ids))
            .values({col: new_id})
            .execution_options(synchronize_session=False, include_deleted=True)
        )


def merge_conflicts(dep: Dependents) -> list[tuple[str, str]]:
    """(type, detail) conflicts a merge cannot resolve on its own."""
    out: list[tuple[str, str]] = []
    names: dict[str, int] = {}
    for a in dep.address_sets:
        names[a.name] = names.get(a.name, 0) + 1
    dup = sorted(n for n, c in names.items() if c > 1)
    if dup:
        out.append(
            (
                "address_set_name_conflict",
                "Address sets with the same name exist on more than one source "
                f"subnet ({', '.join(dup)}). Rename them first.",
            )
        )
    levels = {str(z.purdue_level) for z in dep.ot_zones}
    if len(levels) > 1:
        out.append(
            (
                "ot_zone_level_conflict",
                "The source subnets have OT zones at different Purdue levels "
                f"({', '.join(sorted(levels))}); a merged subnet has one. "
                "Re-zone them to one level first.",
            )
        )
    return out


def merge_warnings(dep: Dependents) -> list[str]:
    out: list[str] = []
    if dep.address_sets:
        out.append(
            f"{len(dep.address_sets)} address set(s) on the sources move onto the "
            "merged subnet, keeping their id and access grants."
        )
    if len(dep.ot_zones) == 1:
        out.append("The OT zone (Purdue level and cell) moves onto the merged subnet.")
    elif len(dep.ot_zones) > 1:
        out.append(
            f"{len(dep.ot_zones)} OT zones at the same Purdue level are folded into "
            "one on the merged subnet (the target's, else the first); the others' "
            "name and cell are dropped."
        )
    if dep.links:
        what = ", ".join(f"{n} {k}" for k, n in sorted(dep.links.items()))
        out.append(f"Links to the sources ({what}) are re-pointed to the merged subnet.")
    return out


async def carry_for_merge(
    db: AsyncSession, source_ids: list[uuid.UUID], target_id: uuid.UUID, merged_id: uuid.UUID
) -> None:
    dep = await load_dependents(db, source_ids)
    for aset in dep.address_sets:
        aset.subnet_id = merged_id
    keep = next((z for z in dep.ot_zones if z.subnet_id == target_id), None) or (
        dep.ot_zones[0] if dep.ot_zones else None
    )
    for zone in dep.ot_zones:
        if zone is not keep:
            await db.delete(zone)
    await db.flush()
    if keep is not None:
        keep.subnet_id = merged_id
    await db.flush()
    await _repoint_links(db, source_ids, merged_id)

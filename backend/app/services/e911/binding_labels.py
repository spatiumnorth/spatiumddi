"""Human-readable target labels for ERL bindings (#4060).

A binding stores its target as a foreign key (an address row id, an
interface id, ...). The Bindings list showed that key, which tells an
operator nothing — least of all for an inactive IP pin kept after its
address was released (#4038). Resolve every target in one query per kind
so a page of bindings costs a handful of statements, not one per row.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import ERLBinding
from app.models.ipam import IPAddress, Subnet
from app.models.network import NetworkDevice, NetworkInterface
from app.models.ownership import Site
from app.models.vlans import VLAN, Router


def _subnet_label(network: object, name: str | None) -> str:
    return f"{network} ({name})" if name else str(network)


async def resolve_binding_labels(
    db: AsyncSession, rows: Iterable[ERLBinding]
) -> dict[uuid.UUID, tuple[str | None, bool]]:
    """Map binding id -> ``(label, target_missing)``.

    ``label`` is None for kinds whose raw value already reads well (MAC,
    BSSID) and when the referenced row is gone; ``target_missing`` is True
    only in the latter case, so a caller can say "deleted" instead of
    guessing.
    """
    rows = list(rows)
    out: dict[uuid.UUID, tuple[str | None, bool]] = {}

    async def _fetch(stmt, ids: set[uuid.UUID]):  # type: ignore[no-untyped-def]
        if not ids:
            return {}
        return {r[0]: r[1:] for r in (await db.execute(stmt)).all()}

    ip_ids = {r.ip_address_id for r in rows if r.ip_address_id}
    ips = await _fetch(
        select(IPAddress.id, IPAddress.address, Subnet.network)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .where(IPAddress.id.in_(ip_ids)),
        ip_ids,
    )
    sub_ids = {r.subnet_id for r in rows if r.subnet_id}
    subs = await _fetch(
        select(Subnet.id, Subnet.network, Subnet.name).where(
            Subnet.id.in_(sub_ids), Subnet.deleted_at.is_(None)
        ),
        sub_ids,
    )
    vlan_ids = {r.vlan_ref_id for r in rows if r.vlan_ref_id}
    vlans = await _fetch(
        select(VLAN.id, VLAN.vlan_id, VLAN.name, Router.name)
        .join(Router, Router.id == VLAN.router_id)
        .where(VLAN.id.in_(vlan_ids)),
        vlan_ids,
    )
    if_ids = {r.network_interface_id for r in rows if r.network_interface_id}
    ifs = await _fetch(
        select(NetworkInterface.id, NetworkInterface.name, NetworkDevice.name)
        .join(NetworkDevice, NetworkDevice.id == NetworkInterface.device_id)
        .where(NetworkInterface.id.in_(if_ids)),
        if_ids,
    )
    site_ids = {r.site_id for r in rows if r.site_id}
    sites = await _fetch(select(Site.id, Site.name).where(Site.id.in_(site_ids)), site_ids)

    for b in rows:
        label: str | None = None
        missing = False
        if b.ip_address_id:
            hit = ips.get(b.ip_address_id)
            if hit:
                label = f"{hit[0]} (subnet {hit[1]})"
            else:
                missing = True
        elif b.subnet_id:
            sub = subs.get(b.subnet_id)
            if sub:
                label = _subnet_label(sub[0], sub[1])
            else:
                missing = True
        elif b.vlan_ref_id:
            hit = vlans.get(b.vlan_ref_id)
            if hit:
                label = f"VLAN {hit[0]} {hit[1]} ({hit[2]})".replace("  ", " ")
            else:
                missing = True
        elif b.network_interface_id:
            hit = ifs.get(b.network_interface_id)
            if hit:
                label = f"{hit[1]} {hit[0]}"
            else:
                missing = True
        elif b.site_id:
            hit = sites.get(b.site_id)
            if hit:
                label = str(hit[0])
            else:
                missing = True
        out[b.id] = (label, missing)
    return out

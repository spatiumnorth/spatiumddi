"""Fleet-wide MAC → vendor rollups (issue #917).

"How many Apple devices are on my network?" is a question the copilot could
answer and the REST API could not: single-MAC lookup exists at
``POST /tools/mac-vendor`` and lease/address lists carry a per-row ``vendor``,
but the rollup itself lived only in ``count_devices_by_vendor`` /
``find_devices_by_vendor``. Over REST that meant paging the entire address
space client-side and doing the OUI join by hand.

Both the copilot tools and the new ``/ipam/reports/vendors`` routes call this
module, so the two surfaces cannot disagree about what counts as a device.

Everything degrades cleanly when ``PlatformSettings.oui_lookup_enabled`` is
off: :func:`bulk_lookup_vendors` returns ``{}``, so the rollup reports zero
matches with an unchanged shape rather than erroring.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Collection
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPScope
from app.models.ipam import IPAddress, Subnet
from app.services.ipam.host_name import current_fqdn
from app.services.oui import bulk_lookup_vendors, normalize_mac_key

VendorSource = Literal["ipam", "dhcp_active", "all"]


def _active_leases(subnet_ids: Collection[uuid.UUID] | None) -> Any:
    """Active leases, limited to leases in ``subnet_ids``' scopes when given.
    A lease with no scope cannot be placed in a subnet, so a limited caller
    does not see it."""
    stmt = select(DHCPLease).where(DHCPLease.state == "active")
    if subnet_ids is not None:
        stmt = stmt.join(DHCPScope, DHCPLease.scope_id == DHCPScope.id).where(
            DHCPScope.subnet_id.in_(list(subnet_ids))
        )
    return stmt


async def collect_mac_keys(
    db: AsyncSession, source: str, *, subnet_ids: Collection[uuid.UUID] | None = None
) -> set[str]:
    """Normalized MAC keys present in scope.

    ``ipam`` reads ``IPAddress.mac_address`` (managed + DHCP-mirrored rows),
    ``dhcp_active`` reads currently-active leases, ``all`` is the union
    deduplicated by MAC — a device with both a managed row and a live lease is
    one device. ``subnet_ids`` limits both sources to those subnets (a caller
    bound to specific subnets); ``None`` applies no limit.
    """
    out: set[str] = set()
    if source in ("ipam", "all"):
        ipam_q = select(IPAddress.mac_address).where(IPAddress.mac_address.is_not(None))
        if subnet_ids is not None:
            ipam_q = ipam_q.where(IPAddress.subnet_id.in_(list(subnet_ids)))
        rows = (await db.execute(ipam_q)).scalars().all()
        for raw in rows:
            key = normalize_mac_key(str(raw)) if raw is not None else None
            if key:
                out.add(key)
    if source in ("dhcp_active", "all"):
        rows = (
            (await db.execute(_active_leases(subnet_ids).with_only_columns(DHCPLease.mac_address)))
            .scalars()
            .all()
        )
        for raw in rows:
            key = normalize_mac_key(str(raw)) if raw is not None else None
            if key:
                out.add(key)
    return out


async def count_by_vendor(
    db: AsyncSession,
    *,
    source: str = "ipam",
    vendor_search: str | None = None,
    limit: int = 100,
    subnet_ids: Collection[uuid.UUID] | None = None,
) -> dict[str, Any]:
    """Vendor → device-count buckets, most common first.

    ``total_macs_seen`` counts every MAC in scope; ``total_with_vendor`` only
    those whose OUI resolved. The gap between them is the honest measure of
    how complete the OUI table is, and collapsing it would make a stale table
    look like an empty network.
    """
    keys = await collect_mac_keys(db, source, subnet_ids=subnet_ids)
    # bulk_lookup_vendors keys its output by the same canonical 12-char form
    # normalize_mac_key produces, so the key set is passed straight through.
    vendors_map = await bulk_lookup_vendors(db, list(keys))

    counter: Counter[str] = Counter()
    for key in keys:
        vendor = vendors_map.get(key)
        if vendor:
            counter[vendor] += 1

    # Captured BEFORE the search filter: the field is documented as "MACs
    # whose OUI resolved", and computing it afterwards silently redefined it
    # as "MACs matching your search" — so a narrow search made the OUI table
    # look empty, which is the exact confusion the field exists to prevent.
    total_with_vendor = sum(counter.values())

    if vendor_search:
        needle = vendor_search.lower()
        counter = Counter({v: c for v, c in counter.items() if needle in v.lower()})

    return {
        "source": source,
        "total_macs_seen": len(keys),
        "total_with_vendor": total_with_vendor,
        "matching_macs": sum(counter.values()),
        "distinct_vendors": len(counter),
        "vendors": [{"vendor": v, "count": c} for v, c in counter.most_common(limit)],
    }


async def find_devices(
    db: AsyncSession,
    *,
    vendor_search: str,
    source: str = "ipam",
    limit: int = 100,
    subnet_ids: Collection[uuid.UUID] | None = None,
) -> dict[str, Any]:
    """The matching devices themselves, IPAM rows first.

    IPAM rows carry hostname / subnet context an active lease does not, so
    when the same MAC appears in both the richer row wins — deduplicated by
    normalized MAC, not by row, or a device with a managed row *and* a live
    lease would be listed twice. ``subnet_ids`` limits both sources to those
    subnets, as in :func:`collect_mac_keys`.
    """
    needle = vendor_search.lower().strip()
    if not needle:
        return {
            "vendor_search": vendor_search,
            "error": "vendor_search must be a non-empty string",
            "matches": [],
        }

    matches: list[dict[str, Any]] = []
    seen_macs: set[str] = set()

    if source in ("ipam", "all"):
        # Column-select rather than whole ORM entities: this scans every
        # address row with a MAC, and hydrating full objects (each with its
        # relationship machinery) to read seven fields is the difference
        # between a list comprehension and a materialised estate. The inner
        # per-row ``db.get(Subnet, …)`` was the obvious N+1; this is the outer
        # one, and it matters more now the path is reachable over HTTP.
        device_q = select(
            IPAddress.address,
            IPAddress.mac_address,
            IPAddress.hostname,
            IPAddress.fqdn,
            IPAddress.subnet_id,
            IPAddress.status,
            IPAddress.last_seen_at,
        ).where(IPAddress.mac_address.is_not(None))
        if subnet_ids is not None:
            device_q = device_q.where(IPAddress.subnet_id.in_(list(subnet_ids)))
        ipam_rows = (await db.execute(device_q)).all()
        vendors_map = await bulk_lookup_vendors(
            db, [str(r.mac_address) if r.mac_address else None for r in ipam_rows]
        )
        # Resolve every subnet in ONE query rather than a ``db.get`` per
        # matching row. The per-row form was a real N+1 — invisible on a lab
        # estate and quadratic on a real one — and this is now reachable from
        # an HTTP route rather than only from a copilot turn.
        wanted_subnets = {
            r.subnet_id
            for r in ipam_rows
            if r.subnet_id
            and (v := vendors_map.get(normalize_mac_key(str(r.mac_address)) or ""))
            and needle in v.lower()
        }
        subnets: dict[uuid.UUID, Subnet] = {}
        if wanted_subnets:
            for sub in (
                (await db.execute(select(Subnet).where(Subnet.id.in_(wanted_subnets))))
                .scalars()
                .all()
            ):
                subnets[sub.id] = sub

        for r in ipam_rows:
            key = normalize_mac_key(str(r.mac_address)) if r.mac_address else None
            if not key or key in seen_macs:
                continue
            vendor = vendors_map.get(key)
            if not vendor or needle not in vendor.lower():
                continue
            seen_macs.add(key)
            sub = subnets.get(r.subnet_id) if r.subnet_id else None
            matches.append(
                {
                    "source": "ipam",
                    "ip_address": str(r.address),
                    "mac_address": str(r.mac_address),
                    "vendor": vendor,
                    "hostname": r.hostname,
                    "fqdn": current_fqdn(r.hostname, r.fqdn),
                    "subnet_id": str(r.subnet_id) if r.subnet_id else None,
                    "subnet_network": str(sub.network) if sub else None,
                    "subnet_name": sub.name if sub else None,
                    "status": r.status,
                    "last_seen_at": (r.last_seen_at.isoformat() if r.last_seen_at else None),
                }
            )
            if len(matches) >= limit:
                return {"vendor_search": vendor_search, "matches": matches}

    if source in ("dhcp_active", "all"):
        lease_rows = (await db.execute(_active_leases(subnet_ids))).scalars().all()
        # mypy invariance — bulk_lookup_vendors takes list[str | None], so
        # spell the element type rather than letting the comprehension lock it.
        lease_macs: list[str | None] = [str(le.mac_address) for le in lease_rows]
        vendors_map = await bulk_lookup_vendors(db, lease_macs)
        for le in lease_rows:
            key = normalize_mac_key(str(le.mac_address))
            if not key or key in seen_macs:
                continue
            vendor = vendors_map.get(key)
            if not vendor or needle not in vendor.lower():
                continue
            seen_macs.add(key)
            matches.append(
                {
                    "source": "dhcp_lease",
                    "ip_address": str(le.ip_address),
                    "mac_address": str(le.mac_address),
                    "vendor": vendor,
                    "hostname": le.hostname,
                    "fqdn": None,
                    "subnet_id": None,
                    "subnet_network": None,
                    "subnet_name": None,
                    "status": le.state,
                    "last_seen_at": (le.starts_at.isoformat() if le.starts_at else None),
                }
            )
            if len(matches) >= limit:
                break

    return {"vendor_search": vendor_search, "matches": matches}


__all__ = ["VendorSource", "collect_mac_keys", "count_by_vendor", "find_devices"]

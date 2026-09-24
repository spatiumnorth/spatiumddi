"""Shared lease row shape + enrichment, used by both the per-server and the
fleet-wide lease routes (issue #917).

Extracted rather than duplicated for a specific reason: the fleet-wide route
exists so a client does not have to fan out across every server and merge the
results itself, and a client that gets a *differently shaped* row from the two
routes has to write the merge logic anyway. Two copies of the enrichment would
also drift the moment one grows a field — which is how ``find_dhcp_leases``
(the MCP tool) ended up as the only surface that could search the fleet in the
first place.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, field_validator
from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.models.dhcp import DHCPLease
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.services.oui import bulk_lookup_vendors, is_voip_phone_vendor, normalize_mac_key


class LeaseResponse(BaseModel):
    id: uuid.UUID
    server_id: uuid.UUID
    scope_id: uuid.UUID | None
    ip_address: str
    # NULL on most DHCPv6 leases, which are identified by DUID + IAID (#1141).
    mac_address: str | None
    duid: str | None = None
    iaid: int | None = None
    hostname: str | None
    state: str
    starts_at: datetime | None
    ends_at: datetime | None
    expires_at: datetime | None
    last_seen_at: datetime
    # IEEE OUI vendor for this MAC, when the feature is enabled.
    vendor: str | None = None
    # ``True`` when the vendor matches the curated VoIP-phone list
    # (issue #112 phase 3). Drives a Phone icon in the lease table.
    is_voip_phone: bool = False
    # Fingerbank passive-fingerprinting device classification for this MAC
    # (issue #373), joined from ``dhcp_fingerprint`` when a fingerprint exists.
    # All ``None`` when fingerprinting is off / unconfigured / not-yet-looked-up.
    device_class: str | None = None
    device_name: str | None = None
    device_manufacturer: str | None = None
    fingerbank_score: int | None = None

    model_config = {"from_attributes": True}

    # asyncpg decodes INET / MACADDR columns into ipaddress.IPv4Address and
    # netaddr.EUI-like objects. Coerce to str for the wire — this hit our
    # lease list 500 when the first windows_dhcp lease landed.
    @field_validator("ip_address", "mac_address", mode="before")
    @classmethod
    def _to_str(cls, v: Any) -> Any:
        return str(v) if v is not None else v


def apply_lease_filters(
    q: Select[Any],
    *,
    search: str | None,
    state: str | None,
    device_class: str | None,
) -> Select[Any]:
    """The ``search`` / ``state`` / ``device_class`` filters, applied once.

    ``device_class`` inner-joins the fingerprint table so the page lands on
    matching rows rather than filtering after the slice.
    """
    if device_class:
        q = q.join(DHCPFingerprint, DHCPFingerprint.mac_address == DHCPLease.mac_address).where(
            DHCPFingerprint.fingerbank_device_class == device_class
        )
    if state:
        q = q.where(DHCPLease.state == state)
    if search and search.strip():
        like = f"%{search.strip()}%"
        # ip_address / mac_address are INET / MACADDR — cast to text for ilike.
        q = q.where(
            or_(
                cast(DHCPLease.ip_address, String).ilike(like),
                cast(DHCPLease.mac_address, String).ilike(like),
                DHCPLease.hostname.ilike(like),
                DHCPLease.duid.ilike(like),
            )
        )
    return q


async def enrich_leases(db: AsyncSession, rows: list[DHCPLease]) -> None:
    """Attach OUI vendor + fingerbank device fields to each lease, in place.

    Two batched queries for the whole page (one OUI bulk lookup, one
    fingerprint ``IN``) rather than per-row lookups — the same shape the IPAM
    address list uses.
    """
    vendors = await bulk_lookup_vendors(
        db, [str(lease.mac_address) if lease.mac_address else None for lease in rows]
    )
    macs = [str(lease.mac_address) for lease in rows if lease.mac_address]
    fps: dict[str, DHCPFingerprint] = {}
    if macs:
        fp_rows = (
            await db.execute(select(DHCPFingerprint).where(DHCPFingerprint.mac_address.in_(macs)))
        ).scalars()
        for fp in fp_rows:
            fps[normalize_mac_key(str(fp.mac_address))] = fp
    for lease in rows:
        key = normalize_mac_key(str(lease.mac_address)) if lease.mac_address else None
        vendor = vendors.get(key) if key else None
        lease.vendor = vendor  # type: ignore[attr-defined]
        lease.is_voip_phone = is_voip_phone_vendor(vendor)  # type: ignore[attr-defined]
        fp = fps.get(key) if key else None
        lease.device_class = fp.fingerbank_device_class if fp else None  # type: ignore[attr-defined]
        lease.device_name = fp.fingerbank_device_name if fp else None  # type: ignore[attr-defined]
        lease.device_manufacturer = (  # type: ignore[attr-defined]
            fp.fingerbank_manufacturer if fp else None
        )
        lease.fingerbank_score = fp.fingerbank_score if fp else None  # type: ignore[attr-defined]

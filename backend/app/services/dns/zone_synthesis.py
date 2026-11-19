"""Refusal for writes against an integration-synthesised zone (#2653).

Shared by the REST router (``_reject_if_synthesised_zone``) and the copilot's
DNS operations so neither path can write into a zone whose reconciler owns it.
"""

from __future__ import annotations

from typing import Any


def synthesised_zone_error(zone: Any, op: str) -> str | None:
    """Why ``zone`` cannot be ``op``ed manually, or None when it can."""
    if zone.tailscale_tenant_id is not None:
        return (
            f"Zone {zone.name!r} is synthesised by the Tailscale "
            f"integration and cannot be {op}ed manually. The reconciler "
            f"will overwrite any changes on the next sync. Unbind the "
            f"DNS group on the Tailscale tenant or delete the tenant "
            f"to release the zone."
        )
    if zone.netbird_instance_id is not None:
        return (
            f"Zone {zone.name!r} is synthesised by the NetBird "
            f"integration and cannot be {op}ed manually. The reconciler "
            f"will overwrite any changes on the next sync. Unbind the "
            f"DNS group on the NetBird instance or delete the instance "
            f"to release the zone."
        )
    return None


def unauthored_zone_error(zone: Any, op: str) -> str | None:
    """Why no record can be ``op``ed in ``zone``, or None when it can (#3838).

    Only a primary zone is one SpatiumDDI authors: a secondary's or a stub's
    data is its masters', and a forward zone is a forwarders block with no zone
    file. A record written there is stored and listed but served by nobody,
    the rule IPAM already keeps (``sync_check.ipam_authors_zone``).
    """
    zone_type = zone.zone_type or "primary"
    if zone_type == "primary":
        return None
    return (
        f"Zone {zone.name!r} is a {zone_type} zone, not one SpatiumDDI serves as "
        f"primary, so records cannot be {op}ed in it: "
        + (
            "it holds no records, queries are sent to its forwarders."
            if zone_type == "forward"
            else "its data comes from its masters, and a record written here would "
            "be served by nobody."
        )
    )

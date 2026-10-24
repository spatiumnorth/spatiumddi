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

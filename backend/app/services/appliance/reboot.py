"""Stamp a host reboot request on an appliance row.

Two callers ask for the same thing: the Fleet reboot action
(``POST /appliance/appliances/{id}/reboot``) and the rolling upgrade's
per-node chain, which reboots each node into the slot it just staged
(#1445). One helper so the two cannot drift on what "a reboot was
requested" means. The supervisor's next heartbeat delivers it; publishing
the wake after the commit is the caller's job, because only the caller
knows when its transaction commits.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.appliance import Appliance


def request_reboot(row: Appliance) -> None:
    """Mark ``row`` as having a reboot requested now."""
    row.reboot_requested = True
    row.reboot_requested_at = datetime.now(UTC)


__all__ = ["request_reboot"]

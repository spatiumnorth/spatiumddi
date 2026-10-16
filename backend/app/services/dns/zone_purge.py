"""One teardown for a soft-deleted DNS zone about to leave the database (#1830).

A zone is the one DNS object NOT retracted from agentless servers (Windows DNS,
the cloud providers, ``technitium_api``) at soft-delete time: tearing a hosted
zone down and re-creating it on restore mints a new zone id and NS set, so the
delete is deferred to the moment the row is really going away (#632). That makes
the permanent removal the *sole* retraction point, and every path that removes a
trashed zone row must go through here — otherwise the row is gone and the zone
is still served, with no DB trace left to find it by.

Callers: the 30-day ``trash_purge`` sweep and the Trash page's per-row
permanent delete (``DELETE /admin/trash/dns_zone/{id}``). ``DELETE …?permanent=true``
and the reverse-zone retirement push the same way before deleting a live zone.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, select

from app.models.dns import DNSRecord, DNSZone


async def purge_trashed_zone(db: Any, zone: DNSZone) -> None:
    """Retract ``zone`` from every agentless server, then delete its row.

    Raises (an ``HTTPException`` 409/502 from the push, or whatever the driver
    raised) WITHOUT touching the row when the provider teardown fails: a dead or
    rejecting provider must keep the zone in the trash so the operator can retry,
    never orphan it. The caller owns the commit.

    The row is removed with a Core DELETE and the FK ``ON DELETE CASCADE`` takes
    its records, so the delete is atomic with the teardown that gated it.
    """
    # A LIVE record under a trashed zone (a restore before #1957 could leave one)
    # is not served or listed anywhere, and the FK CASCADE below would destroy it
    # without a word. The default filter hides trashed records, so this only ever
    # sees live ones. Raised before any provider push, so nothing is touched.
    live = (
        await db.execute(
            select(DNSRecord.fqdn, DNSRecord.record_type)
            .where(DNSRecord.zone_id == zone.id)
            .limit(5)
        )
    ).all()
    if live:
        shown = ", ".join(f"{fqdn} {rtype}" for fqdn, rtype in live)
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot permanently delete {zone.name}: it still holds live DNS records "
                f"that are not in the Trash ({shown}). Restore the zone from the Trash "
                "first; a permanent delete never takes live rows with it."
            ),
        )
    from app.api.v1.dns.router import _push_zone_to_agentless_servers  # noqa: PLC0415
    from app.services.dns.record_ops import sweep_zone_ops  # noqa: PLC0415

    await _push_zone_to_agentless_servers(db, zone, "delete")
    # Ops queued before the soft-delete started sweeping them have no zone FK to
    # cascade through; sweep defensively so a pre-fix trash row leaves no failed
    # queue behind.
    await sweep_zone_ops(db, zone, zone.group_id)
    await db.execute(
        delete(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
    )

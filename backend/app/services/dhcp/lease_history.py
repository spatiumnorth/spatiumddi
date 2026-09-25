"""Helper for writing ``DHCPLeaseHistory`` rows.

Three callers today: the ``pull_leases`` absence-delete branch, the
``pull_leases`` MAC-supersede branch (same IP, new MAC), and the
``dhcp_lease_cleanup`` time-based expiry sweep. All three share the
same shape — copy the lease's identifying fields into a new history
row before the active row goes away.

Idempotency: each call writes one row; callers either delete the
``DHCPLease`` row in the same transaction or update it in place. A
retry of the same call would emit a duplicate history row, which is
acceptable — the table is append-only and downstream consumers
filter by ``(server_id, ip_address, expired_at)`` to dedupe if they
care. Cheaper than a uniqueness constraint that would force every
caller into ``INSERT ... ON CONFLICT`` plumbing.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPLease, DHCPLeaseHistory


def record_lease_history(
    db: AsyncSession,
    lease: DHCPLease,
    *,
    lease_state: str,
    expired_at: datetime | None = None,
    mac_override: str | None = None,
) -> DHCPLeaseHistory:
    """Stamp one ``DHCPLeaseHistory`` row from an active lease.

    ``lease_state`` is one of ``expired`` / ``released`` / ``removed`` /
    ``superseded``. ``expired_at`` defaults to now (UTC).
    ``mac_override`` lets the supersede path preserve the OLD mac on the
    history row even though the in-memory ``lease.mac_address`` has
    already been mutated to the new MAC.
    """
    if expired_at is None:
        expired_at = datetime.now(UTC)
    mac = mac_override if mac_override is not None else lease.mac_address
    row = DHCPLeaseHistory(
        server_id=lease.server_id,
        scope_id=lease.scope_id,
        ip_address=str(lease.ip_address),
        # A DHCPv6 lease usually has no MAC (#1141). ``str(None)`` would be
        # the literal "None", which is not a MACADDR and fails the insert —
        # the expiry sweep and the purge path would both 500 on a v6 lease.
        mac_address=str(mac) if mac is not None else None,
        duid=lease.duid,
        iaid=lease.iaid,
        hostname=lease.hostname,
        client_id=lease.client_id,
        started_at=lease.starts_at or lease.last_seen_at,
        expired_at=expired_at,
        lease_state=lease_state,
    )
    db.add(row)
    return row


__all__ = ["record_lease_history"]

"""Record the MACs an IP address has been given in ``ip_mac_history``."""

from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mac import canonicalize_mac


async def record_mac_history(db: AsyncSession, ip_id: uuid.UUID, mac_address: str | None) -> None:
    """Upsert ``(ip_id, mac)`` in ``ip_mac_history``, bumping ``last_seen``.

    Called from every path that gives an address a MAC (IPAM's create + update
    routes, the DHCP reservation mirror). The rule is "this IP currently has
    MAC X" → upsert with ``last_seen = now()``. A MAC change leaves the prior
    row alone with its earlier ``last_seen``, so the implicit history is the
    set of distinct rows for the IP.

    No-op when the MAC is missing or malformed: we'd rather not poison the
    history table with garbage.
    """
    if not mac_address:
        return
    try:
        canonicalize_mac(mac_address)
    except ValueError:
        return
    await db.execute(
        text("""
            INSERT INTO ip_mac_history (id, ip_address_id, mac_address, first_seen, last_seen)
            VALUES (gen_random_uuid(), :ip_id, CAST(:mac AS macaddr), now(), now())
            ON CONFLICT (ip_address_id, mac_address)
            DO UPDATE SET last_seen = now()
            """),
        {"ip_id": str(ip_id), "mac": mac_address},
    )

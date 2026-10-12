"""Which raw option-code spelling a DHCP server group's servers read (#1347).

Windows reads ``opt-NN`` and drops ``code:NN``; Kea and FortiGate read
``code:NN`` and drop ``opt-NN`` (#1296). Each driver declares its spelling
(``DHCPDriver.raw_option_spelling``); a group's spelling follows from its
members. A group with no servers yet follows Kea: a Windows scope cannot exist
without a Windows server to write it to.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import get_driver
from app.models.dhcp import DHCPScope, DHCPServer
from app.models.ipam import Subnet
from app.services.dhcp.option_validation import (
    RAW_CODES_KEA,
    RAW_CODES_NONE,
    raw_keys_dropped_by,
)


def spelling_for_drivers(drivers: Iterable[str]) -> str:
    """The raw spelling a set of drivers shares, or ``none`` if they differ."""
    spellings = {get_driver(d).raw_option_spelling for d in drivers}
    if not spellings:
        return RAW_CODES_KEA
    if len(spellings) == 1:
        return spellings.pop()
    return RAW_CODES_NONE


async def group_drivers(
    db: AsyncSession, group_id: Any, *, exclude_server_id: uuid.UUID | None = None
) -> set[str]:
    if group_id is None:
        return set()
    q = select(DHCPServer.driver).where(DHCPServer.server_group_id == group_id)
    if exclude_server_id is not None:
        q = q.where(DHCPServer.id != exclude_server_id)
    return set((await db.execute(q)).scalars().all())


async def group_raw_codes(db: AsyncSession, group_id: Any) -> str:
    """The raw option-code spelling ``group_id``'s servers read."""
    return spelling_for_drivers(await group_drivers(db, group_id))


async def scopes_losing_raw_options(
    db: AsyncSession, group_id: Any, drivers: set[str]
) -> list[tuple[str, list[str]]]:
    """Scopes in ``group_id`` holding raw-code options a group of ``drivers``
    would drop, as ``(scope label, keys)`` pairs.

    The write-time check (#1296) sees an option only when it is written, so a
    scope saved with ``code:43`` on a Kea or empty group kept it when a
    Windows server joined, and the Windows driver dropped it silently. A
    server joining a group is checked against what is already stored there.
    """
    if group_id is None:
        return []
    spelling = spelling_for_drivers(drivers)
    rows = await db.execute(
        select(DHCPScope.name, DHCPScope.options, Subnet.network)
        .join(Subnet, Subnet.id == DHCPScope.subnet_id)
        .where(DHCPScope.group_id == group_id, DHCPScope.deleted_at.is_(None))
    )
    out: list[tuple[str, list[str]]] = []
    for name, options, network in rows:
        dropped = raw_keys_dropped_by(options or {}, spelling)
        if dropped:
            out.append((f"{name} ({network})" if name else str(network), dropped))
    return out

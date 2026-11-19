"""Subnet hold overlap rule (#4492).

Shared by the subnet create / restore path (``_assert_no_overlap``) so a CIDR
claimed by an active hold cannot be allocated out from under its owner.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def assert_not_held(
    db: AsyncSession,
    space_id: uuid.UUID,
    network: str,
    exclude_hold_id: uuid.UUID | None = None,
) -> None:
    """Raise 409 if ``network`` overlaps an *active* hold in the space.

    An expired hold still blocks: it is flagged and listed, never freed by
    itself, so the operator decides (release / convert / extend).
    """
    q = (
        "SELECT network, reason FROM subnet_hold "
        "WHERE space_id = CAST(:space_id AS uuid) AND status = 'active' "
        "AND network && CAST(:network AS cidr)"
    )
    params: dict[str, str] = {"space_id": str(space_id), "network": network}
    if exclude_hold_id is not None:
        q += " AND id != CAST(:hid AS uuid)"
        params["hid"] = str(exclude_hold_id)
    row = (await db.execute(text(q), params)).first()
    if row is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Network {network} overlaps a hold on {row[0]}"
            + (f" ({row[1]})" if row[1] else "")
            + "; release or convert the hold first",
        )

"""Subnet hold overlap rule (#4492).

Shared by every path that gives a subnet a CIDR: create / restore / allocate
(``_assert_no_overlap``), resize, split and merge, so a CIDR claimed by an
active hold cannot be taken out from under its owner.
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


async def hold_conflicts(
    db: AsyncSession,
    space_id: uuid.UUID,
    network: str,
) -> list[str]:
    """Details of the active holds a subnet at ``network`` would overlap.

    The non-raising form of :func:`assert_not_held`, for the resize / split /
    merge previews, which collect every conflict instead of stopping at one.
    """
    rows = (
        await db.execute(
            text(
                "SELECT network, reason FROM subnet_hold "
                "WHERE space_id = CAST(:space_id AS uuid) AND status = 'active' "
                "AND network && CAST(:network AS cidr) ORDER BY network"
            ),
            {"space_id": str(space_id), "network": network},
        )
    ).all()
    return [
        f"New CIDR {network} overlaps a hold on {r[0]}"
        + (f" ({r[1]})" if r[1] else "")
        + "; release or convert the hold first"
        for r in rows
    ]

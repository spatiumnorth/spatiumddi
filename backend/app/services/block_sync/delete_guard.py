"""Refuse to delete a block-sync target that still enforces blocks (#2291).

Push rows are polymorphic (no FK), so a target delete would drop the record of
what was pushed while the device keeps enforcing it: PAN-OS tags are
registered with ``timeout=0``, UniFi MACs stay quarantined, Meraki clients
stay ``Blocked``. Disarming lifts them (``lift_all_for_target``, async), so
delete is refused while the target is armed, and while push rows remain (the
lift has not finished, or failed because the device was unreachable) unless
the operator explicitly forces it.
"""

from __future__ import annotations

import uuid

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.block_sync import NetworkBlockPush


async def assert_block_sync_deletable(
    db: AsyncSession,
    *,
    target_kind: str,
    target_id: uuid.UUID,
    armed: bool,
    force: bool = False,
) -> None:
    if armed:
        raise HTTPException(
            status_code=409,
            detail=(
                "Active block sync is armed on this target, so its blocks are still "
                "enforced on the device. Disarm block sync first (that lifts them), "
                "then delete."
            ),
        )
    if force:
        return
    n = (
        await db.execute(
            select(func.count())
            .select_from(NetworkBlockPush)
            .where(
                NetworkBlockPush.target_kind == target_kind,
                NetworkBlockPush.target_id == target_id,
            )
        )
    ).scalar_one()
    if n:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{n} pushed block(s) have not been lifted from the device yet (the "
                "disarm lift is pending or failed). Wait for it to finish, or retry "
                "after fixing device reachability; pass force=true to delete anyway "
                "and clean the device by hand."
            ),
        )

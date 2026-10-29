"""Required custom fields on IPAM writes (#2478).

A ``CustomFieldDefinition`` with ``is_required`` was shown with a star and
enforced nowhere. This is the one server-side check the IPAM create / update
handlers for blocks and subnets share.

The rule is deliberately narrower than "every row must hold every required
field", because turning a field Required later must not make the rows that
already exist uneditable:

* **Create** — every required field must have a value, own or inherited from
  the block / space chain above it (``effective-fields`` reads the same chain).
* **Update** — checked only when the request sends ``custom_fields`` (a PUT
  that leaves it out never touches them), and then only for a field the
  request sends or the row already held. A legacy row that never had the
  field can still be renamed, resized and re-saved untouched; it cannot be
  given the key as an empty value, and a value it holds cannot be blanked.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import CustomFieldDefinition, IPBlock


def is_empty_value(value: Any) -> bool:
    """``None`` and blank strings are empty; ``0`` and ``False`` are values."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) == 0
    return False


async def inherited_block_custom_fields(db: AsyncSession, block_id: Any | None) -> dict[str, Any]:
    """Custom fields a row under ``block_id`` inherits (nearest block wins)."""
    chain: list[IPBlock] = []
    cur = await db.get(IPBlock, block_id) if block_id else None
    seen: set[Any] = set()
    while cur is not None and cur.id not in seen:
        seen.add(cur.id)
        chain.append(cur)
        cur = await db.get(IPBlock, cur.parent_block_id) if cur.parent_block_id else None
    merged: dict[str, Any] = {}
    for blk in reversed(chain):  # root first, so nearer blocks override
        for key, value in (blk.custom_fields or {}).items():
            if not is_empty_value(value):
                merged[key] = value
    return merged


async def enforce_required_custom_fields(
    db: AsyncSession,
    resource_type: str,
    new_values: Mapping[str, Any] | None,
    *,
    inherited: Mapping[str, Any] | None = None,
    stored: Mapping[str, Any] | None = None,
    creating: bool,
) -> None:
    """Raise 422 when a required custom field of ``resource_type`` is left empty.

    ``new_values`` is what the row will hold; ``inherited`` the values from
    the ancestors above it; ``stored`` what the row holds now (updates only).
    """
    defs = (
        (
            await db.execute(
                select(CustomFieldDefinition).where(
                    CustomFieldDefinition.resource_type == resource_type,
                    CustomFieldDefinition.is_required.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    if not defs:
        return
    new_values = new_values or {}
    inherited = inherited or {}
    stored = stored or {}
    missing: list[str] = []
    for d in sorted(defs, key=lambda x: (x.display_order, x.name)):
        if not creating and d.name not in new_values and is_empty_value(stored.get(d.name)):
            continue  # an update neither sent it nor had a value to lose
        if is_empty_value(new_values.get(d.name)) and is_empty_value(inherited.get(d.name)):
            missing.append(f"{d.label} ({d.name})")
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Required custom field(s) need a value: " + ", ".join(missing),
        )


async def missing_required_custom_fields(
    db: AsyncSession,
    resource_type: str,
    new_values: Mapping[str, Any] | None,
    *,
    inherited: Mapping[str, Any] | None = None,
) -> str | None:
    """The 422 detail ``enforce_required_custom_fields`` would raise on create, or None.

    One rule, two callers: the handlers raise it, and Subnet Planner
    validation reports it as a conflict so Apply never meets it (#2986).
    """
    try:
        await enforce_required_custom_fields(
            db, resource_type, new_values, inherited=inherited, creating=True
        )
    except HTTPException as exc:
        return str(exc.detail)
    return None

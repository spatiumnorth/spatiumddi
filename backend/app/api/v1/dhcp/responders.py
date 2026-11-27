"""Rogue-DHCP observed-responder list + allowlist (issue #370).

Operator-facing read of what the agent's active DHCP probe has seen on each
group's segments, plus an acknowledge action that allowlists a responder so it
stops classifying ``rogue``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.core.permissions import require_resource_permission
from app.models.dhcp import DHCPObservedResponder, DHCPResponderAllowlist

router = APIRouter(
    tags=["dhcp"],
    dependencies=[
        Depends(require_resource_permission("dhcp_server", audit_resource_type="dhcp_responder"))
    ],
)


class ResponderResponse(BaseModel):
    id: uuid.UUID
    group_id: uuid.UUID
    server_identifier: str
    source_ip: str
    source_mac: str | None
    giaddr: str | None
    offered_ip: str | None
    classification: str
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("source_ip", "source_mac", "giaddr", "offered_ip", mode="before")
    @classmethod
    def _to_str(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class AcknowledgeRequest(BaseModel):
    note: str = ""


@router.get("/groups/{group_id}/responders", response_model=list[ResponderResponse])
async def list_responders(
    group_id: uuid.UUID, db: DB, _: CurrentUser, classification: str | None = None
) -> list[DHCPObservedResponder]:
    """List DHCP responders observed on this group's segments (#370)."""
    stmt = select(DHCPObservedResponder).where(DHCPObservedResponder.group_id == group_id)
    if classification:
        stmt = stmt.where(DHCPObservedResponder.classification == classification)
    stmt = stmt.order_by(DHCPObservedResponder.last_seen_at.desc())
    return list((await db.execute(stmt)).scalars().all())


@router.post(
    "/groups/{group_id}/responders/{responder_id}/acknowledge",
    response_model=ResponderResponse,
)
async def acknowledge_responder(
    group_id: uuid.UUID,
    responder_id: uuid.UUID,
    body: AcknowledgeRequest,
    db: DB,
    current_user: CurrentUser,
) -> DHCPObservedResponder:
    """Allowlist a responder + reclassify it ``acknowledged`` (#370).

    Adds an allowlist entry keyed on the responder's server-id + source-ip so
    future probe reports keep it acknowledged, and flips the current row so the
    rogue alert auto-resolves on the next tick.
    """
    row = await db.get(DHCPObservedResponder, responder_id)
    if row is None or row.group_id != group_id:
        raise HTTPException(status_code=404, detail="Responder not found")
    # Idempotent allowlist add (server-id + source-ip pair).
    existing = (
        await db.execute(
            select(DHCPResponderAllowlist).where(
                DHCPResponderAllowlist.group_id == group_id,
                DHCPResponderAllowlist.server_identifier == row.server_identifier,
                DHCPResponderAllowlist.source_ip == row.source_ip,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        db.add(
            DHCPResponderAllowlist(
                group_id=group_id,
                server_identifier=row.server_identifier,
                source_ip=str(row.source_ip),
                note=body.note,
                created_by_user_id=current_user.id,
            )
        )
    row.classification = "acknowledged"
    write_audit(
        db,
        user=current_user,
        action="acknowledge",
        resource_type="dhcp_responder",
        resource_id=str(row.id),
        resource_display=f"{row.source_ip} (server-id {row.server_identifier})",
        new_value={"note": body.note},
    )
    await db.commit()
    await db.refresh(row)
    return row

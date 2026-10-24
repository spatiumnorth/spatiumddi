"""Read-only report of IPAM rows an integration took from another space (#2577).

``GET /api/v1/ipam/integration-space-audit``. Superadmin only: it lists rows
across every IP space, which no scoped role can see in one view. It changes
nothing; the repair is manual and documented in ``docs/TROUBLESHOOTING.md``.
Not mounted behind ``include_token_scoped``, so a resource-bound API token is
refused here (``app.api.token_binding``) rather than shown other spaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.api.deps import DB, SuperAdmin
from app.services.ipam.integration_space_audit import audit_cross_space_adoptions

router = APIRouter(tags=["ipam"])


class HomeCandidateOut(BaseModel):
    subnet_id: uuid.UUID
    network: str
    space_id: uuid.UUID
    space_name: str
    address_free: bool


class SuspectRowOut(BaseModel):
    ip_address_id: uuid.UUID
    address: str
    hostname: str | None = None
    status: str
    integration: str
    target_id: uuid.UUID
    target_name: str
    target_space_ids: list[uuid.UUID]
    current_subnet_id: uuid.UUID
    current_subnet: str
    current_space_id: uuid.UUID
    current_space_name: str
    created_at: datetime
    user_modified_at: datetime | None = None
    created_by: str | None = None
    evidence: list[str]
    likely_cross_space: bool
    needs_review: bool = False
    review_reason: str | None = None
    home_candidates: list[HomeCandidateOut]


class IntegrationSpaceAuditOut(BaseModel):
    count: int
    truncated: bool
    rows: list[SuspectRowOut]


@router.get("/integration-space-audit", response_model=IntegrationSpaceAuditOut)
async def integration_space_audit(
    db: DB,
    _: SuperAdmin,
    include_same_space: bool = Query(
        False,
        description="Also list operator-origin rows adopted inside the integration's own "
        "space whose address exists in no other space (normal adoption, not #2577 damage).",
    ),
    limit: int = Query(500, ge=1, le=5000),
) -> IntegrationSpaceAuditOut:
    result = await audit_cross_space_adoptions(
        db, include_same_space=include_same_space, limit=limit
    )
    return IntegrationSpaceAuditOut(
        count=len(result.rows),
        truncated=result.truncated,
        rows=[SuspectRowOut.model_validate(r, from_attributes=True) for r in result.rows],
    )

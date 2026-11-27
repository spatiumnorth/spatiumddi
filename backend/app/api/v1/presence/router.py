"""``POST /presence`` — are these MACs on the network right now? (#2147).

A read: the POST only carries a list too long for a query string, so it is
marked ``@read_only_post`` and a read-scoped API token may call it. Rows are
narrowed to subnets the caller may read inside the service, so the coarse gate
admits a caller whose ``read`` grant on ``subnet`` is scoped to instances.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import DB
from app.core.permissions import require_permission_or_scoped
from app.models.auth import User
from app.services.api_token_scopes import read_only_post
from app.services.ipam.presence import PresenceRequest, PresenceResponse, presence_for

router = APIRouter(prefix="/presence", tags=["presence"])


@router.post("", response_model=PresenceResponse)
@read_only_post
async def lookup_device_presence(
    body: PresenceRequest,
    db: DB,
    user: User = Depends(require_permission_or_scoped("read", "subnet")),
) -> PresenceResponse:
    """One row per distinct requested MAC, in first-seen order. ``present`` needs
    an active unexpired lease AND activity within ``window_seconds``; a MAC the
    caller may not see reads as not present, never as an error."""
    return await presence_for(db, user, body)

"""``GET /api/v1/summary`` — one cheap snapshot for external pollers (#2143)."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import DB, CurrentUser
from app.api.token_binding import honours_token_binding
from app.services.platform_summary import PlatformSummary, build_summary

router = APIRouter()


@router.get("", response_model=PlatformSummary)
@honours_token_binding
async def get_summary(current_user: CurrentUser, db: DB) -> PlatformSummary:
    """Health, IPAM, DNS, DHCP, alert and new-device counts in one call.

    Read-only; works with a ``read``-scoped API token. Every section is gated
    on the permission its own list route needs, and one the caller may not read
    comes back ``null`` with the reason in ``withheld`` rather than failing the
    call. A token bound to specific subnets or zones has the sections it cannot
    narrow to those instances withheld as ``token_scoped``. Cached in-process
    for a few seconds, so ``generated_at`` can be a few seconds old.
    """
    return await build_summary(db, current_user)

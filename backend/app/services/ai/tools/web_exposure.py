"""Web exposure tools for the Operator Copilot (#3651).

Two read-only tools over the same data the Security tab shows a superadmin.
"Is my install on the internet?" is a question the copilot should be able to
answer, so both are default-enabled (non-negotiable #13): they expose no
secret, make no outbound call, and sit behind the default-off
``security.web_exposure`` module an operator had to turn on.

**No ``propose_*`` tool for any setting or mitigation**, deliberately. Every
tier can lock an operator out, which is the broad-blast-radius shape #13 keeps
off the copilot, and the pre-flights depend on WHICH ADDRESS the human is
sitting at, which a chat window does not know. Trusted networks, the
"intentional" acknowledgement and the mitigation switches are Settings-page
actions.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import SUPERADMIN, register_tool
from app.services.web_exposure import store
from app.services.web_exposure.config import config_from_row
from app.services.web_exposure.verdict import build_verdict


class _NoArgs(BaseModel):
    pass


class FindWebAccessSourcesArgs(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)


async def _verdict(db: AsyncSession, limit: int = 50) -> dict[str, Any]:
    row = await db.get(PlatformSettings, 1)
    cfg = config_from_row(row.web_exposure if row else None)
    data = await store.read_window(cfg.window_hours)
    return build_verdict(data, cfg, include_addresses=True, limit=limit).as_dict()


@register_tool(
    name="get_web_exposure_verdict",
    description=(
        "Is this SpatiumDDI install reachable from the internet (from outside "
        "the operator's own networks)? Returns the verdict (exposed / "
        "reached_from_outside / not_observed / unknown) WITH its evidence: how "
        "many outside networks reached the sign-in screen or api in the window, "
        "login-page loads, unauthenticated api requests, failed sign-ins, "
        "refused Host headers, first seen, and the fix for this deployment "
        "shape. 'Exposed' means reachable and probed, not breached. 'Internal' "
        "is private / CGNAT / ULA space plus the operator's trusted-networks "
        "list."
    ),
    args_model=_NoArgs,
    category="security",
    module="security.web_exposure",
    permission=SUPERADMIN,
    default_enabled=True,
)
async def get_web_exposure_verdict(db: AsyncSession, user: User, args: _NoArgs) -> dict[str, Any]:
    out = await _verdict(db)
    out.pop("buckets", None)
    return out


@register_tool(
    name="find_web_access_sources",
    description=(
        "List the outside networks (IPv4 /24, IPv6 /48) that reached this "
        "install in the evaluation window, busiest first: request counts per "
        "signal (login page, unauthenticated api, failed sign-ins, refused "
        "Host), first / last seen, sample addresses and the endpoints each "
        "asked for. Use for 'who is hitting the login page from outside?'."
    ),
    args_model=FindWebAccessSourcesArgs,
    category="security",
    module="security.web_exposure",
    permission=SUPERADMIN,
    default_enabled=True,
)
async def find_web_access_sources(
    db: AsyncSession, user: User, args: FindWebAccessSourcesArgs
) -> dict[str, Any]:
    out = await _verdict(db, limit=args.limit)
    return {
        "verdict": out["verdict"],
        "window_hours": out["window_hours"],
        "sources": out["buckets"],
    }

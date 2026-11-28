"""Router dependency that keeps the in-memory icon-default overrides fresh (#5022)."""

from __future__ import annotations

from app.api.deps import DB
from app.services import icons as icon_svc


async def fresh_icon_overrides(db: DB) -> None:
    """The response schemas resolve ``effective_icon`` synchronously from
    memory, so the operator overrides are loaded here, at most once per TTL per
    process (a dict lookup otherwise). Mounted on the IPAM and DNS routers."""
    await icon_svc.refresh_overrides(db)

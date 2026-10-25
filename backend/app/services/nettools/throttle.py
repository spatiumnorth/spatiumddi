"""Per-user rate limiting for the built-in network tools (issue #58).

The network-tools surface fires real packets (ping floods, traceroute
storms) and off-prem traffic (whois, DNS propagation against public
resolvers). A per-user token bucket caps how often a single operator can
hammer the surface — protects both the api container and the operator's
own egress reputation.

Two budgets:

* ``DEFAULT`` — the on-prem tools (ping / traceroute / mtr / dig /
  port-test / tls-cert / mac-vendor). 20 calls / 60 s.
* ``OFFPREM`` — whois + DNS propagation. Tighter (8 calls / 60 s)
  because these leave the network and hit shared public infrastructure.

Mirrors :mod:`app.core.auth_throttle`: a fixed-window counter in Redis,
**fail-open** when Redis is unreachable so a cache blip never bricks the
tools page. Returned as FastAPI dependency factories — attach one per
endpoint, and called directly by the Operator Copilot / MCP tool registry
(``ToolRegistry.call``) through :func:`consume_budget`, so both surfaces
spend one budget per user. The numbers live in
:mod:`app.services.nettools.budgets`.
"""

from __future__ import annotations

import structlog
from fastapi import Depends, HTTPException, status

from app.api.deps import CurrentUser
from app.config import settings
from app.core.auth_throttle import incr_with_window
from app.core.redis_client import make_async_redis
from app.models.auth import User
from app.services.nettools.budgets import (
    BUDGETS as _BUDGETS,
)
from app.services.nettools.budgets import (
    WINDOW_SECONDS as _WINDOW_SECONDS,
)
from app.services.nettools.budgets import (
    budget_exceeded_message,
    budget_key,
)

logger = structlog.get_logger(__name__)


async def _consume(user_id: str, bucket: str) -> bool:
    """Increment the per-user/bucket counter; return True once it exceeds
    the window budget. Fails open (False) when Redis is unavailable."""
    budget = _BUDGETS.get(bucket, _BUDGETS["default"])
    key = budget_key(bucket, user_id)
    try:
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
        try:
            count = await incr_with_window(r, key, _WINDOW_SECONDS)
            return int(count) > budget
        finally:
            await r.aclose()
    except Exception as exc:  # noqa: BLE001 — throttle must never break the tool
        logger.warning("nettools_rate_limit_redis_unavailable", error=str(exc))
        return False


async def consume_budget(user_id: str, bucket: str) -> bool:
    """Spend one call from ``user_id``'s ``bucket`` window; True once the
    window is exhausted. The non-FastAPI entry point, used by the copilot
    tool registry — it is the same counter the REST dependency spends, so
    the two surfaces share one budget, and it fails open the same way."""
    if bucket not in _BUDGETS:
        raise RuntimeError(f"consume_budget: unknown bucket {bucket!r}")
    return await _consume(user_id, bucket)


def rate_limit(bucket: str = "default"):
    """Build a FastAPI dependency enforcing the per-user token bucket for
    ``bucket``. Raises 429 with a ``Retry-After`` header when the budget
    is exceeded.

    Superadmins are NOT exempt — the limit protects the egress path, not
    a permission boundary, so an admin running a tight loop is exactly
    what we want to throttle.
    """
    if bucket not in _BUDGETS:
        raise RuntimeError(f"rate_limit: unknown bucket {bucket!r}")

    async def _dep(current_user: CurrentUser) -> User:
        if await _consume(str(current_user.id), bucket):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=budget_exceeded_message(bucket),
                headers={"Retry-After": str(_WINDOW_SECONDS)},
            )
        return current_user

    return _dep


# Pre-built dependencies for the two budgets so routes read cleanly.
RateLimitDefault = Depends(rate_limit("default"))
RateLimitOffprem = Depends(rate_limit("offprem"))


__all__ = ["RateLimitDefault", "RateLimitOffprem", "consume_budget", "rate_limit"]

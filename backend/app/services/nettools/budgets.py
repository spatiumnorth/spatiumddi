"""Per-user network-tool budgets, shared by every surface that runs a probe.

The numbers live here, apart from :mod:`app.services.nettools.throttle`,
because two callers enforce them: the ``/api/v1/tools/*`` REST routes (via
the FastAPI dependency in ``throttle``) and the Operator Copilot / MCP tool
registry (``ToolRegistry.call``). The registry is imported on a path that
must not load the FastAPI auth dependencies, so it reads the bucket names
from this module, which imports nothing.

Both surfaces count against the same Redis key per user and bucket, so a
user has one budget no matter which surface they drive the tools from.
"""

from __future__ import annotations

from typing import Final

WINDOW_SECONDS: Final[int] = 60

# Budget per fixed window, keyed by "bucket" name. The bucket lets us
# share one window across the on-prem tools while giving the off-prem
# tools their own tighter counter.
BUDGETS: Final[dict[str, int]] = {
    "default": 20,
    "offprem": 8,
}


def budget_key(bucket: str, user_id: str) -> str:
    """The Redis counter key for ``user_id``'s ``bucket`` window."""
    return f"nettools_rl:{bucket}:{user_id}"


def budget_exceeded_message(bucket: str) -> str:
    """The refusal text both surfaces return once the window is spent."""
    return (
        f"Rate limit exceeded — max {BUDGETS[bucket]} "
        f"{bucket} network-tool calls per {WINDOW_SECONDS}s. "
        "Wait a moment and retry."
    )


__all__ = ["BUDGETS", "WINDOW_SECONDS", "budget_exceeded_message", "budget_key"]

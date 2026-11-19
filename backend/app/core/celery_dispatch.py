"""Publish a Celery task without blocking the event loop.

``task.delay(...)`` opens a broker connection and writes to it
synchronously. Called inline from an ``async def`` handler it stalls the
whole loop for the length of the publish, and for a long time if the
broker is slow or unreachable. ``dispatch`` runs the same call in a worker
thread and hands back the same ``AsyncResult``.
"""

from __future__ import annotations

import asyncio
from typing import Any


async def dispatch(task: Any, /, *args: Any, **kwargs: Any) -> Any:
    """``await dispatch(task, *args, **kw)`` == ``task.delay(*args, **kw)``."""
    return await asyncio.to_thread(task.delay, *args, **kwargs)


async def dispatch_apply_async(task: Any, /, *args: Any, **kwargs: Any) -> Any:
    """``await dispatch_apply_async(task, args=[...], countdown=5)`` ==
    ``task.apply_async(args=[...], countdown=5)``."""
    return await asyncio.to_thread(task.apply_async, *args, **kwargs)

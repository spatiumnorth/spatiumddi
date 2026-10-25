"""Shared policy for riding out a transient kubeapi answer (#2449, #2767).

A rolling upgrade's own per-node writes retry in ``per_node`` (#2056, #2599).
The plan, the preview and the pre-flight checks read the cluster with one
request each, and the api reaches kubeapi through the ``kubernetes`` Service,
which spreads every new connection across the control-plane nodes' API servers.
While one of them restarts k3s a new connection can land on it and be refused
although the others answer. A read made here is tried again, which opens a new
connection that is spread again.

One classifier (:func:`_kubeapi_transient`) serves both paths so they cannot
disagree about which answers a retry may clear.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from typing import Any

import structlog

from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

_KUBEAPI_TRANSIENT_STATUSES = frozenset({408, 409, 429})
_KUBEAPI_STATUS_RE = re.compile(r"\bkubeapi status (\d{3})\b")

# A read on the plan path is made while an operator waits on an HTTP request, so
# its budget is seconds, not the run's five minutes.
READ_RETRY_BUDGET_S = 30.0
READ_RETRY_INTERVAL_S = 3.0


def _kubeapi_transient(error: str | None) -> bool:
    """Is a kubeapi helper's error an answer a retry might clear? Like
    ``shared_tags._transient``, but gated to a kubeapi helper's own error: the
    helpers (``k8s.py``) return one that starts ``kubeapi `` for every answer
    but a missing ServiceAccount. A missing ServiceAccount is a permanent
    misconfiguration; a status under 500 (403, 404, 422) is the server's
    considered no; a kubeapi error with no HTTP status is a socket error that
    never reached the server, so it is transient; anything that is not a kubeapi
    error at all (a crash message, a synthetic test error) is left to fail as
    before."""
    if not error or not error.startswith("kubeapi "):
        return False
    if "ServiceAccount not mounted" in error:
        return False
    match = _KUBEAPI_STATUS_RE.search(error)
    if match is None:
        return True
    status = int(match.group(1))
    return status >= 500 or status in _KUBEAPI_TRANSIENT_STATUSES


def _status_transient(status: int) -> bool:
    return status >= 500 or status in _KUBEAPI_TRANSIENT_STATUSES


async def _sleep(delay_s: float) -> None:
    await asyncio.sleep(delay_s)


def _attempt(fn: Callable[[], Any]) -> tuple[Any, k8s.KubeapiUnavailableError | None, bool]:
    """One blocking try: (result, error, transient)."""
    try:
        result = fn()
    except k8s.KubeapiUnavailableError as exc:
        return None, exc, _kubeapi_transient(str(exc))
    transient = (
        isinstance(result, tuple)
        and bool(result)
        and isinstance(result[0], int)
        and _status_transient(result[0])
    )
    return result, None, transient


def _log(what: str, attempt: int, result: Any, error: Exception | None, interval: float) -> None:
    logger.warning(
        "upgrade_kubeapi_read_transient",
        what=what,
        attempt=attempt,
        answer=str(error) if error is not None else f"status {result[0]}",
        retry_in_s=interval,
    )


async def read_with_retry(
    fn: Callable[[], Any],
    *,
    what: str,
    budget_s: float | None = None,
    interval_s: float | None = None,
) -> Any:
    """Run the blocking kubeapi read ``fn`` off the event loop, trying again on
    a transient answer for ``budget_s``.

    ``fn`` is a ``k8s`` helper call returning ``(status, ...)`` or raising
    ``KubeapiUnavailableError``. A raised error the classifier calls transient,
    or a returned status of 5xx / 408 / 409 / 429, is retried. A permanent
    answer is returned or raised at once. Once the budget is spent the last
    answer is returned, or the last error raised, unchanged, so the caller's
    own handling (and message) is the one it had before.
    """
    budget = READ_RETRY_BUDGET_S if budget_s is None else budget_s
    interval = READ_RETRY_INTERVAL_S if interval_s is None else interval_s
    started = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        result, error, transient = await asyncio.to_thread(_attempt, fn)
        if not transient or time.monotonic() - started + interval > budget:
            if error is not None:
                raise error
            return result
        _log(what, attempt, result, error, interval)
        await _sleep(interval)


def read_with_retry_blocking(
    fn: Callable[[], Any],
    *,
    what: str,
    budget_s: float,
    interval_s: float | None = None,
) -> Any:
    """:func:`read_with_retry` for a sync caller that already runs in a worker
    thread. The same policy; the wait is ``time.sleep``."""
    interval = READ_RETRY_INTERVAL_S if interval_s is None else interval_s
    started = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        result, error, transient = _attempt(fn)
        if not transient or time.monotonic() - started + interval > budget_s:
            if error is not None:
                raise error
            return result
        _log(what, attempt, result, error, interval)
        time.sleep(interval)

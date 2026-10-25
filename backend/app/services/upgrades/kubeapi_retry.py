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
import contextlib
import contextvars
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import structlog

from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

_KUBEAPI_TRANSIENT_STATUSES = frozenset({408, 409, 429})
_KUBEAPI_STATUS_RE = re.compile(r"\bkubeapi status (\d{3})\b")

# A read made outside a request deadline (a caller with no ``request_deadline``)
# keeps this per-read budget.
READ_RETRY_BUDGET_S = 30.0
READ_RETRY_INTERVAL_S = 3.0

# One plan / preview / pre-flight request reads kubeapi several times in series
# (CNPG detection, the lease, the quorum node list, the node list). They share
# ONE deadline, not a budget each, because the console's nginx answers an /api/
# request 504 after ``proxy_read_timeout 60s`` (charts/spatiumddi/templates/
# frontend-tls-config.yaml and frontend/default.conf.template): three reads at 30 s
# each, plus the socket timeout of the attempt in flight, ran past it, and an
# unreachable kubeapi surfaced as a gateway error instead of the 409. 40 s leaves
# 20 s for the rest of the request. An attempt is only STARTED while at least
# ``SOCKET_TIMEOUT_S`` remains, so the one in flight when the deadline falls can
# block for its whole socket timeout and still end inside it.
PLAN_DEADLINE_S = 40.0
# k8s._request's default socket timeout (pinned by a test).
SOCKET_TIMEOUT_S = 10.0


@dataclass
class _Deadline:
    ends_at: float
    last_error: str | None = None

    def remaining(self) -> float:
        return self.ends_at - time.monotonic()


_deadline: contextvars.ContextVar[_Deadline | None] = contextvars.ContextVar(
    "kubeapi_retry_deadline", default=None
)


@contextlib.contextmanager
def request_deadline(budget_s: float | None = None) -> Iterator[None]:
    """Give every read made inside this block (including ones run through
    ``asyncio.to_thread``, which copies the context) one shared deadline. A
    nested use joins the outer one."""
    if _deadline.get() is not None:
        yield
        return
    token = _deadline.set(
        _Deadline(time.monotonic() + (PLAN_DEADLINE_S if budget_s is None else budget_s))
    )
    try:
        yield
    finally:
        _deadline.reset(token)


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


def _gate_first_attempt() -> None:
    """A read that begins with too little of the shared deadline left, after an
    earlier read failed, does not start: it would not finish inside it. It raises
    the earlier read's own error, so the answer keeps the real message."""
    state = _deadline.get()
    if state is not None and state.last_error and state.remaining() < SOCKET_TIMEOUT_S:
        raise k8s.KubeapiUnavailableError(state.last_error)


def _may_retry(started: float, budget_s: float, interval: float) -> bool:
    state = _deadline.get()
    if state is not None:
        return state.remaining() - interval >= SOCKET_TIMEOUT_S
    return time.monotonic() - started + interval <= budget_s


def _note(result: Any, error: Exception | None) -> None:
    state = _deadline.get()
    if state is None:
        return
    if error is not None:
        state.last_error = str(error)
    elif isinstance(result, tuple) and result and isinstance(result[0], int):
        state.last_error = f"kubeapi status {result[0]}" if _status_transient(result[0]) else None


async def read_with_retry(
    fn: Callable[[], Any],
    *,
    what: str,
    budget_s: float | None = None,
    interval_s: float | None = None,
) -> Any:
    """Run the blocking kubeapi read ``fn`` off the event loop, trying again on
    a transient answer until the request's shared deadline (or, with none,
    ``budget_s``).

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
    _gate_first_attempt()
    while True:
        attempt += 1
        result, error, transient = await asyncio.to_thread(_attempt, fn)
        _note(result, error)
        if not transient or not _may_retry(started, budget, interval):
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
    thread. The same policy; the wait is ``time.sleep``. ``budget_s`` of 0
    means a single try, deadline or not."""
    interval = READ_RETRY_INTERVAL_S if interval_s is None else interval_s
    started = time.monotonic()
    attempt = 0
    if budget_s > 0:
        _gate_first_attempt()
    while True:
        attempt += 1
        result, error, transient = _attempt(fn)
        _note(result, error)
        if not transient or budget_s <= 0 or not _may_retry(started, budget_s, interval):
            if error is not None:
                raise error
            return result
        _log(what, attempt, result, error, interval)
        time.sleep(interval)

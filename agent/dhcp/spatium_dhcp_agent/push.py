"""Glue between the DHCP agent's shippers and the durable spool (#1077).

:mod:`.spool` is shared byte-for-byte with the DNS agent, so everything that
is specific to this agent's HTTP plumbing lives here instead:

* :class:`CPPoster` — the ``post(payload) -> status`` callable a
  :class:`~.spool.Shipper` needs, bound to one control-plane path and the
  agent's live token.
* :func:`drain_for` — drain a backlog for a bounded wall-clock budget, so a
  long outage replays in minutes instead of one 50-batch slice per tick
  without ever holding a shipper thread hostage.
* :func:`disabled_spool` — a spool that keeps nothing, for callers that build
  a shipper without a :class:`~.spool.SpoolManager` (unit tests, mostly).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import structlog

from .config import AgentConfig
from .spool import Shipper, Spool

log = structlog.get_logger(__name__)


def disabled_spool(stream: str) -> Spool:
    """A :class:`Spool` that never keeps anything — the pre-#1077 behaviour.

    ``enabled=False`` skips the directory creation, so the path is never
    touched.
    """
    return Spool(Path("."), stream, 0, enabled=False)


def late_bound(owner: Any, attr: str) -> Callable[[], httpx.Client]:
    """A client factory that looks ``owner.<attr>`` up on EVERY call.

    Passing ``self._client`` directly would capture the bound method at
    construction, so a test that swaps the owner's ``_client`` afterwards
    (``monkeypatch.setattr(obj, "_client", ...)``) would silently keep talking
    to the real one.
    """

    def factory() -> httpx.Client:
        return getattr(owner, attr)()

    return factory


class CPPoster:
    """POST one payload to one control-plane path; return the HTTP status.

    ``client_factory`` is resolved on every call so a test that monkeypatches
    the owning object's ``_client`` after construction still takes effect.

    **Version skew.** Several control-plane batch models are
    ``extra="forbid"``, so a control plane older than #1077 answers a
    ``batch_id`` with a 422 — which the spool classifies as a verdict on the
    body and DROPS. That would turn "agent upgraded before the control plane"
    into "every lease event lost", so a 422 that names ``batch_id`` is retried
    once without it and the key is omitted from then on. Replay is no longer
    deduplicated against such a control plane, which is exactly the
    pre-#1077 contract it was built for.
    """

    def __init__(
        self,
        cfg: AgentConfig,
        token_ref: list[str],
        path: str,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        self.cfg = cfg
        self.token_ref = token_ref
        self.path = path
        self._client_factory = client_factory or self._default_client
        self._strip_batch_id = False
        # Set from the last 2xx body: the control plane answers a replayed
        # batch_id with ``{"duplicate": true}``. Callers that count delivered
        # items read it so a replay is not counted twice.
        self.last_duplicate = False

    def _default_client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.cfg.control_plane_url,
            verify=self.cfg.httpx_verify(),
            timeout=15.0,
        )

    def _post_once(self, body: dict[str, Any]) -> httpx.Response:
        with self._client_factory() as c:
            return c.post(
                self.path,
                json=body,
                headers={"Authorization": f"Bearer {self.token_ref[0]}"},
            )

    def __call__(self, payload: dict[str, Any]) -> int:
        body = payload
        if self._strip_batch_id and "batch_id" in body:
            body = {k: v for k, v in payload.items() if k != "batch_id"}
        resp = self._post_once(body)
        status = int(resp.status_code)
        if status == 422 and "batch_id" in body and "batch_id" in _text(resp):
            log.warning("agent_push_batch_id_unsupported", path=self.path)
            self._strip_batch_id = True
            body = {k: v for k, v in payload.items() if k != "batch_id"}
            resp = self._post_once(body)
            status = int(resp.status_code)
        self.last_duplicate = False
        if 200 <= status < 300:
            try:
                data = resp.json()
            except Exception:  # noqa: BLE001 — a 204 / non-JSON body is not a duplicate
                data = None
            self.last_duplicate = isinstance(data, dict) and data.get("duplicate") is True
        return status


def _text(resp: Any) -> str:
    try:
        return str(resp.text)
    except Exception:  # noqa: BLE001 — a fake / streamed response without text
        return ""


def drain_for(shipper: Shipper, budget_seconds: float) -> bool:
    """Drain ``shipper``'s backlog until empty, stalled, or out of budget.

    Returns True when the backlog is empty. Stops as soon as one drain pass
    makes no progress: that is the control plane still refusing, and trying
    again immediately would only burn another connect timeout.
    """
    deadline = time.monotonic() + budget_seconds
    while True:
        before = len(shipper.spool)
        if before == 0:
            return True
        if shipper.drain():
            return True
        if len(shipper.spool) >= before or time.monotonic() >= deadline:
            return False


__all__ = ["CPPoster", "disabled_spool", "drain_for", "late_bound"]

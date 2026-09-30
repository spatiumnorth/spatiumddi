"""Supervisor-side md / multipath management poll thread (#999 Part B).

Part A reads storage state; this is the half that changes it. The
supervisor does NOT run ``mdadm`` itself — it is a container, and every
action here needs a root binary the container should not be executing
directly. So it drops a request file for the host-side
``spatiumddi-storage-action`` runner (fired by its ``.path`` unit) and
relays the runner's result back to the control plane.

Flow, one action at a time:

  1. Long-poll ``POST /api/v1/appliance/supervisor/storage/poll``
     (cert-authed). A queued command carries ``{request_id, tool,
     params}``, where ``params`` is the structured, server-validated
     action — never a shell string.
  2. Write ``release-state/storage/<rid>.request.json`` atomically.
  3. Wait for ``<rid>.result.json`` (bounded).
  4. POST it to ``…/storage/reply/{request_id}``.
  5. Delete both files.

Structured params all the way down: the runner re-validates every field
against its own allowlist and builds the argv itself, so no operator
string ever reaches a shell.

The wait is bounded and a timeout is REPORTED rather than left to the
operator's HTTP timeout — "the runner did not answer in 60 s" and "the
control plane could not reach this appliance" are different faults with
different fixes, and collapsing them into one spinner is how an operator
ends up power-cycling a box that was merely resyncing.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import structlog

from . import cp_tls
from .cert_auth import build_auth_headers, load_cert
from .config import SupervisorConfig
from .heartbeat import _effective_control_plane_url
from .identity import Identity, load_appliance_id

log = structlog.get_logger(__name__)

_POLL_PATH = "/api/v1/appliance/supervisor/storage/poll"
_REPLY_PATH = "/api/v1/appliance/supervisor/storage/reply"
_BACKOFF_S = 10.0
_REVOKED_BACKOFF_S = 60.0
_POLL_TIMEOUT_S = 35.0

#: How long to wait for the host runner's result before giving up. Every
#: action is a single mdadm/multipathd call that returns immediately —
#: ``--add`` starts a rebuild and returns, it does not wait for it — so
#: this is generous rather than tight.
_RESULT_TIMEOUT_S = 60.0
_RESULT_POLL_S = 0.5

_STATE_SUBDIR = "storage"


def _request_dir() -> Path:
    return Path("/var/lib/spatiumddi-host/release-state") / _STATE_SUBDIR


def storage_loop_forever(cfg: SupervisorConfig, identity: Identity) -> None:
    """Run the storage long-poll loop until the process exits."""
    # Verification comes from ``cp_tls`` like every other control-plane call
    # (#1219), not from a config field: the previous ``verify=cfg.verify_tls``
    # named one ``SupervisorConfig`` never had, raised AttributeError ABOVE the
    # loop's guard, and ended this thread at boot on every appliance (#1072).
    # #1219 — a fresh client per poll, verified against the control
    # plane's pinned certificate, so a re-pin by the heartbeat loop is
    # picked up here too. The pin is only ever taken by registration.
    while True:
        try:
            with cp_tls.client(
                cfg.state_dir,
                _effective_control_plane_url(cfg),
                first_contact=False,
                timeout=_POLL_TIMEOUT_S + 10.0,
            ) as client:
                _storage_once(cfg, identity, client)
        except Exception as exc:  # noqa: BLE001
            # Non-essential thread: never let it kill the supervisor.
            log.warning("supervisor.storage.loop_crashed", error=str(exc))
            time.sleep(_BACKOFF_S)


def _storage_once(
    cfg: SupervisorConfig, identity: Identity, client: httpx.Client
) -> None:
    appliance_id = load_appliance_id(cfg.state_dir)
    if appliance_id is None:
        time.sleep(_BACKOFF_S)
        return
    cert_pem = load_cert(cfg.state_dir)
    if cert_pem is None:
        time.sleep(_BACKOFF_S)
        return
    base_url = _effective_control_plane_url(cfg)
    if not base_url:
        time.sleep(_BACKOFF_S)
        return

    headers = build_auth_headers(
        "POST", _POLL_PATH, cert_pem, identity.private_key, appliance_id
    )
    try:
        resp = client.post(base_url.rstrip("/") + _POLL_PATH, headers=headers)
    except httpx.HTTPError as exc:
        log.warning("supervisor.storage.poll_failed", error=str(exc))
        time.sleep(_BACKOFF_S)
        return
    if resp.status_code in (403, 404):
        # 403 revoked; 404 = a control plane that predates this surface.
        time.sleep(_REVOKED_BACKOFF_S)
        return
    if resp.status_code != 200:
        log.warning(
            "supervisor.storage.poll_unexpected_status", status_code=resp.status_code
        )
        time.sleep(_BACKOFF_S)
        return
    try:
        body = resp.json()
    except ValueError:
        log.warning("supervisor.storage.poll_bad_json")
        time.sleep(_BACKOFF_S)
        return

    request_id = body.get("request_id") or ""
    if not request_id:
        return  # empty long-poll — no queued work

    params = body.get("params") or {}
    outcome = run_action(params)
    _post_reply(cfg, identity, client, appliance_id, request_id, outcome)


def run_action(params: dict[str, Any]) -> dict[str, Any]:
    """Hand one action to the host runner and wait for its result.

    Always returns the ``{"result": …}`` xor ``{"error": …}`` shape the
    reply endpoint expects — it never raises, because a crash here would
    leave the operator's request hanging until their HTTP timeout with
    nothing said about why.
    """
    action = str(params.get("action") or "")
    if not action:
        return {"error": "no action supplied"}

    req_dir = _request_dir()
    try:
        req_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # The host bind mount is missing — this is a non-appliance
        # deployment, or the supervisor is running without it.
        return {"error": f"storage actions are unavailable on this host: {exc}"}

    rid = uuid.uuid4().hex
    req_path = req_dir / f"{rid}.request.json"
    # The host runner CLAIMS the request by renaming it to
    # ``.request.running`` — that is what makes the level-triggered
    # .path unit's condition go false, so it must be cleaned up here
    # too or the directory fills with claimed stubs.
    claimed_path = req_dir / f"{rid}.request.running"
    res_path = req_dir / f"{rid}.result.json"
    tmp = req_dir / f"{rid}.request.json.new"
    try:
        tmp.write_text(json.dumps(params))
        # Atomic rename so the .path unit fires exactly once, on a file
        # that is already complete — a partial write would be parsed as a
        # malformed request and refused.
        os.replace(tmp, req_path)
    except OSError as exc:
        return {"error": f"could not queue the storage action: {exc}"}

    deadline = time.monotonic() + _RESULT_TIMEOUT_S
    try:
        while time.monotonic() < deadline:
            if res_path.exists():
                try:
                    return {"result": json.loads(res_path.read_text())}
                except (OSError, ValueError) as exc:
                    return {"error": f"unreadable result from the host runner: {exc}"}
            time.sleep(_RESULT_POLL_S)
        return {
            "error": (
                f"the host storage runner did not answer within "
                f"{int(_RESULT_TIMEOUT_S)}s. Check "
                "'journalctl -u spatiumddi-storage-action' on the node."
            )
        }
    finally:
        # Always clean up, including on the timeout path — a request file
        # left behind would be picked up and acted on by a LATER firing
        # of the .path unit, long after the operator gave up.
        for path in (req_path, claimed_path, res_path, tmp):
            try:
                path.unlink()
            except OSError:
                # Best-effort by design: most of these never existed on
                # any given call (the runner renames the request, so
                # exactly one of req/claimed is present, and a timed-out
                # action has no result). A failure to remove a file that
                # is already gone is the expected case, and the host
                # runner ignores any request that already has a result,
                # so a genuine leftover cannot be re-executed either.
                continue


def _post_reply(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
    appliance_id: str,
    request_id: str,
    outcome: dict[str, Any],
) -> None:
    from urllib.parse import quote  # noqa: PLC0415

    path = f"{_REPLY_PATH}/{quote(request_id)}"
    cert_pem = load_cert(cfg.state_dir)
    if cert_pem is None:
        return
    headers = build_auth_headers(
        "POST", path, cert_pem, identity.private_key, appliance_id
    )
    base_url = _effective_control_plane_url(cfg)
    if not base_url:
        return
    # ``request_id`` is REQUIRED by StorageReplyRequest and the endpoint
    # 422s without it — which, with the status unchecked, meant every
    # action timed out at the operator's end with nothing logged. The
    # nettool proxy has always sent it; this one did not.
    body = {"request_id": request_id, **outcome}
    try:
        resp = client.post(base_url.rstrip("/") + path, headers=headers, json=body)
    except httpx.HTTPError as exc:
        log.warning("supervisor.storage.reply_failed", error=str(exc))
        return
    # Checked, and not just logged on error: a silently-rejected reply is
    # indistinguishable from an appliance that never answered.
    if resp.status_code != 200:
        log.warning(
            "supervisor.storage.reply_rejected",
            status_code=resp.status_code,
            request_id=request_id,
        )


def start_storage_thread(
    cfg: SupervisorConfig, identity: Identity
) -> threading.Thread:
    """Spawn the storage loop as a daemon thread + return the handle."""
    thread = threading.Thread(
        target=storage_loop_forever,
        args=(cfg, identity),
        name="spatium-storage-proxy",
        daemon=True,
    )
    thread.start()
    log.info("supervisor.storage.thread_started")
    return thread


__all__ = ["run_action", "storage_loop_forever", "start_storage_thread"]

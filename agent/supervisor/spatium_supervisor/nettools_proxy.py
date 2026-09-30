"""Supervisor-side network-tool poll thread (dashboard-and-remote-nettools).

Mirror of :mod:`spatium_supervisor.k8s_proxy`, but instead of forwarding
a raw kubeapi request to ``127.0.0.1:6443`` it runs an already-validated
reachability tool against the supervisor's LOCAL vantage and posts the
structured result back.

Flow (one iteration):

  1. Long-poll ``POST /api/v1/appliance/supervisor/nettool/poll`` (cert-
     authed, same headers ``heartbeat.py`` / ``k8s_proxy.py`` build).
  2. Empty response (no queued work) → loop immediately + re-extend the
     keepalive. A queued command carries ``{request_id, tool, params}``.
  3. Run ``nettools.execute(tool, params)`` — a self-contained local
     executor that returns ``{"result": <dict>}`` or ``{"error": <str>}``.
  4. POST the structured result to
     ``POST /api/v1/appliance/supervisor/nettool/reply/{request_id}``.

Runs as a daemon thread alongside the heartbeat + k8s-proxy loops. Self-
resilient: no cert / no registration → sleep + retry; 403 → control
plane revoked us → longer backoff. Harmless + dormant when the appliance
has no nettool work queued — it just sees empty polls.

This thread is intentionally independent of the k3s runtime gate the
k8s-proxy applies: a reachability tool runs from ANY approved appliance
vantage (remote DNS / DHCP agent appliances included), not just
control-plane k3s nodes. The only prerequisites are a registered
appliance_id + an issued cert.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import httpx
import structlog

from . import cp_tls
from . import nettools
from .cert_auth import build_auth_headers, load_cert
from .config import SupervisorConfig
from .heartbeat import _effective_control_plane_url
from .identity import Identity, load_appliance_id

log = structlog.get_logger(__name__)

# Long-poll timeout. Matches the backend's pop_command(timeout=30) on
# the other side (plus headroom) so our request doesn't return BEFORE
# the backend gives up waiting for a queued command.
_POLL_TIMEOUT_S = 32.0

# Backoff after recoverable errors. The nettool thread is non-essential
# to the supervisor's primary heartbeat duty; back off gently rather
# than hammering the control plane.
_BACKOFF_S = 5.0
_REVOKED_BACKOFF_S = 30.0

_POLL_PATH = "/api/v1/appliance/supervisor/nettool/poll"


def nettool_loop_forever(cfg: SupervisorConfig, identity: Identity) -> None:
    """Run the nettool long-poll loop until the process exits.

    Called from ``__main__`` as a daemon thread so it lives alongside
    the heartbeat + k8s-proxy loops. Reads ``appliance_id`` fresh each
    iteration so a post-revoke re-pair (new appliance_id on disk) is
    picked up without restarting the supervisor.
    """
    # #1219 — a fresh client per poll, verified against the control
    # plane's pinned certificate, so a re-pin by the heartbeat loop is
    # picked up here too. The pin is only ever taken by registration.
    while True:
        try:
            with cp_tls.client(
                cfg.state_dir,
                _effective_control_plane_url(cfg),
                first_contact=False,
                timeout=_POLL_TIMEOUT_S + 5.0,
            ) as client:
                _nettool_once(cfg, identity, client)
        except Exception as exc:  # noqa: BLE001
            # Last-ditch swallow — any uncaught error must not kill
            # the thread. Log loud + back off.
            log.warning("supervisor.nettool.loop_crashed", error=str(exc))
            time.sleep(_BACKOFF_S)


def _nettool_once(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
) -> None:
    """One poll → execute → reply cycle. Returns immediately on success
    or after a backoff sleep on error."""
    appliance_id = load_appliance_id(cfg.state_dir)
    if appliance_id is None:
        # Not yet registered — heartbeat thread lands it eventually.
        time.sleep(_BACKOFF_S)
        return
    cert_pem = load_cert(cfg.state_dir)
    if cert_pem is None:
        # No cert yet (pre-approval). Can't cert-auth the poll; the
        # heartbeat loop is doing the session-token + cert exchange.
        time.sleep(_BACKOFF_S)
        return

    # Cluster members talk to the in-cluster api Service; remote agents
    # use their configured CONTROL_PLANE_URL. Empty only for a
    # non-member with no configured URL — nothing to poll.
    base_url = _effective_control_plane_url(cfg)
    if not base_url:
        time.sleep(_BACKOFF_S)
        return

    poll_url = base_url.rstrip("/") + _POLL_PATH
    headers = build_auth_headers(
        "POST", _POLL_PATH, cert_pem, identity.private_key, appliance_id
    )
    try:
        resp = client.post(poll_url, headers=headers)
    except httpx.HTTPError as exc:
        log.warning("supervisor.nettool.poll_failed", error=str(exc))
        time.sleep(_BACKOFF_S)
        return
    if resp.status_code == 403:
        log.warning("supervisor.nettool.poll_revoked")
        time.sleep(_REVOKED_BACKOFF_S)
        return
    if resp.status_code == 404:
        # Control plane doesn't ship the nettool surface (pre-feature).
        # Back off longer so an old control plane doesn't get hammered.
        time.sleep(_REVOKED_BACKOFF_S)
        return
    if resp.status_code != 200:
        log.warning(
            "supervisor.nettool.poll_unexpected_status",
            status_code=resp.status_code,
        )
        time.sleep(_BACKOFF_S)
        return

    try:
        body = resp.json()
    except ValueError:
        log.warning("supervisor.nettool.poll_bad_json")
        time.sleep(_BACKOFF_S)
        return

    request_id = body.get("request_id") or ""
    if not request_id:
        # Empty long-poll — no queued work. Loop immediately so the next
        # poll re-extends the keepalive.
        return

    tool = body.get("tool") or ""
    params = body.get("params") or {}

    # Run the tool against the local vantage. ``execute`` never raises
    # and always returns the ``{"result": ...}`` xor ``{"error": ...}``
    # shape the reply endpoint expects.
    outcome = _run_tool(tool, params)

    _post_reply(cfg, identity, client, appliance_id, request_id, tool, outcome)


def _run_tool(tool: str, params: dict[str, Any]) -> dict[str, Any]:
    """Run the async executor synchronously inside this thread.

    ``asyncio.run`` spins a fresh event loop per command. That's fine —
    commands are infrequent operator actions, not a hot path, and a
    fresh loop keeps this thread free of any shared-loop state.
    """
    try:
        return asyncio.run(nettools.execute(tool, params))
    except Exception as exc:  # noqa: BLE001 — execute shouldn't raise, but be safe
        log.warning("supervisor.nettool.run_crashed", tool=tool, error=str(exc))
        return {"error": f"{tool} failed: {exc}"}


def _post_reply(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
    appliance_id: Any,
    request_id: str,
    tool: str,
    outcome: dict[str, Any],
) -> None:
    """POST the structured result back to the reply endpoint. The body
    matches ``NetToolReplyRequest`` — ``request_id`` + ``result`` xor
    ``error``."""
    reply_path = f"/api/v1/appliance/supervisor/nettool/reply/{request_id}"
    reply_url = _effective_control_plane_url(cfg).rstrip("/") + reply_path
    reply_headers = build_auth_headers(
        "POST",
        reply_path,
        load_cert(cfg.state_dir) or "",
        identity.private_key,
        appliance_id,
    )
    reply_body = {
        "request_id": request_id,
        "result": outcome.get("result"),
        "error": outcome.get("error"),
    }
    try:
        reply_resp = client.post(reply_url, headers=reply_headers, json=reply_body)
    except httpx.HTTPError as exc:
        log.warning("supervisor.nettool.reply_failed", error=str(exc))
        return
    if reply_resp.status_code != 200:
        log.warning(
            "supervisor.nettool.reply_unexpected_status",
            status_code=reply_resp.status_code,
        )
        return
    log.info(
        "supervisor.nettool.replied",
        request_id=request_id,
        tool=tool,
        has_error=outcome.get("error") is not None,
    )


def start_nettool_thread(cfg: SupervisorConfig, identity: Identity) -> threading.Thread:
    """Spawn the nettool loop as a daemon thread + return the handle.
    Daemon=True so a process exit doesn't hang waiting on the thread."""
    thread = threading.Thread(
        target=nettool_loop_forever,
        args=(cfg, identity),
        name="spatium-nettool-proxy",
        daemon=True,
    )
    thread.start()
    log.info("supervisor.nettool.thread_started")
    return thread


__all__ = ["nettool_loop_forever", "start_nettool_thread"]

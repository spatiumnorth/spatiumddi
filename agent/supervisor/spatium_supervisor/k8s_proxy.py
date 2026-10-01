"""Supervisor-side kubeapi proxy thread (#183 Phase 4).

Bridges control plane → local kubeapi. The control plane enqueues
operator-action requests (rollout-restart, kubectl-logs, etc) bound
for this appliance; this thread long-polls
``/supervisor/k8s-proxy/poll``, executes against the local kubeapi
via ``k8s_api._request``, and POSTs the response back via
``/supervisor/k8s-proxy/reply/{request_id}``.

Runs as a daemon thread alongside the heartbeat loop. The thread
exits when the process exits — no clean shutdown handshake; the
control plane's queue tolerates supervisors that vanish mid-poll
(operator request times out + retries).

Cert auth: every poll + reply is signed with the supervisor's mTLS
keypair (same headers ``heartbeat.py`` builds for the heartbeat
endpoint). The control plane's
``_require_cert_auth`` validates the cert chain + signature + ts
+ that the appliance row is approved.

Failure handling:
  * Transient network errors → log + sleep 5 s + retry. The poll
    loop keeps the supervisor running even if the control plane is
    briefly unreachable.
  * 403 → control plane revoked us. Sleep 30 s + retry. The
    heartbeat loop's revocation handler will tear down service
    containers separately; the proxy thread just stays idle.
  * Local kubeapi unreachable → reply 502 to the control plane
    with a placeholder body. The operator sees the kubeapi error
    propagated up.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import ssl
import threading
import time

import httpx
import structlog

from . import cp_tls
from . import appliance_state, k8s_api
from .cert_auth import build_auth_headers, load_cert
from .config import SupervisorConfig
from .identity import Identity, load_appliance_id

log = structlog.get_logger(__name__)

# Long-poll timeout. Matches the backend's queue.get(timeout=30) on
# the other side — keep them in sync so the supervisor's request
# doesn't return BEFORE the backend gives up on enqueuing.
_POLL_TIMEOUT_S = 32.0

# Sleep after recoverable errors. The proxy thread is non-essential
# for the supervisor's primary heartbeat duty; back off gently
# instead of hammering the control plane.
_BACKOFF_S = 5.0
_REVOKED_BACKOFF_S = 30.0


def proxy_loop_forever(
    cfg: SupervisorConfig,
    identity: Identity,
) -> None:
    """Run the proxy long-poll loop until the process exits.

    Called from ``__main__`` as ``threading.Thread(target=...)`` so
    the proxy lives alongside the heartbeat loop. Both threads share
    the SupervisorConfig + Identity but otherwise run independently.

    Reads ``appliance_id`` fresh each iteration so a post-revoke
    re-pair (which writes a new ``appliance_id`` file) picks up the
    new ID on the next loop without restarting the supervisor.
    """
    # httpx.Client is thread-safe but the supervisor's main heartbeat
    # client is in another thread; create our own to avoid lock
    # contention on concurrent polls.
    # #1219 — a fresh client per poll, verified against the control
    # plane's pinned certificate, so a re-pin by the heartbeat loop is
    # picked up here too. The pin is only ever taken by registration.
    while True:
        try:
            with cp_tls.client(
                cfg.state_dir,
                cfg.control_plane_url,
                first_contact=False,
                timeout=_POLL_TIMEOUT_S + 5.0,
            ) as client:
                _proxy_once(cfg, identity, client)
        except Exception as exc:  # noqa: BLE001
            # Last-ditch swallow — any uncaught error in the
            # proxy must not kill the supervisor thread. Log
            # loud + back off.
            log.warning("supervisor.k8s_proxy.loop_crashed", error=str(exc))
            time.sleep(_BACKOFF_S)


def _proxy_once(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
) -> None:
    """One poll → execute → reply cycle. Returns to the caller
    immediately on success or after the backoff sleep on error."""
    appliance_id = load_appliance_id(cfg.state_dir)
    if appliance_id is None:
        # Not yet registered. Sleep + retry — heartbeat thread will
        # land the registration eventually.
        time.sleep(_BACKOFF_S)
        return
    cert_pem = load_cert(cfg.state_dir)
    if cert_pem is None:
        # No cert yet (pre-approval). The heartbeat loop is doing
        # its session-token thing; we can't proxy anything until the
        # cert exchange lands. Sleep + retry.
        time.sleep(_BACKOFF_S)
        return

    # Issue #183 — only proxy when k3s is actually our active
    # runtime. On legacy compose deployments the kubeapi isn't
    # reachable anyway, and the queue would just back up.
    if appliance_state.detect_runtime() != "k3s":
        time.sleep(_BACKOFF_S)
        return

    poll_path = "/api/v1/appliance/supervisor/k8s-proxy/poll"
    poll_url = cfg.control_plane_url.rstrip("/") + poll_path
    headers = build_auth_headers(
        "POST", poll_path, cert_pem, identity.private_key, appliance_id
    )

    try:
        resp = client.post(poll_url, headers=headers)
    except httpx.HTTPError as exc:
        log.warning("supervisor.k8s_proxy.poll_failed", error=str(exc))
        time.sleep(_BACKOFF_S)
        return
    if resp.status_code == 403:
        log.warning("supervisor.k8s_proxy.poll_revoked")
        time.sleep(_REVOKED_BACKOFF_S)
        return
    if resp.status_code != 200:
        log.warning(
            "supervisor.k8s_proxy.poll_unexpected_status",
            status_code=resp.status_code,
        )
        time.sleep(_BACKOFF_S)
        return

    try:
        body = resp.json()
    except ValueError:
        log.warning("supervisor.k8s_proxy.poll_bad_json")
        time.sleep(_BACKOFF_S)
        return

    request_id = body.get("request_id") or ""
    if not request_id:
        # Empty long-poll — no queued work. Loop immediately so the
        # next poll re-extends the keepalive.
        return

    # Execute against local kubeapi.
    method = body.get("method") or "GET"
    api_path = body.get("path") or "/"
    req_headers = body.get("headers") or {}
    req_body_b64 = body.get("body_b64") or ""
    req_body = base64.b64decode(req_body_b64) if req_body_b64 else b""

    response_status, response_body = _call_local_kubeapi(
        method, api_path, req_body, req_headers
    )

    reply_path = f"/api/v1/appliance/supervisor/k8s-proxy/reply/{request_id}"
    reply_url = cfg.control_plane_url.rstrip("/") + reply_path
    reply_headers = build_auth_headers(
        "POST", reply_path, cert_pem, identity.private_key, appliance_id
    )
    reply_body = {
        "request_id": request_id,
        "status": response_status,
        "headers": {},
        "body_b64": base64.b64encode(response_body).decode("ascii"),
    }
    try:
        reply_resp = client.post(reply_url, headers=reply_headers, json=reply_body)
    except httpx.HTTPError as exc:
        log.warning("supervisor.k8s_proxy.reply_failed", error=str(exc))
        return
    if reply_resp.status_code != 200:
        log.warning(
            "supervisor.k8s_proxy.reply_unexpected_status",
            status_code=reply_resp.status_code,
        )
        return
    log.info(
        "supervisor.k8s_proxy.replied",
        request_id=request_id,
        method=method,
        path=api_path,
        local_status=response_status,
    )


def _call_local_kubeapi(
    method: str, path: str, body: bytes, headers: dict[str, str]
) -> tuple[int, bytes]:
    """Forward the proxied request to ``127.0.0.1:6443`` (the local
    kubeapi). Reuses ``k8s_api._request``'s auth resolution — we get
    the same in-cluster SA token + ca.crt + TLS path.

    Returns ``(status_code, body_bytes)``. On local-kubeapi
    transport failure (kubeapi down, TLS verification fail) returns
    a synthetic 502 with a JSON error body the control plane can
    surface to the operator.
    """
    cfg = k8s_api.get_config()
    if cfg is None:
        return 502, json.dumps(
            {"error": "supervisor: kubeapi config not resolved"}
        ).encode("utf-8")

    ctx = ssl.create_default_context()
    if cfg.ca_path:
        try:
            ctx.load_verify_locations(cafile=cfg.ca_path)
        except OSError as exc:
            return 502, json.dumps(
                {"error": f"supervisor: ca load failed: {exc}"}
            ).encode("utf-8")
    elif os.environ.get("SPATIUM_INSECURE_SKIP_TLS_VERIFY") == "1":
        # Documented dev-only opt-out (issue #233). Mirrors the
        # k8s_api._ssl_context branch.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        # No CA path AND no opt-out → refuse to proxy. Same rationale
        # as #233 — the proxy carries operator-queued kubeapi requests
        # whose responses the UI treats as truth; an unverified channel
        # lets a MITM inject responses.
        return 502, json.dumps(
            {
                "error": "supervisor: kubeapi CA path not resolved and "
                "SPATIUM_INSECURE_SKIP_TLS_VERIFY is not set; refusing "
                "to proxy over an unverified channel (issue #233)."
            }
        ).encode("utf-8")

    conn = http.client.HTTPSConnection(cfg.host, cfg.port, timeout=15.0, context=ctx)
    try:
        # Merge supervisor-supplied headers with the auth header. The
        # control plane sets Content-Type + Accept; we add Authorization
        # from the in-cluster service-account token.
        req_headers = dict(headers)
        if cfg.token and "Authorization" not in req_headers:
            req_headers["Authorization"] = f"Bearer {cfg.token}"
        req_headers.setdefault("Host", cfg.host)
        conn.request(method.upper(), path, body=body, headers=req_headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    except (OSError, socket.timeout, ssl.SSLError) as exc:
        return 502, json.dumps(
            {"error": f"supervisor: kubeapi {method} {path}: {exc}"}
        ).encode("utf-8")
    finally:
        conn.close()


def start_proxy_thread(cfg: SupervisorConfig, identity: Identity) -> threading.Thread:
    """Spawn the proxy loop as a daemon thread + return the handle
    so callers can name/log it. Daemon=True so a process exit
    doesn't hang waiting on the thread."""
    thread = threading.Thread(
        target=proxy_loop_forever,
        args=(cfg, identity),
        name="spatium-k8s-proxy",
        daemon=True,
    )
    thread.start()
    log.info("supervisor.k8s_proxy.thread_started")
    return thread


__all__ = ["proxy_loop_forever", "start_proxy_thread"]

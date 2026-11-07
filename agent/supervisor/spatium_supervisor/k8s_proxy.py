"""Supervisor-side kubeapi proxy thread (#183 Phase 4).

Bridges control plane → local kubeapi. The control plane enqueues
operator-action requests (rollout-restart, kubectl-logs, etc) bound
for this appliance; this thread long-polls
``/supervisor/k8s-proxy/poll``, executes against the local kubeapi
via ``k8s_api._request``, and POSTs the response back via
``/supervisor/k8s-proxy/reply/{request_id}``.

Only the requests the shipped Fleet routes build are executed (#3618):
pod list + pod log, workload list and rollout-restart, all in the
``spatium`` namespace. Anything else is answered 403 unexecuted; see
``_refusal``.

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
import re
import socket
import ssl
import threading
import time
from urllib.parse import parse_qsl, urlsplit

import httpx
import structlog

from . import cp_tls
from . import appliance_state, k8s_api
from .cert_auth import JSON_CONTENT_TYPE, build_auth_headers, encode_json, load_cert
from .config import SupervisorConfig
from .heartbeat import _effective_control_plane_url
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

# #3618 — what the control plane may ask this supervisor to run. The
# service account behind the proxy holds far more than the Fleet tab
# needs (HelmChart CRUD in kube-system, which is cluster-admin by
# another route; node delete; PVC delete), so relaying whatever method
# and path arrives would hand every control-plane caller that power on
# every appliance. Only the requests the shipped Fleet routes build are
# executed: the pod list + pod log, the workload list, and the
# rollout-restart patch, all in the ``spatium`` namespace. Anything
# else is answered 403 without touching the kubeapi.
_NAMESPACE = "spatium"
_NAME_RE = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
_LABEL_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
_WORKLOAD_PLURALS = ("deployments", "daemonsets", "statefulsets")
_PODS_PATH = f"/api/v1/namespaces/{_NAMESPACE}/pods"
_WORKLOADS_PREFIX = f"/apis/apps/v1/namespaces/{_NAMESPACE}/"
_RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt"
_FORWARDED_HEADERS = ("Accept", "Content-Type")


def _is_pod_log_route(method: str, path: str) -> bool:
    """True for the allowlisted pod-log GET (already validated by
    ``_refusal`` before this is consulted)."""
    route = urlsplit(path).path
    return (
        method == "GET"
        and route.startswith(_PODS_PATH + "/")
        and route.endswith("/log")
    )


def _is_name(value: str) -> bool:
    return _NAME_RE.fullmatch(value) is not None


def _refusal(
    method: str, path: str, body: bytes, headers: dict[str, str]
) -> str | None:
    """Why ``method path`` is not one of the requests this proxy runs,
    or None when it is. See ``_NAMESPACE`` above for the rule."""
    split = urlsplit(path)
    if split.scheme or split.netloc or split.fragment:
        return "absolute or fragment URL"
    try:
        query = parse_qsl(
            split.query, keep_blank_values=True, strict_parsing=bool(split.query)
        )
    except ValueError:
        return "malformed query"
    route = split.path
    if method == "GET" and route == _PODS_PATH:
        return "unexpected query" if query else None
    if (
        method == "GET"
        and route.startswith(_PODS_PATH + "/")
        and route.endswith("/log")
    ):
        pod = route[len(_PODS_PATH) + 1 : -len("/log")]
        if not _is_name(pod):
            return "bad pod name"
        seen: set[str] = set()
        for key, value in query:
            if key in seen:
                return "repeated query key"
            seen.add(key)
            if key == "tailLines" and value.isdigit() and len(value) <= 6:
                continue
            if key == "container" and _LABEL_RE.fullmatch(value):
                continue
            return f"query key {key!r} not allowed"
        return None
    if route.startswith(_WORKLOADS_PREFIX):
        rest = route[len(_WORKLOADS_PREFIX) :].split("/")
        if query or rest[0] not in _WORKLOAD_PLURALS:
            return "not a workload list or restart"
        if method == "GET" and len(rest) == 1:
            return None
        if method == "PATCH" and len(rest) == 2 and _is_name(rest[1]):
            if headers.get("Content-Type") != "application/strategic-merge-patch+json":
                return "restart patch must be a strategic-merge patch"
            try:
                patch = json.loads(body)
                annotations = patch["spec"]["template"]["metadata"]["annotations"]
            except (ValueError, TypeError, KeyError):
                return "not a rollout-restart patch"
            shape = {"spec": {"template": {"metadata": {"annotations": annotations}}}}
            if (
                patch != shape
                or list(annotations) != [_RESTART_ANNOTATION]
                or not isinstance(annotations[_RESTART_ANNOTATION], str)
            ):
                return "not a rollout-restart patch"
            return None
    return "method and path not allowed"


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
                _effective_control_plane_url(cfg),
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
    # runtime. Since Phase 7 ``detect_runtime`` is the constant
    # "k3s", so this never skips today; a supervisor with no kubeapi
    # credentials answers each request 502 from ``_call_local_kubeapi``.
    if appliance_state.detect_runtime() != "k3s":
        time.sleep(_BACKOFF_S)
        return

    poll_path = "/api/v1/appliance/supervisor/k8s-proxy/poll"
    poll_url = _effective_control_plane_url(cfg).rstrip("/") + poll_path
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
    method = str(body.get("method") or "GET").upper()
    api_path = str(body.get("path") or "/")
    req_headers = body.get("headers")
    if not isinstance(req_headers, dict):
        req_headers = {}
    req_body_b64 = body.get("body_b64") or ""
    req_body = base64.b64decode(req_body_b64) if req_body_b64 else b""

    refusal = _refusal(method, api_path, req_body, req_headers)
    if refusal is None:
        # Only the content-negotiation headers travel; anything else the
        # control plane put there (Authorization, Impersonate-*) does not.
        forwarded = {
            k: str(req_headers[k]) for k in _FORWARDED_HEADERS if k in req_headers
        }
        if _is_pod_log_route(method, api_path):
            # kubeapi answers a pod log with 406 unless Accept admits a
            # non-JSON body: it lists only json / yaml / protobuf, so the
            # ``text/plain`` an older control plane sends is refused. Send
            # ``*/*`` whatever the caller asked for. The body is raw text;
            # it is relayed as opaque bytes (base64), never parsed.
            forwarded["Accept"] = "*/*"
        response_status, response_body = _call_local_kubeapi(
            method, api_path, req_body, forwarded
        )
    else:
        log.warning(
            "supervisor.k8s_proxy.refused",
            request_id=request_id,
            method=method,
            path=api_path,
            reason=refusal,
        )
        response_status = 403
        response_body = json.dumps(
            {
                "error": f"supervisor: kubeapi proxy refused {method} {api_path}: {refusal}"
            }
        ).encode("utf-8")

    reply_path = f"/api/v1/appliance/supervisor/k8s-proxy/reply/{request_id}"
    reply_url = _effective_control_plane_url(cfg).rstrip("/") + reply_path
    reply_body = encode_json(
        {
            "request_id": request_id,
            "status": response_status,
            "headers": {},
            "body_b64": base64.b64encode(response_body).decode("ascii"),
        }
    )
    reply_headers = build_auth_headers(
        "POST", reply_path, cert_pem, identity.private_key, appliance_id, reply_body
    )
    try:
        reply_resp = client.post(
            reply_url,
            headers={**reply_headers, **JSON_CONTENT_TYPE},
            content=reply_body,
        )
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

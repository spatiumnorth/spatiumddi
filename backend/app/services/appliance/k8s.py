"""Minimal kubeapi client for the api pod.

The api pod has a ServiceAccount mounted at
``/var/run/secrets/kubernetes.io/serviceaccount/`` (token + ca.crt
+ namespace) when deployed via the umbrella chart with
``api.serviceAccount.enabled=true``. We use stdlib http.client +
ssl rather than the upstream ``kubernetes`` Python SDK to avoid
the ~30 MB extra wheel + transitive deps for a handful of
endpoints.

Pattern is identical to ``agent/supervisor/spatium_supervisor/
k8s_api.py`` — same in-cluster ServiceAccount auth, same single-
connection-per-call shape.

Used by:

* ``services/appliance/containers.py`` — list pods + tail logs
  for the Fleet UI's Pods tab (post-Phase-11 rename of the old
  /appliance/containers docker surface).
* ``services/appliance/deployment.py`` — patch the
  ``spatium-appliance-tls`` Secret in place when an operator
  uploads a cert through the Cert Manager UI. Replaces the
  pre-Phase-11 ``/var/run/docker.sock`` SIGHUP-the-frontend
  shape.

Gated on ``settings.appliance_mode`` at every call site so non-
appliance deploys never look for the ServiceAccount.
"""

from __future__ import annotations

import http.client
import json
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, overload
from urllib.parse import quote

import structlog

logger = structlog.get_logger(__name__)


_SA_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_SA_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
_SA_NAMESPACE_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")


class KubeapiUnavailableError(RuntimeError):
    """Raised when the kubeapi can't be reached.

    Router translates to 503 Service Unavailable. Distinct from
    a NotFound / Forbidden from kubeapi itself (those come back
    via the (status, body) return shape on each helper).
    """


@dataclass(frozen=True)
class _Config:
    host: str
    port: int
    token: str
    ca_path: str
    namespace: str


_CACHED_CONFIG: _Config | None = None
_CONFIG_LOADED_AT: float = 0.0
# Re-read the ServiceAccount token every 10 min so a rotated
# projected token doesn't strand us on a stale value. kubelet
# projects with 1h TTL by default; 10 min is well under that.
_CONFIG_TTL_S = 600.0


def _resolve_config() -> _Config | None:
    """Read SA token / ca / namespace from the projected volume.

    Returns None when the volume isn't mounted (non-appliance
    deploy, or chart installed without the api.serviceAccount.
    enabled flag). Caller treats None as "kubeapi not configured;
    fall back to whatever the legacy code path did".
    """
    if not (_SA_TOKEN_PATH.exists() and _SA_CA_PATH.exists()):
        return None
    try:
        token = _SA_TOKEN_PATH.read_text(encoding="utf-8").strip()
        ns = (
            _SA_NAMESPACE_PATH.read_text(encoding="utf-8").strip()
            if _SA_NAMESPACE_PATH.exists()
            else "default"
        )
    except OSError as exc:
        logger.warning("k8s_sa_read_failed", error=str(exc))
        return None
    # In-cluster kubeapi is reachable on ``kubernetes.default.svc``.
    # The env vars ``KUBERNETES_SERVICE_HOST`` / ``_PORT_HTTPS``
    # are set by kubelet for every pod; prefer them over hardcoded
    # values so a non-default service port still works.
    import os  # noqa: PLC0415

    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = int(os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443"))
    return _Config(host=host, port=port, token=token, ca_path=str(_SA_CA_PATH), namespace=ns)


def get_config() -> _Config | None:
    """Cached config accessor — refreshed every 10 min."""
    global _CACHED_CONFIG, _CONFIG_LOADED_AT
    now = time.monotonic()
    if _CACHED_CONFIG is None or now - _CONFIG_LOADED_AT > _CONFIG_TTL_S:
        _CACHED_CONFIG = _resolve_config()
        _CONFIG_LOADED_AT = now
    return _CACHED_CONFIG


def _ssl_context(ca_path: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_path)
    return ctx


@overload
def _request(
    method: str,
    path: str,
    *,
    body: bytes | None = ...,
    content_type: str | None = ...,
    timeout: float = ...,
    stream: Literal[False] = False,
) -> tuple[int, bytes]:
    pass


@overload
def _request(
    method: str,
    path: str,
    *,
    body: bytes | None = ...,
    content_type: str | None = ...,
    timeout: float = ...,
    stream: Literal[True],
) -> tuple[int, http.client.HTTPResponse]:
    pass


def _request(
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 10.0,
    stream: bool = False,
) -> tuple[int, bytes | http.client.HTTPResponse]:
    """Issue a request to kubeapi.

    When ``stream=True`` returns the live ``HTTPResponse`` so
    callers can iterate over chunks (pod log follow). The caller
    MUST close the connection — use the streaming SSE wrapper for
    that.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    conn = http.client.HTTPSConnection(
        cfg.host, cfg.port, timeout=timeout, context=_ssl_context(cfg.ca_path)
    )
    try:
        headers = {
            "Host": cfg.host,
            "Authorization": f"Bearer {cfg.token}",
            "Accept": "application/json",
        }
        if content_type:
            headers["Content-Type"] = content_type
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        if stream:
            # Caller owns the conn — return both so they can close.
            return resp.status, resp
        return resp.status, resp.read()
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        raise KubeapiUnavailableError(f"kubeapi {method} {path}: {exc}") from exc
    finally:
        if not stream:
            conn.close()


# ── Endpoint helpers ──────────────────────────────────────────────────


def list_pods(namespace: str | None = None) -> list[dict[str, Any]]:
    """List pods in ``namespace`` (defaults to the api pod's own
    namespace from the ServiceAccount projection).

    Returns the raw kubeapi PodList ``items`` array. Caller is
    responsible for flattening to whatever summary shape it
    needs.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    path = f"/api/v1/namespaces/{quote(ns)}/pods"
    status, body = _request("GET", path)
    if status != 200:
        raise KubeapiUnavailableError(f"kubeapi list pods status {status}: {body[:200]!r}")
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise KubeapiUnavailableError(f"kubeapi list pods bad json: {exc}") from exc
    return data.get("items") or []


def list_all_pods() -> tuple[int, list[dict[str, Any]]]:
    """List pods across ALL namespaces (cluster-wide).

    Returns (status, items). On non-200 returns the status + empty
    list so the Cluster-health caller can branch on a 403 (RBAC not
    granted) without an exception. Distinct from ``list_pods`` (single
    namespace) — the health screen rolls up control-plane + system +
    agent pods, which span ``spatium`` / ``kube-system`` / etc.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    status, body = _request("GET", "/api/v1/pods")
    if status != 200:
        return status, []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise KubeapiUnavailableError(f"kubeapi list all pods bad json: {exc}") from exc
    return status, data.get("items") or []


# ── Kubelet Summary API transports (#983 Phase 2 item 6) ─────────────────────
# Two ways to reach the same document, needing different authorization:
#
#   proxy   GET {apiserver}/api/v1/nodes/<n>/proxy/stats/summary
#           needs ``nodes/proxy [get]`` at the APISERVER — which authorizes
#           read GETs to EVERY kubelet endpoint (/pods, /logs/…, /configz,
#           /debug/…), not just this one. That is the grant #983 wants gone.
#
#   direct  GET https://<nodeIP>:10250/stats/summary
#           the kubelet authorizes it itself via SubjectAccessReview, and
#           Kubernetes 1.36 GA'd fine-grained kubelet subresources — so this
#           needs only ``nodes/stats [get]``.
#
# Direct is tried first and the proxy is the fallback, rather than a flag
# day, for one reason we could not settle without a cluster: k3s signs
# kubelet serving certs with its own ``server-ca``, and whether that is the
# same CA as the one in the ServiceAccount's ``ca.crt`` is a fact about the
# deployment, not something the chart can assert. #983 suggested the TTY
# console as a reference implementation — it is not one; ``spatium-console``
# also goes through the apiserver proxy (``kubectl get --raw``), so nothing
# in this repo has ever spoken to a kubelet directly.
#
# So the code finds out, once, and says which transport served. When the
# direct path is confirmed in the field the ``nodes/proxy`` grant can be
# switched off (``api.upgradeOrchestratorRBAC.kubeletProxyFallback``) and
# this degrades to direct-only.
_KUBELET_PORT = 10250
# A failure that will not change on the next poll — a CA that cannot verify
# the kubelet, or an RBAC answer — must not be retried every tick: the health
# poll fans out over every node once a minute and a TLS handshake against a
# wrong CA costs a round trip each time. Re-probe on this interval instead.
_KUBELET_DIRECT_RETRY_S = 900.0
# #993 — the direct probe's socket timeout, and it is on the REQUEST path:
# the cluster-health snapshot probes each node before it can fall back, so
# the first request after api start (and after every retry expiry above)
# pays this once per node, serially.
#
# It was 6 s, which is a reasonable read timeout and a terrible connect
# timeout for a LAN peer. On the appliance the port was firewalled shut
# (the other half of this issue), so every probe hit the full 6 s: two nodes
# is 12 s, three is 18 s, and the browser gave up first — the api logged the
# dashboard request being cancelled mid-flight, with its DB connection torn
# down under it.
#
# 1.5 s is the judgement that a kubelet on the same LAN which has not
# completed a TCP handshake in that time is not going to.
#
# CONNECT ONLY. ``HTTPSConnection(timeout=…)`` sets one socket timeout that
# also caps the response read, and 1.5 s is far too tight for that: a busy
# node marshalling /stats/summary for a few hundred pods can legitimately
# take seconds, and it would be blocked-direct for 15 minutes with a reason
# indistinguishable from the firewall failure #993 exists to fix. So the
# socket is re-armed with the read budget below immediately after connect.
_KUBELET_CONNECT_TIMEOUT_S = 1.5
# Read budget once the handshake is through. Matches the apiserver-proxy
# path's own 6 s, so choosing the direct transport never costs a node the
# patience the fallback would have given it.
_KUBELET_READ_TIMEOUT_S = 6.0
# PER NODE, keyed by node IP: ``{ip: (blocked_until_monotonic, reason)}``.
#
# Deliberately not one global flag. A single kubelet restarting would
# otherwise demote the WHOLE cluster to the apiserver proxy for 15 minutes —
# and with ``kubeletProxyFallback: false`` that is not a demotion, it is total
# loss of live metrics for every node because one of them blinked.
_kubelet_direct_blocked: dict[str, tuple[float, str]] = {}

TRANSPORT_DIRECT = "direct"
TRANSPORT_PROXY = "proxy"


def kubelet_block_reasons() -> dict[str, str]:
    """``{node_ip: reason}`` for every node whose direct path is blocked NOW.

    Expired entries are pruned as they are read. That pruning is also what
    stops a recovered node reporting a stale reason: the reason lives inside
    the block entry rather than in a separate variable nothing clears, so it
    cannot outlive it.
    """
    now = time.monotonic()
    for ip in [ip for ip, (until, _) in _kubelet_direct_blocked.items() if until <= now]:
        _kubelet_direct_blocked.pop(ip, None)
    return {ip: reason for ip, (_, reason) in _kubelet_direct_blocked.items()}


def _direct_is_blocked(node_ip: str) -> bool:
    entry = _kubelet_direct_blocked.get(node_ip)
    if entry is None:
        return False
    if entry[0] <= time.monotonic():
        # Expired — clear it here so the reason disappears WITH the block.
        # Keeping a reason around after recovery is how a status line ends up
        # reporting "direct" and a CA error at the same time.
        _kubelet_direct_blocked.pop(node_ip, None)
        return False
    return True


def _block_direct(node_ip: str, reason: str) -> None:
    _kubelet_direct_blocked[node_ip] = (time.monotonic() + _KUBELET_DIRECT_RETRY_S, reason)
    logger.info(
        "kubelet_direct_unavailable",
        node_ip=node_ip,
        reason=reason,
        retry_in_s=int(_KUBELET_DIRECT_RETRY_S),
        note="this node falls back to the apiserver nodes/proxy transport",
    )


def _kubelet_ca_path(cfg: _Config) -> str:
    """CA bundle used to verify the kubelet's serving cert.

    Defaults to the ServiceAccount's ``ca.crt``. ``SPATIUM_KUBELET_CA_PATH``
    overrides it for a cluster whose kubelet serving certs are signed by a
    different CA than the apiserver's — k3s's ``server-ca`` is the case this
    exists for, and until it is checked on real hardware the override is how
    an operator fixes it without a release.
    """
    import os  # noqa: PLC0415

    return os.environ.get("SPATIUM_KUBELET_CA_PATH") or cfg.ca_path


def _get_stats_summary_direct(node_ip: str) -> tuple[int, dict[str, Any] | None]:
    """``GET https://<nodeIP>:10250/stats/summary`` with the SA token.

    Raises nothing: every failure mode is converted into a blocked-direct
    verdict plus a (0, None) return, because the caller's job is to fall back
    rather than to surface a transport problem as missing metrics.
    """
    cfg = get_config()
    if cfg is None:
        return 0, None
    # Building the context is INSIDE the guard on purpose. ``SPATIUM_KUBELET_
    # CA_PATH`` is operator-supplied, and ``create_default_context`` raises on
    # a path that is missing or is not a PEM — outside the guard that
    # exception escapes ``get_node_stats_summary``, past cluster_health's
    # ``KubeapiUnavailableError``-only handler, and 500s the whole health
    # poll. A misconfigured CA has to degrade to the proxy like every other
    # direct-path failure, not take the Cluster screen down.
    try:
        ctx = _ssl_context(_kubelet_ca_path(cfg))
    except (OSError, ssl.SSLError) as exc:
        _block_direct(node_ip, f"cannot load kubelet CA bundle: {exc} (SPATIUM_KUBELET_CA_PATH?)")
        return 0, None
    conn = http.client.HTTPSConnection(
        node_ip, _KUBELET_PORT, timeout=_KUBELET_CONNECT_TIMEOUT_S, context=ctx
    )
    try:
        # Connect under the short budget, then hand the open socket the long
        # one. ``connect()`` is explicit rather than left to ``request()`` so
        # there is a point at which to swap them; it is idempotent, so the
        # request below reuses this connection rather than making a second.
        conn.connect()
        if conn.sock is not None:
            conn.sock.settimeout(_KUBELET_READ_TIMEOUT_S)
        conn.request(
            "GET",
            "/stats/summary",
            headers={"Authorization": f"Bearer {cfg.token}", "Accept": "application/json"},
        )
        resp = conn.getresponse()
        body = resp.read()
        if resp.status == 200:
            try:
                return 200, json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                # A 200 we cannot parse is not a transport problem; do not
                # block the direct path over it.
                return 200, None
        if resp.status in (401, 403):
            # The kubelet authorized us and said no — almost certainly the
            # ``nodes/stats`` grant is missing. Naming the status matters:
            # this is the one failure an operator fixes in the chart.
            _block_direct(node_ip, f"kubelet returned HTTP {resp.status} (nodes/stats grant?)")
        else:
            _block_direct(node_ip, f"kubelet returned HTTP {resp.status}")
        return resp.status, None
    except ssl.SSLCertVerificationError as exc:
        # THE question this whole arrangement exists to answer. Logged with
        # the remedy rather than just the error.
        _block_direct(
            node_ip,
            f"kubelet serving cert not valid for the ServiceAccount CA: {exc}. "
            "Set SPATIUM_KUBELET_CA_PATH to the CA that signs kubelet serving "
            "certs (k3s: /var/lib/rancher/k3s/server/tls/server-ca.crt)",
        )
        return 0, None
    except (OSError, http.client.HTTPException) as exc:
        _block_direct(node_ip, f"{type(exc).__name__}: {exc}")
        return 0, None
    finally:
        conn.close()


def get_node_stats_summary(
    node_name: str, node_ip: str | None = None
) -> tuple[int, dict[str, Any] | None, str]:
    """Fetch the kubelet Summary API for a node.

    Per-node + per-pod CPU (``usageNanoCores``) + memory
    (``workingSetBytes``) + filesystem usage, and since Kubernetes 1.36 the
    PSI blocks (#983 Phase 2 item 7). This is how the appliance surfaces
    live usage WITHOUT a metrics-server / Prometheus.

    Tries the direct kubelet transport when ``node_ip`` is known and THAT
    NODE's direct path is not currently blocked, then falls back to the
    apiserver proxy.

    Returns ``(status, parsed_or_None, transport)``. The transport is returned
    rather than stashed in a module global because the caller is the only
    thing that knows the node NAMES, and a global would report whichever node
    happened to be processed last — reading "direct" while another node was
    quietly served by the proxy, which is the opposite of the fact an operator
    needs before dropping the ``nodes/proxy`` grant.

    A 403 from the proxy (a chart without that grant) comes back as the status
    so the caller degrades to "no live usage" instead of erroring. Short
    timeouts keep a wedged kubelet from stalling the health poll.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")

    if node_ip and not _direct_is_blocked(node_ip):
        status, parsed = _get_stats_summary_direct(node_ip)
        if status == 200:
            return status, parsed, TRANSPORT_DIRECT

    path = f"/api/v1/nodes/{quote(node_name)}/proxy/stats/summary"
    status, body = _request("GET", path, timeout=6.0)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8")), TRANSPORT_PROXY
        except (ValueError, UnicodeDecodeError):
            return status, None, TRANSPORT_PROXY
    return status, None, TRANSPORT_PROXY


def get_pod_logs(
    name: str,
    namespace: str | None = None,
    *,
    tail: int = 200,
    since_seconds: int | None = None,
    container: str | None = None,
) -> str:
    """Fetch tail of pod logs.

    Uses ``GET /api/v1/namespaces/<ns>/pods/<name>/log``. Single-
    shot read; for SSE-streaming follow use ``stream_pod_logs``.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    qs = [f"tailLines={tail}"]
    if since_seconds is not None:
        qs.append(f"sinceSeconds={since_seconds}")
    if container:
        qs.append(f"container={quote(container)}")
    path = f"/api/v1/namespaces/{quote(ns)}/pods/{quote(name)}/log?{'&'.join(qs)}"
    status, body = _request("GET", path)
    if status == 404:
        raise KubeapiUnavailableError(f"pod {ns}/{name} not found")
    if status != 200:
        raise KubeapiUnavailableError(f"kubeapi pod logs status {status}: {body[:200]!r}")
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)


def stream_pod_logs(
    name: str,
    namespace: str | None = None,
    *,
    tail: int = 200,
    container: str | None = None,
):
    """Yield log lines (str) as kubeapi emits them. ``follow=true``
    so the call blocks while the pod runs + closes on pod exit.

    Generator caller iterates; the underlying conn is closed when
    the generator is garbage-collected or .close() is invoked.
    Use in SSE handlers like:

        async def events():
            for line in stream_pod_logs(...):
                yield f"data: {line}\\n\\n"

    NOTE: this is a synchronous generator. The router wraps it in
    ``anyio.to_thread.run_sync`` for the async-FastAPI handler so
    we don't block the event loop.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    qs = [f"tailLines={tail}", "follow=true"]
    if container:
        qs.append(f"container={quote(container)}")
    path = f"/api/v1/namespaces/{quote(ns)}/pods/{quote(name)}/log?{'&'.join(qs)}"
    conn = http.client.HTTPSConnection(
        cfg.host, cfg.port, timeout=None, context=_ssl_context(cfg.ca_path)
    )
    try:
        # ``Accept: text/plain`` fails kubeapi's media-type check with
        # 406 — the api server only allows application/json,
        # application/yaml, application/vnd.kubernetes.protobuf,
        # application/cbor, or ``*/*``. Pod logs are returned as raw
        # text regardless. Use ``*/*`` so we don't accidentally
        # constrain the negotiation.
        headers = {
            "Host": cfg.host,
            "Authorization": f"Bearer {cfg.token}",
            "Accept": "*/*",
        }
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            err_body = resp.read()[:200]
            raise KubeapiUnavailableError(
                f"kubeapi pod logs stream status {resp.status}: {err_body!r}"
            )
        # Stream line-by-line. fp.readline() blocks on chunked
        # transfer; closing the conn breaks the read with an
        # exception — caller should swallow + re-raise as needed.
        while True:
            line = resp.readline()
            if not line:
                break
            yield line.decode("utf-8", errors="replace").rstrip("\n")
    finally:
        conn.close()


def delete_pod(name: str, namespace: str | None = None) -> tuple[bool, str | None]:
    """Delete a pod. The owning Deployment/DaemonSet recreates it
    — this is the k8s analog of ``docker restart``.
    """
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    path = f"/api/v1/namespaces/{quote(ns)}/pods/{quote(name)}"
    try:
        status, body = _request("DELETE", path)
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 202, 404):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


def get_secret(name: str, namespace: str | None = None) -> tuple[int, dict[str, str] | None]:
    """Read a Secret's ``data`` block, base64-decoded to str.

    Returns ``(status, decoded_data_or_None)``. ``status`` is 0 when the
    ServiceAccount isn't mounted or the kubeapi is unreachable, so a
    caller can tell "not on k8s" from "Secret genuinely absent" (404).

    Values that aren't valid UTF-8 after the base64 decode are dropped —
    every caller here reads PEM, which is ASCII.
    """
    import base64  # noqa: PLC0415

    cfg = get_config()
    if cfg is None:
        return 0, None
    ns = namespace or cfg.namespace
    path = f"/api/v1/namespaces/{quote(ns)}/secrets/{quote(name)}"
    try:
        status, body = _request("GET", path)
    except KubeapiUnavailableError:
        return 0, None
    if status != 200:
        return status, None
    try:
        secret = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return status, None
    out: dict[str, str] = {}
    for key, encoded in (secret.get("data") or {}).items():
        try:
            out[key] = base64.b64decode(encoded).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
    return status, out


def patch_secret(
    name: str, data: dict[str, str], namespace: str | None = None
) -> tuple[bool, str | None]:
    """Strategic-merge-patch a Secret's ``data`` block in place.

    ``data`` keys are filenames inside the Secret (e.g. ``tls.crt``);
    values are the PEM contents — this function does the base64
    encoding the kubeapi expects on the wire.

    Used by the cert-deploy path to update
    ``spatium-appliance-tls`` after an operator-uploaded cert
    activates.
    """
    import base64  # noqa: PLC0415

    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    encoded = {
        k: base64.b64encode(v.encode("utf-8") if isinstance(v, str) else v).decode("ascii")
        for k, v in data.items()
    }
    payload = json.dumps({"data": encoded}).encode("utf-8")
    path = f"/api/v1/namespaces/{quote(ns)}/secrets/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/strategic-merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 201):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


def patch_deployment_annotation(
    name: str,
    key: str,
    value: str,
    namespace: str | None = None,
) -> tuple[bool, str | None]:
    """Bump a single annotation on a Deployment's pod template.

    Used to trigger a rollout after a referenced Secret has been
    patched (k8s doesn't auto-roll on Secret changes — the pod
    template's annotation acts as a rollout trigger).
    """
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    payload = json.dumps(
        {"spec": {"template": {"metadata": {"annotations": {key: value}}}}}
    ).encode("utf-8")
    path = f"/apis/apps/v1/namespaces/{quote(ns)}/deployments/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/strategic-merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 201):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


# ── Lease (coordination.k8s.io/v1) ────────────────────────────────────
# Thin wrappers around the Lease resource. Used by the multi-node
# rolling-upgrade mutex (#296 Phase A) — at-most-one upgrade in flight
# cluster-wide, with the holder's identity + a renewal heartbeat that
# expires if the api pod holding the lease is rescheduled mid-upgrade.
# Generic on purpose: any future "single-node-does-this-at-a-time"
# beat task can use the same helpers without re-inventing the auth.


def get_lease(
    name: str,
    namespace: str | None = None,
) -> tuple[int, dict[str, Any] | None]:
    """Read a Lease. Returns (status, parsed_body_or_None).

    404 => lease doesn't exist; caller should ``create_lease``.
    Anything else (200 / 5xx) => parsed body or None on JSON error.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    path = f"/apis/coordination.k8s.io/v1/namespaces/{quote(ns)}/leases/{quote(name)}"
    status, body = _request("GET", path)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None
    return status, None


def create_lease(
    name: str,
    holder: str,
    *,
    namespace: str | None = None,
    lease_duration_seconds: int = 60,
) -> tuple[bool, str | None]:
    """Create a Lease claimed by ``holder``.

    Returns (created, error). 409 (already exists) is reported as
    error so the caller can fall through to the read-then-update
    path. ``lease_duration_seconds`` is how long until k8s considers
    the lease stale if not renewed — 60 s matches the upstream
    leader-election library's default.
    """
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = json.dumps(
        {
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {"name": name, "namespace": ns},
            "spec": {
                "holderIdentity": holder,
                "leaseDurationSeconds": lease_duration_seconds,
                "acquireTime": now,
                "renewTime": now,
                "leaseTransitions": 1,
            },
        }
    ).encode("utf-8")
    path = f"/apis/coordination.k8s.io/v1/namespaces/{quote(ns)}/leases"
    try:
        status, body = _request("POST", path, body=payload, content_type="application/json")
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 201):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


def update_lease(
    name: str,
    holder: str,
    *,
    namespace: str | None = None,
    lease_duration_seconds: int = 60,
    bump_transitions: bool = False,
    expected_transitions: int | None = None,
    resource_version: str | None = None,
) -> tuple[bool, str | None]:
    """Update a Lease's renewTime + holderIdentity.

    Standard renewal: caller passes the same ``holder`` that's
    currently in the lease and we bump ``renewTime``.

    Acquisition (after a previous holder's lease expired): caller
    passes their own identity as ``holder`` + sets ``bump_transitions=
    True`` so ``leaseTransitions`` increments (this is how k8s
    leader-election detects a takeover). ``expected_transitions`` is the
    value the caller read; the patch writes it plus one.

    ``resource_version`` makes the update a compare-and-swap (#1512): the
    patch carries the ``metadata.resourceVersion`` the caller read, and the
    apiserver answers 409 when the lease changed since. Without it two
    takeovers of one expired lease both succeeded. Returns (ok, error);
    409 reports the conflict.
    """
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    # We do a server-side merge patch on ``spec`` only — the
    # metadata is owned by k8s + the controller-manager.
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    spec: dict[str, Any] = {
        "holderIdentity": holder,
        "leaseDurationSeconds": lease_duration_seconds,
        "renewTime": now,
    }
    if bump_transitions:
        if expected_transitions is not None:
            spec["leaseTransitions"] = expected_transitions + 1
        spec["acquireTime"] = now
    patch: dict[str, Any] = {"spec": spec}
    if resource_version:
        patch["metadata"] = {"resourceVersion": resource_version}
    payload = json.dumps(patch).encode("utf-8")
    path = f"/apis/coordination.k8s.io/v1/namespaces/{quote(ns)}/leases/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/strategic-merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status == 200:
        return True, None
    if status == 409:
        return False, "conflict: lease updated by another holder"
    return False, f"kubeapi status {status}: {body[:200]!r}"


def clear_lease_holder(
    name: str,
    *,
    namespace: str | None = None,
    resource_version: str | None = None,
) -> tuple[bool, str | None]:
    """Mark a lease as released without deleting it.

    Sets ``holderIdentity`` to empty + ``renewTime`` to a long-past
    timestamp so the next ``acquire()`` claims it via the expired-
    takeover path. The Lease object stays in etcd so
    ``kubectl get leases`` still surfaces who last held it — useful
    audit signal that doesn't cost anything to keep.
    """
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    # Two-hour-ago renewTime is well beyond any sane
    # leaseDurationSeconds → next read treats this as expired.
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 7200))
    patch: dict[str, Any] = {"spec": {"holderIdentity": "", "renewTime": old}}
    if resource_version:
        # #1512 — only clear the lease the caller read (see update_lease).
        patch["metadata"] = {"resourceVersion": resource_version}
    payload = json.dumps(patch).encode("utf-8")
    path = f"/apis/coordination.k8s.io/v1/namespaces/{quote(ns)}/leases/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/strategic-merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status == 200:
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


# ── Node + drain primitives (#296 Phase C) ─────────────────────────────
# Wrappers used by the per-node rolling-upgrade primitive. Each is
# idempotent so a resumed orchestrator (e.g. after an api pod
# reschedule mid-upgrade) can re-issue them without double-counting.


def get_node(name: str) -> tuple[int, dict[str, Any] | None]:
    """Read a Node. Returns (status, parsed_body_or_None)."""
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    path = f"/api/v1/nodes/{quote(name)}"
    status, body = _request("GET", path)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None
    return status, None


def list_nodes(
    label_selector: str | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """List Nodes, optionally filtered by label selector.

    Returns (status, items). On non-200 returns the status + empty list
    so the caller can branch cleanly without a None check.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    path = "/api/v1/nodes"
    if label_selector:
        path += f"?labelSelector={quote(label_selector)}"
    status, body = _request("GET", path)
    if status != 200:
        return status, []
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, []
    items = data.get("items") or []
    return status, items


def cordon_node(name: str) -> tuple[bool, str | None]:
    """Mark a Node unschedulable (idempotent — k8s no-ops if already true)."""
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    payload = json.dumps({"spec": {"unschedulable": True}}).encode("utf-8")
    path = f"/api/v1/nodes/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/strategic-merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 201):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


def uncordon_node(name: str) -> tuple[bool, str | None]:
    """Clear unschedulable on a Node (idempotent)."""
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    # Explicitly setting to None so a strategic-merge-patch removes the
    # field rather than ambiguously leaving it. ``unschedulable: false``
    # is also valid; either has the same effect post-PATCH.
    payload = json.dumps({"spec": {"unschedulable": False}}).encode("utf-8")
    path = f"/api/v1/nodes/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/strategic-merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 201):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


def is_node_ready(node: dict[str, Any]) -> bool:
    """True if the node's ``Ready`` condition is ``True``.

    Defensive against a missing status block (a node mid-add can
    surface that briefly).
    """
    conditions = (node.get("status") or {}).get("conditions") or []
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)


def list_pods_on_node(node_name: str) -> list[dict[str, Any]]:
    """List all pods scheduled on ``node_name`` cluster-wide.

    Uses ``fieldSelector=spec.nodeName=<n>`` so we filter server-side
    rather than walking every namespace's pod list. Returns the raw
    PodList ``items`` array.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    path = f"/api/v1/pods?fieldSelector=spec.nodeName%3D{quote(node_name)}"
    status, body = _request("GET", path)
    if status != 200:
        raise KubeapiUnavailableError(
            f"list pods-on-node {node_name} returned {status}: {body[:200]!r}"
        )
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise KubeapiUnavailableError(f"list pods-on-node bad json: {exc}") from exc
    return data.get("items") or []


def pod_is_owned_by_daemonset(pod: dict[str, Any]) -> bool:
    """True if any ownerReference on the pod is a DaemonSet.

    Used by drain to skip DS pods — they reboot in place with the
    node, exactly the same semantic as ``kubectl drain
    --ignore-daemonsets``. The controller field is the standard
    ownerReferences entry from the pod metadata.
    """
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    return any(o.get("kind") == "DaemonSet" for o in owners)


def pod_is_terminal(pod: dict[str, Any]) -> bool:
    """True if pod.status.phase is Succeeded or Failed.

    Drain skips terminal pods — they're already done; evicting them
    is a no-op that just adds noise to the log.
    """
    phase = (pod.get("status") or {}).get("phase")
    return phase in ("Succeeded", "Failed")


def pod_is_mirror(pod: dict[str, Any]) -> bool:
    """True if the pod is a static-mirror pod (managed by kubelet,
    not by the api server).

    Mirror pods carry ``kubernetes.io/config.mirror`` in their
    annotations and can't be evicted via the API — they're owned by
    the node's kubelet config dir directly. kubectl drain skips
    these for the same reason.
    """
    annotations = (pod.get("metadata") or {}).get("annotations") or {}
    return "kubernetes.io/config.mirror" in annotations


def evict_pod(
    name: str,
    namespace: str,
    *,
    grace_period_seconds: int | None = None,
) -> tuple[int, str | None]:
    """POST an Eviction subresource for a pod.

    Returns (status, error). Status codes the caller cares about:

    * 200/201 — eviction accepted; pod will start terminating.
    * 404     — pod already gone (race with drain or another evictor);
                treat as success.
    * 429     — PDB blocks; caller retries.
    * 500+    — other failure; surface to operator.

    The eviction body uses ``policy/v1`` (GA since k8s 1.22).
    """
    cfg = get_config()
    if cfg is None:
        return -1, "ServiceAccount not mounted"
    spec: dict[str, Any] = {
        "apiVersion": "policy/v1",
        "kind": "Eviction",
        "metadata": {"name": name, "namespace": namespace},
    }
    if grace_period_seconds is not None:
        spec["deleteOptions"] = {"gracePeriodSeconds": grace_period_seconds}
    payload = json.dumps(spec).encode("utf-8")
    path = f"/api/v1/namespaces/{quote(namespace)}/pods/{quote(name)}/eviction"
    try:
        status, body = _request("POST", path, body=payload, content_type="application/json")
    except KubeapiUnavailableError as exc:
        return -1, str(exc)
    if status in (200, 201, 404):
        return status, None
    return status, body[:200].decode("utf-8", errors="replace")


# ── CNPG Cluster CR primitives (#296 Phase C) ──────────────────────────
# Tiny wrapper layer over the CNPG operator's Cluster resource.
# Identical pattern to the supervisor's k8s_api.patch_cnpg_instances —
# centralised here so the rolling-upgrade primitive can read +
# mutate the Cluster's maintenance window without duplicating the
# CR path math.


def get_cnpg_cluster(name: str, namespace: str | None = None) -> tuple[int, dict[str, Any] | None]:
    """Read a CNPG ``postgresql.cnpg.io/v1`` Cluster CR.

    Returns (status, parsed_body_or_None). 404 + non-2xx come back as
    just status + None so the caller can branch without an exception.
    """
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    path = f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(ns)}/clusters/{quote(name)}"
    status, body = _request("GET", path)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None
    return status, None


def patch_cnpg_maintenance_window(
    name: str,
    *,
    in_progress: bool,
    reuse_pvc: bool = True,
    namespace: str | None = None,
) -> tuple[bool, str | None]:
    """Stamp / clear ``spec.nodeMaintenanceWindow`` on a CNPG Cluster.

    The CNPG-blessed pattern for "we're about to drain a node, leave
    the PVC alone + suspend the PDB until I clear this." See the
    Phase C primitive in #296 + the CNPG kubernetes_upgrade doc.
    """
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    ns = namespace or cfg.namespace
    payload = json.dumps(
        {
            "spec": {
                "nodeMaintenanceWindow": {
                    "inProgress": in_progress,
                    "reusePVC": reuse_pvc,
                }
            }
        }
    ).encode("utf-8")
    path = f"/apis/postgresql.cnpg.io/v1/namespaces/{quote(ns)}/clusters/{quote(name)}"
    try:
        status, body = _request(
            "PATCH",
            path,
            body=payload,
            content_type="application/merge-patch+json",
        )
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status in (200, 201):
        return True, None
    return False, f"kubeapi status {status}: {body[:200]!r}"


# ── HelmChartConfig + rollout primitives (#296 Phase E) ────────────────
# The orchestrator's post-loop chart bump patches the same
# ``helm.cattle.io/v1`` HelmChartConfig CR the supervisor writes to
# for cp-size / VIP overrides. Helpers mirror the supervisor's
# ``_helmchartconfig_upsert`` shape so both sides converge on identical
# kubeapi semantics — see agent/supervisor/spatium_supervisor/k8s_api.py
# for the durability rationale.


def get_helmchartconfig(
    name: str, namespace: str = "kube-system"
) -> tuple[int, dict[str, Any] | None]:
    """Read a HelmChartConfig CR. ``kube-system`` is the k3s default
    namespace for chart configs.  Returns (status, parsed_body_or_None)
    so the caller can branch on 404 cleanly."""
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    path = (
        f"/apis/helm.cattle.io/v1/namespaces/{quote(namespace)}" f"/helmchartconfigs/{quote(name)}"
    )
    status, body = _request("GET", path)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None
    return status, None


def upsert_helmchartconfig(
    name: str,
    values_yaml: str,
    *,
    namespace: str = "kube-system",
) -> tuple[bool, str | None]:
    """Create-or-update the HelmChartConfig so its ``spec.valuesContent``
    equals ``values_yaml``. Idempotent — returns ``(True, None)`` when
    already current. Same shape as the supervisor's
    ``_helmchartconfig_upsert``."""
    cfg = get_config()
    if cfg is None:
        return False, "ServiceAccount not mounted"
    base = f"/apis/helm.cattle.io/v1/namespaces/{quote(namespace)}/helmchartconfigs"
    path = f"{base}/{quote(name)}"
    try:
        status, resp = _request("GET", path)
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if status == 200:
        try:
            current = (json.loads(resp).get("spec") or {}).get("valuesContent") or ""
        except (json.JSONDecodeError, ValueError):
            current = None
        if current == values_yaml:
            return True, None
        patch = json.dumps({"spec": {"valuesContent": values_yaml}}).encode("utf-8")
        try:
            st, rb = _request(
                "PATCH", path, body=patch, content_type="application/merge-patch+json"
            )
        except KubeapiUnavailableError as exc:
            return False, str(exc)
        if st in (200, 201):
            return True, None
        return False, f"PATCH status {st}: {rb[:200]!r}"
    if status != 404:
        return False, f"kubeapi GET status {status}"
    body = json.dumps(
        {
            "apiVersion": "helm.cattle.io/v1",
            "kind": "HelmChartConfig",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"valuesContent": values_yaml},
        }
    ).encode("utf-8")
    try:
        st, rb = _request("POST", base, body=body, content_type="application/json")
    except KubeapiUnavailableError as exc:
        return False, str(exc)
    if st in (200, 201):
        return True, None
    return False, f"POST status {st}: {rb[:200]!r}"


def get_deployment(name: str, namespace: str | None = None) -> tuple[int, dict[str, Any] | None]:
    """Read a Deployment. Used by the rollout-poll path to inspect
    ``status.observedGeneration`` + ``status.updatedReplicas`` to know
    when a chart bump's rolling update has settled."""
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    path = f"/apis/apps/v1/namespaces/{quote(ns)}/deployments/{quote(name)}"
    status, body = _request("GET", path)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None
    return status, None


def deployment_is_rolled_out(deployment: dict[str, Any]) -> bool:
    """True when a Deployment's rolling update has finished.

    Matches ``kubectl rollout status`` semantics:

    * ``status.observedGeneration`` >= ``metadata.generation`` (the
      controller has seen the latest spec change).
    * ``status.updatedReplicas`` >= ``spec.replicas`` (the new RS has
      ramped to the desired count).
    * ``status.availableReplicas`` >= ``spec.replicas`` (every pod
      passed readiness; old RS is fully drained).
    """
    meta = deployment.get("metadata") or {}
    spec = deployment.get("spec") or {}
    status = deployment.get("status") or {}
    spec_replicas = int(spec.get("replicas") or 0)
    if spec_replicas == 0:
        # Scaled to zero — trivially rolled out.
        return True
    return (
        int(status.get("observedGeneration") or 0) >= int(meta.get("generation") or 0)
        and int(status.get("updatedReplicas") or 0) >= spec_replicas
        and int(status.get("availableReplicas") or 0) >= spec_replicas
    )


def get_job(name: str, namespace: str | None = None) -> tuple[int, dict[str, Any] | None]:
    """Read a batch/v1 Job. The migrate Job's ``status.succeeded`` /
    ``status.failed`` counters tell us whether the chart-bump's
    schema migration ran cleanly."""
    cfg = get_config()
    if cfg is None:
        raise KubeapiUnavailableError("ServiceAccount not mounted; kubeapi unreachable")
    ns = namespace or cfg.namespace
    path = f"/apis/batch/v1/namespaces/{quote(ns)}/jobs/{quote(name)}"
    status, body = _request("GET", path)
    if status == 200:
        try:
            return status, json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None
    return status, None


def job_terminal_state(job: dict[str, Any]) -> str | None:
    """``'succeeded'`` / ``'failed'`` / ``None`` (still running).

    The chart-bump's migrate Job is helm-hook-managed; we poll until
    it transitions out of running so we can flip the orchestrator's
    run state cleanly."""
    status = job.get("status") or {}
    if int(status.get("succeeded") or 0) >= 1:
        return "succeeded"
    if int(status.get("failed") or 0) >= 1:
        return "failed"
    return None


__all__ = [
    "KubeapiUnavailableError",
    "clear_lease_holder",
    "cordon_node",
    "create_lease",
    "delete_pod",
    "deployment_is_rolled_out",
    "evict_pod",
    "get_cnpg_cluster",
    "get_deployment",
    "get_helmchartconfig",
    "get_job",
    "get_lease",
    "get_node",
    "get_pod_logs",
    "is_node_ready",
    "job_terminal_state",
    "list_nodes",
    "list_pods",
    "list_pods_on_node",
    "patch_cnpg_maintenance_window",
    "patch_deployment_annotation",
    "patch_secret",
    "pod_is_owned_by_daemonset",
    "pod_is_mirror",
    "pod_is_terminal",
    "stream_pod_logs",
    "uncordon_node",
    "update_lease",
    "upsert_helmchartconfig",
]

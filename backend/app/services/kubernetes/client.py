"""Minimal async Kubernetes API client — enough for the Phase 1b reconciler.

We hit three endpoints: ``/api/v1/nodes``, ``/api/v1/services`` (all
namespaces), and ``/apis/networking.k8s.io/v1/ingresses`` (all
namespaces). No watches, no RBAC-sensitive calls, no writes. Just
``httpx.AsyncClient`` with a bearer token + optional CA bundle.

Why not ``kubernetes-asyncio`` / the official client? Overkill for
three GETs + they pull in a lot of transitive dependencies (OpenAPI
generator, swagger parser, ~30 MB of code). The REST shapes we
consume are stable since k8s 1.19.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app.services._mirror_shape import require_keyed_list

logger = structlog.get_logger(__name__)


class KubernetesClientError(Exception):
    """Raised when the k8s API returns an error we can't recover from.

    Subclasses would be nice but the reconciler treats all of them the
    same (log + mark cluster errored), so a single exception keeps the
    call site clean. The message carries the HTTP status / reason.
    """


@dataclass
class _K8sNode:
    name: str
    # First ``InternalIP`` from status.addresses; ``None`` if the node
    # has no reachable IP (shouldn't happen on a healthy node).
    internal_ip: str | None
    ready: bool


@dataclass
class _K8sLBService:
    namespace: str
    name: str
    # LoadBalancer VIPs — usually one but k8s permits multiple. We take
    # the first entry with an IP; hostname-only entries (AWS ELB) are
    # skipped since we can't put a hostname in IPAM. Phase 2 will
    # handle the CNAME case via DNS instead.
    ip: str | None
    hostname: str | None


@dataclass
class _K8sService:
    """Any Service with a ClusterIP, regardless of ``spec.type``.

    Services are stable — one ClusterIP per Service for the Service's
    lifetime — so mirroring them into IPAM is low-churn. Skip
    ``ClusterIP: None`` headless services; they have no IP to mirror.
    """

    namespace: str
    name: str
    cluster_ip: str
    service_type: str  # ClusterIP | LoadBalancer | NodePort | ExternalName


@dataclass
class _K8sPod:
    """A running pod with an assigned pod IP. ``hostIP`` is ignored —
    it's the node IP, already covered by ``list_nodes``.

    We filter for ``status.podIP`` being set (pod scheduled + networked);
    pending pods have no IP yet.
    """

    namespace: str
    name: str
    pod_ip: str
    phase: str  # Running | Pending | Succeeded | Failed | Unknown


@dataclass
class _K8sIngress:
    namespace: str
    name: str
    # Every rule's host, deduped. Empty list = wildcard / default backend
    # ingress — skip in the reconciler.
    hosts: list[str]
    # status.loadBalancer.ingress[0] — what the ingress controller
    # surfaces as the public endpoint. May be an IP (MetalLB) or a
    # hostname (cloud LB, nginx-ingress with a service of type LB).
    target_ip: str | None
    target_hostname: str | None


class KubernetesClient:
    """Per-cluster async client. One instance per reconcile pass.

    Caller is responsible for ``async with`` lifecycle — we hold a
    single ``httpx.AsyncClient`` so the three list calls share a TLS
    session.
    """

    def __init__(self, *, api_server_url: str, token: str, ca_bundle_pem: str = "") -> None:
        self._base = api_server_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        self._ca_bundle_pem = ca_bundle_pem.strip()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> KubernetesClient:
        verify: Any = True
        if self._ca_bundle_pem:
            verify = ssl.create_default_context(cadata=self._ca_bundle_pem)
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers=self._headers,
            verify=verify,
            timeout=20.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _list(self, path: str) -> list[dict[str, Any]]:
        assert self._client is not None, "use within 'async with'"
        # #1560 — follow the ``metadata.continue`` token until it is
        # empty. Reading only the first ``limit=500`` page and treating
        # it as the whole cluster made the reconciler's absence-delete
        # prune every Service / Ingress / node past page one on large
        # clusters. Any failure mid-paging (including a 410 Gone on an
        # expired continue token) raises, so the reconcile aborts
        # instead of pruning against a partial list.
        items: list[dict[str, Any]] = []
        continue_token: str | None = None
        while True:
            params: dict[str, str] = {"limit": "500"}
            if continue_token:
                params["continue"] = continue_token
            try:
                resp = await self._client.get(path, params=params)
            except httpx.HTTPError as exc:
                raise KubernetesClientError(f"{path}: {exc}") from exc
            if resp.status_code in (401, 403):
                raise KubernetesClientError(
                    f"{path}: HTTP {resp.status_code} — RBAC or token issue"
                )
            if resp.status_code >= 400:
                raise KubernetesClientError(f"{path}: HTTP {resp.status_code} {resp.text[:200]}")
            try:
                body = resp.json()
            except ValueError as exc:
                raise KubernetesClientError(f"{path}: non-JSON body: {resp.text[:200]}") from exc
            # #430 — a 200 that isn't a List object (auth-proxy page, Status
            # object, envelope change) must raise, not collapse to [] and purge
            # the whole cluster mirror. A real empty cluster is {"items": []}.
            items.extend(
                require_keyed_list(body, "items", make_error=KubernetesClientError, context=path)
            )
            metadata = body.get("metadata") if isinstance(body, dict) else None
            token = metadata.get("continue") if isinstance(metadata, dict) else None
            if not token:
                return items
            continue_token = str(token)

    # ── Public surface ───────────────────────────────────────────────

    async def list_nodes(self) -> list[_K8sNode]:
        items = await self._list("/api/v1/nodes")
        out: list[_K8sNode] = []
        for item in items:
            name = (item.get("metadata") or {}).get("name") or ""
            status = item.get("status") or {}
            internal_ip: str | None = None
            for addr in status.get("addresses") or []:
                if addr.get("type") == "InternalIP" and addr.get("address"):
                    internal_ip = addr["address"]
                    break
            ready = False
            for cond in status.get("conditions") or []:
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    ready = True
                    break
            if name:
                out.append(_K8sNode(name=name, internal_ip=internal_ip, ready=ready))
        return out

    async def list_loadbalancer_services(self) -> list[_K8sLBService]:
        """Returns only ``spec.type=LoadBalancer`` services with a
        populated ``status.loadBalancer.ingress`` — i.e. the LB has
        been provisioned. Pending (``ingress: []``) services get
        skipped since there's no VIP to mirror yet; they'll appear on
        a subsequent reconcile pass once the LB controller finishes.
        """
        items = await self._list("/api/v1/services")
        out: list[_K8sLBService] = []
        for item in items:
            meta = item.get("metadata") or {}
            spec = item.get("spec") or {}
            status = item.get("status") or {}
            if spec.get("type") != "LoadBalancer":
                continue
            lb = status.get("loadBalancer") or {}
            ingress_entries = lb.get("ingress") or []
            if not ingress_entries:
                continue
            first = ingress_entries[0]
            out.append(
                _K8sLBService(
                    namespace=meta.get("namespace") or "default",
                    name=meta.get("name") or "",
                    ip=first.get("ip"),
                    hostname=first.get("hostname"),
                )
            )
        return out

    async def list_services(self) -> list[_K8sService]:
        """Every Service with a concrete ClusterIP. Headless services
        (``ClusterIP: None``) and ExternalName services (no cluster IP
        at all) are filtered out — there's nothing to mirror.
        """
        items = await self._list("/api/v1/services")
        out: list[_K8sService] = []
        for item in items:
            meta = item.get("metadata") or {}
            spec = item.get("spec") or {}
            cluster_ip = spec.get("clusterIP") or ""
            # "None" (literal string) = headless; "" = not allocated.
            if not cluster_ip or cluster_ip == "None":
                continue
            out.append(
                _K8sService(
                    namespace=meta.get("namespace") or "default",
                    name=meta.get("name") or "",
                    cluster_ip=cluster_ip,
                    service_type=spec.get("type") or "ClusterIP",
                )
            )
        return out

    async def list_pods(self) -> list[_K8sPod]:
        """Every pod with an assigned IP. We list across all namespaces
        and pull ``status.podIP`` — the first IP k8s assigned. Pods with
        no IP yet (Pending + unscheduled) are filtered out.

        Pagination is handled by ``_list`` (#1560): every page is read
        via the ``continue`` token, so busy clusters with >500 pods are
        mirrored in full.
        """
        items = await self._list("/api/v1/pods")
        out: list[_K8sPod] = []
        for item in items:
            meta = item.get("metadata") or {}
            status = item.get("status") or {}
            pod_ip = status.get("podIP") or ""
            if not pod_ip:
                continue
            out.append(
                _K8sPod(
                    namespace=meta.get("namespace") or "default",
                    name=meta.get("name") or "",
                    pod_ip=pod_ip,
                    phase=status.get("phase") or "Unknown",
                )
            )
        return out

    async def list_ingresses(self) -> list[_K8sIngress]:
        items = await self._list("/apis/networking.k8s.io/v1/ingresses")
        out: list[_K8sIngress] = []
        for item in items:
            meta = item.get("metadata") or {}
            spec = item.get("spec") or {}
            status = item.get("status") or {}
            hosts: list[str] = []
            for rule in spec.get("rules") or []:
                host = rule.get("host")
                if host and host not in hosts:
                    hosts.append(host)
            lb = status.get("loadBalancer") or {}
            entries = lb.get("ingress") or []
            target_ip = entries[0].get("ip") if entries else None
            target_hostname = entries[0].get("hostname") if entries else None
            out.append(
                _K8sIngress(
                    namespace=meta.get("namespace") or "default",
                    name=meta.get("name") or "",
                    hosts=hosts,
                    target_ip=target_ip,
                    target_hostname=target_hostname,
                )
            )
        return out


__all__ = [
    "KubernetesClient",
    "KubernetesClientError",
    "_K8sIngress",
    "_K8sLBService",
    "_K8sNode",
    "_K8sPod",
    "_K8sService",
]

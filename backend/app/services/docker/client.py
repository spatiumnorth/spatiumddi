"""Minimal async Docker Engine API client — enough for the reconciler.

We hit three endpoints: ``GET /networks``, ``GET /containers/json``,
``GET /info``. No image/volume/compose — those are Phase 3 management
features that belong on a dedicated detail page.

Why plain ``httpx`` instead of the official ``docker`` SDK? Same
tradeoff as the Kubernetes client — the SDK is sync-first, pulls in
``requests`` + ``websocket-client``, and wraps ~40 endpoints for no
benefit when we consume three. The Engine API surface we read is
stable and has been since Docker 1.30.

Transport options:

  * ``unix://`` — local socket, e.g. ``/var/run/docker.sock``.
                  Requires mounting the host socket into the api
                  container. ``httpx`` handles UDS via
                  ``AsyncHTTPTransport(uds=path)``.
  * ``tcp://host:port`` — remote daemon. If ``ca_bundle_pem`` is
                  set we configure mTLS with the client cert + key;
                  otherwise plain HTTP (the router warns operators
                  off this, but it's legal — you can expose a docker
                  daemon on a trusted LAN).

SSH (``docker -H ssh://``) is explicitly deferred — it needs
paramiko + ``docker system dial-stdio`` stream shuffling, which is
more code than this whole module.
"""

from __future__ import annotations

import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import structlog

from app.core.exc_text import describe_exc
from app.services._mirror_shape import require_list

logger = structlog.get_logger(__name__)


class DockerClientError(Exception):
    """Raised when the Docker daemon returns an error we can't recover from."""


@dataclass
class _DockerNetwork:
    """One Docker network with at least one IPv4 subnet configured.

    Networks without IPAM config (``Config`` empty) are filtered out
    at fetch time since there's nothing to mirror.
    """

    id: str
    name: str
    driver: str  # "bridge" | "overlay" | "macvlan" | "ipvlan" | "host" | "none" | ...
    scope: str  # "local" | "swarm" | "global"
    # One entry per IPAM config block. Normally 1 for IPv4 bridges; 2
    # for dual-stack, etc.
    subnets: list[tuple[str, str]] = field(default_factory=list)
    # Labels — we surface them so the reconciler can tag IPAM rows.
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class _DockerContainer:
    """One container that's attached to at least one bridge-like network
    with an IP. Host-networking containers don't get listed here (no IP
    to mirror). Stopped containers appear only if the reconciler was
    told to include them."""

    id: str
    name: str  # without leading slash
    image: str  # repository:tag as reported
    state: str  # "running" | "exited" | "paused" | ...
    status: str  # "Up 3 days", etc.
    # One entry per connected network with an IP. A container can be
    # on multiple networks — we surface all of them and let the
    # reconciler decide which subnets matter.
    ip_bindings: list[tuple[str, str]] = field(default_factory=list)
    # Compose project + service labels, when present — used by the
    # reconciler to compose a stack/service hostname. The full labels
    # dict is also on ``labels`` below.
    compose_project: str | None = None
    compose_service: str | None = None
    labels: dict[str, str] = field(default_factory=dict)


class DockerClient:
    """Per-host async client. One instance per reconcile pass."""

    def __init__(
        self,
        *,
        connection_type: str,
        endpoint: str,
        ca_bundle_pem: str = "",
        client_cert_pem: str = "",
        client_key_pem: str = "",
    ) -> None:
        self._conn_type = connection_type
        self._endpoint = endpoint
        self._ca_bundle_pem = ca_bundle_pem
        self._client_cert_pem = client_cert_pem
        self._client_key_pem = client_key_pem
        self._client: httpx.AsyncClient | None = None
        self._tmpdir: tempfile.TemporaryDirectory | None = None

    async def __aenter__(self) -> DockerClient:
        transport: httpx.AsyncBaseTransport | None = None
        verify: Any = True
        cert: Any = None

        if self._conn_type == "unix":
            # UDS transport — base_url is just a placeholder host.
            transport = httpx.AsyncHTTPTransport(uds=self._endpoint)
            base_url = "http://docker"
        elif self._conn_type == "tcp":
            use_tls = bool(self._ca_bundle_pem.strip() or self._client_cert_pem.strip())
            scheme = "https" if use_tls else "http"
            endpoint = self._endpoint.strip()
            if "://" in endpoint:
                endpoint = endpoint.split("://", 1)[1]
            base_url = f"{scheme}://{endpoint.rstrip('/')}"
            if use_tls:
                if self._ca_bundle_pem.strip():
                    try:
                        verify = ssl.create_default_context(cadata=self._ca_bundle_pem)
                    except Exception as exc:  # noqa: BLE001
                        raise DockerClientError(f"CA bundle is invalid: {exc}") from exc
                if self._client_cert_pem.strip() and self._client_key_pem.strip():
                    # httpx wants cert/key as file paths; materialize
                    # to a temp dir that we clean up on exit.
                    self._tmpdir = tempfile.TemporaryDirectory()
                    td = Path(self._tmpdir.name)
                    cert_path = td / "cert.pem"
                    key_path = td / "key.pem"
                    cert_path.write_text(self._client_cert_pem)
                    key_path.write_text(self._client_key_pem)
                    # Tighten perms on the private key — best-effort;
                    # on the api container's tmpdir nobody else can
                    # read it anyway, but explicit is better.
                    key_path.chmod(0o600)
                    cert = (str(cert_path), str(key_path))
        else:
            raise DockerClientError(f"unknown connection_type: {self._conn_type}")

        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            verify=verify,
            cert=cert,
            timeout=20.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None

    async def _get(self, path: str, **params: Any) -> Any:
        assert self._client is not None, "use within 'async with'"
        try:
            resp = await self._client.get(path, params=params or None)
        except httpx.HTTPError as exc:
            raise DockerClientError(f"{path}: {describe_exc(exc)}") from exc
        if resp.status_code in (401, 403):
            raise DockerClientError(f"{path}: HTTP {resp.status_code} — TLS / permission issue")
        if resp.status_code >= 400:
            raise DockerClientError(f"{path}: HTTP {resp.status_code} {resp.text[:200]}")
        return resp.json()

    # ── Public surface ───────────────────────────────────────────────

    async def info(self) -> dict[str, Any]:
        return await self._get("/info")

    async def version(self) -> dict[str, Any]:
        return await self._get("/version")

    async def list_networks(self) -> list[_DockerNetwork]:
        """Return networks that carry at least one parseable subnet.

        Networks with an empty ``IPAM.Config`` (e.g. ``host`` / ``none``)
        are skipped — there's nothing to mirror. Swarm overlay networks
        are returned; the reconciler filters them based on
        ``include_default_networks`` / driver.
        """
        # #430 — Docker returns a JSON array on success; a 200 that decodes
        # to {} (proxy/gateway error in front of a tcp:// daemon) must raise,
        # not iterate-to-empty and purge every mirrored Docker subnet/row.
        items = require_list(
            await self._get("/networks"), make_error=DockerClientError, context="/networks"
        )
        out: list[_DockerNetwork] = []
        for item in items:
            ipam = (item.get("IPAM") or {}).get("Config") or []
            subnets: list[tuple[str, str]] = []
            for cfg in ipam:
                subnet = cfg.get("Subnet") or ""
                gateway = cfg.get("Gateway") or ""
                if subnet:
                    subnets.append((subnet, gateway))
            if not subnets:
                continue
            out.append(
                _DockerNetwork(
                    id=item.get("Id") or "",
                    name=item.get("Name") or "",
                    driver=item.get("Driver") or "bridge",
                    scope=item.get("Scope") or "local",
                    subnets=subnets,
                    labels=item.get("Labels") or {},
                )
            )
        return out

    async def list_containers(self, *, include_stopped: bool) -> list[_DockerContainer]:
        """Every container that has at least one network IP assigned."""
        items = require_list(
            await self._get("/containers/json", all=str(include_stopped).lower()),
            make_error=DockerClientError,
            context="/containers/json",
        )
        out: list[_DockerContainer] = []
        for item in items:
            # ``Names`` is a list with a leading slash each. Take the
            # first and strip.
            names = item.get("Names") or []
            name = names[0].lstrip("/") if names else (item.get("Id") or "")[:12]
            networks = ((item.get("NetworkSettings") or {}).get("Networks")) or {}
            bindings: list[tuple[str, str]] = []
            for net_name, net_info in networks.items():
                ip = (net_info or {}).get("IPAddress") or ""
                if ip:
                    bindings.append((net_name, ip))
            if not bindings:
                continue
            labels = item.get("Labels") or {}
            out.append(
                _DockerContainer(
                    id=item.get("Id") or "",
                    name=name,
                    image=item.get("Image") or "",
                    state=item.get("State") or "",
                    status=item.get("Status") or "",
                    ip_bindings=bindings,
                    compose_project=labels.get("com.docker.compose.project"),
                    compose_service=labels.get("com.docker.compose.service"),
                    labels=labels,
                )
            )
        return out


__all__ = [
    "DockerClient",
    "DockerClientError",
    "_DockerContainer",
    "_DockerNetwork",
]

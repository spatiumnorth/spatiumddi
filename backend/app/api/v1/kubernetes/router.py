"""Kubernetes integration CRUD — Phase 1a.

Register / edit / delete per-cluster connection configs, plus a
**Test Connection** probe that validates the service-account token
against the cluster's API server. No sync logic here — the reconciler
lands in Phase 1b as its own Celery task.

Bearer tokens are Fernet-encrypted at rest via
``app.core.crypto.encrypt_str`` alongside other driver credentials.
We never echo the token back in API responses — the admin UI shows
"••• stored" and the operator re-enters it on edit if they want to
rotate.
"""

from __future__ import annotations

import ipaddress
import ssl
import tempfile
import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.header_credentials import header_credential_problem, header_secret
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace
from app.models.kubernetes import KubernetesCluster
from app.services.dns.bundle_dirty import mark_integration_dns_released
from app.services.integration_ownership import release_integration_rows

router = APIRouter(
    tags=["kubernetes"],
    dependencies=[Depends(require_resource_permission("kubernetes_cluster"))],
)

# ── Pydantic schemas ─────────────────────────────────────────────────


class ClusterBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    api_server_url: str
    ca_bundle_pem: str = ""
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    pod_cidr: str = ""
    service_cidr: str = ""
    sync_interval_seconds: int = 60
    mirror_pods: bool = False

    @field_validator("api_server_url")
    @classmethod
    def _must_be_https(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("api_server_url must start with http(s)://")
        return v

    @field_validator("pod_cidr", "service_cidr")
    @classmethod
    def _valid_cidr_or_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            return v
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {exc}") from exc
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        # 30s is the floor — anything tighter starts loading the
        # apiserver meaningfully for multi-cluster deployments.
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class ClusterCreate(ClusterBase):
    token: str  # plaintext; encrypted before persist

    _check_token = field_validator("token")(header_secret)


class ClusterUpdate(BaseModel):
    """Partial update — any unset field is left unchanged.

    ``token`` is optional because rotating isn't always wanted; empty
    string / omitted means "keep the existing token".
    """

    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    api_server_url: str | None = None
    ca_bundle_pem: str | None = None
    token: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    pod_cidr: str | None = None
    service_cidr: str | None = None
    sync_interval_seconds: int | None = None
    mirror_pods: bool | None = None

    _check_token = field_validator("token")(header_secret)


class ClusterResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    api_server_url: str
    # Presence only — never echo the actual cert (long) or the token.
    ca_bundle_present: bool
    token_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    pod_cidr: str
    service_cidr: str
    sync_interval_seconds: int
    mirror_pods: bool
    last_synced_at: datetime | None
    last_sync_error: str | None
    cluster_version: str | None
    node_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    """Dry-run probe — used before the operator saves a new cluster
    (or to re-probe a stored one after editing fields). When an
    existing ``cluster_id`` is supplied, any omitted field falls back
    to the stored value; that way the operator can test without
    re-typing the token or CA bundle.
    """

    cluster_id: uuid.UUID | None = None
    api_server_url: str | None = None
    ca_bundle_pem: str | None = None
    token: str | None = None

    _check_token = field_validator("token")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    version: str | None = None
    node_count: int | None = None


class DetectCIDRsRequest(BaseModel):
    """Same auth shape as TestConnectionRequest — supply stored
    cluster_id to reuse creds, or api_server_url + token + optional
    ca_bundle_pem for a pre-save probe.
    """

    cluster_id: uuid.UUID | None = None
    api_server_url: str | None = None
    ca_bundle_pem: str | None = None
    token: str | None = None

    _check_token = field_validator("token")(header_secret)


class DetectCIDRsResponse(BaseModel):
    pod_cidr: str | None
    service_cidr: str | None
    # Short, human-readable notes about what was tried and why a field
    # may still be empty — surfaced in the UI so the operator knows
    # whether to type the value in.
    messages: list[str]


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(c: KubernetesCluster) -> ClusterResponse:
    return ClusterResponse(
        id=c.id,
        name=c.name,
        description=c.description,
        enabled=c.enabled,
        api_server_url=c.api_server_url,
        ca_bundle_present=bool(c.ca_bundle_pem),
        token_present=bool(c.token_encrypted),
        ipam_space_id=c.ipam_space_id,
        dns_group_id=c.dns_group_id,
        pod_cidr=c.pod_cidr,
        service_cidr=c.service_cidr,
        sync_interval_seconds=c.sync_interval_seconds,
        mirror_pods=c.mirror_pods,
        last_synced_at=c.last_synced_at,
        last_sync_error=c.last_sync_error,
        cluster_version=c.cluster_version,
        node_count=c.node_count,
        created_at=c.created_at,
        modified_at=c.modified_at,
    )


def _require_usable_credentials(api_server_url: str, token: str) -> str:
    """422 for a token that cannot be a bearer token, or a URL httpx cannot
    parse, before a client is built from them (#1913). The token may come
    from the request body or from the stored cluster, so surrounding
    whitespace (a stored token saved with its trailing newline before the
    schema stripped it) is dropped here too. Returns the token to send."""
    token = token.strip()
    problem = header_credential_problem(token, "token")
    if problem:
        raise HTTPException(status_code=422, detail=problem)
    try:
        url = httpx.URL(api_server_url)
    except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"api_server_url is not a valid URL: {exc}")
    if url.scheme not in ("http", "https") or not url.host:
        raise HTTPException(
            status_code=422,
            detail="api_server_url must be an http(s) URL such as https://k8s.example:6443",
        )
    return token


async def _probe_cluster(
    *, api_server_url: str, token: str, ca_bundle_pem: str
) -> TestConnectionResponse:
    """Call ``GET /version`` + ``GET /api/v1/nodes?limit=500`` on the
    cluster with the supplied credentials. Returns a structured result
    — always returns, never raises — so the UI can surface the exact
    error without a generic 500.

    TLS: when ``ca_bundle_pem`` is non-empty we write it to a temp
    file and use it as the verify source; otherwise we fall back to
    the system CA store (cloud-provider clusters with publicly-signed
    API servers work out of the box). We never use
    ``verify=False`` — the operator can always paste the CA; a typo
    shouldn't silently weaken TLS.
    """
    base = api_server_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"}

    verify: Any = True
    ca_file: Any = None
    if ca_bundle_pem.strip():
        try:
            ctx = ssl.create_default_context(cadata=ca_bundle_pem)
            verify = ctx
        except Exception as exc:  # noqa: BLE001
            return TestConnectionResponse(ok=False, message=f"CA bundle is invalid: {exc}")
    try:
        async with httpx.AsyncClient(
            base_url=base, headers=headers, verify=verify, timeout=10.0
        ) as client:
            v = await client.get("/version")
            if v.status_code == 401:
                return TestConnectionResponse(
                    ok=False,
                    message="401 Unauthorized — check the bearer token",
                )
            if v.status_code == 403:
                return TestConnectionResponse(
                    ok=False,
                    message="403 Forbidden — the ServiceAccount has no RBAC for /version",
                )
            v.raise_for_status()
            version_data = v.json()
            version_str = (
                version_data.get("gitVersion") or version_data.get("git_version") or "unknown"
            )

            n = await client.get("/api/v1/nodes", params={"limit": "500"})
            node_count: int | None = None
            if n.status_code == 200:
                node_count = len(n.json().get("items") or [])
            elif n.status_code in (401, 403):
                # Version endpoint worked but /nodes is denied — RBAC
                # is incomplete. Report it inline so the operator can
                # fix the ClusterRole; connectivity is still OK.
                return TestConnectionResponse(
                    ok=False,
                    message=(
                        f"Connected to Kubernetes {version_str} but the "
                        f"ServiceAccount cannot list Nodes "
                        f"(HTTP {n.status_code}). Apply the ClusterRole "
                        "from the setup guide."
                    ),
                    version=version_str,
                )

            return TestConnectionResponse(
                ok=True,
                message=f"Connected to Kubernetes {version_str}",
                version=version_str,
                node_count=node_count,
            )
    except httpx.HTTPStatusError as exc:
        return TestConnectionResponse(
            ok=False, message=f"HTTP {exc.response.status_code} from apiserver"
        )
    except httpx.ConnectError as exc:
        return TestConnectionResponse(ok=False, message=f"Could not reach apiserver: {exc}")
    except ssl.SSLError as exc:
        return TestConnectionResponse(ok=False, message=f"TLS error: {exc}")
    except Exception as exc:  # noqa: BLE001 — surface anything else verbatim
        return TestConnectionResponse(ok=False, message=str(exc))
    finally:
        if ca_file is not None:
            tempfile.TemporaryFile().close()


def _smallest_common_supernet(
    networks: Sequence[ipaddress.IPv4Network] | Sequence[ipaddress.IPv6Network],
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return the smallest network that contains every input network.

    kube-controller-manager hands each node a per-node slice out of
    ``--cluster-cidr`` (usually a /24), so aggregating the slices gets
    us back to the operator-configured supernet. Returns ``None`` if
    the inputs span so much of the address space that the supernet
    would be /0 (effectively nonsense). Caller passes a single-family
    sequence — mixing IPv4 + IPv6 is a type error at the call site.
    """
    if not networks:
        return None
    candidate = networks[0]
    for net in networks[1:]:
        while not net.subnet_of(candidate):  # type: ignore[arg-type]
            if candidate.prefixlen == 0:
                return None
            candidate = candidate.supernet()
    return candidate


async def _detect_cidrs(
    *, api_server_url: str, token: str, ca_bundle_pem: str
) -> DetectCIDRsResponse:
    """Probe the cluster for pod + service CIDRs. Always returns —
    never raises — so partial detection (one field found, one not)
    lands cleanly in the UI.

    Pod CIDR strategy: aggregate every node's ``spec.podCIDRs`` to the
    smallest supernet. CNIs like Cilium / Calico-IPAM leave those
    fields empty and manage pod IPs out-of-band, so detection fails
    silently on those clusters and we tell the operator to enter it.

    Service CIDR strategy: hit the ``ServiceCIDR`` resource, trying
    stable ``networking.k8s.io/v1`` (k8s 1.33+) → ``v1beta1`` (1.31+)
    → ``v1alpha1`` (1.29+). Each ``ServiceCIDR`` carries a
    ``spec.cidrs`` list; we pick the first IPv4 entry (or first entry
    overall). Clusters older than 1.29 or with the feature gate off
    return 404 on all three — operator types it in.
    """
    base = api_server_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"}

    verify: Any = True
    if ca_bundle_pem.strip():
        try:
            verify = ssl.create_default_context(cadata=ca_bundle_pem)
        except Exception as exc:  # noqa: BLE001
            return DetectCIDRsResponse(
                pod_cidr=None,
                service_cidr=None,
                messages=[f"CA bundle is invalid: {exc}"],
            )

    messages: list[str] = []
    pod_cidr: str | None = None
    service_cidr: str | None = None

    try:
        async with httpx.AsyncClient(
            base_url=base, headers=headers, verify=verify, timeout=15.0
        ) as client:
            # ── Pod CIDR from Node.spec.podCIDRs ──────────────────────
            try:
                resp = await client.get("/api/v1/nodes", params={"limit": "500"})
                if resp.status_code >= 400:
                    messages.append(f"Could not list Nodes for pod CIDR (HTTP {resp.status_code}).")
                else:
                    v4_nets: list[ipaddress.IPv4Network] = []
                    v6_nets: list[ipaddress.IPv6Network] = []
                    for item in resp.json().get("items") or []:
                        spec = item.get("spec") or {}
                        cidrs = list(spec.get("podCIDRs") or [])
                        legacy = spec.get("podCIDR")
                        if legacy and legacy not in cidrs:
                            cidrs.append(legacy)
                        for c in cidrs:
                            try:
                                net = ipaddress.ip_network(c, strict=False)
                            except ValueError:
                                continue
                            if isinstance(net, ipaddress.IPv4Network):
                                v4_nets.append(net)
                            else:
                                v6_nets.append(net)
                    # Prefer IPv4 — matches the pod_cidr column's v4 bias.
                    picked = _smallest_common_supernet(v4_nets) or _smallest_common_supernet(
                        v6_nets
                    )
                    if picked is not None:
                        pod_cidr = str(picked)
                        if v4_nets and v6_nets:
                            messages.append(
                                "Cluster is dual-stack — using IPv4 pod CIDR; v6 not recorded."
                            )
                    else:
                        messages.append(
                            "Nodes have no spec.podCIDRs — CNIs like Cilium / Calico-IPAM "
                            "manage pod IPs out-of-band. Enter the pod CIDR manually."
                        )
            except httpx.HTTPError as exc:
                messages.append(f"Pod CIDR probe failed: {exc}")

            # ── Service CIDR from ServiceCIDR resource ────────────────
            sc_paths = [
                ("v1", "/apis/networking.k8s.io/v1/servicecidrs"),
                ("v1beta1", "/apis/networking.k8s.io/v1beta1/servicecidrs"),
                ("v1alpha1", "/apis/networking.k8s.io/v1alpha1/servicecidrs"),
            ]
            sc_found = False
            for version, path in sc_paths:
                try:
                    resp = await client.get(path, params={"limit": "50"})
                except httpx.HTTPError as exc:
                    messages.append(f"Service CIDR probe ({version}) failed: {exc}")
                    continue
                if resp.status_code == 404:
                    continue
                if resp.status_code in (401, 403):
                    messages.append(
                        f"Service CIDR probe ({version}) denied (HTTP {resp.status_code}) "
                        "— add 'servicecidrs' to the ClusterRole to auto-detect."
                    )
                    break
                if resp.status_code >= 400:
                    messages.append(f"Service CIDR probe ({version}) HTTP {resp.status_code}.")
                    continue
                v4: str | None = None
                v6: str | None = None
                for item in resp.json().get("items") or []:
                    for c in (item.get("spec") or {}).get("cidrs") or []:
                        try:
                            net = ipaddress.ip_network(c, strict=False)
                        except ValueError:
                            continue
                        if isinstance(net, ipaddress.IPv4Network) and v4 is None:
                            v4 = str(net)
                        elif isinstance(net, ipaddress.IPv6Network) and v6 is None:
                            v6 = str(net)
                service_cidr = v4 or v6
                sc_found = True
                break
            if not sc_found and service_cidr is None:
                messages.append(
                    "ServiceCIDR API not available (pre-1.29 or feature-gate off) — "
                    "enter the service CIDR manually."
                )

    except httpx.ConnectError as exc:
        return DetectCIDRsResponse(
            pod_cidr=None,
            service_cidr=None,
            messages=[f"Could not reach apiserver: {exc}"],
        )
    except ssl.SSLError as exc:
        return DetectCIDRsResponse(
            pod_cidr=None,
            service_cidr=None,
            messages=[f"TLS error: {exc}"],
        )
    except Exception as exc:  # noqa: BLE001 — honour "never raises" (#1913)
        # e.g. httpx refusing to build the client from a header value it
        # cannot encode; keep whatever was detected before the failure.
        messages.append(f"Detection failed: {exc}")

    return DetectCIDRsResponse(
        pod_cidr=pod_cidr,
        service_cidr=service_cidr,
        messages=messages,
    )


async def _validate_bindings(
    db: Any, ipam_space_id: uuid.UUID, dns_group_id: uuid.UUID | None
) -> None:
    """Fail early with 422 if the operator points at a missing space /
    group instead of letting Postgres raise a FK violation."""
    space = await db.get(IPSpace, ipam_space_id)
    if space is None:
        raise HTTPException(status_code=422, detail="ipam_space_id not found")
    if dns_group_id is not None:
        group = await db.get(DNSServerGroup, dns_group_id)
        if group is None:
            raise HTTPException(status_code=422, detail="dns_group_id not found")


def _audit(
    db: Any,
    *,
    user: Any,
    action: str,
    cluster_id: uuid.UUID,
    cluster_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="kubernetes_cluster",
            resource_id=str(cluster_id),
            resource_display=cluster_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/clusters", response_model=list[ClusterResponse])
async def list_clusters(db: DB, _: CurrentUser) -> list[ClusterResponse]:
    res = await db.execute(select(KubernetesCluster).order_by(KubernetesCluster.name))
    return [_to_response(c) for c in res.scalars().all()]


@router.post(
    "/clusters",
    response_model=ClusterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_cluster(body: ClusterCreate, db: DB, user: SuperAdmin) -> ClusterResponse:
    forbid_in_demo_mode("Kubernetes cluster registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    # Name uniqueness — better error than the pg integrity violation.
    existing = await db.execute(
        select(KubernetesCluster).where(KubernetesCluster.name == body.name)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A cluster with that name exists")

    c = KubernetesCluster(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        api_server_url=body.api_server_url,
        ca_bundle_pem=body.ca_bundle_pem,
        token_encrypted=encrypt_str(body.token),
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        pod_cidr=body.pod_cidr,
        service_cidr=body.service_cidr,
        sync_interval_seconds=body.sync_interval_seconds,
        mirror_pods=body.mirror_pods,
    )
    db.add(c)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        cluster_id=c.id,
        cluster_name=c.name,
        new_value=body.model_dump(mode="json", exclude={"token"}),
    )
    await db.commit()
    await db.refresh(c)
    return _to_response(c)


@router.put("/clusters/{cluster_id}", response_model=ClusterResponse)
async def update_cluster(
    cluster_id: uuid.UUID, body: ClusterUpdate, db: DB, user: SuperAdmin
) -> ClusterResponse:
    c = await db.get(KubernetesCluster, cluster_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Cluster not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", c.ipam_space_id)
    new_dns = changes.get("dns_group_id", c.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "token":
            if v:
                c.token_encrypted = encrypt_str(v)
        else:
            setattr(c, k, v)

    _audit(
        db,
        user=user,
        action="update",
        cluster_id=c.id,
        cluster_name=c.name,
        changed_fields=list(changes.keys()),
        # Strip secrets from the audit row — ``token`` value never
        # leaves the commit boundary.
        new_value={k: v for k, v in changes.items() if k != "token"},
    )
    await db.commit()
    await db.refresh(c)
    return _to_response(c)


@router.delete("/clusters/{cluster_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_cluster(cluster_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    c = await db.get(KubernetesCluster, cluster_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    _audit(
        db,
        user=user,
        action="delete",
        cluster_id=c.id,
        cluster_name=c.name,
    )
    # #2287 — hand back operator-made rows in mirrored subnets / blocks before
    # the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="kubernetes_cluster_id", target_id=c.id, user=user, target_name=c.name
    )
    # #2288 — the DNS rows cascade in the database; mark their groups' bundles dirty.
    await mark_integration_dns_released(db, own_fk="kubernetes_cluster_id", target_id=c.id)
    await db.delete(c)
    await db.commit()


@router.post(
    "/clusters/{cluster_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_cluster(cluster_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    """Queue an on-demand reconcile for this cluster.

    Fire-and-forget — the reconciler runs on the worker and updates
    ``last_synced_at`` / ``last_sync_error`` on the cluster row when
    it's done. UI polls the list endpoint to see the result.
    """
    c = await db.get(KubernetesCluster, cluster_id)
    if c is None:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Deferred import — keeps the router module cheap to import.
    add_trigger_audit(
        db,
        user,
        resource_type="kubernetes_cluster",
        resource_id=c.id,
        resource_display=str(getattr(c, "name", None) or c.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.kubernetes_sync import sync_cluster_now  # noqa: PLC0415

    try:
        result = sync_cluster_now.delay(str(c.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        # Broker down — the periodic sweep will catch up.
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post(
    "/clusters/test",
    response_model=TestConnectionResponse,
)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    """Probe a cluster's API server with the supplied (or stored) creds.

    Called from the admin UI's "Test Connection" button both pre-save
    (body carries api_server_url + token + ca_bundle_pem) and post-save
    (body carries ``cluster_id`` only → we use the stored values).
    """
    api_server_url = body.api_server_url
    ca_bundle_pem = body.ca_bundle_pem
    token = body.token

    if body.cluster_id is not None:
        stored = await db.get(KubernetesCluster, body.cluster_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
        api_server_url = api_server_url or stored.api_server_url
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        if not token:
            try:
                token = decrypt_str(stored.token_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored token could not be decrypted — re-enter it",
                ) from exc

    if not api_server_url or not token:
        raise HTTPException(
            status_code=422,
            detail="api_server_url and token are required (either in body or via stored cluster_id)",
        )

    token = _require_usable_credentials(api_server_url, token)

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved API
    # server IP so operators can audit what the control plane dialed.
    # Not hard-blocked: a co-located k3s appliance legitimately points
    # at an on-box / RFC1918 API server.
    assert_safe_target(api_server_url, label="kubernetes")

    result = await _probe_cluster(
        api_server_url=api_server_url,
        token=token,
        ca_bundle_pem=ca_bundle_pem or "",
    )

    # When probing a stored cluster, persist the version / node_count
    # so the list page shows fresh values without waiting for sync.
    if body.cluster_id is not None and result.ok:
        stored = await db.get(KubernetesCluster, body.cluster_id)
        if stored is not None:
            stored.cluster_version = result.version
            stored.node_count = result.node_count
            stored.last_sync_error = None
            await db.commit()

    return result


@router.post(
    "/clusters/detect-cidrs",
    response_model=DetectCIDRsResponse,
)
async def detect_cidrs(body: DetectCIDRsRequest, db: DB, _: SuperAdmin) -> DetectCIDRsResponse:
    """Probe the cluster for pod + service CIDRs so the operator can
    fill the modal with one click instead of typing them.
    """
    api_server_url = body.api_server_url
    ca_bundle_pem = body.ca_bundle_pem
    token = body.token

    if body.cluster_id is not None:
        stored = await db.get(KubernetesCluster, body.cluster_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Cluster not found")
        api_server_url = api_server_url or stored.api_server_url
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        if not token:
            try:
                token = decrypt_str(stored.token_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored token could not be decrypted — re-enter it",
                ) from exc

    if not api_server_url or not token:
        raise HTTPException(
            status_code=422,
            detail="api_server_url and token are required (either in body or via stored cluster_id)",
        )

    token = _require_usable_credentials(api_server_url, token)

    return await _detect_cidrs(
        api_server_url=api_server_url,
        token=token,
        ca_bundle_pem=ca_bundle_pem or "",
    )


__all__ = ["router"]

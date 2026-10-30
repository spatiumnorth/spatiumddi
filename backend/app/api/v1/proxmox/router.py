"""Proxmox VE integration CRUD + probe endpoints.

Parallels ``app/api/v1/docker/router.py``. Token secret is
Fernet-encrypted at rest; admin-only surface.
"""

from __future__ import annotations

import ssl
import uuid
from datetime import datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.celery_dispatch import dispatch
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.header_credentials import header_secret
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace
from app.models.proxmox import ProxmoxNode
from app.services.backup.targets.base import describe_exc
from app.services.integration_ownership import release_integration_rows

router = APIRouter(
    tags=["proxmox"],
    dependencies=[Depends(require_resource_permission("proxmox_node"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


class NodeBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    host: str
    port: int = 8006
    verify_tls: bool = True
    ca_bundle_pem: str = ""
    token_id: str
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    mirror_vms: bool = True
    mirror_lxc: bool = True
    include_stopped: bool = False
    infer_vnet_subnets: bool = False
    sync_interval_seconds: int = 120

    @field_validator("host")
    @classmethod
    def _strip_host(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("host is required")
        # Strip any scheme + trailing slash the operator may have
        # pasted — we always use https and the fixed /api2/json path.
        if "://" in v:
            v = v.split("://", 1)[1]
        return v.rstrip("/")

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("port must be in 1..65535")
        return v

    @field_validator("token_id")
    @classmethod
    def _valid_token_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("token_id is required (e.g. root@pam!spatiumddi)")
        if "@" not in v or "!" not in v:
            raise ValueError("token_id must be 'user@realm!tokenid' (e.g. root@pam!spatiumddi)")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v

    _check_token_id = field_validator("token_id")(header_secret)


class NodeCreate(NodeBase):
    # The PVE token secret (UUID). Encrypted before persist. Required
    # on create.
    token_secret: str

    @field_validator("token_secret")
    @classmethod
    def _valid_token_secret(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("token_secret is required")
        return v

    _check_token_secret = field_validator("token_secret")(header_secret)


class NodeUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    token_id: str | None = None
    # Omit or send empty to keep the stored secret; non-empty rotates.
    token_secret: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_vms: bool | None = None
    mirror_lxc: bool | None = None
    include_stopped: bool | None = None
    infer_vnet_subnets: bool | None = None
    sync_interval_seconds: int | None = None

    _check_token_id = field_validator("token_id")(header_secret)
    _check_token_secret = field_validator("token_secret")(header_secret)


class NodeResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    host: str
    port: int
    verify_tls: bool
    ca_bundle_present: bool
    token_id: str
    token_secret_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    mirror_vms: bool
    mirror_lxc: bool
    include_stopped: bool
    infer_vnet_subnets: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    pve_version: str | None
    cluster_name: str | None
    node_count: int | None
    # Populated by the reconciler on every successful pass — drives the
    # "Discovery" modal in the admin page. Opaque to the API; see
    # services/proxmox/reconcile.py::_build_discovery_payload for shape.
    last_discovery: dict | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    node_id: uuid.UUID | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    token_id: str | None = None
    token_secret: str | None = None

    _check_token_id = field_validator("token_id")(header_secret)
    _check_token_secret = field_validator("token_secret")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    pve_version: str | None = None
    cluster_name: str | None = None
    node_count: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(n: ProxmoxNode) -> NodeResponse:
    return NodeResponse(
        id=n.id,
        name=n.name,
        description=n.description,
        enabled=n.enabled,
        host=n.host,
        port=n.port,
        verify_tls=n.verify_tls,
        ca_bundle_present=bool(n.ca_bundle_pem),
        token_id=n.token_id,
        token_secret_present=bool(n.token_secret_encrypted),
        ipam_space_id=n.ipam_space_id,
        dns_group_id=n.dns_group_id,
        mirror_vms=n.mirror_vms,
        mirror_lxc=n.mirror_lxc,
        include_stopped=n.include_stopped,
        infer_vnet_subnets=n.infer_vnet_subnets,
        sync_interval_seconds=n.sync_interval_seconds,
        last_synced_at=n.last_synced_at,
        last_sync_error=n.last_sync_error,
        pve_version=n.pve_version,
        cluster_name=n.cluster_name,
        node_count=n.node_count,
        last_discovery=n.last_discovery,
        created_at=n.created_at,
        modified_at=n.modified_at,
    )


async def _probe(
    *,
    host: str,
    port: int,
    verify_tls: bool,
    ca_bundle_pem: str,
    token_id: str,
    token_secret: str,
) -> TestConnectionResponse:
    """Probe PVE. Always returns a structured result; never raises.

    Hits ``/version`` for authn + version, then ``/cluster/status`` for
    cluster-name + node-count (or falls back to ``/nodes`` for
    standalone hosts). Distinguishes 401 / 403 / TLS / connect errors
    with human-readable messages.
    """
    verify: Any = verify_tls
    if verify_tls and ca_bundle_pem.strip():
        try:
            verify = ssl.create_default_context(cadata=ca_bundle_pem)
        except Exception as exc:  # noqa: BLE001
            return TestConnectionResponse(ok=False, message=f"CA bundle is invalid: {exc}")

    base_url = f"https://{host}:{port}/api2/json"
    headers = {
        "Authorization": f"PVEAPIToken={token_id}={token_secret}",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            base_url=base_url, headers=headers, verify=verify, timeout=10.0
        ) as client:
            v = await client.get("/version")
            if v.status_code == 401:
                return TestConnectionResponse(
                    ok=False, message="HTTP 401 — token invalid or revoked"
                )
            if v.status_code == 403:
                return TestConnectionResponse(
                    ok=False,
                    message="HTTP 403 — token ACL denies /version (grant PVEAuditor or similar)",
                )
            v.raise_for_status()
            version_data = (v.json() or {}).get("data") or {}
            pve_version = str(version_data.get("version") or "unknown")

            cluster_name: str | None = None
            node_count = 0
            try:
                c = await client.get("/cluster/status")
                if c.status_code < 400:
                    items = (c.json() or {}).get("data") or []
                    for item in items:
                        if item.get("type") == "cluster":
                            cluster_name = str(item.get("name") or "") or None
                        elif item.get("type") == "node":
                            node_count += 1
            except httpx.HTTPError:
                pass
            if node_count == 0:
                try:
                    n = await client.get("/nodes")
                    if n.status_code < 400:
                        nodes = (n.json() or {}).get("data") or []
                        node_count = len(nodes)
                except httpx.HTTPError:
                    pass

            summary = f"Connected to Proxmox VE {pve_version}"
            if cluster_name:
                summary += f" (cluster {cluster_name}, {node_count} nodes)"
            elif node_count:
                summary += f" ({node_count} node{'s' if node_count != 1 else ''})"
            return TestConnectionResponse(
                ok=True,
                message=summary,
                pve_version=pve_version,
                cluster_name=cluster_name,
                node_count=node_count or None,
            )
    except httpx.HTTPStatusError as exc:
        return TestConnectionResponse(ok=False, message=f"HTTP {exc.response.status_code} from PVE")
    except httpx.ConnectError as exc:
        return TestConnectionResponse(ok=False, message=f"Could not reach PVE: {describe_exc(exc)}")
    except ssl.SSLError as exc:
        return TestConnectionResponse(
            ok=False,
            message=(
                f"TLS error: {exc}. Upload the PVE CA bundle, or disable "
                f"verify_tls for a self-signed lab host."
            ),
        )
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))


async def _validate_bindings(
    db: Any, ipam_space_id: uuid.UUID, dns_group_id: uuid.UUID | None
) -> None:
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
    node_id: uuid.UUID,
    node_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="proxmox_node",
            resource_id=str(node_id),
            resource_display=node_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/nodes", response_model=list[NodeResponse])
async def list_nodes(db: DB, _: CurrentUser) -> list[NodeResponse]:
    res = await db.execute(select(ProxmoxNode).order_by(ProxmoxNode.name))
    return [_to_response(n) for n in res.scalars().all()]


@router.post(
    "/nodes",
    response_model=NodeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_node(body: NodeCreate, db: DB, user: SuperAdmin) -> NodeResponse:
    forbid_in_demo_mode("Proxmox endpoint registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    existing = await db.execute(select(ProxmoxNode).where(ProxmoxNode.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A Proxmox endpoint with that name exists")

    n = ProxmoxNode(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        host=body.host,
        port=body.port,
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
        token_id=body.token_id,
        token_secret_encrypted=encrypt_str(body.token_secret),
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        mirror_vms=body.mirror_vms,
        mirror_lxc=body.mirror_lxc,
        include_stopped=body.include_stopped,
        infer_vnet_subnets=body.infer_vnet_subnets,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(n)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        node_id=n.id,
        node_name=n.name,
        new_value=body.model_dump(mode="json", exclude={"token_secret"}),
    )
    await db.commit()
    await db.refresh(n)
    return _to_response(n)


@router.put("/nodes/{node_id}", response_model=NodeResponse)
async def update_node(
    node_id: uuid.UUID, body: NodeUpdate, db: DB, user: SuperAdmin
) -> NodeResponse:
    n = await db.get(ProxmoxNode, node_id)
    if n is None:
        raise HTTPException(status_code=404, detail="Proxmox endpoint not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", n.ipam_space_id)
    new_dns = changes.get("dns_group_id", n.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "token_secret":
            if v:
                n.token_secret_encrypted = encrypt_str(v)
        else:
            setattr(n, k, v)

    _audit(
        db,
        user=user,
        action="update",
        node_id=n.id,
        node_name=n.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k != "token_secret"},
    )
    await db.commit()
    await db.refresh(n)
    return _to_response(n)


@router.delete("/nodes/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_node(node_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    n = await db.get(ProxmoxNode, node_id)
    if n is None:
        raise HTTPException(status_code=404, detail="Proxmox endpoint not found")
    _audit(db, user=user, action="delete", node_id=n.id, node_name=n.name)
    # #2287 — hand back operator-made rows in mirrored subnets / blocks before
    # the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="proxmox_node_id", target_id=n.id, user=user, target_name=n.name
    )
    await db.delete(n)
    await db.commit()


@router.post(
    "/nodes/{node_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_node(node_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    n = await db.get(ProxmoxNode, node_id)
    if n is None:
        raise HTTPException(status_code=404, detail="Proxmox endpoint not found")

    add_trigger_audit(
        db,
        user,
        resource_type="proxmox_node",
        resource_id=n.id,
        resource_display=str(getattr(n, "name", None) or n.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.proxmox_sync import sync_node_now  # noqa: PLC0415

    try:
        result = await dispatch(sync_node_now, str(n.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/nodes/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    host = body.host
    port = body.port or 8006
    verify_tls = body.verify_tls if body.verify_tls is not None else True
    ca_bundle_pem = body.ca_bundle_pem
    token_id = body.token_id
    token_secret = body.token_secret

    if body.node_id is not None:
        stored = await db.get(ProxmoxNode, body.node_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Proxmox endpoint not found")
        host = host or stored.host
        port = body.port or stored.port
        verify_tls = body.verify_tls if body.verify_tls is not None else stored.verify_tls
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        token_id = token_id or stored.token_id
        if not token_secret and stored.token_secret_encrypted:
            try:
                token_secret = decrypt_str(stored.token_secret_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored token secret could not be decrypted — re-enter it",
                ) from exc

    if not host or not token_id or not token_secret:
        raise HTTPException(
            status_code=422,
            detail="host, token_id, and token_secret are required (either in body or via stored node_id)",
        )

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved
    # Proxmox host IP. Not hard-blocked: PVE hosts are almost always on
    # the RFC1918 LAN.
    assert_safe_target(host, label="proxmox")

    result = await _probe(
        host=host,
        port=port,
        verify_tls=verify_tls,
        ca_bundle_pem=ca_bundle_pem or "",
        token_id=token_id,
        token_secret=token_secret,
    )

    if body.node_id is not None and result.ok:
        stored = await db.get(ProxmoxNode, body.node_id)
        if stored is not None:
            stored.pve_version = result.pve_version
            stored.cluster_name = result.cluster_name
            stored.node_count = result.node_count
            stored.last_sync_error = None
            await db.commit()

    return result


__all__ = ["router"]

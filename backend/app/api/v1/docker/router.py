"""Docker integration CRUD + probe endpoints.

Parallels ``app/api/v1/kubernetes/router.py`` — the shape is
deliberate so the admin UI can reuse the same patterns. TLS client
keys are Fernet-encrypted at rest alongside Kubernetes bearer
tokens and driver credentials.
"""

from __future__ import annotations

import ssl
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
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
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.docker import DockerHost
from app.models.ipam import IPSpace
from app.services.backup.targets.base import describe_exc
from app.services.integration_ownership import release_integration_rows

router = APIRouter(
    tags=["docker"],
    dependencies=[Depends(require_resource_permission("docker_host"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


_CONNECTION_TYPES = {"unix", "tcp"}


class HostBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    connection_type: str = "tcp"
    endpoint: str
    ca_bundle_pem: str = ""
    client_cert_pem: str = ""
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    mirror_containers: bool = False
    include_default_networks: bool = False
    include_stopped_containers: bool = False
    sync_interval_seconds: int = 60

    @field_validator("connection_type")
    @classmethod
    def _valid_conn(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _CONNECTION_TYPES:
            raise ValueError(f"connection_type must be one of {sorted(_CONNECTION_TYPES)}")
        return v

    @field_validator("endpoint")
    @classmethod
    def _strip_endpoint(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("endpoint is required")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class HostCreate(HostBase):
    # Plaintext — encrypted before persist. Empty string = no client
    # cert (e.g. unencrypted TCP or mTLS-disabled unix socket).
    client_key_pem: str = ""


class HostUpdate(BaseModel):
    """Partial update. Any unset field is left unchanged. Sending
    ``client_key_pem`` with a non-empty value rotates the key; empty
    string or omitted means "keep the stored key".
    """

    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    connection_type: str | None = None
    endpoint: str | None = None
    ca_bundle_pem: str | None = None
    client_cert_pem: str | None = None
    client_key_pem: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_containers: bool | None = None
    include_default_networks: bool | None = None
    include_stopped_containers: bool | None = None
    sync_interval_seconds: int | None = None


class HostResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    connection_type: str
    endpoint: str
    ca_bundle_present: bool
    client_cert_present: bool
    client_key_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    mirror_containers: bool
    include_default_networks: bool
    include_stopped_containers: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    engine_version: str | None
    container_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    host_id: uuid.UUID | None = None
    connection_type: str | None = None
    endpoint: str | None = None
    ca_bundle_pem: str | None = None
    client_cert_pem: str | None = None
    client_key_pem: str | None = None


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    engine_version: str | None = None
    container_count: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(h: DockerHost) -> HostResponse:
    return HostResponse(
        id=h.id,
        name=h.name,
        description=h.description,
        enabled=h.enabled,
        connection_type=h.connection_type,
        endpoint=h.endpoint,
        ca_bundle_present=bool(h.ca_bundle_pem),
        client_cert_present=bool(h.client_cert_pem),
        client_key_present=bool(h.client_key_encrypted),
        ipam_space_id=h.ipam_space_id,
        dns_group_id=h.dns_group_id,
        mirror_containers=h.mirror_containers,
        include_default_networks=h.include_default_networks,
        include_stopped_containers=h.include_stopped_containers,
        sync_interval_seconds=h.sync_interval_seconds,
        last_synced_at=h.last_synced_at,
        last_sync_error=h.last_sync_error,
        engine_version=h.engine_version,
        container_count=h.container_count,
        created_at=h.created_at,
        modified_at=h.modified_at,
    )


async def _probe(
    *,
    connection_type: str,
    endpoint: str,
    ca_bundle_pem: str,
    client_cert_pem: str,
    client_key_pem: str,
) -> TestConnectionResponse:
    """Probe the Docker daemon. Always returns a structured result;
    never raises.
    """
    transport: httpx.AsyncBaseTransport | None = None
    verify: Any = True
    cert: Any = None
    base_url: str
    tmpdir: tempfile.TemporaryDirectory | None = None

    try:
        if connection_type == "unix":
            transport = httpx.AsyncHTTPTransport(uds=endpoint)
            base_url = "http://docker"
        elif connection_type == "tcp":
            use_tls = bool(ca_bundle_pem.strip() or client_cert_pem.strip())
            scheme = "https" if use_tls else "http"
            ep = endpoint.strip()
            if "://" in ep:
                ep = ep.split("://", 1)[1]
            base_url = f"{scheme}://{ep.rstrip('/')}"
            if ca_bundle_pem.strip():
                try:
                    verify = ssl.create_default_context(cadata=ca_bundle_pem)
                except Exception as exc:  # noqa: BLE001
                    return TestConnectionResponse(ok=False, message=f"CA bundle is invalid: {exc}")
            if client_cert_pem.strip() and client_key_pem.strip():
                tmpdir = tempfile.TemporaryDirectory()
                td = Path(tmpdir.name)
                cp = td / "cert.pem"
                kp = td / "key.pem"
                cp.write_text(client_cert_pem)
                kp.write_text(client_key_pem)
                kp.chmod(0o600)
                cert = (str(cp), str(kp))
        else:
            return TestConnectionResponse(
                ok=False, message=f"unknown connection_type: {connection_type}"
            )

        try:
            async with httpx.AsyncClient(
                base_url=base_url,
                transport=transport,
                verify=verify,
                cert=cert,
                timeout=10.0,
            ) as client:
                v = await client.get("/version")
                if v.status_code in (401, 403):
                    return TestConnectionResponse(
                        ok=False,
                        message=f"HTTP {v.status_code} — credentials rejected",
                    )
                v.raise_for_status()
                version_data = v.json()
                engine_version = version_data.get("Version") or "unknown"

                info_resp = await client.get("/info")
                container_count: int | None = None
                if info_resp.status_code == 200:
                    container_count = int(info_resp.json().get("Containers") or 0)

                return TestConnectionResponse(
                    ok=True,
                    message=f"Connected to Docker {engine_version}",
                    engine_version=engine_version,
                    container_count=container_count,
                )
        except httpx.HTTPStatusError as exc:
            return TestConnectionResponse(
                ok=False, message=f"HTTP {exc.response.status_code} from daemon"
            )
        except httpx.ConnectError as exc:
            return TestConnectionResponse(
                ok=False, message=f"Could not reach daemon: {describe_exc(exc)}"
            )
        except ssl.SSLError as exc:
            return TestConnectionResponse(ok=False, message=f"TLS error: {exc}")
        except Exception as exc:  # noqa: BLE001
            return TestConnectionResponse(ok=False, message=str(exc))
    finally:
        if tmpdir is not None:
            tmpdir.cleanup()


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
    host_id: uuid.UUID,
    host_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="docker_host",
            resource_id=str(host_id),
            resource_display=host_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/hosts", response_model=list[HostResponse])
async def list_hosts(db: DB, _: CurrentUser) -> list[HostResponse]:
    res = await db.execute(select(DockerHost).order_by(DockerHost.name))
    return [_to_response(h) for h in res.scalars().all()]


@router.post(
    "/hosts",
    response_model=HostResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_host(body: HostCreate, db: DB, user: SuperAdmin) -> HostResponse:
    forbid_in_demo_mode("Docker host registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    existing = await db.execute(select(DockerHost).where(DockerHost.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A host with that name exists")

    h = DockerHost(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        connection_type=body.connection_type,
        endpoint=body.endpoint,
        ca_bundle_pem=body.ca_bundle_pem,
        client_cert_pem=body.client_cert_pem,
        client_key_encrypted=encrypt_str(body.client_key_pem) if body.client_key_pem else b"",
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        mirror_containers=body.mirror_containers,
        include_default_networks=body.include_default_networks,
        include_stopped_containers=body.include_stopped_containers,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(h)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        host_id=h.id,
        host_name=h.name,
        new_value=body.model_dump(mode="json", exclude={"client_key_pem"}),
    )
    await db.commit()
    await db.refresh(h)
    return _to_response(h)


@router.put("/hosts/{host_id}", response_model=HostResponse)
async def update_host(
    host_id: uuid.UUID, body: HostUpdate, db: DB, user: SuperAdmin
) -> HostResponse:
    h = await db.get(DockerHost, host_id)
    if h is None:
        raise HTTPException(status_code=404, detail="Host not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", h.ipam_space_id)
    new_dns = changes.get("dns_group_id", h.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "client_key_pem":
            if v:
                h.client_key_encrypted = encrypt_str(v)
        else:
            setattr(h, k, v)

    _audit(
        db,
        user=user,
        action="update",
        host_id=h.id,
        host_name=h.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k != "client_key_pem"},
    )
    await db.commit()
    await db.refresh(h)
    return _to_response(h)


@router.delete("/hosts/{host_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_host(host_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    h = await db.get(DockerHost, host_id)
    if h is None:
        raise HTTPException(status_code=404, detail="Host not found")
    _audit(db, user=user, action="delete", host_id=h.id, host_name=h.name)
    # #2287 — hand back operator-made rows in mirrored subnets / blocks before
    # the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="docker_host_id", target_id=h.id, user=user, target_name=h.name
    )
    await db.delete(h)
    await db.commit()


@router.post(
    "/hosts/{host_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_host(host_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    h = await db.get(DockerHost, host_id)
    if h is None:
        raise HTTPException(status_code=404, detail="Host not found")

    add_trigger_audit(
        db,
        user,
        resource_type="docker_host",
        resource_id=h.id,
        resource_display=str(getattr(h, "name", None) or h.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.docker_sync import sync_host_now  # noqa: PLC0415

    try:
        result = await dispatch(sync_host_now, str(h.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/hosts/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    connection_type = body.connection_type
    endpoint = body.endpoint
    ca_bundle_pem = body.ca_bundle_pem
    client_cert_pem = body.client_cert_pem
    client_key_pem = body.client_key_pem

    if body.host_id is not None:
        stored = await db.get(DockerHost, body.host_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Host not found")
        connection_type = connection_type or stored.connection_type
        endpoint = endpoint or stored.endpoint
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        client_cert_pem = client_cert_pem if client_cert_pem is not None else stored.client_cert_pem
        if not client_key_pem and stored.client_key_encrypted:
            try:
                client_key_pem = decrypt_str(stored.client_key_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored client key could not be decrypted — re-enter it",
                ) from exc

    if not connection_type or not endpoint:
        raise HTTPException(
            status_code=422,
            detail="connection_type and endpoint are required (either in body or via stored host_id)",
        )

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved docker
    # daemon IP. Not hard-blocked: docker hosts are routinely on the LAN
    # (RFC1918) or a unix-socket endpoint (no network host to resolve).
    assert_safe_target(endpoint, label="docker")

    result = await _probe(
        connection_type=connection_type,
        endpoint=endpoint,
        ca_bundle_pem=ca_bundle_pem or "",
        client_cert_pem=client_cert_pem or "",
        client_key_pem=client_key_pem or "",
    )

    if body.host_id is not None and result.ok:
        stored = await db.get(DockerHost, body.host_id)
        if stored is not None:
            stored.engine_version = result.engine_version
            stored.container_count = result.container_count
            stored.last_sync_error = None
            await db.commit()

    return result


__all__ = ["router"]

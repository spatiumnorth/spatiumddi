"""VMware vSphere integration CRUD + probe endpoints (#4740).

Parallels ``app/api/v1/proxmox/router.py``. The vCenter password is
Fernet-encrypted at rest and never returned; admin-only surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.celery_dispatch import dispatch
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.exc_text import describe_exc
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.core.stored_secret_guard import (
    require_secret_for_changed_connection,
    require_secret_with_destination_change,
)
from app.models.audit import AuditLog
from app.models.ipam import IPSpace
from app.models.vsphere import VSphereTarget
from app.services.integration_ownership import release_integration_rows
from app.services.vsphere.client import VSphereClient, VSphereClientError

router = APIRouter(
    tags=["vsphere"],
    dependencies=[Depends(require_resource_permission("vsphere_target"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


def _clean_host(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("host is required")
    # Strip a pasted scheme / path: the client always uses https + /api.
    if "://" in v:
        v = v.split("://", 1)[1]
    return v.split("/", 1)[0]


def _check_port(v: int) -> int:
    if v < 1 or v > 65535:
        raise ValueError("port must be in 1..65535")
    return v


def _check_interval(v: int) -> int:
    if v < 30:
        raise ValueError("sync_interval_seconds must be >= 30")
    return v


class TargetBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    host: str
    port: int = 443
    verify_tls: bool = True
    ca_bundle_pem: str = ""
    username: str
    ipam_space_id: uuid.UUID
    mirror_vms: bool = True
    mirror_hosts: bool = True
    sync_interval_seconds: int = 120

    @field_validator("host")
    @classmethod
    def _strip_host(cls, v: str) -> str:
        return _clean_host(v)

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        return _check_port(v)

    @field_validator("username")
    @classmethod
    def _valid_username(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username is required (e.g. svc-spatium@vsphere.local)")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        return _check_interval(v)


class TargetCreate(TargetBase):
    password: str

    @field_validator("password")
    @classmethod
    def _valid_password(cls, v: str) -> str:
        if not v:
            raise ValueError("password is required")
        return v


class TargetUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    username: str | None = None
    # Omit or send empty to keep the stored password; non-empty rotates.
    password: str | None = None
    ipam_space_id: uuid.UUID | None = None
    mirror_vms: bool | None = None
    mirror_hosts: bool | None = None
    sync_interval_seconds: int | None = None

    @field_validator("host")
    @classmethod
    def _strip_host(cls, v: str | None) -> str | None:
        return None if v is None else _clean_host(v)

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int | None) -> int | None:
        return None if v is None else _check_port(v)

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int | None) -> int | None:
        return None if v is None else _check_interval(v)


class TargetResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    host: str
    port: int
    verify_tls: bool
    ca_bundle_present: bool
    username: str
    password_present: bool
    ipam_space_id: uuid.UUID
    mirror_vms: bool
    mirror_hosts: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    vcenter_version: str | None
    host_count: int | None
    vm_count: int | None
    last_discovery: dict | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    target_id: uuid.UUID | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    username: str | None = None
    password: str | None = None


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    vcenter_version: str | None = None
    host_count: int | None = None
    vm_count: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(t: VSphereTarget) -> TargetResponse:
    return TargetResponse(
        id=t.id,
        name=t.name,
        description=t.description,
        enabled=t.enabled,
        host=t.host,
        port=t.port,
        verify_tls=t.verify_tls,
        ca_bundle_present=bool(t.ca_bundle_pem),
        username=t.username,
        password_present=bool(t.password_encrypted),
        ipam_space_id=t.ipam_space_id,
        mirror_vms=t.mirror_vms,
        mirror_hosts=t.mirror_hosts,
        sync_interval_seconds=t.sync_interval_seconds,
        last_synced_at=t.last_synced_at,
        last_sync_error=t.last_sync_error,
        vcenter_version=t.vcenter_version,
        host_count=t.host_count,
        vm_count=t.vm_count,
        last_discovery=t.last_discovery,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


async def _probe(
    *,
    host: str,
    port: int,
    verify_tls: bool,
    ca_bundle_pem: str,
    username: str,
    password: str,
) -> TestConnectionResponse:
    """Open a session, count hosts + VMs, close the session. Never raises."""
    try:
        async with VSphereClient(
            host=host,
            port=port,
            username=username,
            password=password,
            verify_tls=verify_tls,
            ca_bundle_pem=ca_bundle_pem,
        ) as client:
            version = await client.get_version()
            hosts = await client.list_hosts()
            vms = await client.list_vms()
    except VSphereClientError as exc:
        msg = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate" in msg.lower():
            msg += " — upload the vCenter CA bundle, or disable verify_tls for a self-signed lab."
        return TestConnectionResponse(ok=False, message=msg)
    except Exception as exc:  # noqa: BLE001 — a probe reports, it never raises
        return TestConnectionResponse(ok=False, message=describe_exc(exc))
    summary = f"Connected to vCenter {version or '(version hidden)'}"
    summary += f" — {len(hosts)} host(s), {len(vms)} VM(s)"
    return TestConnectionResponse(
        ok=True,
        message=summary,
        vcenter_version=version,
        host_count=len(hosts),
        vm_count=len(vms),
    )


async def _validate_space(db: Any, ipam_space_id: uuid.UUID) -> None:
    if await db.get(IPSpace, ipam_space_id) is None:
        raise HTTPException(status_code=422, detail="ipam_space_id not found")


def _audit(
    db: Any,
    *,
    user: Any,
    action: str,
    target_id: uuid.UUID,
    target_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="vsphere_target",
            resource_id=str(target_id),
            resource_display=target_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/targets", response_model=list[TargetResponse])
async def list_targets(db: DB, _: CurrentUser) -> list[TargetResponse]:
    res = await db.execute(select(VSphereTarget).order_by(VSphereTarget.name))
    return [_to_response(t) for t in res.scalars().all()]


@router.post("/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(body: TargetCreate, db: DB, user: SuperAdmin) -> TargetResponse:
    forbid_in_demo_mode("vSphere target registration is disabled")
    await _validate_space(db, body.ipam_space_id)

    existing = await db.execute(select(VSphereTarget).where(VSphereTarget.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A vSphere target with that name exists")

    t = VSphereTarget(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        host=body.host,
        port=body.port,
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
        username=body.username,
        password_encrypted=encrypt_str(body.password),
        ipam_space_id=body.ipam_space_id,
        mirror_vms=body.mirror_vms,
        mirror_hosts=body.mirror_hosts,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(t)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        target_id=t.id,
        target_name=t.name,
        new_value=body.model_dump(mode="json", exclude={"password"}),
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.put("/targets/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: uuid.UUID, body: TargetUpdate, db: DB, user: SuperAdmin
) -> TargetResponse:
    t = await db.get(VSphereTarget, target_id)
    if t is None:
        raise HTTPException(status_code=404, detail="vSphere target not found")

    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] != t.name:
        clash = await db.execute(
            select(VSphereTarget.id).where(VSphereTarget.name == changes["name"])
        )
        if clash.first() is not None:
            raise HTTPException(status_code=409, detail="A vSphere target with that name exists")
    require_secret_with_destination_change(
        t,
        changes,
        destination=["host", "port"],
        secrets={"password": t.password_encrypted},
        blank_keeps=("password",),
    )
    if "ipam_space_id" in changes:
        await _validate_space(db, changes["ipam_space_id"])

    for k, v in changes.items():
        if k == "password":
            if v:
                t.password_encrypted = encrypt_str(v)
        else:
            setattr(t, k, v)

    _audit(
        db,
        user=user,
        action="update",
        target_id=t.id,
        target_name=t.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k != "password"},
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    t = await db.get(VSphereTarget, target_id)
    if t is None:
        raise HTTPException(status_code=404, detail="vSphere target not found")
    _audit(db, user=user, action="delete", target_id=t.id, target_name=t.name)
    # #2287 — hand back operator-made rows before the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="vsphere_target_id", target_id=t.id, user=user, target_name=t.name
    )
    await db.delete(t)
    await db.commit()


@router.post("/targets/{target_id}/sync", status_code=status.HTTP_202_ACCEPTED)
async def sync_target(target_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    t = await db.get(VSphereTarget, target_id)
    if t is None:
        raise HTTPException(status_code=404, detail="vSphere target not found")

    add_trigger_audit(
        db,
        user,
        resource_type="vsphere_target",
        resource_id=t.id,
        resource_display=str(t.name or t.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.vsphere_sync import sync_target_now  # noqa: PLC0415

    try:
        result = await dispatch(sync_target_now, str(t.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/targets/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    host = body.host
    port = body.port or 443
    verify_tls = body.verify_tls if body.verify_tls is not None else True
    ca_bundle_pem = body.ca_bundle_pem
    username = body.username
    password = body.password

    stored: VSphereTarget | None = None
    if body.target_id is not None:
        stored = await db.get(VSphereTarget, body.target_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="vSphere target not found")
        require_secret_for_changed_connection(
            stored,
            {"host": body.host, "port": body.port, "password": body.password},
            destination=("host", "port"),
            secrets={"password": stored.password_encrypted},
        )
        host = host or stored.host
        port = body.port or stored.port
        verify_tls = body.verify_tls if body.verify_tls is not None else stored.verify_tls
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        username = username or stored.username
        if not password and stored.password_encrypted:
            try:
                password = decrypt_str(stored.password_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored password could not be decrypted — re-enter it",
                ) from exc

    if not host or not username or not password:
        raise HTTPException(
            status_code=422,
            detail="host, username and password are required (in the body or via a stored target_id)",
        )

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved vCenter IP.
    # Not hard-blocked: a vCenter is almost always on the RFC1918 LAN.
    assert_safe_target(host, label="vsphere")

    result = await _probe(
        host=host,
        port=port,
        verify_tls=verify_tls,
        ca_bundle_pem=ca_bundle_pem or "",
        username=username,
        password=password,
    )

    if stored is not None and result.ok:
        stored.vcenter_version = result.vcenter_version
        stored.host_count = result.host_count
        stored.vm_count = result.vm_count
        stored.last_sync_error = None
        await db.commit()

    return result


__all__ = ["router"]

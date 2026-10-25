"""NetBird integration CRUD + probe endpoints.

Parallels ``app/api/v1/tailscale/router.py``. PAT is Fernet-encrypted
at rest; admin-only surface. Unlike Tailscale (fixed cloud host), the
management URL is operator-supplied, so the probe runs it through the
SSRF guard before dialing.
"""

from __future__ import annotations

import ipaddress
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
from app.core.header_credentials import header_secret
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace
from app.models.netbird import NetbirdInstance
from app.services.dns.bundle_dirty import mark_integration_dns_released
from app.services.integration_ownership import release_integration_rows
from app.services.netbird.client import (
    NetbirdClient,
    NetbirdClientError,
    derive_netbird_domain,
)

router = APIRouter(
    tags=["netbird"],
    dependencies=[Depends(require_resource_permission("netbird_instance"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


def _normalise_api_url(v: str) -> str:
    v = v.strip().rstrip("/")
    if not v:
        raise ValueError("api_url is required (e.g. https://api.netbird.io)")
    if not (v.startswith("http://") or v.startswith("https://")):
        raise ValueError("api_url must start with http:// or https://")
    return v


def _validate_cidr(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("network_cidr is required")
    try:
        ipaddress.ip_network(v, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid CIDR: {exc}") from exc
    return v


def _floor_sync_interval(v: int) -> int:
    if v < 30:
        raise ValueError("sync_interval_seconds must be ≥ 30")
    return v


class InstanceBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    api_url: str = "https://api.netbird.io"
    verify_tls: bool = True
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    network_cidr: str = "100.64.0.0/10"
    skip_expired: bool = True
    sync_interval_seconds: int = 60

    @field_validator("api_url")
    @classmethod
    def _valid_api_url(cls, v: str) -> str:
        return _normalise_api_url(v)

    @field_validator("network_cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        return _validate_cidr(v)

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        return _floor_sync_interval(v)


class InstanceCreate(InstanceBase):
    api_key: str

    @field_validator("api_key")
    @classmethod
    def _valid_api_key(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("api_key is required")
        return v

    _check_api_key = field_validator("api_key")(header_secret)


class InstanceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    api_url: str | None = None
    verify_tls: bool | None = None
    # Omit / send empty to keep the stored key; non-empty rotates.
    api_key: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    network_cidr: str | None = None
    skip_expired: bool | None = None
    sync_interval_seconds: int | None = None

    # Validate the same fields as InstanceBase, but only when a value is
    # actually supplied (partial update) — so a PUT can't persist an
    # invalid api_url / CIDR / sub-30s interval that later breaks sync.
    @field_validator("api_url")
    @classmethod
    def _valid_api_url(cls, v: str | None) -> str | None:
        return None if v is None else _normalise_api_url(v)

    @field_validator("network_cidr")
    @classmethod
    def _valid_cidr(cls, v: str | None) -> str | None:
        return None if v is None else _validate_cidr(v)

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int | None) -> int | None:
        return None if v is None else _floor_sync_interval(v)

    _check_api_key = field_validator("api_key")(header_secret)


class InstanceResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    api_url: str
    verify_tls: bool
    api_key_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    network_cidr: str
    skip_expired: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    dns_domain: str | None
    peer_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    instance_id: uuid.UUID | None = None
    api_url: str | None = None
    verify_tls: bool = True
    api_key: str | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    dns_domain: str | None = None
    peer_count: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(t: NetbirdInstance) -> InstanceResponse:
    return InstanceResponse(
        id=t.id,
        name=t.name,
        description=t.description,
        enabled=t.enabled,
        api_url=t.api_url,
        verify_tls=t.verify_tls,
        api_key_present=bool(t.api_key_encrypted),
        ipam_space_id=t.ipam_space_id,
        dns_group_id=t.dns_group_id,
        network_cidr=t.network_cidr,
        skip_expired=t.skip_expired,
        sync_interval_seconds=t.sync_interval_seconds,
        last_synced_at=t.last_synced_at,
        last_sync_error=t.last_sync_error,
        dns_domain=t.dns_domain,
        peer_count=t.peer_count,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


async def _probe(*, api_url: str, verify: bool, api_key: str) -> TestConnectionResponse:
    """Probe NetBird. Always returns a structured result; never raises."""
    # SECURITY (#400, L5): api_url is operator-supplied, so unlike the
    # fixed-host Tailscale probe we run it through the SSRF guard (which
    # logs + flags loopback / link-local / cloud-metadata targets). It is
    # advisory (no block=True) because a self-hosted NetBird management
    # server legitimately lives on a LAN address. See app/core/ssrf.py.
    assert_safe_target(api_url, label="netbird")
    try:
        async with NetbirdClient(
            api_key=api_key, api_url=api_url, verify=verify, timeout=10.0
        ) as client:
            peers = await client.list_peers()
    except NetbirdClientError as exc:
        return TestConnectionResponse(ok=False, message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))
    domain = derive_netbird_domain(peers)
    return TestConnectionResponse(
        ok=True,
        message=f"Connected{' to ' + domain if domain else ''} ({len(peers)} peers)",
        dns_domain=domain,
        peer_count=len(peers),
    )


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
    instance_id: uuid.UUID,
    instance_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="netbird_instance",
            resource_id=str(instance_id),
            resource_display=instance_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/instances", response_model=list[InstanceResponse])
async def list_instances(db: DB, _: CurrentUser) -> list[InstanceResponse]:
    res = await db.execute(select(NetbirdInstance).order_by(NetbirdInstance.name))
    return [_to_response(t) for t in res.scalars().all()]


@router.post(
    "/instances",
    response_model=InstanceResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_instance(body: InstanceCreate, db: DB, user: SuperAdmin) -> InstanceResponse:
    forbid_in_demo_mode("NetBird instance registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    existing = await db.execute(select(NetbirdInstance).where(NetbirdInstance.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A NetBird instance with that name exists")

    t = NetbirdInstance(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        api_url=body.api_url,
        verify_tls=body.verify_tls,
        api_key_encrypted=encrypt_str(body.api_key),
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        network_cidr=body.network_cidr,
        skip_expired=body.skip_expired,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(t)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        instance_id=t.id,
        instance_name=t.name,
        new_value=body.model_dump(mode="json", exclude={"api_key"}),
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.put("/instances/{instance_id}", response_model=InstanceResponse)
async def update_instance(
    instance_id: uuid.UUID, body: InstanceUpdate, db: DB, user: SuperAdmin
) -> InstanceResponse:
    t = await db.get(NetbirdInstance, instance_id)
    if t is None:
        raise HTTPException(status_code=404, detail="NetBird instance not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", t.ipam_space_id)
    new_dns = changes.get("dns_group_id", t.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "api_key":
            if v:
                t.api_key_encrypted = encrypt_str(v)
        else:
            setattr(t, k, v)

    _audit(
        db,
        user=user,
        action="update",
        instance_id=t.id,
        instance_name=t.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k != "api_key"},
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.delete("/instances/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_instance(instance_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    t = await db.get(NetbirdInstance, instance_id)
    if t is None:
        raise HTTPException(status_code=404, detail="NetBird instance not found")
    _audit(db, user=user, action="delete", instance_id=t.id, instance_name=t.name)
    # #2287 — hand back operator-made rows in mirrored subnets / blocks before
    # the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="netbird_instance_id", target_id=t.id, user=user, target_name=t.name
    )
    # #2288 — the DNS rows cascade in the database; mark their groups' bundles dirty.
    await mark_integration_dns_released(db, own_fk="netbird_instance_id", target_id=t.id)
    await db.delete(t)
    await db.commit()


@router.post(
    "/instances/{instance_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_instance(instance_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    t = await db.get(NetbirdInstance, instance_id)
    if t is None:
        raise HTTPException(status_code=404, detail="NetBird instance not found")

    add_trigger_audit(
        db,
        user,
        resource_type="netbird_instance",
        resource_id=t.id,
        resource_display=str(getattr(t, "name", None) or t.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.netbird_sync import sync_instance_now  # noqa: PLC0415

    try:
        result = await dispatch(sync_instance_now, str(t.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/instances/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    api_url = body.api_url
    verify = body.verify_tls
    api_key = body.api_key

    if body.instance_id is not None:
        stored = await db.get(NetbirdInstance, body.instance_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="NetBird instance not found")
        api_url = api_url or stored.api_url
        if body.api_url is None:
            verify = stored.verify_tls
        if not api_key and stored.api_key_encrypted:
            try:
                api_key = decrypt_str(stored.api_key_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored API key could not be decrypted — re-enter it",
                ) from exc

    if not api_url or not api_key:
        raise HTTPException(
            status_code=422,
            detail="api_url and api_key are required (either in body or via stored instance_id)",
        )

    result = await _probe(api_url=api_url, verify=verify, api_key=api_key)

    if body.instance_id is not None and result.ok:
        stored = await db.get(NetbirdInstance, body.instance_id)
        if stored is not None:
            stored.dns_domain = result.dns_domain
            stored.peer_count = result.peer_count
            stored.last_sync_error = None
            await db.commit()

    return result


__all__ = ["router"]

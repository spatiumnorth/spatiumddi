"""Cloud integration CRUD + probe + sync endpoints (issue #37, Part A).

Parallels ``app/api/v1/proxmox/router.py``. One ``CloudEndpoint`` row per
connected public-cloud account (AWS / Azure / GCP). Credentials are a
provider-specific dict, Fernet-encrypted at rest. Reads gate on the
``cloud_endpoint`` resource permission; writes require superadmin.

The reconcile itself is connector-agnostic — this router only does CRUD,
a test-connection probe (``CloudConnector.probe``), and enqueues the
Celery sweep for a one-off "Sync now".
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
from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import require_resource_permission
from app.models.audit import AuditLog
from app.models.cloud import CloudEndpoint
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace
from app.services.cloud.base import (
    CloudConnectorError,
    get_connector,
    implemented_providers,
)

router = APIRouter(
    tags=["cloud"],
    dependencies=[Depends(require_resource_permission("cloud_endpoint"))],
)


# Required credential / provider_config keys per provider. The connector
# needs these to authenticate + scope; we validate at the API boundary so
# operators get a clear 422 instead of a confusing reconcile failure.
_REQUIRED_CREDENTIAL_KEYS: dict[str, tuple[str, ...]] = {
    "aws": ("access_key_id", "secret_access_key"),
    "azure": ("tenant_id", "client_id", "client_secret"),
    "gcp": ("service_account_json",),
}
# provider_config keys that must be a non-empty list.
_REQUIRED_CONFIG_LISTS: dict[str, str] = {
    "azure": "subscription_ids",
    "gcp": "project_ids",
}


# ── Pydantic schemas ─────────────────────────────────────────────────


class EndpointBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    provider_config: dict[str, Any] = {}
    regions: list[str] = []
    ipam_space_id: uuid.UUID
    public_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_load_balancers: bool = True
    mirror_stopped_instances: bool = False
    sync_interval_seconds: int = 300

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 60:
            raise ValueError("sync_interval_seconds must be ≥ 60")
        return v

    @field_validator("regions")
    @classmethod
    def _clean_regions(cls, v: list[str]) -> list[str]:
        return [r.strip() for r in v if r and r.strip()]


class EndpointCreate(EndpointBase):
    provider: str
    # Provider-specific secret dict; encrypted before persist. Required.
    credentials: dict[str, Any]

    @field_validator("provider")
    @classmethod
    def _valid_provider(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in implemented_providers():
            raise ValueError(
                f"provider must be one of: {', '.join(sorted(implemented_providers()))}"
            )
        return v


class EndpointUpdate(BaseModel):
    # provider is immutable post-create (like the AI-provider kind).
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    # Omit or send empty to keep the stored credentials; non-empty rotates.
    credentials: dict[str, Any] | None = None
    provider_config: dict[str, Any] | None = None
    regions: list[str] | None = None
    ipam_space_id: uuid.UUID | None = None
    public_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_load_balancers: bool | None = None
    mirror_stopped_instances: bool | None = None
    sync_interval_seconds: int | None = None


class EndpointResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    provider: str
    credentials_present: bool
    provider_config: dict[str, Any]
    regions: list[str]
    ipam_space_id: uuid.UUID
    public_space_id: uuid.UUID | None
    dns_group_id: uuid.UUID | None
    mirror_load_balancers: bool
    mirror_stopped_instances: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    provider_account_id: str | None
    network_count: int | None
    instance_count: int | None
    last_discovery: dict | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    endpoint_id: uuid.UUID | None = None
    provider: str | None = None
    credentials: dict[str, Any] | None = None
    provider_config: dict[str, Any] | None = None
    regions: list[str] | None = None


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    provider_account_id: str | None = None
    network_count: int | None = None
    instance_count: int | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(e: CloudEndpoint) -> EndpointResponse:
    return EndpointResponse(
        id=e.id,
        name=e.name,
        description=e.description,
        enabled=e.enabled,
        provider=e.provider,
        credentials_present=bool(e.credentials_encrypted),
        provider_config=e.provider_config or {},
        regions=e.regions or [],
        ipam_space_id=e.ipam_space_id,
        public_space_id=e.public_space_id,
        dns_group_id=e.dns_group_id,
        mirror_load_balancers=e.mirror_load_balancers,
        mirror_stopped_instances=e.mirror_stopped_instances,
        sync_interval_seconds=e.sync_interval_seconds,
        last_synced_at=e.last_synced_at,
        last_sync_error=e.last_sync_error,
        provider_account_id=e.provider_account_id,
        network_count=e.network_count,
        instance_count=e.instance_count,
        last_discovery=e.last_discovery,
        created_at=e.created_at,
        modified_at=e.modified_at,
    )


def _validate_provider_payload(
    provider: str, credentials: dict[str, Any], provider_config: dict[str, Any]
) -> None:
    """422 when required credential / routing keys are missing."""
    missing = [k for k in _REQUIRED_CREDENTIAL_KEYS.get(provider, ()) if not credentials.get(k)]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"{provider} credentials require: {', '.join(missing)}",
        )
    list_key = _REQUIRED_CONFIG_LISTS.get(provider)
    if list_key:
        value = provider_config.get(list_key)
        if not isinstance(value, list) or not value:
            raise HTTPException(
                status_code=422,
                detail=f"{provider} provider_config requires a non-empty {list_key} list",
            )


async def _validate_bindings(
    db: Any,
    ipam_space_id: uuid.UUID,
    public_space_id: uuid.UUID | None,
    dns_group_id: uuid.UUID | None,
) -> None:
    if await db.get(IPSpace, ipam_space_id) is None:
        raise HTTPException(status_code=422, detail="ipam_space_id not found")
    if public_space_id is not None and await db.get(IPSpace, public_space_id) is None:
        raise HTTPException(status_code=422, detail="public_space_id not found")
    if dns_group_id is not None and await db.get(DNSServerGroup, dns_group_id) is None:
        raise HTTPException(status_code=422, detail="dns_group_id not found")


def _audit(
    db: Any,
    *,
    user: Any,
    action: str,
    endpoint_id: uuid.UUID,
    endpoint_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="cloud_endpoint",
            resource_id=str(endpoint_id),
            resource_display=endpoint_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/endpoints", response_model=list[EndpointResponse])
async def list_endpoints(db: DB, _: CurrentUser) -> list[EndpointResponse]:
    res = await db.execute(select(CloudEndpoint).order_by(CloudEndpoint.name))
    return [_to_response(e) for e in res.scalars().all()]


@router.post("/endpoints", response_model=EndpointResponse, status_code=status.HTTP_201_CREATED)
async def create_endpoint(body: EndpointCreate, db: DB, user: SuperAdmin) -> EndpointResponse:
    forbid_in_demo_mode("Cloud endpoint registration is disabled")
    _validate_provider_payload(body.provider, body.credentials, body.provider_config)
    await _validate_bindings(db, body.ipam_space_id, body.public_space_id, body.dns_group_id)

    existing = await db.execute(select(CloudEndpoint).where(CloudEndpoint.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A Cloud endpoint with that name exists")

    e = CloudEndpoint(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        provider=body.provider,
        credentials_encrypted=encrypt_dict(body.credentials),
        provider_config=body.provider_config,
        regions=body.regions,
        ipam_space_id=body.ipam_space_id,
        public_space_id=body.public_space_id,
        dns_group_id=body.dns_group_id,
        mirror_load_balancers=body.mirror_load_balancers,
        mirror_stopped_instances=body.mirror_stopped_instances,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(e)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        endpoint_id=e.id,
        endpoint_name=e.name,
        new_value=body.model_dump(mode="json", exclude={"credentials"}),
    )
    await db.commit()
    await db.refresh(e)
    return _to_response(e)


@router.put("/endpoints/{endpoint_id}", response_model=EndpointResponse)
async def update_endpoint(
    endpoint_id: uuid.UUID, body: EndpointUpdate, db: DB, user: SuperAdmin
) -> EndpointResponse:
    e = await db.get(CloudEndpoint, endpoint_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Cloud endpoint not found")

    changes = body.model_dump(exclude_unset=True)

    new_ipam = changes.get("ipam_space_id", e.ipam_space_id)
    new_public = changes.get("public_space_id", e.public_space_id)
    new_dns = changes.get("dns_group_id", e.dns_group_id)
    if {"ipam_space_id", "public_space_id", "dns_group_id"} & changes.keys():
        await _validate_bindings(db, new_ipam, new_public, new_dns)

    # Re-validate the provider payload when EITHER credentials or the
    # routing config (provider_config) changes — clearing
    # subscription_ids / project_ids without rotating creds would
    # otherwise save an invalid endpoint that only fails later at
    # sync/probe time. When creds aren't being rotated, validate the new
    # config against the stored creds.
    new_creds = changes.get("credentials")
    if new_creds or "provider_config" in changes:
        creds_for_check: dict[str, Any] = new_creds or {}
        if not new_creds and e.credentials_encrypted:
            try:
                creds_for_check = decrypt_dict(e.credentials_encrypted)
            except ValueError:
                creds_for_check = {}
        _validate_provider_payload(
            e.provider, creds_for_check, changes.get("provider_config", e.provider_config or {})
        )

    for k, v in changes.items():
        if k == "credentials":
            if v:
                e.credentials_encrypted = encrypt_dict(v)
        else:
            setattr(e, k, v)

    _audit(
        db,
        user=user,
        action="update",
        endpoint_id=e.id,
        endpoint_name=e.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k != "credentials"},
    )
    await db.commit()
    await db.refresh(e)
    return _to_response(e)


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_endpoint(endpoint_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    e = await db.get(CloudEndpoint, endpoint_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Cloud endpoint not found")
    _audit(db, user=user, action="delete", endpoint_id=e.id, endpoint_name=e.name)
    # Mirror rows (IPBlock/Subnet/IPAddress) cascade via cloud_endpoint_id FK.
    await db.delete(e)
    await db.commit()


@router.post(
    "/endpoints/{endpoint_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=StatusResponse,
)
async def sync_endpoint(endpoint_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    forbid_in_demo_mode("Cloud sync is disabled")
    e = await db.get(CloudEndpoint, endpoint_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Cloud endpoint not found")

    add_trigger_audit(
        db,
        user,
        resource_type="cloud_endpoint",
        resource_id=e.id,
        resource_display=str(getattr(e, "name", None) or e.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.cloud_sync import sync_endpoint_now  # noqa: PLC0415

    try:
        result = sync_endpoint_now.delay(str(e.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001 — broker may be down; surface gracefully
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/endpoints/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    forbid_in_demo_mode("Cloud connection testing is disabled")
    provider = (body.provider or "").strip().lower()
    credentials = body.credentials
    provider_config = body.provider_config if body.provider_config is not None else {}
    regions = body.regions if body.regions is not None else []

    if body.endpoint_id is not None:
        stored = await db.get(CloudEndpoint, body.endpoint_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Cloud endpoint not found")
        provider = provider or stored.provider
        provider_config = (
            body.provider_config
            if body.provider_config is not None
            else (stored.provider_config or {})
        )
        regions = body.regions if body.regions is not None else (stored.regions or [])
        if not credentials and stored.credentials_encrypted:
            try:
                credentials = decrypt_dict(stored.credentials_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored credentials could not be decrypted — re-enter them",
                ) from exc

    if provider not in implemented_providers():
        raise HTTPException(
            status_code=422,
            detail=f"provider must be one of: {', '.join(sorted(implemented_providers()))}",
        )
    if not credentials:
        raise HTTPException(
            status_code=422,
            detail="credentials are required (either in the body or via a stored endpoint_id)",
        )

    # SECURITY (#400, L5): no SSRF guard call here — the AWS / Azure /
    # GCP connectors dial each cloud's FIXED SDK service endpoints
    # (derived from subscription / project / region IDs), not an
    # operator-supplied host, so there is no operator-controlled connect
    # target to resolve. If a custom ``endpoint_url`` field is ever added
    # to ``provider_config``, route it through
    # ``app.core.ssrf.assert_safe_target`` here. See app/core/ssrf.py.
    try:
        connector = get_connector(
            provider,
            credentials=credentials,
            provider_config=provider_config,
            regions=regions,
        )
        result = await connector.probe()
    except CloudConnectorError as exc:
        return TestConnectionResponse(ok=False, message=str(exc))
    except Exception as exc:  # noqa: BLE001 — never 500 the probe
        return TestConnectionResponse(ok=False, message=f"{provider} probe error: {exc}")

    if body.endpoint_id is not None and result.ok:
        stored = await db.get(CloudEndpoint, body.endpoint_id)
        if stored is not None:
            stored.provider_account_id = result.account_id
            stored.last_sync_error = None
            await db.commit()

    return TestConnectionResponse(
        ok=result.ok,
        message=result.message,
        provider_account_id=result.account_id,
        network_count=result.network_count,
        instance_count=result.instance_count,
    )


__all__ = ["router"]

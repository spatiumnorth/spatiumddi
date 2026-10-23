"""Tailscale integration CRUD + probe endpoints.

Parallels ``app/api/v1/proxmox/router.py``. PAT is Fernet-
encrypted at rest; admin-only surface.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.header_credentials import header_secret
from app.core.permissions import require_resource_permission
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace
from app.models.tailscale import TailscaleTenant
from app.services.dns.bundle_dirty import mark_integration_dns_released
from app.services.integration_credentials import credential_status
from app.services.tailscale.client import AUTH_REJECTED_PREFIX, is_auth_rejected
from app.services.tailscale.token_expiry import (
    TokenExpiryRead,
    apply_operator_expiry,
    apply_read,
    fetch_token_expiry,
)

router = APIRouter(
    tags=["tailscale"],
    dependencies=[Depends(require_resource_permission("tailscale_tenant"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


class TenantBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    tailnet: str = "-"
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    cgnat_cidr: str = "100.64.0.0/10"
    ipv6_cidr: str = "fd7a:115c:a1e0::/48"
    skip_expired: bool = True
    sync_interval_seconds: int = 60

    @field_validator("tailnet")
    @classmethod
    def _strip_tailnet(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("tailnet is required (use '-' for the PAT's default tailnet)")
        return v

    @field_validator("cgnat_cidr", "ipv6_cidr")
    @classmethod
    def _valid_cidr(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("CIDR is required")
        try:
            ipaddress.ip_network(v, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid CIDR: {exc}") from exc
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class TenantCreate(TenantBase):
    api_key: str
    # #2138 — fallback when Tailscale's keys endpoint can't say when the
    # token expires. A date read from Tailscale always replaces it.
    api_key_expires_at: datetime | None = None

    @field_validator("api_key")
    @classmethod
    def _valid_api_key(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("api_key is required")
        return v

    _check_api_key = field_validator("api_key")(header_secret)


class TenantUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    tailnet: str | None = None
    # Omit / send empty to keep the stored key; non-empty rotates.
    api_key: str | None = None
    # #2138 — operator-entered token expiry; null clears it. Replacing the
    # key without sending this resets the expiry to unknown, since the old
    # key's date says nothing about the new one.
    api_key_expires_at: datetime | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    cgnat_cidr: str | None = None
    ipv6_cidr: str | None = None
    skip_expired: bool | None = None
    sync_interval_seconds: int | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    tailnet: str
    api_key_present: bool
    # #2138 — when the access token expires. Null = unknown.
    api_key_expires_at: datetime | None
    # "api" (read from Tailscale) | "operator" (typed in) | null.
    api_key_expiry_source: str | None
    # ok | expiring | expired | rejected | unknown | disabled — see
    # app/services/integration_credentials.py.
    credential_state: str
    credential_days_left: int | None
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    cgnat_cidr: str
    ipv6_cidr: str
    skip_expired: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    tailnet_domain: str | None
    device_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    tenant_id: uuid.UUID | None = None
    tailnet: str | None = None
    api_key: str | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    tailnet_domain: str | None = None
    device_count: int | None = None
    # #2138 — the tested token's expiry as Tailscale reports it, or null
    # with the reason in ``api_key_expiry_note``.
    api_key_expires_at: datetime | None = None
    api_key_expiry_note: str | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(t: TailscaleTenant) -> TenantResponse:
    cred = credential_status(
        expires_at=t.api_key_expires_at,
        rejected=is_auth_rejected(t.last_sync_error),
        now=datetime.now(UTC),
        enabled=t.enabled,
    )
    return TenantResponse(
        id=t.id,
        name=t.name,
        description=t.description,
        enabled=t.enabled,
        tailnet=t.tailnet,
        api_key_present=bool(t.api_key_encrypted),
        api_key_expires_at=t.api_key_expires_at,
        api_key_expiry_source=t.api_key_expiry_source,
        credential_state=cred.state,
        credential_days_left=cred.days_left,
        ipam_space_id=t.ipam_space_id,
        dns_group_id=t.dns_group_id,
        cgnat_cidr=t.cgnat_cidr,
        ipv6_cidr=t.ipv6_cidr,
        skip_expired=t.skip_expired,
        sync_interval_seconds=t.sync_interval_seconds,
        last_synced_at=t.last_synced_at,
        last_sync_error=t.last_sync_error,
        tailnet_domain=t.tailnet_domain,
        device_count=t.device_count,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


async def _probe(*, tailnet: str, api_key: str) -> TestConnectionResponse:
    """Probe Tailscale. Always returns a structured result; never raises."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }
    url = f"https://api.tailscale.com/api/v2/tailnet/{tailnet}/devices"
    try:
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            r = await client.get(url, params={"fields": "default"})
            if r.status_code == 401:
                return TestConnectionResponse(
                    ok=False,
                    message=f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked",
                )
            if r.status_code == 403:
                return TestConnectionResponse(
                    ok=False,
                    message="HTTP 403 — API key lacks permission for this tailnet",
                )
            if r.status_code == 404:
                return TestConnectionResponse(
                    ok=False,
                    message=f"HTTP 404 — tailnet '{tailnet}' not found (use '-' for default)",
                )
            r.raise_for_status()
            data = r.json() or {}
            devices = data.get("devices") or []
            domain: str | None = None
            for d in devices:
                name = str(d.get("name") or "").rstrip(".")
                if "." in name:
                    domain = name.split(".", 1)[1]
                    break
            return TestConnectionResponse(
                ok=True,
                message=(
                    f"Connected to tailnet"
                    f"{' ' + domain if domain else ''} ({len(devices)} devices)"
                ),
                tailnet_domain=domain,
                device_count=len(devices),
            )
    except httpx.HTTPStatusError as exc:
        return TestConnectionResponse(
            ok=False, message=f"HTTP {exc.response.status_code} from Tailscale"
        )
    except httpx.ConnectError as exc:
        return TestConnectionResponse(ok=False, message=f"Could not reach Tailscale: {exc}")
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))


async def _read_expiry_into(tenant: TailscaleTenant, api_key: str) -> TokenExpiryRead:
    """Ask Tailscale for the token's expiry and store it when it answers.

    Best-effort: a save never fails because the expiry could not be read —
    the stored (or operator-entered) value is kept and the chip says
    "unknown" until a later read succeeds.
    """
    read = await fetch_token_expiry(api_key=api_key, tailnet=tenant.tailnet)
    apply_read(tenant, read)
    return read


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
    tenant_id: uuid.UUID,
    tenant_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="tailscale_tenant",
            resource_id=str(tenant_id),
            resource_display=tenant_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/tenants", response_model=list[TenantResponse])
async def list_tenants(db: DB, _: CurrentUser) -> list[TenantResponse]:
    res = await db.execute(select(TailscaleTenant).order_by(TailscaleTenant.name))
    return [_to_response(t) for t in res.scalars().all()]


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_tenant(body: TenantCreate, db: DB, user: SuperAdmin) -> TenantResponse:
    forbid_in_demo_mode("Tailscale tenant registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    existing = await db.execute(select(TailscaleTenant).where(TailscaleTenant.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A Tailscale tenant with that name exists")

    t = TailscaleTenant(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        tailnet=body.tailnet,
        api_key_encrypted=encrypt_str(body.api_key),
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        cgnat_cidr=body.cgnat_cidr,
        ipv6_cidr=body.ipv6_cidr,
        skip_expired=body.skip_expired,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    apply_operator_expiry(t, body.api_key_expires_at)
    await _read_expiry_into(t, body.api_key)
    db.add(t)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        tenant_id=t.id,
        tenant_name=t.name,
        new_value={
            **body.model_dump(mode="json", exclude={"api_key", "api_key_expires_at"}),
            "api_key_expires_at": (
                t.api_key_expires_at.isoformat() if t.api_key_expires_at else None
            ),
            "api_key_expiry_source": t.api_key_expiry_source,
        },
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.put("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: uuid.UUID, body: TenantUpdate, db: DB, user: SuperAdmin
) -> TenantResponse:
    t = await db.get(TailscaleTenant, tenant_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Tailscale tenant not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", t.ipam_space_id)
    new_dns = changes.get("dns_group_id", t.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    new_key = changes.get("api_key") or None
    for k, v in changes.items():
        if k in ("api_key", "api_key_expires_at"):
            continue
        setattr(t, k, v)
    if new_key:
        t.api_key_encrypted = encrypt_str(new_key)
        # The old key's expiry and its 401 say nothing about the new one.
        apply_operator_expiry(t, changes.get("api_key_expires_at"))
        if is_auth_rejected(t.last_sync_error):
            t.last_sync_error = None
        await _read_expiry_into(t, new_key)
    elif "api_key_expires_at" in changes:
        apply_operator_expiry(t, changes["api_key_expires_at"])

    _audit(
        db,
        user=user,
        action="update",
        tenant_id=t.id,
        tenant_name=t.name,
        changed_fields=list(changes.keys()),
        new_value={
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in changes.items()
            if k != "api_key"
        }
        | (
            {"api_key_expiry_source": t.api_key_expiry_source}
            if new_key or "api_key_expires_at" in changes
            else {}
        ),
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.delete("/tenants/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(tenant_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    t = await db.get(TailscaleTenant, tenant_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Tailscale tenant not found")
    _audit(db, user=user, action="delete", tenant_id=t.id, tenant_name=t.name)
    # #2288 — the DNS rows cascade in the database; mark their groups' bundles dirty.
    await mark_integration_dns_released(db, own_fk="tailscale_tenant_id", target_id=t.id)
    await db.delete(t)
    await db.commit()


@router.post(
    "/tenants/{tenant_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_tenant(tenant_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    t = await db.get(TailscaleTenant, tenant_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Tailscale tenant not found")

    add_trigger_audit(
        db,
        user,
        resource_type="tailscale_tenant",
        resource_id=t.id,
        resource_display=str(getattr(t, "name", None) or t.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.tailscale_sync import sync_tenant_now  # noqa: PLC0415

    try:
        result = sync_tenant_now.delay(str(t.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/tenants/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    tailnet = body.tailnet
    api_key = body.api_key

    if body.tenant_id is not None:
        stored = await db.get(TailscaleTenant, body.tenant_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Tailscale tenant not found")
        tailnet = tailnet or stored.tailnet
        if not api_key and stored.api_key_encrypted:
            try:
                api_key = decrypt_str(stored.api_key_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored API key could not be decrypted — re-enter it",
                ) from exc

    if not tailnet or not api_key:
        raise HTTPException(
            status_code=422,
            detail="tailnet and api_key are required (either in body or via stored tenant_id)",
        )

    # SECURITY (#400, L5): no SSRF guard call here — ``_probe`` dials a
    # FIXED host (``api.tailscale.com``) with ``tailnet`` only as a URL
    # path segment, so there is no operator-controlled connect target to
    # resolve (unlike the proxmox / unifi / opnsense / docker / k8s LAN
    # integrations). See app/core/ssrf.py.
    result = await _probe(tailnet=tailnet, api_key=api_key)
    if result.ok:
        read = await fetch_token_expiry(api_key=api_key, tailnet=tailnet)
        result.api_key_expires_at = read.expires_at
        result.api_key_expiry_note = read.note

    # Only a test of the STORED key says anything about the stored row: a key
    # typed into the form but not yet saved must not clear the stored key's
    # 401 or stamp its expiry onto the tenant.
    tested_stored_key = body.tenant_id is not None and not body.api_key
    if tested_stored_key and result.ok:
        stored = await db.get(TailscaleTenant, body.tenant_id)
        if stored is not None:
            stored.tailnet_domain = result.tailnet_domain
            stored.device_count = result.device_count
            stored.last_sync_error = None
            if result.api_key_expires_at is not None:
                apply_read(stored, TokenExpiryRead(result.api_key_expires_at))
            await db.commit()

    return result


__all__ = ["router"]

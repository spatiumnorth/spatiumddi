"""OPNsense integration CRUD + probe endpoints.

Parallels ``app/api/v1/proxmox/router.py``. The API secret is
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
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace
from app.models.opnsense import OPNsenseRouter
from app.services.integration_ownership import release_integration_rows

router = APIRouter(
    tags=["opnsense"],
    dependencies=[Depends(require_resource_permission("opnsense_router"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


class RouterBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    host: str
    port: int = 443
    verify_tls: bool = True
    ca_bundle_pem: str = ""
    api_key: str
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    mirror_dhcp_leases: bool = True
    mirror_static_mappings: bool = True
    mirror_arp: bool = False
    sync_interval_seconds: int = 60

    @field_validator("host")
    @classmethod
    def _strip_host(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("host is required")
        # Strip any scheme + trailing slash the operator may have pasted
        # — we always use https and the fixed /api path.
        if "://" in v:
            v = v.split("://", 1)[1]
        return v.rstrip("/")

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("port must be in 1..65535")
        return v

    @field_validator("api_key")
    @classmethod
    def _valid_api_key(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("api_key is required")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class RouterCreate(RouterBase):
    # The OPNsense API secret (Basic-auth password). Encrypted before
    # persist. Required on create.
    api_secret: str

    @field_validator("api_secret")
    @classmethod
    def _valid_api_secret(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("api_secret is required")
        return v


class RouterUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    api_key: str | None = None
    # Omit or send empty to keep the stored secret; non-empty rotates.
    api_secret: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_dhcp_leases: bool | None = None
    mirror_static_mappings: bool | None = None
    mirror_arp: bool | None = None
    sync_interval_seconds: int | None = None


class RouterResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    host: str
    port: int
    verify_tls: bool
    ca_bundle_present: bool
    api_key: str
    api_secret_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    mirror_dhcp_leases: bool
    mirror_static_mappings: bool
    mirror_arp: bool
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    # #797 — non-fatal findings from the last pass, newline-joined.
    # A sync can be green and still mirror nothing; this is what says why.
    last_sync_warning: str | None
    firmware_version: str | None
    interface_count: int | None
    lease_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    router_id: uuid.UUID | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    api_key: str | None = None
    api_secret: str | None = None


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    firmware_version: str | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(r: OPNsenseRouter) -> RouterResponse:
    return RouterResponse(
        id=r.id,
        name=r.name,
        description=r.description,
        enabled=r.enabled,
        host=r.host,
        port=r.port,
        verify_tls=r.verify_tls,
        ca_bundle_present=bool(r.ca_bundle_pem),
        api_key=r.api_key,
        api_secret_present=bool(r.api_secret_encrypted),
        ipam_space_id=r.ipam_space_id,
        dns_group_id=r.dns_group_id,
        mirror_dhcp_leases=r.mirror_dhcp_leases,
        mirror_static_mappings=r.mirror_static_mappings,
        mirror_arp=r.mirror_arp,
        sync_interval_seconds=r.sync_interval_seconds,
        last_synced_at=r.last_synced_at,
        last_sync_error=r.last_sync_error,
        last_sync_warning=r.last_sync_warning,
        firmware_version=r.firmware_version,
        interface_count=r.interface_count,
        lease_count=r.lease_count,
        created_at=r.created_at,
        modified_at=r.modified_at,
    )


async def _probe(
    *,
    host: str,
    port: int,
    verify_tls: bool,
    ca_bundle_pem: str,
    api_key: str,
    api_secret: str,
) -> TestConnectionResponse:
    """Probe OPNsense. Always returns a structured result; never raises.

    Hits ``/api/core/firmware/status`` for authn + version.
    Distinguishes 401 / 403 / TLS / connect errors with human-readable
    messages.
    """
    verify: Any = verify_tls
    if verify_tls and ca_bundle_pem.strip():
        try:
            verify = ssl.create_default_context(cadata=ca_bundle_pem)
        except Exception as exc:  # noqa: BLE001
            return TestConnectionResponse(ok=False, message=f"CA bundle is invalid: {exc}")

    base_url = f"https://{host}:{port}"

    try:
        async with httpx.AsyncClient(
            base_url=base_url,
            auth=(api_key, api_secret),
            headers={"Accept": "application/json"},
            verify=verify,
            timeout=10.0,
        ) as client:
            v = await client.get("/api/core/firmware/status")
            if v.status_code == 401:
                return TestConnectionResponse(ok=False, message="HTTP 401 — API key/secret invalid")
            if v.status_code == 403:
                return TestConnectionResponse(
                    ok=False,
                    message="HTTP 403 — API user lacks privilege (grant read access to the firewall)",
                )
            v.raise_for_status()
            data = v.json() or {}
            firmware = ""
            if isinstance(data, dict):
                for key in ("product_version", "os_version", "product_id"):
                    val = data.get(key)
                    if isinstance(val, str) and val:
                        firmware = val
                        break
            summary = f"Connected to OPNsense {firmware}".rstrip()
            return TestConnectionResponse(
                ok=True,
                message=summary,
                firmware_version=firmware or None,
            )
    except httpx.HTTPStatusError as exc:
        return TestConnectionResponse(
            ok=False, message=f"HTTP {exc.response.status_code} from OPNsense"
        )
    except httpx.ConnectError as exc:
        return TestConnectionResponse(ok=False, message=f"Could not reach OPNsense: {exc}")
    except ssl.SSLError as exc:
        return TestConnectionResponse(
            ok=False,
            message=(
                f"TLS error: {exc}. Upload the OPNsense CA bundle, or disable "
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
    router_id: uuid.UUID,
    router_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="opnsense_router",
            resource_id=str(router_id),
            resource_display=router_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/routers", response_model=list[RouterResponse])
async def list_routers(db: DB, _: CurrentUser) -> list[RouterResponse]:
    res = await db.execute(select(OPNsenseRouter).order_by(OPNsenseRouter.name))
    return [_to_response(r) for r in res.scalars().all()]


@router.post(
    "/routers",
    response_model=RouterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_router(body: RouterCreate, db: DB, user: SuperAdmin) -> RouterResponse:
    forbid_in_demo_mode("OPNsense firewall registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    existing = await db.execute(select(OPNsenseRouter).where(OPNsenseRouter.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="An OPNsense firewall with that name exists")

    r = OPNsenseRouter(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        host=body.host,
        port=body.port,
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
        api_key=body.api_key,
        api_secret_encrypted=encrypt_str(body.api_secret),
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        mirror_dhcp_leases=body.mirror_dhcp_leases,
        mirror_static_mappings=body.mirror_static_mappings,
        mirror_arp=body.mirror_arp,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(r)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        router_id=r.id,
        router_name=r.name,
        new_value=body.model_dump(mode="json", exclude={"api_secret"}),
    )
    await db.commit()
    await db.refresh(r)
    return _to_response(r)


@router.put("/routers/{router_id}", response_model=RouterResponse)
async def update_router(
    router_id: uuid.UUID, body: RouterUpdate, db: DB, user: SuperAdmin
) -> RouterResponse:
    r = await db.get(OPNsenseRouter, router_id)
    if r is None:
        raise HTTPException(status_code=404, detail="OPNsense firewall not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", r.ipam_space_id)
    new_dns = changes.get("dns_group_id", r.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "api_secret":
            if v:
                r.api_secret_encrypted = encrypt_str(v)
        else:
            setattr(r, k, v)

    _audit(
        db,
        user=user,
        action="update",
        router_id=r.id,
        router_name=r.name,
        changed_fields=list(changes.keys()),
        new_value={k: v for k, v in changes.items() if k != "api_secret"},
    )
    await db.commit()
    await db.refresh(r)
    return _to_response(r)


@router.delete("/routers/{router_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_router(
    router_id: uuid.UUID, db: DB, user: SuperAdmin, force: bool = False
) -> None:
    r = await db.get(OPNsenseRouter, router_id)
    if r is None:
        raise HTTPException(status_code=404, detail="OPNsense firewall not found")
    from app.services.block_sync.delete_guard import (  # noqa: PLC0415
        assert_block_sync_deletable,
    )

    await assert_block_sync_deletable(
        db,
        target_kind="opnsense",
        target_id=r.id,
        armed=r.block_sync_enabled,
        force=force,
    )
    # #601 — sweep any active block-sync push rows for this target. They have no
    # FK to opnsense_router (target_id is polymorphic), so nothing cascades.
    # NOTE: this does NOT lift the blocks off the firewall — disarm the target
    # first (which lifts) if the device should stop enforcing them.
    from sqlalchemy import delete as sa_delete  # noqa: PLC0415

    from app.models.block_sync import NetworkBlockPush  # noqa: PLC0415

    await db.execute(
        sa_delete(NetworkBlockPush).where(
            NetworkBlockPush.target_kind == "opnsense",
            NetworkBlockPush.target_id == r.id,
        )
    )
    _audit(db, user=user, action="delete", router_id=r.id, router_name=r.name)
    # #2287 — hand back operator-made rows in mirrored subnets / blocks before
    # the FK cascade can destroy them.
    await release_integration_rows(
        db, own_fk="opnsense_router_id", target_id=r.id, user=user, target_name=r.name
    )
    await db.delete(r)
    await db.commit()


@router.post(
    "/routers/{router_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
)
async def sync_router(router_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    r = await db.get(OPNsenseRouter, router_id)
    if r is None:
        raise HTTPException(status_code=404, detail="OPNsense firewall not found")

    add_trigger_audit(
        db,
        user,
        resource_type="opnsense_router",
        resource_id=r.id,
        resource_display=str(getattr(r, "name", None) or r.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.opnsense_sync import sync_router_now  # noqa: PLC0415

    try:
        result = sync_router_now.delay(str(r.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/routers/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    host = body.host
    port = body.port or 443
    verify_tls = body.verify_tls if body.verify_tls is not None else True
    ca_bundle_pem = body.ca_bundle_pem
    api_key = body.api_key
    api_secret = body.api_secret

    if body.router_id is not None:
        stored = await db.get(OPNsenseRouter, body.router_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="OPNsense firewall not found")
        host = host or stored.host
        port = body.port or stored.port
        verify_tls = body.verify_tls if body.verify_tls is not None else stored.verify_tls
        ca_bundle_pem = ca_bundle_pem if ca_bundle_pem is not None else stored.ca_bundle_pem
        api_key = api_key or stored.api_key
        if not api_secret and stored.api_secret_encrypted:
            try:
                api_secret = decrypt_str(stored.api_secret_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored API secret could not be decrypted — re-enter it",
                ) from exc

    if not host or not api_key or not api_secret:
        raise HTTPException(
            status_code=422,
            detail="host, api_key, and api_secret are required (either in body or via stored router_id)",
        )

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved
    # OPNsense host IP. Not hard-blocked: firewalls live on the
    # RFC1918 LAN by definition.
    assert_safe_target(host, label="opnsense")

    result = await _probe(
        host=host,
        port=port,
        verify_tls=verify_tls,
        ca_bundle_pem=ca_bundle_pem or "",
        api_key=api_key,
        api_secret=api_secret,
    )

    if body.router_id is not None and result.ok:
        stored = await db.get(OPNsenseRouter, body.router_id)
        if stored is not None:
            stored.firmware_version = result.firmware_version
            stored.last_sync_error = None
            # last_sync_warning is deliberately NOT cleared here. The probe
            # only proves the credentials reach the firmware endpoint; it
            # says nothing about whether a DHCP backend exists or whether
            # a subnet is claimable. Clearing it on a green Test Connection
            # would hide exactly the #797 condition the field exists for,
            # until the next reconcile pass re-derived it.
            await db.commit()

    return result


__all__ = ["router"]

"""Palo Alto PAN-OS / Panorama integration CRUD + probe + mirror-read endpoints.

Parallels ``app/api/v1/opnsense/router.py``. The API key is Fernet-encrypted at
rest; admin-only surface. The read-only mirror is configured here; the DAG
*enforcement* arming (``block_sync_enabled`` + write key + tag) rides the shared
#601 block-sync target endpoints (``/block-sync/targets/paloalto/...``), not
this router — keeping the mirror config and the write-back arming separate, as
the OPNsense integration does.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.header_credentials import header_secret
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace, Subnet
from app.models.panos import FirewallObject, PANOSFirewall
from app.services.panos.client import PANOSClient, PANOSClientError

router = APIRouter(
    tags=["paloalto"],
    dependencies=[Depends(require_resource_permission("panos_firewall"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


class FirewallBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    host: str
    port: int = 443
    verify_tls: bool = True
    ca_bundle_pem: str = ""
    api_version: str = "10.1"
    is_panorama: bool = False
    vsys: str = "vsys1"
    device_group: str = ""
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    mirror_address_objects: bool = True
    mirror_nat_rules: bool = True
    mirror_interfaces: bool = False
    mirror_dhcp_leases: bool = False
    sync_interval_seconds: int = 60

    @field_validator("host")
    @classmethod
    def _strip_host(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("host is required")
        if "://" in v:
            v = v.split("://", 1)[1]
        return v.rstrip("/")

    @field_validator("port")
    @classmethod
    def _valid_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("port must be in 1..65535")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class FirewallCreate(FirewallBase):
    # The PAN-OS API key. Encrypted before persist. Required on create.
    api_key: str

    @field_validator("api_key")
    @classmethod
    def _valid_api_key(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("api_key is required")
        return v

    _check_api_key = field_validator("api_key")(header_secret)


class FirewallUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    api_version: str | None = None
    is_panorama: bool | None = None
    vsys: str | None = None
    device_group: str | None = None
    # Omit or send empty to keep the stored key; non-empty rotates.
    api_key: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_address_objects: bool | None = None
    mirror_nat_rules: bool | None = None
    mirror_interfaces: bool | None = None
    mirror_dhcp_leases: bool | None = None
    sync_interval_seconds: int | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class FirewallResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    host: str
    port: int
    verify_tls: bool
    ca_bundle_present: bool
    api_version: str
    api_key_present: bool
    is_panorama: bool
    vsys: str
    device_group: str
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    mirror_address_objects: bool
    mirror_nat_rules: bool
    mirror_interfaces: bool
    mirror_dhcp_leases: bool
    sync_interval_seconds: int
    # Enforcement (#601 tier) — read-only surfacing here; armed via block-sync.
    block_sync_enabled: bool
    block_tag_name: str
    last_block_sync_at: datetime | None
    last_block_sync_error: str | None
    last_synced_at: datetime | None
    last_sync_error: str | None
    sw_version: str | None
    model: str | None
    object_count: int | None
    nat_rule_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    firewall_id: uuid.UUID | None = None
    host: str | None = None
    port: int | None = None
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    api_version: str | None = None
    is_panorama: bool | None = None
    vsys: str | None = None
    device_group: str | None = None
    api_key: str | None = None
    # Alternative to api_key: mint one via type=keygen from admin creds.
    username: str | None = None
    password: str | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    sw_version: str | None = None
    model: str | None = None
    # When the probe minted a key via keygen, return it so the create form can
    # store it (the operator supplied creds once, not a raw key).
    api_key: str | None = None


class FirewallObjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    value: str
    description: str
    tags: list
    resolved_cidr: str | None
    ip_address_id: uuid.UUID | None
    subnet_id: uuid.UUID | None
    # True when the object resolves to a CIDR/IP but no IPAM row links to it —
    # the "object on firewall with no IPAM row" side of the drift report.
    unlinked: bool


class DriftReport(BaseModel):
    objects_total: int
    objects_unlinked: int  # firewall objects with a CIDR but no IPAM row
    subnets_uncovered: int  # in-space subnets with no matching firewall object
    subnets_uncovered_cidrs: list[str]


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(f: PANOSFirewall) -> FirewallResponse:
    return FirewallResponse(
        id=f.id,
        name=f.name,
        description=f.description,
        enabled=f.enabled,
        host=f.host,
        port=f.port,
        verify_tls=f.verify_tls,
        ca_bundle_present=bool(f.ca_bundle_pem),
        api_version=f.api_version,
        api_key_present=bool(f.api_key_encrypted),
        is_panorama=f.is_panorama,
        vsys=f.vsys,
        device_group=f.device_group,
        ipam_space_id=f.ipam_space_id,
        dns_group_id=f.dns_group_id,
        mirror_address_objects=f.mirror_address_objects,
        mirror_nat_rules=f.mirror_nat_rules,
        mirror_interfaces=f.mirror_interfaces,
        mirror_dhcp_leases=f.mirror_dhcp_leases,
        sync_interval_seconds=f.sync_interval_seconds,
        block_sync_enabled=f.block_sync_enabled,
        block_tag_name=f.block_tag_name,
        last_block_sync_at=f.last_block_sync_at,
        last_block_sync_error=f.last_block_sync_error,
        last_synced_at=f.last_synced_at,
        last_sync_error=f.last_sync_error,
        sw_version=f.sw_version,
        model=f.model,
        object_count=f.object_count,
        nat_rule_count=f.nat_rule_count,
        created_at=f.created_at,
        modified_at=f.modified_at,
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
    firewall_id: uuid.UUID,
    firewall_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="panos_firewall",
            resource_id=str(firewall_id),
            resource_display=firewall_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/firewalls", response_model=list[FirewallResponse])
async def list_firewalls(db: DB, _: CurrentUser) -> list[FirewallResponse]:
    res = await db.execute(select(PANOSFirewall).order_by(PANOSFirewall.name))
    return [_to_response(f) for f in res.scalars().all()]


@router.post("/firewalls", response_model=FirewallResponse, status_code=status.HTTP_201_CREATED)
async def create_firewall(body: FirewallCreate, db: DB, user: SuperAdmin) -> FirewallResponse:
    forbid_in_demo_mode("Palo Alto firewall registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)
    if body.is_panorama and not body.device_group.strip():
        raise HTTPException(
            status_code=422, detail="device_group is required for a Panorama target"
        )

    existing = await db.execute(select(PANOSFirewall).where(PANOSFirewall.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A Palo Alto firewall with that name exists")

    f = PANOSFirewall(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        host=body.host,
        port=body.port,
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
        api_version=body.api_version,
        api_key_encrypted=encrypt_str(body.api_key),
        is_panorama=body.is_panorama,
        vsys=body.vsys,
        device_group=body.device_group,
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        mirror_address_objects=body.mirror_address_objects,
        mirror_nat_rules=body.mirror_nat_rules,
        mirror_interfaces=body.mirror_interfaces,
        mirror_dhcp_leases=body.mirror_dhcp_leases,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(f)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        firewall_id=f.id,
        firewall_name=f.name,
        new_value=body.model_dump(mode="json", exclude={"api_key"}),
    )
    await db.commit()
    await db.refresh(f)
    return _to_response(f)


@router.put("/firewalls/{firewall_id}", response_model=FirewallResponse)
async def update_firewall(
    firewall_id: uuid.UUID, body: FirewallUpdate, db: DB, user: SuperAdmin
) -> FirewallResponse:
    f = await db.get(PANOSFirewall, firewall_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Palo Alto firewall not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", f.ipam_space_id)
    new_dns = changes.get("dns_group_id", f.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "api_key":
            if v:
                f.api_key_encrypted = encrypt_str(v)
        else:
            setattr(f, k, v)

    if f.is_panorama and not (f.device_group or "").strip():
        raise HTTPException(
            status_code=422, detail="device_group is required for a Panorama target"
        )

    _audit(
        db,
        user=user,
        action="update",
        firewall_id=f.id,
        firewall_name=f.name,
        changed_fields=list(changes.keys()),
        new_value={k: str(v) for k, v in changes.items() if k != "api_key"},
    )
    await db.commit()
    await db.refresh(f)
    return _to_response(f)


@router.delete("/firewalls/{firewall_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_firewall(
    firewall_id: uuid.UUID, db: DB, user: SuperAdmin, force: bool = False
) -> None:
    f = await db.get(PANOSFirewall, firewall_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Palo Alto firewall not found")
    from app.services.block_sync.delete_guard import (  # noqa: PLC0415
        assert_block_sync_deletable,
    )

    await assert_block_sync_deletable(
        db,
        target_kind="paloalto",
        target_id=f.id,
        armed=f.block_sync_enabled,
        force=force,
    )
    # #601 — sweep any active block-sync push rows for this target (polymorphic
    # target_id, so nothing cascades). Does NOT lift the tags off the firewall
    # — disarm the target first if it should stop enforcing them.
    from sqlalchemy import delete as sa_delete  # noqa: PLC0415

    from app.models.block_sync import NetworkBlockPush  # noqa: PLC0415

    await db.execute(
        sa_delete(NetworkBlockPush).where(
            NetworkBlockPush.target_kind == "paloalto",
            NetworkBlockPush.target_id == f.id,
        )
    )
    _audit(db, user=user, action="delete", firewall_id=f.id, firewall_name=f.name)
    await db.delete(f)
    await db.commit()


@router.post(
    "/firewalls/{firewall_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=StatusResponse,
)
async def sync_firewall(firewall_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    f = await db.get(PANOSFirewall, firewall_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Palo Alto firewall not found")

    add_trigger_audit(
        db,
        user,
        resource_type="panos_firewall",
        resource_id=f.id,
        resource_display=str(getattr(f, "name", None) or f.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.panos_sync import sync_firewall_now  # noqa: PLC0415

    try:
        result = sync_firewall_now.delay(str(f.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.get("/firewalls/{firewall_id}/objects", response_model=list[FirewallObjectResponse])
async def list_objects(
    firewall_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[FirewallObjectResponse]:
    f = await db.get(PANOSFirewall, firewall_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Palo Alto firewall not found")
    rows = (
        (
            await db.execute(
                select(FirewallObject)
                .where(FirewallObject.panos_firewall_id == firewall_id)
                .order_by(FirewallObject.name)
            )
        )
        .scalars()
        .all()
    )
    return [
        FirewallObjectResponse(
            id=o.id,
            name=o.name,
            kind=o.kind,
            value=o.value,
            description=o.description,
            tags=list(o.tags or []),
            resolved_cidr=str(o.resolved_cidr) if o.resolved_cidr else None,
            ip_address_id=o.ip_address_id,
            subnet_id=o.subnet_id,
            unlinked=bool(o.resolved_cidr) and o.ip_address_id is None and o.subnet_id is None,
        )
        for o in rows
    ]


@router.get("/firewalls/{firewall_id}/drift", response_model=DriftReport)
async def drift_report(firewall_id: uuid.UUID, db: DB, _: CurrentUser) -> DriftReport:
    """Two-way drift between the firewall's address objects and IPAM:
    objects that resolve to a CIDR/IP but link no IPAM row, and in-space
    subnets that no firewall object covers."""
    f = await db.get(PANOSFirewall, firewall_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Palo Alto firewall not found")

    total = (
        await db.scalar(
            select(func.count())
            .select_from(FirewallObject)
            .where(FirewallObject.panos_firewall_id == firewall_id)
        )
        or 0
    )
    unlinked = (
        await db.scalar(
            select(func.count())
            .select_from(FirewallObject)
            .where(FirewallObject.panos_firewall_id == firewall_id)
            .where(FirewallObject.resolved_cidr.isnot(None))
            .where(FirewallObject.ip_address_id.is_(None))
            .where(FirewallObject.subnet_id.is_(None))
        )
        or 0
    )

    # Subnets in the bound space with no firewall object pointing at them.
    covered_subnet_ids = set(
        (
            await db.execute(
                select(FirewallObject.subnet_id)
                .where(FirewallObject.panos_firewall_id == firewall_id)
                .where(FirewallObject.subnet_id.isnot(None))
            )
        )
        .scalars()
        .all()
    )
    space_subnets = (
        await db.execute(
            select(Subnet.id, Subnet.network).where(Subnet.space_id == f.ipam_space_id)
        )
    ).all()
    uncovered = [str(net) for sid, net in space_subnets if sid not in covered_subnet_ids]

    return DriftReport(
        objects_total=int(total),
        objects_unlinked=int(unlinked),
        subnets_uncovered=len(uncovered),
        subnets_uncovered_cidrs=uncovered[:200],
    )


@router.post("/firewalls/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    host = body.host
    port = body.port or 443
    verify_tls = body.verify_tls if body.verify_tls is not None else True
    ca_bundle_pem = body.ca_bundle_pem or ""
    api_version = body.api_version or "10.1"
    is_panorama = body.is_panorama or False
    vsys = body.vsys or "vsys1"
    device_group = body.device_group or ""
    api_key = body.api_key

    if body.firewall_id is not None:
        stored = await db.get(PANOSFirewall, body.firewall_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Palo Alto firewall not found")
        host = host or stored.host
        port = body.port or stored.port
        verify_tls = body.verify_tls if body.verify_tls is not None else stored.verify_tls
        ca_bundle_pem = (
            body.ca_bundle_pem if body.ca_bundle_pem is not None else stored.ca_bundle_pem
        )
        api_version = body.api_version or stored.api_version
        is_panorama = body.is_panorama if body.is_panorama is not None else stored.is_panorama
        vsys = body.vsys or stored.vsys
        device_group = body.device_group if body.device_group is not None else stored.device_group
        if not api_key and stored.api_key_encrypted:
            try:
                api_key = decrypt_str(stored.api_key_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored API key could not be decrypted — re-enter it",
                ) from exc

    if not host:
        raise HTTPException(status_code=422, detail="host is required")

    # SECURITY: advisory SSRF guard — log the resolved firewall host IP.
    # Not hard-blocked: firewalls live on the RFC1918 LAN by definition.
    assert_safe_target(host, label="paloalto")

    minted_key: str | None = None
    try:
        if not api_key:
            if not (body.username and body.password):
                raise HTTPException(
                    status_code=422,
                    detail="provide either api_key, or username + password to mint one",
                )
            api_key = await PANOSClient.keygen(
                host=host,
                port=port,
                username=body.username,
                password=body.password,
                verify_tls=verify_tls,
                ca_bundle_pem=ca_bundle_pem,
            )
            minted_key = api_key

        async with PANOSClient(
            host=host,
            port=port,
            api_key=api_key,
            api_version=api_version,
            is_panorama=is_panorama,
            vsys=vsys,
            device_group=device_group,
            verify_tls=verify_tls,
            ca_bundle_pem=ca_bundle_pem,
        ) as client:
            info = await client.get_system_info()
    except HTTPException:
        raise
    except PANOSClientError as exc:
        return TestConnectionResponse(ok=False, message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))

    if body.firewall_id is not None:
        stored = await db.get(PANOSFirewall, body.firewall_id)
        if stored is not None:
            stored.sw_version = info.version
            stored.model = info.model
            stored.last_sync_error = None
            await db.commit()

    return TestConnectionResponse(
        ok=True,
        message=f"Connected to PAN-OS {info.version} ({info.model or 'unknown model'})".rstrip(),
        sw_version=info.version,
        model=info.model or None,
        api_key=minted_key,
    )


__all__ = ["router"]

"""Cisco Meraki integration CRUD + probe + mirror-read endpoints (#606).

Parallels ``app/api/v1/panos/router.py``. The Dashboard API key is
Fernet-encrypted at rest; admin-only surface. The read-only mirror is
configured here; the per-client-block *enforcement* arming
(``block_sync_enabled`` + write key + policy) rides the shared #601 block-sync
target endpoints (``/block-sync/targets/meraki/...``), not this router.
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
from app.models.audit import AuditLog
from app.models.dns import DNSServerGroup
from app.models.ipam import IPSpace, Subnet
from app.models.meraki import MerakiOrg
from app.models.panos import FirewallObject
from app.services.meraki.client import MerakiClient, MerakiClientError

router = APIRouter(
    tags=["meraki"],
    dependencies=[Depends(require_resource_permission("meraki_org"))],
)


# ── Pydantic schemas ─────────────────────────────────────────────────


class OrgBase(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    base_url: str = "https://api.meraki.com/api/v1"
    org_id: str
    network_ids: list[str] = []
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None = None
    mirror_policy_objects: bool = True
    mirror_vlans: bool = True
    mirror_dhcp_reservations: bool = True
    mirror_nat_rules: bool = True
    mirror_clients: bool = False
    sync_interval_seconds: int = 300

    @field_validator("base_url")
    @classmethod
    def _strip_base(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        return v

    @field_validator("org_id")
    @classmethod
    def _strip_org(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("org_id is required")
        return v

    @field_validator("sync_interval_seconds")
    @classmethod
    def _floor_interval(cls, v: int) -> int:
        if v < 30:
            raise ValueError("sync_interval_seconds must be ≥ 30")
        return v


class OrgCreate(OrgBase):
    # The Meraki Dashboard API key. Encrypted before persist. Required on create.
    api_key: str

    @field_validator("api_key")
    @classmethod
    def _valid_api_key(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("api_key is required")
        return v

    _check_api_key = field_validator("api_key")(header_secret)


class OrgUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    base_url: str | None = None
    org_id: str | None = None
    network_ids: list[str] | None = None
    # Omit or send empty to keep the stored key; non-empty rotates.
    api_key: str | None = None
    ipam_space_id: uuid.UUID | None = None
    dns_group_id: uuid.UUID | None = None
    mirror_policy_objects: bool | None = None
    mirror_vlans: bool | None = None
    mirror_dhcp_reservations: bool | None = None
    mirror_nat_rules: bool | None = None
    mirror_clients: bool | None = None
    sync_interval_seconds: int | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class OrgResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    base_url: str
    org_id: str
    network_ids: list[str]
    api_key_present: bool
    ipam_space_id: uuid.UUID
    dns_group_id: uuid.UUID | None
    mirror_policy_objects: bool
    mirror_vlans: bool
    mirror_dhcp_reservations: bool
    mirror_nat_rules: bool
    mirror_clients: bool
    sync_interval_seconds: int
    # Enforcement (#601 tier) — read-only surfacing here; armed via block-sync.
    block_sync_enabled: bool
    block_policy_name: str
    last_block_sync_at: datetime | None
    last_block_sync_error: str | None
    last_synced_at: datetime | None
    last_sync_error: str | None
    network_count: int | None
    object_count: int | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    org_id_pk: uuid.UUID | None = None  # the SpatiumDDI row id (to reuse stored key)
    base_url: str | None = None
    org_id: str | None = None
    api_key: str | None = None

    _check_api_key = field_validator("api_key")(header_secret)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    org_name: str | None = None
    network_count: int | None = None


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
    unlinked: bool


class DriftReport(BaseModel):
    objects_total: int
    objects_unlinked: int
    subnets_uncovered: int
    subnets_uncovered_cidrs: list[str]


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(o: MerakiOrg) -> OrgResponse:
    return OrgResponse(
        id=o.id,
        name=o.name,
        description=o.description,
        enabled=o.enabled,
        base_url=o.base_url,
        org_id=o.org_id,
        network_ids=list(o.network_ids or []),
        api_key_present=bool(o.api_key_encrypted),
        ipam_space_id=o.ipam_space_id,
        dns_group_id=o.dns_group_id,
        mirror_policy_objects=o.mirror_policy_objects,
        mirror_vlans=o.mirror_vlans,
        mirror_dhcp_reservations=o.mirror_dhcp_reservations,
        mirror_nat_rules=o.mirror_nat_rules,
        mirror_clients=o.mirror_clients,
        sync_interval_seconds=o.sync_interval_seconds,
        block_sync_enabled=o.block_sync_enabled,
        block_policy_name=o.block_policy_name,
        last_block_sync_at=o.last_block_sync_at,
        last_block_sync_error=o.last_block_sync_error,
        last_synced_at=o.last_synced_at,
        last_sync_error=o.last_sync_error,
        network_count=o.network_count,
        object_count=o.object_count,
        created_at=o.created_at,
        modified_at=o.modified_at,
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
    org_id: uuid.UUID,
    org_name: str,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            user_display_name=user.display_name if user else "system",
            auth_source=user.auth_source if user else "system",
            action=action,
            resource_type="meraki_org",
            resource_id=str(org_id),
            resource_display=org_name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/orgs", response_model=list[OrgResponse])
async def list_orgs(db: DB, _: CurrentUser) -> list[OrgResponse]:
    res = await db.execute(select(MerakiOrg).order_by(MerakiOrg.name))
    return [_to_response(o) for o in res.scalars().all()]


@router.post("/orgs", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def create_org(body: OrgCreate, db: DB, user: SuperAdmin) -> OrgResponse:
    forbid_in_demo_mode("Meraki organization registration is disabled")
    await _validate_bindings(db, body.ipam_space_id, body.dns_group_id)

    existing = await db.execute(select(MerakiOrg).where(MerakiOrg.name == body.name))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="A Meraki org with that name exists")

    o = MerakiOrg(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        base_url=body.base_url,
        org_id=body.org_id,
        network_ids=body.network_ids,
        api_key_encrypted=encrypt_str(body.api_key),
        ipam_space_id=body.ipam_space_id,
        dns_group_id=body.dns_group_id,
        mirror_policy_objects=body.mirror_policy_objects,
        mirror_vlans=body.mirror_vlans,
        mirror_dhcp_reservations=body.mirror_dhcp_reservations,
        mirror_nat_rules=body.mirror_nat_rules,
        mirror_clients=body.mirror_clients,
        sync_interval_seconds=body.sync_interval_seconds,
    )
    db.add(o)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        org_id=o.id,
        org_name=o.name,
        new_value=body.model_dump(mode="json", exclude={"api_key"}),
    )
    await db.commit()
    await db.refresh(o)
    return _to_response(o)


@router.put("/orgs/{org_pk}", response_model=OrgResponse)
async def update_org(org_pk: uuid.UUID, body: OrgUpdate, db: DB, user: SuperAdmin) -> OrgResponse:
    o = await db.get(MerakiOrg, org_pk)
    if o is None:
        raise HTTPException(status_code=404, detail="Meraki org not found")

    changes = body.model_dump(exclude_unset=True)
    new_ipam = changes.get("ipam_space_id", o.ipam_space_id)
    new_dns = changes.get("dns_group_id", o.dns_group_id)
    if "ipam_space_id" in changes or "dns_group_id" in changes:
        await _validate_bindings(db, new_ipam, new_dns)

    for k, v in changes.items():
        if k == "api_key":
            if v:
                o.api_key_encrypted = encrypt_str(v)
        else:
            setattr(o, k, v)

    _audit(
        db,
        user=user,
        action="update",
        org_id=o.id,
        org_name=o.name,
        changed_fields=list(changes.keys()),
        new_value={k: str(v) for k, v in changes.items() if k != "api_key"},
    )
    await db.commit()
    await db.refresh(o)
    return _to_response(o)


@router.delete("/orgs/{org_pk}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_org(org_pk: uuid.UUID, db: DB, user: SuperAdmin, force: bool = False) -> None:
    o = await db.get(MerakiOrg, org_pk)
    if o is None:
        raise HTTPException(status_code=404, detail="Meraki org not found")
    from app.services.block_sync.delete_guard import (  # noqa: PLC0415
        assert_block_sync_deletable,
    )

    await assert_block_sync_deletable(
        db,
        target_kind="meraki",
        target_id=o.id,
        armed=o.block_sync_enabled,
        force=force,
    )
    # #601 — sweep any active block-sync push rows for this target (polymorphic
    # target_id, so nothing cascades). Does NOT restore blocked clients — disarm
    # the target first if it should stop enforcing them.
    from sqlalchemy import delete as sa_delete  # noqa: PLC0415

    from app.models.block_sync import NetworkBlockPush  # noqa: PLC0415

    await db.execute(
        sa_delete(NetworkBlockPush).where(
            NetworkBlockPush.target_kind == "meraki",
            NetworkBlockPush.target_id == o.id,
        )
    )
    _audit(db, user=user, action="delete", org_id=o.id, org_name=o.name)
    await db.delete(o)
    await db.commit()


@router.post(
    "/orgs/{org_pk}/sync", status_code=status.HTTP_202_ACCEPTED, response_model=StatusResponse
)
async def sync_org(org_pk: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    o = await db.get(MerakiOrg, org_pk)
    if o is None:
        raise HTTPException(status_code=404, detail="Meraki org not found")

    add_trigger_audit(
        db,
        user,
        resource_type="meraki_org",
        resource_id=o.id,
        resource_display=str(getattr(o, "name", None) or o.id),
        action="sync",
    )
    await db.commit()

    from app.tasks.meraki_sync import sync_org_now  # noqa: PLC0415

    try:
        result = sync_org_now.delay(str(o.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.get("/orgs/{org_pk}/objects", response_model=list[FirewallObjectResponse])
async def list_objects(org_pk: uuid.UUID, db: DB, _: CurrentUser) -> list[FirewallObjectResponse]:
    o = await db.get(MerakiOrg, org_pk)
    if o is None:
        raise HTTPException(status_code=404, detail="Meraki org not found")
    rows = (
        (
            await db.execute(
                select(FirewallObject)
                .where(FirewallObject.meraki_org_id == org_pk)
                .order_by(FirewallObject.name)
            )
        )
        .scalars()
        .all()
    )
    return [
        FirewallObjectResponse(
            id=obj.id,
            name=obj.name,
            kind=obj.kind,
            value=obj.value,
            description=obj.description,
            tags=list(obj.tags or []),
            resolved_cidr=str(obj.resolved_cidr) if obj.resolved_cidr else None,
            ip_address_id=obj.ip_address_id,
            subnet_id=obj.subnet_id,
            unlinked=bool(obj.resolved_cidr)
            and obj.ip_address_id is None
            and obj.subnet_id is None,
        )
        for obj in rows
    ]


@router.get("/orgs/{org_pk}/drift", response_model=DriftReport)
async def drift_report(org_pk: uuid.UUID, db: DB, _: CurrentUser) -> DriftReport:
    """Two-way drift between the org's policy objects and IPAM."""
    o = await db.get(MerakiOrg, org_pk)
    if o is None:
        raise HTTPException(status_code=404, detail="Meraki org not found")

    total = (
        await db.scalar(
            select(func.count())
            .select_from(FirewallObject)
            .where(FirewallObject.meraki_org_id == org_pk)
        )
        or 0
    )
    unlinked = (
        await db.scalar(
            select(func.count())
            .select_from(FirewallObject)
            .where(FirewallObject.meraki_org_id == org_pk)
            .where(FirewallObject.resolved_cidr.isnot(None))
            .where(FirewallObject.ip_address_id.is_(None))
            .where(FirewallObject.subnet_id.is_(None))
        )
        or 0
    )
    covered_subnet_ids = set(
        (
            await db.execute(
                select(FirewallObject.subnet_id)
                .where(FirewallObject.meraki_org_id == org_pk)
                .where(FirewallObject.subnet_id.isnot(None))
            )
        )
        .scalars()
        .all()
    )
    space_subnets = (
        await db.execute(
            select(Subnet.id, Subnet.network).where(Subnet.space_id == o.ipam_space_id)
        )
    ).all()
    uncovered = [str(net) for sid, net in space_subnets if sid not in covered_subnet_ids]

    return DriftReport(
        objects_total=int(total),
        objects_unlinked=int(unlinked),
        subnets_uncovered=len(uncovered),
        subnets_uncovered_cidrs=uncovered[:200],
    )


@router.post("/orgs/test", response_model=TestConnectionResponse)
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    base_url = body.base_url or "https://api.meraki.com/api/v1"
    org_id = body.org_id
    api_key = body.api_key

    if body.org_id_pk is not None:
        stored = await db.get(MerakiOrg, body.org_id_pk)
        if stored is None:
            raise HTTPException(status_code=404, detail="Meraki org not found")
        base_url = body.base_url or stored.base_url
        org_id = org_id or stored.org_id
        if not api_key and stored.api_key_encrypted:
            try:
                api_key = decrypt_str(stored.api_key_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Stored API key could not be decrypted — re-enter it",
                ) from exc

    if not org_id:
        raise HTTPException(status_code=422, detail="org_id is required")
    if not api_key:
        raise HTTPException(status_code=422, detail="api_key is required")

    try:
        async with MerakiClient(
            api_key=api_key, org_id=org_id, base_url=base_url, verify_tls=True
        ) as client:
            info = await client.get_organization()
            networks = await client.list_networks()
    except MerakiClientError as exc:
        return TestConnectionResponse(ok=False, message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))

    if body.org_id_pk is not None:
        stored = await db.get(MerakiOrg, body.org_id_pk)
        if stored is not None:
            stored.network_count = len(networks)
            stored.last_sync_error = None
            await db.commit()

    return TestConnectionResponse(
        ok=True,
        message=f"Connected to Meraki org '{info.name}' ({len(networks)} appliance networks)",
        org_name=info.name,
        network_count=len(networks),
    )


__all__ = ["router"]

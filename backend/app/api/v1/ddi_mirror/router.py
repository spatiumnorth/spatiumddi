"""Commercial-DDI live mirror: target CRUD, test connection, mirror browse and
the cutover-rehearsal diff (#4729).

Mounted at ``/migration/ddi-mirror`` behind the ``migration.ddi_mirror`` feature
module. Superadmin writes; reads need ``read`` on ``ddi_mirror_target``. The
password is Fernet-encrypted at rest and never returned. The mirror is
read-only toward the source and writes nothing into live IPAM / DNS / DHCP.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.api.v1._common import StatusResponse, add_trigger_audit
from app.core.celery_dispatch import dispatch
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import require_resource_permission
from app.core.ssrf import assert_safe_target
from app.core.stored_secret_guard import (
    require_secret_for_changed_connection,
    require_secret_with_destination_change,
)
from app.models.audit import AuditLog
from app.models.ddi_mirror import DDIMirrorObject, DDIMirrorTarget
from app.services.api_token_scopes import token_write
from app.services.ddi_mirror.base import ALL_KINDS, DDIProviderError, ProviderConfig
from app.services.ddi_mirror.registry import (
    PLANNED_VENDORS,
    PROVIDERS,
    get_provider_class,
    vendor_error,
)
from app.services.ddi_mirror.rehearsal import ACTIONS, build_rehearsal

router = APIRouter(
    tags=["ddi-mirror"],
    dependencies=[Depends(require_resource_permission("ddi_mirror_target"))],
)

_RESOURCE = "ddi_mirror_target"


# ── Schemas ──────────────────────────────────────────────────────────


def _clean_url(v: str) -> str:
    v = v.strip().rstrip("/")
    parts = urlsplit(v)
    if parts.scheme != "https":
        raise ValueError("base_url must be an https:// URL (the credentials ride basic auth)")
    if not parts.hostname:
        raise ValueError("base_url has no host")
    if parts.username or parts.password:
        raise ValueError("base_url must not carry credentials; use username / password")
    if parts.path or parts.query or parts.fragment:
        raise ValueError(
            "base_url is scheme + host (+ port) only; the /wapi/<version> path is added"
        )
    return v


class TargetBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    enabled: bool = True
    vendor: str = "infoblox"
    base_url: str
    api_version: str = Field(default="v2.12", pattern=r"^v\d+(\.\d+)?$")
    verify_tls: bool = True
    ca_bundle_pem: str = ""
    username: str = Field(min_length=1, max_length=255)
    network_view: str = ""
    dns_view: str = ""
    sync_interval_seconds: int = 900
    page_size: int = 500

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _clean_url(v)

    @field_validator("sync_interval_seconds")
    @classmethod
    def _interval(cls, v: int) -> int:
        if v < 60:
            raise ValueError("sync_interval_seconds must be >= 60")
        return v

    @field_validator("page_size")
    @classmethod
    def _page(cls, v: int) -> int:
        if not 50 <= v <= 1000:
            raise ValueError("page_size must be in 50..1000")
        return v


class TargetCreate(TargetBase):
    password: str = Field(min_length=1)


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    enabled: bool | None = None
    vendor: str | None = None
    base_url: str | None = None
    api_version: str | None = Field(default=None, pattern=r"^v\d+(\.\d+)?$")
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    username: str | None = Field(default=None, min_length=1, max_length=255)
    # Omit or send empty to keep the stored password; non-empty rotates.
    password: str | None = None
    network_view: str | None = None
    dns_view: str | None = None
    sync_interval_seconds: int | None = None
    page_size: int | None = None

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return None if v is None else _clean_url(v)

    @field_validator("sync_interval_seconds")
    @classmethod
    def _interval(cls, v: int | None) -> int | None:
        if v is not None and v < 60:
            raise ValueError("sync_interval_seconds must be >= 60")
        return v

    @field_validator("page_size")
    @classmethod
    def _page(cls, v: int | None) -> int | None:
        if v is not None and not 50 <= v <= 1000:
            raise ValueError("page_size must be in 50..1000")
        return v


class TargetResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    enabled: bool
    vendor: str
    base_url: str
    api_version: str
    verify_tls: bool
    ca_bundle_present: bool
    username: str
    password_present: bool
    network_view: str
    dns_view: str
    sync_interval_seconds: int
    page_size: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    last_sync_warning: str | None
    source_version: str | None
    object_count: int | None
    last_report: dict[str, Any] | None
    created_at: datetime
    modified_at: datetime


class TestConnectionRequest(BaseModel):
    target_id: uuid.UUID | None = None
    vendor: str | None = None
    base_url: str | None = None
    api_version: str | None = Field(default=None, pattern=r"^v\d+(\.\d+)?$")
    verify_tls: bool | None = None
    ca_bundle_pem: str | None = None
    username: str | None = None
    password: str | None = None

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return None if v is None else _clean_url(v)


class TestConnectionResponse(BaseModel):
    ok: bool
    message: str
    version: str | None = None


class VendorInfo(BaseModel):
    vendor: str
    label: str
    supported: bool
    kinds: list[str]


class MirrorObjectResponse(BaseModel):
    id: uuid.UUID
    kind: str
    name: str
    view: str
    value: str
    comment: str
    source_ref: str
    data: dict[str, Any]
    modified_at: datetime


class MirrorObjectPage(BaseModel):
    total: int
    items: list[MirrorObjectResponse]


class KindCountsResponse(BaseModel):
    total: int
    create: int
    exists: int
    differs: int


class RehearsalItemResponse(BaseModel):
    kind: str
    name: str
    value: str
    view: str
    action: str
    differences: list[str]


class RehearsalResponse(BaseModel):
    target_id: uuid.UUID
    synced_at: datetime | None
    totals: KindCountsResponse
    kinds: dict[str, KindCountsResponse]
    total_items: int
    items: list[RehearsalItemResponse]


# ── Helpers ──────────────────────────────────────────────────────────


def _to_response(t: DDIMirrorTarget) -> TargetResponse:
    return TargetResponse(
        id=t.id,
        name=t.name,
        description=t.description,
        enabled=t.enabled,
        vendor=t.vendor,
        base_url=t.base_url,
        api_version=t.api_version,
        verify_tls=t.verify_tls,
        ca_bundle_present=bool(t.ca_bundle_pem),
        username=t.username,
        password_present=bool(t.password_encrypted),
        network_view=t.network_view,
        dns_view=t.dns_view,
        sync_interval_seconds=t.sync_interval_seconds,
        page_size=t.page_size,
        last_synced_at=t.last_synced_at,
        last_sync_error=t.last_sync_error,
        last_sync_warning=t.last_sync_warning,
        source_version=t.source_version,
        object_count=t.object_count,
        last_report=t.last_report,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


def _audit(
    db: Any,
    *,
    user: Any,
    action: str,
    target: DDIMirrorTarget,
    changed_fields: list[str] | None = None,
    new_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type=_RESOURCE,
            resource_id=str(target.id),
            resource_display=target.name,
            changed_fields=changed_fields,
            new_value=new_value,
        )
    )


def _require_vendor(vendor: str) -> None:
    err = vendor_error(vendor)
    if err:
        raise HTTPException(status_code=422, detail=err)


async def _get(db: Any, target_id: uuid.UUID) -> DDIMirrorTarget:
    t = await db.get(DDIMirrorTarget, target_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Mirror target not found")
    return t


async def _name_taken(db: Any, name: str, *, exclude: uuid.UUID | None = None) -> bool:
    stmt = select(DDIMirrorTarget.id).where(func.lower(DDIMirrorTarget.name) == name.lower())
    if exclude is not None:
        stmt = stmt.where(DDIMirrorTarget.id != exclude)
    return (await db.execute(stmt)).first() is not None


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/vendors", response_model=list[VendorInfo])
async def list_vendors(_: CurrentUser) -> list[VendorInfo]:
    out = [
        VendorInfo(vendor=v, label=cls.label, supported=True, kinds=list(cls.kinds))
        for v, cls in sorted(PROVIDERS.items())
    ]
    out += [VendorInfo(vendor=v, label=v, supported=False, kinds=[]) for v in PLANNED_VENDORS]
    return out


@router.get("/targets", response_model=list[TargetResponse])
async def list_targets(db: DB, _: CurrentUser) -> list[TargetResponse]:
    rows = (await db.execute(select(DDIMirrorTarget).order_by(DDIMirrorTarget.name))).scalars()
    return [_to_response(t) for t in rows.all()]


@router.post("/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
@token_write("Registers a stored credential for a commercial DDI source")
async def create_target(body: TargetCreate, db: DB, user: SuperAdmin) -> TargetResponse:
    forbid_in_demo_mode("Commercial DDI mirror registration is disabled")
    _require_vendor(body.vendor)
    if await _name_taken(db, body.name):
        raise HTTPException(status_code=409, detail="A mirror target with that name exists")
    t = DDIMirrorTarget(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        vendor=body.vendor,
        base_url=body.base_url,
        api_version=body.api_version,
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
        username=body.username,
        password_encrypted=encrypt_str(body.password),
        network_view=body.network_view,
        dns_view=body.dns_view,
        sync_interval_seconds=body.sync_interval_seconds,
        page_size=body.page_size,
    )
    db.add(t)
    await db.flush()
    _audit(
        db,
        user=user,
        action="create",
        target=t,
        new_value=body.model_dump(mode="json", exclude={"password"}),
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.get("/targets/{target_id}", response_model=TargetResponse)
async def get_target(target_id: uuid.UUID, db: DB, _: CurrentUser) -> TargetResponse:
    return _to_response(await _get(db, target_id))


@router.put("/targets/{target_id}", response_model=TargetResponse)
@token_write("Changes the stored credential or destination of a commercial DDI source")
async def update_target(
    target_id: uuid.UUID, body: TargetUpdate, db: DB, user: SuperAdmin
) -> TargetResponse:
    t = await _get(db, target_id)
    changes = body.model_dump(exclude_unset=True)
    if "vendor" in changes:
        _require_vendor(changes["vendor"])
    if "name" in changes and await _name_taken(db, changes["name"], exclude=t.id):
        raise HTTPException(status_code=409, detail="A mirror target with that name exists")
    require_secret_with_destination_change(
        t,
        changes,
        destination=["base_url", "username"],
        secrets={"password": t.password_encrypted},
        blank_keeps=("password",),
    )
    for k, v in changes.items():
        if k == "password":
            if v:
                t.password_encrypted = encrypt_str(v)
        elif v is not None or k in ("description", "ca_bundle_pem", "network_view", "dns_view"):
            setattr(t, k, v if v is not None else "")
    _audit(
        db,
        user=user,
        action="update",
        target=t,
        changed_fields=list(changes.keys()),
        new_value={k: str(v) for k, v in changes.items() if k != "password"},
    )
    await db.commit()
    await db.refresh(t)
    return _to_response(t)


@router.delete("/targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: uuid.UUID, db: DB, user: SuperAdmin) -> None:
    """Remove the target and, by FK cascade, its mirrored objects. Nothing live
    is touched: the mirror never wrote to IPAM / DNS / DHCP."""
    t = await _get(db, target_id)
    _audit(db, user=user, action="delete", target=t)
    await db.delete(t)
    await db.commit()


@router.post(
    "/targets/{target_id}/sync",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=StatusResponse,
)
@token_write("Queues a pull from a commercial DDI source (outbound)")
async def sync_target(target_id: uuid.UUID, db: DB, user: SuperAdmin) -> StatusResponse:
    t = await _get(db, target_id)
    add_trigger_audit(
        db,
        user,
        resource_type=_RESOURCE,
        resource_id=t.id,
        resource_display=t.name,
        action="sync",
    )
    await db.commit()

    from app.tasks.ddi_mirror_sync import sync_target_now  # noqa: PLC0415

    try:
        result = await dispatch(sync_target_now, str(t.id))
        return StatusResponse(status="queued", task_id=result.id)
    except Exception:  # noqa: BLE001
        return StatusResponse(status="broker_unavailable", task_id="")


@router.post("/targets/test", response_model=TestConnectionResponse)
@token_write("Connects to a caller-supplied commercial DDI URL with credentials (outbound)")
async def test_connection(
    body: TestConnectionRequest, db: DB, _: SuperAdmin
) -> TestConnectionResponse:
    vendor = body.vendor or "infoblox"
    base_url, api_version = body.base_url, body.api_version or "v2.12"
    verify_tls = body.verify_tls if body.verify_tls is not None else True
    ca_bundle_pem = body.ca_bundle_pem or ""
    username, password = body.username, body.password

    stored: DDIMirrorTarget | None = None
    if body.target_id is not None:
        stored = await _get(db, body.target_id)
        require_secret_for_changed_connection(
            stored,
            {"base_url": body.base_url, "username": body.username, "password": body.password},
            destination=("base_url", "username"),
            secrets={"password": stored.password_encrypted},
        )
        vendor = body.vendor or stored.vendor
        base_url = base_url or stored.base_url
        api_version = body.api_version or stored.api_version
        verify_tls = body.verify_tls if body.verify_tls is not None else stored.verify_tls
        ca_bundle_pem = (
            body.ca_bundle_pem if body.ca_bundle_pem is not None else stored.ca_bundle_pem
        )
        username = username or stored.username
        if not password and stored.password_encrypted:
            try:
                password = decrypt_str(stored.password_encrypted)
            except ValueError as exc:
                raise HTTPException(
                    status_code=500, detail="Stored password could not be decrypted — re-enter it"
                ) from exc

    _require_vendor(vendor)
    if not base_url:
        raise HTTPException(status_code=422, detail="base_url is required")
    if not username or not password:
        raise HTTPException(status_code=422, detail="username and password are required")

    # Advisory SSRF guard: log the resolved host. Not hard-blocked, since the
    # estate being mirrored lives on the operator's own network by definition.
    assert_safe_target(urlsplit(base_url).hostname or "", label="ddi_mirror")

    cfg = ProviderConfig(
        base_url=base_url,
        api_version=api_version,
        username=username,
        password=password,
        verify_tls=verify_tls,
        ca_bundle_pem=ca_bundle_pem,
    )
    try:
        async with get_provider_class(vendor)(cfg) as provider:
            info = await provider.probe()
    except DDIProviderError as exc:
        return TestConnectionResponse(ok=False, message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return TestConnectionResponse(ok=False, message=str(exc))

    if stored is not None:
        stored.source_version = info.version
        stored.last_sync_error = None
        await db.commit()
    return TestConnectionResponse(
        ok=True,
        message=f"Connected ({info.version}{', ' + info.detail if info.detail else ''})",
        version=info.version,
    )


@router.get("/targets/{target_id}/objects", response_model=MirrorObjectPage)
async def list_objects(
    target_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    kind: str | None = Query(default=None),
    q: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> MirrorObjectPage:
    await _get(db, target_id)
    if kind is not None and kind not in ALL_KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {', '.join(ALL_KINDS)}")
    cond = [DDIMirrorObject.target_id == target_id]
    if kind:
        cond.append(DDIMirrorObject.kind == kind)
    if q:
        like = f"%{q.lower()}%"
        cond.append(
            or_(
                func.lower(DDIMirrorObject.name).like(like),
                func.lower(DDIMirrorObject.value).like(like),
                func.lower(DDIMirrorObject.comment).like(like),
            )
        )
    total = await db.scalar(select(func.count()).select_from(DDIMirrorObject).where(*cond)) or 0
    rows = (
        (
            await db.execute(
                select(DDIMirrorObject)
                .where(*cond)
                .order_by(DDIMirrorObject.kind, DDIMirrorObject.name, DDIMirrorObject.source_ref)
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return MirrorObjectPage(
        total=int(total),
        items=[
            MirrorObjectResponse(
                id=o.id,
                kind=o.kind,
                name=o.name,
                view=o.view,
                value=o.value,
                comment=o.comment,
                source_ref=o.source_ref,
                data=o.data,
                modified_at=o.modified_at,
            )
            for o in rows
        ],
    )


@router.get("/targets/{target_id}/rehearsal", response_model=RehearsalResponse)
async def rehearsal(
    target_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    kind: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> RehearsalResponse:
    """What importing this mirror into live SpatiumDDI would create, and what
    differs from what is already there. Read-only; computed on request."""
    t = await _get(db, target_id)
    if kind is not None and kind not in ALL_KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {', '.join(ALL_KINDS)}")
    if action is not None and action not in ACTIONS:
        raise HTTPException(status_code=422, detail=f"action must be one of {', '.join(ACTIONS)}")
    counts, total_items, items = await build_rehearsal(
        db, target_id, kind=kind, action=action, limit=limit, offset=offset
    )
    totals = KindCountsResponse(
        total=sum(c.total for c in counts.values()),
        create=sum(c.create for c in counts.values()),
        exists=sum(c.exists for c in counts.values()),
        differs=sum(c.differs for c in counts.values()),
    )
    return RehearsalResponse(
        target_id=t.id,
        synced_at=t.last_synced_at,
        totals=totals,
        kinds={
            k: KindCountsResponse(
                total=c.total, create=c.create, exists=c.exists, differs=c.differs
            )
            for k, c in counts.items()
        },
        total_items=total_items,
        items=[
            RehearsalItemResponse(
                kind=i.kind,
                name=i.name,
                value=i.value,
                view=i.view,
                action=i.action,
                differences=i.differences,
            )
            for i in items
        ],
    )


__all__ = ["router"]

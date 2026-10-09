"""DHCP configuration importer endpoints — preview + commit per source.

Three sources behind one shared canonical IR + commit pipeline:

* ``/dhcp/import/kea/{preview,commit}``  — Kea JSON file upload
* ``/dhcp/import/windows/{servers,preview,commit}`` — Windows DHCP live pull
* ``/dhcp/import/isc/{preview,commit}``  — ISC dhcpd.conf file upload

The split between preview (multipart upload / live pull) and commit
(JSON body carrying the previewed plan) means we don't re-upload /
re-pull on commit. The operator-edited per-scope conflict actions +
IPAM linkage choices ride in the commit body, so the server stays
stateless between the two calls.
"""

from __future__ import annotations

import uuid
from typing import Literal

import structlog
from fastapi import APIRouter, Body, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, SuperAdmin
from app.core.agent_wake import collect_wake, dhcp_group_channel
from app.models.dhcp import DHCPServer
from app.services.dhcp_import import (
    CommitResult,
    IscImportError,
    KeaImportError,
    WindowsDHCPImportError,
    commit_import,
    detect_conflicts,
    parse_isc_config,
    parse_kea_config,
    parse_windows_dhcp_server,
)
from app.services.dhcp_import.canonical import (
    ConflictAction,
    ImportedClientClass,
    ImportedPool,
    ImportedReservation,
    ImportedScope,
    ImportPreview,
    ScopeConflict,
)

logger = structlog.get_logger(__name__)
router = APIRouter()

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024


# ── Pydantic IO models ───────────────────────────────────────────────


class ImportedReservationOut(BaseModel):
    ip_address: str
    mac_address: str
    hostname: str = ""
    client_id: str | None = None
    options: dict = Field(default_factory=dict)


class ImportedPoolOut(BaseModel):
    start_ip: str
    end_ip: str
    pool_type: str = "dynamic"
    name: str = ""
    class_restriction: str | None = None


class ImportedClientClassOut(BaseModel):
    name: str
    match_expression: str = ""
    description: str = ""
    address_family: Literal["ipv4", "ipv6", "dual"] = "ipv4"
    options: dict = Field(default_factory=dict)
    supported: bool = True
    warning: str | None = None


class ImportedScopeOut(BaseModel):
    subnet_cidr: str
    address_family: str
    name: str = ""
    description: str = ""
    lease_time: int = 86400
    min_lease_time: int | None = None
    max_lease_time: int | None = None
    is_active: bool = True
    options: dict = Field(default_factory=dict)
    pools: list[ImportedPoolOut] = Field(default_factory=list)
    reservations: list[ImportedReservationOut] = Field(default_factory=list)
    ddns_enabled: bool = False
    ddns_hostname_policy: str = "client"
    v6_address_mode: str = "stateful"
    skipped_options: dict = Field(default_factory=dict)
    ha_info: str | None = None
    parse_warnings: list[str] = Field(default_factory=list)


class ScopeConflictOut(BaseModel):
    subnet_cidr: str
    existing_scope_id: str | None = None
    existing_subnet_id: str | None = None
    existing_subnet_name: str | None = None
    existing_pool_count: int = 0
    existing_reservation_count: int = 0
    soft_deleted: bool = False
    action: Literal["skip", "overwrite"] = "skip"


class PreviewOut(BaseModel):
    """Preview response shape — also the commit request payload's
    ``plan`` field, so the UI hands back the same shape it received."""

    source: Literal["kea", "windows_dhcp", "isc_dhcp"]
    scopes: list[ImportedScopeOut]
    client_classes: list[ImportedClientClassOut]
    conflicts: list[ScopeConflictOut]
    warnings: list[str]
    unsupported: list[str]
    total_pools: int
    total_reservations: int
    address_family_histogram: dict[str, int]


class ConflictDecision(BaseModel):
    action: Literal["skip", "overwrite"]


class CommitIn(BaseModel):
    target_group_id: uuid.UUID
    # IPAM linkage: required (both) to auto-create subnets that don't
    # already exist; omit to link-only (scopes with no matching subnet
    # fail with an actionable error).
    ipam_space_id: uuid.UUID | None = None
    ipam_block_id: uuid.UUID | None = None
    plan: PreviewOut
    # Keyed by canonical scope CIDR. Scopes the operator left untouched
    # default to skip-on-conflict / create-otherwise.
    conflict_actions: dict[str, ConflictDecision] = Field(default_factory=dict)


class WindowsDHCPPreviewIn(BaseModel):
    server_id: uuid.UUID
    target_group_id: uuid.UUID
    ipam_space_id: uuid.UUID | None = None


class WindowsDHCPServerOption(BaseModel):
    id: uuid.UUID
    name: str
    host: str
    group_id: uuid.UUID | None = None
    group_name: str | None = None
    has_credentials: bool


class CommitScopeOut(BaseModel):
    subnet_cidr: str
    action_taken: Literal["created", "overwrote", "skipped", "failed"]
    scope_id: str | None = None
    subnet_id: str | None = None
    subnet_created: bool = False
    pools_created: int = 0
    reservations_created: int = 0
    error: str | None = None


class CommitOut(BaseModel):
    target_group_id: uuid.UUID
    scopes: list[CommitScopeOut]
    client_classes_created: int
    warnings: list[str]
    total_scopes_created: int
    total_scopes_overwrote: int
    total_scopes_skipped: int
    total_scopes_failed: int
    total_subnets_created: int
    total_pools_created: int
    total_reservations_created: int


# ── Conversion helpers (canonical IR ↔ Pydantic) ─────────────────────


def _scope_to_pydantic(s: ImportedScope) -> ImportedScopeOut:
    return ImportedScopeOut(
        subnet_cidr=s.subnet_cidr,
        address_family=s.address_family,
        name=s.name,
        description=s.description,
        lease_time=s.lease_time,
        min_lease_time=s.min_lease_time,
        max_lease_time=s.max_lease_time,
        is_active=s.is_active,
        options=dict(s.options),
        pools=[ImportedPoolOut(**p.__dict__) for p in s.pools],
        reservations=[ImportedReservationOut(**r.__dict__) for r in s.reservations],
        ddns_enabled=s.ddns_enabled,
        ddns_hostname_policy=s.ddns_hostname_policy,
        v6_address_mode=s.v6_address_mode,
        skipped_options=dict(s.skipped_options),
        ha_info=s.ha_info,
        parse_warnings=list(s.parse_warnings),
    )


def _preview_to_pydantic(p: ImportPreview) -> PreviewOut:
    return PreviewOut(
        source=p.source,
        scopes=[_scope_to_pydantic(s) for s in p.scopes],
        client_classes=[ImportedClientClassOut(**c.__dict__) for c in p.client_classes],
        conflicts=[ScopeConflictOut(**c.__dict__) for c in p.conflicts],
        warnings=list(p.warnings),
        unsupported=list(p.unsupported),
        total_pools=p.total_pools,
        total_reservations=p.total_reservations,
        address_family_histogram=dict(p.address_family_histogram),
    )


def _scope_from_pydantic(o: ImportedScopeOut) -> ImportedScope:
    return ImportedScope(
        subnet_cidr=o.subnet_cidr,
        address_family=o.address_family,
        name=o.name,
        description=o.description,
        lease_time=o.lease_time,
        min_lease_time=o.min_lease_time,
        max_lease_time=o.max_lease_time,
        is_active=o.is_active,
        options=dict(o.options),
        pools=[ImportedPool(**p.model_dump()) for p in o.pools],
        reservations=[ImportedReservation(**r.model_dump()) for r in o.reservations],
        ddns_enabled=o.ddns_enabled,
        ddns_hostname_policy=o.ddns_hostname_policy,
        v6_address_mode=o.v6_address_mode,
        skipped_options=dict(o.skipped_options),
        ha_info=o.ha_info,
        parse_warnings=list(o.parse_warnings),
    )


def _preview_from_pydantic(o: PreviewOut) -> ImportPreview:
    return ImportPreview(
        source=o.source,
        scopes=[_scope_from_pydantic(s) for s in o.scopes],
        client_classes=[ImportedClientClass(**c.model_dump()) for c in o.client_classes],
        conflicts=[ScopeConflict(**c.model_dump()) for c in o.conflicts],
        warnings=list(o.warnings),
        unsupported=list(o.unsupported),
        total_pools=o.total_pools,
        total_reservations=o.total_reservations,
        address_family_histogram=dict(o.address_family_histogram),
    )


def _commit_result_to_pydantic(r: CommitResult) -> CommitOut:
    return CommitOut(
        target_group_id=r.target_group_id,
        scopes=[
            CommitScopeOut(
                subnet_cidr=s.subnet_cidr,
                action_taken=s.action_taken,  # type: ignore[arg-type]
                scope_id=s.scope_id,
                subnet_id=s.subnet_id,
                subnet_created=s.subnet_created,
                pools_created=s.pools_created,
                reservations_created=s.reservations_created,
                error=s.error,
            )
            for s in r.scopes
        ],
        client_classes_created=r.client_classes_created,
        warnings=list(r.warnings),
        total_scopes_created=r.total_scopes_created,
        total_scopes_overwrote=r.total_scopes_overwrote,
        total_scopes_skipped=r.total_scopes_skipped,
        total_scopes_failed=r.total_scopes_failed,
        total_subnets_created=r.total_subnets_created,
        total_pools_created=r.total_pools_created,
        total_reservations_created=r.total_reservations_created,
    )


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Upload exceeds {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
        )
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload")
    return data


def _actions(body: CommitIn) -> dict[str, ConflictAction]:
    return {cidr: decision.action for cidr, decision in body.conflict_actions.items()}


async def _run_commit(
    db: DB, current_user: SuperAdmin, body: CommitIn, *, source: str
) -> CommitOut:
    if body.plan.source != source:
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint={source} plan={body.plan.source}",
        )
    preview = _preview_from_pydantic(body.plan)
    try:
        result = await commit_import(
            db,
            preview=preview,
            target_group_id=body.target_group_id,
            ipam_space_id=body.ipam_space_id,
            ipam_block_id=body.ipam_block_id,
            conflict_actions=_actions(body),
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    # A commit creates scopes (+ optional subnets) under the target
    # group — wake that group's parked agent long-polls so the new
    # config converges immediately (the wake_publishing dependency
    # flushes this after commit). All three sources (kea / isc /
    # windows) funnel through here, so this covers them all.
    collect_wake(dhcp_group_channel(body.target_group_id))
    logger.info(
        "dhcp_import_commit",
        source=source,
        target_group_id=str(body.target_group_id),
        scopes_created=result.total_scopes_created,
        scopes_overwrote=result.total_scopes_overwrote,
        scopes_skipped=result.total_scopes_skipped,
        scopes_failed=result.total_scopes_failed,
        subnets_created=result.total_subnets_created,
        classes_created=result.client_classes_created,
        user=current_user.display_name,
    )
    return _commit_result_to_pydantic(result)


async def _attach_conflicts(
    db: DB,
    preview: ImportPreview,
    *,
    target_group_id: uuid.UUID,
    ipam_space_id: uuid.UUID | None,
) -> None:
    preview.conflicts = await detect_conflicts(
        db,
        scope_cidrs=[s.subnet_cidr for s in preview.scopes],
        target_group_id=target_group_id,
        ipam_space_id=ipam_space_id,
    )


# ── Kea endpoints ────────────────────────────────────────────────────


@router.post("/kea/preview", response_model=PreviewOut)
async def kea_preview(
    current_user: SuperAdmin,
    db: DB,
    file: UploadFile = File(..., description="Kea kea-dhcp4.conf / kea-dhcp6.conf JSON"),
    target_group_id: uuid.UUID = Form(...),
    ipam_space_id: uuid.UUID | None = Form(default=None),
) -> PreviewOut:
    """Parse an uploaded Kea config and return the would-create plan +
    per-scope conflict status. Side-effect-free — no DB writes."""
    data = await _read_upload(file)
    try:
        preview = parse_kea_config(data)
    except KeaImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await _attach_conflicts(
        db, preview, target_group_id=target_group_id, ipam_space_id=ipam_space_id
    )
    logger.info(
        "dhcp_import_kea_preview",
        scopes=len(preview.scopes),
        pools=preview.total_pools,
        reservations=preview.total_reservations,
        conflicts=len(preview.conflicts),
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview)


@router.post("/kea/commit", response_model=CommitOut)
async def kea_commit(current_user: SuperAdmin, db: DB, body: CommitIn = Body(...)) -> CommitOut:
    return await _run_commit(db, current_user, body, source="kea")


# ── ISC dhcpd.conf endpoints ─────────────────────────────────────────


@router.post("/isc/preview", response_model=PreviewOut)
async def isc_preview(
    current_user: SuperAdmin,
    db: DB,
    file: UploadFile = File(..., description="ISC dhcpd.conf"),
    target_group_id: uuid.UUID = Form(...),
    ipam_space_id: uuid.UUID | None = Form(default=None),
) -> PreviewOut:
    data = await _read_upload(file)
    try:
        preview = parse_isc_config(data)
    except IscImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await _attach_conflicts(
        db, preview, target_group_id=target_group_id, ipam_space_id=ipam_space_id
    )
    logger.info(
        "dhcp_import_isc_preview",
        scopes=len(preview.scopes),
        pools=preview.total_pools,
        reservations=preview.total_reservations,
        conflicts=len(preview.conflicts),
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview)


@router.post("/isc/commit", response_model=CommitOut)
async def isc_commit(current_user: SuperAdmin, db: DB, body: CommitIn = Body(...)) -> CommitOut:
    return await _run_commit(db, current_user, body, source="isc_dhcp")


# ── Windows DHCP endpoints ───────────────────────────────────────────


@router.get("/windows/servers", response_model=list[WindowsDHCPServerOption])
async def windows_servers(_: SuperAdmin, db: DB) -> list[WindowsDHCPServerOption]:
    """List every ``driver=windows_dhcp`` server for the UI's picker,
    with a ``has_credentials`` flag so the UI greys out servers that
    haven't had WinRM creds configured yet."""
    rows = (
        (
            await db.execute(
                select(DHCPServer)
                .where(DHCPServer.driver == "windows_dhcp")
                .order_by(DHCPServer.name)
            )
        )
        .scalars()
        .all()
    )
    out: list[WindowsDHCPServerOption] = []
    for srv in rows:
        out.append(
            WindowsDHCPServerOption(
                id=srv.id,
                name=srv.name,
                host=srv.host or "",
                group_id=srv.server_group_id,
                group_name=srv.group.name if srv.group else None,
                has_credentials=bool(srv.credentials_encrypted),
            )
        )
    return out


@router.post("/windows/preview", response_model=PreviewOut)
async def windows_preview(
    current_user: SuperAdmin, db: DB, body: WindowsDHCPPreviewIn = Body(...)
) -> PreviewOut:
    """Live-pull every IPv4 scope from a Windows DHCP server."""
    server = (
        await db.execute(select(DHCPServer).where(DHCPServer.id == body.server_id))
    ).scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=404, detail=f"DHCP server {body.server_id} not found")
    if server.driver != "windows_dhcp":
        raise HTTPException(
            status_code=400,
            detail=f"Server {server.name!r} is driver {server.driver!r}; expected windows_dhcp",
        )
    if not server.credentials_encrypted:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Server {server.name!r} has no Windows credentials configured. "
                "Add them via the DHCP server modal before importing."
            ),
        )
    try:
        preview = await parse_windows_dhcp_server(server)
    except WindowsDHCPImportError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    await _attach_conflicts(
        db, preview, target_group_id=body.target_group_id, ipam_space_id=body.ipam_space_id
    )
    logger.info(
        "dhcp_import_windows_preview",
        server_id=str(body.server_id),
        scopes=len(preview.scopes),
        conflicts=len(preview.conflicts),
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview)


@router.post("/windows/commit", response_model=CommitOut)
async def windows_commit(current_user: SuperAdmin, db: DB, body: CommitIn = Body(...)) -> CommitOut:
    return await _run_commit(db, current_user, body, source="windows_dhcp")

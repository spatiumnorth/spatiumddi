"""DNS configuration importer endpoints — preview + commit per source.

Phase 1 ships ``/dns/import/bind9/{preview,commit}``; Phase 2 + 3
add ``/dns/import/windows-dns/...`` and ``/dns/import/powerdns/...``
under the same shape (multipart upload + JSON commit body).

The split between preview (multipart) and commit (JSON body
carrying the previewed plan) means we don't re-upload the archive
on commit. The operator-edited per-zone conflict actions ride in
the commit body too, so the server stays stateless between the
two calls.
"""

from __future__ import annotations

import uuid
from typing import Literal

import structlog
from fastapi import APIRouter, Body, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, SuperAdmin
from app.core.agent_wake import collect_wake, dns_group_channel
from app.core.ssrf import assert_safe_target
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.name_scope import classify_zone_name
from app.services.dns.tld_registry import effective_registry
from app.services.dns_import import (
    CLOUD_DRIVERS,
    CloudDNSImportError,
    CommitResult,
    ImportSourceError,
    PowerDNSImportError,
    TechnitiumImportError,
    WindowsDNSImportError,
    parse_bind9_archive,
    parse_powerdns_server,
    parse_technitium_server,
    parse_windows_dns_server,
    preview_cloud_import,
    test_powerdns_connection,
    test_technitium_connection,
)
from app.services.dns_import.canonical import (
    ConflictAction,
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
    ZoneConflict,
)
from app.services.dns_import.commit import commit_import, detect_conflicts

logger = structlog.get_logger(__name__)
router = APIRouter()

# Match the BIND9 parser's archive cap so the multipart upload guard
# fails fast before unpack.
_MAX_UPLOAD_BYTES = 50 * 1024 * 1024


# ── Pydantic IO models ───────────────────────────────────────────────


class ImportedRecordOut(BaseModel):
    name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None
    weight: int | None = None
    port: int | None = None


class ImportedSOAOut(BaseModel):
    primary_ns: str
    admin_email: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    ttl: int


class ImportedZoneOut(BaseModel):
    name: str
    zone_type: str
    kind: str
    # Defaulted, unlike its annotation alone would suggest, because this model
    # is BOTH the preview response and the commit request payload (see
    # ``PreviewOut``). Without a default pydantic makes the key mandatory on
    # the way in, so the published contract had to say "required" — and a
    # generated client then cannot express the null a zone with no SOA
    # legitimately carries. Handled as None everywhere it is read (#907).
    soa: ImportedSOAOut | None = None
    records: list[ImportedRecordOut]
    view_name: str | None = None
    forwarders: list[str] = Field(default_factory=list)
    skipped_record_types: dict[str, int] = Field(default_factory=dict)
    parse_warnings: list[str] = Field(default_factory=list)
    # #986 — TLD scope of the incoming zone name, so a bulk import is where
    # an estate full of ``.lan`` zones is visible *before* it is committed.
    # Derived, never round-tripped: ``_zone_from_pydantic`` ignores it, and
    # it carries a default because this model is also the commit request
    # payload (see the ``soa`` note above). None rather than "public" so an
    # unclassified row shows no pill instead of a reassuring wrong one.
    name_scope: str | None = None


class ZoneConflictOut(BaseModel):
    zone_name: str
    existing_zone_id: str
    existing_record_count: int
    action: Literal["skip", "overwrite", "rename"] = "skip"
    rename_to: str | None = None


class PreviewOut(BaseModel):
    """Preview response shape — also the commit request payload's
    ``plan`` field, so the UI hands back the same shape it received."""

    source: Literal[
        "bind9",
        "windows_dns",
        "powerdns",
        "technitium",
        "cloudflare",
        "route53",
        "azure_dns",
        "google_dns",
    ]
    zones: list[ImportedZoneOut]
    conflicts: list[ZoneConflictOut]
    warnings: list[str]
    total_records: int
    record_type_histogram: dict[str, int]
    # Set by the live-pull previews (cloud, Windows DNS) to the server the
    # records came from; the commit doesn't push them back to it (#1456).
    source_server_id: uuid.UUID | None = None


class ConflictDecision(BaseModel):
    """Per-zone strategy from the operator."""

    action: Literal["skip", "overwrite", "rename"]
    rename_to: str | None = None


class CommitIn(BaseModel):
    target_group_id: uuid.UUID
    target_view_id: uuid.UUID | None = None
    plan: PreviewOut
    # Keyed by ImportedZone.name (FQDN as parsed). Zones the operator
    # left untouched can be omitted; the commit defaults them to
    # skip-on-conflict / create-otherwise.
    conflict_actions: dict[str, ConflictDecision] = Field(default_factory=dict)


class WindowsDNSPreviewIn(BaseModel):
    """Body shape for ``POST /dns/import/windows-dns/preview``.

    Unlike BIND9 (which takes a multipart upload), Windows DNS is a
    live pull — the operator picks a pre-registered Windows DNS
    server row and the server pulls zones + records over WinRM.
    """

    server_id: uuid.UUID
    target_group_id: uuid.UUID
    target_view_id: uuid.UUID | None = None


class WindowsDNSServerOption(BaseModel):
    """One row in the windows_dns server picker — drives the UI's
    server dropdown (filtered to ``driver=windows_dns`` rows that
    have credentials configured)."""

    id: uuid.UUID
    name: str
    host: str
    group_id: uuid.UUID
    group_name: str
    has_credentials: bool


class CloudDNSPreviewIn(BaseModel):
    """Body shape for ``POST /dns/import/cloud/preview``.

    Like Windows DNS, cloud DNS is a live pull — the operator picks a
    pre-registered cloud DNS server row (driver in {cloudflare, route53,
    azure_dns, google_dns}) and the control plane pulls hosted zones +
    records via the provider API. This is also the engine behind the
    "Sync from provider" button on a cloud DNS server.
    """

    server_id: uuid.UUID
    target_group_id: uuid.UUID
    target_view_id: uuid.UUID | None = None


class CloudDNSServerOption(BaseModel):
    """One row in the cloud-DNS server picker — filtered to cloud-driver
    rows that have credentials configured."""

    id: uuid.UUID
    name: str
    driver: str
    group_id: uuid.UUID
    group_name: str
    has_credentials: bool


# A remote-source URL / API credential travels as a URL and an HTTP header,
# which are ASCII on the wire — a non-ASCII value can never be a working
# credential, only a crash in the outbound client (live under fuzz:
# UnicodeEncodeError out of the URL build and "Invalid HTTP header value"
# out of the header build, both surfacing as 500 before any pull started).
# Rejecting it here makes it the 422 it is.
_ASCII = Field(pattern=r"^[\x20-\x7e]*$")


class PowerDNSPreviewIn(BaseModel):
    """Body shape for ``POST /dns/import/powerdns/preview``.

    PowerDNS imports target a *non-managed* upstream — the
    operator is migrating *from* it, so we don't expect a
    DNSServer row to exist for it. Credentials live in the body
    and are read-once (never persisted).
    """

    api_url: str = _ASCII
    api_key: str = _ASCII
    server_name: str = Field(default="localhost", pattern=r"^[\x20-\x7e]*$")
    target_group_id: uuid.UUID
    target_view_id: uuid.UUID | None = None


class PowerDNSTestIn(BaseModel):
    """Body shape for ``POST /dns/import/powerdns/test-connection`` —
    same auth fields as the preview body but without a target
    group, since the test endpoint never touches the DB."""

    api_url: str = _ASCII
    api_key: str = _ASCII
    server_name: str = Field(default="localhost", pattern=r"^[\x20-\x7e]*$")


class TechnitiumPreviewIn(BaseModel):
    """Body shape for ``POST /dns/import/technitium/preview``."""

    api_url: str = _ASCII
    api_token: str = _ASCII
    target_group_id: uuid.UUID
    target_view_id: uuid.UUID | None = None


class TechnitiumTestIn(BaseModel):
    """Body shape for ``POST /dns/import/technitium/test-connection``."""

    api_url: str = _ASCII
    api_token: str = _ASCII


class TechnitiumTestOut(BaseModel):
    """Response from ``POST /dns/import/technitium/test-connection``.

    ``importable_zone_count`` is deliberately reported separately from
    ``zone_count``: only a Primary carries authoritative data of its own,
    so a server that is mostly secondaries has far less to import than
    its raw zone count suggests.
    """

    ok: bool
    zone_count: int
    importable_zone_count: int


class PowerDNSTestOut(BaseModel):
    """Response shape from ``POST /dns/import/powerdns/test-connection``.

    Mirrors the PowerDNS server-info object's identifying fields
    so the operator can confirm "yes, that's the daemon I expected"
    before kicking off a 5000-zone pull.
    """

    type: str
    id: str
    daemon_type: str
    version: str
    url: str


class CommitZoneOut(BaseModel):
    zone_name: str
    action_taken: Literal["created", "overwrote", "renamed", "skipped", "failed"]
    zone_id: str | None = None
    records_created: int = 0
    records_deleted: int = 0
    error: str | None = None


class CommitOut(BaseModel):
    target_group_id: uuid.UUID
    zones: list[CommitZoneOut]
    warnings: list[str]
    total_zones_created: int
    total_zones_overwrote: int
    total_zones_renamed: int
    total_zones_skipped: int
    total_zones_failed: int
    total_records_created: int


# ── Conversion helpers (canonical IR ↔ Pydantic) ─────────────────────


def _zone_to_pydantic(z: ImportedZone, tlds: frozenset[str] | None = None) -> ImportedZoneOut:
    return ImportedZoneOut(
        name_scope=classify_zone_name(z.name, tlds=tlds).scope,
        name=z.name,
        zone_type=z.zone_type,
        kind=z.kind,
        soa=ImportedSOAOut(**z.soa.__dict__) if z.soa else None,
        records=[ImportedRecordOut(**r.__dict__) for r in z.records],
        view_name=z.view_name,
        forwarders=list(z.forwarders),
        skipped_record_types=dict(z.skipped_record_types),
        parse_warnings=list(z.parse_warnings),
    )


def _preview_to_pydantic(p: ImportPreview, tlds: frozenset[str] | None = None) -> PreviewOut:
    return PreviewOut(
        source=p.source,
        zones=[_zone_to_pydantic(z, tlds) for z in p.zones],
        conflicts=[
            ZoneConflictOut(
                zone_name=c.zone_name,
                existing_zone_id=c.existing_zone_id,
                existing_record_count=c.existing_record_count,
                action=c.action,
                rename_to=c.rename_to,
            )
            for c in p.conflicts
        ],
        warnings=list(p.warnings),
        total_records=p.total_records,
        record_type_histogram=dict(p.record_type_histogram),
        source_server_id=p.source_server_id,
    )


def _zone_from_pydantic(o: ImportedZoneOut) -> ImportedZone:
    return ImportedZone(
        name=o.name,
        zone_type=o.zone_type,
        kind=o.kind,
        soa=ImportedSOA(**o.soa.model_dump()) if o.soa else None,
        records=[ImportedRecord(**r.model_dump()) for r in o.records],
        view_name=o.view_name,
        forwarders=list(o.forwarders),
        skipped_record_types=dict(o.skipped_record_types),
        parse_warnings=list(o.parse_warnings),
    )


def _preview_from_pydantic(o: PreviewOut) -> ImportPreview:
    return ImportPreview(
        source=o.source,
        zones=[_zone_from_pydantic(z) for z in o.zones],
        conflicts=[
            ZoneConflict(
                zone_name=c.zone_name,
                existing_zone_id=c.existing_zone_id,
                existing_record_count=c.existing_record_count,
                action=c.action,
                rename_to=c.rename_to,
            )
            for c in o.conflicts
        ],
        warnings=list(o.warnings),
        total_records=o.total_records,
        record_type_histogram=dict(o.record_type_histogram),
        source_server_id=o.source_server_id,
    )


async def _check_source_server(db: DB, plan: PreviewOut) -> None:
    """Reject a plan whose ``source_server_id`` doesn't match its source.

    The id comes back from the client with the plan, and it turns off the
    record ops to that server (#1456), so it has to name a server of the
    plan's own driver: a live-pull source only, never a file import.
    """
    if plan.source_server_id is None:
        return
    server = await db.get(DNSServer, plan.source_server_id)
    if server is None or server.driver != plan.source:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Plan source_server_id {plan.source_server_id} is not a " f"{plan.source} server"
            ),
        )


def _commit_result_to_pydantic(r: CommitResult) -> CommitOut:
    return CommitOut(
        target_group_id=r.target_group_id,
        zones=[
            CommitZoneOut(
                zone_name=z.zone_name,
                action_taken=z.action_taken,  # type: ignore[arg-type]
                zone_id=z.zone_id,
                records_created=z.records_created,
                records_deleted=z.records_deleted,
                error=z.error,
            )
            for z in r.zones
        ],
        warnings=list(r.warnings),
        total_zones_created=r.total_zones_created,
        total_zones_overwrote=r.total_zones_overwrote,
        total_zones_renamed=r.total_zones_renamed,
        total_zones_skipped=r.total_zones_skipped,
        total_zones_failed=r.total_zones_failed,
        total_records_created=r.total_records_created,
    )


# ── Multipart upload guard ───────────────────────────────────────────


async def _read_archive(file: UploadFile) -> bytes:
    data = await file.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Upload exceeds {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit",
        )
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload")
    return data


# ── Endpoints ────────────────────────────────────────────────────────


@router.post("/bind9/preview", response_model=PreviewOut)
async def bind9_preview(
    current_user: SuperAdmin,
    db: DB,
    file: UploadFile = File(
        ..., description="ZIP or tar(.gz/.bz2/.xz) archive containing named.conf + zone files"
    ),
    target_group_id: uuid.UUID = Form(..., description="DNS server group the import will land in"),
    target_view_id: uuid.UUID | None = Form(default=None),
) -> PreviewOut:
    """Parse the uploaded BIND9 archive and return the would-create
    plan + per-zone conflict status.

    Side-effect-free: no DB writes, no audit row. The operator can
    re-upload as many times as they want while iterating on the
    archive contents. Only the commit endpoint mutates state.
    """

    data = await _read_archive(file)
    try:
        preview = parse_bind9_archive(data)
    except ImportSourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Conflict detection runs against the target group + view here so
    # the UI's per-zone strategy picker has accurate data. Re-checked
    # at commit time in case the world moved.
    zone_names = [z.name if z.name.endswith(".") else z.name + "." for z in preview.zones]
    zone_names = [n.lower() for n in zone_names]
    preview.conflicts = await detect_conflicts(
        db,
        zone_names=zone_names,
        target_group_id=target_group_id,
        target_view_id=target_view_id,
    )

    logger.info(
        "dns_import_bind9_preview",
        zone_count=len(preview.zones),
        record_count=preview.total_records,
        conflict_count=len(preview.conflicts),
        warning_count=len(preview.warnings),
        target_group_id=str(target_group_id),
        target_view_id=str(target_view_id) if target_view_id else None,
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview, (await effective_registry(db)).tlds)


@router.post("/bind9/commit", response_model=CommitOut)
async def bind9_commit(
    current_user: SuperAdmin,
    db: DB,
    body: CommitIn = Body(...),
) -> CommitOut:
    """Apply a previously-previewed BIND9 import.

    Per-zone savepoints — a parse / FK error on zone N rolls back N
    but keeps zones 1..N-1. Each successful zone gets a single
    audit_log row tagged ``import_source=bind9`` in ``new_value``.
    """

    if body.plan.source != "bind9":
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint=bind9 plan={body.plan.source}",
        )

    await _check_source_server(db, body.plan)
    preview = _preview_from_pydantic(body.plan)
    actions: dict[str, tuple[ConflictAction, str | None]] = {
        zone_name: (decision.action, decision.rename_to)
        for zone_name, decision in body.conflict_actions.items()
    }

    try:
        result = await commit_import(
            db,
            preview=preview,
            target_group_id=body.target_group_id,
            target_view_id=body.target_view_id,
            conflict_actions=actions,
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Wake the target group's parked agent long-polls so the newly
    # imported zones converge immediately (the wake_publishing
    # dependency flushes this after commit).
    collect_wake(dns_group_channel(body.target_group_id))

    logger.info(
        "dns_import_bind9_commit",
        target_group_id=str(body.target_group_id),
        zones_created=result.total_zones_created,
        zones_overwrote=result.total_zones_overwrote,
        zones_renamed=result.total_zones_renamed,
        zones_skipped=result.total_zones_skipped,
        zones_failed=result.total_zones_failed,
        records_created=result.total_records_created,
        user=current_user.display_name,
    )
    return _commit_result_to_pydantic(result)


# ── Windows DNS endpoints (Phase 2) ──────────────────────────────────


@router.get("/windows-dns/servers", response_model=list[WindowsDNSServerOption])
async def windows_dns_servers(
    _: SuperAdmin,
    db: DB,
) -> list[WindowsDNSServerOption]:
    """List every ``driver=windows_dns`` server with its group, for
    the UI's server picker.

    Returns the server's ``has_credentials`` flag so the picker can
    grey out servers that haven't had WinRM creds configured yet —
    Path B requires them, and the UI shouldn't let the operator
    pick a server we know will fail at preview time.
    """

    rows = (
        await db.execute(
            select(DNSServer, DNSServerGroup)
            .join(DNSServerGroup, DNSServer.group_id == DNSServerGroup.id)
            .where(DNSServer.driver == "windows_dns")
            .order_by(DNSServerGroup.name, DNSServer.name)
        )
    ).all()
    return [
        WindowsDNSServerOption(
            id=server.id,
            name=server.name,
            host=server.host or "",
            group_id=group.id,
            group_name=group.name,
            has_credentials=bool(server.credentials_encrypted),
        )
        for (server, group) in rows
    ]


@router.post(
    "/windows-dns/preview",
    response_model=PreviewOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def windows_dns_preview(
    current_user: SuperAdmin,
    db: DB,
    body: WindowsDNSPreviewIn = Body(...),
) -> PreviewOut:
    """Live-pull every zone + record from a Windows DNS server.

    Validates the server row + WinRM creds before delegating to
    :func:`parse_windows_dns_server`. The pull blocks until every
    zone's records have been walked — a 50-zone server takes a few
    seconds; a 5000-zone server takes minutes. The UI shows a
    progress spinner during the wait.
    """

    server = (
        await db.execute(select(DNSServer).where(DNSServer.id == body.server_id))
    ).scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=404, detail=f"DNS server {body.server_id} not found")
    if server.driver != "windows_dns":
        raise HTTPException(
            status_code=400,
            detail=f"Server {server.name!r} is driver {server.driver!r}; expected windows_dns",
        )
    if not server.credentials_encrypted:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Server {server.name!r} has no WinRM credentials configured. "
                "Add them via the DNS server modal before importing."
            ),
        )

    try:
        preview = await parse_windows_dns_server(server)
    except WindowsDNSImportError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    zone_names = [(z.name if z.name.endswith(".") else z.name + ".").lower() for z in preview.zones]
    preview.conflicts = await detect_conflicts(
        db,
        zone_names=zone_names,
        target_group_id=body.target_group_id,
        target_view_id=body.target_view_id,
    )

    logger.info(
        "dns_import_windows_dns_preview",
        server_id=str(body.server_id),
        zone_count=len(preview.zones),
        record_count=preview.total_records,
        conflict_count=len(preview.conflicts),
        warning_count=len(preview.warnings),
        target_group_id=str(body.target_group_id),
        target_view_id=str(body.target_view_id) if body.target_view_id else None,
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview, (await effective_registry(db)).tlds)


@router.post("/windows-dns/commit", response_model=CommitOut)
async def windows_dns_commit(
    current_user: SuperAdmin,
    db: DB,
    body: CommitIn = Body(...),
) -> CommitOut:
    """Apply a previously-previewed Windows DNS import.

    Identical pipeline as the BIND9 commit — re-detect conflicts,
    per-zone savepoints, audit log per zone — just dispatched via
    a different endpoint so the operator-side UI is keyed by source.
    """

    if body.plan.source != "windows_dns":
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint=windows_dns plan={body.plan.source}",
        )

    await _check_source_server(db, body.plan)
    preview = _preview_from_pydantic(body.plan)
    actions: dict[str, tuple[ConflictAction, str | None]] = {
        zone_name: (decision.action, decision.rename_to)
        for zone_name, decision in body.conflict_actions.items()
    }

    try:
        result = await commit_import(
            db,
            preview=preview,
            target_group_id=body.target_group_id,
            target_view_id=body.target_view_id,
            conflict_actions=actions,
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Wake the target group's parked agent long-polls so the newly
    # imported zones converge immediately.
    collect_wake(dns_group_channel(body.target_group_id))

    logger.info(
        "dns_import_windows_dns_commit",
        target_group_id=str(body.target_group_id),
        zones_created=result.total_zones_created,
        zones_overwrote=result.total_zones_overwrote,
        zones_renamed=result.total_zones_renamed,
        zones_skipped=result.total_zones_skipped,
        zones_failed=result.total_zones_failed,
        records_created=result.total_records_created,
        user=current_user.display_name,
    )
    return _commit_result_to_pydantic(result)


# ── PowerDNS endpoints (Phase 3) ─────────────────────────────────────


@router.post(
    "/powerdns/test-connection",
    response_model=PowerDNSTestOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def powerdns_test_connection(
    _: SuperAdmin,
    body: PowerDNSTestIn = Body(...),
) -> PowerDNSTestOut:
    """Probe the PowerDNS REST API and return the daemon's
    identifying info. Operator clicks this before kicking off a
    full pull on a giant server."""

    # SECURITY (#400, L5): advisory SSRF guard — log the resolved
    # PowerDNS API IP so operators can audit the connect target. Not
    # hard-blocked: a co-located / LAN PowerDNS daemon is a legitimate
    # import source.
    assert_safe_target(body.api_url, label="dns_import_powerdns")

    try:
        info = await test_powerdns_connection(
            api_url=body.api_url,
            api_key=body.api_key,
            server_name=body.server_name,
        )
    except PowerDNSImportError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return PowerDNSTestOut(**info)


@router.post(
    "/powerdns/preview",
    response_model=PreviewOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def powerdns_preview(
    current_user: SuperAdmin,
    db: DB,
    body: PowerDNSPreviewIn = Body(...),
) -> PreviewOut:
    """Live-pull every zone + record from a PowerDNS REST API.

    Credentials live in the body, never persisted. The pull is
    blocking — a 500-zone server takes a few seconds; a 5000-zone
    server takes minutes. Above 5000 the importer rejects the pull
    and asks the operator to split the migration.
    """

    try:
        preview = await parse_powerdns_server(
            api_url=body.api_url,
            api_key=body.api_key,
            server_name=body.server_name,
        )
    except PowerDNSImportError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    zone_names = [(z.name if z.name.endswith(".") else z.name + ".").lower() for z in preview.zones]
    preview.conflicts = await detect_conflicts(
        db,
        zone_names=zone_names,
        target_group_id=body.target_group_id,
        target_view_id=body.target_view_id,
    )

    logger.info(
        "dns_import_powerdns_preview",
        api_url=body.api_url,
        server_name=body.server_name,
        zone_count=len(preview.zones),
        record_count=preview.total_records,
        conflict_count=len(preview.conflicts),
        warning_count=len(preview.warnings),
        target_group_id=str(body.target_group_id),
        target_view_id=str(body.target_view_id) if body.target_view_id else None,
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview, (await effective_registry(db)).tlds)


@router.post("/powerdns/commit", response_model=CommitOut)
async def powerdns_commit(
    current_user: SuperAdmin,
    db: DB,
    body: CommitIn = Body(...),
) -> CommitOut:
    """Apply a previously-previewed PowerDNS import.

    Same shared pipeline as bind9 + windows_dns — the canonical IR
    reuse means audit + per-zone savepoints + RBAC stay in
    lock-step across all three sources.
    """

    if body.plan.source != "powerdns":
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint=powerdns plan={body.plan.source}",
        )

    await _check_source_server(db, body.plan)
    preview = _preview_from_pydantic(body.plan)
    actions: dict[str, tuple[ConflictAction, str | None]] = {
        zone_name: (decision.action, decision.rename_to)
        for zone_name, decision in body.conflict_actions.items()
    }

    try:
        result = await commit_import(
            db,
            preview=preview,
            target_group_id=body.target_group_id,
            target_view_id=body.target_view_id,
            conflict_actions=actions,
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # #358 — imported zones land under target_group_id; wake its agents.
    collect_wake(dns_group_channel(body.target_group_id))

    logger.info(
        "dns_import_powerdns_commit",
        target_group_id=str(body.target_group_id),
        zones_created=result.total_zones_created,
        zones_overwrote=result.total_zones_overwrote,
        zones_renamed=result.total_zones_renamed,
        zones_skipped=result.total_zones_skipped,
        zones_failed=result.total_zones_failed,
        records_created=result.total_records_created,
        user=current_user.display_name,
    )
    return _commit_result_to_pydantic(result)


# ── Technitium endpoints (issue #744) ────────────────────────────────


@router.post(
    "/technitium/test-connection",
    response_model=TechnitiumTestOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def technitium_test_connection(
    _: SuperAdmin,
    body: TechnitiumTestIn = Body(...),
) -> TechnitiumTestOut:
    """Probe a Technitium server before kicking off a full pull."""

    # SECURITY (#400, L5): advisory SSRF guard, same posture as the
    # PowerDNS path — a LAN Technitium daemon is a legitimate import
    # source, so the resolved target is logged rather than hard-blocked.
    assert_safe_target(body.api_url, label="dns_import_technitium")

    try:
        info = await test_technitium_connection(api_url=body.api_url, api_token=body.api_token)
    except TechnitiumImportError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return TechnitiumTestOut(**info)


@router.post(
    "/technitium/preview",
    response_model=PreviewOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def technitium_preview(
    current_user: SuperAdmin,
    db: DB,
    body: TechnitiumPreviewIn = Body(...),
) -> PreviewOut:
    """Live-pull every primary zone + record from a Technitium server.

    The token lives in the body and is never persisted. Non-primary
    zones are reported as warnings rather than imported — a secondary is
    a copy of someone else's data.
    """

    assert_safe_target(body.api_url, label="dns_import_technitium")

    try:
        preview = await parse_technitium_server(api_url=body.api_url, api_token=body.api_token)
    except TechnitiumImportError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    zone_names = [(z.name if z.name.endswith(".") else z.name + ".").lower() for z in preview.zones]
    preview.conflicts = await detect_conflicts(
        db,
        zone_names=zone_names,
        target_group_id=body.target_group_id,
        target_view_id=body.target_view_id,
    )

    logger.info(
        "dns_import_technitium_preview",
        api_url=body.api_url,
        zone_count=len(preview.zones),
        record_count=preview.total_records,
        conflict_count=len(preview.conflicts),
        warning_count=len(preview.warnings),
        target_group_id=str(body.target_group_id),
        target_view_id=str(body.target_view_id) if body.target_view_id else None,
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview, (await effective_registry(db)).tlds)


@router.post("/technitium/commit", response_model=CommitOut)
async def technitium_commit(
    current_user: SuperAdmin,
    db: DB,
    body: CommitIn = Body(...),
) -> CommitOut:
    """Apply a previously-previewed Technitium import.

    Same shared pipeline as every other source — the canonical IR reuse
    keeps audit, per-zone savepoints and RBAC in lock-step.
    """

    if body.plan.source != "technitium":
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint=technitium plan={body.plan.source}",
        )

    await _check_source_server(db, body.plan)
    preview = _preview_from_pydantic(body.plan)
    actions: dict[str, tuple[ConflictAction, str | None]] = {
        zone_name: (decision.action, decision.rename_to)
        for zone_name, decision in body.conflict_actions.items()
    }

    try:
        result = await commit_import(
            db,
            preview=preview,
            target_group_id=body.target_group_id,
            target_view_id=body.target_view_id,
            conflict_actions=actions,
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # #358 — imported zones land under target_group_id; wake its agents.
    collect_wake(dns_group_channel(body.target_group_id))

    logger.info(
        "dns_import_technitium_commit",
        target_group_id=str(body.target_group_id),
        zones_created=result.total_zones_created,
        zones_overwrote=result.total_zones_overwrote,
        zones_renamed=result.total_zones_renamed,
        zones_skipped=result.total_zones_skipped,
        zones_failed=result.total_zones_failed,
        records_created=result.total_records_created,
        user=current_user.display_name,
    )
    return _commit_result_to_pydantic(result)


# ── Cloud DNS endpoints (issue #37, Part B) ──────────────────────────


@router.get("/cloud/servers", response_model=list[CloudDNSServerOption])
async def cloud_dns_servers(
    _: SuperAdmin,
    db: DB,
) -> list[CloudDNSServerOption]:
    """List every cloud-driver DNS server with its group, for the UI's
    server picker.

    Returns ``has_credentials`` so the picker can grey out servers
    missing their provider API token / key — the live pull needs them.
    """

    rows = (
        await db.execute(
            select(DNSServer, DNSServerGroup)
            .join(DNSServerGroup, DNSServer.group_id == DNSServerGroup.id)
            .where(DNSServer.driver.in_(sorted(CLOUD_DRIVERS)))
            .order_by(DNSServerGroup.name, DNSServer.name)
        )
    ).all()
    return [
        CloudDNSServerOption(
            id=server.id,
            name=server.name,
            driver=server.driver,
            group_id=group.id,
            group_name=group.name,
            has_credentials=bool(server.credentials_encrypted),
        )
        for (server, group) in rows
    ]


@router.post("/cloud/preview", response_model=PreviewOut)
async def cloud_dns_preview(
    current_user: SuperAdmin,
    db: DB,
    body: CloudDNSPreviewIn = Body(...),
) -> PreviewOut:
    """Live-pull every hosted zone + record from a cloud DNS provider.

    Delegates to :func:`preview_cloud_import`, which validates the
    server is a cloud driver, pulls zones + records through the driver,
    and stamps the provider name as ``import_source``. Side-effect-free
    — only the commit endpoint mutates state.
    """

    try:
        preview = await preview_cloud_import(
            db,
            server_id=body.server_id,
            target_group_id=body.target_group_id,
            target_view_id=body.target_view_id,
        )
    except CloudDNSImportError as exc:
        # Validation failures (not a cloud driver / unknown server) → 400.
        raise HTTPException(status_code=400, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    logger.info(
        "dns_import_cloud_preview",
        server_id=str(body.server_id),
        source=preview.source,
        zone_count=len(preview.zones),
        record_count=preview.total_records,
        conflict_count=len(preview.conflicts),
        warning_count=len(preview.warnings),
        target_group_id=str(body.target_group_id),
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview, (await effective_registry(db)).tlds)


@router.post("/cloud/commit", response_model=CommitOut)
async def cloud_dns_commit(
    current_user: SuperAdmin,
    db: DB,
    body: CommitIn = Body(...),
) -> CommitOut:
    """Apply a previously-previewed cloud DNS import.

    Identical pipeline to the other sources (re-detect conflicts,
    per-zone savepoints, audit per zone). The plan's ``source`` must be
    one of the cloud provider names so provenance stays per-provider.
    """

    if body.plan.source not in CLOUD_DRIVERS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Plan source mismatch: endpoint=cloud plan={body.plan.source} "
                f"(expected one of {', '.join(sorted(CLOUD_DRIVERS))})"
            ),
        )

    await _check_source_server(db, body.plan)
    preview = _preview_from_pydantic(body.plan)
    actions: dict[str, tuple[ConflictAction, str | None]] = {
        zone_name: (decision.action, decision.rename_to)
        for zone_name, decision in body.conflict_actions.items()
    }

    try:
        result = await commit_import(
            db,
            preview=preview,
            target_group_id=body.target_group_id,
            target_view_id=body.target_view_id,
            conflict_actions=actions,
            current_user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # #358 — imported zones land under target_group_id; wake its agents.
    collect_wake(dns_group_channel(body.target_group_id))

    logger.info(
        "dns_import_cloud_commit",
        source=body.plan.source,
        target_group_id=str(body.target_group_id),
        zones_created=result.total_zones_created,
        zones_overwrote=result.total_zones_overwrote,
        zones_renamed=result.total_zones_renamed,
        zones_skipped=result.total_zones_skipped,
        zones_failed=result.total_zones_failed,
        records_created=result.total_records_created,
        user=current_user.display_name,
    )
    return _commit_result_to_pydantic(result)

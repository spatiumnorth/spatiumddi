"""NetBox one-shot IPAM importer endpoints — test-connection + preview + commit.

A read-only migration tool (issue #36), NOT a continuous reconciler. The
operator supplies a NetBox ``base_url`` + ``token`` per request (creds are
read-once and never persisted), previews what the import would bring into
native IPAM rows, then commits the *unmodified* previewed plan.

The split between preview and commit keeps the server **stateless** between
the two calls: ``POST /preview`` returns the full canonical IR as
``PreviewOut``; the UI hands the same shape straight back as
``CommitIn.plan`` (plus any per-entity conflict decisions). Nothing is
stored server-side between the two calls — exactly the contract the DNS /
DHCP importers establish.

Differences from the DNS importer this clones:

* ``ConflictAction`` is ``skip | overwrite`` (no ``rename`` — NetBox
  entities are CIDR / rd / name-keyed and can't be renamed).
* The plan ``source`` is the single value ``"netbox"``.
* **No ``wake_publishing``** — NetBox seeds IPAM rows only and touches no
  DNS / DHCP agent config bundle, so there's no agent long-poll to wake.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import DB, SuperAdmin
from app.api.pre_body_auth import PreBodyAuthRoute
from app.core.ssrf import assert_safe_target
from app.services.netbox_import import (
    CommitResult,
    EntityConflict,
    ImportedAddress,
    ImportedBlock,
    ImportedCustomer,
    ImportedSite,
    ImportedSpace,
    ImportedSubnet,
    ImportedVLAN,
    ImportedVRF,
    ImportPreview,
    NetBoxClient,
    NetBoxClientError,
    commit_import,
    preview_netbox_import,
)
from app.services.netbox_import.canonical import ConflictAction

logger = structlog.get_logger(__name__)
# Every body route here checks the login from the request headers before
# the body is read (app.api.pre_body_auth): the preview sent back to commit
# carries the /ipam/import/ body allowance (app.core.body_limit).
router = APIRouter(route_class=PreBodyAuthRoute)


# ── Pydantic IO models ───────────────────────────────────────────────


class NetboxConnIn(BaseModel):
    """Connection fields shared by test-connection + preview.

    Credentials live in the request body and are read-once — never
    persisted. ``token`` accepts either the v1 ``Token`` scheme or the
    v2 ``Bearer nbt_…`` scheme (the client detects which by prefix).
    """

    # ASCII-only for the same reason as the DNS importers: the URL and the
    # Authorization header are ASCII on the wire, and a non-ASCII value
    # crashed the outbound client as a 500 before any pull started.
    base_url: str = Field(
        description="NetBox base URL, e.g. https://netbox.example.com",
        pattern=r"^[\x20-\x7e]*$",
    )
    token: str = Field(
        description="NetBox API token (read-once; never persisted).",
        pattern=r"^[\x20-\x7e]*$",
    )
    verify_tls: bool = True


class NetboxPreviewFilters(BaseModel):
    """Optional scope slice forwarded to the prefix / address / vrf /
    tenant pulls so the operator can import a slice of a large NetBox."""

    vrf_id: int | None = None
    tenant_id: int | None = None
    status: str | None = None
    family: Literal[4, 6] | None = None
    within_include: str | None = None


class NetboxPreviewIn(NetboxConnIn):
    """Body for ``POST /ipam/import/netbox/preview``."""

    space_strategy: Literal["per_vrf", "single"] = "per_vrf"
    # Required when space_strategy='single' — the IP space everything
    # collapses into (the preview warns + the commit 422s if missing).
    target_space_id: uuid.UUID | None = None
    filters: NetboxPreviewFilters | None = None


class ImportedCustomerOut(BaseModel):
    name: str
    notes: str = ""
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, Any] = Field(default_factory=dict)
    netbox_id: int | None = None


class ImportedSiteOut(BaseModel):
    name: str
    code: str | None = None
    parent_code: str | None = None
    kind: str = "datacenter"
    region: str | None = None
    notes: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)
    netbox_id: int | None = None


class ImportedVRFOut(BaseModel):
    name: str
    rd: str | None = None
    import_targets: list[str] = Field(default_factory=list)
    export_targets: list[str] = Field(default_factory=list)
    description: str = ""
    customer_name: str | None = None
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, Any] = Field(default_factory=dict)
    netbox_id: int | None = None


class ImportedSpaceOut(BaseModel):
    name: str
    vrf_name: str | None = None
    is_default: bool = False
    customer_name: str | None = None
    description: str = ""
    tags: dict[str, Any] = Field(default_factory=dict)


class ImportedVLANOut(BaseModel):
    vid: int
    name: str
    description: str = ""
    netbox_id: int | None = None


class ImportedBlockOut(BaseModel):
    network: str
    name: str = ""
    description: str = ""
    space_name: str | None = None
    parent_cidr: str | None = None
    customer_name: str | None = None
    site_code: str | None = None
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, Any] = Field(default_factory=dict)
    netbox_id: int | None = None


class ImportedSubnetOut(BaseModel):
    network: str
    name: str = ""
    description: str = ""
    space_name: str | None = None
    status: str = "active"
    vlan_vid: int | None = None
    customer_name: str | None = None
    site_code: str | None = None
    subnet_role: str | None = None
    kind: str = "unicast"
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, Any] = Field(default_factory=dict)
    netbox_id: int | None = None


class ImportedAddressOut(BaseModel):
    address: str
    status: str = "allocated"
    role: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    description: str = ""
    subnet_cidr: str | None = None
    space_name: str | None = None
    custom_fields: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, Any] = Field(default_factory=dict)
    netbox_id: int | None = None


class EntityConflictOut(BaseModel):
    kind: str
    key: str
    existing_id: str
    reason: str
    action: Literal["skip", "overwrite"] = "skip"


class PreviewOut(BaseModel):
    """Preview response shape — also the commit request payload's ``plan``
    field, so the UI hands back the same shape it received.

    Carries the **full** canonical IR across every entity type. ``counts``
    is the per-entity-type rollup for the preview UI.
    """

    source: Literal["netbox"]
    customers: list[ImportedCustomerOut] = Field(default_factory=list)
    sites: list[ImportedSiteOut] = Field(default_factory=list)
    vrfs: list[ImportedVRFOut] = Field(default_factory=list)
    spaces: list[ImportedSpaceOut] = Field(default_factory=list)
    vlans: list[ImportedVLANOut] = Field(default_factory=list)
    blocks: list[ImportedBlockOut] = Field(default_factory=list)
    subnets: list[ImportedSubnetOut] = Field(default_factory=list)
    addresses: list[ImportedAddressOut] = Field(default_factory=list)
    conflicts: list[EntityConflictOut] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class ConflictDecision(BaseModel):
    """Per-entity strategy from the operator."""

    action: Literal["skip", "overwrite"] = "skip"


class CommitIn(BaseModel):
    """Body for ``POST /ipam/import/netbox/commit``.

    ``plan`` is the unmodified ``PreviewOut`` the UI received.
    ``conflict_actions`` is keyed by each entity's stable conflict key
    (the ``EntityConflict.key`` carried on the preview); entities the
    operator left untouched default to skip-on-conflict / create-otherwise.
    """

    plan: PreviewOut
    conflict_actions: dict[str, ConflictDecision] = Field(default_factory=dict)
    space_strategy: Literal["per_vrf", "single"] = "per_vrf"
    target_space_id: uuid.UUID | None = None
    default_router_name: str = "Imported VLANs (NetBox)"


class NetboxTestOut(BaseModel):
    """Response from ``POST /ipam/import/netbox/test-connection``."""

    ok: bool
    netbox_version: str | None = None
    api_version: str | None = None
    counts: dict[str, int] | None = None


class CommitEntityOut(BaseModel):
    kind: str
    key: str
    action_taken: Literal["created", "overwrote", "skipped", "failed"]
    entity_id: str | None = None
    error: str | None = None


class CommitOut(BaseModel):
    source: str
    entities: list[CommitEntityOut]
    warnings: list[str]
    # Per-kind created rollups.
    customers_created: int
    sites_created: int
    vrfs_created: int
    spaces_created: int
    vlans_created: int
    blocks_created: int
    subnets_created: int
    addresses_created: int
    # Cross-kind action rollups.
    total_created: int
    total_overwrote: int
    total_skipped: int
    total_failed: int


# ── Conversion helpers (canonical IR ↔ Pydantic) ─────────────────────


def _preview_to_pydantic(p: ImportPreview) -> PreviewOut:
    """dataclass IR → Pydantic (the preview-side serializer)."""
    return PreviewOut(
        source=p.source,
        customers=[ImportedCustomerOut(**c.__dict__) for c in p.customers],
        sites=[ImportedSiteOut(**s.__dict__) for s in p.sites],
        vrfs=[ImportedVRFOut(**v.__dict__) for v in p.vrfs],
        spaces=[ImportedSpaceOut(**sp.__dict__) for sp in p.spaces],
        vlans=[ImportedVLANOut(**vl.__dict__) for vl in p.vlans],
        blocks=[ImportedBlockOut(**b.__dict__) for b in p.blocks],
        subnets=[ImportedSubnetOut(**sub.__dict__) for sub in p.subnets],
        addresses=[ImportedAddressOut(**a.__dict__) for a in p.addresses],
        conflicts=[
            EntityConflictOut(
                kind=c.kind,
                key=c.key,
                existing_id=c.existing_id,
                reason=c.reason,
                action=c.action,
            )
            for c in p.conflicts
        ],
        warnings=list(p.warnings),
        counts=dict(p.counts),
    )


def _preview_from_pydantic(o: PreviewOut) -> ImportPreview:
    """Pydantic → dataclass IR (the commit-side inverse).

    Rebuilds the full :class:`ImportPreview` from the round-tripped
    ``plan`` so the committer re-runs against a real IR. ``counts`` is a
    derived ``@property`` on the dataclass — it's not a constructor field,
    so it's intentionally dropped here.
    """
    return ImportPreview(
        source=o.source,
        customers=[ImportedCustomer(**c.model_dump()) for c in o.customers],
        sites=[ImportedSite(**s.model_dump()) for s in o.sites],
        vrfs=[ImportedVRF(**v.model_dump()) for v in o.vrfs],
        spaces=[ImportedSpace(**sp.model_dump()) for sp in o.spaces],
        vlans=[ImportedVLAN(**vl.model_dump()) for vl in o.vlans],
        blocks=[ImportedBlock(**b.model_dump()) for b in o.blocks],
        subnets=[ImportedSubnet(**sub.model_dump()) for sub in o.subnets],
        addresses=[ImportedAddress(**a.model_dump()) for a in o.addresses],
        conflicts=[
            EntityConflict(
                kind=c.kind,
                key=c.key,
                existing_id=c.existing_id,
                reason=c.reason,
                action=c.action,
            )
            for c in o.conflicts
        ],
        warnings=list(o.warnings),
    )


def _commit_result_to_pydantic(r: CommitResult) -> CommitOut:
    """``CommitResult`` dataclass → ``CommitOut`` Pydantic (rollups read
    off the dataclass ``@property`` counters)."""
    return CommitOut(
        source=r.source,
        entities=[
            CommitEntityOut(
                kind=e.kind,
                key=e.key,
                action_taken=e.action_taken,  # type: ignore[arg-type]
                entity_id=e.entity_id,
                error=e.error,
            )
            for e in r.entities
        ],
        warnings=list(r.warnings),
        customers_created=r.customers_created,
        sites_created=r.sites_created,
        vrfs_created=r.vrfs_created,
        spaces_created=r.spaces_created,
        vlans_created=r.vlans_created,
        blocks_created=r.blocks_created,
        subnets_created=r.subnets_created,
        addresses_created=r.addresses_created,
        total_created=r.total_created,
        total_overwrote=r.total_overwrote,
        total_skipped=r.total_skipped,
        total_failed=r.total_failed,
    )


# ── Endpoints ────────────────────────────────────────────────────────


@router.post(
    "/test-connection",
    response_model=NetboxTestOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def netbox_test_connection(
    _: SuperAdmin,
    body: NetboxConnIn = Body(...),
) -> NetboxTestOut:
    """Probe a NetBox install and confirm auth + version before a pull.

    Detects the version (``GET /api/status/``) and, on NetBox 4.5+, runs
    the cheap ``GET /api/authentication-check/`` to validate the token
    without touching data. Returns the daemon's version + per-object
    counts so the operator can confirm "yes, that's the NetBox I expected"
    before kicking off a 25 000-row migration.
    """

    # SECURITY: advisory SSRF guard — log the resolved NetBox IP so
    # operators can audit the connect target. Not hard-blocked: a
    # co-located / LAN NetBox is a legitimate migration source.
    assert_safe_target(body.base_url, label="netbox_import")

    try:
        async with NetBoxClient(
            base_url=body.base_url, token=body.token, verify_tls=body.verify_tls
        ) as nb:
            # Populates nb.netbox_version / nb.api_version as a side effect.
            await nb.detect_version()
            # Validate creds without pulling data on 4.5+; on older NetBox
            # the endpoint is absent and detect_version already proved auth.
            await nb.authentication_check()
            counts = await _status_counts(nb)
    except NetBoxClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    logger.info(
        "netbox_import.test_connection",
        endpoint=body.base_url,
        netbox_version=nb.netbox_version,
        api_version=nb.api_version,
        tls_verify=body.verify_tls,
    )
    return NetboxTestOut(
        ok=True,
        netbox_version=nb.netbox_version,
        api_version=nb.api_version,
        counts=counts,
    )


async def _status_counts(nb: NetBoxClient) -> dict[str, int] | None:
    """Pull the integer object counts from ``GET /api/status/`` if present.

    NetBox's status payload may carry a few rollup integers; we surface
    only the int-valued top-level fields so the operator gets a sense of
    scale. Best-effort — a missing / malformed body is non-fatal.
    """
    try:
        body = await nb.get_json("/api/status/")
    except NetBoxClientError:
        return None
    if not isinstance(body, dict):
        return None
    counts = {k: v for k, v in body.items() if isinstance(v, int) and not isinstance(v, bool)}
    return counts or None


@router.post(
    "/preview",
    response_model=PreviewOut,
    responses={502: {"description": "The remote import source is unreachable or refused the pull"}},
)
async def netbox_preview(
    current_user: SuperAdmin,
    db: DB,
    body: NetboxPreviewIn = Body(...),
) -> PreviewOut:
    """Live-pull a NetBox install and return the would-create plan.

    Side-effect-free: no DB writes, no audit row. Pulls every in-scope
    endpoint, maps onto the canonical IR, and flags every imported entity
    whose key already exists in the target. The operator can re-run as
    many times as they want while iterating on filters / strategy — only
    the commit endpoint mutates state.
    """

    # SECURITY: advisory SSRF guard (same as test-connection).
    assert_safe_target(body.base_url, label="netbox_import")

    filters = body.filters.model_dump() if body.filters else None
    try:
        preview = await preview_netbox_import(
            db,
            base_url=body.base_url,
            token=body.token,
            verify_tls=body.verify_tls,
            space_strategy=body.space_strategy,
            target_space_id=body.target_space_id,
            filters=filters,
        )
    except NetBoxClientError as exc:
        # Unreachable / unauthorised / over-ceiling pull → bad upstream.
        raise HTTPException(status_code=502, detail=str(exc))

    logger.info(
        "netbox_import.preview_endpoint",
        endpoint=body.base_url,
        space_strategy=body.space_strategy,
        customers=len(preview.customers),
        sites=len(preview.sites),
        vrfs=len(preview.vrfs),
        spaces=len(preview.spaces),
        vlans=len(preview.vlans),
        blocks=len(preview.blocks),
        subnets=len(preview.subnets),
        addresses=len(preview.addresses),
        conflicts=len(preview.conflicts),
        warnings=len(preview.warnings),
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview)


@router.post("/commit", response_model=CommitOut)
async def netbox_commit(
    current_user: SuperAdmin,
    db: DB,
    body: CommitIn = Body(...),
) -> CommitOut:
    """Apply a previously-previewed NetBox import.

    Re-detects conflicts fresh against up-to-date state (the previewed
    ``conflicts`` are advisory) and writes each entity in its own
    savepoint — a FK / overlap error on entity N rolls back N but keeps
    entities 1..N-1. Each committed entity gets one audit_log row tagged
    ``import_source=netbox``. A bad ``target_space_id`` aborts the whole
    batch before any row (422); per-row failures land as ``failed`` ledger
    rows. No agent wake — NetBox seeds IPAM only.
    """

    if body.plan.source != "netbox":
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint=netbox plan={body.plan.source}",
        )

    preview = _preview_from_pydantic(body.plan)
    actions: dict[str, ConflictAction] = {
        key: decision.action for key, decision in body.conflict_actions.items()
    }

    # Plain value up front: the commit may roll back, which expires the loaded user (#2816).
    actor_name = current_user.display_name
    try:
        result = await commit_import(
            db,
            preview=preview,
            conflict_actions=actions,
            space_strategy=body.space_strategy,
            target_space_id=body.target_space_id,
            default_router_name=body.default_router_name,
            actor=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    logger.info(
        "netbox_import.commit_endpoint",
        space_strategy=body.space_strategy,
        customers_created=result.customers_created,
        sites_created=result.sites_created,
        vrfs_created=result.vrfs_created,
        spaces_created=result.spaces_created,
        vlans_created=result.vlans_created,
        blocks_created=result.blocks_created,
        subnets_created=result.subnets_created,
        addresses_created=result.addresses_created,
        total_created=result.total_created,
        total_overwrote=result.total_overwrote,
        total_skipped=result.total_skipped,
        total_failed=result.total_failed,
        user=actor_name,
    )
    return _commit_result_to_pydantic(result)

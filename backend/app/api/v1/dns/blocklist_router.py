"""DNS Blocking List (RPZ) API.

Manages:
  - /blocklists                    (CRUD)
  - /blocklists/{id}/entries       (CRUD + bulk-add)
  - /blocklists/{id}/exceptions    (CRUD)
  - /blocklists/{id}/refresh       (enqueue feed sync)
  - /blocklists/{id}/assignments   (attach to views / server groups)
  - /blocklists/effective/view/{view_id}
  - /blocklists/effective/group/{group_id}

All mutations are audited. No backend-specific logic (BIND9 RPZ)
lives in this module — the driver will consume the effective representation
produced by `app.services.dns_blocklist`.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy import update as sa_update
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser, SuperAdmin
from app.core.agent_wake import collect_wake, dns_group_channel
from app.core.permissions import require_resource_permission
from app.core.update_nulls import resolve_update_changes
from app.models.audit import AuditLog
from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServerGroup,
    DNSView,
)
from app.services.dns.blocklist_templates import (
    BlocklistTemplate,
    TemplateGroupConflict,
    all_profiles,
    all_templates,
    profile_for,
    template_entries,
    template_for,
)
from app.services.dns_blocklist import (
    build_effective_for_group,
    build_effective_for_view,
    dedupe_domains,
)

logger = structlog.get_logger(__name__)
router = APIRouter(dependencies=[Depends(require_resource_permission("dns_blocklist"))])


VALID_SOURCE_TYPES = {"manual", "url", "file_upload"}
VALID_FEED_FORMATS = {"hosts", "domains", "adblock"}
VALID_BLOCK_MODES = {"nxdomain", "sinkhole", "refused"}
VALID_ENTRY_TYPES = {"block", "redirect", "nxdomain"}


# ── Schemas ─────────────────────────────────────────────────────────────────


class BlockListCreate(BaseModel):
    name: str
    description: str = ""
    category: str = "custom"
    source_type: str = "manual"
    feed_url: str | None = None
    feed_format: str = "hosts"
    update_interval_hours: int = 24
    block_mode: str = "nxdomain"
    sinkhole_ip: str | None = None
    # Feed rows block subdomains too. Default on — see the model.
    feed_entries_are_wildcard: bool = True
    enabled: bool = True

    @field_validator("source_type")
    @classmethod
    def _v_source(cls, v: str) -> str:
        if v not in VALID_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}")
        return v

    @field_validator("feed_format")
    @classmethod
    def _v_format(cls, v: str) -> str:
        if v not in VALID_FEED_FORMATS:
            raise ValueError(f"feed_format must be one of {sorted(VALID_FEED_FORMATS)}")
        return v

    @field_validator("block_mode")
    @classmethod
    def _v_mode(cls, v: str) -> str:
        if v not in VALID_BLOCK_MODES:
            raise ValueError(f"block_mode must be one of {sorted(VALID_BLOCK_MODES)}")
        return v


class BlockListUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    source_type: str | None = None
    feed_url: str | None = None
    feed_format: str | None = None
    update_interval_hours: int | None = None
    block_mode: str | None = None
    sinkhole_ip: str | None = None
    feed_entries_are_wildcard: bool | None = None
    enabled: bool | None = None

    @field_validator("source_type")
    @classmethod
    def _v_source(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {sorted(VALID_SOURCE_TYPES)}")
        return v

    @field_validator("feed_format")
    @classmethod
    def _v_format(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_FEED_FORMATS:
            raise ValueError(f"feed_format must be one of {sorted(VALID_FEED_FORMATS)}")
        return v

    @field_validator("block_mode")
    @classmethod
    def _v_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_BLOCK_MODES:
            raise ValueError(f"block_mode must be one of {sorted(VALID_BLOCK_MODES)}")
        return v


class BlockListResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    category: str
    source_type: str
    feed_url: str | None
    feed_format: str
    update_interval_hours: int
    block_mode: str
    sinkhole_ip: str | None
    feed_entries_are_wildcard: bool
    enabled: bool
    last_synced_at: datetime | None
    last_sync_status: str | None
    last_sync_error: str | None
    entry_count: int
    created_at: datetime
    modified_at: datetime
    applied_group_ids: list[uuid.UUID] = []
    applied_view_ids: list[uuid.UUID] = []

    model_config = {"from_attributes": True}


class EntryCreate(BaseModel):
    domain: str
    entry_type: str = "block"
    target: str | None = None
    # Default on: matches Pi-hole / uBlock expectations where adding a
    # domain blocks it AND every subdomain. The operator can uncheck to
    # block only the apex.
    is_wildcard: bool = True
    reason: str = ""

    @field_validator("entry_type")
    @classmethod
    def _v_et(cls, v: str) -> str:
        if v not in VALID_ENTRY_TYPES:
            raise ValueError(f"entry_type must be one of {sorted(VALID_ENTRY_TYPES)}")
        return v


class EntryUpdate(BaseModel):
    domain: str | None = None
    entry_type: str | None = None
    target: str | None = None
    is_wildcard: bool | None = None
    reason: str | None = None

    @field_validator("entry_type")
    @classmethod
    def _v_et_upd(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ENTRY_TYPES:
            raise ValueError(f"entry_type must be one of {sorted(VALID_ENTRY_TYPES)}")
        return v


class EntryResponse(BaseModel):
    id: uuid.UUID
    list_id: uuid.UUID
    domain: str
    entry_type: str
    target: str | None
    source: str
    is_wildcard: bool
    reason: str
    added_at: datetime

    model_config = {"from_attributes": True}


class EntryPage(BaseModel):
    total: int
    items: list[EntryResponse]


class BulkAddRequest(BaseModel):
    domains: list[str]
    entry_type: str = "block"
    target: str | None = None
    is_wildcard: bool = False

    @field_validator("entry_type")
    @classmethod
    def _v_et(cls, v: str) -> str:
        if v not in VALID_ENTRY_TYPES:
            raise ValueError(f"entry_type must be one of {sorted(VALID_ENTRY_TYPES)}")
        return v


class BulkAddResponse(BaseModel):
    added: int
    skipped: int
    total: int


class ExceptionCreate(BaseModel):
    domain: str
    reason: str = ""


class ExceptionUpdate(BaseModel):
    domain: str | None = None
    reason: str | None = None


class ExceptionResponse(BaseModel):
    id: uuid.UUID
    list_id: uuid.UUID
    domain: str
    reason: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AssignmentUpdate(BaseModel):
    server_group_ids: list[uuid.UUID] | None = None
    view_ids: list[uuid.UUID] | None = None


class RefreshResponse(BaseModel):
    list_id: uuid.UUID
    task_id: str | None
    status: str


class EffectiveEntryResponse(BaseModel):
    domain: str
    action: str
    block_mode: str
    sinkhole_ip: str | None
    target: str | None
    is_wildcard: bool
    list_id: uuid.UUID
    list_name: str


class EffectiveBlocklistResponse(BaseModel):
    scope: str
    scope_id: uuid.UUID
    entries: list[EffectiveEntryResponse]
    exceptions: list[str]
    lists: list[uuid.UUID]


# ── Helpers ─────────────────────────────────────────────────────────────────


async def _require_list(list_id: uuid.UUID, db: DB) -> DNSBlockList:
    result = await db.execute(
        select(DNSBlockList)
        .where(DNSBlockList.id == list_id)
        .options(
            selectinload(DNSBlockList.server_groups),
            selectinload(DNSBlockList.views),
        )
    )
    bl = result.scalar_one_or_none()
    if bl is None:
        raise HTTPException(status_code=404, detail="Blocklist not found")
    return bl


def _to_response(bl: DNSBlockList) -> BlockListResponse:
    return BlockListResponse(
        id=bl.id,
        name=bl.name,
        description=bl.description,
        category=bl.category,
        source_type=bl.source_type,
        feed_url=bl.feed_url,
        feed_format=bl.feed_format,
        update_interval_hours=bl.update_interval_hours,
        block_mode=bl.block_mode,
        sinkhole_ip=bl.sinkhole_ip,
        feed_entries_are_wildcard=bl.feed_entries_are_wildcard,
        enabled=bl.enabled,
        last_synced_at=bl.last_synced_at,
        last_sync_status=bl.last_sync_status,
        last_sync_error=bl.last_sync_error,
        entry_count=bl.entry_count,
        created_at=bl.created_at,
        modified_at=bl.modified_at,
        applied_group_ids=[g.id for g in bl.server_groups],
        applied_view_ids=[v.id for v in bl.views],
    )


def _blocklist_group_ids(bl: DNSBlockList) -> set[uuid.UUID]:
    """Server-group ids whose rendered RPZ config a change to ``bl`` affects.

    Union of the blocklist's directly-assigned ``server_groups`` and the
    groups owning any ``view`` the blocklist is scoped to. Both relationships
    must already be eager-loaded (``_require_list`` does this via
    ``selectinload``); ``view.group_id`` is a plain loaded column so reading
    it triggers no async-lazy relationship load (no MissingGreenlet).
    """
    gids: set[uuid.UUID] = {g.id for g in bl.server_groups}
    gids.update(v.group_id for v in bl.views)
    return gids


def _wake_blocklist_groups(bl: DNSBlockList) -> None:
    """Stash a DNS-group wake for every group affected by a change to ``bl``.

    Safe no-op when the blocklist is unassigned (e.g. just-created) — no group
    renders it yet, so there's nothing to wake.
    """
    for gid in _blocklist_group_ids(bl):
        collect_wake(dns_group_channel(gid))


def _audit(
    current_user: Any,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
    changed_fields: list[str] | None = None,
) -> AuditLog:
    return AuditLog(
        user_id=current_user.id,
        user_display_name=current_user.display_name,
        auth_source=current_user.auth_source,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_display=resource_display,
        changed_fields=changed_fields,
        result="success",
    )


# ── Curated catalog ─────────────────────────────────────────────────────────


_CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "dns_blocklist_catalog.json"


@lru_cache(maxsize=1)
def _load_catalog() -> dict[str, Any]:
    """Load the static blocklist catalog JSON shipped with the app.

    Memoised — the file is read once per process. Operators who want a
    fresh snapshot from upstream get it via the next release.
    """
    with open(_CATALOG_PATH, encoding="utf-8") as f:
        return json.load(f)


class CatalogSource(BaseModel):
    id: str
    name: str
    description: str
    category: str
    feed_url: str
    feed_format: str
    license: str
    homepage: str | None = None
    recommended: bool = False
    # Absent on every current entry, meaning True — see _build_from_source.
    entries_are_wildcard: bool = True


class CatalogTemplateGroup(BaseModel):
    id: str
    name: str
    target: str
    domain_count: int
    default: bool
    note: str | None = None
    conflicts_with: list[str] = []


class CatalogTemplate(BaseModel):
    id: str
    name: str
    description: str
    category: str
    block_mode: str
    groups: list[CatalogTemplateGroup]


class CatalogProfile(BaseModel):
    id: str
    name: str
    description: str
    source_ids: list[str]
    template_ids: list[str]
    note: str | None = None


class CatalogResponse(BaseModel):
    version: str
    comment: str
    sources: list[CatalogSource]
    templates: list[CatalogTemplate]
    profiles: list[CatalogProfile]


class SubscribeFromCatalogRequest(BaseModel):
    source_id: str
    # Operator can override the default name (handy if they're subscribing to
    # the same source twice with different scopes).
    name: str | None = None
    update_interval_hours: int = 24
    block_mode: str = "nxdomain"
    enabled: bool = True


@router.get("/blocklists/catalog", response_model=CatalogResponse)
async def get_blocklist_catalog(_: CurrentUser) -> CatalogResponse:
    """Return the curated catalog of blocklist sources, templates, profiles.

    Three kinds of thing, all applied the same way — pick one, click apply:

    * **sources** — well-known remote feeds (StevenBlack, Hagezi, OISD,
      AdGuard, Phishing Army, URLhaus, …). ``POST /blocklists/from-catalog``
      creates a ``source_type="url"`` list the refresh task then populates.
    * **templates** — entry sets shipped inline rather than fetched, for
      rules that have no upstream feed. ``POST /blocklists/from-template``
      creates a ``source_type="manual"`` list with the entries already in
      it. Group ``domain_count`` is returned instead of the domains
      themselves: the SafeSearch template alone carries 269 names, and no
      caller needs them to render a picker.
    * **profiles** — named compositions of the above, applied together by
      ``POST /blocklists/apply-profile``.
    """
    raw = _load_catalog()
    return CatalogResponse(
        version=raw["version"],
        comment=raw["comment"],
        sources=[CatalogSource(**s) for s in raw["sources"]],
        templates=[
            CatalogTemplate(
                id=t.id,
                name=t.name,
                description=t.description,
                category=t.category,
                block_mode=t.block_mode,
                groups=[
                    CatalogTemplateGroup(
                        id=g.id,
                        name=g.name,
                        target=g.target,
                        domain_count=len(g.domains),
                        default=g.default,
                        note=g.note,
                        conflicts_with=list(g.conflicts_with),
                    )
                    for g in t.groups
                ],
            )
            for t in all_templates()
        ],
        profiles=[
            CatalogProfile(
                id=p.id,
                name=p.name,
                description=p.description,
                source_ids=list(p.source_ids),
                template_ids=list(p.template_ids),
                note=p.note,
            )
            for p in all_profiles()
        ],
    )


@router.post(
    "/blocklists/from-catalog",
    response_model=BlockListResponse,
    status_code=status.HTTP_201_CREATED,
)
async def subscribe_from_catalog(
    body: SubscribeFromCatalogRequest, db: DB, current_user: SuperAdmin
) -> BlockListResponse:
    """Create a ``DNSBlockList`` subscribed to a catalog entry.

    Equivalent to ``POST /blocklists`` with the catalog entry's URL,
    format, name, and category prefilled. The operator can override
    the name (so they can subscribe to the same upstream twice with
    different scopes); everything else comes from the catalog.
    """
    catalog = _load_catalog()
    src = next((s for s in catalog["sources"] if s["id"] == body.source_id), None)
    if src is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Catalog entry '{body.source_id}' not found",
        )
    name = body.name or src["name"]
    await _assert_name_free(db, name)
    bl = _build_from_source(
        src,
        name,
        update_interval_hours=body.update_interval_hours,
        block_mode=body.block_mode,
        enabled=body.enabled,
    )
    db.add(bl)
    await db.flush()
    db.add(
        _audit(
            current_user,
            "create",
            "dns_blocklist",
            str(bl.id),
            bl.name,
        )
    )
    await db.commit()
    reloaded = await _require_list(bl.id, db)

    _enqueue_initial_refresh(bl)
    _wake_blocklist_groups(reloaded)
    logger.info(
        "dns_blocklist_subscribed_from_catalog",
        list_id=str(bl.id),
        source_id=body.source_id,
    )
    return _to_response(reloaded)


# ── Built-in templates + profiles (issue #878) ──────────────────────────────


async def _assert_name_free(db: DB, name: str) -> None:
    existing = await db.execute(select(DNSBlockList).where(DNSBlockList.name == name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"A blocklist named '{name}' already exists",
        )


def _build_from_source(
    src: dict[str, Any],
    name: str,
    *,
    update_interval_hours: int,
    block_mode: str,
    enabled: bool,
) -> DNSBlockList:
    return DNSBlockList(
        name=name,
        description=src["description"],
        category=src["category"],
        source_type="url",
        feed_url=src["feed_url"],
        feed_format=src["feed_format"],
        update_interval_hours=update_interval_hours,
        block_mode=block_mode,
        # Per-source, defaulting on (#894). Every catalog entry today is a
        # "block this domain and everything under it" list, so none set it
        # — the key exists for a host-specific feed (a threat-intel drop of
        # individual C2 FQDNs), where blocking the parent domain would be
        # over-blocking. Left absent rather than stamped `true` on all 19
        # entries, which would be noise carrying no information.
        feed_entries_are_wildcard=bool(src.get("entries_are_wildcard", True)),
        enabled=enabled,
    )


def _enqueue_initial_refresh(bl: DNSBlockList) -> None:
    """Populate a freshly-subscribed feed without a manual Refresh click.

    Same work the explicit ``/refresh`` endpoint enqueues. Failure to
    enqueue is logged, never raised: the list row is already committed
    and the scheduled sweep will pick it up, so turning a broker hiccup
    into a 500 would lose a valid subscription for nothing.
    """
    if not bl.enabled or bl.source_type != "url":
        return
    from app.tasks.dns import refresh_blocklist_feed

    try:
        refresh_blocklist_feed.delay(str(bl.id))
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "blocklist_initial_refresh_enqueue_failed",
            list_id=str(bl.id),
            error=str(e),
        )


class FromTemplateRequest(BaseModel):
    template_id: str
    name: str | None = None
    # None ⇒ the template's default groups. An explicit [] means "none",
    # which is refused below rather than quietly creating an empty list.
    group_ids: list[str] | None = None
    block_mode: str | None = None
    enabled: bool = True

    @field_validator("block_mode")
    @classmethod
    def _v_bm(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_BLOCK_MODES:
            raise ValueError(f"block_mode must be one of {sorted(VALID_BLOCK_MODES)}")
        return v


async def _materialise_template(
    db: DB,
    template: BlocklistTemplate,
    *,
    name: str,
    group_ids: list[str] | None,
    block_mode: str | None,
    enabled: bool,
) -> DNSBlockList:
    """Create a manual list carrying the template's rendered entries.

    Flushes but does not commit — the caller owns the transaction so a
    profile can apply several of these atomically.
    """
    try:
        entries = template_entries(template, group_ids)
    except TemplateGroupConflict as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if not entries:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No groups selected for template '{template.id}', so the list "
                f"would be empty. Available groups: "
                f"{', '.join(g.id for g in template.groups)}"
            ),
        )

    bl = DNSBlockList(
        name=name,
        description=template.description,
        category=template.category,
        source_type="manual",
        feed_url=None,
        # There is no feed to refresh, so the cadence is meaningless here;
        # 0 says so rather than advertising a 24 h refresh that can never
        # happen. (Feed refresh is enqueue-driven today — subscribe and the
        # explicit /refresh button — so nothing polls this field yet.)
        update_interval_hours=0,
        block_mode=block_mode or template.block_mode,
        enabled=enabled,
        entry_count=len(entries),
    )
    db.add(bl)
    await db.flush()

    db.add_all(
        [
            DNSBlockListEntry(
                list_id=bl.id,
                domain=e.domain,
                entry_type=e.entry_type,
                target=e.target,
                is_wildcard=e.is_wildcard,
                # "manual", not "feed": the refresh task diffs feed-sourced
                # rows against the fetched set and deletes what is missing.
                # These rows have no feed, so a stray refresh would wipe them.
                source="manual",
                reason=e.reason,
            )
            for e in entries
        ]
    )
    return bl


@router.post(
    "/blocklists/from-template",
    response_model=BlockListResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_from_template(
    body: FromTemplateRequest, db: DB, current_user: SuperAdmin
) -> BlockListResponse:
    """Create a manual blocklist from a built-in template.

    Unlike ``/from-catalog`` there is nothing to fetch: the entries ship
    in the catalog file and are written straight into the new list, so it
    is usable the moment this returns.
    """
    template = template_for(body.template_id)
    if template is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template '{body.template_id}' not found",
        )
    name = body.name or template.name
    await _assert_name_free(db, name)

    bl = await _materialise_template(
        db,
        template,
        name=name,
        group_ids=body.group_ids,
        block_mode=body.block_mode,
        enabled=body.enabled,
    )
    db.add(_audit(current_user, "create", "dns_blocklist", str(bl.id), bl.name))
    await db.commit()

    reloaded = await _require_list(bl.id, db)
    _wake_blocklist_groups(reloaded)
    logger.info(
        "dns_blocklist_created_from_template",
        list_id=str(bl.id),
        template_id=template.id,
        entries=reloaded.entry_count,
    )
    return _to_response(reloaded)


class ApplyProfileRequest(BaseModel):
    profile_id: str
    enabled: bool = True


class AppliedItem(BaseModel):
    kind: str  # "source" | "template"
    catalog_id: str
    name: str
    list_id: uuid.UUID | None = None
    # "created" | "skipped_existing" | "skipped_missing"
    # (``skipped_missing`` = the profile names a catalog id this release
    # does not ship — a packaging bug, reported rather than raised.)
    status: str


class ApplyProfileResponse(BaseModel):
    profile_id: str
    created: int
    skipped: int
    items: list[AppliedItem]


@router.post("/blocklists/apply-profile", response_model=ApplyProfileResponse)
async def apply_profile(
    body: ApplyProfileRequest, db: DB, current_user: SuperAdmin
) -> ApplyProfileResponse:
    """Apply a named profile — several feeds and templates in one action.

    Nothing is scoped to a group or view here. A profile that auto-applied
    itself everywhere would filter the server VLAN along with the kids'
    one, so assignment stays a deliberate second step via
    ``PUT /blocklists/{id}/assignments``.

    Re-applying is safe: an entry whose list name is already taken is
    reported as ``skipped_existing`` rather than failing the whole call,
    so a profile that gained a source in a later release can be re-run to
    pick up just the new one.
    """
    profile = profile_for(body.profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile '{body.profile_id}' not found",
        )

    catalog = _load_catalog()
    by_id = {s["id"]: s for s in catalog["sources"]}
    items: list[AppliedItem] = []
    fresh_feeds: list[DNSBlockList] = []
    created_lists: list[DNSBlockList] = []

    # Names claimed in one pass, so a profile naming the same list twice
    # collides here rather than at flush.
    existing_names = set((await db.execute(select(DNSBlockList.name))).scalars().all())

    for source_id in profile.source_ids:
        src = by_id.get(source_id)
        if src is None:
            # A profile referencing an unknown source is a packaging bug,
            # not operator error. Report it and keep applying the rest.
            logger.warning(
                "blocklist_profile_unknown_source",
                profile_id=profile.id,
                source_id=source_id,
            )
            items.append(
                AppliedItem(
                    kind="source",
                    catalog_id=source_id,
                    name=source_id,
                    status="skipped_missing",
                )
            )
            continue
        if src["name"] in existing_names:
            items.append(
                AppliedItem(
                    kind="source",
                    catalog_id=source_id,
                    name=src["name"],
                    status="skipped_existing",
                )
            )
            continue
        bl = _build_from_source(
            src,
            src["name"],
            update_interval_hours=24,
            block_mode="nxdomain",
            enabled=body.enabled,
        )
        db.add(bl)
        await db.flush()
        existing_names.add(bl.name)
        fresh_feeds.append(bl)
        created_lists.append(bl)
        items.append(
            AppliedItem(
                kind="source",
                catalog_id=source_id,
                name=bl.name,
                list_id=bl.id,
                status="created",
            )
        )

    for template_id in profile.template_ids:
        template = template_for(template_id)
        if template is None:
            logger.warning(
                "blocklist_profile_unknown_template",
                profile_id=profile.id,
                template_id=template_id,
            )
            items.append(
                AppliedItem(
                    kind="template",
                    catalog_id=template_id,
                    name=template_id,
                    status="skipped_missing",
                )
            )
            continue
        if template.name in existing_names:
            items.append(
                AppliedItem(
                    kind="template",
                    catalog_id=template_id,
                    name=template.name,
                    status="skipped_existing",
                )
            )
            continue
        bl = await _materialise_template(
            db,
            template,
            name=template.name,
            group_ids=None,
            block_mode=None,
            enabled=body.enabled,
        )
        existing_names.add(bl.name)
        created_lists.append(bl)
        items.append(
            AppliedItem(
                kind="template",
                catalog_id=template_id,
                name=bl.name,
                list_id=bl.id,
                status="created",
            )
        )

    for bl in created_lists:
        db.add(_audit(current_user, "create", "dns_blocklist", str(bl.id), bl.name))
    await db.commit()

    # Enqueued after commit — the rows must exist before a worker looks
    # them up, and the worker runs in a different process.
    for bl in fresh_feeds:
        _enqueue_initial_refresh(bl)

    created = sum(1 for i in items if i.status == "created")
    logger.info(
        "dns_blocklist_profile_applied",
        profile_id=profile.id,
        created=created,
        total=len(items),
    )
    return ApplyProfileResponse(
        profile_id=profile.id,
        created=created,
        skipped=len(items) - created,
        items=items,
    )


# ── Blocklist CRUD ──────────────────────────────────────────────────────────


@router.get("/blocklists", response_model=list[BlockListResponse])
async def list_blocklists(db: DB, _: CurrentUser) -> list[BlockListResponse]:
    result = await db.execute(
        select(DNSBlockList)
        .options(
            selectinload(DNSBlockList.server_groups),
            selectinload(DNSBlockList.views),
        )
        .order_by(DNSBlockList.name)
    )
    return [_to_response(bl) for bl in result.scalars().all()]


@router.post(
    "/blocklists",
    response_model=BlockListResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_blocklist(
    body: BlockListCreate, db: DB, current_user: SuperAdmin
) -> BlockListResponse:
    existing = await db.execute(select(DNSBlockList).where(DNSBlockList.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A blocklist with that name already exists")

    bl = DNSBlockList(**body.model_dump())
    db.add(bl)
    await db.flush()
    db.add(
        _audit(
            current_user,
            "create",
            "dns_blocklist",
            str(bl.id),
            bl.name,
        )
    )
    await db.commit()
    reloaded = await _require_list(bl.id, db)
    _wake_blocklist_groups(reloaded)
    logger.info("dns_blocklist_created", list_id=str(bl.id), name=bl.name)
    return _to_response(reloaded)


@router.get("/blocklists/{list_id}", response_model=BlockListResponse)
async def get_blocklist(list_id: uuid.UUID, db: DB, _: CurrentUser) -> BlockListResponse:
    bl = await _require_list(list_id, db)
    return _to_response(bl)


@router.put("/blocklists/{list_id}", response_model=BlockListResponse)
async def update_blocklist(
    list_id: uuid.UUID, body: BlockListUpdate, db: DB, current_user: SuperAdmin
) -> BlockListResponse:
    bl = await _require_list(list_id, db)
    # #1563 — explicit null clears feed_url / sinkhole_ip; null for a
    # NOT NULL column is a 422.
    changes = resolve_update_changes(
        body,
        clearable={"feed_url", "sinkhole_ip"},
        non_nullable={
            "name", "description", "category", "source_type", "feed_format",
            "update_interval_hours", "block_mode", "feed_entries_are_wildcard", "enabled",
        },
    )
    wildcard_flipped = (
        "feed_entries_are_wildcard" in changes
        and changes["feed_entries_are_wildcard"] != bl.feed_entries_are_wildcard
    )
    for k, v in changes.items():
        setattr(bl, k, v)

    if wildcard_flipped:
        # Restamp the rows already stored (#894). The refresh task diffs by
        # domain and never revisits an unchanged one, so without this the
        # toggle would appear to do nothing until a feed's contents
        # happened to churn — the operator's stated intent silently
        # deferred for days.
        #
        # Feed rows only. A manual entry's ``is_wildcard`` is that row's own
        # setting, and someone who unchecked "include subdomains" on one
        # domain did not ask for a list-wide switch to overwrite it.
        #
        # One statement, in the same transaction as the flag write, and
        # deliberately so: the flag and the rows it describes must not be
        # able to disagree, and a background job would set the flag while
        # the rows lagged — reintroducing the exact "silently deferred"
        # state this restamp exists to prevent. Measured at **~7 s** on
        # the largest catalog feed (Hagezi Gambling, 464k rows) on a
        # 2-core dev box, which is slow for a click but nowhere near an
        # HTTP timeout. Revisit if a list an order of magnitude larger
        # ever becomes normal.
        await db.execute(
            sa_update(DNSBlockListEntry)
            .where(
                DNSBlockListEntry.list_id == bl.id,
                DNSBlockListEntry.source == "feed",
            )
            .values(is_wildcard=bl.feed_entries_are_wildcard)
        )

    db.add(
        _audit(
            current_user,
            "update",
            "dns_blocklist",
            str(bl.id),
            bl.name,
            changed_fields=list(changes.keys()),
        )
    )
    await db.commit()
    reloaded = await _require_list(list_id, db)
    _wake_blocklist_groups(reloaded)
    return _to_response(reloaded)


@router.delete("/blocklists/{list_id}", status_code=204)
async def delete_blocklist(list_id: uuid.UUID, db: DB, current_user: SuperAdmin) -> None:
    bl = await _require_list(list_id, db)
    # Capture affected groups from the eager-loaded assignments BEFORE the
    # delete (the association rows go away with the cascade).
    _wake_blocklist_groups(bl)
    db.add(_audit(current_user, "delete", "dns_blocklist", str(bl.id), bl.name))
    await db.delete(bl)
    await db.commit()


# ── Assignments ─────────────────────────────────────────────────────────────


@router.put("/blocklists/{list_id}/assignments", response_model=BlockListResponse)
async def update_assignments(
    list_id: uuid.UUID,
    body: AssignmentUpdate,
    db: DB,
    current_user: SuperAdmin,
) -> BlockListResponse:
    bl = await _require_list(list_id, db)

    # Capture the pre-change affected groups so a de-assigned group also
    # re-renders (drops the blocklist). Read from the eager-loaded relationships
    # before we reassign them.
    old_group_ids = _blocklist_group_ids(bl)

    changed: list[str] = []
    if body.server_group_ids is not None:
        groups = list(
            (
                await db.execute(
                    select(DNSServerGroup).where(DNSServerGroup.id.in_(body.server_group_ids))
                )
            )
            .scalars()
            .all()
        )
        if len(groups) != len(set(body.server_group_ids)):
            raise HTTPException(status_code=404, detail="One or more server groups not found")
        bl.server_groups = groups
        changed.append("server_group_ids")

    if body.view_ids is not None:
        views = list(
            (await db.execute(select(DNSView).where(DNSView.id.in_(body.view_ids)))).scalars().all()
        )
        if len(views) != len(set(body.view_ids)):
            raise HTTPException(status_code=404, detail="One or more views not found")
        bl.views = views
        changed.append("view_ids")

    db.add(
        _audit(
            current_user,
            "update",
            "dns_blocklist_assignment",
            str(bl.id),
            bl.name,
            changed_fields=changed,
        )
    )
    await db.commit()
    reloaded = await _require_list(list_id, db)
    # Wake BOTH the old and new group sets so de-assigned groups re-render too.
    for gid in old_group_ids | _blocklist_group_ids(reloaded):
        collect_wake(dns_group_channel(gid))
    return _to_response(reloaded)


# ── Entries ────────────────────────────────────────────────────────────────


@router.get("/blocklists/{list_id}/entries", response_model=EntryPage)
async def list_entries(
    list_id: uuid.UUID,
    db: DB,
    _: CurrentUser,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> EntryPage:
    await _require_list(list_id, db)
    stmt = select(DNSBlockListEntry).where(DNSBlockListEntry.list_id == list_id)
    if q:
        stmt = stmt.where(DNSBlockListEntry.domain.ilike(f"%{q.lower()}%"))
    total_stmt = stmt
    total = len((await db.execute(total_stmt)).scalars().all())
    items_result = await db.execute(
        stmt.order_by(DNSBlockListEntry.domain).limit(limit).offset(offset)
    )
    return EntryPage(
        total=total,
        items=[EntryResponse.model_validate(e) for e in items_result.scalars().all()],
    )


@router.post(
    "/blocklists/{list_id}/entries",
    response_model=EntryResponse,
    status_code=201,
)
async def add_entry(
    list_id: uuid.UUID, body: EntryCreate, db: DB, current_user: SuperAdmin
) -> EntryResponse:
    bl = await _require_list(list_id, db)
    domain = body.domain.strip().lower().strip(".")
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain")

    existing = await db.execute(
        select(DNSBlockListEntry).where(
            DNSBlockListEntry.list_id == list_id, DNSBlockListEntry.domain == domain
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Domain already in this blocklist")

    entry = DNSBlockListEntry(
        list_id=list_id,
        domain=domain,
        entry_type=body.entry_type,
        target=body.target,
        source="manual",
        is_wildcard=body.is_wildcard,
        reason=body.reason,
    )
    db.add(entry)
    bl.entry_count = bl.entry_count + 1
    db.add(
        _audit(
            current_user,
            "create",
            "dns_blocklist_entry",
            str(entry.id),
            f"{domain} ({bl.name})",
        )
    )
    await db.commit()
    await db.refresh(entry)
    _wake_blocklist_groups(bl)
    return EntryResponse.model_validate(entry)


@router.post(
    "/blocklists/{list_id}/entries/bulk",
    response_model=BulkAddResponse,
)
async def bulk_add_entries(
    list_id: uuid.UUID,
    body: BulkAddRequest,
    db: DB,
    current_user: SuperAdmin,
) -> BulkAddResponse:
    bl = await _require_list(list_id, db)

    # Dedupe submitted domains + validate
    incoming = dedupe_domains(body.domains)

    # Fetch existing domains in the list for the diff
    existing_result = await db.execute(
        select(DNSBlockListEntry.domain).where(DNSBlockListEntry.list_id == list_id)
    )
    existing: set[str] = set(existing_result.scalars().all())

    added = 0
    skipped = 0
    for d in incoming:
        if d in existing:
            skipped += 1
            continue
        db.add(
            DNSBlockListEntry(
                list_id=list_id,
                domain=d,
                entry_type=body.entry_type,
                target=body.target,
                source="manual",
                is_wildcard=body.is_wildcard,
            )
        )
        existing.add(d)
        added += 1

    # Non-canonical / duplicate inputs that got filtered by dedupe:
    skipped += max(0, len(body.domains) - len(incoming))

    bl.entry_count = bl.entry_count + added
    db.add(
        _audit(
            current_user,
            "bulk_create",
            "dns_blocklist_entry",
            str(list_id),
            f"{added} added to {bl.name}",
        )
    )
    await db.commit()
    if added:
        _wake_blocklist_groups(bl)
    return BulkAddResponse(added=added, skipped=skipped, total=len(body.domains))


@router.put(
    "/blocklists/{list_id}/entries/{entry_id}",
    response_model=EntryResponse,
)
async def update_entry(
    list_id: uuid.UUID,
    entry_id: uuid.UUID,
    body: EntryUpdate,
    db: DB,
    current_user: SuperAdmin,
) -> EntryResponse:
    bl = await _require_list(list_id, db)
    result = await db.execute(
        select(DNSBlockListEntry).where(
            DNSBlockListEntry.id == entry_id, DNSBlockListEntry.list_id == list_id
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    # Editing is only meaningful for manual entries; feed-sourced entries are
    # overwritten on the next refresh so silent edits would be lost.
    if entry.source != "manual":
        raise HTTPException(
            status_code=409,
            detail="Only manual entries can be edited; feed-sourced entries are refreshed from source.",
        )
    # #1563 — explicit null clears target; null for a NOT NULL column is a 422.
    changes = resolve_update_changes(
        body,
        clearable={"target"},
        non_nullable={"domain", "entry_type", "is_wildcard", "reason"},
    )
    if "domain" in changes:
        domain = changes["domain"].strip().lower().strip(".")
        if not domain or "." not in domain:
            raise HTTPException(status_code=422, detail="Invalid domain")
        if domain != entry.domain:
            dup = await db.execute(
                select(DNSBlockListEntry).where(
                    DNSBlockListEntry.list_id == list_id,
                    DNSBlockListEntry.domain == domain,
                    DNSBlockListEntry.id != entry_id,
                )
            )
            if dup.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Domain already in this blocklist")
        changes["domain"] = domain
    for k, v in changes.items():
        setattr(entry, k, v)
    db.add(
        _audit(
            current_user,
            "update",
            "dns_blocklist_entry",
            str(entry.id),
            f"{entry.domain} ({bl.name})",
        )
    )
    await db.commit()
    await db.refresh(entry)
    _wake_blocklist_groups(bl)
    return EntryResponse.model_validate(entry)


@router.delete("/blocklists/{list_id}/entries/{entry_id}", status_code=204)
async def delete_entry(
    list_id: uuid.UUID,
    entry_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> None:
    bl = await _require_list(list_id, db)
    result = await db.execute(
        select(DNSBlockListEntry).where(
            DNSBlockListEntry.id == entry_id, DNSBlockListEntry.list_id == list_id
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    db.add(
        _audit(
            current_user,
            "delete",
            "dns_blocklist_entry",
            str(entry.id),
            f"{entry.domain} ({bl.name})",
        )
    )
    await db.delete(entry)
    bl.entry_count = max(0, bl.entry_count - 1)
    await db.commit()
    _wake_blocklist_groups(bl)


# ── Exceptions ─────────────────────────────────────────────────────────────


@router.get("/blocklists/{list_id}/exceptions", response_model=list[ExceptionResponse])
async def list_exceptions(
    list_id: uuid.UUID, db: DB, _: CurrentUser
) -> list[DNSBlockListException]:
    await _require_list(list_id, db)
    result = await db.execute(
        select(DNSBlockListException)
        .where(DNSBlockListException.list_id == list_id)
        .order_by(DNSBlockListException.domain)
    )
    return list(result.scalars().all())


@router.post(
    "/blocklists/{list_id}/exceptions",
    response_model=ExceptionResponse,
    status_code=201,
)
async def add_exception(
    list_id: uuid.UUID,
    body: ExceptionCreate,
    db: DB,
    current_user: SuperAdmin,
) -> DNSBlockListException:
    bl = await _require_list(list_id, db)
    domain = body.domain.strip().lower().strip(".")
    if not domain or "." not in domain:
        raise HTTPException(status_code=422, detail="Invalid domain")

    existing = await db.execute(
        select(DNSBlockListException).where(
            DNSBlockListException.list_id == list_id,
            DNSBlockListException.domain == domain,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Exception already exists")

    ex = DNSBlockListException(
        list_id=list_id,
        domain=domain,
        reason=body.reason,
        created_by_user_id=current_user.id,
    )
    db.add(ex)
    db.add(
        _audit(
            current_user,
            "create",
            "dns_blocklist_exception",
            str(ex.id),
            f"{domain} ({bl.name})",
        )
    )
    await db.commit()
    await db.refresh(ex)
    _wake_blocklist_groups(bl)
    return ex


@router.put(
    "/blocklists/{list_id}/exceptions/{exception_id}",
    response_model=ExceptionResponse,
)
async def update_exception(
    list_id: uuid.UUID,
    exception_id: uuid.UUID,
    body: ExceptionUpdate,
    db: DB,
    current_user: SuperAdmin,
) -> DNSBlockListException:
    bl = await _require_list(list_id, db)
    result = await db.execute(
        select(DNSBlockListException).where(
            DNSBlockListException.id == exception_id,
            DNSBlockListException.list_id == list_id,
        )
    )
    ex = result.scalar_one_or_none()
    if not ex:
        raise HTTPException(status_code=404, detail="Exception not found")
    changes = body.model_dump(exclude_none=True)
    if "domain" in changes:
        domain = changes["domain"].strip().lower().strip(".")
        if not domain or "." not in domain:
            raise HTTPException(status_code=422, detail="Invalid domain")
        if domain != ex.domain:
            dup = await db.execute(
                select(DNSBlockListException).where(
                    DNSBlockListException.list_id == list_id,
                    DNSBlockListException.domain == domain,
                    DNSBlockListException.id != exception_id,
                )
            )
            if dup.scalar_one_or_none():
                raise HTTPException(status_code=409, detail="Exception already exists")
        changes["domain"] = domain
    for k, v in changes.items():
        setattr(ex, k, v)
    db.add(
        _audit(
            current_user,
            "update",
            "dns_blocklist_exception",
            str(ex.id),
            f"{ex.domain} ({bl.name})",
        )
    )
    await db.commit()
    await db.refresh(ex)
    _wake_blocklist_groups(bl)
    return ex


@router.delete("/blocklists/{list_id}/exceptions/{exception_id}", status_code=204)
async def delete_exception(
    list_id: uuid.UUID,
    exception_id: uuid.UUID,
    db: DB,
    current_user: SuperAdmin,
) -> None:
    bl = await _require_list(list_id, db)
    result = await db.execute(
        select(DNSBlockListException).where(
            DNSBlockListException.id == exception_id,
            DNSBlockListException.list_id == list_id,
        )
    )
    ex = result.scalar_one_or_none()
    if not ex:
        raise HTTPException(status_code=404, detail="Exception not found")
    db.add(
        _audit(
            current_user,
            "delete",
            "dns_blocklist_exception",
            str(ex.id),
            f"{ex.domain} ({bl.name})",
        )
    )
    await db.delete(ex)
    await db.commit()
    _wake_blocklist_groups(bl)


# ── Feed refresh ───────────────────────────────────────────────────────────


@router.post("/blocklists/{list_id}/refresh", response_model=RefreshResponse)
async def refresh_blocklist(
    list_id: uuid.UUID, db: DB, current_user: SuperAdmin
) -> RefreshResponse:
    bl = await _require_list(list_id, db)
    if not bl.feed_url:
        raise HTTPException(
            status_code=422,
            detail="Blocklist has no feed_url — cannot refresh from feed",
        )
    # Lazy import so tests can run without broker connectivity
    from app.tasks.dns import refresh_blocklist_feed

    task_id: str | None = None
    try:
        result = refresh_blocklist_feed.delay(str(bl.id))
        task_id = result.id
    except Exception as e:  # noqa: BLE001
        logger.warning("blocklist_refresh_enqueue_failed", list_id=str(bl.id), error=str(e))

    db.add(
        _audit(
            current_user,
            "refresh",
            "dns_blocklist",
            str(bl.id),
            bl.name,
        )
    )
    await db.commit()
    # Advisory wake on enqueue. The feed fetch + entry rewrite happens in the
    # Celery worker (`refresh_blocklist_feed`), which publishes its own wake
    # after committing the new entries; this just nudges the parked poll so a
    # no-change refresh still converges promptly.
    _wake_blocklist_groups(bl)
    return RefreshResponse(list_id=bl.id, task_id=task_id, status="queued")


# ── Effective list (backend-neutral; consumed by DNS driver in Wave 2) ─────


@router.get(
    "/blocklists/effective/view/{view_id}",
    response_model=EffectiveBlocklistResponse,
)
async def effective_for_view(
    view_id: uuid.UUID, db: DB, _: CurrentUser
) -> EffectiveBlocklistResponse:
    eff = await build_effective_for_view(db, view_id)
    return EffectiveBlocklistResponse(
        scope=eff.scope,
        scope_id=eff.scope_id,
        entries=[
            EffectiveEntryResponse.model_validate(e, from_attributes=True) for e in eff.entries
        ],
        exceptions=sorted(eff.exceptions),
        lists=eff.lists,
    )


@router.get(
    "/blocklists/effective/group/{group_id}",
    response_model=EffectiveBlocklistResponse,
)
async def effective_for_group(
    group_id: uuid.UUID, db: DB, _: CurrentUser
) -> EffectiveBlocklistResponse:
    eff = await build_effective_for_group(db, group_id)
    return EffectiveBlocklistResponse(
        scope=eff.scope,
        scope_id=eff.scope_id,
        entries=[
            EffectiveEntryResponse.model_validate(e, from_attributes=True) for e in eff.entries
        ],
        exceptions=sorted(eff.exceptions),
        lists=eff.lists,
    )

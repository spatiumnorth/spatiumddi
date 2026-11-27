"""phpIPAM one-shot IPAM importer endpoints -- test-connection + preview + commit.

A read-only migration tool (issue #4734), NOT a continuous reconciler, shaped
exactly like the NetBox importer (#36): the operator supplies the phpIPAM URL
and credentials per request (read once, **never persisted, never echoed**),
previews what would be imported, then commits the unmodified previewed plan.
The server stores nothing between the two calls.

The preview and commit shapes are the NetBox importer's (``PreviewOut`` carries
``source: "phpipam"`` here), and the commit runs the same pipeline, so
conflicts are reported and default to skip, every entity writes in its own
savepoint with one audit row, and a re-run is a no-op. No ``wake_publishing``:
this seeds IPAM rows only and touches no DNS / DHCP agent bundle.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any, Literal

import structlog
from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field, StringConstraints, model_validator

from app.api.deps import DB, SuperAdmin
from app.api.pre_body_auth import PreBodyAuthRoute
from app.api.v1.netbox_import.router import (
    CommitOut,
    ConflictDecision,
    PreviewOut,
    _commit_result_to_pydantic,
    _preview_from_pydantic,
    _preview_to_pydantic,
)
from app.core.ssrf import assert_safe_target
from app.services.api_token_scopes import token_write
from app.services.netbox_import import commit_import
from app.services.netbox_import.canonical import ConflictAction
from app.services.phpipam_import import (
    PhpipamClient,
    PhpipamClientError,
    preview_phpipam_import,
)

logger = structlog.get_logger(__name__)
# Every body route checks the login from the request headers before the body is
# read (app.api.pre_body_auth); the preview sent back to commit carries the
# /ipam/import/ body allowance (app.core.body_limit).
router = APIRouter(route_class=PreBodyAuthRoute)

# Printable ASCII only: the URL and the ``token`` header are ASCII on the wire,
# and a non-ASCII value crashed the outbound client as a 500 (see NetboxConnIn).
_Ascii = Annotated[str, StringConstraints(pattern=r"^[\x20-\x7e]*$")]


class PhpipamConnIn(BaseModel):
    """Connection fields shared by test-connection + preview.

    Authenticate with either the API application's code (``token``, the
    "SSL with app code token" security mode) or a ``username`` + ``password``
    (exchanged once for a session token). All of it is read-once.
    """

    base_url: _Ascii = Field(description="phpIPAM base URL, e.g. https://ipam.example.com")
    app_id: str = Field(
        description="The API application id (Administration -> API).",
        pattern=r"^[A-Za-z0-9_.-]{1,64}$",
    )
    token: _Ascii | None = Field(
        default=None, description="The API application's app code (read-once; never persisted)."
    )
    username: _Ascii | None = None
    password: _Ascii | None = Field(default=None, description="Read-once; never persisted.")
    verify_tls: bool = True

    @model_validator(mode="after")
    def _one_credential(self) -> PhpipamConnIn:
        if not self.token and not (self.username and self.password):
            raise ValueError("provide an app-code token, or a username and password")
        return self


class PhpipamPreviewFilters(BaseModel):
    """Optional scope slice, so a large phpIPAM can be imported in parts."""

    section_ids: list[int] | None = Field(default=None, max_length=1000)
    family: Literal[4, 6] | None = None
    within_include: str | None = Field(default=None, max_length=64)


class PhpipamPreviewIn(PhpipamConnIn):
    """Body for ``POST /ipam/import/phpipam/preview``."""

    space_strategy: Literal["per_section", "single"] = "per_section"
    # Required when space_strategy='single' -- the IP space everything collapses into.
    target_space_id: uuid.UUID | None = None
    filters: PhpipamPreviewFilters | None = None


class PhpipamCommitIn(BaseModel):
    """Body for ``POST /ipam/import/phpipam/commit``.

    ``plan`` is the unmodified ``PreviewOut`` the preview returned;
    ``conflict_actions`` is keyed by each ``EntityConflict.key`` (untouched
    conflicts skip).
    """

    plan: PreviewOut
    conflict_actions: dict[str, ConflictDecision] = Field(default_factory=dict)
    space_strategy: Literal["per_section", "single"] = "per_section"
    target_space_id: uuid.UUID | None = None
    default_router_name: str = Field(default="Imported VLANs (phpIPAM)", max_length=255)


class PhpipamTestOut(BaseModel):
    ok: bool
    counts: dict[str, int]


_UPSTREAM_502: dict[int | str, dict[str, Any]] = {
    502: {"description": "The remote import source is unreachable or refused the pull"}
}


def _client(body: PhpipamConnIn) -> PhpipamClient:
    return PhpipamClient(
        base_url=body.base_url,
        app_id=body.app_id,
        token=body.token,
        username=body.username,
        password=body.password,
        verify_tls=body.verify_tls,
    )


@router.post("/test-connection", response_model=PhpipamTestOut, responses=_UPSTREAM_502)
@token_write("Connects to a phpIPAM instance with a caller-supplied credential (outbound)")
async def phpipam_test_connection(
    _: SuperAdmin,
    body: PhpipamConnIn = Body(...),
) -> PhpipamTestOut:
    """Authenticate to a phpIPAM install and report its scale before a pull."""
    # SECURITY: advisory SSRF guard -- logs the resolved address; a co-located /
    # LAN phpIPAM is a legitimate migration source, so it is not hard-blocked.
    assert_safe_target(body.base_url, label="phpipam_import")
    try:
        async with _client(body) as ipam:
            counts = {
                "sections": len(await ipam.get_list("/sections/")),
                "vrfs": len(await ipam.get_list("/vrf/")),
                "vlans": len(await ipam.get_list("/vlan/")),
            }
    except PhpipamClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    logger.info(
        "phpipam_import.test_connection", endpoint=body.base_url, tls_verify=body.verify_tls
    )
    return PhpipamTestOut(ok=True, counts=counts)


@router.post("/preview", response_model=PreviewOut, responses=_UPSTREAM_502)
@token_write("Live pull from a phpIPAM instance with a caller-supplied credential (outbound)")
async def phpipam_preview(
    current_user: SuperAdmin,
    db: DB,
    body: PhpipamPreviewIn = Body(...),
) -> PreviewOut:
    """Live-pull a phpIPAM install and return the would-create plan.

    Side-effect-free: no DB writes, no audit row. Re-run as often as needed
    while iterating on the strategy / filters; only commit writes.
    """
    assert_safe_target(body.base_url, label="phpipam_import")
    filters = body.filters.model_dump() if body.filters else None
    try:
        preview = await preview_phpipam_import(
            db,
            base_url=body.base_url,
            app_id=body.app_id,
            token=body.token,
            username=body.username,
            password=body.password,
            verify_tls=body.verify_tls,
            space_strategy=body.space_strategy,
            target_space_id=body.target_space_id,
            filters=filters,
        )
    except PhpipamClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    logger.info(
        "phpipam_import.preview_endpoint",
        endpoint=body.base_url,
        space_strategy=body.space_strategy,
        subnets=len(preview.subnets),
        addresses=len(preview.addresses),
        conflicts=len(preview.conflicts),
        warnings=len(preview.warnings),
        user=current_user.display_name,
    )
    return _preview_to_pydantic(preview)


@router.post("/commit", response_model=CommitOut)
@token_write("Creates IPAM rows (spaces, blocks, subnets, addresses, VRFs, VLANs, custom fields)")
async def phpipam_commit(
    current_user: SuperAdmin,
    db: DB,
    body: PhpipamCommitIn = Body(...),
) -> CommitOut:
    """Apply a previously previewed phpIPAM import.

    Conflicts are re-detected against current state (the previewed ones are
    advisory); each entity writes in its own savepoint with one audit row. A
    bad ``target_space_id`` (missing, or in the Trash) aborts before any row
    (422); per-row failures land as ``failed`` ledger rows.
    """
    if body.plan.source != "phpipam":
        raise HTTPException(
            status_code=400,
            detail=f"Plan source mismatch: endpoint=phpipam plan={body.plan.source}",
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
        "phpipam_import.commit_endpoint",
        space_strategy=body.space_strategy,
        total_created=result.total_created,
        total_overwrote=result.total_overwrote,
        total_skipped=result.total_skipped,
        total_failed=result.total_failed,
        user=actor_name,
    )
    return _commit_result_to_pydantic(result)

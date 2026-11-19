"""Admin CRUD for LLM providers (issue #90 — Operator Copilot Wave 1).

Mirrors ``app.api.v1.auth_providers.router``: secrets are stored
Fernet-encrypted via ``app.core.crypto`` and never returned to the
client (a ``has_api_key`` boolean is surfaced instead). A PUT that
omits ``api_key`` leaves the stored ciphertext untouched; passing
``api_key: ""`` clears it.

All routes require superadmin in Wave 1. A future wave can introduce
a ``manage_ai`` permission seeded into a non-Superadmin builtin role.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import DB, SuperAdmin
from app.api.v1.dhcp._audit import write_audit
from app.core.crypto import encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.stored_secret_guard import require_secret_with_destination_change
from app.drivers.llm import get_driver
from app.drivers.llm.registry import known_kinds
from app.models.ai import AI_PROVIDER_KINDS, AIProvider
from app.services.ai.chat import _STATIC_SYSTEM_PROMPT
from app.services.ai.tools import REGISTRY
from app.services.api_token_scopes import token_outbound

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────


class ProviderCreate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str = Field(min_length=1, max_length=255)
    kind: str
    base_url: str = ""
    # ``None`` means \"no API key supplied\" (cleared). Non-empty
    # encrypts on save. Empty string explicitly clears.
    api_key: str | None = None
    default_model: str = ""
    is_enabled: bool = False
    priority: int = 100
    options: dict[str, Any] = Field(default_factory=dict)
    # Optional Operator Copilot system-prompt override for sessions
    # that pick this provider. NULL/empty → baked-in default.
    system_prompt_override: str | None = None
    # NULL = all tools enabled (default). Empty list = no tools.
    # Non-empty list = exactly those tool names.
    enabled_tools: list[str] | None = None

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in AI_PROVIDER_KINDS:
            raise ValueError(f"kind must be one of: {', '.join(sorted(AI_PROVIDER_KINDS))}")
        if v not in known_kinds():
            raise ValueError(
                f"kind {v!r} has no driver registered. "
                f"Wave 1 ships only: {', '.join(known_kinds())}"
            )
        return v


class ProviderUpdate(BaseModel):
    model_config = {"extra": "ignore"}

    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: str | None = None
    # None → leave key untouched. ``""`` → clear. Non-empty → replace.
    api_key: str | None = None
    default_model: str | None = None
    is_enabled: bool | None = None
    priority: int | None = None
    options: dict[str, Any] | None = None
    # None → leave override unchanged. ``""`` → clear (revert to
    # default). Non-empty → replace.
    system_prompt_override: str | None = None
    # ``model_config={"extra":"ignore"}`` plus a sentinel: when the
    # client wants to set this back to NULL ("revert to all enabled"),
    # they explicitly send ``enabled_tools: null``. Pydantic
    # ``exclude_unset`` distinguishes "absent → leave unchanged" from
    # "explicit null → clear column".
    enabled_tools: list[str] | None = None


class ProviderResponse(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    base_url: str
    has_api_key: bool
    default_model: str
    is_enabled: bool
    priority: int
    options: dict[str, Any]
    system_prompt_override: str | None
    enabled_tools: list[str] | None
    created_at: datetime
    modified_at: datetime


class DefaultSystemPromptResponse(BaseModel):
    prompt: str


class ToolCatalogEntry(BaseModel):
    name: str
    description: str
    category: str
    writes: bool


class ToolCatalogResponse(BaseModel):
    tools: list[ToolCatalogEntry]


class TestConnectionRequest(BaseModel):
    """Body for the unsaved-test-connection endpoint. Mirrors the
    ``ProviderCreate`` shape minus the id-affecting fields.
    """

    kind: str
    base_url: str = ""
    api_key: str | None = None
    default_model: str = ""
    options: dict[str, Any] = Field(default_factory=dict)


class TestConnectionResponse(BaseModel):
    ok: bool
    detail: str
    latency_ms: int | None
    sample_models: list[str]


class ListModelsResponse(BaseModel):
    models: list[dict[str, Any]]


# ── Helpers ──────────────────────────────────────────────────────────────


def _to_response(p: AIProvider) -> ProviderResponse:
    return ProviderResponse(
        id=p.id,
        name=p.name,
        kind=p.kind,
        base_url=p.base_url,
        has_api_key=p.api_key_encrypted is not None,
        default_model=p.default_model,
        is_enabled=p.is_enabled,
        priority=p.priority,
        options=p.options or {},
        system_prompt_override=p.system_prompt_override,
        enabled_tools=p.enabled_tools,
        created_at=p.created_at,
        modified_at=p.modified_at,
    )


class _EphemeralProvider:
    """Stand-in for an :class:`AIProvider` row used by the unsaved
    test-connection endpoint — lets us instantiate a driver without
    persisting the config first.
    """

    def __init__(
        self,
        kind: str,
        base_url: str,
        api_key: str | None,
        options: dict[str, Any],
    ) -> None:
        self.kind = kind
        self.base_url = base_url
        # The driver decrypts via ``decrypt_str``; mimic the same
        # encrypted-bytes shape so it works without code branches.
        self.api_key_encrypted = encrypt_str(api_key) if api_key else None
        self.options = options or {}


# ── Endpoints ────────────────────────────────────────────────────────────


@router.get("/providers", response_model=list[ProviderResponse])
async def list_providers(current_user: SuperAdmin, db: DB) -> list[ProviderResponse]:
    rows = (
        (
            await db.execute(
                select(AIProvider).order_by(AIProvider.priority.asc(), AIProvider.name.asc())
            )
        )
        .scalars()
        .all()
    )
    return [_to_response(p) for p in rows]


@router.post(
    "/providers",
    response_model=ProviderResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider(
    body: ProviderCreate, current_user: SuperAdmin, db: DB
) -> ProviderResponse:
    forbid_in_demo_mode("AI provider creation is disabled")
    row = AIProvider(
        name=body.name,
        kind=body.kind,
        base_url=body.base_url,
        api_key_encrypted=encrypt_str(body.api_key) if body.api_key else None,
        default_model=body.default_model,
        is_enabled=body.is_enabled,
        priority=body.priority,
        options=body.options,
        # Empty string treated as "no override" so the UI's clear
        # button can post "" without our ORM holding empty text.
        system_prompt_override=(
            body.system_prompt_override if body.system_prompt_override else None
        ),
        enabled_tools=body.enabled_tools,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"AI provider name {body.name!r} already exists.",
        ) from exc
    write_audit(
        db,
        user=current_user,
        action="create",
        resource_type="ai_provider",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={
            **body.model_dump(mode="json", exclude={"api_key"}),
            "has_api_key": body.api_key is not None and body.api_key != "",
        },
    )
    await db.commit()
    await db.refresh(row)
    logger.info("ai_provider_created", provider_id=str(row.id), kind=row.kind)
    return _to_response(row)


@router.get(
    "/providers/tools",
    response_model=ToolCatalogResponse,
)
async def get_tool_catalog(current_user: SuperAdmin) -> ToolCatalogResponse:
    """Return every registered Operator Copilot tool with its name,
    description, category, and writes flag.

    Used by the AI Provider modal's Tools tab to render the
    category-grouped checkbox list. Read-only — does not depend on
    DB state, so it stays useful for "preview the registry"
    workflows independent of any saved provider.

    Registered ahead of ``GET /providers/{provider_id}`` for the
    same reason as default-system-prompt — Starlette matches by
    path template.
    """
    return ToolCatalogResponse(
        tools=[
            ToolCatalogEntry(
                name=t.name,
                description=t.description,
                category=t.category,
                writes=t.writes,
            )
            for t in sorted(REGISTRY.all(), key=lambda x: (x.category, x.name))
        ]
    )


@router.get(
    "/providers/default-system-prompt",
    response_model=DefaultSystemPromptResponse,
)
async def get_default_system_prompt(current_user: SuperAdmin) -> DefaultSystemPromptResponse:
    """Return the baked-in Operator Copilot system prompt.

    The provider edit modal shows this read-only so the operator can
    see what they're overriding, copy it, and paste it back as a
    starting point for their own override.

    Registered ahead of ``GET /providers/{provider_id}`` because
    Starlette matches by path template, not type — a typed-UUID
    route declared first would swallow the literal.
    """
    return DefaultSystemPromptResponse(prompt=_STATIC_SYSTEM_PROMPT)


@router.get("/providers/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: uuid.UUID, current_user: SuperAdmin, db: DB
) -> ProviderResponse:
    row = await db.get(AIProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return _to_response(row)


@router.put("/providers/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: uuid.UUID,
    body: ProviderUpdate,
    current_user: SuperAdmin,
    db: DB,
) -> ProviderResponse:
    row = await db.get(AIProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    changes = body.model_dump(exclude_unset=True)
    require_secret_with_destination_change(
        row,
        changes,
        destination=("base_url",),
        secrets={"api_key": row.api_key_encrypted},
    )
    for k, v in changes.items():
        if k == "api_key":
            # None already excluded by exclude_unset; "" clears, anything else replaces.
            if v == "":
                row.api_key_encrypted = None
            else:
                row.api_key_encrypted = encrypt_str(v)
        elif k == "system_prompt_override":
            # Same convention as api_key — empty string clears the
            # override (= revert to default); a non-empty string
            # replaces it.
            row.system_prompt_override = v if v else None
        elif k == "enabled_tools":
            # ``exclude_unset`` distinguishes "absent" from "explicit
            # null" — explicit null lands here as ``v is None`` and
            # clears the column (revert to "all enabled").
            row.enabled_tools = v
        else:
            setattr(row, k, v)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="name conflict") from exc
    write_audit(
        db,
        user=current_user,
        action="update",
        resource_type="ai_provider",
        resource_id=str(row.id),
        resource_display=row.name,
        new_value={k: ("***" if k == "api_key" else v) for k, v in changes.items()},
    )
    await db.commit()
    await db.refresh(row)
    return _to_response(row)


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_provider(provider_id: uuid.UUID, current_user: SuperAdmin, db: DB) -> None:
    row = await db.get(AIProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    write_audit(
        db,
        user=current_user,
        action="delete",
        resource_type="ai_provider",
        resource_id=str(row.id),
        resource_display=row.name,
    )
    await db.delete(row)
    await db.commit()


@router.post(
    "/providers/test",
    response_model=TestConnectionResponse,
)
async def test_unsaved_provider(
    body: TestConnectionRequest, current_user: SuperAdmin
) -> TestConnectionResponse:
    """Probe a provider before persisting — lets the operator check
    config from the create modal.
    """
    if body.kind not in known_kinds():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"kind must be one of: {', '.join(known_kinds())}",
        )
    fake = _EphemeralProvider(
        kind=body.kind,
        base_url=body.base_url,
        api_key=body.api_key,
        options=body.options,
    )
    driver = get_driver(fake)
    # Run the probe with a hard cap — providers may hang on bad URLs.
    try:
        result = await asyncio.wait_for(driver.test_connection(), timeout=30.0)
    except TimeoutError:
        return TestConnectionResponse(
            ok=False,
            detail="probe timed out after 30s",
            latency_ms=30000,
            sample_models=[],
        )
    return TestConnectionResponse(
        ok=result.ok,
        detail=result.detail,
        latency_ms=result.latency_ms,
        sample_models=list(result.sample_models),
    )


@router.post(
    "/providers/{provider_id}/test",
    response_model=TestConnectionResponse,
)
async def test_saved_provider(
    provider_id: uuid.UUID, current_user: SuperAdmin, db: DB
) -> TestConnectionResponse:
    row = await db.get(AIProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    driver = get_driver(row)
    try:
        result = await asyncio.wait_for(driver.test_connection(), timeout=30.0)
    except TimeoutError:
        return TestConnectionResponse(
            ok=False,
            detail="probe timed out after 30s",
            latency_ms=30000,
            sample_models=[],
        )
    return TestConnectionResponse(
        ok=result.ok,
        detail=result.detail,
        latency_ms=result.latency_ms,
        sample_models=list(result.sample_models),
    )


@router.get(
    "/providers/{provider_id}/models",
    response_model=ListModelsResponse,
)
@token_outbound
async def list_models(
    provider_id: uuid.UUID, current_user: SuperAdmin, db: DB
) -> ListModelsResponse:
    """Return the full model list for the provider — used by the
    UI's model picker, which needs more than the 10-sample limit
    of the test-connection response.
    """
    row = await db.get(AIProvider, provider_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    driver = get_driver(row)
    try:
        models = await asyncio.wait_for(driver.list_models(), timeout=30.0)
    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="provider did not respond within 30s",
        ) from None
    return ListModelsResponse(
        models=[
            {"id": m.id, "owned_by": m.owned_by, "context_window": m.context_window} for m in models
        ]
    )

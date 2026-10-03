"""Operator Copilot chat surface (issue #90 Wave 3).

Three surfaces:

* ``/available`` — whether a new chat would find an enabled provider,
  for any signed-in user (#1345).
* ``/sessions`` — session CRUD (list user's sessions, get one with
  history, rename, archive).
* ``/chat`` — POST a user message, receive an SSE stream with
  assistant content + tool-call cards interleaved.

Auth: ``CurrentUser`` — both session JWT and API token paths work.
The chat session is owned by the calling user.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, select

from app.api.deps import DB, CurrentUser
from app.core.responses import EventStreamResponse
from app.models.ai import (
    AIChatMessage,
    AIChatSession,
    AIProvider,
)
from app.services.ai.chat import ChatOrchestrator
from app.services.ai.usage import UsageCapExceeded, check_user_caps

logger = structlog.get_logger(__name__)
router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────


class ChatTurnRequest(BaseModel):
    """Body of POST /chat. ``session_id=None`` starts a fresh
    session (uses the highest-priority enabled provider unless
    ``provider_id`` overrides). Subsequent turns reuse the session.
    """

    message: str = Field(min_length=1, max_length=8000)
    session_id: uuid.UUID | None = None
    # Optional overrides for new sessions only — ignored once a
    # session is locked in.
    provider_id: uuid.UUID | None = None
    model: str | None = None
    # Operator-supplied context that pre-seeds the system prompt for
    # *new* sessions. Used by the "Ask AI about this" affordances —
    # right-click a subnet / IP / DNS record and the frontend bundles
    # a human-readable summary here so the model knows what the
    # operator is looking at without them having to restate it. Length-
    # capped to avoid ballooning the system prompt; ignored on existing
    # sessions (the snapshot already includes any prior context).
    initial_context: str | None = Field(default=None, max_length=4000)


class SessionSummary(BaseModel):
    id: uuid.UUID
    name: str
    provider_id: uuid.UUID | None
    model: str
    archived_at: datetime | None
    created_at: datetime
    modified_at: datetime
    message_count: int


class MessageRead(BaseModel):
    id: uuid.UUID
    role: str
    content: str
    tool_calls: list[dict[str, Any]] | None
    tool_call_id: str | None
    name: str | None
    tokens_in: int | None
    tokens_out: int | None
    latency_ms: int | None
    created_at: datetime


class SessionDetail(BaseModel):
    id: uuid.UUID
    name: str
    provider_id: uuid.UUID | None
    model: str
    system_prompt: str
    archived_at: datetime | None
    created_at: datetime
    modified_at: datetime
    messages: list[MessageRead]


class SessionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    archived: bool | None = None


class CopilotAvailability(BaseModel):
    """Whether a new chat would find a provider to talk to (#1345)."""

    available: bool


# ── Helpers ──────────────────────────────────────────────────────────────


async def _get_default_provider(db: Any) -> AIProvider | None:
    """Pick the lowest-priority enabled AI provider — same selection
    rule as auth providers' priority chain.
    """
    return await db.scalar(
        select(AIProvider)
        .where(AIProvider.is_enabled.is_(True))
        .order_by(AIProvider.priority.asc())
        .limit(1)
    )


async def _session_message_count(db: Any, session_id: uuid.UUID) -> int:
    from sqlalchemy import func

    return int(
        await db.scalar(
            select(func.count(AIChatMessage.id)).where(AIChatMessage.session_id == session_id)
        )
        or 0
    )


# ── Availability ─────────────────────────────────────────────────────────


@router.get("/available", response_model=CopilotAvailability)
async def copilot_available(current_user: CurrentUser, db: DB) -> CopilotAvailability:
    """Whether the Operator Copilot has an enabled provider to chat with.

    The console asks this on every page to decide whether to offer "Ask AI"
    (#1345). It used to read ``GET /providers`` for it, which is
    superadmin-only, so every other user's page raised a 403 and the console
    read the refusal as "available". Any signed-in user may chat, so any
    signed-in user may ask. The answer is the lookup a new chat makes
    (``_get_default_provider``) as a bare yes or no, naming no provider.
    """
    return CopilotAvailability(available=await _get_default_provider(db) is not None)


# ── Sessions CRUD ────────────────────────────────────────────────────────


@router.get("/sessions", response_model=list[SessionSummary])
async def list_sessions(
    current_user: CurrentUser, db: DB, include_archived: bool = False
) -> list[SessionSummary]:
    stmt = select(AIChatSession).where(AIChatSession.user_id == current_user.id)
    if not include_archived:
        stmt = stmt.where(AIChatSession.archived_at.is_(None))
    stmt = stmt.order_by(desc(AIChatSession.modified_at))
    rows = (await db.execute(stmt)).scalars().all()
    out: list[SessionSummary] = []
    for s in rows:
        out.append(
            SessionSummary(
                id=s.id,
                name=s.name,
                provider_id=s.provider_id,
                model=s.model,
                archived_at=s.archived_at,
                created_at=s.created_at,
                modified_at=s.modified_at,
                message_count=await _session_message_count(db, s.id),
            )
        )
    return out


@router.get("/sessions/{session_id}", response_model=SessionDetail)
async def get_session(session_id: uuid.UUID, current_user: CurrentUser, db: DB) -> SessionDetail:
    s = await db.get(AIChatSession, session_id)
    if s is None or s.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    msg_rows = (
        (
            await db.execute(
                select(AIChatMessage)
                .where(AIChatMessage.session_id == s.id)
                .order_by(AIChatMessage.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return SessionDetail(
        id=s.id,
        name=s.name,
        provider_id=s.provider_id,
        model=s.model,
        system_prompt=s.system_prompt,
        archived_at=s.archived_at,
        created_at=s.created_at,
        modified_at=s.modified_at,
        messages=[
            MessageRead(
                id=m.id,
                role=m.role,
                content=m.content,
                tool_calls=m.tool_calls,
                tool_call_id=m.tool_call_id,
                name=m.name,
                tokens_in=m.tokens_in,
                tokens_out=m.tokens_out,
                latency_ms=m.latency_ms,
                created_at=m.created_at,
            )
            for m in msg_rows
        ],
    )


@router.put("/sessions/{session_id}", response_model=SessionSummary)
async def update_session(
    session_id: uuid.UUID,
    body: SessionUpdate,
    current_user: CurrentUser,
    db: DB,
) -> SessionSummary:
    s = await db.get(AIChatSession, session_id)
    if s is None or s.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if body.name is not None:
        s.name = body.name
    if body.archived is True and s.archived_at is None:
        s.archived_at = datetime.now(UTC)
    if body.archived is False:
        s.archived_at = None
    await db.commit()
    await db.refresh(s)
    return SessionSummary(
        id=s.id,
        name=s.name,
        provider_id=s.provider_id,
        model=s.model,
        archived_at=s.archived_at,
        created_at=s.created_at,
        modified_at=s.modified_at,
        message_count=await _session_message_count(db, s.id),
    )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_session(session_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    s = await db.get(AIChatSession, session_id)
    if s is None or s.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    await db.delete(s)
    await db.commit()


# ── Chat (streaming) ─────────────────────────────────────────────────────


def _sse_frame(event_kind: str, data: dict[str, Any]) -> bytes:
    """Render one SSE frame. Each event has a typed name + JSON
    payload. The browser's ``EventSource`` API parses these natively.
    """
    payload = json.dumps(data, default=str)
    return f"event: {event_kind}\ndata: {payload}\n\n".encode()


@router.post(
    "/chat",
    # ``response_class`` REPLACES the documented application/json (#921);
    # a ``responses={200: {"content": ...}}`` entry merges with it instead,
    # leaving the route declaring a JSON body it never produces.
    response_class=EventStreamResponse,
    responses={200: {"description": "Server-sent event stream of the assistant's reply"}},
)
async def chat(body: ChatTurnRequest, current_user: CurrentUser, db: DB) -> StreamingResponse:
    """Stream one turn of the chat conversation back as SSE events.

    Frontend opens an ``EventSource`` (or fetch with ``ReadableStream``)
    and renders events incrementally:

        session         { session_id, name }
        content         { delta: "..." }       ← stream tokens
        tool_call       { id, name, arguments }← model wants to call X
        tool_result     { id, preview, is_error }
        done            { finish_reason, tokens_in, tokens_out }
        error           { message }
    """
    # Resolve provider for new sessions. Existing sessions snapshotted
    # their provider at creation time — we reuse that.
    if body.session_id is None:
        if body.provider_id is not None:
            provider = await db.get(AIProvider, body.provider_id)
            if provider is None or not provider.is_enabled:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="provider not found or not enabled",
                )
        else:
            provider = await _get_default_provider(db)
            if provider is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "no enabled AI provider configured — visit "
                        "/admin/ai/providers to set one up"
                    ),
                )
        model = body.model or provider.default_model
        if not model:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "no model — set a default_model on the provider "
                    "or pass `model` in the request body"
                ),
            )
    else:
        existing = await db.get(AIChatSession, body.session_id)
        if existing is None or existing.user_id != current_user.id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")
        if existing.provider_id is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="session's provider has been deleted — start a new chat",
            )
        provider = await db.get(AIProvider, existing.provider_id)
        if provider is None or not provider.is_enabled:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="session's provider is disabled — start a new chat",
            )
        model = existing.model

    # Cap enforcement (Wave 4). Cheap aggregate query against today's
    # ai_chat_message rows for this user. No-op when neither cap is
    # configured in PlatformSettings.
    try:
        await check_user_caps(db, current_user)
    except UsageCapExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc

    orchestrator = ChatOrchestrator(db, current_user)
    session_row = await orchestrator.get_or_create_session(
        session_id=str(body.session_id) if body.session_id else None,
        provider=provider,
        model=model,
        initial_context=body.initial_context,
    )

    async def _stream():
        try:
            async for event in orchestrator.stream_turn(
                session=session_row, user_text=body.message
            ):
                yield _sse_frame(event.kind, event.data)
        except Exception:  # noqa: BLE001
            # Log full exception server-side; surface a generic message
            # to the client so the SSE stream doesn't leak stack-trace
            # info (file paths, SQL fragments from IntegrityError-style
            # exceptions, etc). The server-side log is the source of
            # truth for triage. CodeQL py/stack-trace-exposure (#22).
            logger.exception("ai_chat_stream_error", session_id=str(session_row.id))
            yield _sse_frame(
                "error",
                {"message": "Chat stream failed — see server logs for details."},
            )

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # X-Accel-Buffering disables nginx response buffering so
            # SSE frames flush immediately when the frontend nginx
            # proxies them through.
            "X-Accel-Buffering": "no",
        },
    )

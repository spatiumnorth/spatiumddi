"""LLM provider configuration (issue #90 — Operator Copilot).

Mirrors ``app.models.auth_provider.AuthProvider`` — same priority +
is_enabled + JSONB-config + Fernet-encrypted-secret pattern.

The ``kind`` discriminator carries the driver name. Concrete drivers
live under ``app/drivers/llm/`` and are looked up via the registry
(``get_driver(kind)`` mirrors how DNS / DHCP drivers are resolved).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# Driver discriminator values. Keep in sync with the CHECK constraint
# on ``ai_provider.kind`` in the migration and with the driver registry
# in ``app/drivers/llm/registry.py``.
AI_PROVIDER_KINDS: tuple[str, ...] = (
    "openai_compat",
    "anthropic",
    "google",
    "azure_openai",
)


class AIProvider(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Operator-configured LLM provider.

    The OpenAI-compat driver covers ~90% of the ecosystem in one row
    type — point ``base_url`` at OpenAI, Ollama, OpenWebUI, vLLM, LM
    Studio, llama.cpp's server, LocalAI, Together, Groq, or Fireworks
    and the same driver speaks to all of them.
    """

    __tablename__ = "ai_provider"
    __table_args__ = (UniqueConstraint("name", name="uq_ai_provider_name"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # openai_compat | anthropic | google | azure_openai
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # The endpoint base URL. Empty string for providers whose SDK has a
    # canonical default (Anthropic, Gemini); explicit for OpenAI-compat
    # since the whole point is pointing it at non-OpenAI hosts.
    base_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    # Fernet-encrypted API key. Nullable because some local providers
    # (Ollama on localhost) don't require auth.
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # The preferred model for this provider — used as the default when
    # a chat request doesn't specify one. ``list_models()`` populates
    # the picker in the UI.
    default_model: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Lower = higher priority. Mirrors ``auth_provider.priority``.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # Free-form per-provider tuning that doesn't warrant its own column:
    # temperature, max_tokens, top_p, top_k, request_timeout_seconds,
    # streaming-options overrides, etc. Drivers consume what they
    # recognize and ignore the rest.
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Optional per-provider override of the baked-in Operator Copilot
    # system prompt. NULL → use the default from
    # ``app.services.ai.chat._STATIC_SYSTEM_PROMPT``. Empty string is
    # treated the same as NULL so the UI's "clear" button doesn't have
    # to delete-then-recreate the row. The override only applies to
    # *new* sessions — existing sessions snapshot the prompt at
    # creation time on ``AIChatSession.system_prompt``.
    system_prompt_override: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Optional per-provider tool allowlist. NULL → all registered
    # tools enabled (default for new + existing rows). Empty list ``[]``
    # = no tools at all (rare; useful for chat-only providers). Non-empty
    # list = exactly these tools. Names that no longer match a
    # registered tool are silently skipped at request-build time so the
    # provider doesn't blow up after a tool rename — the admin sees the
    # stale entry in the modal and can clear it.
    enabled_tools: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    # The operator's statement that this endpoint runs on infrastructure
    # they control (Ollama, vLLM, LM Studio ... on their own hosts), so
    # what is sent to it does not leave their network. Copilot Watch
    # (#4405) sends install data with nobody watching and, by default,
    # uses only providers that carry this mark. The chat ignores it. Only
    # an ``openai_compat`` provider can be marked: the other kinds are
    # hosted services by definition. Cleared when ``base_url`` changes,
    # since the statement was about the old endpoint.
    is_on_prem: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )


CHAT_ROLES: tuple[str, ...] = ("system", "user", "assistant", "tool")


class AIChatSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One Operator Copilot conversation. Messages live on
    :class:`AIChatMessage` linked by ``session_id``.

    Provider + model + system prompt are *snapshotted* on the session
    so a later edit of the global config doesn't retroactively change
    how this conversation was answered.
    """

    __tablename__ = "ai_chat_session"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="Untitled")
    provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_provider.id", ondelete="SET NULL"),
        nullable=True,
    )
    model: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    system_prompt: Mapped[str] = mapped_column(Text, nullable=False, default="")
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AIChatMessage(UUIDPrimaryKeyMixin, Base):
    """One message in an :class:`AIChatSession`. Append-only — operators
    edit by starting a new session, not by mutating history.

    ``role`` mirrors the OpenAI chat schema. ``tool_calls`` is set on
    assistant messages that requested tool execution; the response
    arrives as one or more ``role=tool`` messages whose
    ``tool_call_id`` matches.
    """

    __tablename__ = "ai_chat_message"

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_chat_session.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Shape: [{"id": str, "name": str, "arguments": str-as-json}, ...]
    tool_calls: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)
    tool_call_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Per-message observability — populated when this message comes from
    # the LLM. ``cost_usd`` is computed at write time via the rate sheet
    # in ``app.services.ai.pricing``; None when the model is unknown to
    # the rate sheet (local Ollama, custom-hosted, etc.).
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(12, 6), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )


class AIPrompt(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A reusable prompt the operator can load into the chat drawer.

    Two visibility modes (selected via ``is_shared``):

    * **Shared** — visible to every user with chat access. Curated by
      superadmins so triage runbooks ("audit trail review",
      "identify orphan IPs in /24") are one click away for everyone.
      Names must be globally unique across shared rows.
    * **Private** — visible only to ``created_by_user_id``. Lets a
      power user keep half-finished or personal prompts without
      polluting the shared list. Names must be unique per-user.

    Both modes live in the same row type to keep the picker query
    simple — one ``WHERE is_shared OR created_by = me`` predicate.
    """

    __tablename__ = "ai_prompt"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    prompt_text: Mapped[str] = mapped_column(Text, nullable=False)
    is_shared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )


class AIOperationProposal(UUIDPrimaryKeyMixin, Base):
    """Pending Copilot write operation awaiting operator confirmation.

    When the LLM fires a write tool, the orchestrator calls the
    operation's :func:`preview` instead of its :func:`apply`. The
    preview produces a human-readable description (no side effects),
    and a row of this type is persisted with the args. The chat
    surface renders the proposal as an Apply / Discard card; the
    actual mutation only runs after an explicit POST to
    ``/api/v1/ai/proposals/{id}/apply``.

    A row reaches one of three terminal states:

    * ``applied_at`` set    — operator confirmed; ``result`` carries
      the dispatch outcome.
    * ``discarded_at`` set  — operator rejected; ``error`` may carry
      a discard reason.
    * Neither, ``expires_at`` in the past — the cleanup task drops it
      on the next sweep.
    """

    __tablename__ = "ai_operation_proposal"

    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ai_chat_session.id", ondelete="CASCADE"),
        nullable=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    args: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    preview_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=datetime.utcnow
    )

"""Typed-event webhook subscriptions + outbox.

Distinct from ``AuditForwardTarget`` (which fires on every audit row in
the platform's chosen wire format). This surface emits **typed events**
shaped for downstream automation: ``subnet.created`` / ``ip.allocated``
/ ``zone.modified`` and the rest. Each event is delivered with an
HMAC-SHA256 signature so the receiver can verify authenticity, and
delivery is backed by a database outbox with exponential-backoff retry
+ dead-letter state — at-least-once semantics modulo a crash window
between audit commit and outbox write.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class EventSubscription(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One downstream webhook receiver."""

    __tablename__ = "event_subscription"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true"), index=True
    )
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Fernet-encrypted at rest. The plaintext is the HMAC key — every
    # delivery POST carries
    # ``X-SpatiumDDI-Signature: sha256=<hex(hmac(secret, ts+"."+body))>``
    # so the receiver can verify the request actually came from us
    # without trusting TLS alone. ``smtp_password_set``-style boolean
    # gate on the API response keeps the cleartext off the wire.
    secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # JSONB list of event types this subscription wants. Empty list (or
    # ``None``) = subscribe to every event type. Glob support is
    # deferred — operators wanting "all subnet events" today list
    # ``subnet.created``, ``subnet.updated``, ``subnet.deleted``
    # explicitly. Cheap to add later.
    event_types: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    # Optional custom headers (auth tokens, routing hints) merged in on
    # delivery. Keys with names colliding with the X-SpatiumDDI-* family
    # are silently overridden by the publisher. The whole dict is
    # Fernet-encrypted at rest (#1579, mirroring #1506): the values are
    # receiver credentials (``Authorization: Bearer …``), so they get the
    # same treatment as ``secret_encrypted`` above — the API takes them
    # write-only and returns header names plus a ``headers_set`` flag,
    # never the values. Serialised with ``encrypt_dict`` /
    # ``decrypt_dict`` (JSON, sorted keys), the same convention as
    # ``auth_provider.secrets_encrypted``.
    #
    # The pre-#1579 plaintext ``headers`` JSONB column is still in the
    # table, unmapped and unread, for one release, so a rolling
    # upgrade's old pods keep working (#296). The next release drops it.
    headers_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Per-subscription HTTP timeout. The default (10s) is high enough to
    # let receivers do real work but low enough that one slow consumer
    # can't starve the worker. Min 1s, max 30s — clamped server-side.
    timeout_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10, server_default=sa_text("10")
    )
    # Dead-letter threshold. After ``max_attempts`` failed deliveries
    # the outbox row flips to state=``dead``; the operator can manually
    # retry from the UI / API. Default 8 attempts ≈ ~8.5 min cumulative
    # backoff (2+4+8+16+32+64+128+256s).
    max_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=8, server_default=sa_text("8")
    )

    outbox_rows: Mapped[list[EventOutbox]] = relationship(
        "EventOutbox",
        back_populates="subscription",
        cascade="all, delete-orphan",
    )


class EventOutbox(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One pending / in-flight / delivered / failed / dead delivery."""

    __tablename__ = "event_outbox"

    subscription_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("event_subscription.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # The full event payload (matches the body the receiver sees).
    # Includes the ``event_id`` (= this row's id, as string) so a
    # receiver dedupes across retries.
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # state: pending | in_flight | delivered | failed | dead
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default=sa_text("'pending'")
    )
    attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=sa_text("now()"),
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    subscription: Mapped[EventSubscription] = relationship(
        "EventSubscription",
        back_populates="outbox_rows",
    )

    __table_args__ = (
        Index(
            "ix_event_outbox_due",
            "state",
            "next_attempt_at",
            postgresql_where=sa_text("state IN ('pending', 'failed')"),
        ),
        Index("ix_event_outbox_subscription_id", "subscription_id"),
    )


__all__ = ["EventSubscription", "EventOutbox"]

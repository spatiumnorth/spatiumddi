"""Audit-forwarding target model.

One row per delivery destination. The ``kind`` discriminator picks
which column subset matters (syslog vs webhook vs smtp); the rest stay
at their defaults. Formats are pluggable — the service layer picks the
right formatter at send time.

For ``kind="webhook"``, ``webhook_flavor`` further selects how the JSON
body is shaped: ``generic`` posts the raw audit/alert payload,
``slack``/``teams``/``discord`` wraps it in the platform's
incoming-webhook block format so chat-channel delivery works without a
separate transformer. ``telegram`` posts to the Telegram Bot API's
``sendMessage`` instead of ``url``: the bot token, chat id and optional
forum topic live in the ``telegram_*`` columns, the token Fernet-encrypted
at rest like the SMTP password.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Integer, LargeBinary, String, Text
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AuditForwardTarget(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "audit_forward_target"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    # kind: syslog | webhook | smtp
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # format: rfc5424_json | rfc5424_cef | rfc5424_leef | rfc3164 | json_lines
    # Used by syslog only; ignored for webhook + smtp (which have their
    # own platform-specific or template-based rendering).
    format: Mapped[str] = mapped_column(String(32), nullable=False, default="rfc5424_json")

    # ── syslog fields ──────────────────────────────────────────────
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=514)
    # protocol: udp | tcp | tls
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="udp")
    facility: Mapped[int] = mapped_column(Integer, nullable=False, default=16)
    # Optional PEM-encoded CA certificate for TLS verification. When NULL
    # on a TLS target, the system CA bundle is used.
    ca_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── webhook fields ─────────────────────────────────────────────
    url: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    # Plaintext today (matches existing audit_forward_webhook_auth_header on
    # platform_settings); migrating to Fernet-at-rest is a separate pass
    # tracked with the other secret-hardening work.
    auth_header: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    # webhook_flavor: generic | slack | teams | discord | telegram
    # Picks the platform-specific JSON shape at send time. ``generic`` is
    # the original behaviour (raw audit/alert payload); the others wrap
    # in Slack mrkdwn / Teams MessageCard / Discord embed format so a
    # standard incoming-webhook URL works without a transformer.
    # ``telegram`` ignores ``url`` and uses the ``telegram_*`` columns.
    webhook_flavor: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="generic",
        server_default=sa_text("'generic'"),
    )

    # ── telegram fields (webhook_flavor="telegram") ────────────────
    # The bot token is the whole credential (it goes in the Bot API URL
    # path), so it is Fernet-encrypted at rest and write-only in the API,
    # which exposes only ``telegram_bot_token_set`` — same shape as
    # ``smtp_password_encrypted``.
    telegram_bot_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # A numeric chat id (``-100…`` for a supergroup or channel) or a
    # public ``@channelusername``. Text, because both forms are valid.
    telegram_chat_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=sa_text("''")
    )
    # Forum topic to post into, for a supergroup with topics enabled.
    telegram_message_thread_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Bot API base URL. Empty means Telegram's public API; set it for a
    # self-hosted Bot API server.
    telegram_api_base: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )

    # ── smtp fields ────────────────────────────────────────────────
    # smtp_security: none | starttls | ssl
    # ``starttls`` is the default — port 587 with opportunistic upgrade,
    # which is what most modern relays expect. ``ssl`` is implicit-TLS
    # on port 465. ``none`` is plain SMTP for trusted-network relays.
    smtp_host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    smtp_port: Mapped[int] = mapped_column(Integer, nullable=False, default=587)
    smtp_security: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="starttls",
        server_default=sa_text("'starttls'"),
    )
    smtp_username: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # Fernet-encrypted at rest. The Settings API exposes only a boolean
    # ``smtp_password_set`` — same shape Fingerbank uses.
    smtp_password_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    smtp_from_address: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    # JSONB list of recipient addresses. One target = one fan-out group;
    # operators who want different recipient sets per alert severity can
    # create multiple targets and use ``min_severity`` to gate them.
    smtp_to_addresses: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    # Optional reply-to override. Helpful when ``from_address`` is a
    # no-reply mailbox but the recipient should reply to a real inbox.
    smtp_reply_to: Mapped[str] = mapped_column(String(320), nullable=False, default="")

    # ── filter ─────────────────────────────────────────────────────
    # Drop events below this severity. Accepted values: info | warn |
    # error | denied. Null = forward everything.
    min_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Optional allowlist of ``AuditLog.resource_type`` values. Null or
    # empty = forward everything.
    resource_types: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)


__all__ = ["AuditForwardTarget"]

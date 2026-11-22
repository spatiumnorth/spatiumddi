"""Audit-forwarding target model.

One row per delivery destination. The ``kind`` discriminator picks
which column subset matters (syslog vs webhook vs smtp); the rest stay
at their defaults. Formats are pluggable — the service layer picks the
right formatter at send time.

For ``kind="webhook"``, ``webhook_flavor`` further selects how the JSON
body is shaped: ``generic`` posts the raw audit/alert payload,
``slack``/``teams``/``discord`` wraps it in the platform's
incoming-webhook block format so chat-channel delivery works without a
separate transformer.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, LargeBinary, String, Text
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
    # Both Fernet-encrypted at rest (#1502): an incoming-webhook URL is the
    # credential for its channel, and the header is a collector token. The
    # API takes them write-only and returns ``url_set`` / ``url_display`` /
    # ``auth_header_set``; ``app.services.forward_secrets`` has the helpers.
    # The pre-#1502 plaintext ``url`` / ``auth_header`` columns were dropped
    # by migration ``c2b203844c95``.
    url_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    auth_header_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # webhook_flavor: generic | slack | teams | discord
    # Picks the platform-specific JSON shape at send time. ``generic`` is
    # the original behaviour (raw audit/alert payload); the others wrap
    # in Slack mrkdwn / Teams Adaptive Card / Discord embed format so a
    # standard incoming-webhook URL works without a transformer.
    webhook_flavor: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="generic",
        server_default=sa_text("'generic'"),
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

    # ── log streams (#4545) ────────────────────────────────────────
    # Per-target opt-in for the DNS query log and the DHCP activity log the
    # agents already ship to the control plane. Syslog targets only; both
    # off on every existing and every new target, because a query log is
    # high-volume and names clients.
    stream_dns_query_log: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    stream_dhcp_activity_log: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # JSONB object, keys validated by the settings API (``log_stream_forward.
    # FILTER_KEYS``): dns_server_group_ids, dns_server_ids, dns_rcodes,
    # dns_qtypes, dhcp_server_group_ids, dhcp_server_ids, dhcp_codes. Absent
    # or empty key = no filter on that dimension.
    log_stream_filters: Mapped[dict[str, list[str]] | None] = mapped_column(JSONB, nullable=True)
    # Forward this percentage (1-100) of DNS queries; 100 = all of them.
    dns_query_sample_percent: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, server_default=sa_text("100")
    )
    # Entries dropped because the target could not keep up (queue cap hit or
    # delivery kept failing). Cumulative, flushed by the api process every
    # few seconds; the ``log_forward_dropping`` alert reads the timestamp.
    log_stream_dropped_total: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=sa_text("0")
    )
    log_stream_last_drop_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


__all__ = ["AuditForwardTarget"]

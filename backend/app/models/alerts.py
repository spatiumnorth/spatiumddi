"""Alerts — rule-based notifications on metrics we already collect.

Two tables:

* ``AlertRule`` — the operator-authored definition. Each row pins a
  rule type (``subnet_utilization`` / ``server_unreachable``) plus its
  params and which delivery channels to hit on firing.

* ``AlertEvent`` — one row per firing. ``resolved_at`` is NULL while
  the underlying condition still matches; the evaluator flips it to
  the current timestamp when the condition clears. This is the
  "open vs resolved" view the UI renders and the syslog/webhook hooks
  consume.

Delivery reuses the platform-level syslog + webhook targets configured
for audit forwarding (``services/audit_forward._send_syslog`` /
``_send_webhook``). A per-rule delivery override would be nice but adds
a config surface we don't need yet — every op shop I've seen feeds
alerts into the same SIEM that audit goes to.

De-duplication: the evaluator looks for an existing *open* AlertEvent
for ``(rule_id, subject_type, subject_id)`` before opening a new one.
So a subnet hovering at 96% utilisation doesn't fire every minute —
exactly one open event until it drops back below threshold.
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
    String,
    Text,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AlertRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Operator-authored alert definition."""

    __tablename__ = "alert_rule"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # Rule type discriminator. Valid values today:
    #   "subnet_utilization"          — threshold_percent vs Subnet.utilization_percent.
    #                                    Honours PlatformSettings.utilization_max_prefix_*
    #                                    so /30, /127 etc. can't trip the alarm.
    #   "server_unreachable"          — server_type in {"dns","dhcp","any"}; fires on
    #                                    any server row whose `status` is "unreachable"
    #                                    or "error" at eval time.
    #   "domain_expiring"             — threshold_days against Domain.expires_at.
    #                                    Severity escalates: soft at threshold, warning
    #                                    at threshold/4, critical at threshold/12.
    #                                    Resolves on renewal or row delete.
    #   "domain_nameserver_drift"     — fires when Domain.nameserver_drift = true.
    #   "domain_registrar_changed"    — fires once per registrar transition.
    #                                    Auto-resolves after 7 days.
    #   "domain_dnssec_status_changed"— fires once per dnssec_signed flip.
    #                                    Auto-resolves after 7 days.
    #   "compliance_change"           — fires on audit-log mutations to
    #                                    subnets / IPs / DHCP scopes whose
    #                                    classification flag matches the
    #                                    rule's ``classification``. See
    #                                    issue #105.
    rule_type: Mapped[str] = mapped_column(String(40), nullable=False)

    # Subnet utilization params. Re-used as the occupancy-% threshold by
    # ``dhcp_pool_exhaustion`` (issue #339) and as a raw-count threshold by
    # ``voice_lease_count_below`` / ``stale_ip_count``.
    threshold_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ``dhcp_pool_exhaustion`` params (issue #339) — absolute free-address
    # floor. The rule fires when a dynamic pool's occupancy reaches
    # ``threshold_percent`` OR its free-address count drops below this; both
    # are optional so an operator can alert on either signal (or both).
    min_free_addresses: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Server-unreachable params.
    server_type: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # Domain-expiring params. Number of days before ``expires_at`` at
    # which the rule first fires. The rule's ``severity`` column drives
    # the *base* severity; the evaluator escalates based on how close
    # ``expires_at`` actually is — threshold/4 widens to "warning",
    # threshold/12 widens to "critical". Default 30 d (matches the
    # ``whois_state="expiring"`` bucket).
    threshold_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ``compliance_change`` params. ``classification`` names the column
    # on Subnet to watch (``pci_scope`` | ``hipaa_scope`` |
    # ``internet_facing``). ``change_scope`` filters which audit-log
    # actions count (``any_change`` | ``create`` | ``delete``).
    # ``last_scanned_audit_at`` is the high-water mark; the evaluator
    # only fires for audit rows whose ``timestamp`` is strictly greater.
    # NULL on a fresh rule means "never scanned" — the evaluator
    # initialises it to NOW() on its first pass so historical audit
    # rows don't retroactively page the operator.
    classification: Mapped[str | None] = mapped_column(String(30), nullable=True)
    change_scope: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_scanned_audit_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Severity (info | warning | critical). Maps to a syslog severity on
    # delivery and drives UI colour.
    severity: Mapped[str] = mapped_column(
        String(10), nullable=False, default="warning", server_default=sa_text("'warning'")
    )

    # Delivery channel toggles. Platform-level audit-forward targets are
    # reused for the actual connection — every target whose ``kind``
    # matches an enabled toggle here receives the firing event (filtered
    # by the target's own ``min_severity`` / ``resource_types`` rules).
    notify_syslog: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    notify_webhook: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    # Email channel — defaults to OFF so existing rules don't suddenly
    # spam every SMTP target the operator configures.
    notify_smtp: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    __table_args__ = (Index("ix_alert_rule_rule_type_enabled", "rule_type", "enabled"),)


class AlertEvent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One firing of an ``AlertRule`` against one subject.

    A row's lifecycle:
      * Created when the evaluator first sees the condition match for a
        subject with no existing open event → ``resolved_at`` NULL.
      * Stays open as long as the condition still matches on each eval.
      * Closed by the next eval pass that finds the condition cleared
        — the same pass never both opens and closes an event; there's
        always at least one "still-firing" tick in between.
    """

    __tablename__ = "alert_event"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alert_rule.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # What fired. `subject_type` mirrors the rule type family:
    #   "subnet"  — subject_id is a Subnet UUID, display is "<CIDR> — <name>"
    #   "server"  — subject_id is a DNS/DHCPServer UUID, display is the name
    # 40 chars accommodates the longest type today
    # (``network_service_resource`` = 25) with room for future families.
    subject_type: Mapped[str] = mapped_column(String(40), nullable=False)
    # 128: a conformity subject is "<policy>:<kind>:<target>", up to 89 (#2277).
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_display: Mapped[str] = mapped_column(String(500), nullable=False, default="")

    severity: Mapped[str] = mapped_column(String(10), nullable=False, default="warning")
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")

    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Delivery receipts. Set once by the first evaluator pass that
    # opened the event; subsequent "still firing" ticks don't re-deliver.
    delivered_syslog: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    delivered_webhook: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    delivered_smtp: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # Snapshot of the value at the time of firing. Used by transition-
    # once rules (``domain_registrar_changed``, ``domain_dnssec_status_changed``)
    # to dedupe — the evaluator only opens a new event when the
    # observed value has actually moved off the snapshot stored in the
    # most recent open event for the same subject. Shape is rule-type
    # specific:
    #   domain_registrar_changed     → {"from": "<old>", "to": "<new>"}
    #   domain_dnssec_status_changed → {"from": <bool>, "to": <bool>}
    # Other rule types may write None.
    last_observed_value: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # #2261 — set when an evaluator pass queues this event's delivery to run
    # after its commit; cleared the moment a sender claims it. Still set long
    # after the pass means the worker died between the commit and the send,
    # and ``alerts.redeliver_stranded`` sends it. NULL for every event
    # delivered inline, which the sweep ignores.
    delivery_pending_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        # #2261 — UNIQUE: at most one open event per (rule, subject). Two
        # overlapping evaluator passes used to open a pair, and only one of
        # the pair was ever resolved.
        Index(
            "ix_alert_event_rule_subject_open",
            "rule_id",
            "subject_type",
            "subject_id",
            unique=True,
            postgresql_where=sa_text("resolved_at IS NULL"),
        ),
        Index("ix_alert_event_fired_at", "fired_at"),
        Index(
            "ix_alert_event_delivery_pending",
            "delivery_pending_since",
            postgresql_where=sa_text("delivery_pending_since IS NOT NULL"),
        ),
    )

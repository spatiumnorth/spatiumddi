"""Active block-sync — SpatiumDDI-owned network-block desired state (#601).

This is the *enforcement* half of the detection→block loop. Where the
integration mirrors (OPNsense #31 / UniFi #30) pull ``source → IPAM``
read-only, this model is the deliberate, guarded exception that pushes
``decision → source``: a SpatiumDDI-owned set of blocked IPs / MACs that
a reconciler converges onto each *armed* upstream target (an OPNsense
firewall table alias, a UniFi client quarantine).

Two tables:

* ``network_block`` — the desired state. One row per blocked value
  (``kind`` = ``ip`` | ``mac``). ``enabled`` + ``expires_at`` gate
  whether the value should currently be enforced anywhere.
* ``network_block_push`` — per-(block, target) convergence state. The
  reconciler is target-driven: for each armed target it ensures every
  applicable enabled block is present on the device and every push row
  whose block is disabled / expired / deleted is removed. The row
  carries ``push_status`` + ``last_error`` so the UI can show exactly
  where each block landed.

Guardrails live one layer up (feature module ``security.block_sync``,
per-target ``block_sync_enabled`` master switch, distinct write-scoped
credentials, ``manage_block_sync`` RBAC + approval-workflow gating). The
row itself is pure intent — an out-of-band reconciler does the pushing,
mirroring the ``dhcp_mac_block`` → Kea-DROP-class shape.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# ``kind`` values — an L3 address block (OPNsense alias membership) or an
# L2 MAC quarantine (UniFi block-sta). Firewall targets consume ``ip``;
# gateway/AP targets consume ``mac``.
BLOCK_KINDS: tuple[str, ...] = ("ip", "mac")

# Where the block originated. Drives provenance + the one-click wiring
# from the new-device review queue (#459) / rogue-DHCP detection (#370).
BLOCK_SOURCES: tuple[str, ...] = ("manual", "new_device", "rogue_dhcp")

# Per-(block, target) push lifecycle.
#   pending   — queued, not yet confirmed on the device
#   pushed    — present on the device (converged)
#   removing  — block was lifted; the IP/MAC still needs removing upstream
#   error     — last push/remove attempt failed (see ``last_error``)
PUSH_STATUSES: tuple[str, ...] = ("pending", "pushed", "removing", "error")

# Target kinds a push row can point at. Loose (no cross-table FK) because the
# target is polymorphic across ``opnsense_router`` / ``unifi_controller`` /
# ``panos_firewall`` / ``meraki_org``. ``paloalto`` consumes ``ip`` blocks
# (Dynamic Address Group tag register via the User-ID API, #605); ``meraki``
# consumes ``mac`` blocks (per-client ``Blocked`` device policy via the
# Dashboard API, #606). Fortinet enforcement is NOT a push target — it polls a
# ``FirewallFeed`` URL (the "feed inversion", #606).
BLOCK_TARGET_KINDS: tuple[str, ...] = ("opnsense", "unifi", "paloalto", "meraki")


class NetworkBlock(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single blocked IP or MAC — SpatiumDDI's desired-state intent."""

    __tablename__ = "network_block"
    __table_args__ = (
        UniqueConstraint("kind", "value", name="uq_network_block_kind_value"),
        Index("ix_network_block_enabled", "enabled"),
    )

    # ``ip`` | ``mac`` — validated at the API layer against ``BLOCK_KINDS``.
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    # Normalised value: a bare IP (``10.0.0.5``) for ``kind="ip"`` or a
    # canonical lowercase colon MAC (``aa:bb:cc:dd:ee:ff``) for ``kind="mac"``.
    value: Mapped[str] = mapped_column(String(64), nullable=False)

    # Free-text operator reason bucket (rogue / lost_stolen / quarantine /
    # policy / other) — mirrors ``dhcp_mac_block.reason`` semantics.
    reason: Mapped[str] = mapped_column(String(32), nullable=False, default="quarantine")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Provenance — where this block came from + an opaque back-reference
    # (a new-device sighting id, a rogue responder id, …) for audit trails.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="manual")
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Desired-state flags. ``enabled=False`` or an ``expires_at`` in the past
    # means the reconciler should lift this block from every target it landed
    # on (it does NOT delete the row — history stays for audit).
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )


class NetworkBlockPush(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Per-(block, target) convergence state.

    ``target_id`` is the ``opnsense_router.id`` / ``unifi_controller.id``
    this block was pushed to. No cross-table FK (polymorphic), so nothing
    cascades from a target delete — instead the OPNsense / UniFi delete
    handlers explicitly sweep the matching push rows (and an operator is
    expected to *disarm* a target first, which lifts the blocks off the
    device via ``lift_all_for_target``; the delete handlers refuse while the target
    is armed or rows remain (#2291), and ``force`` leaves the device state).

    ``block_id`` IS ``ON DELETE CASCADE``: a block is normally *lifted*
    (``enabled=False``, row kept) rather than hard-deleted, and the
    reconciler removes the device entry before the disabled row is ever
    reaped — so the cascade only fires once the value is already gone from
    every device. A raw hard-delete of a still-active block (manual DB /
    factory reset) is the one path that can strand a device entry; those
    flows should lift first.
    """

    __tablename__ = "network_block_push"
    __table_args__ = (
        UniqueConstraint(
            "block_id", "target_kind", "target_id", name="uq_network_block_push_block_target"
        ),
        Index("ix_network_block_push_target", "target_kind", "target_id"),
    )

    block_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_block.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    push_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default=sa_text("'pending'")
    )
    last_pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


__all__ = [
    "BLOCK_KINDS",
    "BLOCK_SOURCES",
    "BLOCK_TARGET_KINDS",
    "PUSH_STATUSES",
    "NetworkBlock",
    "NetworkBlockPush",
]

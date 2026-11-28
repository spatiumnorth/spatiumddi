"""Subnet holds — a CIDR set aside for a future project (#4492).

A hold is a *claim on address space*, not a subnet: it has no placeholder
addresses, no reverse zone and no DHCP scope. It records who asked for the
space, why, and until when. Subnet creation / resize refuses a CIDR that
overlaps an active hold (``app.services.ipam.holds``); an expired hold keeps
holding until an operator releases or converts it, so space never frees
itself silently (the ``subnet_hold_expiring`` alert surfaces it).

``block_id`` is informational (the block the CIDR sits in when it was
created) and ``SET NULL`` on block delete; ``space_id`` cascades.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import CIDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

HOLD_STATUSES: frozenset[str] = frozenset({"active", "converted", "released"})


class SubnetHold(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "subnet_hold"
    __table_args__ = (
        Index(
            "ix_subnet_hold_space_active", "space_id", postgresql_where=text("status = 'active'")
        ),
        Index("ix_subnet_hold_expires_at", "expires_at"),
    )

    space_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_space.id", ondelete="CASCADE"), nullable=False
    )
    block_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_block.id", ondelete="SET NULL"), nullable=True
    )
    network: Mapped[str] = mapped_column(CIDR, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    # active | converted | released. Only ``active`` rows block allocation.
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="active", server_default=text("'active'")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    owner_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("group.id", ondelete="SET NULL"), nullable=True
    )
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("customer.id", ondelete="SET NULL"), nullable=True
    )
    # The subnet a hold was converted into; no FK so a later subnet delete
    # leaves the history row alone.
    converted_subnet_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

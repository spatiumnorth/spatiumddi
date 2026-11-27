"""Commercial-DDI live mirror (issue #4729): per-target connection config plus
the mirrored object store.

A ``DDIMirrorTarget`` points SpatiumDDI at ONE estate of a commercial DDI
product (Infoblox first; BlueCat and EfficientIP slot in behind the provider
abstraction in ``app.services.ddi_mirror``). The reconciler pulls networks,
containers, ranges, fixed addresses, host / A / PTR records, zones and views
into ``DDIMirrorObject`` rows and **nowhere else**: the mirror is a separate,
provenance-stamped store, never live IPAM / DNS / DHCP. The cutover-rehearsal
view compares that store with the live tables to show what an import would
create and what differs. Nothing is ever written back to the source system.

Because the store is separate from IPAM, a target has no ``ipam_space_id`` and
no ownership columns on the IPAM tables — "kept apart from live data until
promoted" holds by construction. Removing the target cascades its objects.
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
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class DDIMirrorTarget(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One commercial DDI estate SpatiumDDI mirrors read-only."""

    __tablename__ = "ddi_mirror_target"
    __table_args__ = (Index("ix_ddi_mirror_target_name", "name", unique=True),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Provider key in ``app.services.ddi_mirror.registry`` — ``infoblox`` today.
    vendor: Mapped[str] = mapped_column(String(32), nullable=False, default="infoblox")

    # ── Connection ──────────────────────────────────────────────────
    # Scheme + host (+ optional port), no path: ``https://gm.<your-domain>``.
    # https only — the credentials ride HTTP basic auth.
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    # WAPI version segment, ``v2.12`` style (the provider builds ``/wapi/<ver>/``).
    api_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v2.12")
    # TLS is verified by default; ``False`` is an explicit, logged opt-out.
    verify_tls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    ca_bundle_pem: Mapped[str] = mapped_column(Text, nullable=False, default="")
    username: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # Fernet-encrypted; empty bytes = unset.
    password_encrypted: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, default=b"", server_default=sa_text("''::bytea")
    )

    # ── Scope ───────────────────────────────────────────────────────
    # Empty = every network view / DNS view on the source.
    network_view: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    dns_view: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    # ── Cadence + politeness ────────────────────────────────────────
    # A estate mirror is bulk data: 15 min default, 60 s floor.
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)
    # WAPI ``_max_results`` per page (bounded 50..1000 at the API).
    page_size: Mapped[int] = mapped_column(Integer, nullable=False, default=500)

    # ── Sync state ──────────────────────────────────────────────────
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # A sync that finished but could not read some object types.
    last_sync_warning: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    object_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Per-run report: counts per kind + what could not be mapped.
    last_report: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class DDIMirrorObject(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One mirrored source object. ``source_ref`` is the source system's own id
    (Infoblox ``_ref``), so repeated pulls update the row rather than duplicate."""

    __tablename__ = "ddi_mirror_object"
    __table_args__ = (
        UniqueConstraint("target_id", "kind", "source_ref", name="uq_ddi_mirror_object_ref"),
        Index("ix_ddi_mirror_object_target_kind", "target_id", "kind"),
    )

    target_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ddi_mirror_target.id", ondelete="CASCADE"),
        nullable=False,
    )
    # view | container | network | range | reservation | host | a | ptr | zone
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    # Network view (IPAM kinds) or DNS view (DNS kinds); "" when not applicable.
    view: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # The primary value: CIDR, "start-end" for a range, IP, or record data.
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


__all__ = ["DDIMirrorObject", "DDIMirrorTarget"]

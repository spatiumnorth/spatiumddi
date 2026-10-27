"""Packet-capture (tcpdump) job history — issue #59.

One row is one operator-triggered packet capture. It mirrors
:class:`app.models.nmap.NmapScan`'s lifecycle (a persisted long-running
job with a 5-state machine, isolated worker execution, retention) but
diverges in three structural ways:

1. The deliverable is a **binary ``.pcap`` artifact on disk** —
   ``pcap_path`` points at a file under ``SPATIUM_PCAP_DIR``; the
   download endpoint streams it. The bytes are *never* embedded in a DB
   column or JSON (they're large + sensitive).
2. The meaningful vantage is *where tcpdump runs* — the control-plane
   container (``vantage_kind="server"``, Phase 1) or an appliance host
   (``vantage_kind="appliance"``, Phase 2). ``vantage_label`` is the
   denormalised hostname so the row survives a target delete.
3. PCAP **auto-prunes** (``app.tasks.pcap.prune_captures``) — pcaps are
   large and sensitive (plaintext creds/PII), so terminal rows + their
   files expire after ``PlatformSettings.pcap_retention_days`` (7 by
   default), unlike nmap's operator-curated-forever history.

Live progress is **polled** (no SSE): while ``running`` the UI reads
``bytes_captured`` (honest, from an fstat of the growing file) +
``status``. ``packets_captured`` + ``metadata_json`` are authoritative
only at completion (tcpdump emits its count at exit).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PacketCapture(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One tcpdump invocation initiated from the SpatiumDDI UI."""

    __tablename__ = "packet_capture"
    __table_args__ = (
        Index("ix_packet_capture_status", "status"),
        Index("ix_packet_capture_appliance", "appliance_id"),
        Index("ix_packet_capture_creator_created", "created_by_user_id", "created_at"),
        Index("ix_packet_capture_created", "created_at"),
    )

    # ── Vantage (where tcpdump runs) ────────────────────────────────────
    # "server" = control-plane worker container (Phase 1).
    # "appliance" = an approved Fleet appliance host (Phase 2).
    vantage_kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="server", server_default="server"
    )
    appliance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Denormalised hostname / "control plane" so the row stays meaningful
    # after the appliance row is deleted (cf. NmapScan.target_ip).
    vantage_label: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    # ── Inputs (server-validated before persist; re-validated at runner) ─
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # BPF expression — passed as tcpdump's single trailing argv element,
    # NEVER shell-interpolated / shlex.split. Charset-validated.
    bpf_filter: Mapped[str | None] = mapped_column(Text, nullable=True)
    snaplen: Mapped[int] = mapped_column(Integer, nullable=False, default=256, server_default="256")
    promiscuous: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Stop conditions — at least one is required at the API layer.
    max_packets: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_duration_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # ── Run state (5 states, identical semantics to NmapScan) ───────────
    # status: queued | running | completed | failed | cancelled
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="queued", server_default="queued"
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # tcpdump PID for orphan reaping on the running vantage.
    tcpdump_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Live progress (polled; not a stream) ────────────────────────────
    packets_captured: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    bytes_captured: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )

    # ── Artifact (binary on disk) ───────────────────────────────────────
    pcap_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    pcap_size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    pcap_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The k8s node whose pod stored the artifact (#2866). ``pcap_path`` is
    # the per-node ``pcaps`` hostPath on a multi-node appliance, so the file
    # exists only on that node's disk. NULL is unknown (a capture from before
    # #2866, or Compose, which has no node name).
    artifact_node: Mapped[str | None] = mapped_column(String(253), nullable=True)
    # Set when the row outlives its file (restore drift / pruned) so the
    # UI hides the Download button instead of offering a 404.
    artifact_missing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # {first_ts,last_ts,packet_count,byte_count,link_type,truncated}
    metadata_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── Provenance ──────────────────────────────────────────────────────
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )


__all__ = ["PacketCapture"]

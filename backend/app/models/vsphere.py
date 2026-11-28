"""VMware vSphere integration — per-vCenter connection config (#4740).

Same shape as ``ProxmoxNode``: one ``VSphereTarget`` row per vCenter Server,
polled read-only over the vSphere Automation REST API (vCenter 7.0 U2 and
later; no SOAP, no pyVmomi). The target's credentials are a vCenter
username + password, Fernet-encrypted at rest. A session token is created
per sync pass and deleted at the end of it; nothing but the password is
ever persisted.
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
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class VSphereTarget(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A vCenter Server SpatiumDDI polls for host + VM + guest-IP state."""

    __tablename__ = "vsphere_target"
    __table_args__ = (Index("ix_vsphere_target_name", "name", unique=True),)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Connection ──────────────────────────────────────────────────
    # vCenter host without scheme (``vcenter.example.com`` or ``10.0.0.5``);
    # the client builds ``https://{host}:{port}/api/...``.
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    # TLS is verified unless the operator opts out (self-signed lab vCenter).
    verify_tls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    # Optional PEM trusted in addition to the system store.
    ca_bundle_pem: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Not a secret on its own (``svc-spatium@vsphere.local``).
    username: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # Fernet-encrypted password. Empty bytes = unset.
    password_encrypted: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False, default=b"", server_default=sa_text("''::bytea")
    )

    # ── Binding ─────────────────────────────────────────────────────
    ipam_space_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_space.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # ── Mirror policy ───────────────────────────────────────────────
    mirror_vms: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    # ESXi hosts whose vCenter inventory name is an IP literal land as
    # ``vsphere-host`` rows (the REST API does not return a host's
    # management address any other way).
    mirror_hosts: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # ── Cadence ─────────────────────────────────────────────────────
    # Per-VM guest calls make a pass chatty on a big vCenter: 120 s default,
    # 30 s floor. Swept by ``sweep_vsphere_targets`` on a 30 s beat tick.
    sync_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=120)

    # ── Sync state ──────────────────────────────────────────────────
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Populated by test-connection + every successful pass.
    vcenter_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vm_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Per-pass diagnostic snapshot: which VMs report no guest IPs and why
    # (VMware Tools not running, powered off, no NIC). Shape: see
    # services/vsphere/reconcile.py::_build_discovery_payload.
    last_discovery: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


__all__ = ["VSphereTarget"]

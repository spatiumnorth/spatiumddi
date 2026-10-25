"""Service catalog — first-class customer-deliverable bundles (issue #94).

A ``NetworkService`` is one row per thing the operator delivers — typically
to a customer, sometimes to an internal team. The first concrete ``kind``
is ``mpls_l3vpn`` (a VRF + edge sites + edge circuits, all sold to one
customer). Other kinds light up against the same base entity in later
phases (DIA, hosted DNS / DHCP, SD-WAN, ``custom``).

The polymorphic ``NetworkServiceResource`` join row binds a service to
arbitrary core entities (VRF / Subnet / IPBlock / DNSZone / DHCPScope /
Circuit / Site / OverlayNetwork). Because the link points at multiple
tables, ``resource_id`` is *not* a true FK — application code in the
services router validates the target row exists at attach time, and the
``service_resource_orphaned`` alert rule (Wave 2) sweeps for orphans
asynchronously when a target is later deleted.

Soft-deletable: a service that goes ``decom`` is the operator-visible
end-of-life flag; the soft-delete row keeps the audit trail of "Customer
X had which services in 2024?".
"""

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal

from sqlalchemy import (
    Date,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin

# Service kinds. Only ``mpls_l3vpn`` and ``custom`` are end-to-end in
# v1; the others reserve names so future phases can add validators +
# kind-specific summary endpoints without an enum migration.
SERVICE_KINDS: frozenset[str] = frozenset(
    {
        "mpls_l3vpn",
        "mpls_l2vpn",
        "vpls",
        "evpn",
        "dia",
        "hosted_dns",
        "hosted_dhcp",
        "sdwan",
        "custom",
    }
)

# Kinds the v1 router will accept on create / update. The wider
# ``SERVICE_KINDS`` list above is what the column allows at the DB
# level so a future release can add a kind without a column migration.
# ``sdwan`` lit up alongside #95 — services can now bundle an
# OverlayNetwork as the central deliverable.
SERVICE_KINDS_V1: frozenset[str] = frozenset({"mpls_l3vpn", "sdwan", "custom"})

SERVICE_STATUSES: frozenset[str] = frozenset({"active", "provisioning", "suspended", "decom"})

# Resource kinds the polymorphic join row supports. ``overlay_network``
# is reserved for the SD-WAN overlay roadmap (#95) — the router rejects
# attach attempts until the OverlayNetwork model lands.
RESOURCE_KINDS: frozenset[str] = frozenset(
    {
        "vrf",
        "subnet",
        "ip_block",
        "dns_zone",
        "dhcp_scope",
        "circuit",
        "overlay_network",
        "site",
    }
)


class NetworkService(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """One row per customer / team deliverable.

    ``name`` is unique within a single customer so two customers can
    both have a service called ``HQ-DC L3VPN``. ``sla_tier`` is a
    free-form label (``gold`` / ``silver`` / operator-defined) — actual
    SLA enforcement is out of scope per the issue body.
    """

    __tablename__ = "network_service"
    __table_args__ = (
        # Partial, so a soft-deleted service stops holding its name (#2738).
        Index(
            "uq_network_service_customer_name",
            "customer_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_network_service_customer_id", "customer_id"),
        Index("ix_network_service_kind", "kind"),
        Index("ix_network_service_status", "status"),
        Index("ix_network_service_term_end_date", "term_end_date"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # ``mpls_l3vpn`` | ``mpls_l2vpn`` | ``vpls`` | ``evpn`` | ``dia`` |
    # ``hosted_dns`` | ``hosted_dhcp`` | ``sdwan`` | ``custom``
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="custom", server_default="custom"
    )

    customer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # ``active`` | ``provisioning`` | ``suspended`` | ``decom``
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="provisioning", server_default="provisioning"
    )

    term_start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    term_end_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    monthly_cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    currency: Mapped[str] = mapped_column(
        String(3), nullable=False, default="USD", server_default="USD"
    )

    # Free-form SLA label. Operators self-define ("gold" / "silver" /
    # "platinum-24x7"). Uppercased / normalised in the router so list
    # filters dedupe sanely.
    sla_tier: Mapped[str | None] = mapped_column(String(32), nullable=True)

    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")

    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    custom_fields: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class NetworkServiceResource(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Polymorphic join from a service to a core entity.

    ``resource_id`` is not a real FK — the router validates the target
    exists at attach time, and the ``service_resource_orphaned`` alert
    sweeps for stale rows when a target is later deleted (Wave 2 of
    issue #94).

    A single service can attach the same kind multiple times (e.g.
    several edge sites, several circuits) but never the same row twice
    — the unique index on ``(service_id, resource_kind, resource_id)``
    guards the second case.
    """

    __tablename__ = "network_service_resource"
    __table_args__ = (
        UniqueConstraint(
            "service_id",
            "resource_kind",
            "resource_id",
            name="uq_network_service_resource_triple",
        ),
        Index("ix_nsr_service_kind", "service_id", "resource_kind"),
        Index("ix_nsr_kind_target", "resource_kind", "resource_id"),
    )

    service_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_service.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``vrf`` | ``subnet`` | ``ip_block`` | ``dns_zone`` |
    # ``dhcp_scope`` | ``circuit`` | ``overlay_network`` | ``site``
    resource_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    # Free-form operator label ("primary" / "backup" / "hub" / "spoke")
    # so a service that has 5 circuits can mark which ones do what.
    role: Mapped[str | None] = mapped_column(String(64), nullable=True)


__all__ = [
    "NetworkService",
    "NetworkServiceResource",
    "SERVICE_KINDS",
    "SERVICE_KINDS_V1",
    "SERVICE_STATUSES",
    "RESOURCE_KINDS",
]

"""SD-WAN overlay topology — first-class overlays + routing policies (#95).

SpatiumDDI is the vendor-neutral source of truth for SD-WAN overlay
*topology and intent* — what the overlay looks like and what policies
apply where. Vendor config push (vManage / Meraki Dashboard /
FortiManager / Versa Director) and real-time path telemetry are
explicitly out of scope per the issue body.

Four tables:

* ``overlay_network`` — one row per logical overlay (an "Acme Corp
  Global Overlay"). Soft-deletable so a decommissioned overlay can
  still answer historical "what did Customer-X use?" queries.
* ``overlay_site`` — m2m through row binding sites into the overlay
  with a role (hub / spoke / transit / gateway), the edge device that
  terminates tunnels at this site, and an ordered list of preferred
  underlay circuits (``preferred_circuits`` jsonb — first-listed wins,
  fall through on outage).
* ``routing_policy`` — per-overlay declarative policy (priority +
  match + action). Operators declare "steer Office365 to internet
  broadband"; vendors enforce.
* ``application_category`` — curated catalog of well-known SaaS apps
  used by ``routing_policy.match_kind=application``. Seeded at
  startup (~30 apps) and operator-extensible.

FK semantics throughout:

* ``customer_id`` on ``overlay_network`` is ``ON DELETE SET NULL`` so
  removing a customer doesn't cascade overlay deletion (operators may
  want to re-attribute, not lose history).
* ``overlay_network_id`` on the join + policy rows is
  ``ON DELETE CASCADE`` — when an overlay is hard-deleted (rare; usually
  soft-delete) its bindings + policies go with it.
* ``site_id`` / ``device_id`` / ``loopback_subnet_id`` on
  ``overlay_site`` are ``ON DELETE SET NULL`` — losing the underlying
  resource shouldn't cascade-delete the overlay membership row.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin

# Overlay kinds. ``sdwan`` is the umbrella for vendor-managed SD-WAN
# (Cisco / Meraki / Fortinet / Versa / VeloCloud / Cato / Aryaka). The
# others cover the open-source / DIY overlays operators commonly run
# alongside or instead of vendor SD-WAN.
OVERLAY_KINDS: frozenset[str] = frozenset(
    {
        "sdwan",
        "ipsec_mesh",
        "wireguard_mesh",
        "dmvpn",
        "vxlan_evpn",
        "gre_mesh",
    }
)

# Vendor labels — free-form so operators can plug a non-curated vendor
# in. The frontend shows the curated list as a dropdown plus an "other"
# free-text option.
CURATED_OVERLAY_VENDORS: tuple[str, ...] = (
    "cisco_viptela",
    "cisco_meraki",
    "fortinet",
    "velocloud",
    "versa",
    "cato",
    "aryaka",
    "silver_peak",
    "open_source",
)

# How traffic distributes when no specific routing_policy matches.
DEFAULT_PATH_STRATEGIES: frozenset[str] = frozenset(
    {"active_active", "active_backup", "load_balance", "app_aware"}
)

OVERLAY_STATUSES: frozenset[str] = frozenset({"active", "building", "suspended", "decom"})

OVERLAY_SITE_ROLES: frozenset[str] = frozenset({"hub", "spoke", "transit", "gateway"})

# Routing-policy match kinds. Each implies a different shape for
# ``match_value`` — the router validates per-kind at write time.
ROUTING_POLICY_MATCH_KINDS: frozenset[str] = frozenset(
    {
        "application",  # match_value = application_category.name
        "dscp",  # match_value = "0"-"63" or named (EF, AF11, …)
        "source_subnet",  # match_value = CIDR
        "destination_subnet",  # match_value = CIDR
        "port_range",  # match_value = "tcp:80-443" / "udp:53"
        "acl",  # match_value = free-form ACL identifier
    }
)

# Routing-policy actions. ``action_target`` interpretation depends on
# the action (circuit UUID, transport class name, site UUID + path,
# DSCP value, bandwidth limit).
ROUTING_POLICY_ACTIONS: frozenset[str] = frozenset(
    {
        "steer_to_circuit",
        "steer_to_transport_class",
        "steer_to_site_via_path",
        "drop",
        "shape",
        "mark_dscp",
    }
)

# Application categories — curated taxonomy mirroring common SD-WAN
# vendor app catalogs.
APPLICATION_CATEGORIES: frozenset[str] = frozenset(
    {
        "saas",
        "voice",
        "video",
        "file_transfer",
        "security",
        "collaboration",
        "ml",
        "custom",
    }
)


class OverlayNetwork(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A logical overlay — sites tied together by an SD-WAN /
    IPsec / WireGuard / DMVPN / VXLAN / GRE mesh on top of one or
    more underlay transports.

    Optional ``customer_id`` so internal-only overlays (HQ ↔ branches)
    don't have to be attributed to a customer row.
    """

    __tablename__ = "overlay_network"
    __table_args__ = (
        # Partial, so a soft-deleted overlay stops holding its name (#2738).
        Index(
            "uq_overlay_network_name",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_overlay_network_customer_id", "customer_id"),
        Index("ix_overlay_network_kind", "kind"),
        Index("ix_overlay_network_status", "status"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # ``sdwan`` | ``ipsec_mesh`` | ``wireguard_mesh`` | ``dmvpn`` |
    # ``vxlan_evpn`` | ``gre_mesh``
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="sdwan", server_default="sdwan"
    )
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Free-form because the curated list grows over time. Validated
    # against ``CURATED_OVERLAY_VENDORS`` only as a soft warning in
    # the UI; backend accepts anything.
    vendor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Free-form encryption descriptor (``aes-256-gcm-x509``,
    # ``chacha20-poly1305-psk``, etc.). Operators self-curate.
    encryption_profile: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # ``active_active`` | ``active_backup`` | ``load_balance`` | ``app_aware``
    default_path_strategy: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active_backup",
        server_default="active_backup",
    )
    # ``active`` | ``building`` | ``suspended`` | ``decom``
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="building", server_default="building"
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="{}")
    custom_fields: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}"
    )


class OverlaySite(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Site membership in an overlay.

    Each row binds one site into one overlay with a role plus the edge
    device terminating tunnels and an ordered list of preferred
    underlay circuits. Failover walks the list top-down — first
    available circuit wins, the rest are fallbacks.
    """

    __tablename__ = "overlay_site"
    __table_args__ = (
        UniqueConstraint(
            "overlay_network_id",
            "site_id",
            name="uq_overlay_site_overlay_site",
        ),
        Index("ix_overlay_site_overlay_id", "overlay_network_id"),
        Index("ix_overlay_site_site_id", "site_id"),
        Index("ix_overlay_site_role", "role"),
    )

    overlay_network_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("overlay_network.id", ondelete="CASCADE"),
        nullable=False,
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``hub`` | ``spoke`` | ``transit`` | ``gateway``
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, default="spoke", server_default="spoke"
    )
    # Optional — the actual SD-WAN edge box at this site. ``ON DELETE
    # SET NULL`` so device deletion doesn't cascade-delete the
    # membership row.
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_device.id", ondelete="SET NULL"),
        nullable=True,
    )
    # The loopback / TLOC subnet used to terminate overlay tunnels —
    # typically a /32 on a loopback interface, or a tiny shared block
    # everyone TLOCs out of.
    loopback_subnet_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subnet.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Ordered list of circuit UUIDs (strings in JSONB). First wins,
    # subsequent entries are fallbacks. Validation lives in the router
    # (existence check + non-decom-status); the column itself is loose
    # so operators can stage changes.
    preferred_circuits: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")


class RoutingPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Declarative routing policy for an overlay.

    Operators express *intent* ("steer Office365 to internet
    broadband"); SpatiumDDI is the source of truth for the policy set,
    vendors enforce on-box. Lower ``priority`` = evaluated first; ties
    are broken by ``created_at`` so reordering doesn't depend on
    primary-key ordering.
    """

    __tablename__ = "routing_policy"
    __table_args__ = (
        Index("ix_routing_policy_overlay_id", "overlay_network_id"),
        Index(
            "ix_routing_policy_overlay_priority",
            "overlay_network_id",
            "priority",
        ),
    )

    overlay_network_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("overlay_network.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=100, server_default="100"
    )
    # ``application`` | ``dscp`` | ``source_subnet`` |
    # ``destination_subnet`` | ``port_range`` | ``acl``
    match_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    match_value: Mapped[str] = mapped_column(String(255), nullable=False)
    # ``steer_to_circuit`` | ``steer_to_transport_class`` |
    # ``steer_to_site_via_path`` | ``drop`` | ``shape`` | ``mark_dscp``
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    # Interpretation depends on action (circuit UUID, transport class,
    # site UUID, DSCP value, bandwidth limit). Free-form so operators
    # can express vendor-specific args without an enum migration.
    action_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")


class ApplicationCategory(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Curated catalog of well-known SaaS / voice / video apps used as
    match values by ``routing_policy.match_kind=application``.

    Seeded at startup (~30 apps) by ``services.applications.seed_*``
    and operator-extensible — ``is_builtin=true`` rows are owned by the
    platform and refreshed on every boot, ``is_builtin=false`` rows are
    untouched.
    """

    __tablename__ = "application_category"
    __table_args__ = (UniqueConstraint("name", name="uq_application_category_name"),)

    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    # Suggested DSCP per RFC 4594. Nullable because non-real-time apps
    # (Salesforce, GitHub) don't have a canonical DSCP recommendation.
    default_dscp: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # ``saas`` | ``voice`` | ``video`` | ``file_transfer`` | ``security`` |
    # ``collaboration`` | ``ml`` | ``custom``
    category: Mapped[str] = mapped_column(
        String(16), nullable=False, default="saas", server_default="saas"
    )
    is_builtin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )


__all__ = [
    "OverlayNetwork",
    "OverlaySite",
    "RoutingPolicy",
    "ApplicationCategory",
    "OVERLAY_KINDS",
    "CURATED_OVERLAY_VENDORS",
    "DEFAULT_PATH_STRATEGIES",
    "OVERLAY_STATUSES",
    "OVERLAY_SITE_ROLES",
    "ROUTING_POLICY_MATCH_KINDS",
    "ROUTING_POLICY_ACTIONS",
    "APPLICATION_CATEGORIES",
]

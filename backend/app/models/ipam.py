import uuid
from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    text as sa_text,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin

# Valid IPAddress.status values. Operator-settable values cover the
# manual lifecycle (free → allocated → reserved → deprecated, plus the
# static_dhcp tag for DHCP reservations). Integration-owned values are
# stamped by reconcilers (Proxmox / Docker / Kubernetes / DHCP lease
# pull). The combined set is what API validators accept on update;
# operators can keep an integration status as-is on a row, or override
# with any operator-settable value (which stamps user_modified_at on
# the row and locks it from future reconciler overwrites).
IP_STATUSES_OPERATOR_SETTABLE: frozenset[str] = frozenset(
    {
        "available",
        "allocated",
        "reserved",
        "static_dhcp",
        "deprecated",
        "orphan",
    }
)
IP_STATUSES_INTEGRATION_OWNED: frozenset[str] = frozenset(
    {
        "dhcp",
        "docker-container",
        "kubernetes-node",
        "kubernetes-lb",
        "kubernetes-service",
        "proxmox-vm",
        "proxmox-lxc",
        "tailscale-node",
        # NetBird peer mirror (issue #603). One row per NetBird peer's
        # overlay IP, mirrored from the management API. Read-only — the
        # reconciler owns the row unless an operator edits it.
        "netbird-peer",
        # OPNsense ARP-table mirror (issue #31). Opt-in secondary source
        # — a host the firewall has seen on the wire, distinct from a
        # DHCP lease (status="dhcp") or static reservation
        # (status="reserved") which the OPNsense reconciler also emits.
        "opnsense-arp",
        # Cloud integration (issue #37, Part A). cloud-instance = a
        # VM/EC2/GCE NIC private IP; cloud-public = an Elastic/public
        # IP or external address; cloud-lb = a load-balancer frontend
        # IP (ELB/ALB/NLB, Azure LB, GCP forwarding rule).
        "cloud-instance",
        "cloud-public",
        "cloud-lb",
        # Stamped by the nmap "Stamp alive hosts → IPAM" action on a
        # multi-host (CIDR) scan result. Marks an IP as "we saw a host
        # on the wire here" without claiming it's allocated. Operators
        # can transition discovered rows to allocated / reserved
        # through the normal edit path; that stamps user_modified_at
        # and locks the row from further auto-discovery overwrites.
        "discovered",
    }
)
IP_STATUSES: frozenset[str] = IP_STATUSES_OPERATOR_SETTABLE | IP_STATUSES_INTEGRATION_OWNED
# The statuses a NEW address may be created with by hand — over REST and over
# the operation layer (requests portal, Copilot) alike: the operator-settable
# set plus ``dhcp`` for the static-reservation conversion path. Integration
# statuses (proxmox-vm, kubernetes-node, …) belong to their reconcilers; a
# brand-new row carrying one would be "owned" by no integration.
IP_STATUSES_CREATE_SETTABLE: frozenset[str] = IP_STATUSES_OPERATOR_SETTABLE | {"dhcp"}

# Valid IPAddress.role values. Orthogonal to ``status`` — the role
# describes what the IP *is* (a host vs. a VRRP virtual address),
# while the status describes its lifecycle (allocated vs. reserved).
# Roles in ``IP_ROLES_SHARED`` (anycast / vip / vrrp) are intentionally
# shared across multiple devices and bypass the MAC-collision warning.
IP_ROLES: frozenset[str] = frozenset(
    {
        "host",
        "loopback",
        "anycast",
        "vip",
        "vrrp",
        "secondary",
        "gateway",
        # Baseboard management controller — iDRAC / iLO / IPMI / Redfish
        # (#722). Worth its own role rather than a tag: a BMC is a
        # management-plane endpoint on a fragile embedded stack, and it
        # is a routine casualty of ping sweeps and nmap runs. Naming the
        # class is what lets an operator find every one of them and
        # decide whether their subnet belongs behind ``do_not_probe``.
        "bmc",
        # TLS-serving classifications (#118 Phase 2) — an IP in one of these
        # roles is auto-added as a TLS cert probe target by the discovery
        # reconciler (see TLS_SERVING_ROLES).
        "web",
        "api",
        "lb",
    }
)
IP_ROLES_SHARED: frozenset[str] = frozenset({"anycast", "vip", "vrrp"})
# IP roles that imply a TLS endpoint worth probing for a cert (#118 Phase 2).
TLS_SERVING_ROLES: frozenset[str] = frozenset({"web", "api", "lb"})

# Network-role classification on Subnet (issue #112 phase 2). Operators
# pick one when the subnet has a clear network function; null means
# unspecified. Drives IPAM filter chips, VLAN page tags, voice-VLAN
# conformity checks, and the voice-lease-count alert rule.
SUBNET_ROLES: frozenset[str] = frozenset({"data", "voice", "management", "guest"})


class IPSpace(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """VRF / isolated routing domain. IPs in different spaces may overlap."""

    __tablename__ = "ip_space"
    __table_args__ = (
        # Partial unique index (NOT column-level unique=True) so a
        # soft-deleted space stops occupying its name slot. IPSpace is
        # soft-deletable; a plain unique index kept the trashed name, so the
        # ORM create pre-check (auto-filtered to deleted_at IS NULL) couldn't
        # see it and the INSERT 500'd on the constraint (#491). Scoping
        # uniqueness to live rows matches the soft-delete semantics — same
        # pattern as uq_dhcp_scope_group_subnet (b67286f).
        Index(
            "ix_ip_space_name",
            "name",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Optional swatch key painted as a dot in the IPAM tree — same curated
    # palette as DNSZone.color so the two feel coherent.
    color: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # DNS assignment — propagates down to child blocks/subnets that inherit
    dns_group_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    dns_zone_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_additional_zone_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # DHCP server group — parallels the DNS inheritance path. A space-level
    # default is picked up by any child block/subnet that has
    # dhcp_inherit_settings=True and no override of its own.
    dhcp_server_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )

    # DDNS defaults — the root of the block/subnet inheritance chain.
    # Enabling ddns_enabled here and leaving descendants on inherit mode
    # cascades DDNS to every subnet in the space. Semantics mirror the
    # subnet-level fields; see ``Subnet`` for the policy enum.
    ddns_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ddns_hostname_policy: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="client_or_generated",
        server_default=sa_text("'client_or_generated'"),
    )
    ddns_domain_override: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ddns_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Fragile-device probe suppression (issue #722) ────────────────────
    # Root of the space → block → subnet chain. See ``Subnet`` for the
    # full semantics; the short version is that this flag ORs downward
    # (a space marked do-not-probe suppresses probes on every subnet
    # under it, and no descendant can un-set it).
    do_not_probe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    do_not_probe_reason: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )

    # ── VRF / routing annotation ─────────────────────────────────────────
    # First-class VRF binding (added by issue #86). The freeform
    # ``vrf_name`` / ``route_distinguisher`` / ``route_targets``
    # columns immediately below are DEPRECATED — drop after one
    # release cycle, see issue #86. They are kept through this
    # release so operators can verify the freeform→``vrf_id``
    # mapping landed by the ``vrf_first_class`` migration; new
    # writes should set ``vrf_id`` instead.
    vrf_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vrf.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # DEPRECATED — drop after one release cycle, see issue #86.
    vrf_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # DEPRECATED — drop after one release cycle, see issue #86.
    route_distinguisher: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # DEPRECATED — drop after one release cycle, see issue #86.
    route_targets: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # Optional BGP origin (issue #85). NULL = "no AS recorded".
    asn_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asn.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Logical ownership (issue #91). Spaces are routing domains and
    # are deliberately not ``site``-scoped — that lives on subnets /
    # blocks where it has crisp meaning.
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Provenance for the NetBox one-shot importer (issue #36). ``netbox``
    # for spaces created by /ipam/import/netbox; NULL for hand-created
    # rows so the importer never claims ownership of rows it didn't
    # create. ``imported_at`` is the wall-clock commit timestamp.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    blocks: Mapped[list["IPBlock"]] = relationship(
        "IPBlock", back_populates="space", cascade="all, delete-orphan"
    )
    subnets: Mapped[list["Subnet"]] = relationship("Subnet", back_populates="space")


class RouterZone(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Groups subnets that share a routing context (site, VRF, campus, etc.)."""

    __tablename__ = "router_zone"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # zone_type values: site | vrf_lite | mpls_domain | data_center | custom
    zone_type: Mapped[str] = mapped_column(String(50), nullable=False, default="site")
    parent_zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("router_zone.id", ondelete="SET NULL"), nullable=True
    )
    contact_info: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    parent: Mapped["RouterZone | None"] = relationship("RouterZone", remote_side="RouterZone.id")
    subnets: Mapped[list["Subnet"]] = relationship("Subnet", back_populates="router_zone")


class IPBlock(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """
    Aggregate/supernet range for organizational grouping.
    IPs are not directly assigned to blocks — only to subnets.
    Blocks can be nested (parent_block_id).
    """

    __tablename__ = "ip_block"
    __table_args__ = (Index("ix_ip_block_network", "network"),)

    space_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_space.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_block_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_block.id", ondelete="CASCADE"), nullable=True
    )

    network: Mapped[str] = mapped_column(CIDR, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Computed / cached. ``allocated_ips`` is the recursive sum of descendant
    # subnets' allocated_ips plus each subnet's network/broadcast addresses
    # (a block's utilization is the share of its CIDR in use, #2982), clamped
    # to the CIDR size; ``total_ips`` is the block's CIDR size clamped to
    # BIGINT (a huge IPv6 block reads as "uncountable" in the UI, like a /64
    # subnet). Both are populated by ``_update_block_utilization`` alongside
    # ``utilization_percent`` so block rows can show Used IPs, not just a bar.
    utilization_percent: Mapped[float] = mapped_column(nullable=False, default=0.0)
    allocated_ips: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    total_ips: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    custom_fields: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Set by the Kubernetes reconciler for pod CIDR / service CIDR
    # blocks mirrored from a cluster. FK cascades on cluster delete.
    kubernetes_cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kubernetes_cluster.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the Docker reconciler for wrapper blocks it creates
    # when no operator block encloses a Docker network CIDR.
    # Cascades on host delete.
    docker_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("docker_host.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the Proxmox reconciler for blocks it creates from bridge
    # CIDRs. Cascades on endpoint delete.
    proxmox_node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("proxmox_node.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the Tailscale reconciler for the auto-created CGNAT +
    # IPv6 ULA blocks under the bound space. Cascades on tenant
    # delete.
    tailscale_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tailscale_tenant.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the UniFi reconciler for wrapper blocks it creates when
    # no operator block encloses a UniFi network's CIDR. Cascades on
    # controller delete.
    unifi_controller_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("unifi_controller.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the Cloud reconciler (issue #37) for the IPBlock it creates
    # per VPC/VNet address-space CIDR under the bound space. Cascades on
    # endpoint delete.
    cloud_endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_endpoint.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # OPNsense integration provenance (issue #31). Set on wrapper blocks
    # the OPNsense reconciler creates when no operator block encloses a
    # firewall interface's CIDR. Cascades on firewall delete.
    opnsense_router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("opnsense_router.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # NetBird provenance (issue #603) — set on the wrapper block the
    # NetBird reconciler creates for the overlay CIDR. Cascades on
    # instance delete.
    netbird_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("netbird_instance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Palo Alto PAN-OS / Panorama provenance (issue #605). Set on the wrapper
    # block the PAN-OS reconciler creates for a mirrored zone/interface CIDR.
    # Cascades on firewall delete.
    panos_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("panos_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Fortinet FortiGate provenance (issue #606) — wrapper block for a mirrored
    # FortiGate interface CIDR. Cascades on firewall delete.
    fortinet_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fortinet_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Cisco Meraki provenance (issue #606) — wrapper block for a mirrored
    # Meraki VLAN subnet. Cascades on org delete.
    meraki_org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("meraki_org.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # DNS assignment (propagates to child blocks and subnets unless overridden)
    dns_group_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    dns_zone_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_additional_zone_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    dns_inherit_settings: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Block-level split-horizon (issue #25). Inheritable to descendant
    # subnets via the existing ``dns_inherit_settings`` walk. False by
    # default — operators opt in per-block (or per-subnet) so existing
    # IPAM trees keep their single-zone publishing semantics.
    dns_split_horizon: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # DHCP assignment — same inherit-from-parent semantics as DNS. When
    # ``dhcp_inherit_settings`` is True we walk up the block chain (and
    # finally the space) for the effective server group.
    dhcp_server_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )
    dhcp_inherit_settings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # DDNS — same inherit-from-parent walk as DNS / DHCP. When
    # ``ddns_inherit_settings`` is True we walk up the block chain (and
    # finally the space) for the effective DDNS config. Override at any
    # level by flipping this toggle off and setting the four fields.
    ddns_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ddns_hostname_policy: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="client_or_generated",
        server_default=sa_text("'client_or_generated'"),
    )
    ddns_domain_override: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ddns_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ddns_inherit_settings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # ── Fragile-device probe suppression (issue #722) ─────────────────────
    # Mid-chain link. Deliberately has NO ``*_inherit_settings`` toggle:
    # unlike DDNS, this is a safety constraint, so it ORs downward rather
    # than being overridable by a descendant. See ``Subnet``.
    do_not_probe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    do_not_probe_reason: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )

    # ── VRF binding (issue #86) ───────────────────────────────────────────
    # Optional. NULL means "inherit from the parent block (recurse) or
    # ultimately from the IPSpace". Pinning a non-NULL value lets a
    # block live in a different VRF than its enclosing space — common
    # in hub-and-spoke designs where one space hosts blocks belonging
    # to multiple tenant VRFs.
    vrf_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vrf.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Optional BGP origin (issue #85). NULL = "inherit from the
    # parent block (recurse) or ultimately from the IPSpace".
    asn_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asn.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Logical ownership (issue #91). Inheritance is *not* implicit —
    # the issue ships an ownership tag, not a walk. Operators set
    # the tag explicitly at the level they want to query on.
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Back-reference to the IPAMTemplate (issue #26) that stamped this
    # block, if any. Lets a "reapply to all instances" sweep find every
    # block touched by a given template. SET NULL on template delete —
    # we don't want a template removal to take blocks with it.
    applied_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ipam_template.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Provenance for the NetBox one-shot importer (issue #36). ``netbox``
    # for blocks created by /ipam/import/netbox; NULL for hand-created
    # rows. ``imported_at`` is the wall-clock commit timestamp.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    space: Mapped[IPSpace] = relationship("IPSpace", back_populates="blocks")
    parent: Mapped["IPBlock | None"] = relationship("IPBlock", remote_side="IPBlock.id")
    children: Mapped[list["IPBlock"]] = relationship("IPBlock", back_populates="parent")
    subnets: Mapped[list["Subnet"]] = relationship("Subnet", back_populates="block")


class Subnet(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Primary managed unit. Routable network; IPs are allocated here."""

    __tablename__ = "subnet"
    __table_args__ = (
        Index("ix_subnet_network", "network"),
        Index("ix_subnet_decom_date", "decom_date"),
        Index(
            "ix_subnet_bgp_should_advertise",
            "bgp_should_advertise",
            postgresql_where=sa_text("bgp_should_advertise = true"),
        ),
        # Fragile-device probe suppression (#722). Partial because the
        # flagged rows are a small minority in any real estate, so the
        # index is tiny and turns the discovery dispatcher's per-tick
        # question into an index scan. Declared here as well as in the
        # migration so autogenerate sees it and reports no drift.
        Index(
            "ix_subnet_do_not_probe",
            "do_not_probe",
            postgresql_where=sa_text("do_not_probe"),
        ),
        # Subnets cannot overlap within the same IP space (enforced at application layer)
    )

    space_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_space.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    block_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_block.id", ondelete="RESTRICT"), nullable=False
    )
    router_zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("router_zone.id", ondelete="SET NULL"), nullable=True
    )
    vlan_ref_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vlan.id", ondelete="SET NULL"), nullable=True, index=True
    )

    network: Mapped[str] = mapped_column(CIDR, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Discriminator that forks IPAM tree rendering + endpoint
    # behaviour (issue #126 Phase 2). Auto-set from the network
    # CIDR on create:
    #   - ``unicast`` (default) for any subnet outside the IANA
    #     multicast ranges
    #   - ``multicast`` when the CIDR sits inside ``224.0.0.0/4``
    #     (v4) or ``ff00::/8`` (v6)
    #
    # IP-allocation endpoints refuse on ``multicast`` subnets —
    # multicast addresses are stream identities tracked by
    # ``MulticastGroup`` rather than per-endpoint IPAM rows.
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unicast", server_default="unicast"
    )

    # Layer 2
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vxlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Routing
    gateway: Mapped[str | None] = mapped_column(INET, nullable=True)

    # DNS integration (FK to DNS models added in Phase 2)
    dns_servers: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    domain_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # DNS assignment (mirrors ip_block fields; inherits from parent block unless overridden)
    dns_group_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    dns_zone_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_additional_zone_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    dns_inherit_settings: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Per-subnet opt-in for split-horizon multi-zone publishing
    # (issue #25). When False the IP picker stays single-group like
    # today. When True the picker becomes a multi-select grouped by
    # DNS server group; ``IPAddress.extra_zone_ids`` carries the
    # extra picks. Inheritable from the parent block via the
    # existing ``dns_inherit_settings`` walk.
    dns_split_horizon: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # DHCP assignment — same inherit-from-parent semantics as DNS.
    dhcp_server_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )
    dhcp_inherit_settings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # DDNS — dynamic DNS from DHCP leases. Independent of Kea's own DDNS
    # hook (which lives on ``DHCPScope``): this set of fields drives
    # SpatiumDDI's reconciliation layer — when a lease lands (via agent
    # push or the agentless lease pull), the DDNS service resolves a
    # hostname per ``ddns_hostname_policy`` and calls the same
    # ``_sync_dns_record`` path that static allocations use.
    #
    # Policy values:
    #   ``client_provided``      — only write if the lease has a hostname
    #   ``client_or_generated``  — use client hostname if present, else
    #                              generate ``dhcp-<hyphenated-ip>``
    #   ``always_generate``      — always synthesise, ignore client hostname
    #   ``disabled``             — never fire DDNS on this subnet
    #
    # ``ddns_enabled`` is the master toggle; the policy is only read when
    # enabled. ``ddns_ttl`` overrides the zone-level TTL for
    # auto-generated records. ``ddns_domain_override`` lets the operator
    # publish DDNS into a different zone (e.g. ``dhcp.corp.example.com``
    # rather than ``corp.example.com``) without affecting manual IPAM
    # allocations.
    ddns_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ddns_hostname_policy: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="client_or_generated",
        server_default=sa_text("'client_or_generated'"),
    )
    ddns_domain_override: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ddns_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Inherit DDNS config from the parent block chain + space. When True,
    # the four ddns_* fields above are ignored in favour of the first
    # non-inheriting ancestor's values. Default True so enabling DDNS at
    # the space level cascades automatically.
    ddns_inherit_settings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # ── Device profiling — auto-nmap on new DHCP leases ──────────────
    # When enabled, a fresh DHCP lease landing in this subnet enqueues
    # an active nmap scan against the leased IP via the existing
    # NmapScan pipeline. ``auto_profile_preset`` picks one of the
    # PRESETS keys in services/nmap/runner.py (default
    # ``service_version`` — gives OS hints + open services without the
    # heavyweight ``aggressive`` flag). ``auto_profile_refresh_days``
    # is the dedupe window: the same (mac, ip) pair won't re-scan
    # within this many days of its last profile, so churning Wi-Fi
    # leases don't spawn back-to-back scans.
    #
    # Tradeoffs intentionally exposed in the UI: nmap from the
    # SpatiumDDI host shows up as a port-scan to corporate IDS, so
    # the toggle is default-off and operators have to opt in per
    # subnet. See CLAUDE.md "Device profiling" entry for the full
    # design. (Block/space inheritance intentionally omitted in Phase 1 —
    # added once operators ask for cascade.)
    auto_profile_on_dhcp_lease: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    auto_profile_preset: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="service_and_os",
        server_default=sa_text("'service_and_os'"),
    )
    auto_profile_refresh_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default=sa_text("30")
    )

    # ── IP discovery — opt-in scheduled ping/ARP sweep (issue #23) ────
    # When enabled, a Celery beat task periodically sweeps this subnet
    # for live hosts (unprivileged ICMP with a TCP-connect fallback) +
    # reads the worker's ARP table, stamping ``last_seen_at`` /
    # ``last_seen_method`` on existing rows and inserting
    # ``status='discovered'`` rows for live IPs not yet in IPAM.
    # Default-off + per-subnet because a sweep is only meaningful for
    # subnets the worker can actually reach, and unsolicited probes can
    # trip an IDS. Locked rows (``user_modified_at`` set) and dynamic
    # DHCP pool ranges are never auto-created/clobbered. ``last_discovery_at``
    # gates the beat dispatcher the same way ``next_poll_at`` gates the
    # SNMP poller — change the interval in the UI and it takes effect
    # without restarting beat.
    discovery_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    discovery_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=360, server_default=sa_text("360")
    )
    last_discovery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Fragile-device probe suppression (issue #722) ─────────────────
    # "Do not send SpatiumDDI's own active probes at anything in here."
    #
    # Medical- and OT-device vendors explicitly instruct sites not to
    # scan their VLANs — Swisslog's pneumatic-tube guide says to omit
    # ping sweeps and nmap of any range supporting the PTS, and the same
    # hazard covers patient monitors and the PLC / RTU class ``network.ot``
    # already registers. Fragile IP stacks fault or drop off the network
    # under a sweep. Until this flag existed there was no way to say so.
    #
    # Three properties of these two columns are load-bearing:
    #
    # 1. **It ORs down the space → block → subnet chain, and there is no
    #    per-level inherit toggle.** DDNS resolves to the first
    #    non-inheriting ancestor, so a descendant can override its
    #    parent. That shape is wrong for a safety constraint: a hospital
    #    that marks the clinical IPSpace do-not-probe must not have a
    #    single subnet quietly opt back in. Any level saying "do not
    #    probe" wins, and nothing downstream can un-say it. See
    #    ``app.services.ipam.probe_policy``.
    # 2. **It is not gated behind a vertical feature module.** It is a
    #    constraint on *our* behaviour and a correctness fix to three
    #    already-shipped features (#23 discovery sweeps, ``tools.nmap``,
    #    ``tools.network``), so hiding it behind a default-off module
    #    would leave the sites that need it unprotected by default.
    # 3. **The reason travels with the flag.** Every refusal quotes it
    #    back, because "422 — subnet marked do-not-probe" without "these
    #    are Alaris pumps, per vendor bulletin X" just gets overridden by
    #    the next operator who hits it.
    #
    # The flag suppresses probes; it does not hide the subnet, block
    # allocation, or affect passive collection (PCAP #59, DHCP
    # fingerprinting, ARP-table reads) — passive observation was never
    # the hazard.
    do_not_probe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    do_not_probe_reason: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )

    # The create-time opt-out from the auto reverse zone (#2735). Stored, because
    # the zone is also created by the catch-up every address sync runs and by a
    # resize, and neither can see the request that said "no".
    skip_reverse_zone: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # Presentational (#2137): show the green "N free · click to allocate"
    # gap rows between allocated addresses. NULL = use the default (off
    # for integration-owned subnets and anything larger than a /16);
    # an explicit True / False overrides it. No effect on allocation or
    # utilization.
    show_free_ranges: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # IPv6 auto-allocation policy (ignored for IPv4 subnets — those use
    # PlatformSettings.ip_allocation_strategy which is sequential /
    # random only). Values:
    #
    #   "random"     (default) CSPRNG 64-bit host suffix + DB uniqueness
    #                retry. Right default for /64 LAN subnets where the
    #                host space is too large to sequentially enumerate.
    #   "eui64"      Derive the 64-bit host suffix from the MAC address
    #                per RFC 4291 §2.5.1 — requires a MAC on the request.
    #                Falls back to "random" if no MAC was supplied.
    #   "sequential" First-free linear scan (same 65k cap used for v4).
    #                Only sane for small v6 subnets (>= /112 or so);
    #                exposed for LAB / point-to-point /127 cases.
    ipv6_allocation_policy: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="random",
        server_default=sa_text("'random'"),
    )

    # Status: active | deprecated | reserved | quarantine
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", index=True)

    # ── Compliance / classification flags ────────────────────────────
    # First-class booleans rather than freeform tags so auditor queries
    # ("show me every PCI subnet, owner, last changed") are clean
    # indexed predicates. Subnet-level only (not block / space) — the
    # ask is precise scope tagging, not inheritance. Each column is
    # individually indexed (partial index, ``WHERE col = true``) so
    # the Compliance dashboard's three filtered lists each hit an
    # index without competing with a single composite key. See
    # ``/admin/compliance``.
    pci_scope: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    hipaa_scope: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    internet_facing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # Planned decommission date (issue #46). NULL = no scheduled decom.
    # Indexed (``ix_subnet_decom_date``) so the ``decom_expiring`` alert
    # rule and the admin dashboard widget can scan "decom within N days"
    # cheaply. Date-only — operators schedule decoms by calendar day,
    # not to the second.
    decom_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # Network-role classification (issue #112 phase 2). Pure metadata —
    # no behaviour change in the Kea / BIND drivers. Drives the IPAM
    # filter chip, the VLAN page "Voice" tag, the
    # ``voice_segment_not_internet_facing`` conformity check, and the
    # ``voice_lease_count_below`` alert rule. NULL means "unspecified"
    # so existing rows are not retroactively misclassified. Values:
    # ``data`` / ``voice`` / ``management`` / ``guest``.
    subnet_role: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # BGP Looking Glass "should be advertised" flag (issue #566 Phase
    # 5). Pure operator intent — the collector is receive-only and
    # never advertises anything; this just marks "the network is
    # SUPPOSED to be carrying this prefix over BGP somewhere" so the
    # bgp_lg_missing_advertisement alert has an owned-intent signal to
    # check the live RIB against. Indexed (partial, WHERE true) so the
    # alert's scan stays cheap regardless of subnet-table size.
    bgp_should_advertise: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # Kubernetes integration provenance. When set, the subnet was auto-
    # created by the Kubernetes reconciler for this cluster; the FK
    # cascade-deletes mirrored subnets when the cluster row is dropped.
    kubernetes_cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kubernetes_cluster.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Pod / Service CIDR subnets are routed overlays without LAN
    # semantics — no broadcast, no gateway, the full range is usable
    # pod / service IP space. Suppresses the network / broadcast /
    # gateway placeholder rows that ``POST /ipam/subnets`` normally
    # inserts, and tells the UI not to offer edit controls for those
    # LAN-specific fields.
    kubernetes_semantics: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # Docker integration provenance. Same cascade semantics as the
    # Kubernetes FK above. Docker bridge networks DO carry LAN
    # semantics (gateway + broadcast), so there's no docker_semantics
    # flag — the reconciler creates these subnets with normal LAN
    # placeholder rows.
    docker_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("docker_host.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Proxmox integration provenance. Bridges + VLAN interfaces on a
    # PVE node carry a real LAN CIDR (gateway + broadcast) so normal
    # placeholder rows apply, same as Docker.
    proxmox_node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("proxmox_node.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Tailscale integration provenance. Subnets created by the
    # Tailscale reconciler under the auto-created CGNAT + IPv6 ULA
    # blocks. Tailnet IPs are routed overlays without LAN semantics
    # (no broadcast, no gateway), so the reconciler sets this with
    # ``kubernetes_semantics=True`` analogue logic — but we don't
    # need a separate flag because we don't allocate sub-subnets in
    # the CGNAT block; every device IP lives in one big subnet.
    tailscale_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tailscale_tenant.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # UniFi integration provenance — networks pulled via the legacy
    # ``rest/networkconf`` endpoint. UniFi networks are real LAN CIDRs
    # with gateway + broadcast, so normal placeholder rows apply
    # (same as Docker / Proxmox). Cascades on controller delete.
    unifi_controller_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("unifi_controller.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Cloud integration provenance (issue #37). Set on subnets the Cloud
    # reconciler mirrors from a VPC subnet. Cloud subnets are routed
    # overlays whose first usable host is the gateway by convention
    # (x.x.x.1 on AWS/Azure/GCP) but carry no broadcast row — the
    # reconciler creates them with ``kubernetes_semantics``-style
    # suppression. Cascades on endpoint delete.
    cloud_endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_endpoint.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # OPNsense provenance (issue #31). Set on subnets mirrored from a
    # firewall interface CIDR (LAN / OPT* / VLAN). These are real LANs
    # — gateway + broadcast apply, unlike a Proxmox plain bridge.
    # Cascades on firewall delete.
    opnsense_router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("opnsense_router.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # NetBird provenance (issue #603). Subnet created by the NetBird
    # reconciler under the auto-created overlay block. Peer IPs are a
    # routed overlay (no broadcast / gateway), so the whole range is
    # one flat subnet. Cascades on instance delete.
    netbird_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("netbird_instance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Palo Alto PAN-OS / Panorama provenance (issue #605). Set on subnets the
    # PAN-OS reconciler mirrors from zone/interface CIDRs. Cascades on delete.
    panos_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("panos_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Fortinet FortiGate provenance (issue #606) — subnets mirrored from a
    # FortiGate interface CIDR. Cascades on firewall delete.
    fortinet_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fortinet_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Cisco Meraki provenance (issue #606) — subnets mirrored from a Meraki
    # appliance VLAN. Cascades on org delete.
    meraki_org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("meraki_org.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Computed / cached. ``total_ips`` is BigInteger because IPv6 subnets can
    # be as large as 2^64 addresses (a /64 — the standard LAN size) which
    # overflows INT4. We still clamp at the BIGINT max (2^63 − 1) to keep
    # the math simple; utilization_percent remains a fraction and is
    # meaningless for /64s anyway.
    utilization_percent: Mapped[float] = mapped_column(nullable=False, default=0.0)
    total_ips: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    allocated_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    custom_fields: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Logical ownership (issue #91). Same shape as IPBlock — explicit,
    # no inheritance walk. Operators set these at the subnet level
    # when the customer / site only owns the subnet, or up at the
    # block level when the assignment is broader.
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Back-reference to the IPAMTemplate (issue #26) that stamped this
    # subnet, if any. SET NULL on template delete.
    applied_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ipam_template.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Provenance for the NetBox one-shot importer (issue #36). ``netbox``
    # for subnets created by /ipam/import/netbox; NULL for hand-created
    # rows. ``imported_at`` is the wall-clock commit timestamp.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    space: Mapped[IPSpace] = relationship("IPSpace", back_populates="subnets")
    block: Mapped[IPBlock | None] = relationship("IPBlock", back_populates="subnets")
    router_zone: Mapped[RouterZone | None] = relationship("RouterZone", back_populates="subnets")
    vlan_ref: Mapped["VLAN | None"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "VLAN", lazy="joined", foreign_keys=[vlan_ref_id]
    )
    addresses: Mapped[list["IPAddress"]] = relationship(
        "IPAddress", back_populates="subnet", cascade="all, delete-orphan"
    )


class IPAddress(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual IP address within a subnet."""

    __tablename__ = "ip_address"
    __table_args__ = (
        Index("ix_ip_address_address", "address"),
        Index("ix_ip_address_decom_date", "decom_date"),
        UniqueConstraint("subnet_id", "address", name="uq_ip_address_subnet_address"),
    )

    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnet.id", ondelete="CASCADE"), nullable=False, index=True
    )

    address: Mapped[str] = mapped_column(INET, nullable=False)

    # status: available | allocated | reserved | dhcp | static_dhcp |
    #          discovered | orphan | deprecated
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="available", index=True)

    # Role describes what the IP *is*, orthogonal to status. Allowed values
    # live in ``IP_ROLES``; null means uncategorised. Roles in
    # ``IP_ROLES_SHARED`` bypass MAC-collision warnings (intentional sharing).
    role: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Reservation TTL — only meaningful when status='reserved'.
    # The sweep_expired_reservations beat task flips expired rows to
    # 'available' and clears this column.  Null = indefinite reservation.
    reserved_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Planned decommission date (issue #46). NULL = no scheduled decom.
    # Indexed (``ix_ip_address_decom_date``) for the decom-awareness
    # reports + alert. Date-only, same rationale as ``Subnet.decom_date``.
    decom_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    fqdn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Ownership
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    owner_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("group.id", ondelete="SET NULL"), nullable=True
    )
    managed_by: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Discovery
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # last_seen_method: ping | arp | dhcp | manual | snmp
    last_seen_method: Mapped[str | None] = mapped_column(String(20), nullable=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    custom_fields: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # ── Linkage fields (written by Wave 3 DDNS / DHCP integration) ──
    # Forward zone hosting the A/AAAA record for this IP's FQDN.
    forward_zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dns_zone.id", ondelete="SET NULL"), nullable=True
    )
    # Additional zones to publish into beyond the singular
    # ``forward_zone_id`` — issue #25 split-horizon. Each entry is a
    # zone UUID; the IPAM → DNS sync emits one A/AAAA record per
    # distinct (forward_zone + each entry). Ordering preserved on
    # round-trip. Default empty list = current behaviour (one
    # record). Each zone implicitly carries its DNS server group
    # via the existing ``DNSZone.group_id`` FK so multi-group fanout
    # is implicit.
    extra_zone_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # Reverse zone hosting the PTR record for this IP.
    reverse_zone_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dns_zone.id", ondelete="SET NULL"), nullable=True
    )
    # Linked DNS record (A/AAAA).
    dns_record_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dns_record.id", ondelete="SET NULL"), nullable=True
    )
    # DHCP linkage: stored as a string (the DHCP models didn't exist yet when
    # this column landed).
    dhcp_lease_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Back-link to the reservation that owns this row (mirror of the forward
    # ``DHCPStaticAssignment.ip_address_id`` FK).
    #
    # Still a bare string, NOT a foreign key: as a varchar it can dangle, and it
    # did — a scope hard-delete/purge removes reservations via FK CASCADE (or a
    # Core DELETE), neither of which runs Python, so nothing released the mirror
    # and this row was left stranded at ``status="static_dhcp"`` pointing at a
    # reservation Postgres had already dropped (#618). Fixed at the behavioural
    # level: the destruction paths now call
    # ``services.dhcp.static_ipam.detach_ipam_for_static`` first — see that
    # module's docstring for the wired-in list, and for the one known gap
    # (the Windows scope-sync reconciler) that still needs a re-point pass.
    #
    # Making it a real ``uuid`` FK (ON DELETE SET NULL) would make the dangle
    # unrepresentable, but retyping varchar → uuid in one shot breaks the
    # rolling-upgrade contract (#296): during the mixed-version window N-1 pods
    # still compare this column against a Python ``str``, which Postgres cannot
    # coerce to ``uuid``. It needs the two-release expand/contract treatment —
    # deferred, tracked on #618.
    static_assignment_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # True if the row was auto-created from a live DHCP lease (as opposed to
    # being manually allocated or from a static assignment). When the lease
    # expires the row is removed automatically; a manually-allocated row
    # with the same IP wouldn't be.
    auto_from_lease: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # Set by the Kubernetes reconciler when this row mirrors a k8s
    # Node or LoadBalancer Service VIP. Null on all non-k8s rows. FK
    # cascades on cluster delete so we never leak orphans.
    kubernetes_cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kubernetes_cluster.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Same pattern for the Docker reconciler — set on containers
    # that are mirrored in, null otherwise.
    docker_host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("docker_host.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Proxmox provenance — set on rows mirrored from a PVE VM or LXC.
    # Cascades on endpoint delete.
    proxmox_node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("proxmox_node.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Tailscale provenance — set on rows mirrored from a tailnet
    # device. Cascades on tenant delete.
    tailscale_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tailscale_tenant.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # UniFi provenance — set on rows mirrored from a UniFi client
    # (active or fixed-IP reservation). Cascades on controller delete.
    unifi_controller_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("unifi_controller.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Cloud provenance (issue #37) — set on rows mirrored from an
    # instance NIC (cloud-instance), public IP (cloud-public), or
    # load-balancer frontend (cloud-lb). Cascades on endpoint delete.
    cloud_endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_endpoint.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # OPNsense provenance (issue #31) — set on rows mirrored from a
    # DHCPv4 lease (status="dhcp"), static reservation
    # (status="reserved"), or ARP entry (status="opnsense-arp").
    # Cascades on firewall delete.
    opnsense_router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("opnsense_router.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # NetBird provenance (issue #603) — set on rows mirrored from a
    # NetBird peer's overlay IP. Cascades on instance delete.
    netbird_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("netbird_instance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Palo Alto PAN-OS / Panorama provenance (issue #605). Set on IP rows the
    # PAN-OS reconciler mirrors from DHCP leases. Cascades on firewall delete.
    panos_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("panos_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Fortinet FortiGate provenance (issue #606) — IP rows mirrored from a
    # FortiGate DHCP lease. Cascades on firewall delete.
    fortinet_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fortinet_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Cisco Meraki provenance (issue #606) — IP rows mirrored from a Meraki DHCP
    # fixed-IP reservation or client. Cascades on org delete.
    meraki_org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("meraki_org.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # ── Device profiling — populated by the auto-profile pipeline ────
    # ``last_profiled_at`` is the timestamp of the last *successful*
    # profile scan; the dedupe gate in services/profiling/auto_profile.py
    # uses it together with the subnet's ``auto_profile_refresh_days``
    # to decide whether a fresh lease should re-trigger a scan.
    # ``last_profile_scan_id`` deep-links to the NmapScan row that
    # produced the most recent result, so the IP detail modal can
    # render the full scan output without denormalising it here.
    last_profiled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_profile_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("nmap_scan.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Device profile — passive layer (Phase 2) ─────────────────────
    # Denormalised fingerbank lookup result for fast list rendering.
    # Source of truth is ``dhcp_fingerprint`` keyed by MAC; the
    # fingerprint task stamps these three columns whenever a fresh
    # lookup lands. Operators with edits on the row (``user_modified_at``
    # not null) keep their values — the stamper respects the same
    # lock the integration reconcilers use. nmap OS-detection
    # populates the same surface (``os.name`` → ``device_type``) so
    # the IP detail modal can render one consistent "device" line
    # whether enrichment came from passive DHCP or active nmap.
    device_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    device_class: Mapped[str | None] = mapped_column(String(50), nullable=True)
    device_manufacturer: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # Stamped by the API write path when an operator edits the row's
    # soft fields (hostname / description / status / mac_address).
    # While non-null, integration reconcilers (Proxmox / Docker /
    # Kubernetes) treat those soft fields as locked and skip overwrites
    # — so a VM rename in PVE doesn't blow away an operator-chosen IPAM
    # name, and a row that pre-existed before the integration was
    # enabled keeps its operator-chosen values when the reconciler
    # claims it. ``subnet_id`` is always updated regardless of the lock
    # — that's a factual binding between address and subnet, not an
    # operator preference. Cleared by the reconciler when the row is
    # un-claimed (integration-owned but no longer in the upstream
    # snapshot, with the operator's edits preserved).
    user_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Provenance for the NetBox one-shot importer (issue #36). ``netbox``
    # for addresses created by /ipam/import/netbox; NULL for hand-created
    # rows. ``imported_at`` is the wall-clock commit timestamp.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    subnet: Mapped[Subnet] = relationship("Subnet", back_populates="addresses")


class SubnetDomain(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Junction table linking a Subnet to one or more DNS zones.

    The subnet keeps a convenience `dns_zone_id` pointer to its primary
    domain; the SubnetDomain rows are the source of truth for the full set.
    """

    __tablename__ = "subnet_domain"
    __table_args__ = (
        UniqueConstraint("subnet_id", "dns_zone_id", name="uq_subnet_domain_subnet_zone"),
        Index("ix_subnet_domain_subnet_id", "subnet_id"),
        Index("ix_subnet_domain_dns_zone_id", "dns_zone_id"),
    )

    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnet.id", ondelete="CASCADE"), nullable=False
    )
    dns_zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dns_zone.id", ondelete="CASCADE"), nullable=False
    )
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class CustomFieldDefinition(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Administrator-defined metadata fields attached to IPAM and DNS resources."""

    __tablename__ = "custom_field_definition"
    __table_args__ = (
        UniqueConstraint("resource_type", "name", name="uq_custom_field_resource_name"),
    )

    # resource_type: subnet | ip_address | ip_block | dns_zone | dhcp_scope
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    # field_type: text | number | boolean | date | email | url | select | multi_select
    field_type: Mapped[str] = mapped_column(String(20), nullable=False, default="text")
    options: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # for select types
    is_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_searchable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    default_value: Mapped[str | None] = mapped_column(String(500), nullable=True)
    display_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class IpMacHistory(UUIDPrimaryKeyMixin, Base):
    """Per-IP MAC observation log (upsert on every create/update with a MAC).

    Keyed on (ip_address_id, mac_address); last_seen bumped each touch.
    Cascades on IP delete.

    Doubles as the new-device-watch sighting store (issue #459): each row's
    ``classification`` distinguishes a never-before-seen MAC (``new``) from one
    the operator has acknowledged (``acknowledged``) or that is part of the
    known fleet / allowlist (``known``). ``source`` records which ingestion path
    first/last touched it; ``is_randomized`` flags a locally-administered
    (privacy-randomised) MAC so the ``new_mac_seen`` alert can skip it by
    default and avoid a reconnection storm.
    """

    __tablename__ = "ip_mac_history"
    __table_args__ = (
        UniqueConstraint("ip_address_id", "mac_address", name="uq_ip_mac_history_ip_mac"),
        Index("ix_ip_mac_history_ip_address_id", "ip_address_id"),
        Index("ix_ip_mac_history_last_seen", "last_seen"),
        Index("ix_ip_mac_history_classification", "classification"),
    )

    ip_address_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_address.id", ondelete="CASCADE"),
        nullable=False,
    )
    mac_address: Mapped[str] = mapped_column(MACADDR, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )
    # new | acknowledged | known  (issue #459)
    classification: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=sa_text("'new'")
    )
    # sweep | snmp | dhcp_lease | l2_sniff  — which path first/last observed it
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=sa_text("'sweep'")
    )
    # Locally-administered (privacy-randomised) MAC — second-least-significant
    # bit of the first octet is set. Flagged, not alerted, by default.
    is_randomized: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa_text("false")
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )


class MACAllowlist(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Operator-curated set of trusted MACs that never raise a new-device alert.

    Keyed on the MAC itself (or an OUI prefix for vendor/virtualisation
    allowlisting, e.g. ``005056`` for VMware), so a trusted device stays quiet
    wherever it shows up — independent of the ``ip_mac_history`` rows it
    generates, which cascade-delete with their IP. At least one of
    ``mac_address`` / ``oui_prefix`` must be set (issue #459).
    """

    __tablename__ = "mac_allowlist"
    __table_args__ = (
        UniqueConstraint("mac_address", name="uq_mac_allowlist_mac"),
        CheckConstraint(
            "mac_address IS NOT NULL OR oui_prefix IS NOT NULL",
            name="ck_mac_allowlist_one_key",
        ),
        Index("ix_mac_allowlist_mac", "mac_address"),
        # Partial-unique so an OUI prefix can't be allowlisted twice (the DB is
        # the source of truth, not a racy check-then-insert). NULLs are exempt
        # (rows keyed on mac_address only).
        Index(
            "uq_mac_allowlist_oui_prefix",
            "oui_prefix",
            unique=True,
            postgresql_where=sa_text("oui_prefix IS NOT NULL"),
        ),
    )

    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    # 6 hex chars, lower-case, no separators (e.g. "005056"); matches any MAC
    # whose first three octets equal this prefix.
    oui_prefix: Mapped[str | None] = mapped_column(String(6), nullable=True)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # True for the seeded virtualisation-vendor rows; lets the UI distinguish
    # platform defaults from operator entries (cloned but not deleted).
    is_builtin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sa_text("false")
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )


class NATMapping(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Operator-curated NAT/PAT mapping for IPAM cross-reference.

    Three kinds: ``1to1`` (static NAT), ``pat`` (port translation),
    ``hide`` (many-to-one masquerade). SpatiumDDI records but does not
    push these rules; they surface as a nat_mapping_count badge on IP rows.

    Both internal and external IPs carry an optional FK to ``ip_address``
    in addition to the raw INET string. The FK is auto-resolved on
    write when the typed string matches an existing IPAM row; the
    string stays authoritative so external IPs not tracked in IPAM
    (e.g. a public WAN address) still work. ``ON DELETE SET NULL``
    so deleting an IPAM row leaves the NAT history intact.
    """

    __tablename__ = "nat_mapping"
    __table_args__ = (
        Index("ix_nat_mapping_internal_ip", "internal_ip"),
        Index("ix_nat_mapping_external_ip", "external_ip"),
        Index("ix_nat_mapping_internal_subnet_id", "internal_subnet_id"),
        Index("ix_nat_mapping_internal_ip_address_id", "internal_ip_address_id"),
        Index("ix_nat_mapping_external_ip_address_id", "external_ip_address_id"),
    )

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)  # 1to1 | pat | hide

    internal_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    internal_ip_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_address.id", ondelete="SET NULL"), nullable=True
    )
    internal_subnet_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnet.id", ondelete="SET NULL"), nullable=True
    )
    internal_port_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    internal_port_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    external_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    external_ip_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_address.id", ondelete="SET NULL"), nullable=True
    )
    external_port_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    external_port_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="any")
    device_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    custom_fields: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Integration provenance (issue #605/#606). NULL for operator-entered rows;
    # set when a firewall reconciler mirrored this mapping from a NAT rule (PAN-OS
    # NAT / FortiGate VIP / Meraki 1:1-NAT + port-forward), so the mirror owns
    # (and sweeps) its rows on target delete. Manual rows stay untouched.
    # ``ON DELETE CASCADE`` — a firewall delete removes the NAT rows it created.
    panos_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("panos_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    fortinet_firewall_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("fortinet_firewall.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    meraki_org_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("meraki_org.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )


class VLANMapping(UUIDPrimaryKeyMixin, Base):
    """Reference table tracking VLAN → VXLAN mappings."""

    __tablename__ = "vlan_mapping"
    __table_args__ = (UniqueConstraint("space_id", "vlan_id", name="uq_vlan_mapping_space_vlan"),)

    space_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_space.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    vxlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")


class SubnetPlan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Operator-designed multi-level CIDR plan, applied transactionally.

    The ``tree`` JSONB carries the planned hierarchy. Each node has the
    shape::

        {
            "id":          "node-uuid",          // client-stable id (DnD)
            "network":     "10.0.0.0/16",        // CIDR
            "name":        "Datacenter East",    // operator-friendly label
            "description": "...",
            "children":    [ ... ],              // nested nodes
        }

    The root node may carry ``"existing_block_id": "<uuid>"`` to anchor the
    plan inside an already-existing IPBlock. When set, apply does not
    re-create the root — only the descendants are materialised, with the
    existing block as their parent. When null, the root itself becomes a
    new top-level block in the bound IPSpace on apply.

    A node with children = an IPBlock; a leaf = a Subnet. The kind is
    inferred from tree shape so the operator doesn't have to toggle a
    per-node flag.

    ``applied_at`` is set the first time the plan is applied; once
    applied, the plan is immutable (the materialised IPAM rows are the
    source of truth). ``applied_resource_ids`` records what was
    created so operators can audit "this plan produced these blocks +
    subnets".
    """

    __tablename__ = "subnet_plan"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    space_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_space.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tree: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    applied_resource_ids: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    space: Mapped["IPSpace"] = relationship("IPSpace")


class IPAMTemplate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Reusable stamp template for IPBlocks or Subnets (issue #26).

    Carries default tags, custom-field values, DNS / DHCP group
    assignments, and DDNS settings. ``applies_to`` locks each row to
    one carrier ('block' or 'subnet') — same template can't stamp
    both because the apply-time semantics (child_layout, DDNS
    inheritance gate, etc.) diverge.

    Templates STAMP at apply time. Inheritance LOOKS UP at read
    time. Re-apply is the operator-driven way to refresh stamp
    values after a template edit.
    """

    __tablename__ = "ipam_template"
    __table_args__ = (UniqueConstraint("name", name="uq_ipam_template_name"),)

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # 'block' | 'subnet' — enforced by CHECK constraint at the DB
    # layer + Pydantic at the API layer.
    applies_to: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    custom_fields: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    dns_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Stored as text since the rest of the IPAM tree treats DNS zone
    # IDs as opaque strings — see ``Subnet.dns_zone_id``.
    dns_zone_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    dns_additional_zone_ids: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    dhcp_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="SET NULL"),
        nullable=True,
    )

    # DDNS settings stamped onto the carrier on apply. Note we
    # deliberately do NOT mirror ``ddns_inherit_settings`` — a
    # template's whole point is to lock in a config, not to inherit
    # upstream. Apply always sets ``ddns_inherit_settings=False`` on
    # the target when any of these four fields are non-null.
    ddns_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ddns_hostname_policy: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="client_or_generated",
        server_default=sa_text("'client_or_generated'"),
    )
    ddns_domain_override: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ddns_ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Optional sub-subnet layout. Only valid when applies_to='block'.
    # Schema:
    #   {"children": [
    #       {"prefix": int, "name_template": str,
    #        "description"?: str, "tags"?: dict, "custom_fields"?: dict}
    #   ]}
    # Children are carved with the standard split logic on apply;
    # name_template supports the same {n} / {oct1}–{oct4} tokens as
    # bulk-allocate.
    child_layout: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class SubnetUtilizationHistory(UUIDPrimaryKeyMixin, Base):
    """Daily snapshot of a subnet's IP utilization (#44).

    One row per subnet per daily sample; powers the 30 / 90-day "% used
    over time" chart on the subnet detail. Storage piggy-backs on the
    already-maintained ``Subnet.allocated_ips`` / ``total_ips`` columns —
    the snapshot beat task just records them. 90-day retention is enforced
    by that task's prune pass, so the table stays bounded
    (subnets × ~90 rows).
    """

    __tablename__ = "subnet_utilization_history"

    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subnet.id", ondelete="CASCADE"),
        nullable=False,
    )
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    allocated_ips: Mapped[int] = mapped_column(Integer, nullable=False)
    total_ips: Mapped[int] = mapped_column(BigInteger, nullable=False)

    __table_args__ = (Index("ix_subnet_util_hist_subnet_sampled", "subnet_id", "sampled_at"),)

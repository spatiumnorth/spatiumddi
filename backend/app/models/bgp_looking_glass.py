"""BGP Looking Glass — receive-only collector, sessions + learned RIB (issue #566).

The internal-table companion to the #527 public-table hijack monitor. Where
that watches the *public* routing table via RIPEstat / RIS Live, the Looking
Glass peers with the operator's own routers over real BGP sessions and turns
the live Adj-RIB-In into an operator surface — every prefix, origin ASN and
community linked back into IPAM / the ASN catalog / the community catalog.

Three tables:

* ``looking_glass_collector`` — the agent-registration identity row for a
  GoBGP collector daemon, one per appliance node (or standalone box). Shaped
  like ``DNSServer`` / ``DHCPServer``: the register/heartbeat endpoints upsert
  it keyed on ``agent_id``; ``BGPLGPeer.collector_id`` FKs to it. The daemon is
  a **pure sink** — no export policy, receive-only.

* ``bgp_lg_peer`` — a configured BGP session (one row per peer router). Carries
  the config the collector renders into the GoBGP neighbor block
  (``peer_asn`` / ``peer_address`` / ``address_families`` / ``max_prefixes`` /
  optional Fernet MD5) plus collector-reported runtime state
  (``session_state`` / ``prefixes_received`` / ``last_flap_at`` / …). The
  ``max_prefixes`` cap is a hard safety limit rendered into the daemon's
  ``prefix-limit`` — it protects the collector from a full-table blow-up.

* ``bgp_lg_route`` — the learned RIB, control-plane-side source of truth for the
  UI / IPAM linkage / alerts. One row per ``(peer, prefix, next_hop)`` path.
  Absence-reconcile marks a route ``withdrawn_at`` (NOT a hard delete) when it
  drops out of the peer's feed — mirroring the DHCP ``pull_leases`` shape, with
  the same zero-wire floor guard on the ingest side. ``matched_*_id`` FKs link a
  learned route to the IPAM block / subnet / space / ASN / VRF it falls under,
  populated at ingest by ``app.services.looking_glass.ipam_link`` (Phase 3) and,
  for ``matched_vrf_id`` specifically, overridden by a Route-Target cross-check
  against ``vrf.import_targets``/``export_targets`` when the route's
  ``ext_communities`` carry a hit (``app.services.looking_glass.vrf_match``,
  Phase 6) — see that module for the precedence rule.
  ``rpki_status`` reuses ``derive_rpki_status()`` from the #527 hijack monitor.

Distinct from #527 (public-table hijack monitor) and from the MetalLB VIP
advertiser — the collector *receives* routes, it never advertises.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
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
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class LookingGlassCollector(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A GoBGP receive-only collector daemon — the agent identity row.

    Upserted by the register/heartbeat endpoints keyed on ``agent_id``. Shaped
    like ``DNSServer`` / ``DHCPServer`` (agent bookkeeping) since it is itself an
    agent-managed resource, not a passively-polled discovery target.
    """

    __tablename__ = "looking_glass_collector"
    __table_args__ = (
        UniqueConstraint("agent_id", name="uq_looking_glass_collector_agent_id"),
        Index("ix_looking_glass_collector_name", "name"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )
    # Populated by the agent on register (its routable host / hostname).
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # status: unknown | active | unreachable | error
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="unknown", server_default=sa_text("'unknown'")
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # Agent bookkeeping — mirrors DNSServer / DHCPServer.
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_registered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    agent_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Source IP of the most recent agent heartbeat — operator-visible so a
    # NAT'd / distributed collector can be identified. See dns_server.last_seen_ip.
    last_seen_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── #882 last config-apply verdict ────────────────────────────────────
    #
    # Reported by the agent on every heartbeat. Distinct from ``status`` /
    # ``last_seen_at``, which only say whether the agent is TALKING to us:
    # a server can be reachable, healthy and answering queries while running
    # a config the operator never approved, because the one they saved was
    # rejected and the agent reverted to its last-known-good.
    #
    # ``config_apply_status`` values, mirroring the agent's
    # ``config_apply.py``:
    #   ok            — converged; the live config is the saved one
    #   reverted      — the saved bundle failed; running the previous one
    #   revert_failed — the saved bundle failed AND the revert failed
    #   no_previous   — failed with nothing to fall back to (first bundle)
    #
    # NULL means the agent has never reported (a pre-#882 agent, or an
    # agentless driver that has no apply loop at all). Treat NULL as
    # UNKNOWN, never as ``ok``.
    config_apply_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # The daemon's own words about why it refused — ``named-checkconf``
    # output, Kea's config-test text. Truncated agent-side to 2000 chars.
    config_apply_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # etag of the bundle that was rejected, so the operator can tell whether
    # the failure is still current or predates the config now saved.
    config_failed_etag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    config_apply_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Issue #197 shape — deleting the owning appliance sweeps its collector
    # rows via ON DELETE CASCADE. NULL for standalone / operator-registered
    # collectors (off-fleet box, manual register).
    appliance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )


class BGPLGPeer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A configured receive-only BGP session held by a collector."""

    __tablename__ = "bgp_lg_peer"
    __table_args__ = (
        # One receive-only session per (collector, neighbor address) — BGP has
        # a single session per neighbor IP, and two peers sharing a collector +
        # peer_address would render two GoBGP neighbor blocks with an identical
        # neighbor-address and collapse into one RIB attribution slot.
        UniqueConstraint("collector_id", "peer_address", name="uq_bgp_lg_peer_addr"),
        Index("ix_bgp_lg_peer_collector", "collector_id"),
        Index("ix_bgp_lg_peer_enabled", "enabled"),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    collector_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("looking_glass_collector.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ── Session config (rendered into the GoBGP neighbor block) ──────────
    local_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    peer_asn: Mapped[int] = mapped_column(BigInteger, nullable=False)
    peer_address: Mapped[str] = mapped_column(INET, nullable=False)

    # Denormalised link to a tracked ASN row when one exists (raw ``peer_asn``
    # stays the source of truth — a peer AS may have no local ASN row).
    matched_asn_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("asn.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Optional link to the SNMP-polled device this session terminates on.
    peer_router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("network_device.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Address families to negotiate, e.g. ["ipv4-unicast", "ipv6-unicast"].
    # vpnv4/vpnv6 accepted since issue #566 Phase 6 (see
    # app.services.looking_glass.vrf_match for the VRF Route-Target
    # cross-check that reads a matching route's ext_communities). EVPN
    # remains a later phase.
    address_families: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=sa_text("'[\"ipv4-unicast\"]'::jsonb"),
    )
    # Fernet-encrypted TCP-MD5 password. Never returned in plaintext; the API
    # exposes ``md5_password_set: bool`` computed inline. Rotate by supplying a
    # new value; omit/blank on PATCH keeps the stored ciphertext.
    md5_password_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Hard per-peer safety cap rendered into the GoBGP prefix-limit — protects
    # the sink from a full-table blow-up. Default enterprise-internal scale;
    # raise for full-table feeds. See issue #566 (decision D4).
    max_prefixes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10000, server_default=sa_text("10000")
    )
    # {"mode": "accept_all"} | {"mode": "scope", "prefixes": [...]} — scope the
    # accepted RIB to configured IPAM spaces / an explicit prefix list.
    import_filter: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {"mode": "accept_all"},
        server_default=sa_text('\'{"mode": "accept_all"}\'::jsonb'),
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    description: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )

    # ── Runtime state (collector-reported via heartbeat; "only overwrite when
    #    the agent actually sends a value") ────────────────────────────────
    # session_state: idle | connect | active | opensent | openconfirm | established
    session_state: Mapped[str] = mapped_column(
        String(24), nullable=False, default="idle", server_default=sa_text("'idle'")
    )
    uptime_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    prefixes_received: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    prefixes_accepted: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    last_state_change: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_flap_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rpki_invalid_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    # Watermark for the deferred bgp_lg_session_down grace-window alert
    # (harmless to ship the column now).
    down_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BGPLGRoute(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A learned route in a peer's Adj-RIB-In — the control-plane RIB mirror.

    Absence-reconcile sets ``withdrawn_at`` (never a hard delete) when the route
    drops out of the peer's feed. ``matched_*_id`` FKs link the route to the
    IPAM object it falls under (populated at ingest; see the module docstring).
    """

    __tablename__ = "bgp_lg_route"
    __table_args__ = (
        # ``route_distinguisher`` joined the identity in issue #566 Phase 6 —
        # a VPNv4/VPNv6 path's RD (RFC 4364) is the whole reason two VRFs can
        # originate the SAME customer prefix without collision; without it
        # here, two different VRFs' overlapping prefixes learned via the
        # same peer + next-hop (an ordinary shape — the PE's own loopback is
        # the next-hop for every VRF it serves) would silently overwrite
        # each other on this constraint. '' (not NULL) for plain
        # ipv4-unicast/ipv6-unicast routes — Postgres treats every NULL as
        # distinct in a UNIQUE constraint, so a nullable column here would
        # silently defeat the existing dedup semantics for ordinary routes.
        UniqueConstraint(
            "peer_id", "prefix", "next_hop", "route_distinguisher", name="uq_bgp_lg_route"
        ),
        Index("ix_bgp_lg_route_peer", "peer_id"),
        Index("ix_bgp_lg_route_origin_asn", "origin_asn"),
        Index("ix_bgp_lg_route_prefix", "prefix"),
        # Containment (``>>=`` / ``<<=``): btree cannot serve these, GiST can (#1255).
        Index(
            "ix_bgp_lg_route_prefix_gist",
            "prefix",
            postgresql_using="gist",
            postgresql_ops={"prefix": "inet_ops"},
        ),
        Index("ix_bgp_lg_route_rpki_status", "rpki_status"),
        # The "active RIB" scan — everything not withdrawn.
        Index(
            "ix_bgp_lg_route_active",
            "peer_id",
            "prefix",
            postgresql_where=sa_text("withdrawn_at IS NULL"),
        ),
        Index("ix_bgp_lg_route_matched_block", "matched_block_id"),
        Index("ix_bgp_lg_route_matched_subnet", "matched_subnet_id"),
        Index("ix_bgp_lg_route_matched_space", "matched_space_id"),
        Index("ix_bgp_lg_route_matched_asn", "matched_asn_id"),
        Index("ix_bgp_lg_route_matched_vrf", "matched_vrf_id"),
        Index("ix_bgp_lg_route_last_flap_at", "last_flap_at"),
        # Supports the VRF "Learned VPN Routes" tab / admin debug queries
        # filtering to VPN-carrying rows specifically.
        Index(
            "ix_bgp_lg_route_rd",
            "route_distinguisher",
            postgresql_where=sa_text("route_distinguisher != ''"),
        ),
    )

    peer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("bgp_lg_peer.id", ondelete="CASCADE"),
        nullable=False,
    )

    prefix: Mapped[str] = mapped_column(CIDR, nullable=False)
    # Denormalised origin (last AS in as_path) for the mismatch/link compares.
    origin_asn: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # JSONB list[int] (no native ARRAY anywhere in this repo — convention).
    as_path: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    next_hop: Mapped[str] = mapped_column(INET, nullable=False)
    local_pref: Mapped[int | None] = mapped_column(Integer, nullable=True)
    med: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Community wire-forms as JSONB list[str]; matched against the BGPCommunity
    # catalog by value at render time (no FK — same precedent as the ASN/hijack
    # subsystem).
    communities: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    large_communities: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # Extended communities carry the Route Target for VPNv4/VPNv6 routes;
    # matched against vrf.import_targets/export_targets at ingest (and by the
    # periodic re-resolve sweep) to populate matched_vrf_id — see
    # app.services.looking_glass.vrf_match (issue #566 Phase 6). This match
    # takes precedence over the plain IPAM-effective-VRF match (see
    # app.services.looking_glass.ipam_link) when a Route Target hit is
    # found. Note: this column does NOT carry the Route Distinguisher — RD
    # is part of the VPN-IPv4/VPN-IPv6 NLRI (RFC 4364), not an extended
    # community; it lives in the dedicated ``route_distinguisher`` column
    # below.
    ext_communities: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # Route Distinguisher for VPNv4/VPNv6 paths (RFC 4364) — part of the
    # NLRI, not an extended community. '' (not NULL) for plain
    # ipv4-unicast/ipv6-unicast routes (see the migration docstring and
    # uq_bgp_lg_route above for why NULL would silently break dedup).
    # Participates in route identity because RD's entire purpose is
    # letting two VRFs originate the same customer prefix without
    # collision (issue #566 Phase 6).
    route_distinguisher: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=sa_text("''")
    )

    # valid | invalid | unknown — reuses derive_rpki_status() at ingest.
    rpki_status: Mapped[str] = mapped_column(
        String(12), nullable=False, default="unknown", server_default=sa_text("'unknown'")
    )
    is_best: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # IPAM / entity linkage — SET NULL so deleting an IPAM row never corrupts
    # the live RIB row (the link is re-resolved on the next reconcile pass).
    # Populated Phase 3/6; columns present now so no later migration is needed.
    matched_block_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_block.id", ondelete="SET NULL"), nullable=True
    )
    matched_subnet_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnet.id", ondelete="SET NULL"), nullable=True
    )
    matched_space_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ip_space.id", ondelete="SET NULL"), nullable=True
    )
    matched_asn_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asn.id", ondelete="SET NULL"), nullable=True
    )
    matched_vrf_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vrf.id", ondelete="SET NULL"), nullable=True
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )
    # Absence-reconcile marker — set when the route leaves the peer's feed.
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    flap_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    # Timestamp of the most recent absence-withdraw bump on this row
    # (issue #566 Phase 5) — lets bgp_lg_route_flap require a RECENT
    # flap, not just a lifetime count, so a route that flapped a lot
    # months ago but has been stable since doesn't page forever. Stamped
    # by routes_ingest.py's absence-withdraw branch alongside
    # flap_count. Distinct from BGPLGPeer.last_flap_at (a peer SESSION
    # flap, different model/table) — this is a per-route
    # announce/withdraw flap.
    last_flap_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Vendor-attribute escape hatch (mirrors BGPHijackDetection.detail).
    detail: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


__all__ = ["LookingGlassCollector", "BGPLGPeer", "BGPLGRoute"]

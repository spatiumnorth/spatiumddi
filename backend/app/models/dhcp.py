"""DHCP data models — server groups, servers, scopes, pools, static
assignments, client classes, leases, and agent op queue.

Configuration lives on **DHCPServerGroup**: all servers in a group
serve the same scopes / pools / statics / client classes. A group
with a single Kea server is a standalone DHCP service; a group with
two Kea servers is implicitly an HA pair, using the group's mode +
tuning fields to drive the ``libdhcp_ha.so`` hook.

Per-server fields stay on **DHCPServer**: registration + agent state,
health, and the server's own HA peer URL (the listener endpoint the
partner calls). Leases are per-server — each Kea owns its own
memfile — and the ops queue is per-server.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.dhcp_device_policy import DHCPDevicePolicy

# ── Server Group / Server ────────────────────────────────────────────────────


class DHCPServerGroup(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Logical cluster of DHCP servers. Primary configuration container.

    All servers in a group render identical config bundles (except
    ``this-server-name`` under Kea HA). A group with two Kea members
    is an HA pair; the group's ``mode`` + HA tuning drive the
    ``libdhcp_ha.so`` hook. A single-member group is standalone and
    ignores HA fields.
    """

    __tablename__ = "dhcp_server_group"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # mode: load-balancing | hot-standby (only rendered when the group has >= 2 Kea peers)
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="hot-standby")

    # #170 Wave C2 — appliance-side container networking mode. The
    # supervisor reads this off the heartbeat response when rendering
    # the dhcp-kea compose snippet on a host with the ``dhcp`` role
    # assigned. Two values:
    #   * ``host`` — container shares the host's network namespace
    #     (today's behaviour). Required for receiving raw L2
    #     broadcasts from clients on the same broadcast domain.
    #   * ``bridged`` — container listens on the host IP UDP/67 only.
    #     For deployments where the DHCP server sits behind a relay
    #     (``ip helper-address`` / ``dhcrelay``) or a DMZ NAT. Does
    #     NOT receive local L2 broadcasts.
    network_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="host", server_default="host"
    )

    # Issue #365 — Kea ``dhcp-socket-type`` (inside ``interfaces-config``).
    # Distinct from ``network_mode`` above: that's the *container* network
    # namespace; this is how the Kea daemon reads packets off the wire. It
    # is a per-daemon setting (cannot vary per subnet), so it lives on the
    # group and applies to every member Kea.
    #   * ``direct`` → ``raw`` (AF_PACKET). Receives broadcast DISCOVERs
    #     from directly-attached clients that have no IP yet *and* relayed
    #     traffic — the superset, and Kea's own default. Needs CAP_NET_RAW
    #     (granted on the appliance DaemonSet + the compose Kea services).
    #   * ``relay`` → ``udp`` (datagram). Relay-only; cannot receive direct
    #     L2 broadcasts. Pick only when Kea sits exclusively behind a DHCP
    #     relay, or the runtime can't grant raw-socket capability.
    # Delivered to every deploy path (k8s/compose/appliance) via the
    # ConfigBundle long-poll — not the supervisor role assignment — so the
    # agent renders ``interfaces-config`` from it and the ETag shifts on
    # change.
    dhcp_socket_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="direct", server_default="direct"
    )

    # Kea HA hook tuning — rendered into libdhcp_ha.so config when the
    # group is an HA pair. Defaults mirror Kea's documented recommendations.
    heartbeat_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=10000)
    max_response_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=60000)
    max_ack_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=10000)
    max_unacked_clients: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    auto_failover: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Kea lease cache (issue #637) — group-wide default, overridable per scope.
    #
    # ``cache-threshold`` is a fraction of ``valid-lifetime``: when a client
    # re-requests a lease that still has more than (1 - threshold) of its
    # lifetime left, Kea hands back the SAME lease with an UNCHANGED expiry and
    # skips the lease-database write entirely.
    #
    # Kea 3.0 turns this on by default (0.25). We default to **0.0 (disabled)**
    # deliberately: SpatiumDDI's lease pipeline is driven by memfile CSV writes
    # (the agent tails the lease file and POSTs lease-events, which in turn feed
    # DDNS and the IPAM lease mirror). Caching suppresses those writes, so a
    # chatty client would stop producing lease events and its DDNS record /
    # IPAM ``last_seen`` would go stale. 0.0 preserves the pre-3.0 write-through
    # behaviour exactly; operators who want the reduced DB churn can opt in.
    #
    # ``cache-max-age`` caps how long a cached lease may be reused regardless of
    # the threshold. NULL = unset (Kea's own default: no cap).
    lease_cache_threshold: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, server_default=sa_text("0.0")
    )
    lease_cache_max_age: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # #980 — Kea ``multi-threading.thread-pool-size``, rendered explicitly
    # instead of left at Kea's own default of 0 ("auto").
    #
    # "Auto" means ``std::thread::hardware_concurrency()``: the number of CPUs
    # on the MACHINE, with no regard for the cgroup share the container
    # actually holds. On a 4 vCPU appliance Kea therefore starts four packet
    # workers that compete, inside one cgroup, with the single thread whose
    # only job is to drain the receive socket — and when that thread is late,
    # the kernel drops datagrams Kea never learns about. Fewer workers get the
    # receiver scheduled sooner; measured against kea-dhcp4 3.0.3 with the
    # memfile backend at 12,000 relayed pkt/s (median of 4 runs, packets
    # served):
    #
    #     cgroup CPU    pool=1     pool=2     pool=4 (what "auto" gives here)
    #     0.25          19,381     11,119      6,723
    #     4.0 (none)    93,717     73,089     55,957
    #
    # Monotonic in both shapes, so 1 is the default. It is a *pool* size, not
    # a thread count: MT stays enabled, so the receive thread is still
    # separate and every multi-threaded semantic (host-reservation lookup
    # order, ``dhcp-queue-control`` staying disabled) is unchanged — which is
    # why this rather than ``enable-multi-threading: false``, whose single
    # thread must both receive and process and measured 15,170 socket drops
    # in a run where pool=1 measured 0.
    #
    # Kea's HA hook does NOT keep independent HTTP pools by default:
    # ``http-listener-threads`` / ``http-client-threads`` default to 0, which
    # Kea reads as "same as thread-pool-size". Verified by counting OS
    # threads with the HA hook loaded — pool=1 gave 8 and pool=8 gave 29, a
    # delta of 21 for a pool delta of 7, i.e. three pools of N. So the agent
    # pins them (``_HA_HTTP_THREADS`` in ``render_kea.py``) and this setting
    # moves only the packet-worker pool.
    #
    # ``0`` restores Kea's auto-sizing for an operator who measures otherwise.
    kea_thread_pool_size: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=sa_text("1")
    )

    # #980 — per-packet logging, and whether it is worth its cost here.
    #
    # At severity INFO, Kea writes FOUR lines per transaction, to two
    # appenders, one of them flushed: ``DHCP4_QUERY_LABEL`` and
    # ``DHCP4_LEASE_ALLOC``/``_OFFER`` (from ``kea-dhcp4.dhcp4`` and
    # ``kea-dhcp4.leases``), plus ``DHCP4_PACKET_RECEIVED`` and
    # ``DHCP4_PACKET_SEND`` (from ``kea-dhcp4.packets``). Only the last two
    # are switched off here, and only they: measured on the same rig as
    # ``kea_thread_pool_size``, silencing that one child logger took packets
    # served from 19,026-20,403 to 24,997-26,077 — 1.30x — for lines whose
    # information is largely carried by the two that remain.
    #
    # ``kea-dhcp4.dhcp4`` is deliberately NOT part of this. It looks like the
    # other noisy one, and silencing it also loses ``DHCP4_OPEN_SOCKETS_FAILED``
    # (a real failure Kea logs at INFO), ``DHCP4_CONFIG_COMPLETE``,
    # ``DHCP4_STARTED`` and ``DHCP4_MULTI_THREADING_INFO`` — the last of which
    # is the line that reports the pool size above actually took effect.
    #
    # Defaults to True: OFF is a change an operator can SEE, since those two
    # codes carry the source address and receiving interface and no other line
    # does. Preserving observable behaviour and offering the throughput as an
    # opt-in is the same call #637 made for the lease cache. The #980 loss
    # counters are what tell an operator whether they are at the knee where
    # this is worth reaching for.
    kea_packet_logging: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # Eager-load `servers` by default. The API's group list endpoint
    # reads this relationship to compute `kea_member_count` + roll up
    # the members, and it runs in an async session where an accidental
    # sync lazy-load crashes with MissingGreenlet. selectin is one
    # extra small query per list call; not worth the footgun.
    servers: Mapped[list[DHCPServer]] = relationship(
        "DHCPServer",
        back_populates="group",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    scopes: Mapped[list[DHCPScope]] = relationship(
        "DHCPScope", back_populates="group", cascade="all, delete-orphan"
    )
    client_classes: Mapped[list[DHCPClientClass]] = relationship(
        "DHCPClientClass", back_populates="group", cascade="all, delete-orphan"
    )
    mac_blocks: Mapped[list[DHCPMACBlock]] = relationship(
        "DHCPMACBlock", back_populates="group", cascade="all, delete-orphan"
    )
    option_templates: Mapped[list[DHCPOptionTemplate]] = relationship(
        "DHCPOptionTemplate", back_populates="group", cascade="all, delete-orphan"
    )
    # #700 — fingerprint-driven device policies. Defined in its own module
    # (``models.dhcp_device_policy``) because it depends on the fingerprint
    # store rather than on anything in this file; the string target defers
    # resolution until both are imported.
    device_policies: Mapped[list[DHCPDevicePolicy]] = relationship(
        "DHCPDevicePolicy", back_populates="group", cascade="all, delete-orphan"
    )


class DHCPServer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual DHCP server (Kea instance or Windows DHCP) in a group."""

    __tablename__ = "dhcp_server"
    __table_args__ = (
        UniqueConstraint("name", name="uq_dhcp_server_name"),
        Index("ix_dhcp_server_agent_id", "agent_id", unique=True),
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # driver: kea | windows_dhcp
    driver: Mapped[str] = mapped_column(String(50), nullable=False, default="kea")
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=67)
    # roles: primary | secondary | standalone (JSON array of strings — informational)
    roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: [])

    server_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # status: active | unreachable | syncing | error | pending
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Agent bookkeeping (mirrors DNSServer — see docs/deployment/DNS_AGENT.md)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    agent_registered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    agent_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Source IP of the most recent agent heartbeat — operator-visible
    # to identify which host runs each agent in NAT / distributed
    # deployments. See dns_server.last_seen_ip for the same field.
    last_seen_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    # Issue #197 — same shape as ``DNSServer.appliance_id``. Populated
    # at supervisor-driven register time so the operator's "Delete
    # appliance" click in the Fleet UI atomically drops the matching
    # dhcp_server rows via ``ON DELETE CASCADE``. NULL for operator-
    # registered DHCP servers (off-fleet box, manual register).
    appliance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # #637 — the running Kea DAEMON's version (e.g. "3.0.3"), distinct from
    # ``agent_version`` (the python agent). Read live off the control socket via
    # ``version-get`` and reported on each heartbeat. The rolling-upgrade
    # preflight needs it: Kea 3.0's HA hook is wire-incompatible with peers
    # older than 2.7, so upgrading an HA pair one node at a time breaks HA
    # mid-run. NULL = not reported yet (treat as UNKNOWN, never as "old").
    kea_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

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
    agent_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    agent_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Per-server maintenance mode (issue #182). Same shape as on
    # ``DNSServer`` — see that class for the design notes. Pausing a
    # DHCP server stops pending DHCPConfigOp dispatch + suppresses the
    # heartbeat-stale alert, but the row stays in its group so HA peer
    # accounting still treats it as expected-but-quiet rather than
    # absent.
    maintenance_mode: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    maintenance_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    maintenance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    config_etag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    config_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Phase 8f fleet upgrade orchestration (issue #138). Mirror of the
    # ``DNSServer`` columns — same schema because both server kinds
    # share the agent bookkeeping shape and Fleet view treats them
    # uniformly. See DNSServer for the per-field description.
    desired_appliance_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    desired_slot_image_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    deployment_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)
    installed_appliance_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_slot: Mapped[str | None] = mapped_column(String(16), nullable=True)
    durable_default: Mapped[str | None] = mapped_column(String(16), nullable=True)
    is_trial_boot: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    last_upgrade_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_upgrade_state_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Phase 8f-8 — operator-triggered reboot. See DNSServer for full
    # rationale; same schema both sides for uniform Fleet handling.
    reboot_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    reboot_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Fernet-encrypted JSON blob for driver-specific admin credentials.
    # windows_dhcp stores a dict: {"username", "password", "winrm_port",
    # "transport", "use_tls", "verify_tls"}. Agent-based drivers (kea)
    # leave this NULL — they authenticate via agent JWT.
    credentials_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # Kea HA hook peer URL — this server's OWN HA listener endpoint
    # (``http://<host>:<port>/``). The other peer in the group calls
    # this URL for heartbeats / lease updates. Empty string for
    # standalone servers; rendered into every peer's ``peers`` array
    # so they know where to reach each other.
    ha_peer_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    # Kea HA runtime state — populated by the agent's periodic
    # ``status-get`` poll. Null when the server is standalone. Values
    # follow Kea's own state names (``hot-standby`` / ``normal`` /
    # ``partner-down`` / etc). Treat as opaque reporting.
    ha_state: Mapped[str | None] = mapped_column(String(50), nullable=True)
    ha_last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── #1110 topology observation (agentless drivers with get_scopes) ───
    #
    # Freshness lives HERE, per server, not on the observation rows. The
    # topology poll runs every ~15 s and rewriting an ``observed_at`` on
    # every scope-state row each time would be N updates per server per
    # poll to record that nothing changed; the rows are written only when
    # their content does, and "is this server's view current?" is one
    # timestamp.
    #
    # ``scopes_observed_at`` — last SUCCESSFUL scope enumeration. Another
    # member's scope-state rows only count as evidence while this is
    # recent: an unreachable partner's last-known view must not keep
    # claiming a scope it may no longer serve.
    scopes_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # ``failover_observed_at`` — last SUCCESSFUL read of this server's
    # Windows failover relationships. NULL means never read, which is not
    # the same as "has none": the rows in ``dhcp_failover_relationship``
    # say what the server has, this says whether we know.
    failover_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The most recent failover read's failure, cleared by the next success.
    # A read that fails leaves the previous relationship rows in place —
    # last-known-good, like the lease floor guard (#482) — so this is the
    # only thing that says they are stale and why.
    failover_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    group: Mapped[DHCPServerGroup | None] = relationship(
        "DHCPServerGroup", back_populates="servers", lazy="joined"
    )
    leases: Mapped[list[DHCPLease]] = relationship(
        "DHCPLease", back_populates="server", cascade="all, delete-orphan"
    )


# ── Windows DHCP failover observation (#1110) ─────────────────────────────


class DHCPFailoverRelationship(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A Windows DHCP failover relationship, as ONE server reports it.

    A mirror of ``Get-DhcpServerv4Failover``, refreshed by the topology poll
    and after every relationship action SpatiumDDI takes
    (``services.dhcp.windows_failover_manage``). It is an observation, never
    a desired state: nothing reconciles Windows towards it, so a change made
    in the DHCP console is simply read back. It exists so the write-through
    and the reconciler can answer the question the group model cannot: is
    this scope *coordinated* between these two servers, or are two servers
    handing out the same addresses on their own?

    One row per ``(observing server, relationship name)``, not one per
    relationship. Both partners report the same relationship under the same
    name, each from its own side (``partner_server`` names the OTHER one, and
    ``server_role`` / ``load_balance_percent`` are this side's values), and a
    relationship whose partner is not registered in SpatiumDDI is only ever
    seen from one side. Storing observations rather than a merged object
    keeps each poll the owner of exactly its own rows and never asks one
    server's read to overwrite what another server said.

    The shared secret is never read: the PowerShell selects the properties
    it wants, and ``SharedSecret`` is not one of them. ``enable_auth`` says
    whether message authentication is on, which is all an operator needs.
    """

    __tablename__ = "dhcp_failover_relationship"
    __table_args__ = (
        UniqueConstraint("server_id", "name", name="uq_dhcp_failover_relationship_server_name"),
    )

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # ``PartnerServer`` verbatim — whatever name or address the relationship
    # was created with. Resolved against the group's members at read time
    # (``services.dhcp.windows_failover``), never stored as an FK: the
    # partner may not be registered at all, which is itself worth showing.
    partner_server: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # Windows' own spellings, verbatim: ``LoadBalance`` / ``HotStandby`` for
    # the mode, ``Active`` / ``Standby`` for the hot-standby role (NULL in
    # load-balance mode), ``Normal`` / ``CommunicationInterrupted`` /
    # ``PartnerDown`` / … for the state. A translation table would be one
    # more thing to drift from what the operator sees in PowerShell.
    mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    server_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    load_balance_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reserve_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_client_lead_time_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state_switch_interval_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    auto_state_transition: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    enable_auth: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # The relationship's explicit scope membership — Windows ``ScopeId``s,
    # i.e. network addresses (``"10.1.2.0"``), in the order reported. A
    # relationship between two servers says nothing about whether a GIVEN
    # scope is in it; this list is the only thing that does.
    scope_ids: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )


class DHCPServerScopeState(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One scope as one agentless DHCP server reports it.

    The group model says every member serves every scope. That is how Kea HA
    works and is not how a pair of Windows servers works unless a failover
    relationship covers the scope — so "which member actually has this scope,
    and is it active there?" has to be recorded per server rather than
    assumed. The write-through does not plan from these rows (it probes live,
    ``services.dhcp.windows_writethrough``); they feed the reconciler's choice
    of which member's view of a shared scope to import, and the group / scope
    views.

    Keyed by the scope's CIDR, not by ``dhcp_scope.id``: a Windows scope whose
    subnet is not in IPAM has no ``DHCPScope`` row, and it still counts when
    deciding whether a server is serving a range it shares with another.

    Written only when the content changes (``modified_at`` records when);
    whether the row is CURRENT is ``DHCPServer.scopes_observed_at``.
    """

    __tablename__ = "dhcp_server_scope_state"
    __table_args__ = (
        UniqueConstraint("server_id", "scope_cidr", name="uq_dhcp_server_scope_state"),
        Index("ix_dhcp_server_scope_state_cidr", "scope_cidr"),
    )

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scope_cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # The scope's dynamic range and exclusions on THIS server. Two servers
    # holding one scope with disjoint effective ranges is a split scope —
    # safe, and the only way to tell it apart from two servers handing out
    # the same addresses.
    start_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    end_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    exclusions: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # sha256 over what should be identical on two failover partners (range,
    # exclusions, reservations, options, lease time, state). Windows syncs
    # LEASES between partners on its own but not configuration, so two
    # partners disagreeing is ordinary drift, and this is how it is seen.
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")


# ── Scope / Pool / Static / Client Class ─────────────────────────────────────


class DHCPScope(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A DHCP scope — one subnet served by one group.

    Under the group-centric model, a scope belongs to a DHCPServerGroup,
    not a single server. All servers in the group render the same scope
    in their Kea config (Dhcp4 ``subnet4``). This mirrors what Kea HA
    requires and replaces the pre-2026.04.22 per-server scope rows that
    operators had to mirror manually.
    """

    __tablename__ = "dhcp_scope"
    __table_args__ = (
        # Partial unique index (NOT a plain UniqueConstraint) so a
        # soft-deleted scope stops occupying the (group, subnet) slot.
        # DHCPScope is soft-deletable; with a non-partial constraint a
        # trashed scope kept the slot, so re-creating a scope for that
        # subnet (or the Windows lease-import auto-create) 500'd on
        # uq_dhcp_scope_group_subnet (#474). Scoping uniqueness to live
        # rows matches the soft-delete semantics.
        Index(
            "uq_dhcp_scope_group_subnet",
            "group_id",
            "subnet_id",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
        Index("ix_dhcp_scope_group", "group_id"),
        Index("ix_dhcp_scope_subnet", "subnet_id"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    subnet_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subnet.id", ondelete="CASCADE"),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Human label for the scope (optional, not unique).
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Address family: "ipv4" (Dhcp4) or "ipv6" (Dhcp6). Populated from the
    # bound subnet's prefix at create time.
    address_family: Mapped[str] = mapped_column(
        String(4), nullable=False, default="ipv4", server_default="ipv4"
    )

    # ── DHCPv6 operating mode (issue #52) ───────────────────────────
    # Only meaningful for ``address_family == "ipv6"`` scopes; v4 ignores
    # it. Drives how the Kea driver renders the subnet6:
    #   * "stateful"  — Kea hands out addresses from the pools (IA_NA) and
    #                   serves option data. RA M-flag=1, O-flag=1.
    #   * "stateless" — no address pools; Kea serves only option data
    #                   (DNS / domain-search) via Information-Request.
    #                   Clients SLAAC their address from the router's RA.
    #                   RA M-flag=0, O-flag=1.
    #   * "slaac"     — no DHCPv6 address service at all; the router's RA
    #                   does everything. RA M-flag=0, O-flag=0.
    # ``ra_managed_flag`` / ``ra_other_flag`` capture the intended RA M/O
    # flags — these are operator intent applied on the *router* (SpatiumDDI's
    # Kea agent doesn't emit Router Advertisements), surfaced in the UI as
    # "what to set upstream". They don't affect the rendered Kea config.
    v6_address_mode: Mapped[str] = mapped_column(
        String(12), nullable=False, default="stateful", server_default="stateful"
    )
    ra_managed_flag: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    ra_other_flag: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # ── IPv6 Router Advertisement management (issue #524) ───────────
    # Opt-in per IPv6 scope. When ``ra_enabled`` is on, the DHCP
    # ConfigBundle carries a rendered radvd.conf stanza for this
    # subnet so the DHCP agent can run radvd and actually emit RAs
    # (previously ``ra_managed_flag`` / ``ra_other_flag`` were pure
    # "set this upstream" intent). v4 scopes ignore all of these.
    #
    # M/O flags: by default derived from ``v6_address_mode``
    # (stateful → M=1,O=1 / stateless → M=0,O=1 / slaac → M=0,O=0).
    # Set ``ra_mo_override`` to use ``ra_managed_flag`` /
    # ``ra_other_flag`` literally instead.
    ra_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ra_mo_override: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # AdvDefaultLifetime — how long clients treat this router as a
    # default gateway (seconds). 0 disables the router as a default
    # route (prefix-only RA). Default 1800 (radvd default).
    ra_router_lifetime: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1800, server_default=sa_text("1800")
    )
    # Max interval between unsolicited RAs (AdvMaxInterval, seconds).
    ra_max_interval: Mapped[int] = mapped_column(
        Integer, nullable=False, default=600, server_default=sa_text("600")
    )
    # Advertised prefix lifetimes (seconds).
    ra_prefix_valid_lifetime: Mapped[int] = mapped_column(
        Integer, nullable=False, default=86400, server_default=sa_text("86400")
    )
    ra_prefix_preferred_lifetime: Mapped[int] = mapped_column(
        Integer, nullable=False, default=14400, server_default=sa_text("14400")
    )
    # Per-prefix flags (AdvOnLink / AdvAutonomous). Autonomous=on lets
    # hosts SLAAC an address from the prefix; turn it off for a
    # DHCPv6-stateful-only subnet.
    ra_prefix_on_link: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    ra_prefix_autonomous: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    # Host interface radvd advertises on. Empty = the agent's
    # ``RADVD_DEFAULT_IFACE`` env default (single-NIC common case).
    ra_interface: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=""
    )

    lease_time: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    min_lease_time: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_lease_time: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Per-scope Kea lease-cache override (issue #637). NULL = inherit the
    # group's ``lease_cache_threshold`` / ``lease_cache_max_age``. See the
    # block comment on DHCPServerGroup for what the cache actually does and
    # why the platform default is 0.0 (disabled).
    lease_cache_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    lease_cache_max_age: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── DHCP relay / giaddr matching (issue #337) ───────────────────
    # List of relay-agent IP addresses (the ``giaddr`` a DHCP relay /
    # ``ip helper-address`` stamps into relayed packets). When non-empty,
    # the Kea driver emits ``relay: {"ip-addresses": [...]}`` on the
    # rendered ``subnet4`` / ``subnet6`` so a centralized Kea selects
    # this scope for traffic arriving via the relay — required for
    # subnets that are NOT directly attached to the server. Empty list
    # (default) preserves today's direct-attach behaviour: Kea matches
    # the subnet by the interface the packet arrived on.
    relay_addresses: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=lambda: {})

    # DDNS
    ddns_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ddns_hostname_policy: Mapped[str] = mapped_column(String(30), nullable=False, default="client")
    hostname_to_ipam_sync: Mapped[str] = mapped_column(
        String(30), nullable=False, default="on_static_only"
    )
    # When False, the IPAM↔DNS drift check ignores this scope's dynamic-pool
    # lease mirrors (``auto_from_lease`` IPs inside a ``dynamic`` pool). Pulled
    # leases carry a client-supplied hostname, so without this the drift check
    # flags every ephemeral lease that has no DNS record as "out of sync" —
    # noise for scopes not publishing lease DNS. Default True preserves the
    # prior behaviour; operators opt out per scope. See ``compute_subnet_dns_drift``.
    dns_track_dynamic_leases: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    last_pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Agentless cloud-provider ownership refs (FortiGate, #630) ─────
    # Records the provider-side object this scope owns, per cloud DHCP
    # server, so a push never adopts/overwrites/deletes an object the
    # operator hand-managed on the device. Shape:
    #   {"<dhcp_server_uuid>": {"mkey": <int>, "interface": "<name>"}}
    # Written by the cloud write-through after a create-we-made (or a
    # confirmed opt-in adopt); an empty/absent entry means "we own
    # nothing here yet", so the driver refuses to clobber a pre-existing
    # object unless the operator opts in. Null for non-cloud scopes.
    provider_refs: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── PXE / iPXE provisioning (issue #51) ─────────────────────────
    # Operator picks one PXEProfile per scope. The profile carries
    # the next-server + N arch-matches; the Kea driver renders one
    # client-class per (profile × arch-match) pair when this is set.
    # Null = no PXE on this scope (default — most scopes don't run
    # PXE; a single scope that does avoids polluting every scope's
    # config). FK is SET NULL so deleting a profile doesn't cascade-
    # trash the scope; the scope just stops emitting PXE classes.
    pxe_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_pxe_profile.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Free-form ``key → value`` labels (issue #104).
    tags: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    # Provenance — set by the DHCP configuration importer (issue #129).
    # ``import_source`` ∈ {kea, windows_dhcp, isc_dhcp}; NULL for
    # hand-created scopes. ``imported_at`` is the commit timestamp.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    group: Mapped[DHCPServerGroup] = relationship("DHCPServerGroup", back_populates="scopes")
    # ``selectin``, NOT ``joined`` (#617). These are collections, so a joined
    # eager load multiplies rows and — the part that actually bit us — forces
    # every ``select(DHCPScope)`` in the codebase to remember ``.unique()`` or
    # raise ``InvalidRequestError`` at runtime. Several didn't: the Trash list,
    # restore, and permanent-delete all 500'd the moment a soft-deleted scope had
    # a single pool or reservation (i.e. any real scope), and the conformity
    # engine / subnet resize / radvd tool carried the same latent trap.
    #
    # It also fixes soft-delete filtering of the children, which ``joined`` got
    # wrong. The global filter registers with ``propagate_to_loaders=False``
    # (app/db.py) so it does NOT reach a JOINED child — a soft-deleted pool would
    # ride the parent's statement straight into the rendered config. ``selectin``
    # emits the child as its own ORM execute, so the filter is applied to it
    # independently (primary entity = the child model). Verified both ways:
    #
    #   live scope + soft-deleted child, no opt-out  -> scope.pools == []
    #   parent loaded with include_deleted=True      -> scope.pools == [child]
    #
    # i.e. the ``include_deleted`` opt-out propagates from the parent statement to
    # the child load, so a blast-radius count / purge pre-pass CAN read the
    # collections on a trashed scope, and a renderer never sees a trashed child.
    #
    # Still eager, which async SQLAlchemy requires; delete-orphan cascade is
    # unaffected (a soft-deleted child the ORM cascade no longer enumerates is
    # removed by the DB-level ON DELETE CASCADE instead).
    pools: Mapped[list[DHCPPool]] = relationship(
        "DHCPPool",
        back_populates="scope",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    statics: Mapped[list[DHCPStaticAssignment]] = relationship(
        "DHCPStaticAssignment",
        back_populates="scope",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    # ``selectin`` rather than ``joined`` because the profile's
    # ``matches`` collection is itself joined-loaded — pulling profile
    # via JOIN on scope queries pulls a JOIN-against-collection that
    # SQLAlchemy refuses without ``.unique()``. Selectin issues one
    # extra small query keyed by ``pxe_profile_id`` and side-steps
    # the collection-joined-load constraint. Bundle assembly does its
    # own targeted query in ``_assemble_pxe_classes`` anyway.
    pxe_profile: Mapped[DHCPPXEProfile | None] = relationship(
        "DHCPPXEProfile",
        foreign_keys=[pxe_profile_id],
        lazy="selectin",
    )


class DHCPPool(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A range within a scope: dynamic, excluded, or reserved.

    Soft-deletable (#617) purely as a cascade child of ``DHCPScope`` — a pool
    is never soft-deleted on its own (``delete_pool`` is a hard delete), it is
    only stamped as part of its scope's deletion batch so a scope restore
    brings its ranges back atomically.
    """

    __tablename__ = "dhcp_pool"
    __table_args__ = (Index("ix_dhcp_pool_scope", "scope_id"),)

    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_scope.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    start_ip: Mapped[str] = mapped_column(INET, nullable=False)
    end_ip: Mapped[str] = mapped_column(INET, nullable=False)
    # pool_type: dynamic | excluded | reserved | pd
    # ``pd`` is a DHCPv6 prefix-delegation pool (issue #368). For ``pd`` pools
    # start_ip/end_ip are set to the prefix's network address (NOT NULL
    # placeholders, unused by the renderer); the delegated prefix is described
    # by the three columns below instead.
    pool_type: Mapped[str] = mapped_column(String(20), nullable=False, default="dynamic")
    class_restriction: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lease_time_override: Mapped[int | None] = mapped_column(Integer, nullable=True)
    options_override: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # DHCPv6 prefix delegation (issue #368), only for pool_type == "pd".
    # ``pd_prefix`` is the delegatable prefix as a CIDR (e.g. "2001:db8:1::/56");
    # ``delegated_length`` is the size of each delegated prefix (e.g. 64, ≥ the
    # pd_prefix length); ``excluded_prefix`` optionally carves a sub-prefix out
    # of every delegation (RFC 6603) as a CIDR.
    pd_prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delegated_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    excluded_prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Provenance — set by the DHCP configuration importer (issue #129).
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scope: Mapped[DHCPScope] = relationship("DHCPScope", back_populates="pools")


class DHCPStaticAssignment(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """A DHCP reservation (MAC → IP) within a scope.

    The scope is part of the reservation's identity — uniqueness is keyed on
    it, Kea renders reservations *nested inside* the scope's ``subnet4``
    stanza, and Windows keys them by the scope's network address. There is no
    renderable form of a scope-less reservation, which is why ``scope_id`` is
    NOT NULL / CASCADE and why the reservation soft-deletes as a cascade child
    of its scope rather than being re-pointed or orphaned (#617).

    Soft-deletable purely as that cascade child — a reservation is never
    soft-deleted on its own (``delete_static`` is a hard delete that releases
    the IPAM mirror); it is only stamped as part of its scope's deletion batch,
    so a scope restore brings its reservations back atomically.
    """

    __tablename__ = "dhcp_static_assignment"
    __table_args__ = (
        # Partial unique indexes, not plain UniqueConstraints: a soft-deleted
        # reservation must not hold the (scope, mac) / (scope, ip) slot against
        # a live one. Same shape as ``uq_dhcp_scope_group_subnet`` (#474).
        Index(
            "uq_dhcp_static_scope_mac",
            "scope_id",
            "mac_address",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
        Index(
            "uq_dhcp_static_scope_ip",
            "scope_id",
            "ip_address",
            unique=True,
            postgresql_where=sa_text("deleted_at IS NULL"),
        ),
        Index("ix_dhcp_static_scope", "scope_id"),
        Index("ix_dhcp_static_mac", "mac_address"),
    )

    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_scope.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    mac_address: Mapped[str] = mapped_column(MACADDR, nullable=False)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # DHCPv6 DUID identifier (issue #368). When set on a v6 scope's
    # reservation, the Kea driver keys the host reservation on ``duid``
    # instead of ``hw-address`` (DHCPv6 clients are identified by DUID).
    duid: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    options_override: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    ip_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_address.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Free-form ``key → value`` labels (issue #104).
    tags: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    # Provenance — set by the DHCP configuration importer (issue #129).
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Operator-metadata snapshot for lossless soft-delete restore (#630) ──
    # A wholesale reservation delete HARD-DELETEs the ``ip_address`` mirror row
    # (a freed row still renders + inflates utilization), which would lose any
    # operator-authored columns on that row (description / tags / custom_fields
    # / owner / role / …). Before deleting, ``remove_ipam_for_static`` snapshots
    # them here (the reservation itself is only soft-deleted, so this survives),
    # and ``upsert_ipam_for_static`` re-applies them when a Trash restore
    # re-creates the mirror. Null when there's nothing worth preserving.
    ipam_metadata_snapshot: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    scope: Mapped[DHCPScope] = relationship("DHCPScope", back_populates="statics")


class DHCPClientClass(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named client class for conditional option delivery — group-wide."""

    __tablename__ = "dhcp_client_class"
    __table_args__ = (
        UniqueConstraint("group_id", "name", name="uq_dhcp_client_class_group_name"),
        Index("ix_dhcp_client_class_group", "group_id"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    match_expression: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=lambda: {})

    # Provenance — set by the DHCP configuration importer (issue #129).
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    group: Mapped[DHCPServerGroup] = relationship(
        "DHCPServerGroup", back_populates="client_classes"
    )


class DHCPOptionTemplate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named bundle of DHCP option-code → value pairs — group-scoped.

    Operators apply a template to a scope (or pool/static in a future
    iteration) to stamp multiple options at once instead of editing them
    individually. The ``options`` JSONB shape mirrors ``DHCPScope.options``
    (``{name: value}``) so apply == merge-by-key.

    Templates are advisory bundles only — they do not flow into the
    ConfigBundle directly. Applying a template copies its options into
    the target scope's options dict at the moment of apply; subsequent
    template edits do NOT propagate back to scopes that already used it.
    """

    __tablename__ = "dhcp_option_template"
    __table_args__ = (
        UniqueConstraint("group_id", "name", name="uq_dhcp_option_template_group_name"),
        Index("ix_dhcp_option_template_group", "group_id"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    address_family: Mapped[str] = mapped_column(
        String(4), nullable=False, default="ipv4", server_default="ipv4"
    )
    options: Mapped[dict] = mapped_column(JSONB, nullable=False, default=lambda: {})

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )

    group: Mapped[DHCPServerGroup] = relationship(
        "DHCPServerGroup", back_populates="option_templates"
    )


# ── MAC blocklist ───────────────────────────────────────────────────────────


class DHCPMACBlock(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A blocked MAC address — group-global, applies to every scope.

    Under Kea this becomes part of the reserved ``DROP`` client class's
    ``test`` expression, rendered by the agent. Under Windows DHCP the
    agentless driver pushes an ``Add-DhcpServerv4Filter -List Deny`` row
    on every member server via WinRM. Expired rows are filtered out of
    the rendered config on every ``ConfigBundle`` build; a beat tick
    notices the state transition and forces a re-push so the operator
    doesn't have to.
    """

    __tablename__ = "dhcp_mac_block"
    __table_args__ = (
        UniqueConstraint("group_id", "mac_address", name="uq_dhcp_mac_block_group_mac"),
        Index("ix_dhcp_mac_block_group", "group_id"),
        Index("ix_dhcp_mac_block_mac", "mac_address"),
        Index("ix_dhcp_mac_block_expires_at", "expires_at"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    mac_address: Mapped[str] = mapped_column(MACADDR, nullable=False)
    # reason: rogue | lost_stolen | quarantine | policy | other
    reason: Mapped[str] = mapped_column(String(20), nullable=False, default="other")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Populated by agents reporting a drop — optional telemetry.
    last_match_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    group: Mapped[DHCPServerGroup] = relationship("DHCPServerGroup", back_populates="mac_blocks")


# ── Leases ──────────────────────────────────────────────────────────────────


class DHCPLease(UUIDPrimaryKeyMixin, Base):
    """An active or historical DHCP lease reported by an agent.

    Per-server because each Kea instance owns its own memfile. Under HA
    the partner syncs leases via ``libdhcp_ha.so``, but the memfile is
    still local — so one lease event arrives here twice (once from each
    peer). The scope_id link points to the group-level scope the lease
    matches.
    """

    __tablename__ = "dhcp_lease"
    __table_args__ = (
        Index("ix_dhcp_lease_server_ip", "server_id", "ip_address"),
        Index("ix_dhcp_lease_server_mac", "server_id", "mac_address"),
        Index("ix_dhcp_lease_state", "state"),
    )

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_scope.id", ondelete="SET NULL"),
        nullable=True,
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    mac_address: Mapped[str] = mapped_column(MACADDR, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user_class: Mapped[str | None] = mapped_column(String(255), nullable=True)

    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    state: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    server: Mapped[DHCPServer] = relationship("DHCPServer", back_populates="leases")


# ── Agent op queue ──────────────────────────────────────────────────────────


class DHCPConfigOp(UUIDPrimaryKeyMixin, Base):
    """Queued op for the agent to apply (config push, restart, reload)."""

    __tablename__ = "dhcp_config_op"
    __table_args__ = (Index("ix_dhcp_config_op_server_status", "server_id", "status"),)

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="CASCADE"),
        nullable=False,
    )
    op_type: Mapped[str] = mapped_column(String(30), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=lambda: {})
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


DHCPRecordOp = DHCPConfigOp


class DHCPLeaseHistory(UUIDPrimaryKeyMixin, Base):
    """Historical record of a DHCP lease that left the active set.

    Written on absence-delete (pull_leases), time-based expiry sweep
    (dhcp_lease_cleanup), and MAC-reassignment within pull_leases.
    Retained for PlatformSettings.dhcp_lease_history_retention_days days
    (default 90).
    """

    __tablename__ = "dhcp_lease_history"
    __table_args__ = (
        Index("ix_dhcp_lease_history_server_id", "server_id"),
        Index("ix_dhcp_lease_history_ip_address", "ip_address"),
        Index("ix_dhcp_lease_history_mac_address", "mac_address"),
        Index("ix_dhcp_lease_history_server_expired", "server_id", "expired_at"),
    )

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_scope.id", ondelete="SET NULL"),
        nullable=True,
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    mac_address: Mapped[str] = mapped_column(MACADDR, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    lease_state: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DHCPPXEProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A reusable PXE / iPXE provisioning profile (issue #51).

    Group-scoped (mirrors how scopes / pools / statics live on
    ``DHCPServerGroup``). One profile carries N arch-matches; an
    operator picks one profile per scope via
    ``DHCPScope.pxe_profile_id``. Disabled profiles render no
    classes, letting an operator A/B-test boot files without
    deleting the configuration.

    ``next_server`` is the IPv4 of the TFTP / HTTP boot server. The
    matches each carry a vendor_class + arch-code filter and the
    boot file the matched client should download (ipxe.efi /
    undionly.kpxe / a chained iPXE config URL / etc).
    """

    __tablename__ = "dhcp_pxe_profile"
    __table_args__ = (UniqueConstraint("group_id", "name", name="uq_dhcp_pxe_profile_group_name"),)

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    next_server: Mapped[str] = mapped_column(String(45), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    matches: Mapped[list[DHCPPXEArchMatch]] = relationship(
        "DHCPPXEArchMatch",
        back_populates="profile",
        cascade="all, delete-orphan",
        lazy="joined",
        order_by="DHCPPXEArchMatch.priority",
    )


class DHCPPXEArchMatch(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One arch-match row within a PXE profile.

    Each match describes a (vendor_class_substring, arch_code_set)
    filter and the boot filename (TFTP) or URL (HTTP / iPXE chain)
    the matched client should download.

    ``priority`` is the deterministic tie-breaker — Kea evaluates
    client-classes in declared order, so the renderer emits matches
    in (priority ASC, id ASC) so config diffs stay stable across
    runs and most-specific matches fire first when the operator
    orders them right.

    ``match_kind`` is informational + drives the UI's preset boot-
    filename hints; the renderer treats both kinds the same. Kea
    sees a class either way.
    """

    __tablename__ = "dhcp_pxe_arch_match"
    __table_args__ = (Index("ix_dhcp_pxe_arch_match_profile_priority", "profile_id", "priority"),)

    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_pxe_profile.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # match_kind: first_stage | ipxe_chain
    match_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="first_stage")
    # Substring match on DHCP option 60 (vendor class identifier).
    # ``PXEClient`` for first-stage TFTP boot, ``iPXE`` for the
    # chained iPXE GET, ``HTTPClient`` for UEFI HTTP boot. Null =
    # match anything (paired with arch_codes to filter).
    vendor_class_match: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # List of DHCP option 93 (Client Architecture Type) values to
    # match — see issue #51 for the canonical lookup table. Null =
    # match any arch (paired with vendor_class_match to filter).
    arch_codes: Mapped[list[int] | None] = mapped_column(JSONB, nullable=True)
    boot_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    boot_file_url_v6: Mapped[str | None] = mapped_column(String(512), nullable=True)

    profile: Mapped[DHCPPXEProfile] = relationship("DHCPPXEProfile", back_populates="matches")


class DHCPPhoneProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A reusable VoIP phone provisioning profile (issue #112 phase 1).

    Group-scoped (mirrors how scopes / pools / statics / PXE profiles
    live on ``DHCPServerGroup``). One profile carries:

    - a ``vendor_class_match`` substring (option-60 vendor-class-id)
      that fences which clients receive its option set
    - an ``option_set`` JSONB list of ``{code, name, value}`` triples
      delivered as Kea ``option-data`` when the match fires

    Attached to one or more scopes via the ``dhcp_phone_profile_scope``
    join table — the same profile can be reused across multiple voice
    VLANs without copy-pasting the option set. The Kea driver emits
    one client-class per profile (gated by the vendor-class match);
    Kea evaluates classes globally, so a profile attached to *any*
    scope drives lease-time options for matching clients group-wide.
    """

    __tablename__ = "dhcp_phone_profile"
    __table_args__ = (
        UniqueConstraint("group_id", "name", name="uq_dhcp_phone_profile_group_name"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Curated vendor label from the VoIP options catalog (Polycom /
    # Yealink / Cisco SPA / etc). Optional — operators can roll their
    # own profile that doesn't map to a curated vendor.
    vendor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Substring match on DHCP option-60 (vendor-class-id). Empty / null
    # means "always match" (paired with a low priority + scope
    # attachment for fencing).
    vendor_class_match: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Option set delivered when the match fires. Shape:
    # ``[{"code": 66, "name": "tftp-server-name", "value": "..."}, ...]``
    # ``name`` is the Kea option-data name (or the SpatiumDDI alias);
    # the renderer prefers the curated name from the option-code library
    # when ``code`` is set and ``name`` is omitted.
    option_set: Mapped[list[dict]] = mapped_column(JSONB, nullable=False, default=list)
    tags: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class DHCPPhoneProfileScope(Base):
    """M:N join — a phone profile can attach to many scopes and vice versa."""

    __tablename__ = "dhcp_phone_profile_scope"

    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_phone_profile.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scope_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_scope.id", ondelete="CASCADE"),
        primary_key=True,
    )


class DHCPObservedResponder(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A DHCP server observed answering on a managed segment (issue #370).

    The agent's active probe broadcasts a DISCOVER and records every OFFER it
    gets back; the control plane upserts one row per (group, server-id,
    source-ip) and classifies it. ``classification`` ∈
    ``expected`` (source matches a known DHCPServer in the group) /
    ``acknowledged`` (operator allowlisted it) / ``rogue`` (unknown responder
    — the alert fires on these).
    """

    __tablename__ = "dhcp_observed_responder"
    __table_args__ = (
        UniqueConstraint(
            "group_id", "server_identifier", "source_ip", name="uq_dhcp_responder_id_ip"
        ),
        Index("ix_dhcp_observed_responder_group", "group_id"),
        Index("ix_dhcp_observed_responder_last_seen", "last_seen_at"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    reported_by_server_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="SET NULL"),
        nullable=True,
    )
    server_identifier: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    source_mac: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    giaddr: Mapped[str | None] = mapped_column(INET, nullable=True)
    offered_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    # expected | acknowledged | rogue
    classification: Mapped[str] = mapped_column(String(16), nullable=False, default="rogue")
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )


class DHCPResponderAllowlist(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An operator-acknowledged DHCP responder (issue #370).

    Suppresses the rogue classification for a known-but-external DHCP server
    (e.g. a corporate edge router). A responder matches when its
    ``server_identifier`` OR ``source_ip`` equals an allowlist entry in the
    same group.
    """

    __tablename__ = "dhcp_responder_allowlist"
    __table_args__ = (Index("ix_dhcp_responder_allowlist_group", "group_id"),)

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    server_identifier: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )


class RAObservedRouter(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An IPv6 router observed emitting a Router Advertisement (issue #524).

    The IPv6 twin of :class:`DHCPObservedResponder`. The DHCP agent's opt-in
    passive RA sniffer (ICMPv6 type 134) ships every RA it sees; the control
    plane upserts one row per ``(group, source_ip)`` and classifies it.
    ``classification`` ∈ ``expected`` (source is on the router allowlist) /
    ``acknowledged`` (operator allowlisted it after the fact) / ``rogue``
    (unknown router — the ``rogue_ra`` alert fires on these).
    """

    __tablename__ = "ra_observed_router"
    # RAs are sourced from a router's link-local (fe80::) address, unique only
    # per-link — routers commonly share fe80::1 across segments. Keying identity
    # on ``source_ip`` alone would let an allowlisted fe80::1 on segment A mask a
    # genuine rogue fe80::1 (different physical router / MAC) on segment B. So
    # ``source_mac`` is part of the identity: two physically distinct routers
    # sharing a link-local IP get distinct rows. A NULL source_mac observation
    # is its own bucket (Postgres treats NULLs as distinct in a UNIQUE index, so
    # the upsert lookup in ra_detection handles NULL explicitly).
    __table_args__ = (
        UniqueConstraint("group_id", "source_ip", "source_mac", name="uq_ra_observed_group_ip_mac"),
        Index("ix_ra_observed_router_group", "group_id"),
        Index("ix_ra_observed_router_last_seen", "last_seen_at"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    reported_by_server_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Link-local (usually fe80::…) source of the RA.
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    source_mac: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    # Advertised prefixes (list of CIDR strings) + the M/O flags + router
    # lifetime observed on the wire.
    prefixes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    managed_flag: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    other_flag: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    router_lifetime: Mapped[int | None] = mapped_column(Integer, nullable=True)
    iface: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # expected | acknowledged | rogue
    classification: Mapped[str] = mapped_column(
        String(16), nullable=False, default="rogue", server_default="rogue"
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=sa_text("now()")
    )


class RARouterAllowlist(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An operator-approved IPv6 RA source router (issue #524).

    Suppresses the rogue classification for a known upstream router. A row
    matches an observed RA when its ``source_ip`` OR ``source_mac`` equals an
    allowlist entry in the same group.
    """

    __tablename__ = "ra_router_allowlist"
    __table_args__ = (Index("ix_ra_router_allowlist_group", "group_id"),)

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    source_mac: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )


__all__ = [
    "DHCPServerGroup",
    "DHCPServer",
    "DHCPScope",
    "DHCPPool",
    "DHCPStaticAssignment",
    "DHCPClientClass",
    "DHCPOptionTemplate",
    "DHCPMACBlock",
    "DHCPPXEProfile",
    "DHCPPXEArchMatch",
    "DHCPPhoneProfile",
    "DHCPPhoneProfileScope",
    "DHCPLease",
    "DHCPConfigOp",
    "DHCPRecordOp",
    "DHCPLeaseHistory",
    "DHCPObservedResponder",
    "DHCPResponderAllowlist",
    "RAObservedRouter",
    "RARouterAllowlist",
]

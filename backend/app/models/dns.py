"""DNS data models: server groups, servers, views, zones, records, ACLs, blocking lists."""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, SoftDeleteMixin, TimestampMixin, UUIDPrimaryKeyMixin


class DNSServerZoneState(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Per-server zone-loaded-serial snapshot.

    Each agent posts back the serial it *actually rendered* after a
    successful config apply — the "ground truth" of what's live on
    that particular server, as distinct from ``DNSZone.last_serial`` which
    is the value the control plane most-recently pushed.

    Unique on ``(server_id, zone_id)`` so the evaluator can drive a
    single row per pair — upserts replace the previous snapshot
    rather than accumulating history.

    Drift detection: for every zone in a group, compare each server's
    ``current_serial`` to the others. Equal → in sync. Different →
    surface "N of M on serial X, rest on Y" on the zone detail page
    and (optionally, via the alerts framework) as a ``zone_serial_drift``
    alert rule.
    """

    __tablename__ = "dns_server_zone_state"
    __table_args__ = (
        UniqueConstraint("server_id", "zone_id", name="uq_dns_server_zone_state"),
        Index("ix_dns_server_zone_state_zone", "zone_id"),
    )

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_zone.id", ondelete="CASCADE"),
        nullable=False,
    )
    current_serial: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DNSServerRuntimeState(Base):
    """Latest agent-pushed runtime snapshot for a single DNS server.

    Two pieces of operator-facing diagnostics live here, both pushed
    from the BIND9 agent:

    - ``rendered_files``: the actual ``named.conf`` + zone files the
      agent wrote to disk during its most recent successful structural
      apply, so operators can answer "is the server actually running
      the config we sent?" without SSHing in.
    - ``rndc_status_text``: stdout of ``rndc status`` from a periodic
      poll. Confirms the daemon is up + which zones are loaded.

    One row per server; the agent overwrites both fields independently
    on its own cadence. Windows DNS servers never write here — they
    have no on-disk rendered config to surface and no rndc.
    """

    __tablename__ = "dns_server_runtime_state"

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server.id", ondelete="CASCADE"),
        primary_key=True,
    )
    rendered_files: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)
    rendered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rndc_status_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    rndc_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DNSServerGroup(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Logical cluster of DNS servers sharing configuration (e.g. internal-resolvers, external-auth)."""

    __tablename__ = "dns_server_group"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # group_type values: internal | external | dmz | custom
    group_type: Mapped[str] = mapped_column(String(50), nullable=False, default="internal")
    default_view: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_recursive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # TSIG key shared by all servers in this group, used to authenticate
    # RFC 2136 dynamic updates from the agent over loopback. Auto-generated
    # on first server registration.
    tsig_key_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tsig_key_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tsig_key_algorithm: Mapped[str] = mapped_column(
        String(50), nullable=False, default="hmac-sha256"
    )

    # ── BIND9 catalog zones (RFC 9432) — distribute zones across the
    # group via one catalog instead of per-server config push. BIND 9.18+
    # only. The producer is the group's `is_primary=True` server; every
    # other bind9 member joins as a consumer. ``catalog_zone_serial`` is
    # bumped by the bundle builder whenever the membership list changes,
    # so a NOTIFY fires automatically on add/remove.
    catalog_zones_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    catalog_zone_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="catalog.spatium.invalid.",
        server_default="catalog.spatium.invalid.",
    )

    # Split-horizon safety flag (issue #25). When True, publishing a
    # private-IP record into a zone in this group requires typed-CIDR
    # confirmation — the safety net catches an operator accidentally
    # exposing internal IPs through a publicly-facing resolver. Off by
    # default; existing groups stay unaffected.
    is_public_facing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    servers: Mapped[list["DNSServer"]] = relationship(
        "DNSServer", back_populates="group", cascade="all, delete-orphan"
    )
    views: Mapped[list["DNSView"]] = relationship(
        "DNSView", back_populates="group", cascade="all, delete-orphan"
    )
    zones: Mapped[list["DNSZone"]] = relationship(
        "DNSZone", back_populates="group", cascade="all, delete-orphan"
    )
    acls: Mapped[list["DNSAcl"]] = relationship(
        "DNSAcl", back_populates="group", cascade="all, delete-orphan"
    )
    options: Mapped["DNSServerOptions | None"] = relationship(
        "DNSServerOptions",
        back_populates="group",
        uselist=False,
        cascade="all, delete-orphan",
    )
    blocklists: Mapped[list["DNSBlockList"]] = relationship(
        "DNSBlockList",
        secondary="dns_blocklist_group_assoc",
        back_populates="server_groups",
    )


class DNSServer(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Individual physical/virtual DNS server managed by SpatiumDDI."""

    __tablename__ = "dns_server"

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # driver: bind9 | powerdns | technitium | windows | cloudflare | route53 |
    # azuredns | googledns — see app/drivers/dns/ for the registry.
    driver: Mapped[str] = mapped_column(String(50), nullable=False, default="bind9")
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=53)
    # api_port: used for rndc (BIND9)
    api_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Issue #210 — Fernet-encrypted at rest, matching the rest of the
    # codebase's encrypted-column convention (LargeBinary + encrypt_str
    # / decrypt_str). Pre-#210 this was a ``Text`` column written with
    # plaintext and a ``# TODO: encrypt`` marker. The migration scrubs
    # any pre-existing plaintext into NULL (no consumer existed yet,
    # so no operator-visible loss; column was effectively decorative).
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # roles: authoritative | recursive | forwarder (JSON array of strings)
    roles: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # User-controlled "pause" — when False, this server is skipped by the
    # health-check sweep, the bi-directional sync task, and the record-op
    # dispatcher. Separate from ``status`` (which tracks reachability —
    # derived, not user-editable). Default True so existing rows keep
    # their current behaviour post-migration.
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    # status: active | unreachable | syncing | error | disabled
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Agent bookkeeping (see docs/deployment/DNS_AGENT.md §2, §6)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, unique=True
    )
    agent_jwt_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Source IP of the most recent agent heartbeat — visible in the UI
    # so operators can identify which host an agent is actually on
    # (the operator-set ``host``/``name`` is just a label; a NAT'd
    # agent in a different subnet would otherwise be invisible).
    last_seen_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # #638 — the running DNS DAEMON's version (e.g. "5.0.5" for pdns,
    # "9.20.26" for BIND), reported on each agent heartbeat. Distinct from the
    # python agent's own version. The rolling-upgrade preflight reads it:
    # PowerDNS 5.0 performs a one-way LMDB schema migration on first open, so
    # a fleet still on pdns 4.x has to be warned before a rolling upgrade
    # crosses that boundary. NULL = not reported yet (agentless drivers never
    # report one) and must be treated as UNKNOWN, never as "old".
    daemon_version: Mapped[str | None] = mapped_column(String(32), nullable=True)

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
    # #1077 — the agent's durable push spool, as last reported on the
    # heartbeat: bytes / entries queued, oldest entry, and cumulative trim
    # counters (``SpoolManager.status()`` on the agent). NULL means the agent
    # has never reported one — a pre-#1077 agent or an agentless driver — and
    # is UNKNOWN, never "empty spool". Only overwritten when a heartbeat
    # carries the field. Read by the server-list chip and the
    # ``agent_spool_trimmed`` alert.
    spool_status: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # ── #1067 daemon state ──
    #
    # The agent's own word about its daemon, reported on every heartbeat
    # (``daemon: {status, reason}``; agent supervisor.py DEFERRED_DAEMON_STATUS,
    # sync.py on a failed apply). Distinct from ``status`` / ``last_seen_at``
    # (is the agent talking to us) and from ``config_apply_status`` (is the
    # live config the saved one): a DNS agent waiting for its first bundle
    # heartbeats every 30 s with ``degraded`` while ``named`` never starts,
    # and until #1067 nothing here kept that. Any word other than ``ok`` is
    # stored as sent and read as not serving. NULL = never reported (a
    # pre-#1061 agent, or an agentless driver): UNKNOWN, never ``ok``.
    # ``daemon_status_since`` is the stamp of the heartbeat that FIRST
    # reported the current status (it moves only on a status change), so the
    # row can say how long a daemon has been degraded; ``last_seen_at`` says
    # whether the report is current.
    daemon_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    daemon_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    daemon_status_since: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Issue #197 — link back to the parent Application appliance
    # (when the row was registered through the supervisor's role-
    # assignment flow). ``ON DELETE CASCADE`` does the orphan-row
    # cleanup automatically when the operator deletes the appliance,
    # so the operator never has to manually prune ghost server rows
    # from the DNS → Server Groups view. Nullable because operators
    # ALSO register DNS servers manually (a remote BIND9 / PowerDNS
    # pointing at an off-fleet box) — those rows stay NULL forever.
    appliance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    last_config_etag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    pending_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Per-server maintenance mode (issue #182). Operator-set intent —
    # NOT derived from heartbeat staleness. When true:
    #   * pending DNSRecordOp rows aren't shipped to the agent
    #   * heartbeat-stale alerts auto-resolve + skip re-emission
    #   * the server is excluded from is_primary cluster-math
    # ``maintenance_started_at`` stamps the UI's "Paused Nh ago" badge;
    # ``maintenance_reason`` carries the operator's free-text reason.
    maintenance_mode: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    maintenance_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    maintenance_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Phase 8f fleet upgrade orchestration (issue #138). Operator-intent
    # fields (``desired_*``) are set from the Fleet view in /appliance and
    # carried to the agent via ConfigBundle long-poll; agent-reality
    # fields are written from the heartbeat path with values from
    # ``spatium-upgrade-slot status`` on the agent host. All nullable so
    # pre-8f rows + docker / k8s deployments keep working unchanged —
    # the agent populates them on its next check-in.
    desired_appliance_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    desired_slot_image_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ``appliance`` / ``docker`` / ``k8s`` / NULL. Agent reports this on
    # registration based on environment introspection (presence of
    # ``/etc/spatiumddi/role-config`` ⇒ appliance, ``KUBERNETES_SERVICE_HOST``
    # ⇒ k8s, else docker / unknown).
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
    # Phase 8f-8 — operator-triggered reboot. Set from the Fleet
    # view's per-row Reboot button; carried to the agent via the
    # ConfigBundle fleet_upgrade block; cleared by the heartbeat
    # handler once the agent reconnects with a timestamp newer than
    # ``reboot_requested_at`` (which proves the box actually rebooted
    # without the agent needing to send a separate "I rebooted"
    # signal).
    reboot_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    reboot_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Fernet-encrypted JSON blob for driver-specific admin credentials.
    # windows_dns Path B stores a dict:
    #   {"username", "password", "winrm_port", "transport", "use_tls",
    #    "verify_tls"}
    # Agent-based drivers (bind9) leave this NULL — they authenticate via
    # the agent JWT. Path A (RFC 2136 record CRUD) also leaves this NULL
    # and signs updates with the group-level TSIG key instead.
    credentials_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    group: Mapped["DNSServerGroup"] = relationship("DNSServerGroup", back_populates="servers")

    __table_args__ = (UniqueConstraint("group_id", "name", name="uq_dns_server_group_name"),)


class DNSRecordOp(UUIDPrimaryKeyMixin, Base):
    """Per-record mutation queued for an agent to apply via RFC 2136."""

    __tablename__ = "dns_record_op"

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    zone_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    op: Mapped[str] = mapped_column(String(20), nullable=False)  # create | update | delete
    record: Mapped[dict] = mapped_column(JSONB, nullable=False)
    target_serial: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DNSServerOptions(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Server-level options applied globally to all views/zones on the server group."""

    __tablename__ = "dns_server_options"

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # Forwarders
    forwarders: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # forward_policy: first | only
    forward_policy: Mapped[str] = mapped_column(String(20), nullable=False, default="first")

    # Recursion
    recursion_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_recursion: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: ["any"])

    # DNSSEC — auto | yes | no
    dnssec_validation: Mapped[str] = mapped_column(String(10), nullable=False, default="auto")

    # GSS-TSIG (Kerberos)
    gss_tsig_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    gss_tsig_keytab_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    gss_tsig_realm: Mapped[str | None] = mapped_column(String(255), nullable=True)
    gss_tsig_principal: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Notify — yes | no | explicit | master-only
    notify_enabled: Mapped[str] = mapped_column(String(20), nullable=False, default="yes")
    also_notify: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    allow_notify: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Query / Transfer ACLs
    allow_query: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: ["any"])
    allow_query_cache: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=lambda: ["localhost", "localnets"]
    )
    allow_transfer: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: ["none"])
    blackhole: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Query logging
    query_log_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # channel: file | syslog | stderr
    query_log_channel: Mapped[str] = mapped_column(String(20), nullable=False, default="file")
    query_log_file: Mapped[str] = mapped_column(
        String(500), nullable=False, default="/var/log/named/queries.log"
    )
    # severity: info | debug | notice | warning | error
    query_log_severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    # print-category / print-severity / print-time in `channel` block
    query_log_print_category: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    query_log_print_severity: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    query_log_print_time: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Response logging (issue #914). BIND 9.20's ``responselog`` adds a
    # second line per query carrying the RCODE and the section counts —
    # the only way, short of dnstap, to know what a client was actually
    # told. Opt-in and default-off because it doubles query-log volume,
    # and volume is the reason the query log is capped at a 24 h window
    # in the first place.
    response_log_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Response Rate Limiting (RRL) + amplification defenses (issue #146) ──
    # All default to a no-op so an existing install renders byte-identical
    # named.conf until an operator opts in. The rate-limit{} block is emitted
    # only when rrl_enabled; the amplification knobs render only when set.
    rrl_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rrl_responses_per_second: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    rrl_window: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    rrl_slip: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    rrl_qps_scale: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rrl_exempt_clients: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # log-only: count + log would-be drops without actually dropping (dry run).
    rrl_log_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Amplification reduction (each renders only when set; null = BIND default).
    minimal_responses: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tcp_clients: Mapped[int | None] = mapped_column(Integer, nullable=True)
    clients_per_query: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_clients_per_query: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── dnsdist front for PowerDNS (#146 Phase 2) ──────────────────────────
    # PowerDNS Authoritative has no RRL equivalent, so the project's answer is
    # a dnsdist sidecar on :53 that forwards to pdns. These knobs compile to
    # the dnsdist config the sidecar runs. Default-off (opt-in per group) so
    # existing PowerDNS deployments don't get a surprise topology change.
    dnsdist_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Per-source-IP QPS cap (MaxQPSIPRule). null = no per-client cap.
    dnsdist_max_qps_per_client: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Action when the per-client cap is exceeded: truncate (TC=1, lets a legit
    # client retry over TCP) or drop.
    dnsdist_action: Mapped[str] = mapped_column(String(10), nullable=False, default="truncate")
    # Dynamic block: clients exceeding this QPS over 10s get blocked for
    # dnsdist_dynblock_seconds (exceedQRate). null = no dynamic blocking.
    dnsdist_dynblock_qps: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dnsdist_dynblock_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)

    # ── Encrypted DNS transports (issue #50) ───────────────────────────────
    # Inbound: serve DoT / DoH to local clients alongside Do53 (the plain
    # :53 listener always stays up — these are additive). Outbound: forward
    # to upstream resolvers over TLS instead of plaintext 53. Every knob
    # defaults to a no-op so an existing install renders a byte-identical
    # named.conf until an operator opts in (same discipline as the RRL
    # block above).
    dot_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dot_port: Mapped[int] = mapped_column(Integer, nullable=False, default=853)
    doh_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 443 is the RFC 8484 default. On a full-stack appliance the frontend
    # already owns 443, so the API refuses to co-locate them (see
    # ``_assert_encrypted_transport_sane``) and operators pick another port.
    doh_port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    doh_path: Mapped[str] = mapped_column(String(128), nullable=False, default="/dns-query")
    # DNS-over-QUIC (RFC 9250), issue #741. Technitium-only: BIND9 has no
    # DoQ listener and pdns-auth speaks none of these, so the API gates
    # this to technitium groups. UDP, unlike DoT/DoH — the firewall layer
    # has to open udp/<doq_port>, not tcp.
    doq_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    doq_port: Mapped[int] = mapped_column(Integer, nullable=False, default=853)

    # Cert served by BOTH listeners. SET NULL rather than CASCADE: deleting a
    # certificate must not delete the whole options row. A NULL id with a
    # listener still flagged on means the cert was deleted out from under
    # us — the renderer skips the listener and logs rather than emitting an
    # unloadable ``tls`` block that would take the whole daemon down.
    tls_certificate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("appliance_certificate.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Outbound forwarding transport — do53 | tls | https | quic.
    #
    # BIND 9.20 can forward over DoT but NOT over DoH (no client-side HTTP
    # transport), so for a bind9 group the API still refuses anything past
    # "tls". Technitium forwards over all four (verified live), which is a
    # capability neither other agent-managed driver has — hence the wider
    # column with a per-driver gate rather than a wider column for everyone.
    forward_transport: Mapped[str] = mapped_column(String(10), nullable=False, default="do53")
    # ``remote-hostname`` for strict upstream cert validation. Group-level
    # rather than per-forwarder because the common case is one provider's
    # anycast pair (1.1.1.1 + 1.0.0.1 both present cloudflare-dns.com).
    # Mixing providers in one group means one of them fails validation —
    # use one group per provider.
    forward_tls_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Off = encrypt without authenticating the upstream (opportunistic DoT).
    # Still beats plaintext against a passive observer, but not against an
    # active MITM — hence default-on.
    forward_tls_verify: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    group: Mapped["DNSServerGroup"] = relationship("DNSServerGroup", back_populates="options")
    trust_anchors: Mapped[list["DNSTrustAnchor"]] = relationship(
        "DNSTrustAnchor", back_populates="server_options", cascade="all, delete-orphan"
    )


class DNSTrustAnchor(UUIDPrimaryKeyMixin, Base):
    """DNSSEC trust anchors (managed-keys / trust-anchors in BIND9)."""

    __tablename__ = "dns_trust_anchor"

    server_options_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_options.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    zone_name: Mapped[str] = mapped_column(String(255), nullable=False)
    algorithm: Mapped[int] = mapped_column(Integer, nullable=False)
    key_tag: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    is_initial_key: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    added_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    server_options: Mapped["DNSServerOptions"] = relationship(
        "DNSServerOptions", back_populates="trust_anchors"
    )


class DNSAcl(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Named address match list reusable across options, views, and zones."""

    __tablename__ = "dns_acl"
    __table_args__ = (UniqueConstraint("group_id", "name", name="uq_dns_acl_group_name"),)

    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    group: Mapped["DNSServerGroup | None"] = relationship("DNSServerGroup", back_populates="acls")
    entries: Mapped[list["DNSAclEntry"]] = relationship(
        "DNSAclEntry",
        back_populates="acl",
        cascade="all, delete-orphan",
        order_by="DNSAclEntry.order",
    )


class DNSAclEntry(UUIDPrimaryKeyMixin, Base):
    """Single entry in a named ACL (CIDR, IP, key reference, or ACL reference)."""

    __tablename__ = "dns_acl_entry"

    acl_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_acl.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # value: CIDR, IP, literal (any/none/localhost/localnets), key name, or ACL reference
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    negate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    acl: Mapped["DNSAcl"] = relationship("DNSAcl", back_populates="entries")


class DNSTSIGKey(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Named TSIG key for RFC 2136 dynamic updates / AXFR auth.

    The legacy single key on ``DNSServerGroup.tsig_key_*`` is auto-generated
    on first server registration and used by the agent itself for loopback
    updates. These rows are operator-managed keys for things like granting
    an external nsupdate client write access to a zone, or authenticating
    a remote AXFR pull from a downstream secondary. Both kinds end up in
    the same ``key { … };`` block in named.conf — the agent doesn't care
    where they came from.
    """

    __tablename__ = "dns_tsig_key"
    __table_args__ = (UniqueConstraint("group_id", "name", name="uq_dns_tsig_key_group_name"),)

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # RFC 1035 dotted name; convention is to end with a dot. The agent
    # quotes whatever string we give it, so trailing-dot is ignored at
    # the wire layer but kept here for operator readability.
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(50), nullable=False, default="hmac-sha256")
    # Base64-encoded raw key bytes, Fernet-encrypted at rest. Never logged
    # or returned in plaintext via the read endpoints — only the create
    # response surfaces the secret one time so the operator can copy it
    # into the consuming client's nsupdate / AXFR config.
    secret_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Operator hint about intended use. Free-form; not enforced.
    purpose: Mapped[str | None] = mapped_column(String(50), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    group: Mapped["DNSServerGroup"] = relationship("DNSServerGroup")


class DNSView(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Split-horizon DNS view — different clients see different zone data."""

    __tablename__ = "dns_view"
    __table_args__ = (UniqueConstraint("group_id", "name", name="uq_dns_view_group_name"),)

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # match_clients / match_destinations: JSON arrays of CIDRs / ACL names
    match_clients: Mapped[list] = mapped_column(JSONB, nullable=False, default=lambda: ["any"])
    match_destinations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    recursion: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # evaluation order (lower = first match)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # View-level query control overrides — fall back to server options when null
    allow_query: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    allow_query_cache: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    group: Mapped["DNSServerGroup"] = relationship("DNSServerGroup", back_populates="views")
    zones: Mapped[list["DNSZone"]] = relationship("DNSZone", back_populates="view")
    blocklists: Mapped[list["DNSBlockList"]] = relationship(
        "DNSBlockList",
        secondary="dns_blocklist_view_assoc",
        back_populates="views",
    )


class DNSZone(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """DNS zone — authoritative, secondary, stub, or forward."""

    __tablename__ = "dns_zone"
    __table_args__ = (
        UniqueConstraint("group_id", "view_id", "name", name="uq_dns_zone_group_view_name"),
        Index("ix_dns_zone_name", "name"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    view_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_view.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # name: FQDN with trailing dot, e.g. "example.com."
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # zone_type values: primary | secondary | stub | forward
    zone_type: Mapped[str] = mapped_column(String(20), nullable=False, default="primary")
    # kind: forward | reverse
    kind: Mapped[str] = mapped_column(String(10), nullable=False, default="forward")

    # SOA fields
    ttl: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    refresh: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    retry: Mapped[int] = mapped_column(Integer, nullable=False, default=7200)
    expire: Mapped[int] = mapped_column(Integer, nullable=False, default=3600000)
    minimum: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    primary_ns: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    admin_email: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    is_auto_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    linked_subnet_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("subnet.id", ondelete="SET NULL"), nullable=True
    )
    # Optional explicit link to the registered domain (issue #87). NULL
    # means "no domain pinned" — the Domain detail page falls back to a
    # name-match heuristic for backward-compat. Setting this lets
    # operators link "example.com." (zone) to a Domain row even when
    # the names don't match exactly (e.g. ``foo.example.com.`` zone
    # under ``example.com`` registration).
    domain_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domain.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Set by the Tailscale reconciler when this zone synthesises
    # ``<tailnet>.ts.net`` from the device list (Phase 2). The FK
    # cascades on tenant delete so the synthetic zone + its records
    # disappear cleanly when the tenant row is removed. While
    # non-null the API blocks edits / deletes — the reconciler is
    # the only writer.
    tailscale_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tailscale_tenant.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # NetBird synthetic-DNS provenance (issue #603, Phase 2). Set on the
    # auto-created NetBird DNS-domain zone. While non-null the API blocks
    # edits / deletes — the reconciler is the only writer. Cascades on
    # instance delete.
    netbird_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("netbird_instance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Optional per-zone color key (from a curated swatch set) shown as a
    # dot/stripe in zone lists + tree nodes. Free-form hex is not accepted
    # so both light and dark themes remain legible. See API validator for
    # the allowed keys.
    color: Mapped[str | None] = mapped_column(String(20), nullable=True)
    dnssec_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # TLS certificate monitoring (#118) — when True, the discovery
    # reconciler auto-creates a tls_cert_target for every A/AAAA record
    # in this zone. Per-record opt-in lives on DNSRecord.auto_tls_probe.
    auto_tls_probe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Populated by the agent after a successful PowerDNS online-signing
    # apply. The DS rrset strings live here so the zone-edit page can
    # surface them for the operator to paste into their parent registrar
    # without round-tripping the agent on every render. Refreshed on every
    # sign / re-sign report (issue #127, Phase 3c.fe).
    dnssec_ds_records: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    dnssec_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # BIND9 DNSSEC signing policy (issue #49). NULL while signing is off, or
    # when signing with BIND's built-in ``default`` policy. Set to a
    # ``DNSSECPolicy`` row to sign with a custom algorithm / NSEC3 / key
    # lifetimes. SET NULL on policy delete so the zone falls back to the
    # built-in default rather than orphaning. Only consulted by the BIND9
    # driver; PowerDNS uses its own online-signing defaults.
    dnssec_policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dnssec_policy.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_serial: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Zone-level ACL overrides (inherit from server options if null)
    allow_query: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    allow_transfer: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    also_notify: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    notify_enabled: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Operator-configurable dynamic-update (RFC 2136) ACL (issue #641).
    # When True the zone accepts DDNS updates from the clients enumerated in
    # ``update_acl_entries`` (by TSIG key or source IP/CIDR), *in addition* to
    # the agent's own loopback writes (the group loopback key is always kept
    # so internal record ops keep flowing). False renders no operator ACL —
    # only the internal loopback grant, i.e. today's behaviour. Only the
    # BIND9 / PowerDNS drivers can express this; cloud drivers 422 the write
    # and Windows maps it coarsely to its enum (see the driver capability
    # descriptors). The ACL rows themselves live in ``dns_zone_update_acl``.
    dynamic_update_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    # Conditional-forwarder config. Only meaningful when ``zone_type == "forward"``.
    # ``forwarders`` is the upstream resolver list (IP or IP@port strings).
    # ``forward_only`` true → ``forward only;`` (don't fall through to recursion);
    # false → ``forward first;`` (fall through if all forwarders fail).
    forwarders: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    forward_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # Primary (master) server IPs this zone transfers FROM (issue #336).
    # Required + non-empty for ``zone_type`` in {secondary, stub}: a
    # secondary / stub zone with no masters renders un-loadable BIND9
    # config (``named-checkconf`` rejects ``type slave;`` / ``type stub;``
    # with no ``primaries`` clause). Each entry is an ``ip`` or ``ip@port``
    # string — the renderer maps ``ip@port`` → ``ip port <n>;``. Ignored
    # for primary / forward zones (those don't pull from a master).
    masters: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    # Logical ownership (issue #91). DNS zones often map 1:1 to a
    # customer (managed-DNS engagements) or to a site (per-DC zones);
    # the FK keeps that visible without resorting to tags.
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("customer.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Free-form ``key → value`` labels — same JSONB column shape every
    # other tagged resource type carries (issue #104). Indexed by the
    # default JSONB GIN so ``apply_tag_filter`` matches via ``?`` /
    # ``@>`` without an extra index.
    tags: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    # Provenance for the DNS configuration importer (issue #128).
    # ``bind9 | windows_dns | powerdns`` for rows that came in through
    # /dns/import; NULL for everything else. ``imported_at`` is the
    # wall-clock commit timestamp — re-imports of the same source key
    # off ``(import_source, name)`` to decide skip-vs-overwrite.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    group: Mapped["DNSServerGroup"] = relationship("DNSServerGroup", back_populates="zones")
    view: Mapped["DNSView | None"] = relationship("DNSView", back_populates="zones")
    records: Mapped[list["DNSRecord"]] = relationship(
        "DNSRecord", back_populates="zone", cascade="all, delete-orphan"
    )
    update_acl_entries: Mapped[list["DNSZoneUpdateAcl"]] = relationship(
        "DNSZoneUpdateAcl",
        back_populates="zone",
        cascade="all, delete-orphan",
        order_by="DNSZoneUpdateAcl.seq",
    )


class DNSRecord(UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin, Base):
    """Individual DNS resource record within a zone."""

    __tablename__ = "dns_record"
    __table_args__ = (
        Index("ix_dns_record_zone_name", "zone_id", "name"),
        Index("ix_dns_record_fqdn", "fqdn"),
    )

    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_zone.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    view_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_view.id", ondelete="SET NULL"),
        nullable=True,
    )
    # name: relative label, e.g. "host1" (not "host1.example.com.")
    # "@" means zone apex
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # fqdn: computed + stored for search
    fqdn: Mapped[str] = mapped_column(String(511), nullable=False, default="")
    # record_type values: A | AAAA | CNAME | MX | TXT | NS | PTR | SRV | CAA | TLSA | SSHFP | NAPTR | LOC
    record_type: Mapped[str] = mapped_column(String(10), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    weight: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    auto_generated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # TLS certificate monitoring (#118) — per-record opt-in for cert
    # probing (the parent zone's auto_tls_probe opts in the whole zone).
    auto_tls_probe: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    ip_address_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ip_address.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    # Set by the Kubernetes reconciler when this record mirrors an
    # Ingress (or annotated Service) hostname from a cluster. FK
    # cascades on cluster delete.
    kubernetes_cluster_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kubernetes_cluster.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the Tailscale reconciler when the row mirrors a
    # tailnet device (Phase 2). The FK cascades on tenant delete.
    # API blocks edits / deletes while non-null.
    tailscale_tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tailscale_tenant.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the NetBird reconciler when the row mirrors a NetBird peer
    # (Phase 2). The FK cascades on instance delete. API blocks edits /
    # deletes while non-null.
    netbird_instance_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("netbird_instance.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Set by the DNS pool health-check pipeline when the row was
    # auto-created for a healthy + enabled pool member. Cascades on
    # member delete so a removed member cleans up its rendered record.
    # API blocks operator edits / deletes while non-null — the row is
    # owned by the pool and only flips through the pool service.
    pool_member_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_pool_member.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    # Free-form ``key → value`` labels (issue #104).
    tags: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    # Provenance for the DNS configuration importer (issue #128). Same
    # shape as ``DNSZone.import_source`` / ``imported_at`` — the
    # importer stamps both on every row it creates so re-imports
    # dedupe and operators can answer "where did this record come
    # from" later. NULL on hand-created or auto-generated rows.
    import_source: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    zone: Mapped["DNSZone"] = relationship("DNSZone", back_populates="records")


class DNSZoneUpdateAcl(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One entry in a zone's dynamic-update (RFC 2136) ACL (issue #641).

    Rows are ordered by ``seq`` (first-match, matching BIND9
    ``update-policy`` semantics) and authorize a dynamic-DNS writer to
    the parent zone — identified either by a named TSIG key
    (``match_kind="tsig_key"`` → ``tsig_key_id``) or by source
    address/prefix (``match_kind="ip"`` → ``ip_cidr``). The
    ``CHECK (num_nonnulls(...) = 1)`` constraint guarantees exactly one
    of the two identity columns is set per row.

    Secrets never live here — a TSIG entry references an operator-managed
    :class:`DNSTSIGKey` by FK, and the key's Fernet-encrypted secret is
    resolved to a *name* only when the ACL is rendered into the config
    bundle. ACL API responses expose ``tsig_key_name`` but never the
    secret (the ``*_set`` boolean pattern used elsewhere).

    P1 renders the coarse ``allow-update`` clause (IP + TSIG mixed) for
    BIND9. The fine-grained BIND9 ``update-policy`` fields
    (``action="deny"``, ``name_scope`` / ``name_pattern``,
    ``record_types``) are persisted but not yet rendered — the API
    rejects them until P2 via the driver capability descriptor, so the
    columns are forward-compatible storage, not live behaviour.
    """

    __tablename__ = "dns_zone_update_acl"
    __table_args__ = (
        CheckConstraint(
            "num_nonnulls(tsig_key_id, ip_cidr) = 1",
            name="ck_dns_zone_update_acl_one_identity",
        ),
        Index("ix_dns_zone_update_acl_zone_seq", "zone_id", "seq"),
    )

    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_zone.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # First-match order. Lower = evaluated first (BIND update-policy).
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # grant | deny. ``deny`` is only meaningful for BIND update-policy
    # (P2); coarse allow-update has no deny concept, so a deny row on a
    # coarse-only driver is rejected at validation.
    action: Mapped[str] = mapped_column(String(10), nullable=False, default="grant")
    # tsig_key | ip — which identity column below is populated.
    match_kind: Mapped[str] = mapped_column(String(10), nullable=False)
    # Populated when match_kind="tsig_key". SET NULL would violate the
    # check constraint, so the FK cascades: deleting a referenced key
    # removes the ACL rows that point at it (the grant is meaningless
    # once its key is gone).
    tsig_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_tsig_key.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    # Populated when match_kind="ip". CIDR or bare IP, stored as text for
    # cross-backend portability (BIND address-match-list / PowerDNS
    # ALLOW-DNSUPDATE-FROM both take plain CIDR strings). Validated in
    # the API layer via ``ipaddress.ip_network``.
    ip_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # BIND update-policy name scoping (P2). self|subdomain|zonesub|wildcard|name.
    name_scope: Mapped[str | None] = mapped_column(String(20), nullable=True)
    name_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Restrict the grant to these RR types (["A","PTR",…]). NULL = all types.
    record_types: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    zone: Mapped["DNSZone"] = relationship("DNSZone", back_populates="update_acl_entries")
    tsig_key: Mapped["DNSTSIGKey | None"] = relationship("DNSTSIGKey")


# ── DNS Pools (GSLB-lite) ───────────────────────────────────────────────────


class DNSPool(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A health-checked pool of A / AAAA targets sharing one DNS name.

    The pool name maps to a record in the bound zone (e.g. ``www`` →
    ``www.example.com``). Members render as **regular A / AAAA
    ``DNSRecord`` rows** with ``pool_member_id`` set, one per healthy +
    enabled member, so BIND9 / Windows DNS render unchanged.

    The health-check task fires on the per-pool ``hc_interval_seconds``
    cadence; member states flip in / out of the rendered record set via
    the pool apply-state service.

    **TTL caveat (operator-facing):** DNS is cached client-side. A
    member dropping out doesn't take effect until ``ttl`` expires, so
    this is **not** the same as a real L4/L7 load balancer — clients
    may still hit a dead box for up to ``ttl`` seconds. Default TTL is
    deliberately short (30 s).
    """

    __tablename__ = "dns_pool"
    __table_args__ = (
        UniqueConstraint("zone_id", "record_name", name="uq_dns_pool_zone_record"),
        Index("ix_dns_pool_zone", "zone_id"),
        Index("ix_dns_pool_next_check_at", "next_check_at"),
    )

    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        nullable=False,
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_zone.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Relative label (``"www"``, ``"@"``) — same convention as DNSRecord.name
    record_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # A | AAAA — the only types that make sense for a pool of host targets
    record_type: Mapped[str] = mapped_column(String(10), nullable=False, default="A")
    ttl: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Health-check config — apply uniformly to every member.
    # hc_type: none | tcp | http | https
    # (icmp deferred — needs CAP_NET_RAW on the api container)
    hc_type: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    hc_target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hc_path: Mapped[str] = mapped_column(String(255), nullable=False, default="/")
    hc_method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")
    # HTTPS-only — when True the check fails fast on bad / self-signed
    # certs. Default False because internal pool members are commonly
    # self-signed; operators flip it on for public targets where a
    # bad cert is itself a signal worth alerting on.
    hc_verify_tls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    # Stored as a JSON array of int status codes; default = [200..399].
    hc_expected_status_codes: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=lambda: [200, 201, 202, 204, 301, 302, 304]
    )
    hc_interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    hc_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    hc_unhealthy_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    hc_healthy_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=2)

    # Beat dispatcher reads ``next_check_at`` to decide which pools to fire.
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    members: Mapped[list["DNSPoolMember"]] = relationship(
        "DNSPoolMember",
        back_populates="pool",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class DNSPoolMember(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One target IP within a ``DNSPool``."""

    __tablename__ = "dns_pool_member"
    __table_args__ = (
        UniqueConstraint("pool_id", "address", name="uq_dns_pool_member_addr"),
        Index("ix_dns_pool_member_pool", "pool_id"),
    )

    pool_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_pool.id", ondelete="CASCADE"),
        nullable=False,
    )
    address: Mapped[str] = mapped_column(String(45), nullable=False)
    # Per-member optional weight (advisory — not used by basic A/AAAA
    # rendering, but reserved for a future weighted-record-set follow-up).
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Operator-controlled "pause" — keeps the member out of the rendered
    # set regardless of health. Distinct from ``last_check_state``.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Geo / topology-aware steering (issue #530) ──────────────────────
    # A member's *serving scope*. Empty ``serving_cidrs`` AND null
    # ``site_id`` ⇒ the member is a **default** target served to every
    # client (the historical health-only behaviour). When a scope is
    # set, the member is only served to clients whose resolver source IP
    # falls inside one of ``serving_cidrs`` OR inside a subnet linked to
    # ``site_id``. The two sources are UNIONed. Rendered on BIND9 as a
    # synthesized ``view { match-clients … }`` block (see
    # ``app.services.dns.pool_geo``); default members render as shared
    # records visible in every view + a catch-all.
    #
    # v1 keys purely on **resolver source IP**. EDNS Client Subnet (ECS)
    # is the future accuracy improvement for the recursive-resolver-in-
    # the-middle case — see ``pool_geo`` module docstring. NOT implemented.
    serving_cidrs: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default="[]"
    )
    # Optional Site whose linked subnets contribute client CIDRs to this
    # member's serving scope. ON DELETE SET NULL — deleting a Site just
    # drops the association; the member reverts to whatever ``serving_cidrs``
    # remain (default target if none).
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("site.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Health-check state — populated by the pool health-check task.
    # last_check_state: unknown | healthy | unhealthy
    last_check_state: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_successes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    pool: Mapped[DNSPool] = relationship("DNSPool", back_populates="members")


# ── Blocking Lists / RPZ ────────────────────────────────────────────────────

# Association tables: a blocklist can be applied to many server groups and/or
# many views. A view or group can reference many blocklists.
dns_blocklist_group_assoc = Table(
    "dns_blocklist_group_assoc",
    Base.metadata,
    Column(
        "blocklist_id",
        UUID(as_uuid=True),
        ForeignKey("dns_blocklist.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "group_id",
        UUID(as_uuid=True),
        ForeignKey("dns_server_group.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


dns_blocklist_view_assoc = Table(
    "dns_blocklist_view_assoc",
    Base.metadata,
    Column(
        "blocklist_id",
        UUID(as_uuid=True),
        ForeignKey("dns_blocklist.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "view_id",
        UUID(as_uuid=True),
        ForeignKey("dns_view.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class DNSBlockList(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named collection of domains to be blocked via RPZ or equivalent backend mechanism.

    A blocklist is backend-neutral: the DNS driver consumes an effective list
    of entries + exceptions via the service layer and emits the appropriate
    BIND9 RPZ zone or BIND9 RPZ config. No driver specifics live on
    this model.
    """

    __tablename__ = "dns_blocklist"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # category: ads | malware | tracking | adult | custom | ...
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="custom")
    # source_type: manual | url | file_upload
    source_type: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    feed_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # format: hosts | domains | adblock
    feed_format: Mapped[str] = mapped_column(String(20), nullable=False, default="hosts")
    # 0 = manual refresh only
    update_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    # block_mode: nxdomain | sinkhole | refused
    block_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="nxdomain")
    sinkhole_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # Whether a feed-sourced entry blocks the named domain's SUBDOMAINS too
    # (#894). Default on, because that is what every one of these feeds
    # means — a list naming ``tracker.example`` intends
    # ``cdn.tracker.example`` as well, and the manual add-entry form has
    # always defaulted the same way. Off suits a host-specific feed (a
    # threat-intel drop of individual C2 FQDNs), where blocking the parent
    # domain would be over-blocking.
    #
    # Only feed entries consult it; a manual entry's ``is_wildcard`` is the
    # operator's own per-row choice and is never rewritten by this flag.
    feed_entries_are_wildcard: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    entries: Mapped[list["DNSBlockListEntry"]] = relationship(
        "DNSBlockListEntry",
        back_populates="blocklist",
        cascade="all, delete-orphan",
    )
    exceptions: Mapped[list["DNSBlockListException"]] = relationship(
        "DNSBlockListException",
        back_populates="blocklist",
        cascade="all, delete-orphan",
    )

    server_groups: Mapped[list["DNSServerGroup"]] = relationship(
        "DNSServerGroup",
        secondary=dns_blocklist_group_assoc,
        back_populates="blocklists",
    )
    views: Mapped[list["DNSView"]] = relationship(
        "DNSView",
        secondary=dns_blocklist_view_assoc,
        back_populates="blocklists",
    )


class DNSBlockListEntry(UUIDPrimaryKeyMixin, Base):
    """A single domain entry within a blocklist."""

    __tablename__ = "dns_blocklist_entry"
    __table_args__ = (
        UniqueConstraint("list_id", "domain", name="uq_dns_blocklist_entry_list_domain"),
        Index("ix_dns_blocklist_entry_list_domain", "list_id", "domain"),
        Index("ix_dns_blocklist_entry_domain", "domain"),
    )

    list_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_blocklist.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain: Mapped[str] = mapped_column(String(512), nullable=False)
    # block_mode values: block | redirect | nxdomain
    entry_type: Mapped[str] = mapped_column(String(20), nullable=False, default="block")
    # target: for redirect entries, the IP/hostname to return instead
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # source: manual | feed
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    is_wildcard: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Operator note — parallels DNSBlockListException.reason. Only meaningful
    # for manual entries; feed-sourced entries would overwrite it on refresh.
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    blocklist: Mapped["DNSBlockList"] = relationship("DNSBlockList", back_populates="entries")


class DNSBlockListException(UUIDPrimaryKeyMixin, Base):
    """Allow-list exception — domain is never blocked by the parent list."""

    __tablename__ = "dns_blocklist_exception"
    __table_args__ = (
        UniqueConstraint("list_id", "domain", name="uq_dns_blocklist_exception_list_domain"),
        Index("ix_dns_blocklist_exception_list_domain", "list_id", "domain"),
    )

    list_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_blocklist.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain: Mapped[str] = mapped_column(String(512), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    blocklist: Mapped["DNSBlockList"] = relationship("DNSBlockList", back_populates="exceptions")


# ── DNSSEC (issue #49) ──────────────────────────────────────────────────────
#
# BIND9 9.16+ inline signing via ``dnssec-policy``. BIND owns the private
# key material and rotates keys automatically per the policy; SpatiumDDI
# only stores the *public* state (DS rrsets + per-key status) the agent
# reports back, so there is no private-key custody here. A ``DNSSECPolicy``
# maps 1:1 to a BIND ``dnssec-policy { ... }`` block; a zone references one
# via ``DNSZone.dnssec_policy_id`` (NULL ⇒ BIND's built-in ``default``).

# Algorithms we expose in the policy editor → BIND dnssec-policy ``algorithm``
# token. ECDSAP256SHA256 is the modern default (small keys, fast, broad
# resolver support). The map is also the API validator's allow-list.
DNSSEC_ALGORITHMS: frozenset[str] = frozenset(
    {
        "ecdsap256sha256",
        "ecdsap384sha384",
        "ed25519",
        "ed448",
        "rsasha256",
        "rsasha512",
    }
)

# Per-key lifecycle states BIND reports via ``rndc dnssec -status`` (the
# RFC 7583 key-timing "states"). Stored verbatim on DNSKey.state.
DNSKEY_STATES: frozenset[str] = frozenset(
    {
        "generated",
        "published",
        "rumoured",
        "active",
        "omnipresent",
        "retired",
        "removed",
        "unknown",
    }
)


class DNSSECPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A reusable BIND9 ``dnssec-policy`` definition (issue #49).

    Renders to a ``dnssec-policy "<name>" { ... };`` block in named.conf.
    Lifetimes are in days; 0 = unlimited (BIND ``lifetime unlimited``),
    which is the normal choice for a KSK (rolled manually via the parent
    DS update) paired with an auto-rolled ZSK.
    """

    __tablename__ = "dnssec_policy"
    __table_args__ = (UniqueConstraint("name", name="uq_dnssec_policy_name"),)

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Built-in seeds (e.g. "default") can't be deleted or renamed.
    is_builtin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    algorithm: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="ecdsap256sha256",
        server_default="ecdsap256sha256",
    )
    # KSK / ZSK lifetimes in days (0 = unlimited). For ECDSA the key size is
    # fixed by the algorithm, so no explicit bits field is needed.
    ksk_lifetime_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    zsk_lifetime_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90, server_default="90"
    )

    # NSEC3 (opt-in). When false the zone uses plain NSEC. iterations 0 +
    # salt-length 0 is the modern best-practice NSEC3 config (RFC 9276).
    nsec3: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    nsec3_iterations: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    nsec3_salt_length: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    nsec3_optout: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    zones: Mapped[list["DNSZone"]] = relationship(
        "DNSZone",
        primaryjoin="DNSSECPolicy.id == foreign(DNSZone.dnssec_policy_id)",
        viewonly=True,
    )


class DNSKey(UUIDPrimaryKeyMixin, Base):
    """Public DNSSEC key state for one zone, reported by the agent.

    Populated from ``rndc dnssec -status <zone>`` (per-key states + timing)
    plus ``dnssec-dsfromkey`` for the KSK DS rrset. **No private key
    material** — BIND holds and rotates the private keys; these rows are a
    read-only mirror for the operator's "is it signed / what do I give the
    registrar / where is the rollover" view. Replaced wholesale per zone on
    each agent report.
    """

    __tablename__ = "dnssec_key"
    __table_args__ = (Index("ix_dnssec_key_zone", "zone_id"),)

    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_zone.id", ondelete="CASCADE"),
        nullable=False,
    )
    # DNSKEY key tag (RFC 4034 §5.1.4) — the operator-visible key id.
    key_tag: Mapped[int] = mapped_column(Integer, nullable=False)
    # "ksk" | "zsk" | "csk" (combined signing key).
    key_type: Mapped[str] = mapped_column(String(4), nullable=False)
    # DNSSEC algorithm number (e.g. 13 for ECDSAP256SHA256).
    algorithm: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # RFC 7583 lifecycle state (see ``DNSKEY_STATES``).
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    # DS rrset string(s) for a KSK/CSK (empty for a ZSK). Operator pastes
    # these into the parent registrar.
    ds_records: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # ISO-8601 timing hints from ``rndc dnssec -status`` (published / active
    # / retire / remove). Free-form so we don't chase BIND's exact phrasing.
    timing: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    zone: Mapped["DNSZone"] = relationship("DNSZone")


class TLDRegistrySnapshot(TimestampMixin, Base):
    """Operator-refreshed copy of IANA's root-zone TLD list (#986).

    Singleton — always exactly one row with ``id=1``, the ``PlatformSettings``
    shape. There is nothing to keep a history of: the list is a full
    replacement each time, and the *bundled* copy in
    ``app/data/iana_tlds.json`` is the fallback, so a bad refresh is
    recovered by refreshing again rather than by rolling back.

    In Postgres rather than on disk deliberately: a node-local file does not
    propagate across a multi-node control plane, so one node would classify
    ``.foo`` as public while its neighbour called it undelegated. Same
    reasoning as the #886 branding logo.

    Only ``tlds`` is overridable this way. The special-use table
    (``.local``, ``example.com``, ``.internal``, …) stays bundled: it
    changes by RFC and by ICANN action, and none of that appears in IANA's
    root-zone download.
    """

    __tablename__ = "tld_registry_snapshot"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # Where it came from, and IANA's own "# Version YYYYMMDDNN" header. The
    # version is what decides whether this row supersedes the bundled list.
    source: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    # When the payload was downloaded (not when the row was written — a
    # re-refresh that returns an identical payload still moves this).
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Lowercased TLD labels. Guarded on write: a payload with fewer than
    # 1,000 entries or missing a sentinel TLD is rejected with a 502 and
    # never lands here, because storing a truncated download would relabel
    # every public zone in the estate as "undelegated" in one action.
    tlds: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

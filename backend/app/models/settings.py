import json
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Integer,
    LargeBinary,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import text as sa_text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

#: ``INITIAL_NTP_SERVERS`` value meaning "the operator was asked for a time
#: source and answered *none*" — as opposed to the empty string, which means
#: nobody was asked (a pre-#995 installer, an unattended run, a STATE volume
#: that was not mounted when firstboot read it).
#:
#: #1002 — those two were the same value, so declining a time source produced
#: the platform default and the appliance synchronised against the public pool
#: anyway, a few minutes into the first boot. They have to be distinguishable
#: HERE, not just on the appliance, because the #154 chrony plane replaces
#: /etc/chrony/chrony.conf wholesale from these settings: the installer's own
#: suppression of Debian's ``pool`` line survives only until the first push.
#:
#: ``!`` is outside the character set the installer and the preseed linter
#: accept for a server name (``[A-Za-z0-9._:-]``), so this can never collide
#: with something an operator typed.
NTP_EXPLICITLY_NONE = "!none"


def _initial_ntp_servers() -> list[str]:
    """Initial ``ntp_pool_servers`` — the OS installer's answer if there is one.

    #1003 item 2. The appliance wizard asks for a time source, writes it to
    ``/etc/chrony/sources.d/spatium-install.sources``, and the #154
    control-plane chrony plane then deletes that file a few minutes into the
    first boot and pushes the platform default instead — because nothing ever
    told the platform what was typed. An air-gapped site that entered
    ``ntp.corp.internal`` got a correct clock for three minutes and a chronyd
    reaching for ``pool.ntp.org`` forever afterwards, with "unsynchronized"
    as the only symptom.

    Applies at ROW CREATION only, which is the point: after that the control
    plane owns the value, and an operator's edit in the UI must not be
    reverted on the next boot. No migration inserts ``platform_settings``
    row 1 — it is created lazily by the ORM in about eight places — so a
    Python-side default covers every one of them, where seeding at any single
    call site would not.

    ``server_default`` deliberately keeps the plain pool: that is what a row
    created outside the ORM gets, and an installer answer is not available at
    DDL time anyway.
    """
    # Deferred purely to keep this model module import-light; there is no
    # cycle to avoid (app.config imports only sys + pydantic), so the
    # justification this line used to carry was wrong. Either form works —
    # `settings` attributes are read at call time regardless, which is what
    # matters, since this must reflect the env at ROW CREATION.
    from app.config import settings  # noqa: PLC0415

    raw = (settings.initial_ntp_servers or "").strip()
    # #1002 — "declined" and "not asked" are different answers and must not
    # collapse. An empty list renders a chrony.conf with no sources at all
    # (services.appliance.ntp.render_chrony_conf already handles it), which is
    # what the operator asked for; falling back to the pool here would undo
    # the installer's suppression on the first config push.
    if raw == NTP_EXPLICITLY_NONE:
        return []
    servers = raw.split()
    return servers or ["pool.ntp.org"]


# Default managed APT repos (issue #155) — mirror the Debian 13 (trixie)
# set baked into the appliance ISO so enabling APT management starts from
# the working defaults rather than an empty sources.list. Used as both
# the ORM default and the migration server_default (kept in sync).
DEFAULT_APT_SOURCES: list[dict] = [
    {
        "name": "Debian trixie",
        "uri": "http://deb.debian.org/debian",
        "suites": "trixie",
        "components": "main contrib non-free-firmware",
        "signed_by_key_id": "",
        "enabled": True,
    },
    {
        "name": "Debian trixie-updates",
        "uri": "http://deb.debian.org/debian",
        "suites": "trixie-updates",
        "components": "main contrib non-free-firmware",
        "signed_by_key_id": "",
        "enabled": True,
    },
    {
        "name": "Debian Security",
        "uri": "http://security.debian.org/debian-security",
        "suites": "trixie-security",
        "components": "main contrib non-free-firmware",
        "signed_by_key_id": "",
        "enabled": True,
    },
]

# Issue #164 — default Allowed-Origins for unattended-upgrades: security
# only, the locked-down appliance default. apt expands ``${distro_id}`` /
# ``${distro_codename}`` at runtime, so this stays correct across Debian
# point releases + a future base-OS bump. Empty list = nothing eligible =
# effectively no auto-upgrades even with the timer on (per #164 acceptance).
DEFAULT_UNATTENDED_ORIGINS: list[str] = [
    "${distro_id}:${distro_codename}-security",
]


class PlatformSettings(Base):
    """Singleton settings table — always exactly one row with id=1."""

    __tablename__ = "platform_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # Branding
    app_title: Mapped[str] = mapped_column(String(255), nullable=False, default="SpatiumDDI")

    # External-facing URL (used for OIDC / SAML redirect + callback URLs). Empty
    # means "derive from the incoming request" at runtime.
    app_base_url: Mapped[str] = mapped_column(String(500), nullable=False, default="")

    # Login-screen acceptable-use banner (issue #885). Rendered above the
    # sign-in form, so every field here is served UNAUTHENTICATED via
    # ``GET /api/v1/settings/public`` — never put anything secret in them.
    # ``require_ack`` gates the submit button on an "I acknowledge"
    # checkbox; that is a display-and-consent affordance, not an
    # enforcement boundary (the API never sees the acknowledgement).
    login_banner_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    login_banner_title: Mapped[str] = mapped_column(
        String(120), nullable=False, default="", server_default=sa_text("''")
    )
    login_banner_text: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )
    login_banner_require_ack: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # Environment banner (issue #887) — the "you are on the DEV box" strip
    # rendered on every screen including the login page. Colours are
    # operator-picked hex, so they land in an inline style rather than a
    # Tailwind class. ``position`` is one of top / bottom / both.
    env_banner_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    env_banner_text: Mapped[str] = mapped_column(
        String(200), nullable=False, default="", server_default=sa_text("''")
    )
    env_banner_bg: Mapped[str] = mapped_column(
        String(7), nullable=False, default="#b91c1c", server_default=sa_text("'#b91c1c'")
    )
    env_banner_fg: Mapped[str] = mapped_column(
        String(7), nullable=False, default="#ffffff", server_default=sa_text("'#ffffff'")
    )
    env_banner_position: Mapped[str] = mapped_column(
        String(10), nullable=False, default="top", server_default=sa_text("'top'")
    )

    # IP allocation
    ip_allocation_strategy: Mapped[str] = mapped_column(
        String(20), nullable=False, default="sequential"
    )

    # Session / security
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    auto_logout_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Password policy (issue #70). Defaults are deliberately permissive so
    # an upgrade doesn't suddenly invalidate working passwords; operators
    # tighten in Settings → Security. ``password_history_count = 0``
    # disables history checking; ``password_max_age_days = 0`` disables
    # forced rotation. Validator + history live in
    # ``app.services.password_policy``.
    password_min_length: Mapped[int] = mapped_column(
        Integer, nullable=False, default=12, server_default=sa_text("12")
    )
    password_require_uppercase: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    password_require_lowercase: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    password_require_digit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    password_require_symbol: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    password_history_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5, server_default=sa_text("5")
    )
    password_max_age_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )

    # Account lockout (issue #71). ``lockout_threshold = 0`` disables
    # the feature; that's the default so an upgrade never locks an
    # admin out. Threshold counts failed logins inside a rolling
    # ``lockout_reset_minutes`` window — anything older falls out.
    # When the threshold is hit, the account is locked for
    # ``lockout_duration_minutes``; superadmin unlock via /users/<id>/
    # unlock clears both columns.
    lockout_threshold: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=sa_text("0")
    )
    lockout_duration_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=15, server_default=sa_text("15")
    )
    lockout_reset_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=15, server_default=sa_text("15")
    )

    # Utilization alert thresholds
    utilization_warn_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=80)
    utilization_critical_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=95)

    # Exclude small PTP / loopback-style subnets from utilization reporting
    # (dashboard + alerts). A subnet is excluded when its prefix length is
    # strictly larger than this value — i.e. at the default 29 for v4 we
    # exclude /30, /31, /32 (PTP links, single-host); at 126 for v6 we
    # exclude /127 (RFC 6164 PTP) and /128. Set to 32 / 128 to disable.
    utilization_max_prefix_ipv4: Mapped[int] = mapped_column(Integer, nullable=False, default=29)
    utilization_max_prefix_ipv6: Mapped[int] = mapped_column(Integer, nullable=False, default=126)

    # Subnet tree UI preference
    subnet_tree_default_expanded_depth: Mapped[int] = mapped_column(
        Integer, nullable=False, default=2
    )

    # Release checking. When enabled, a daily Celery beat task queries
    # ``api.github.com/repos/{github_repo}/releases/latest`` and stores
    # the result on the columns below. Operators can turn this off in
    # air-gapped deployments or for forks that don't want the check.
    github_release_check_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    # Result columns written by the task. Null until the first successful
    # check; retained through disabled periods so the UI can still show
    # "last seen X" when the toggle is off.
    latest_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    update_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latest_release_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    latest_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Populated when the most recent check hit an error (rate limit, DNS,
    # parse issue). Cleared on a successful check. Surfaced in the admin
    # release-check panel so operators don't chase a stale banner.
    latest_check_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # DNS defaults
    dns_default_ttl: Mapped[int] = mapped_column(Integer, nullable=False, default=3600)
    dns_default_zone_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="primary"
    )
    dns_default_dnssec_validation: Mapped[str] = mapped_column(
        String(20), nullable=False, default="auto"
    )
    dns_recursive_by_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # IPAM ↔ DNS auto-sync (Celery beat fires every 60s, task gates on these).
    dns_auto_sync_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dns_auto_sync_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    # When False (default), auto-sync only creates/updates records; stale records
    # (auto-generated rows pointing at deleted IPs) are left for manual cleanup.
    dns_auto_sync_delete_stale: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dns_auto_sync_last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Reverse-DNS (PTR) auto-population — issue #41. Beat fires every 60s;
    # the task gates on ``reverse_dns_enabled`` + the per-run interval so
    # cadence changes in the UI take effect without restarting beat. The
    # sweep fills ``IPAddress.hostname`` (short label) + ``description``
    # (full PTR FQDN, only when description is empty) for operator-owned
    # rows whose hostname is NULL. ``reverse_dns_resolvers`` is a list of
    # resolver IPs to query; NULL / empty = the worker's system resolvers.
    reverse_dns_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    reverse_dns_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=360, server_default="360"
    )
    reverse_dns_resolvers: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    reverse_dns_last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Scheduled "pull from authoritative server" (AXFR → additive import).
    # Complements the IPAM→DNS push direction above; together they keep
    # SpatiumDDI's DB in sync with both its own intent (IPAM) and the live
    # state on the authoritative DNS server (e.g. a Windows DC).
    # Beat fires every 60s; task gates on these so the UI can change cadence
    # without restarting celery-beat.
    dns_pull_from_server_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    dns_pull_from_server_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )
    dns_pull_from_server_last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Scheduled "pull leases from DHCP server" — counterpart to the DNS
    # pull-from-server setting above, but for lease reads (Windows DHCP
    # WinRM today). Beat fires every 60s; task gates on these so the UI can
    # change cadence without restarting celery-beat. Additive-only: lease
    # rows are upserted by (server_id, ip_address); mirrored IPAM rows are
    # removed by the existing lease-cleanup sweep when expires_at passes.
    dhcp_pull_leases_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Interval in *seconds* (was minutes pre-b2f7e91d3c48). Beat ticks every
    # 10 s now, so values down to ~10 s take effect as configured; anything
    # smaller is floored. Operators who want true sub-minute cadence should
    # be mindful of the load it puts on the Windows DC — a 15 s poll is one
    # WinRM round trip every 15 s per server.
    dhcp_pull_leases_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=15
    )
    dhcp_pull_leases_last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # DHCP defaults — applied as the initial values when creating a new DHCP scope
    dhcp_default_dns_servers: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    dhcp_default_domain_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    dhcp_default_domain_search: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    dhcp_default_ntp_servers: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    dhcp_default_lease_time: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)

    # Audit event forwarding — ship each committed AuditLog row out to an
    # external syslog collector and/or a generic HTTP webhook. Both targets
    # are independent: enable either, both, or neither. Failure to deliver
    # never blocks the audit commit; errors are logged via structlog and
    # eventually surface in the scheduled-task / system logs view.
    audit_forward_syslog_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    audit_forward_syslog_host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    audit_forward_syslog_port: Mapped[int] = mapped_column(Integer, nullable=False, default=514)
    # protocol: udp | tcp (TLS deferred — needs cert management)
    audit_forward_syslog_protocol: Mapped[str] = mapped_column(
        String(10), nullable=False, default="udp"
    )
    # facility: 0–23, mapped to LOG_* per RFC 5424 §6.2.1. Default is
    # "local0" (16) since audit events are clearly app-level, not kernel
    # or auth-daemon scope.
    audit_forward_syslog_facility: Mapped[int] = mapped_column(Integer, nullable=False, default=16)

    audit_forward_webhook_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # The legacy single webhook's URL and optional Authorization header,
    # Fernet-encrypted at rest (#1502) like the same fields on
    # ``audit_forward_target``. The plaintext ``audit_forward_webhook_url`` /
    # ``audit_forward_webhook_auth_header`` columns are kept, unmapped and
    # unread, for one release so a rolling upgrade's old pods keep working
    # (#296); the next release drops them.
    audit_forward_webhook_url_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    audit_forward_webhook_auth_header_encrypted: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )

    # IEEE OUI vendor lookup. Opt-in because the daily fetch pulls a ~5 MB
    # CSV from standards-oui.ieee.org and a lot of deployments genuinely
    # don't care about vendor names. When disabled the Celery task is a
    # no-op, list endpoints skip the join, and the UI hides the vendor
    # suffix. Interval is stored in hours — the IEEE CSV changes slowly,
    # once a day is the right default; lab installs can crank it down if
    # they're debugging OUI loader problems.
    oui_lookup_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    oui_update_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    oui_last_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Integrations — one toggle per integration type. Granular by design:
    # enabling Kubernetes should not implicitly enable a future Terraform
    # Cloud / ServiceNow integration. When a toggle is on, the
    # corresponding top-level sidebar nav item appears.
    integration_kubernetes_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    integration_docker_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    integration_proxmox_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    integration_tailscale_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    integration_unifi_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    integration_cloud_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    integration_opnsense_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    integration_netbird_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    integration_panos_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    integration_fortinet_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    integration_meraki_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Trash retention — high-blast-radius IPAM/DNS/DHCP rows are soft-
    # deleted (``deleted_at`` set) and the nightly purge sweep hard-
    # deletes anything older than this many days. Set to 0 to disable
    # purge entirely (rows accumulate forever; manual permanent-delete
    # is still available). Default 30 d matches the user-facing spec.
    soft_delete_purge_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    # Gate for the reservation expiry sweep task. When False, manually-
    # reserved IPs with a reserved_until timestamp are never auto-released.
    reservation_sweep_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # How many days to retain DHCPLeaseHistory rows. Set to 0 to keep forever.
    dhcp_lease_history_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90, server_default=sa_text("90")
    )

    # How many days to retain terminal packet-capture rows (+ their .pcap
    # files) before the nightly prune deletes them. pcaps are large +
    # sensitive (plaintext creds/PII) so the default is short (issue #59).
    pcap_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=7, server_default=sa_text("7")
    )

    # Fingerbank API key for passive DHCP device fingerprinting (Phase 2 of
    # the device profiling feature). Fernet-encrypted at rest; null when the
    # operator hasn't configured a key. When unset, the agent still ships
    # raw option-55 / option-60 fingerprints into ``dhcp_fingerprint`` —
    # operators just don't get the enriched device-type / class /
    # manufacturer triple. Read via ``services.profiling.fingerbank``
    # which decrypts on demand.
    fingerbank_api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # ASN RDAP refresh cadence (Phase 2 of issue #85). Beat ticks
    # hourly; per-row ``asn.next_check_at`` gates against this knob.
    asn_whois_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=24, server_default=sa_text("24")
    )

    # RPKI ROA pull source — ``cloudflare`` (default) or ``ripe``.
    rpki_roa_source: Mapped[str] = mapped_column(
        String(16), nullable=False, default="cloudflare", server_default=sa_text("'cloudflare'")
    )

    # Cadence for the RPKI ROA refresh task; ROA dump cached in-memory
    # for 5 min inside the source service.
    rpki_roa_refresh_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=4, server_default=sa_text("4")
    )

    # Domain WHOIS refresh cadence (Phase 2 of issue #87). Same per-row
    # gating shape as the ASN cadence above.
    domain_whois_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=24, server_default=sa_text("24")
    )

    # BGP prefix-hijack monitoring (issue #527). When enabled, the beat
    # task ``app.tasks.bgp_hijack_poll`` queries RIPEstat for the current
    # announcements of each tracked prefix and opens
    # ``bgp_hijack_detection`` rows on origin-AS mismatch. Default OFF —
    # the feature ships discoverable but silent (external-signal rules
    # are noisy; operators opt in). ``interval_hours`` is the per-prefix
    # ``next_check_at`` cadence, clamped 1..168 in the task.
    bgp_monitoring_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    bgp_monitoring_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=6, server_default=sa_text("6")
    )

    # TLS certificate monitoring (#118) — default probe cadence per
    # target (a target may override via tls_cert_target.interval_hours).
    # Read every dispatch run so cadence changes take effect without
    # restarting beat. Clamped 1..168 in the task.
    tls_cert_check_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=6, server_default=sa_text("6")
    )

    # DNSBL / RBL reputation monitoring (#528). ``enabled`` is the master
    # sweep gate — default OFF so the module ships discoverable (the
    # catalog + settings UI show) but makes NO off-prem DNS queries until
    # the operator opts in and enables at least one list. The
    # ``interval_hours`` is the daily-ish sweep cadence, read every run so
    # UI changes take effect without restarting beat; clamped 6..168 in
    # the task.
    dnsbl_monitoring_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    dnsbl_check_interval_hours: Mapped[int] = mapped_column(
        Integer, nullable=False, default=24, server_default=sa_text("24")
    )
    # Timestamp of the most recent sweep pass — surfaced read-only in the
    # DNSBL admin UI ("Last run"). NULL until the first sweep.
    dnsbl_sweep_last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Optional explicit resolver IPs for the reversed-octet queries. NULL =
    # use the host's system resolver. A JSON list of dotted-quad strings —
    # some DNSBLs (Spamhaus) return "query blocked" from big public
    # resolvers, so an operator may point at a local recursive resolver.
    dnsbl_query_resolvers: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # VRF cross-cutting validation gate (Phase 2 of issue #86). When
    # False (default), an ``ASN:N`` route-distinguisher whose ASN
    # portion does not match the VRF's linked ``asn.number`` produces
    # a non-blocking warning in the create / update response. When
    # True, the same mismatch is a 422. Same logic applies to each
    # ``ASN:N`` entry in the VRF's import / export route-target lists.
    vrf_strict_rd_validation: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # ── Operator Copilot caps + pricing (issue #90 Wave 4) ────────────
    # Per-user daily cap on token consumption against the chat
    # endpoint. None = unlimited. Default unlimited because most
    # operators self-host with local LLMs where this is moot; cloud-
    # API-using deployments will set it.
    ai_per_user_daily_token_cap: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Per-user daily cost cap in USD. None = unlimited. Same default
    # rationale as the token cap.
    ai_per_user_daily_cost_cap_usd: Mapped[Decimal | None] = mapped_column(
        Numeric(10, 4), nullable=True
    )
    # Operator-supplied per-model rate overrides. Shape:
    #   {"<model_id>": {"input": <usd_per_million>, "output": <...>}}
    # The pricing service consults this *first* — operators can pin
    # rates for their custom-hosted or non-canonical model names that
    # the in-code rate sheet wouldn't recognise (e.g. "qwen3:8b" → $0).
    ai_pricing_overrides: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    # ── Operator Copilot tool catalog (issue #101 follow-up) ──────
    # Operator-set explicit allowlist over the Operator Copilot's
    # tool registry. NULL (default) = registry's per-tool
    # ``default_enabled`` flag governs. Non-NULL = exactly these
    # tools are enabled regardless of declared default. Empty list
    # = no tools (chat still works without tools — sanitised demo).
    # Per-provider ``AIProvider.enabled_tools`` narrows further; the
    # two layers compose.
    ai_tools_enabled: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    # ── Daily digest (issue #90 Phase 2) ────────────────────────────
    # When True, a Celery beat job once per day rolls up the previous
    # 24 h of audit / alert / lease activity, sends it to the highest-
    # priority enabled AIProvider for an executive summary, and pushes
    # the result through the existing audit-forward targets (filter on
    # ``resource_types: ["ai.digest"]`` to route it separately from
    # alerts). Default off — operators turn it on once they've put an
    # SMTP / webhook target in place.
    ai_daily_digest_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # ── Appliance SNMP support (issue #153) ─────────────────────────
    # snmpd runs at the Debian host level on the appliance image, not
    # in a container — HOST-RESOURCES-MIB needs unfiltered /proc + /sys
    # which a containerised snmpd can't see cleanly. The columns here
    # are the singleton source of truth that every appliance host
    # (local + remote agents) renders ``/etc/snmp/snmpd.conf`` from
    # via the Phase 8f-4 ConfigBundle → trigger-file pipeline.
    # ``snmp_community_encrypted`` mirrors the fingerbank shape — Fernet
    # ciphertext bytes, NULL = not configured. ``snmp_v3_users`` keeps
    # encrypted passes inline (URL-safe-base64 ciphertext, the string
    # form Fernet emits) so the JSONB shape stays JSON-friendly.
    snmp_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    snmp_version: Mapped[str] = mapped_column(
        String(8), nullable=False, default="v2c", server_default=sa_text("'v2c'")
    )
    snmp_community_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    snmp_v3_users: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    snmp_allowed_sources: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    snmp_sys_contact: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )
    snmp_sys_location: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )

    # ── Appliance NTP support (issue #154) ──────────────────────────
    # chrony runs at the Debian host level on every appliance host.
    # ``ntp_source_mode`` selects between the public pool default
    # (cloud-init seeds pool.ntp.org), operator-supplied unicast
    # servers (air-gapped sites), or a mix. ``ntp_custom_servers`` is
    # a list of ``{host, iburst, prefer}`` dicts; ``iburst`` speeds
    # initial sync, ``prefer`` tags a canonical source. No Fernet
    # encryption — NTP server hostnames are not sensitive (unlike
    # the SNMP community in #153). ``ntp_allow_clients`` plus
    # ``ntp_allow_client_networks`` turn the appliance into a
    # time server for the listed CIDRs and open UDP 123 inbound
    # via the same ``/etc/nftables.d/`` drop-in pattern.
    ntp_source_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pool", server_default=sa_text("'pool'")
    )
    ntp_pool_servers: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=_initial_ntp_servers,
        server_default=sa_text("'[\"pool.ntp.org\"]'::jsonb"),
    )
    ntp_custom_servers: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    ntp_allow_clients: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ntp_allow_client_networks: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    # ── Appliance APT sources / proxy / GPG keys (issue #155) ───────
    # Third leg of the "Settings → Host services" surface alongside
    # SNMP (#153) + NTP (#154). Opt-in: ``apt_managed`` default False
    # leaves Debian's baked sources.list untouched; when on, the
    # appliance renders /etc/apt/sources.list.d/spatiumddi.list (+
    # proxy / auth / keyring artifacts) from these columns via the same
    # ConfigBundle → trigger-file → host-runner pipeline. GPG armoured
    # key text + private-mirror passwords are Fernet-encrypted inline in
    # JSONB (URL-safe-base64 ciphertext, mirroring snmp_v3_users).
    apt_managed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # [{name, uri, suites, components, signed_by_key_id, enabled}]
    apt_sources: Mapped[list[dict]] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: [dict(s) for s in DEFAULT_APT_SOURCES],
        server_default=sa_text(
            "'" + json.dumps(DEFAULT_APT_SOURCES).replace("'", "''") + "'::jsonb"
        ),
    )
    # [{key_id, comment, armoured_text_enc}]  (armoured_text_enc Fernet)
    apt_gpg_keys: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    apt_proxy_http: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )
    apt_proxy_https: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )
    apt_proxy_no_proxy: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=sa_text("''")
    )
    # [{machine, login, password_enc}]  (password_enc Fernet)
    apt_auth: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    apt_unattended_upgrades_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    # Issue #164 — unattended-upgrades POLICY (the WHEN/HOW), orthogonal to
    # ``apt_managed`` (the WHERE, #155). These render
    # /etc/apt/apt.conf.d/50unattended-upgrades and apply even when the
    # operator has NOT taken over apt sources; ``apt_unattended_upgrades_
    # enabled`` above stays the master timer toggle (20auto-upgrades).
    apt_unattended_origins: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: list(DEFAULT_UNATTENDED_ORIGINS),
        server_default=sa_text(
            "'" + json.dumps(DEFAULT_UNATTENDED_ORIGINS).replace("'", "''") + "'::jsonb"
        ),
    )
    # Packages never auto-upgraded (Unattended-Upgrade::Package-Blacklist).
    # Each entry is a Python regular expression matched from the start of
    # the package name, NOT a glob (#1384): ``linux-image-``, ``^openssl$``.
    apt_unattended_blocklist: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # Reboot after an upgrade that needs one. Default False — a surprise
    # reboot is the wrong default for a DDI appliance serving DNS / DHCP.
    apt_unattended_automatic_reboot: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # HH:MM (24h) for Unattended-Upgrade::Automatic-Reboot-Time. apt supports
    # a single reboot time, not a window (the #164 sketch's window_end has no
    # apt analogue), so we model the one value apt actually honours.
    apt_unattended_reboot_time: Mapped[str] = mapped_column(
        String(5), nullable=False, default="02:00", server_default=sa_text("'02:00'")
    )

    # ── Appliance timezone (issue #165) ─────────────────────────────
    # IANA tz name (``UTC``, ``America/Toronto``, …). Installer wizard
    # captures the initial value into ``/etc/timezone`` at install
    # time; this column tracks the operator-set desired value so
    # post-install changes through the Settings UI flow through the
    # same heartbeat → host-runner pattern NTP / SNMP use. Empty
    # string means "follow the install-time default" — supervisor
    # heartbeat skips sending it in that case.
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=sa_text("''")
    )

    # ── Appliance console mode (#393) ──────────────────────────────
    # How the appliance's physical/serial console behaves, one of:
    #   ``dashboard``         (default) — quiet boot (``loglevel=3``) +
    #                         the Talos-style console dashboard on tty1.
    #   ``verbose_dashboard`` — show kernel + systemd boot output during
    #                         boot, THEN the dashboard takes over tty1.
    #   ``text_console``      — verbose boot + a plain getty LOGIN on
    #                         tty1 (no dashboard), i.e. a regular Linux
    #                         box (``spatium-console=off``).
    # The supervisor maps this to the grubenv ``spatium_verbose`` value
    # the grub.cfg menuentries read (dashboard→0 / text_console→1 /
    # verbose_dashboard→2); applies on the next reboot. Flows through
    # the same heartbeat → grubenv → host-runner plane as timezone /
    # NTP / SNMP. Replaces the pre-#393 boolean ``verbose_boot`` (which
    # mapped True→text_console, False→dashboard — backfilled in the
    # migration).
    console_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="dashboard", server_default="dashboard"
    )

    # ── Maintenance mode (issue #57) ────────────────────────────────
    # System-wide read-only switch. When ``maintenance_mode_enabled`` is
    # True the API 503s every mutating request (POST/PUT/PATCH/DELETE)
    # outside the exempt allow-list (auth / settings / health / metrics /
    # agent endpoints), with an effective-superadmin bypass so an admin
    # can still flip it back off. ``maintenance_message`` is shown in the
    # global banner + the 503 body; ``maintenance_started_at`` is
    # server-stamped on enable and cleared on disable (never operator-set
    # directly). Default off / empty so existing installs are unaffected.
    maintenance_mode_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    maintenance_message: Mapped[str] = mapped_column(
        String(500), nullable=False, default="", server_default=sa_text("''")
    )
    maintenance_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Appliance LLDP support (issue #343) ─────────────────────────
    # lldpd runs at the Debian host level on every appliance host (same
    # host-config plane as SNMP / chrony) so it can see the host's real
    # L2 interfaces and send/receive raw ethertype-0x88cc frames. No
    # Fernet — LLDP advertises public identity, not secrets. Default-off
    # so existing appliances leak no topology. ``lldp_interface_pattern``
    # is an lldpd ``configure system interface pattern`` whitelist that
    # excludes container / k3s vNICs by default (we never advertise into
    # the overlay network). ``lldp_protocols`` enables RECEPTION of extra
    # neighbour protocols (cdp / edp / fdp / sonmp) on top of LLDP.
    # ``lldp_med_location`` + ``lldp_snmp_agentx`` are stored for Phase 3
    # (LLDP-MED location + AgentX-to-snmpd) and not yet rendered.
    lldp_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    lldp_tx_interval: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default=sa_text("30")
    )
    lldp_tx_hold: Mapped[int] = mapped_column(
        Integer, nullable=False, default=4, server_default=sa_text("4")
    )
    lldp_protocols: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    lldp_interface_pattern: Mapped[str] = mapped_column(
        String(512),
        nullable=False,
        default="eth*,en*,!docker*,!veth*,!br-*,!cni0,!flannel.1",
        server_default=sa_text("'eth*,en*,!docker*,!veth*,!br-*,!cni0,!flannel.1'"),
    )
    lldp_management_pattern: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )
    lldp_sys_name: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )
    lldp_sys_description: Mapped[str] = mapped_column(
        String(255), nullable=False, default="", server_default=sa_text("''")
    )
    lldp_med_location: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )
    lldp_snmp_agentx: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # ── Appliance syslog forwarding (issue #156) ────────────────────
    # rsyslog runs at the Debian host level on every appliance host
    # (same host-config plane as SNMP / chrony / lldpd) so it can ship
    # both journald + file log sources off-box to a SIEM / collector.
    # The columns here are the singleton source of truth that every
    # appliance host (local + remote agents) renders
    # ``/etc/rsyslog.d/50-spatium-forward.conf`` from via the same
    # ConfigBundle → trigger-file pipeline as #153/#154/#343. Default-
    # off so the column add ships nothing off any existing appliance.
    # ``syslog_targets`` is a JSONB list of ``{host, port, protocol,
    # format, ca_cert_pem}`` dicts; ``ca_cert_pem`` carries Fernet
    # ciphertext as the URL-safe-base64 string Fernet emits (only when
    # ``protocol == 'tls'``) so the JSONB column stays JSON-friendly —
    # mirroring the SNMP v3-user pass shape. ``syslog_filter`` is an
    # rsyslog selector (``*.*`` / ``authpriv.*`` / …) prepended to each
    # ``omfwd`` action; empty = the renderer defaults to ``*.*``.
    # ``syslog_buffer_disk`` enables a disk-assisted queue so a brief
    # collector outage doesn't drop logs.
    syslog_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    syslog_targets: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    syslog_filter: Mapped[str] = mapped_column(
        String, nullable=False, default="", server_default=sa_text("''")
    )
    syslog_buffer_disk: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # ── Appliance SSH (issue #157) ──────────────────────────────────
    # sshd runs at the Debian host level on every appliance host (same
    # host-config plane as SNMP / chrony / lldpd / rsyslog) so operator
    # SSH access can be managed centrally. The columns here are the
    # singleton source of truth that every appliance host (local +
    # remote agents) renders ``~admin/.ssh/authorized_keys`` +
    # ``/etc/ssh/sshd_config.d/spatiumddi.conf`` from via the same
    # ConfigBundle → trigger-file pipeline as #153/#154/#343/#156.
    # ``ssh_authorized_keys`` is a JSONB list of ``{name, public_key,
    # comment}`` entries — public keys are NOT secrets, so no Fernet
    # and no redaction (unlike the SNMP community / syslog CA PEM).
    # ``ssh_password_auth_enabled`` defaults TRUE so existing field
    # installs do NOT lose password auth on upgrade; flipping it to
    # false with zero keys is refused (lockout safety) both here on the
    # PUT and on the host runner. ``ssh_allow_root_login`` → sshd
    # ``PermitRootLogin yes|no``. ``ssh_port`` → sshd ``Port`` (server
    # rejects < 1024 except 22). ``ssh_allowed_source_networks`` is a
    # JSONB list of CIDRs the host nftables drop-in source-scopes the
    # ssh port to (sshd has no native source filter).
    #
    # ``ssh_lockdown`` is what makes that list ENFORCEMENT rather than a
    # note (#1009). Port 22 is opened unconditionally by a management
    # floor — baked at ``/etc/nftables.d/00-spatium-ssh.nft`` and emitted
    # again by the firewall renderers — and nftables is first-match-wins,
    # so the scoped rule sat behind it as dead code. Retiring that floor
    # removes what ``docs/design/FLEET_FIREWALL.md`` §6.1 calls the
    # irreducible recovery channel, which is a decision an operator has
    # to take rather than a side effect of typing a CIDR: hence a second,
    # default-off switch, the same shape §6.1 specified as
    # ``firewall_mgmt_lockdown`` and the same anti-lockout pattern
    # pfSense / OPNsense ship.
    #
    # OFF (the default, including on upgrade): the port is opened
    # unconditionally on every port, and the list is inert — so nothing
    # tightens under an operator who never asked for it.
    # ON: refused unless the list is non-empty (there would be nothing
    # left to accept from), the floor is retired, and the scope applies
    # on port 22 and on a moved port alike.
    ssh_authorized_keys: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    ssh_password_auth_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    ssh_allow_root_login: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    ssh_port: Mapped[int] = mapped_column(
        Integer, nullable=False, default=22, server_default=sa_text("22")
    )
    ssh_allowed_source_networks: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    ssh_lockdown: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # ── Appliance DNS resolver (issue #158) ─────────────────────────
    # systemd-resolved runs at the Debian host level on every appliance
    # host (same host-config plane as SNMP / chrony / lldpd / rsyslog /
    # sshd). The columns here are the singleton source of truth that every
    # appliance host (local + remote agents) renders the
    # ``/etc/systemd/resolved.conf.d/spatiumddi.conf`` drop-in from via the
    # same ConfigBundle → trigger-file pipeline as #153/#154/#343/#156/#157.
    #
    # ``resolver_mode`` selects the behaviour:
    #   ``automatic`` (default) — leave systemd-resolved to pick upstream
    #                 DNS from per-link NetworkManager / DHCP. The runner
    #                 removes the spatiumddi.conf drop-in (leaving the
    #                 image's no-stub-listener.conf intact, which BIND9
    #                 relies on to bind host :53).
    #   ``override``  — pin a global server list (``DNS=``) that wins over
    #                 the per-link servers. The renderer ALSO emits the
    #                 route-only ``Domains=~.`` default ahead of any
    #                 configured search domains so the global ``DNS=``
    #                 servers actually take precedence over per-link
    #                 NetworkManager/DHCP-provided resolvers.
    #
    # Resolver IPs / domains are NOT secrets (like NTP hostnames / SSH
    # public keys), so they are stored verbatim — no Fernet, no redaction.
    # The drop-in NEVER emits ``DNSStubListener`` — the image-shipped
    # no-stub-listener.conf owns that knob (BIND9 binds host :53).
    resolver_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="automatic", server_default=sa_text("'automatic'")
    )
    resolver_servers: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    resolver_fallback_servers: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    resolver_search_domains: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    resolver_dnssec: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="allow-downgrade",
        server_default=sa_text("'allow-downgrade'"),
    )
    resolver_dns_over_tls: Mapped[str] = mapped_column(
        String(16), nullable=False, default="no", server_default=sa_text("'no'")
    )

    # ── Fleet firewall master switch (issue #285 Phase 2) ───────────
    # Gates the NEW server-side-authoritative firewall render (Phase 2a:
    # the control plane ships a rendered drop-in + hash on the heartbeat
    # and the supervisor becomes a pipe). Default FALSE so an upgrade is
    # byte-identical to today — the Phase-1 in-pod renderer keeps running
    # as the fallback and hardening is an explicit operator opt-in. The
    # flip-to-true is additionally gated server-side on every CP node
    # reporting a hardened base-conf marker (no stragglers on the legacy
    # LAN-wide base) so authoritative render never lights mid-rolling-
    # upgrade. Does NOT gate the Phase-1 path, which stays on its own
    # ``cfg.in_pod_firewall_enabled or cluster_peer_cidrs`` gate.
    firewall_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # #404 — opt-in firewall logging. When on (and firewall_enabled is on),
    # the rendered nft drop-in gets a rate-limited catch-all `log prefix
    # "spatium-fw: "` before the chain's policy drop, so dropped/rejected
    # packets land in the kernel log. The supervisor tails /dev/kmsg for that
    # prefix and serves it to the Firewall → Logs viewer. Off by default
    # (log volume); flip on for troubleshooting, off when done.
    firewall_logging_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # #285 Phase 6 — source-scope the Web UI (frontend hostPort 80/443 + the
    # MetalLB control-plane VIP). Empty = open (today's behaviour). When set,
    # both firewall renderers emit a peer-scoped 80/443 accept (requires the
    # base-conf strip of the LAN-wide 80/443) AND the frontend LoadBalancer
    # Service gets loadBalancerSourceRanges. A bad scope here is recoverable
    # over SSH — the port-22 floor is open by default — or at the console.
    # Since #1009 that SSH half is a default-on floor rather than a guarantee:
    # an operator who also turned on ``ssh_lockdown`` with a scope excluding
    # themselves has closed both doors and is left with the console. The two
    # settings are independent and each warns on its own.
    web_ui_allowed_cidrs: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    # ── Aggregation candidate snooze (issue #114) ───────────────────
    # Operator-driven hide-list for the IPAM aggregation badge popover.
    # Keys are stable per-candidate hashes derived from the parent
    # block + sorted child CIDRs (so the same snooze still matches if
    # collapse_addresses returns the children in a different order on
    # a later pass). Values are ISO-8601 timestamps for time-bounded
    # snoozes, or the literal string ``"permanent"`` for "don't suggest
    # again". Filtered server-side in the suggestions endpoint.
    aggregation_snooze: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa_text("'{}'::jsonb")
    )

    # ── Supervisor registration feature flag (#170 Wave A2) ─────────
    # Gates ``POST /api/v1/appliance/supervisor/register``. Default
    # FALSE so Wave A's landing doesn't change behaviour for any
    # existing dns / dhcp agent install (which still uses
    # ``/dns/agents/register`` / ``/dhcp/agents/register`` + the long
    # PSK). Operators flip this on when they're ready to try the new
    # supervisor path. The endpoint returns 404 while disabled — same
    # shape as "endpoint does not exist" so a probing attacker can't
    # distinguish "disabled" from "doesn't exist."
    supervisor_registration_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )

    # ── Appliance soft-delete retention (#170 Wave E follow-up) ─────
    # When an operator clicks Delete on a Fleet UI row, the row goes
    # to ``state=revoked`` + stamps ``revoked_at = now()``. After
    # ``appliance_revoked_retention_days`` the row is permanently
    # hard-deleted by a Celery beat sweep. Set to 0 to disable the
    # automatic hard-delete and require operator action via the
    # "Permanently delete" button on the per-row drilldown.
    appliance_revoked_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default=sa_text("30")
    )

    # ── Control-plane MetalLB VIP (issue #272 Phase 7c) ─────────────
    # Cluster-wide singleton. ``metallb_pool_addresses`` is the L2 IP
    # range the appliance's bundled MetalLB hands out (CIDR ``a.b.c.0/28``
    # or range ``a.b.c.10-a.b.c.20`` per entry); ``control_plane_vip`` is
    # the single floating IP that fronts the frontend Service so the Web
    # UI + every agent heartbeat hit one stable address regardless of
    # which control-plane node is up. The VIP MUST fall inside the pool.
    # Applied to the cluster by the seed supervisor on heartbeat (same
    # desired-state path as ``control_plane_size``): it patches
    # ``metallb.enabled`` + ``metallb.ipPool.addresses`` on the
    # spatium-bootstrap HelmChart and ``frontend.controlPlaneVIP`` on the
    # spatium-control HelmChart (the latter also seeds the auto-issued
    # cert's SAN list via APPLIANCE_EXTRA_CERT_SANS). Disabled / empty =
    # single-node hostNetwork frontend, no VIP.
    metallb_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    metallb_pool_addresses: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    control_plane_vip: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=sa_text("''")
    )

    # ── Data-plane resolver VIPs (issue #272 Phase 10) ──────────────
    # Same cluster-wide singleton + same MetalLB pool as the control-
    # plane VIP. Both default empty = the single-node hostNetwork data
    # plane (no VIP), and both require ``metallb_enabled`` + a value
    # inside ``metallb_pool_addresses`` that differs from every other
    # VIP. The seed supervisor applies them on heartbeat (same desired-
    # state path as ``control_plane_vip``): it writes ``dns.useMetalLBVIP``
    # / ``dns.vip`` / ``dhcpKea.relayVIP`` onto the spatiumddi-appliance
    # HelmChartConfig overlay, and helm-controller flips the resolver
    # Pods off hostNetwork behind an L2 LoadBalancer Service.
    #
    # ``dns_vip`` — one floating :53 resolver IP that follows whichever
    # node is up (bind9 / powerdns drop hostNetwork and sit behind the
    # LoadBalancer Service). Empty = each node answers on its own IP.
    #
    # ``dhcp_relay_vip`` — fronts the relay→server unicast forward on
    # :67 so a DHCP relay's ``forward-to`` target outlives a single Kea
    # node. Kea KEEPS hostNetwork:67 for direct-attached broadcast reach
    # — this VIP does NOT replace client-facing :67. Empty = no relay VIP.
    dns_vip: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=sa_text("''")
    )
    dhcp_relay_vip: Mapped[str] = mapped_column(
        String(64), nullable=False, default="", server_default=sa_text("''")
    )

    # ── MetalLB BGP mode (issue #566 decision D1) ───────────────────
    # Distinct from the L2/ARP ``metallb_enabled`` above — BGP mode is
    # an ADDITIONAL export path (advertise the control-plane VIP + any
    # data-plane VIPs to real upstream routers via BGP) layered on top
    # of the same MetalLB install. Requires ``metallb_enabled=True``
    # (BGP peers/advertisements without a running MetalLB are inert).
    # Applied by the seed supervisor via the SAME apply_metallb_overrides
    # call as the L2 pool (one combined HelmChartConfig valuesContent —
    # see k8s_api.py comment). Activates the GPL-v2 FRRouting image via
    # MetalLB's frr-k8s backend — see NOTICE.
    metallb_bgp_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    # List of {"my_asn": int, "peer_asn": int, "peer_address": str,
    # "peer_port": int|None, "hold_time": str|None} dicts — one BGPPeer
    # CR per entry (chart already renders this; see metallb-bgp.yaml).
    metallb_bgp_peers: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )
    # List of {"ip_address_pools": [str], "communities": [str]|None,
    # "aggregation_length": int|None} dicts — one BGPAdvertisement CR
    # per entry. Empty list + bgp_enabled=True is invalid (validated at
    # the API layer, not the DB) — nothing gets advertised.
    metallb_bgp_advertisements: Mapped[list[dict]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    # ── Embedded ACME client — Let's Encrypt for the Web UI (issue #438) ─
    # SpatiumDDI acting as an ACME client against a public CA to issue a
    # CA-trusted TLS cert for the appliance Web UI, solving DNS-01 through
    # its own managed DNS zones. The issued cert lands in the existing
    # ``ApplianceCertificate`` storage with ``source="letsencrypt"``.
    # ``acme_enabled`` gates issuance and is enforced by ``POST /issue``:
    # configuring an ACME account (``PUT /account``) flips it True (the
    # operator's explicit opt-in), DELETE clears it. The
    # ``security.certificates`` feature module is the separate discovery
    # toggle. ``acme_auto_renew`` is the seam for the deferred renewal
    # beat task (not yet consumed in Phase 1). ``acme_challenge_type`` /
    # ``acme_dns_provider`` / ``acme_domains`` are populated by
    # ``POST /issue`` to record the desired issuance shape for that
    # Phase-2 renewal task to read.
    acme_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )
    acme_auto_renew: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    acme_challenge_type: Mapped[str] = mapped_column(
        String(16), nullable=False, default="dns-01", server_default=sa_text("'dns-01'")
    )
    acme_dns_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acme_domains: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=sa_text("'[]'::jsonb")
    )

    # ── Governance self-protection lock (#62) ────────────────────────────
    # OPT-IN at enable time. When True, WEAKENING the approval control plane
    # (disabling the ``governance.approvals`` module, disabling / deleting a
    # policy, lowering a policy's ``applies_to_superadmin``, or turning this
    # very lock back off) requires a SECOND superadmin's approval via the
    # change-request flow — so a single compromised / rogue superadmin can't
    # quietly defang the workflow. STRENGTHENING moves (enabling the module,
    # enabling a policy, raising ``applies_to_superadmin``, turning this lock
    # on) stay single-person inline. A superadmin break-glass (password
    # re-confirm + typed phrase) can force any weakening change immediately so
    # the platform can never be permanently locked out. The lock is ON iff
    # this flag is True.
    approvals_protect_controls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=sa_text("false")
    )


# Operator-uploaded branding assets (issue #886). One row per ``kind``.
#
# The bytes live in Postgres rather than on a volume because the control
# plane is multi-node: a file written to one API pod's filesystem is
# invisible to the others, which is exactly the problem that forced the
# slot-image mirror sidecar (#296) into existence. The database is already
# the shared store, so a DB blob propagates everywhere for free and rides
# along in backups. A logo is tens of KB — this is not a place where blob
# storage costs anything.
#
# Deliberately NOT columns on PlatformSettings: that row is read on many
# request paths, and no one should pay for a blob on every settings load.
BRANDING_ASSET_KIND_LOGO = "logo"

# PNG only, and small. SVG is deliberately excluded: it is served
# same-origin, and an SVG is a script-execution vector unless sanitised.
BRANDING_ASSET_MAX_BYTES = 512 * 1024
BRANDING_ASSET_MEDIA_TYPE = "image/png"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class BrandingAsset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single operator-uploaded branding file, keyed by ``kind``."""

    __tablename__ = "branding_asset"

    # The uniqueness of ``kind`` is declared as a NAMED constraint rather
    # than ``unique=True`` on the column: an inline unique= lets Postgres
    # auto-name it (``branding_asset_kind_key``) under
    # ``Base.metadata.create_all``, which would not match the name the
    # migration creates. The upload path's ON CONFLICT then resolves
    # differently depending on whether the schema came from migrations or
    # create_all. Naming it here keeps both paths identical.
    #
    # No separate index= on the column either — a unique constraint is
    # already backed by an index, so one would just be a duplicate.
    __table_args__ = (UniqueConstraint("kind", name="uq_branding_asset_kind"),)

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    media_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # Hex sha256 of ``content`` — doubles as the ETag and as the cache-buster
    # in the URL the frontend builds, so a re-upload is picked up immediately
    # instead of sitting behind a stale browser cache.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)

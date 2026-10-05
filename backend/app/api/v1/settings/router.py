"""Platform settings — singleton read/write (superadmin only for writes)."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from ipaddress import ip_network
from typing import Any, Literal

import structlog
from fastapi import (
    APIRouter,
    File,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.api.deps import DB, CurrentUser
from app.core.agent_wake import HOSTCONFIG_ALL, publish_wake
from app.core.demo_mode import forbid_in_demo_mode
from app.core.http_etag import etag_matches, format_etag
from app.core.permissions import is_effective_superadmin, user_has_permission
from app.core.request_meta import get_trusted_client_ip
from app.models.audit import AuditLog
from app.models.audit_forward import AuditForwardTarget
from app.models.influxdb import (
    DEFAULT_MEASUREMENT_PREFIX,
    DEFAULT_PUSH_INTERVAL_SECONDS,
    INFLUXDB_VERSIONS,
    MIN_PUSH_INTERVAL_SECONDS,
    InfluxDBTarget,
)
from app.models.oui import OUIVendor
from app.models.settings import (
    BRANDING_ASSET_KIND_LOGO,
    BRANDING_ASSET_MAX_BYTES,
    BRANDING_ASSET_MEDIA_TYPE,
    PNG_MAGIC,
    BrandingAsset,
    PlatformSettings,
)
from app.services import audit_forward as audit_forward_svc
from app.services.appliance.access import console_only_detail, covers, effective_doors
from app.services.appliance.apt import render_sources_list
from app.services.appliance.ssh import is_valid_public_key, validate_lockout_safe
from app.services.appliance.syslog import validate_syslog_filter, validate_syslog_host
from app.services.forward_secrets import apply_write_only, redact, reveal, url_display

# SNMP v3 protocol allow-lists. Sticking to the protocols net-snmp's
# Debian build ships out of the box — DES/AES for priv, MD5/SHA for
# auth, plus a sentinel "none" for noAuth/noPriv. Stronger AES-256 +
# SHA-256/384/512 land in net-snmp 5.9+ which Debian trixie carries,
# but we leave that to a follow-up so the first cut works against
# every snmpd build operators are likely to see.
_SNMP_VERSIONS: set[str] = {"v2c", "v3"}
_SNMP_AUTH_PROTOCOLS: set[str] = {"none", "MD5", "SHA"}
_SNMP_PRIV_PROTOCOLS: set[str] = {"none", "DES", "AES"}

# Issue #154 — NTP source modes.
#   ``pool``    — use ``ntp_pool_servers`` only (default for the
#                 stock cloud-init pool.ntp.org configuration).
#   ``servers`` — use ``ntp_custom_servers`` only (air-gapped + shops
#                 that mandate internal NTP).
#   ``mixed``   — use both (operator wants internal primary +
#                 public pool as a fallback).
_NTP_SOURCE_MODES: set[str] = {"pool", "servers", "mixed"}

# Issue #156 — rsyslog forward-target validation. ``udp`` / ``tcp`` are
# plaintext; ``tls`` uses rsyslog's gtls stream driver + requires a CA
# PEM. Wire formats map to rsyslog templates in services/appliance/syslog.py.
_SYSLOG_PROTOCOLS: set[str] = {"udp", "tcp", "tls"}
_SYSLOG_FORMATS: set[str] = {"rfc5424", "rfc3164", "json"}

# Issue #158 — systemd-resolved drop-in validation.
#   resolver_mode       — ``automatic`` (per-link DHCP / NetworkManager DNS)
#                         vs ``override`` (pinned global DNS= server list).
#   resolver_dnssec     — systemd-resolved ``DNSSEC=`` values.
#   resolver_dns_over_tls — systemd-resolved ``DNSOverTLS=`` values.
_RESOLVER_MODES: set[str] = {"automatic", "override"}
_RESOLVER_DNSSEC: set[str] = {"yes", "no", "allow-downgrade"}
_RESOLVER_DOT: set[str] = {"yes", "opportunistic", "no"}

logger = structlog.get_logger(__name__)
router = APIRouter()

_SINGLETON_ID = 1


# ── Schema ─────────────────────────────────────────────────────────────────────


class SettingsResponse(BaseModel):
    app_title: str
    app_base_url: str
    # ── Login banner (issue #885) / environment banner (issue #887) ──
    # No secrets — every field here is also served unauthenticated from
    # ``GET /settings/public`` so the login page can render it.
    login_banner_enabled: bool = False
    login_banner_title: str = ""
    login_banner_text: str = ""
    login_banner_require_ack: bool = False
    env_banner_enabled: bool = False
    env_banner_text: str = ""
    env_banner_bg: str = "#b91c1c"
    env_banner_fg: str = "#ffffff"
    env_banner_position: str = "top"
    ip_allocation_strategy: str
    session_timeout_minutes: int
    auto_logout_minutes: int
    utilization_warn_threshold: int
    utilization_critical_threshold: int
    utilization_max_prefix_ipv4: int
    utilization_max_prefix_ipv6: int
    subnet_tree_default_expanded_depth: int
    github_release_check_enabled: bool
    dns_default_ttl: int
    dns_default_zone_type: str
    dns_default_dnssec_validation: str
    dns_recursive_by_default: bool
    dns_auto_sync_enabled: bool
    dns_auto_sync_interval_minutes: int
    dns_auto_sync_delete_stale: bool
    dns_auto_sync_last_run_at: datetime | None
    reverse_dns_enabled: bool
    reverse_dns_interval_minutes: int
    reverse_dns_resolvers: list[str] | None
    reverse_dns_last_run_at: datetime | None
    dns_pull_from_server_enabled: bool
    dns_pull_from_server_interval_minutes: int
    dns_pull_from_server_last_run_at: datetime | None
    dhcp_pull_leases_enabled: bool
    dhcp_pull_leases_interval_seconds: int
    dhcp_pull_leases_last_run_at: datetime | None
    audit_forward_syslog_enabled: bool
    audit_forward_syslog_host: str
    audit_forward_syslog_port: int
    audit_forward_syslog_protocol: str
    audit_forward_syslog_facility: int
    audit_forward_webhook_enabled: bool
    # The legacy webhook's URL and header are credentials, so they are
    # write-only here (#1502).
    audit_forward_webhook_url_set: bool = False
    audit_forward_webhook_url_display: str = ""
    audit_forward_webhook_auth_header_set: bool = False
    dhcp_default_dns_servers: list[str]
    dhcp_default_domain_name: str
    dhcp_default_domain_search: list[str]
    dhcp_default_ntp_servers: list[str]
    dhcp_default_lease_time: int
    oui_lookup_enabled: bool
    oui_update_interval_hours: int
    oui_last_updated_at: datetime | None
    integration_kubernetes_enabled: bool
    integration_docker_enabled: bool
    integration_proxmox_enabled: bool
    integration_tailscale_enabled: bool
    integration_unifi_enabled: bool
    integration_cloud_enabled: bool
    integration_opnsense_enabled: bool
    domain_whois_interval_hours: int
    # Device profiling — fingerbank API key. Boolean reflects whether
    # an encrypted key is stored; the plaintext is never returned.
    fingerbank_api_key_set: bool = False
    # ASN RDAP refresh + RPKI ROA pull (Phase 2 of issue #85).
    asn_whois_interval_hours: int = 24
    rpki_roa_source: str = "cloudflare"
    rpki_roa_refresh_interval_hours: int = 4
    # BGP prefix-hijack monitoring (issue #527).
    bgp_monitoring_enabled: bool = False
    bgp_monitoring_interval_hours: int = 6
    # VRF strict-RD validation toggle (issue #86 phase 2). When False
    # (default), ASN-portion mismatches between the VRF's RD/RT and
    # its linked ASN row produce warnings; when True they are 422.
    vrf_strict_rd_validation: bool = False
    # Operator Copilot daily digest (issue #90 Phase 2). When True,
    # a Celery cron at 08:00 UTC rolls up the prior 24 h, sends to
    # the highest-priority enabled AIProvider for an executive
    # summary, and pushes through audit-forward targets.
    ai_daily_digest_enabled: bool = False
    # Password policy (issue #70). 0 disables history / max-age; the
    # complexity flags are independently toggleable.
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_symbol: bool = False
    password_history_count: int = 5
    password_max_age_days: int = 0
    # Account lockout (issue #71). 0 disables.
    lockout_threshold: int = 0
    lockout_duration_minutes: int = 15
    lockout_reset_minutes: int = 15
    # ── Appliance SNMP (issue #153) ───────────────────────────────
    # Ciphertext columns are folded into ``*_set`` booleans by the
    # model validator below; v3 user pass fields likewise.
    snmp_enabled: bool = False
    snmp_version: str = "v2c"
    snmp_community_set: bool = False
    snmp_v3_users: list[dict[str, Any]] = []
    snmp_allowed_sources: list[str] = []
    snmp_sys_contact: str = ""
    snmp_sys_location: str = ""
    # ── Appliance NTP (issue #154) ────────────────────────────────
    # No secrets in NTP — server hostnames are not sensitive, so
    # the read shape mirrors the stored shape directly.
    ntp_source_mode: str = "pool"
    ntp_pool_servers: list[str] = ["pool.ntp.org"]
    ntp_custom_servers: list[dict[str, Any]] = []
    ntp_allow_clients: bool = False
    ntp_allow_client_networks: list[str] = []
    # ── Appliance timezone (issue #165) ───────────────────────────
    # Empty string means "follow install-time default" (no override).
    timezone: str = ""
    # ── Appliance console mode (#393) ─────────────────────────────
    # ``dashboard`` (default) = quiet boot + Talos dashboard;
    # ``verbose_dashboard`` = verbose boot output then dashboard;
    # ``text_console`` = verbose boot + plain getty login (no dashboard).
    console_mode: str = "dashboard"
    # ── Supervisor (appliance) registration gate (#170 Wave A / #407) ──
    # When false, POST /appliance/supervisor/register 404s so a remote
    # supervisor cannot pair. OS-appliance control-plane installs self-
    # enable this on first boot; generic Kubernetes/Helm control planes
    # have no such auto-enable, so an operator must flip it on (here or
    # via the Fleet → Pairing toggle) before an appliance can register.
    supervisor_registration_enabled: bool = False
    # ── Maintenance mode (issue #57) ──────────────────────────────
    # System-wide read-only switch. ``maintenance_started_at`` is
    # server-managed (stamped on enable / cleared on disable) and so is
    # read-only here — it has no companion field on SettingsUpdate.
    maintenance_mode_enabled: bool = False
    maintenance_message: str = ""
    maintenance_started_at: datetime | None = None
    # ── Appliance LLDP (issue #343) ───────────────────────────────
    # No secrets — LLDP advertises public identity, so the read shape
    # mirrors the stored shape directly (like NTP).
    lldp_enabled: bool = False
    lldp_tx_interval: int = 30
    lldp_tx_hold: int = 4
    lldp_protocols: list[str] = []
    lldp_interface_pattern: str = ""
    lldp_management_pattern: str = ""
    lldp_sys_name: str = ""
    lldp_sys_description: str = ""
    lldp_med_location: dict[str, Any] = {}
    lldp_snmp_agentx: bool = False
    # ── Appliance syslog forwarding (issue #156) ──────────────────
    # Per-target ``ca_cert_pem`` ciphertext is folded into a per-entry
    # ``ca_cert_set`` boolean by the model validator below — the wire
    # never carries the CA PEM bytes (mirrors the SNMP community).
    syslog_enabled: bool = False
    syslog_targets: list[dict[str, Any]] = []
    syslog_filter: str = ""
    syslog_buffer_disk: bool = False
    # ── Appliance SSH (issue #157) ─────────────────────────────────
    # Public keys are NOT secrets — the authorized-keys list is returned
    # verbatim (no redaction, unlike the SNMP community / syslog CA PEM).
    # Each entry is ``{name, public_key, comment}``.
    ssh_authorized_keys: list[dict[str, Any]] = []
    ssh_password_auth_enabled: bool = True
    ssh_allow_root_login: bool = False
    ssh_port: int = 22
    ssh_allowed_source_networks: list[str] = []
    ssh_lockdown: bool = False
    # ── Appliance DNS resolver (issue #158) ───────────────────────
    # No secrets — resolver IPs / search domains are not sensitive, so
    # the read shape mirrors the stored shape directly (like NTP / SSH
    # public keys).
    resolver_mode: str = "automatic"
    resolver_servers: list[str] = []
    resolver_fallback_servers: list[str] = []
    resolver_search_domains: list[str] = []
    resolver_dnssec: str = "allow-downgrade"
    resolver_dns_over_tls: str = "no"
    # ── Appliance APT (issue #155) ─────────────────────────────────
    # Opt-in managed sources / proxy / GPG keys / private-mirror auth.
    # GPG armoured-key text + auth passwords fold into per-entry
    # ``armoured_text_set`` / ``password_set`` booleans (redacted below).
    apt_managed: bool = False
    apt_sources: list[dict[str, Any]] = []
    apt_gpg_keys: list[dict[str, Any]] = []
    apt_proxy_http: str = ""
    apt_proxy_https: str = ""
    apt_proxy_no_proxy: str = ""
    apt_auth: list[dict[str, Any]] = []
    apt_unattended_upgrades_enabled: bool = True
    # Issue #164 — unattended-upgrades policy (non-secret).
    apt_unattended_origins: list[str] = []
    apt_unattended_blocklist: list[str] = []
    apt_unattended_automatic_reboot: bool = False
    apt_unattended_reboot_time: str = "02:00"

    model_config = {"from_attributes": True}

    @model_validator(mode="before")
    @classmethod
    def _redact_secrets(cls, data: Any) -> Any:
        # When serializing a PlatformSettings ORM instance, fold every
        # ciphertext-bearing column into a boolean ``*_set`` marker so
        # the payload never leaks Fernet bytes — the UI only needs to
        # know whether a value is configured. v3 users get the same
        # treatment per-entry (auth_pass_enc / priv_pass_enc → bool
        # ``*_set`` flags).
        if isinstance(data, PlatformSettings):
            cols = {c.name: getattr(data, c.name) for c in data.__table__.columns}
            cols["fingerbank_api_key_set"] = bool(cols.pop("fingerbank_api_key_encrypted", None))
            cols["snmp_community_set"] = bool(cols.pop("snmp_community_encrypted", None))
            # #1502 — the legacy webhook URL is shown as its host only.
            webhook_url = cols.pop("audit_forward_webhook_url_encrypted", None)
            cols["audit_forward_webhook_url_set"] = bool(webhook_url)
            cols["audit_forward_webhook_url_display"] = url_display(
                reveal(webhook_url, field="audit_forward_webhook_url")
            )
            cols["audit_forward_webhook_auth_header_set"] = bool(
                cols.pop("audit_forward_webhook_auth_header_encrypted", None)
            )
            raw_users = cols.get("snmp_v3_users") or []
            cols["snmp_v3_users"] = [_redact_v3_user(u) for u in raw_users]
            # Issue #156 — fold each syslog target's CA PEM ciphertext into
            # a ``ca_cert_set`` boolean so the wire never carries the PEM.
            raw_targets = cols.get("syslog_targets") or []
            cols["syslog_targets"] = [_redact_syslog_target(t) for t in raw_targets]
            # Issue #155 — fold APT GPG armoured-key + private-mirror
            # password ciphertext into ``*_set`` booleans.
            cols["apt_gpg_keys"] = [
                _redact_apt_gpg_key(k) for k in (cols.get("apt_gpg_keys") or [])
            ]
            cols["apt_auth"] = [_redact_apt_auth(a) for a in (cols.get("apt_auth") or [])]
            return cols
        return data


def _redact_apt_gpg_key(k: Any) -> dict[str, Any]:
    """Strip the armoured-key ciphertext from a stored APT GPG-key dict —
    the operator only needs to know a key is present (#155)."""
    if not isinstance(k, dict):
        return {"key_id": "", "comment": "", "armoured_text_set": False}
    return {
        "key_id": k.get("key_id", ""),
        "comment": k.get("comment", ""),
        "armoured_text_set": bool(k.get("armoured_text_enc")),
    }


def _redact_apt_auth(a: Any) -> dict[str, Any]:
    """Strip the password ciphertext from a stored APT auth dict (#155)."""
    if not isinstance(a, dict):
        return {"machine": "", "login": "", "password_set": False}
    return {
        "machine": a.get("machine", ""),
        "login": a.get("login", ""),
        "password_set": bool(a.get("password_enc")),
    }


def _redact_v3_user(u: dict[str, Any]) -> dict[str, Any]:
    """Strip ciphertext from a stored v3-user dict for response shape."""
    return {
        "username": u.get("username", ""),
        "auth_protocol": u.get("auth_protocol") or "none",
        "auth_pass_set": bool(u.get("auth_pass_enc")),
        "priv_protocol": u.get("priv_protocol") or "none",
        "priv_pass_set": bool(u.get("priv_pass_enc")),
    }


def _redact_syslog_target(t: Any) -> dict[str, Any]:
    """Strip the CA PEM ciphertext from a stored syslog-target dict for
    the response shape — the operator only needs to know whether a CA
    is configured (``ca_cert_set``), never the PEM bytes (#156).

    Guards against a non-dict entry (e.g. a malformed JSONB row) so
    ``GET /settings`` never 500s — a bad entry coerces to an empty,
    clearly-default target rather than raising ``AttributeError``."""
    if not isinstance(t, dict):
        return {
            "host": "",
            "port": 514,
            "protocol": "udp",
            "format": "rfc5424",
            "ca_cert_set": False,
        }
    return {
        "host": t.get("host", ""),
        "port": int(t.get("port") or 514),
        "protocol": t.get("protocol") or "udp",
        "format": t.get("format") or "rfc5424",
        "ca_cert_set": bool(t.get("ca_cert_pem")),
    }


def _merge_syslog_targets(
    existing: list[dict[str, Any]], incoming: list[SyslogTargetUpdate]
) -> list[dict[str, Any]]:
    """Atomic replace + per-target CA-PEM merge keyed on ``(host, port)``.

    ``incoming`` is the full new list — targets not present are dropped.
    For each entry, ``ca_cert_pem`` of ``None`` preserves the existing
    ciphertext for the same ``(host, port)`` key; ``""`` clears; anything
    else is encrypted fresh. Mirrors ``_merge_snmp_v3_users`` so an
    operator editing a target's format doesn't have to re-paste its CA
    PEM. Encrypted bytes are stored as the URL-safe-base64 string Fernet
    emits so the JSONB column stays JSON-friendly.
    """
    from app.core.crypto import encrypt_str

    by_key = {(t.get("host"), int(t.get("port") or 514)): t for t in existing}
    out: list[dict[str, Any]] = []
    for entry in incoming:
        prior = by_key.get((entry.host, entry.port), {})
        if entry.protocol == "tls":
            submitted = entry.ca_cert_pem
            prior_enc = prior.get("ca_cert_pem")
            if submitted is None:
                ca_enc = prior_enc if isinstance(prior_enc, str) and prior_enc else None
            elif submitted == "":
                ca_enc = None
            else:
                ca_enc = encrypt_str(submitted).decode("ascii")
        else:
            # Non-TLS targets carry no CA — drop any prior ciphertext.
            ca_enc = None
        out.append(
            {
                "host": entry.host,
                "port": entry.port,
                "protocol": entry.protocol,
                "format": entry.format,
                "ca_cert_pem": ca_enc,
            }
        )
    return out


def _merge_snmp_v3_users(
    existing: list[dict[str, Any]], incoming: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Atomic replace + per-user pass merge keyed on username.

    ``incoming`` is the full new list — usernames not present are
    dropped. For each entry, ``auth_pass`` / ``priv_pass`` of
    ``None`` preserves the existing ciphertext for the same
    username; ``""`` clears; anything else is encrypted fresh.

    Encrypted bytes are stored as the URL-safe-base64 string Fernet
    emits so the column stays JSON-friendly.
    """
    from app.core.crypto import encrypt_str

    by_name = {u.get("username"): u for u in existing}
    out: list[dict[str, Any]] = []
    for entry in incoming:
        username = entry["username"]
        prior = by_name.get(username, {})

        def _resolve(submitted: str | None, prior_enc: Any) -> str | None:
            if submitted is None:
                return prior_enc if isinstance(prior_enc, str) and prior_enc else None
            if submitted == "":
                return None
            return encrypt_str(submitted).decode("ascii")

        auth_proto = entry.get("auth_protocol", "none")
        priv_proto = entry.get("priv_protocol", "none")
        out.append(
            {
                "username": username,
                "auth_protocol": auth_proto,
                "auth_pass_enc": (
                    _resolve(entry.get("auth_pass"), prior.get("auth_pass_enc"))
                    if auth_proto != "none"
                    else None
                ),
                "priv_protocol": priv_proto,
                "priv_pass_enc": (
                    _resolve(entry.get("priv_pass"), prior.get("priv_pass_enc"))
                    if priv_proto != "none"
                    else None
                ),
            }
        )
    return out


class SNMPV3UserUpdate(BaseModel):
    """One row in the v3 user list on PUT.

    ``auth_pass`` / ``priv_pass`` semantics mirror the audit-forward
    ``smtp_password`` pattern:

    * ``None`` — leave the existing ciphertext alone (matched by
      ``username`` against the stored list). Used when an operator
      edits sysContact and shouldn't have to retype passwords.
    * ``""`` — clear any existing ciphertext (downgrades the user to
      noAuth or noPriv).
    * non-empty string — encrypt and replace.
    """

    username: str
    auth_protocol: str = "none"
    auth_pass: str | None = None
    priv_protocol: str = "none"
    priv_pass: str | None = None

    @field_validator("username")
    @classmethod
    def _username_nonempty(cls, v: str) -> str:
        # snmpd's USM treats whitespace-only and empty usernames as
        # parse errors — reject early so the operator's PUT is the
        # error site, not a downstream snmpd reload.
        s = v.strip()
        if not s:
            raise ValueError("username may not be empty")
        # snmpd.conf is whitespace-delimited and does not quote the
        # username token, so INTERNAL whitespace splits the directive
        # into extra arguments and a newline ends it outright:
        # ``ops\nrwuser evil .1`` would inject a read-write user into
        # the rendered config. Reject at the boundary rather than
        # sanitising, so the operator sees the problem on their own PUT.
        # ``services/appliance/snmp.py`` re-checks at render time for
        # rows that predate this validator.
        if any(c.isspace() for c in s) or any(ord(c) < 32 for c in s):
            raise ValueError(
                "username may not contain whitespace or control characters — "
                "snmpd.conf is whitespace-delimited and cannot express them"
            )
        return s

    @field_validator("auth_protocol")
    @classmethod
    def _valid_auth_proto(cls, v: str) -> str:
        if v not in _SNMP_AUTH_PROTOCOLS:
            raise ValueError(f"auth_protocol must be one of {sorted(_SNMP_AUTH_PROTOCOLS)}")
        return v

    @field_validator("priv_protocol")
    @classmethod
    def _valid_priv_proto(cls, v: str) -> str:
        if v not in _SNMP_PRIV_PROTOCOLS:
            raise ValueError(f"priv_protocol must be one of {sorted(_SNMP_PRIV_PROTOCOLS)}")
        return v


class NTPCustomServerUpdate(BaseModel):
    """One entry in ``ntp_custom_servers`` on PUT.

    ``host`` is the NTP server hostname or IP. ``iburst`` accelerates
    initial sync (chrony sends a burst of 8 packets at startup);
    ``prefer`` tags this server as the canonical source — chrony
    biases toward it for selection when ``prefer`` matches. Both
    flags default off because the safe choice is a neutral
    operator-equal-weight pool; operators flip them as needed.
    """

    host: str
    iburst: bool = False
    prefer: bool = False

    @field_validator("host")
    @classmethod
    def _host_nonempty(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("host may not be empty")
        # chrony's parser treats whitespace as a separator inside the
        # server directive, so reject whitespace in the hostname here.
        if any(c.isspace() for c in s):
            raise ValueError("host may not contain whitespace")
        return s


class SyslogTargetUpdate(BaseModel):
    """One entry in ``syslog_targets`` on PUT (#156).

    ``host`` is the collector hostname / IP; ``port`` 1–65535;
    ``protocol`` one of ``udp`` / ``tcp`` / ``tls``; ``format`` one of
    ``rfc5424`` / ``rfc3164`` / ``json``. ``ca_cert_pem`` is REQUIRED
    when ``protocol == 'tls'`` and ignored otherwise; its merge
    semantics mirror the SNMP v3 pass / SMTP password shape:

    * ``None`` — leave the existing ciphertext alone (matched by
      ``(host, port)`` against the stored list).
    * ``""`` — clear any existing ciphertext.
    * non-empty string — encrypt and replace.
    """

    host: str
    port: int = 514
    protocol: str = "udp"
    format: str = "rfc5424"
    ca_cert_pem: str | None = None

    @field_validator("host")
    @classmethod
    def _syslog_host_nonempty(cls, v: str) -> str:
        # Strict charset shared with the AI proposal path — the host is
        # interpolated into a quoted RainerScript action param, so reject
        # quotes / backslashes / whitespace / control chars, not just
        # empty values.
        return validate_syslog_host(v)

    @field_validator("port")
    @classmethod
    def _syslog_port_range(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port must be 1–65535")
        return v

    @field_validator("protocol")
    @classmethod
    def _syslog_protocol(cls, v: str) -> str:
        if v not in _SYSLOG_PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(_SYSLOG_PROTOCOLS)}")
        return v

    @field_validator("format")
    @classmethod
    def _syslog_format(cls, v: str) -> str:
        if v not in _SYSLOG_FORMATS:
            raise ValueError(f"format must be one of {sorted(_SYSLOG_FORMATS)}")
        return v

    @model_validator(mode="after")
    def _tls_requires_ca(self) -> SyslogTargetUpdate:
        # A TLS target needs a CA to validate the collector's cert. The
        # PEM may be supplied now (non-empty string) OR already stored —
        # but ``""`` (explicit clear) on a TLS target leaves it with no
        # CA, which can't validate, so reject that here. ``None`` is OK:
        # it means "keep the existing CA", which the merge resolves.
        if self.protocol == "tls" and self.ca_cert_pem == "":
            raise ValueError("ca_cert_pem is required when protocol is 'tls'")
        return self


class SshAuthorizedKeyUpdate(BaseModel):
    """One entry in ``ssh_authorized_keys`` on PUT (#157).

    ``public_key`` is a single OpenSSH public-key line (``<type>
    <base64-blob> [comment]``); ``name`` is an operator label, ``comment``
    an optional note. Public keys are NOT secrets — they are stored
    verbatim (no Fernet). The key is validated strictly so a malformed /
    multi-line / control-char value can't slip into authorized_keys.
    """

    name: str = ""
    public_key: str
    comment: str = ""

    @field_validator("public_key")
    @classmethod
    def _valid_public_key(cls, v: str) -> str:
        s = v.strip()
        if not is_valid_public_key(s):
            raise ValueError(
                "public_key must be a valid OpenSSH public key "
                "(e.g. 'ssh-ed25519 AAAA… comment') — type + base64 blob, "
                "no embedded newlines / control characters"
            )
        return s

    @field_validator("name", "comment")
    @classmethod
    def _no_control_chars(cls, v: str) -> str:
        # Names / comments land near the rendered authorized_keys line —
        # reject control chars (incl. newlines) so they can't break the
        # file format.
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("must not contain control characters")
        return v.strip()


class AptSourceUpdate(BaseModel):
    """One repo row in ``apt_sources`` on PUT (#155). No secrets — the
    armoured key lives in ``apt_gpg_keys`` and is referenced by
    ``signed_by_key_id``."""

    name: str = ""
    uri: str
    suites: str
    components: str = ""
    signed_by_key_id: str = ""
    enabled: bool = True

    @field_validator("uri")
    @classmethod
    def _valid_uri(cls, v: str) -> str:
        s = v.strip()
        # apt transports: a typo here is exactly the "bricks apt update"
        # case the issue calls out — reject an unknown scheme at the PUT
        # so the operator's request is the error site.
        allowed = ("http://", "https://", "ftp://", "file:", "cdrom:", "mirror+")
        if not s or not s.startswith(allowed):
            raise ValueError(
                "uri must start with a supported apt transport "
                "(http://, https://, ftp://, file:, …)"
            )
        if any(c.isspace() for c in s):
            raise ValueError("uri may not contain whitespace")
        return s

    @field_validator("suites")
    @classmethod
    def _suites_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("suites may not be empty")
        return v.strip()

    @field_validator("signed_by_key_id")
    @classmethod
    def _valid_signed_by(cls, v: str) -> str:
        # Flows into the rendered ``[signed-by=/etc/apt/keyrings/spatiumddi-
        # <id>.asc]`` option — restrict to the same filesystem-safe charset
        # as AptGpgKeyUpdate.key_id so a source can't inject a path
        # separator / apt option syntax into the deb line.
        s = v.strip()
        if s and not all(c.isalnum() or c in "._-" for c in s):
            raise ValueError("signed_by_key_id may only contain alphanumerics, '.', '_', '-'")
        return s

    @field_validator("name", "components")
    @classmethod
    def _no_control_chars(cls, v: str) -> str:
        # ``name`` → sources.list comment, ``components`` → the deb line;
        # reject newlines / control chars so a value can't inject an extra
        # directive into the rendered file.
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("must not contain control characters")
        return v.strip()


class AptGpgKeyUpdate(BaseModel):
    """One entry in ``apt_gpg_keys`` on PUT (#155).

    ``armoured_text`` merge semantics mirror the SNMP v3 pass shape:
    ``None`` keeps the existing ciphertext (matched by ``key_id``), ``""``
    clears it, a non-empty string is encrypted fresh.
    """

    key_id: str
    comment: str = ""
    armoured_text: str | None = None

    @field_validator("key_id")
    @classmethod
    def _key_id_nonempty(cls, v: str) -> str:
        s = v.strip()
        # ``key_id`` becomes the keyring filename (spatiumddi-<id>.asc) so
        # restrict it to a filesystem-safe charset.
        if not s:
            raise ValueError("key_id may not be empty")
        if not all(c.isalnum() or c in "._-" for c in s):
            raise ValueError("key_id may only contain alphanumerics, '.', '_', '-'")
        return s


class AptAuthUpdate(BaseModel):
    """One entry in ``apt_auth`` (private-mirror creds) on PUT (#155).

    ``password`` merge semantics mirror the SNMP v3 pass shape (None
    preserves, "" clears, non-empty encrypts).
    """

    machine: str
    login: str
    password: str | None = None

    @field_validator("machine", "login")
    @classmethod
    def _nonempty_no_ws(cls, v: str) -> str:
        s = v.strip()
        if not s or any(c.isspace() for c in s):
            raise ValueError("must be non-empty and contain no whitespace")
        return s

    @field_validator("password")
    @classmethod
    def _password_no_control(cls, v: str | None) -> str | None:
        # Rendered into a netrc-style ``machine … password <value>`` line;
        # reject newlines / control chars so a value can't inject an extra
        # auth.conf line. ``None`` (preserve) / ``""`` (clear) pass through.
        if v and any(ord(c) < 0x20 for c in v):
            raise ValueError("password must not contain control characters")
        return v


def _merge_apt_gpg_keys(
    existing: list[dict[str, Any]], incoming: list[AptGpgKeyUpdate]
) -> list[dict[str, Any]]:
    """Atomic replace + per-key armoured-text merge keyed on ``key_id``.
    ``armoured_text`` None preserves the stored ciphertext, "" clears,
    non-empty encrypts fresh (mirrors ``_merge_snmp_v3_users``)."""
    from app.core.crypto import encrypt_str

    by_id = {k.get("key_id"): k for k in existing if isinstance(k, dict)}
    out: list[dict[str, Any]] = []
    for entry in incoming:
        prior = by_id.get(entry.key_id, {})
        if entry.armoured_text is None:
            prior_enc = prior.get("armoured_text_enc")
            enc = prior_enc if isinstance(prior_enc, str) and prior_enc else None
        elif entry.armoured_text == "":
            enc = None
        else:
            enc = encrypt_str(entry.armoured_text).decode("ascii")
        out.append({"key_id": entry.key_id, "comment": entry.comment, "armoured_text_enc": enc})
    return out


def _merge_apt_auth(
    existing: list[dict[str, Any]], incoming: list[AptAuthUpdate]
) -> list[dict[str, Any]]:
    """Atomic replace + per-entry password merge keyed on ``(machine,
    login)`` (mirrors ``_merge_apt_gpg_keys``)."""
    from app.core.crypto import encrypt_str

    by_key = {(a.get("machine"), a.get("login")): a for a in existing if isinstance(a, dict)}
    out: list[dict[str, Any]] = []
    for entry in incoming:
        prior = by_key.get((entry.machine, entry.login), {})
        if entry.password is None:
            prior_enc = prior.get("password_enc")
            enc = prior_enc if isinstance(prior_enc, str) and prior_enc else None
        elif entry.password == "":
            enc = None
        else:
            enc = encrypt_str(entry.password).decode("ascii")
        out.append({"machine": entry.machine, "login": entry.login, "password_enc": enc})
    return out


class SettingsUpdate(BaseModel):
    app_title: str | None = None
    app_base_url: str | None = None
    # Login banner (#885) + environment banner (#887).
    login_banner_enabled: bool | None = None
    login_banner_title: str | None = None
    login_banner_text: str | None = None
    login_banner_require_ack: bool | None = None
    env_banner_enabled: bool | None = None
    env_banner_text: str | None = None
    env_banner_bg: str | None = None
    env_banner_fg: str | None = None
    env_banner_position: Literal["top", "bottom", "both"] | None = None
    ip_allocation_strategy: str | None = None
    session_timeout_minutes: int | None = None
    auto_logout_minutes: int | None = None
    utilization_warn_threshold: int | None = None
    utilization_critical_threshold: int | None = None
    utilization_max_prefix_ipv4: int | None = None
    utilization_max_prefix_ipv6: int | None = None
    subnet_tree_default_expanded_depth: int | None = None
    github_release_check_enabled: bool | None = None
    dns_default_ttl: int | None = None
    dns_default_zone_type: str | None = None
    dns_default_dnssec_validation: str | None = None
    dns_recursive_by_default: bool | None = None
    dns_auto_sync_enabled: bool | None = None
    dns_auto_sync_interval_minutes: int | None = None
    dns_auto_sync_delete_stale: bool | None = None
    reverse_dns_enabled: bool | None = None
    reverse_dns_interval_minutes: int | None = None
    reverse_dns_resolvers: list[str] | None = None
    dns_pull_from_server_enabled: bool | None = None
    dns_pull_from_server_interval_minutes: int | None = None
    dhcp_pull_leases_enabled: bool | None = None
    dhcp_pull_leases_interval_seconds: int | None = None
    audit_forward_syslog_enabled: bool | None = None
    audit_forward_syslog_host: str | None = None
    audit_forward_syslog_port: int | None = None
    audit_forward_syslog_protocol: str | None = None
    audit_forward_syslog_facility: int | None = None
    audit_forward_webhook_enabled: bool | None = None
    audit_forward_webhook_url: str | None = None
    audit_forward_webhook_auth_header: str | None = None
    dhcp_default_dns_servers: list[str] | None = None
    dhcp_default_domain_name: str | None = None
    dhcp_default_domain_search: list[str] | None = None
    dhcp_default_ntp_servers: list[str] | None = None
    dhcp_default_lease_time: int | None = None
    oui_lookup_enabled: bool | None = None
    oui_update_interval_hours: int | None = None
    integration_kubernetes_enabled: bool | None = None
    integration_docker_enabled: bool | None = None
    integration_proxmox_enabled: bool | None = None
    integration_tailscale_enabled: bool | None = None
    integration_unifi_enabled: bool | None = None
    integration_cloud_enabled: bool | None = None
    integration_opnsense_enabled: bool | None = None
    domain_whois_interval_hours: int | None = None
    # Device profiling — fingerbank API key. Plaintext on the wire
    # (TLS-protected); empty string clears the stored value. Omit the
    # field entirely to leave the existing value alone (pydantic
    # ``model_dump(exclude_none=True)`` semantics in the write path).
    fingerbank_api_key: str | None = None
    # ASN / RPKI Phase 2 settings (issue #85).
    asn_whois_interval_hours: int | None = None
    rpki_roa_source: str | None = None
    rpki_roa_refresh_interval_hours: int | None = None
    bgp_monitoring_enabled: bool | None = None
    bgp_monitoring_interval_hours: int | None = None
    # VRF strict-RD validation toggle (issue #86 phase 2).
    vrf_strict_rd_validation: bool | None = None
    # Operator Copilot daily digest (issue #90 Phase 2).
    ai_daily_digest_enabled: bool | None = None
    # Password policy (issue #70).
    password_min_length: int | None = None
    password_require_uppercase: bool | None = None
    password_require_lowercase: bool | None = None
    password_require_digit: bool | None = None
    password_require_symbol: bool | None = None
    password_history_count: int | None = None
    password_max_age_days: int | None = None
    # Account lockout (issue #71).
    lockout_threshold: int | None = None
    lockout_duration_minutes: int | None = None
    lockout_reset_minutes: int | None = None
    # ── Appliance SNMP (issue #153) ───────────────────────────────
    snmp_enabled: bool | None = None
    snmp_version: str | None = None
    # ``None`` = leave alone, ``""`` = clear stored community,
    # non-empty = encrypt + replace. Plaintext on the wire (TLS).
    snmp_community: str | None = None
    # When provided, this list is the new full set — usernames not in
    # the incoming list are removed. Per-user pass semantics see
    # ``SNMPV3UserUpdate`` docstring.
    snmp_v3_users: list[SNMPV3UserUpdate] | None = None
    snmp_allowed_sources: list[str] | None = None
    snmp_sys_contact: str | None = None
    snmp_sys_location: str | None = None
    # ── Appliance NTP (issue #154) ────────────────────────────────
    ntp_source_mode: str | None = None
    ntp_pool_servers: list[str] | None = None
    ntp_custom_servers: list[NTPCustomServerUpdate] | None = None
    ntp_allow_clients: bool | None = None
    ntp_allow_client_networks: list[str] | None = None
    # ── Appliance timezone (issue #165) ───────────────────────────
    timezone: str | None = None
    # ── Appliance console mode (#393) ─────────────────────────────
    console_mode: Literal["dashboard", "verbose_dashboard", "text_console"] | None = None
    # ── Supervisor (appliance) registration gate (#170 Wave A / #407) ──
    # Not a host-config field (no supervisor wake needed) — it's read
    # fresh by the register endpoint's module gate on the next pairing.
    supervisor_registration_enabled: bool | None = None
    # ── Maintenance mode (issue #57) ──────────────────────────────
    # ``maintenance_started_at`` is intentionally NOT settable here —
    # it's server-stamped in ``update_settings`` when the enable flag
    # flips, never operator-supplied.
    maintenance_mode_enabled: bool | None = None
    maintenance_message: str | None = None
    # ── Appliance LLDP (issue #343) ───────────────────────────────
    lldp_enabled: bool | None = None
    lldp_tx_interval: int | None = None
    lldp_tx_hold: int | None = None
    lldp_protocols: list[str] | None = None
    lldp_interface_pattern: str | None = None
    lldp_management_pattern: str | None = None
    lldp_sys_name: str | None = None
    lldp_sys_description: str | None = None
    lldp_med_location: dict[str, Any] | None = None
    lldp_snmp_agentx: bool | None = None
    # ── Appliance syslog forwarding (issue #156) ──────────────────
    syslog_enabled: bool | None = None
    # When provided, this list is the new full set — targets not in the
    # incoming list are removed. Per-target CA-PEM merge semantics see
    # ``SyslogTargetUpdate`` docstring (None = leave, "" = clear,
    # non-empty = encrypt + replace).
    syslog_targets: list[SyslogTargetUpdate] | None = None
    syslog_filter: str | None = None
    syslog_buffer_disk: bool | None = None
    # ── Appliance SSH (issue #157) ─────────────────────────────────
    ssh_authorized_keys: list[SshAuthorizedKeyUpdate] | None = None
    ssh_password_auth_enabled: bool | None = None
    ssh_allow_root_login: bool | None = None
    ssh_port: int | None = None
    ssh_allowed_source_networks: list[str] | None = None
    ssh_lockdown: bool | None = None
    # Neither of these is a column — both are acknowledgements for the
    # self-lockout pre-flights below, popped out of ``changes`` before
    # anything is written.
    #
    # ``ssh_lockdown_force`` accepts losing THIS door while another remains.
    # ``acknowledge_console_only`` (#1013) accepts losing EVERY remote door,
    # which is a materially larger thing and so cannot be satisfied by the
    # smaller tick — an operator may have sent that one for another reason.
    ssh_lockdown_force: bool | None = None
    acknowledge_console_only: bool | None = None
    # ── Appliance DNS resolver (issue #158) ───────────────────────
    resolver_mode: str | None = None
    resolver_servers: list[str] | None = None
    resolver_fallback_servers: list[str] | None = None
    resolver_search_domains: list[str] | None = None
    resolver_dnssec: str | None = None
    resolver_dns_over_tls: str | None = None
    # ── Appliance APT (issue #155) ─────────────────────────────────
    apt_managed: bool | None = None
    apt_sources: list[AptSourceUpdate] | None = None
    apt_gpg_keys: list[AptGpgKeyUpdate] | None = None
    apt_proxy_http: str | None = None
    apt_proxy_https: str | None = None
    apt_proxy_no_proxy: str | None = None
    apt_auth: list[AptAuthUpdate] | None = None
    apt_unattended_upgrades_enabled: bool | None = None
    # Issue #164 — unattended-upgrades policy.
    apt_unattended_origins: list[str] | None = None
    apt_unattended_blocklist: list[str] | None = None
    apt_unattended_automatic_reboot: bool | None = None
    apt_unattended_reboot_time: str | None = None

    @field_validator("apt_unattended_reboot_time")
    @classmethod
    def _valid_unattended_reboot_time(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", s):
            raise ValueError("reboot time must be HH:MM (24-hour), e.g. 02:00")
        return s

    @field_validator("apt_unattended_origins", "apt_unattended_blocklist")
    @classmethod
    def _valid_unattended_list(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = str(raw).strip()
            if not s:
                continue
            # These land inside apt.conf double-quoted strings, and apt.conf has
            # no escape syntax there (#1384, verified against apt-config): a
            # backslash is kept literally and a double quote ENDS the string,
            # so an entry carrying one makes apt-config reject the whole policy
            # file and the host keeps the old one. Reject quotes, control
            # chars — C0 (< 0x20) AND ASCII DEL (0x7f) — and over-long entries
            # so a value can't smuggle a newline / extra directive past the
            # render.
            if any(ord(c) < 0x20 or ord(c) == 0x7F or c == '"' for c in s) or len(s) > 200:
                raise ValueError(
                    "unattended origin / package entries must be printable, contain no "
                    "double quote, and be ≤ 200 chars"
                )
            out.append(s)
        return out

    @field_validator("apt_unattended_blocklist")
    @classmethod
    def _blocklist_entries_are_regexes(cls, v: list[str] | None) -> list[str] | None:
        # unattended-upgrades reads each Package-Blacklist entry as a Python
        # regular expression matched from the start of the package name
        # (#1384). The form used to call them globs, so ``*`` (an invalid
        # regex) was a natural thing to type, and an entry that will not
        # compile is refused here rather than on the host, where it would
        # break the daily run and stop every security update with it. Runs
        # after the generic checks above (pydantic applies validators in
        # declaration order).
        if v is None:
            return None
        for entry in v:
            try:
                re.compile(entry)
            except re.error as exc:
                raise ValueError(
                    f"package blocklist entry {entry!r} is not a valid regular expression "
                    f"({exc}); entries match from the start of the package name, "
                    "e.g. 'linux-image-' or '^openssl$'"
                ) from exc
        return v

    @field_validator("apt_proxy_http", "apt_proxy_https")
    @classmethod
    def _valid_apt_proxy(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if s and not s.startswith(("http://", "https://")):
            raise ValueError("proxy URL must start with http:// or https://")
        # Interpolated into ``Acquire::http::Proxy "<value>";`` — reject the
        # double-quote / control chars that would break the apt.conf grammar
        # or inject an extra directive.
        if any(c == '"' or ord(c) < 0x20 for c in s):
            raise ValueError("proxy URL must not contain quotes or control characters")
        return s

    @field_validator("apt_proxy_no_proxy")
    @classmethod
    def _valid_apt_no_proxy(cls, v: str | None) -> str | None:
        # Each comma-separated host becomes ``Acquire::http::Proxy::<host>
        # "DIRECT";`` — reject quotes / control chars for the same reason.
        if v and any(c == '"' or ord(c) < 0x20 for c in v):
            raise ValueError("no_proxy must not contain quotes or control characters")
        return v

    @field_validator("resolver_mode")
    @classmethod
    def _valid_resolver_mode(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _RESOLVER_MODES:
            raise ValueError(f"resolver_mode must be one of {sorted(_RESOLVER_MODES)}")
        return v

    @field_validator("resolver_dnssec")
    @classmethod
    def _valid_resolver_dnssec(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _RESOLVER_DNSSEC:
            raise ValueError(f"resolver_dnssec must be one of {sorted(_RESOLVER_DNSSEC)}")
        return v

    @field_validator("resolver_dns_over_tls")
    @classmethod
    def _valid_resolver_dot(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _RESOLVER_DOT:
            raise ValueError(f"resolver_dns_over_tls must be one of {sorted(_RESOLVER_DOT)}")
        return v

    @field_validator("resolver_servers", "resolver_fallback_servers")
    @classmethod
    def _valid_resolver_servers(cls, v: list[str] | None) -> list[str] | None:
        # Each entry must parse as a bare IP address — systemd-resolved's
        # ``DNS=`` / ``FallbackDNS=`` take resolver IPs (v4 or v6), not
        # hostnames. Reuse the same shape as the reverse_dns_resolvers
        # validator below. Strip whitespace + drop empties.
        if v is None:
            return None
        import ipaddress  # noqa: PLC0415

        cleaned: list[str] = []
        for entry in v:
            host = (entry or "").strip()
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise ValueError(f"invalid resolver IP: {entry!r}") from exc
            cleaned.append(host)
        return cleaned

    @field_validator("resolver_search_domains")
    @classmethod
    def _valid_resolver_search(cls, v: list[str] | None) -> list[str] | None:
        # Search domains are rendered straight into the ``Domains=`` line, so
        # reject embedded whitespace / control chars (a smuggled space would
        # split one domain into two; a newline would break out of the line).
        # Strip + drop empties.
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = (raw or "").strip()
            if not s:
                continue
            if any(c.isspace() for c in s) or any(ord(c) < 0x20 for c in s):
                raise ValueError(
                    f"search domain may not contain whitespace / control chars: {raw!r}"
                )
            out.append(s)
        return out

    @model_validator(mode="after")
    def _resolver_override_requires_servers(self) -> SettingsUpdate:
        # CROSS-FIELD guard (#158, mirrors the SSH lockout-safety pattern):
        # override mode routes ALL host DNS to the global ``DNS=`` server
        # list (``Domains=~.``), so an override with an empty server list
        # leaves the appliance host with zero working upstream DNS — and with
        # DNSOverTLS=yes there's no plaintext fallback either, making it
        # effectively unrecoverable until corrected. Reject the in-request
        # case where override is selected AND servers are explicitly cleared.
        # ``resolver_servers is None`` means "leave the stored list alone";
        # the merged-state guard in ``update_settings`` catches the case where
        # the stored list is also empty (it can see the DB row).
        if (
            self.resolver_mode == "override"
            and self.resolver_servers is not None
            and not self.resolver_servers
        ):
            raise ValueError("resolver override mode requires at least one DNS server")
        return self

    @field_validator("ssh_port")
    @classmethod
    def _valid_ssh_port(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (1 <= v <= 65535):
            raise ValueError("ssh_port must be 1–65535")
        # Privileged-port floor — reject < 1024 except 22 so an operator
        # can't park sshd somewhere that needs root-only bind privileges
        # the runner can't reliably reach. 22 is always an allowed value;
        # the host runner does the real bind / in-use check. (Unrelated to
        # the port-22 firewall floor, which #1009 made retireable.)
        if v < 1024 and v != 22:
            raise ValueError(
                "ssh_port below 1024 is not allowed (except 22) — pick a "
                "non-privileged port or keep 22"
            )
        return v

    @field_validator("ssh_allowed_source_networks")
    @classmethod
    def _valid_ssh_sources(cls, v: list[str] | None) -> list[str] | None:
        # Same CIDR canonicalisation as snmp_allowed_sources — the host
        # nftables drop-in source-scopes the ssh port to these.
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = raw.strip()
            if not s:
                continue
            try:
                net = ip_network(s, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR or host: {raw!r} ({exc})") from exc
            out.append(str(net))
        return out

    @field_validator("syslog_filter")
    @classmethod
    def _valid_syslog_filter(cls, v: str | None) -> str | None:
        # rsyslog selector — ``facility.severity`` tokens, comma-joined,
        # plus ``*`` wildcards and the ``!`` / ``=`` / ``;`` modifiers.
        # Rendered straight into the conf body, so reject control chars /
        # newlines / quotes to keep config injection out. Empty = the
        # renderer defaults to ``*.*``. Shared with the AI proposal path.
        return validate_syslog_filter(v)

    @field_validator("lldp_tx_interval")
    @classmethod
    def _valid_lldp_tx_interval(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 3600):
            raise ValueError("lldp_tx_interval must be 1..3600 seconds")
        return v

    @field_validator("lldp_tx_hold")
    @classmethod
    def _valid_lldp_tx_hold(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 100):
            raise ValueError("lldp_tx_hold must be 1..100")
        return v

    @field_validator("lldp_protocols")
    @classmethod
    def _valid_lldp_protocols(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        allowed = {"cdp", "edp", "fdp", "sonmp"}
        out: list[str] = []
        for p in v:
            pl = str(p).strip().lower()
            if pl not in allowed:
                raise ValueError(f"lldp_protocols entries must be one of {sorted(allowed)}")
            if pl not in out:
                out.append(pl)
        return out

    @field_validator("lldp_interface_pattern", "lldp_management_pattern")
    @classmethod
    def _valid_lldp_pattern(cls, v: str | None) -> str | None:
        # Rendered straight into an lldpcli ``configure … pattern`` directive,
        # so reject anything outside the glob/CIDR charset to keep config
        # injection out (newlines, quotes, shell metachars).
        if v is None:
            return None
        v = v.strip()
        if v and not re.fullmatch(r"[A-Za-z0-9_*!,.\- /:]+", v):
            raise ValueError("pattern may only contain letters, digits, and * ! , . - _ / : space")
        return v

    @field_validator("lldp_sys_name", "lldp_sys_description")
    @classmethod
    def _valid_lldp_sys_text(cls, v: str | None) -> str | None:
        # Quoted by the renderer, but reject control chars / newlines outright
        # so a value can't break out of the lldpcli line.
        if v is None:
            return None
        if any(ord(c) < 32 for c in v):
            raise ValueError("must not contain control characters or newlines")
        return v

    @field_validator("lldp_med_location")
    @classmethod
    def _valid_lldp_med_location(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        # LLDP-MED location (issue #348). The only rendered form today is ELIN
        # (E911 number) — must be digits, since it's rendered bare into
        # ``configure med location elin <n>``. Other keys are accepted + stored
        # for future coordinate/civic support but not yet rendered.
        if v is None:
            return None
        elin = v.get("elin")
        if elin is not None and not str(elin).strip().isdigit():
            raise ValueError("lldp_med_location.elin must be a numeric E911 ELIN")
        return v

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, v: str | None) -> str | None:
        """Validate IANA tz name on PUT. Empty string is allowed
        (clears the override). Non-empty must parse via
        ``zoneinfo.ZoneInfo`` — anything else 422s with a clean
        message instead of waiting for the host runner to bounce."""
        if v is None or v == "":
            return v
        try:
            from zoneinfo import ZoneInfo  # noqa: PLC0415

            ZoneInfo(v)
        except Exception as exc:  # noqa: BLE001 — surface the parse failure
            raise ValueError(f"timezone {v!r} is not a valid IANA tz name: {exc}") from exc
        return v

    @field_validator("env_banner_bg", "env_banner_fg")
    @classmethod
    def _valid_banner_colour(cls, v: str | None) -> str | None:
        # The colour is written straight into an inline ``style`` on every
        # page, so it has to be a literal we control the shape of — a
        # 6-digit hex triple and nothing else. Anything looser (named
        # colours, ``rgb()``, CSS functions) would be operator-supplied
        # text landing in a style attribute.
        if v is None:
            return None
        s = v.strip().lower()
        if not re.fullmatch(r"#[0-9a-f]{6}", s):
            raise ValueError("colour must be a 6-digit hex value such as #b91c1c")
        return s

    @field_validator("env_banner_text")
    @classmethod
    def _valid_env_banner_text(cls, v: str | None) -> str | None:
        # Mirrors the column width (VARCHAR(200)).
        if v is not None and len(v) > 200:
            raise ValueError("env_banner_text must be 200 characters or fewer")
        return v

    @field_validator("login_banner_title")
    @classmethod
    def _valid_login_banner_title(cls, v: str | None) -> str | None:
        # Mirrors the column width (VARCHAR(120)).
        if v is not None and len(v) > 120:
            raise ValueError("login_banner_title must be 120 characters or fewer")
        return v

    @field_validator("login_banner_text")
    @classmethod
    def _valid_login_banner_text(cls, v: str | None) -> str | None:
        # The column is unbounded TEXT, but this renders in a fixed-width
        # box above the sign-in form — cap it so a paste accident can't
        # push the form off-screen for every user at once.
        if v is not None and len(v) > 8000:
            raise ValueError("login_banner_text must be 8000 characters or fewer")
        return v

    @field_validator("maintenance_message")
    @classmethod
    def _validate_maintenance_message(cls, v: str | None) -> str | None:
        # Mirrors the column width (VARCHAR(500)) — reject overlong banners
        # at the API boundary with a clean 422 instead of a DB truncation
        # error. ``None`` (field omitted) is left alone.
        if v is not None and len(v) > 500:
            raise ValueError("maintenance_message must be 500 characters or fewer")
        return v

    @field_validator("lockout_threshold")
    @classmethod
    def validate_lockout_threshold(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 100):
            raise ValueError("Lockout threshold must be 0–100 (0 disables)")
        return v

    @field_validator("lockout_duration_minutes", "lockout_reset_minutes")
    @classmethod
    def validate_lockout_window(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 1440):
            raise ValueError("Lockout window must be 1–1440 minutes")
        return v

    @field_validator("password_min_length")
    @classmethod
    def validate_password_min_length(cls, v: int | None) -> int | None:
        # Floor at 6 even when operators relax the policy — anything
        # shorter is a configuration mistake. Cap at 128 because bcrypt
        # truncates inputs above 72 bytes; values past that are dead
        # length the operator might assume is being checked.
        if v is not None and not (6 <= v <= 128):
            raise ValueError("Min password length must be between 6 and 128")
        return v

    @field_validator("password_history_count")
    @classmethod
    def validate_password_history_count(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 24):
            raise ValueError("Password history must be 0–24 (0 disables)")
        return v

    @field_validator("password_max_age_days")
    @classmethod
    def validate_password_max_age_days(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 3650):
            raise ValueError("Password max age must be 0–3650 days (0 disables)")
        return v

    @field_validator("ip_allocation_strategy")
    @classmethod
    def validate_strategy(cls, v: str | None) -> str | None:
        if v is not None and v not in ("sequential", "random"):
            raise ValueError("ip_allocation_strategy must be 'sequential' or 'random'")
        return v

    @field_validator("session_timeout_minutes")
    @classmethod
    def validate_session_timeout(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("Must be >= 0 (0 = no timeout)")
        return v

    @field_validator(
        "dns_auto_sync_interval_minutes",
        "dns_pull_from_server_interval_minutes",
        "reverse_dns_interval_minutes",
        "oui_update_interval_hours",
    )
    @classmethod
    def validate_positive(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("Must be >= 1")
        return v

    @field_validator("reverse_dns_resolvers")
    @classmethod
    def validate_resolvers(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        import ipaddress

        cleaned: list[str] = []
        for entry in v:
            host = (entry or "").strip()
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise ValueError(f"Invalid resolver IP: {entry!r}") from exc
            cleaned.append(host)
        return cleaned

    @field_validator(
        "asn_whois_interval_hours",
        "rpki_roa_refresh_interval_hours",
        "bgp_monitoring_interval_hours",
    )
    @classmethod
    def validate_asn_rpki_interval(cls, v: int | None) -> int | None:
        if v is None:
            return None
        if not (1 <= v <= 168):
            raise ValueError("Must be between 1 and 168 hours")
        return v

    @field_validator("rpki_roa_source")
    @classmethod
    def validate_rpki_source(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in ("cloudflare", "ripe"):
            raise ValueError("rpki_roa_source must be 'cloudflare' or 'ripe'")
        return v

    @field_validator("dhcp_pull_leases_interval_seconds")
    @classmethod
    def validate_dhcp_pull_seconds(cls, v: int | None) -> int | None:
        # Beat ticks every 10 s — anything below that can't be honoured.
        if v is not None and v < 10:
            raise ValueError("Must be >= 10 (Celery beat ticks every 10 seconds)")
        return v

    @field_validator("domain_whois_interval_hours")
    @classmethod
    def validate_domain_whois_interval(cls, v: int | None) -> int | None:
        # Beat ticks every hour for the domain refresh; floor at 1 h
        # (any faster than that just self-skips). Cap at 168 h (one
        # week) — slower than that and operators may as well not have
        # the feature on.
        if v is not None and not (1 <= v <= 168):
            raise ValueError("Must be between 1 and 168 hours")
        return v

    @field_validator("utilization_warn_threshold", "utilization_critical_threshold")
    @classmethod
    def validate_threshold(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 100):
            raise ValueError("Threshold must be between 0 and 100")
        return v

    @field_validator("utilization_max_prefix_ipv4")
    @classmethod
    def validate_max_prefix_v4(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 32):
            raise ValueError("Max IPv4 prefix must be 0–32")
        return v

    @field_validator("utilization_max_prefix_ipv6")
    @classmethod
    def validate_max_prefix_v6(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 128):
            raise ValueError("Max IPv6 prefix must be 0–128")
        return v

    @field_validator("audit_forward_syslog_protocol")
    @classmethod
    def validate_syslog_protocol(cls, v: str | None) -> str | None:
        if v is not None and v not in ("udp", "tcp"):
            raise ValueError("syslog_protocol must be 'udp' or 'tcp'")
        return v

    @field_validator("audit_forward_syslog_port")
    @classmethod
    def validate_syslog_port(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("Port must be 1–65535")
        return v

    @field_validator("audit_forward_syslog_facility")
    @classmethod
    def validate_syslog_facility(cls, v: int | None) -> int | None:
        # RFC 5424 §6.2.1 — facility is 0–23.
        if v is not None and not (0 <= v <= 23):
            raise ValueError("Syslog facility must be 0–23 (RFC 5424)")
        return v

    @field_validator("snmp_version")
    @classmethod
    def _valid_snmp_version(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _SNMP_VERSIONS:
            raise ValueError(f"snmp_version must be one of {sorted(_SNMP_VERSIONS)}")
        return v

    @field_validator("snmp_allowed_sources")
    @classmethod
    def _valid_snmp_sources(cls, v: list[str] | None) -> list[str] | None:
        # Each entry must parse as a CIDR (or single host). Normalise
        # to the canonical network string so duplicates produced by
        # different host-bit inputs collapse on the way in.
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = raw.strip()
            if not s:
                continue
            try:
                net = ip_network(s, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR or host: {raw!r} ({exc})") from exc
            out.append(str(net))
        return out

    @field_validator("ntp_source_mode")
    @classmethod
    def _valid_ntp_source_mode(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _NTP_SOURCE_MODES:
            raise ValueError(f"ntp_source_mode must be one of {sorted(_NTP_SOURCE_MODES)}")
        return v

    @field_validator("ntp_pool_servers")
    @classmethod
    def _valid_ntp_pool_servers(cls, v: list[str] | None) -> list[str] | None:
        # Pool hostnames are free-form per chrony's parser. Strip
        # whitespace + drop empties; reject embedded whitespace
        # (chrony reads the directive as space-separated tokens).
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = raw.strip()
            if not s:
                continue
            if any(c.isspace() for c in s):
                raise ValueError(f"pool hostname may not contain whitespace: {raw!r}")
            out.append(s)
        return out

    @field_validator("ntp_allow_client_networks")
    @classmethod
    def _valid_ntp_allow_networks(cls, v: list[str] | None) -> list[str] | None:
        # Same CIDR canonicalisation as snmp_allowed_sources — chrony's
        # ``allow`` directive accepts both v4 + v6 networks.
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = raw.strip()
            if not s:
                continue
            try:
                net = ip_network(s, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR: {raw!r} ({exc})") from exc
            out.append(str(net))
        return out


# ── Dedicated resolver schema (issue #158) ──────────────────────────────────────


class ResolverSettingsResponse(BaseModel):
    """Focused read shape for ``GET /settings/resolver`` (issue #158).

    A scoped slice of the combined ``SettingsResponse`` so the Appliance →
    DNS Resolver form (and the ``find_resolver_settings`` MCP read) can fetch
    just the resolver config without the rest of the platform-settings blob.
    No secrets — resolver IPs / domains are not sensitive.
    """

    resolver_mode: str
    resolver_servers: list[str]
    resolver_fallback_servers: list[str]
    resolver_search_domains: list[str]
    resolver_dnssec: str
    resolver_dns_over_tls: str

    model_config = {"from_attributes": True}


class ResolverSettingsUpdate(BaseModel):
    """Focused write shape for ``PUT /settings/resolver`` (issue #158).

    Same field-level validation as the matching ``resolver_*`` fields on
    ``SettingsUpdate`` (mode / dnssec / dot enums + IP / search-domain
    hygiene). ``None`` leaves the existing value alone.
    """

    resolver_mode: str | None = None
    resolver_servers: list[str] | None = None
    resolver_fallback_servers: list[str] | None = None
    resolver_search_domains: list[str] | None = None
    resolver_dnssec: str | None = None
    resolver_dns_over_tls: str | None = None

    @field_validator("resolver_mode")
    @classmethod
    def _valid_mode(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _RESOLVER_MODES:
            raise ValueError(f"resolver_mode must be one of {sorted(_RESOLVER_MODES)}")
        return v

    @field_validator("resolver_dnssec")
    @classmethod
    def _valid_dnssec(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _RESOLVER_DNSSEC:
            raise ValueError(f"resolver_dnssec must be one of {sorted(_RESOLVER_DNSSEC)}")
        return v

    @field_validator("resolver_dns_over_tls")
    @classmethod
    def _valid_dot(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _RESOLVER_DOT:
            raise ValueError(f"resolver_dns_over_tls must be one of {sorted(_RESOLVER_DOT)}")
        return v

    @field_validator("resolver_servers", "resolver_fallback_servers")
    @classmethod
    def _valid_servers(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        import ipaddress  # noqa: PLC0415

        cleaned: list[str] = []
        for entry in v:
            host = (entry or "").strip()
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise ValueError(f"invalid resolver IP: {entry!r}") from exc
            cleaned.append(host)
        return cleaned

    @field_validator("resolver_search_domains")
    @classmethod
    def _valid_search(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        out: list[str] = []
        for raw in v:
            s = (raw or "").strip()
            if not s:
                continue
            if any(c.isspace() for c in s) or any(ord(c) < 0x20 for c in s):
                raise ValueError(
                    f"search domain may not contain whitespace / control chars: {raw!r}"
                )
            out.append(s)
        return out

    @model_validator(mode="after")
    def _override_requires_servers(self) -> ResolverSettingsUpdate:
        # CROSS-FIELD guard (#158, mirrors the SSH lockout-safety pattern):
        # override mode routes ALL host DNS to the global ``DNS=`` server
        # list (``Domains=~.``), so an override with an empty server list
        # leaves the appliance host with zero working upstream DNS — and with
        # DNSOverTLS=yes there's no plaintext fallback either, making it
        # effectively unrecoverable until corrected. Reject the in-request
        # case where override is selected AND servers are explicitly cleared.
        # ``resolver_servers is None`` means "leave the stored list alone";
        # the merged-state guard in ``update_resolver_settings`` /
        # ``update_settings`` catches the case where the stored list is also
        # empty (it can see the DB row, which this validator can't).
        if (
            self.resolver_mode == "override"
            and self.resolver_servers is not None
            and not self.resolver_servers
        ):
            raise ValueError("resolver override mode requires at least one DNS server")
        return self


# ── Helpers ────────────────────────────────────────────────────────────────────


async def _get_or_create(db: DB) -> PlatformSettings:
    settings = await db.get(PlatformSettings, _SINGLETON_ID)
    if settings is None:
        settings = PlatformSettings(id=_SINGLETON_ID)
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    return settings


_USER_SETTABLE_FIELDS = set(SettingsUpdate.model_fields.keys())


def _column_defaults() -> dict[str, Any]:
    """Introspect the model's `default=` kwargs so the UI has a single source
    of truth for "reset to defaults" — the same values Postgres would insert
    for a fresh row. Only user-settable fields (those present on
    `SettingsUpdate`) are returned; server-managed columns like
    `*_last_run_at` are omitted."""
    out: dict[str, Any] = {}
    for col in PlatformSettings.__table__.columns:
        if col.name not in _USER_SETTABLE_FIELDS:
            continue
        d = col.default
        if d is None:
            continue
        arg = d.arg
        if callable(arg):
            try:
                out[col.name] = arg({})
            except TypeError:
                out[col.name] = arg()
        else:
            out[col.name] = arg
    return out


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get("", response_model=SettingsResponse)
async def get_settings(current_user: CurrentUser, db: DB) -> PlatformSettings:
    return await _get_or_create(db)


@router.get("/defaults")
async def get_settings_defaults(current_user: CurrentUser) -> dict[str, Any]:
    return _column_defaults()


@router.put("", response_model=SettingsResponse)
async def update_settings(
    body: SettingsUpdate, request: Request, current_user: CurrentUser, db: DB
) -> PlatformSettings:
    forbid_in_demo_mode("Platform settings updates are disabled")
    # Superadmin passes via user_has_permission shortcut; users with an
    # explicit `write`/`admin` grant on `settings` also pass.
    if not user_has_permission(current_user, "write", "settings"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: need 'write' on 'settings'",
        )

    settings = await _get_or_create(db)
    changes = body.model_dump(exclude_none=True)
    # #1009 / #1013 — acknowledgements, not columns. Pop before anything
    # reads ``changes`` as the set of fields to write or to audit.
    changes.pop("ssh_lockdown_force", None)
    changes.pop("acknowledge_console_only", None)

    # CROSS-FIELD merged-state guard for the DNS resolver (#158). The
    # model_validator already rejects override + explicitly-empty servers in
    # the same request; this also catches the case it can't see — override
    # selected (or already on) while the RESULTING server list is empty (e.g.
    # servers omitted and the stored list is empty too). Override routes all
    # host DNS to the global ``DNS=`` list, so an empty list means zero working
    # upstream DNS. Mirrors the SSH lockout-safety merged-state check below.
    if "resolver_mode" in changes or "resolver_servers" in changes:
        _resolver_resulting_mode = changes.get("resolver_mode", settings.resolver_mode)
        _resolver_resulting_servers = (
            changes["resolver_servers"]
            if "resolver_servers" in changes
            else list(settings.resolver_servers or [])
        )
        if _resolver_resulting_mode == "override" and not _resolver_resulting_servers:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="resolver override mode requires at least one DNS server",
            )

    # Branding is SUPERADMIN-ONLY (issues #885 / #887). These fields render
    # on the unauthenticated login page, so a delegated ``write:settings``
    # editor could otherwise put arbitrary text in front of every visitor —
    # a phishing surface, not a preference. The Settings UI already gates
    # the branding block on superadmin; this is the server-side half of
    # that (non-negotiable #3).
    _branding_fields = {
        f for f in changes if f.startswith(("login_banner_", "env_banner_")) or f == "app_title"
    }
    if _branding_fields and not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Branding can only be changed by a superadmin",
        )

    # Maintenance mode is SUPERADMIN-ONLY (issue #57). Flipping it turns the
    # WHOLE platform read-only for everyone except superadmins — a delegated
    # ``write:settings`` editor must not be able to inflict a platform-wide
    # DoS. This matches the ``set_maintenance_mode`` MCP tool's superadmin
    # gate and the banner copy ("blocked for everyone except superadmins").
    # Either maintenance field in the PUT body requires the stronger gate.
    if (
        "maintenance_mode_enabled" in changes or "maintenance_message" in changes
    ) and not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Maintenance mode can only be changed by a superadmin",
        )

    # Supervisor (appliance) registration is a SECURITY gate (#407): while
    # true, POST /appliance/supervisor/register accepts pairing codes; while
    # false it 404s. Opening it widens the appliance-pairing attack surface,
    # so it is superadmin-only — a delegated ``write:settings`` editor must
    # not be able to flip it. Matches the superadmin-only Fleet → Pairing
    # toggle in the UI.
    if "supervisor_registration_enabled" in changes and not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Appliance registration can only be changed by a superadmin",
        )

    # Maintenance mode (issue #57). Capture the prior enabled state before
    # the setattr loop mutates it so we can detect an actual flip (and
    # server-stamp / clear ``maintenance_started_at`` accordingly + write
    # a dedicated audit row + invalidate the middleware cache). Computed
    # here so it sees the value as it was BEFORE this request.
    _maintenance_prev = bool(settings.maintenance_mode_enabled)
    _maintenance_requested = changes.get("maintenance_mode_enabled")
    _maintenance_message_prev = settings.maintenance_message or ""
    _maintenance_message_requested = changes.get("maintenance_message")

    # #407 — capture the prior registration-gate state before the setattr
    # loop so we can detect an actual flip and write a dedicated audit row.
    _supervisor_reg_prev = bool(settings.supervisor_registration_enabled)
    _supervisor_reg_requested = changes.get("supervisor_registration_enabled")

    # Issue #155 — whether this request touched any APT field. Computed here
    # (before the secret-bearing apt_sources / apt_gpg_keys / apt_auth get
    # popped out of ``changes`` during processing) so an apt_sources-only
    # change still triggers the dedicated audit row below (NN #4).
    _apt_touched = any(f.startswith("apt_") for f in changes)

    # Whether this update touches any host-config field a HOSTCONFIG_ALL
    # subscriber acts on. The DHCP-agent /config long-poll folds SNMP /
    # NTP / LLDP into its ETag; the supervisor heartbeat (#358 Phase 1)
    # ALSO acts on timezone / verbose-boot / firewall-master / MetalLB /
    # VIP / web-UI-CIDR, so a change to any of those must wake a parked
    # supervisor too. (A DHCP agent woken by a field it doesn't fold just
    # re-checks its ETag and 304s — cheap, and these are rare cluster-
    # config edits.) The set below only matches keys actually present in
    # this request. Computed from ``changes`` before the snmp_* fields get
    # popped / rewritten so detection is order-independent.
    _supervisor_host_config_fields = {
        "timezone",
        "console_mode",
        "firewall_enabled",
        "metallb_enabled",
        "metallb_pool_addresses",
        "control_plane_vip",
        "web_ui_allowed_cidrs",
    }
    _host_config_touched = any(
        field.startswith(("snmp_", "ntp_", "lldp_", "syslog_", "ssh_", "resolver_", "apt_"))
        or field in _supervisor_host_config_fields
        for field in changes
    )

    # fingerbank_api_key needs Fernet encryption + maps to a different
    # column name. Empty string = clear; non-empty = encrypt + store.
    # Pop it out of ``changes`` so the audit log doesn't capture the
    # plaintext, then set the encrypted column directly.
    if "fingerbank_api_key" in changes:
        from app.core.crypto import encrypt_str

        raw = changes.pop("fingerbank_api_key")
        if raw == "":
            settings.fingerbank_api_key_encrypted = None
            changes["fingerbank_api_key_cleared"] = True
        else:
            settings.fingerbank_api_key_encrypted = encrypt_str(raw)
            # Don't echo the plaintext in the audit log — record only
            # that a value was set.
            changes["fingerbank_api_key_set"] = True

    # The legacy webhook's URL + Authorization header (#1502): same
    # encrypt-and-redact shape, so neither reaches the column in clear or the
    # ``platform_settings_updated`` log line below.
    for _field in ("audit_forward_webhook_url", "audit_forward_webhook_auth_header"):
        if _field in changes:
            raw = changes.pop(_field)
            setattr(settings, f"{_field}_encrypted", apply_write_only(None, raw))
            changes[f"{_field}_cleared" if raw == "" else f"{_field}_set"] = True

    # snmp_community: same encrypt-and-redact shape as fingerbank.
    if "snmp_community" in changes:
        from app.core.crypto import encrypt_str

        raw = changes.pop("snmp_community")
        if raw == "":
            settings.snmp_community_encrypted = None
            changes["snmp_community_cleared"] = True
        else:
            settings.snmp_community_encrypted = encrypt_str(raw)
            changes["snmp_community_set"] = True

    # snmp_v3_users: atomic replace with per-user pass merge. Match
    # by username so an operator editing one user's protocol doesn't
    # have to retype every other user's passwords. Drop from
    # ``changes`` so the generic setattr loop below doesn't clobber
    # the merged form with the audit-redacted shape we re-stash for
    # logging.
    snmp_users_audit: list[dict[str, Any]] | None = None
    if "snmp_v3_users" in changes:
        incoming = changes.pop("snmp_v3_users")
        existing = list(settings.snmp_v3_users or [])
        merged = _merge_snmp_v3_users(existing, incoming)
        settings.snmp_v3_users = merged
        # Stash the redacted shape for the audit-log call only — never
        # put it back on ``changes`` because the setattr loop would
        # then write the redacted dict back over ``settings.snmp_v3_users``,
        # losing every encrypted pass.
        snmp_users_audit = [_redact_v3_user(u) for u in merged]

    # syslog_targets: same atomic-replace + per-target CA-PEM merge as
    # SNMP v3 users (#156). Match by ``(host, port)`` so editing one
    # target's format doesn't drop another's CA PEM. A TLS target with
    # no CA (neither submitted now nor stored prior) is rejected so the
    # operator's PUT is the error site, not a downstream rsyslog reload.
    syslog_targets_audit: list[dict[str, Any]] | None = None
    if "syslog_targets" in changes:
        incoming_targets: list[SyslogTargetUpdate] = body.syslog_targets or []
        existing_targets = list(settings.syslog_targets or [])
        merged_targets = _merge_syslog_targets(existing_targets, incoming_targets)
        for tgt in merged_targets:
            if tgt["protocol"] == "tls" and not tgt.get("ca_cert_pem"):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=(
                        f"syslog target {tgt['host']}:{tgt['port']} uses TLS but has "
                        "no CA certificate configured — paste a CA PEM for it."
                    ),
                )
        # Drop the raw incoming list out of ``changes`` so the generic
        # setattr loop doesn't clobber the merged form; the model
        # attribute is set directly here.
        changes.pop("syslog_targets")
        settings.syslog_targets = merged_targets
        syslog_targets_audit = [_redact_syslog_target(t) for t in merged_targets]

    # apt_sources: plain atomic replace — no secrets (the armoured key
    # lives in apt_gpg_keys). Normalise the pydantic models to JSON dicts.
    if "apt_sources" in changes:
        changes.pop("apt_sources")
        settings.apt_sources = [
            {
                "name": s.name,
                "uri": s.uri,
                "suites": s.suites,
                "components": s.components,
                "signed_by_key_id": s.signed_by_key_id,
                "enabled": s.enabled,
            }
            for s in (body.apt_sources or [])
        ]

    # apt_gpg_keys / apt_auth: atomic replace + per-entry secret merge,
    # same shape as snmp_v3_users / syslog_targets. Stash redacted shapes
    # for the audit log; never put the merged (ciphertext-bearing) list
    # back on ``changes`` or the setattr loop would clobber it.
    apt_gpg_keys_audit: list[dict[str, Any]] | None = None
    if "apt_gpg_keys" in changes:
        changes.pop("apt_gpg_keys")
        merged_keys = _merge_apt_gpg_keys(
            list(settings.apt_gpg_keys or []), body.apt_gpg_keys or []
        )
        settings.apt_gpg_keys = merged_keys
        apt_gpg_keys_audit = [_redact_apt_gpg_key(k) for k in merged_keys]
    apt_auth_audit: list[dict[str, Any]] | None = None
    if "apt_auth" in changes:
        changes.pop("apt_auth")
        merged_auth = _merge_apt_auth(list(settings.apt_auth or []), body.apt_auth or [])
        settings.apt_auth = merged_auth
        apt_auth_audit = [_redact_apt_auth(a) for a in merged_auth]

    # ssh_authorized_keys: atomic replace (no per-entry secret merge — public
    # keys are not secrets). Normalise the incoming pydantic models into
    # plain ``{name, public_key, comment}`` dicts so the JSONB column stays
    # JSON-friendly. CROSS-FIELD lockout-safety guard (#157): compute the
    # MERGED post-update state (resulting password-auth flag + resulting key
    # list) and refuse to disable password auth when zero valid keys would
    # survive — otherwise the operator locks themselves out of every
    # appliance host. The host runner mirrors this guard defensively.
    ssh_keys_normalised: list[dict[str, Any]] | None = None
    if "ssh_authorized_keys" in changes:
        incoming_keys: list[SshAuthorizedKeyUpdate] = body.ssh_authorized_keys or []
        ssh_keys_normalised = [
            {"name": k.name, "public_key": k.public_key, "comment": k.comment}
            for k in incoming_keys
        ]
        changes.pop("ssh_authorized_keys")
        settings.ssh_authorized_keys = ssh_keys_normalised

    # Resulting (merged) state for the lockout check — read the change if
    # present, else the value already on the row. Compute regardless of
    # whether keys / the toggle were in this request, since either one
    # changing can produce an unsafe combination.
    _resulting_password_auth = bool(
        changes.get("ssh_password_auth_enabled", settings.ssh_password_auth_enabled)
    )
    _resulting_keys = (
        ssh_keys_normalised
        if ssh_keys_normalised is not None
        else list(settings.ssh_authorized_keys or [])
    )
    _ssh_field_in_request = any(f.startswith("ssh_") for f in changes) or (
        ssh_keys_normalised is not None
    )
    # #1009 — ``ssh_lockdown`` with nothing to allow from.
    #
    # The flag retires the port-22 management floor so the allowlist can
    # finally be reached. With an empty list the rendered scope accepts from
    # nowhere, which is not a restriction but a closed port — and it would
    # close it on every appliance at once, recoverable only at the console.
    # docs/design/FLEET_FIREWALL.md §6.1 specified this 422 for the same
    # combination under its ``firewall_mgmt_lockdown`` name.
    _resulting_lockdown = bool(changes.get("ssh_lockdown", settings.ssh_lockdown))
    _resulting_scope = (
        changes["ssh_allowed_source_networks"]
        if "ssh_allowed_source_networks" in changes
        else list(settings.ssh_allowed_source_networks or [])
    )
    if _ssh_field_in_request and _resulting_lockdown and not _resulting_scope:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Refusing to enforce the SSH source restriction with an empty "
                "allowed-networks list — that closes SSH from everywhere, on "
                "every appliance, leaving only the console. Add at least one "
                "network first, or leave the restriction off."
            ),
        )
    # ...and the mistake an operator actually makes: turning it on with a
    # list that does not contain the address they are speaking to us from.
    # Advisory rather than a refusal — browsing the UI from one network and
    # SSHing from another is legitimate — but it must be acknowledged, since
    # the alternative is discovering it at the next SSH attempt. Superadmin
    # forces past it with ``ssh_lockdown_force``.
    #
    # Gated on the TRANSITION, not on the resulting state. Keyed on the
    # latter it fires on every ``ssh_*`` save made while lockdown is already
    # on — adding a key, changing the port — demanding an acknowledgement for
    # a change that alters nothing about who can reach the box. An operator
    # asked to accept a lockout warning for an unrelated edit learns to tick
    # it without reading, which costs more than the warning buys.
    #
    # Two transitions introduce the risk: turning it on, and narrowing the
    # scope while it is on. Both are re-checked against the caller's address
    # even when the OLD scope already excluded them, since the fix for that
    # is a save that includes them and it should stop warning the moment it
    # does.
    _lockdown_was_on = bool(settings.ssh_lockdown)
    _scope_changing = "ssh_allowed_source_networks" in changes and list(_resulting_scope) != list(
        settings.ssh_allowed_source_networks or []
    )
    _lockdown_newly_enforced = _resulting_lockdown and (not _lockdown_was_on or _scope_changing)
    _caller_ip = get_trusted_client_ip(request)
    # The membership test below is ``services.appliance.access.covers``. A
    # ``_caller_within_scope`` helper used to live in this file and was one of
    # TWO implementations of the same question (#1013), the other being the Web
    # UI guard's. They agreed on families and disagreed on the case neither
    # could read: this one counted an unknown address as COVERED and proceeded,
    # that one counted it as excluded and warned. The shared one counts it as
    # not covered, which flips this guard in that case — #1009's reason for the
    # old direction (a gate blocking on "I could not tell" gets forced past by
    # reflex) was an argument about frequency, and the frequency is near zero:
    # ``get_trusted_client_ip`` falls back to the ASGI peer address, which
    # every real HTTP request has.
    #
    # #1013 — the escalation, checked BEFORE the per-door guard because it is
    # the more serious finding and its message subsumes the other's. The Web
    # UI half is read from storage: this endpoint cannot change it, which is
    # exactly why neither guard could see the whole picture before.
    #
    # Gated on the same transition as the guard below, and for the same
    # reason: an operator already in this state who adds an authorized key has
    # not made it worse, and warning them again teaches the tick.
    _doors_after = effective_doors(
        settings,
        _caller_ip,
        ssh_lockdown=_resulting_lockdown,
        ssh_cidrs=list(_resulting_scope),
    )
    _console_only = _lockdown_newly_enforced and _doors_after.console_only
    if _console_only and not body.acknowledge_console_only:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=console_only_detail(_doors_after),
        )
    if (
        _lockdown_newly_enforced
        and _resulting_scope
        # ``_console_only`` here means the acknowledgement above was given.
        # Accepting "only the console reaches this fleet" already contains
        # "my SSH access may close", so a second tick for the smaller
        # statement would be the reflex-training pattern this guard's own
        # comment warns about. It cannot widen anything: when the escalation
        # did not fire, this term is False.
        and not (body.ssh_lockdown_force or _console_only)
        and not covers(_caller_ip, _resulting_scope)
    ):
        # Reaching here proves the Web UI still admits this caller: the
        # condition above IS "the SSH door would not admit you", and had the
        # Web UI door not admitted you either, the escalation would already
        # have raised. So this states the surviving path rather than hedging.
        #
        # This direction is sound in a way the mirror-image sentence on the
        # firewall path is NOT, and the asymmetry is deliberate: the request
        # arrived over the Web UI, from this address, just now — so "you can
        # still reach this UI" is a statement about the very session making
        # it. Asserting the reverse ("you can still SSH") would need an
        # assumption about where the operator SSHes from, which #1009 says
        # explicitly may differ. See SSH_REACHABILITY_CAVEAT in
        # ``services/appliance/access``.
        _web = _doors_after.web_ui
        _web_desc = (
            "restricted to " + ", ".join(_web.allowed_cidrs)
            if _web.restricted
            else "not source-restricted"
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Your own address is not inside the allowed networks, so "
                "enforcing this restriction may close your SSH access to every "
                "appliance. You would still reach this UI to turn it back off "
                f"(the Web UI is {_web_desc}), and the appliance console "
                "recovers it either way. Re-send with ssh_lockdown_force to "
                "proceed."
            ),
        )
    if _ssh_field_in_request and not validate_lockout_safe(
        _resulting_keys, _resulting_password_auth
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Refusing to disable SSH password authentication with no "
                "authorized keys configured — you would lock yourself out of "
                "every appliance host. Add at least one valid public key first, "
                "or keep password authentication enabled."
            ),
        )

    for field, value in changes.items():
        # Skip the synthetic audit-only flags we just inserted.
        if field in (
            "fingerbank_api_key_cleared",
            "fingerbank_api_key_set",
            "snmp_community_cleared",
            "snmp_community_set",
            "audit_forward_webhook_url_cleared",
            "audit_forward_webhook_url_set",
            "audit_forward_webhook_auth_header_cleared",
            "audit_forward_webhook_auth_header_set",
        ):
            continue
        setattr(settings, field, value)

    if snmp_users_audit is not None:
        changes["snmp_v3_users"] = snmp_users_audit
    if syslog_targets_audit is not None:
        changes["syslog_targets"] = syslog_targets_audit
    if ssh_keys_normalised is not None:
        changes["ssh_authorized_keys"] = ssh_keys_normalised
    if apt_gpg_keys_audit is not None:
        changes["apt_gpg_keys"] = apt_gpg_keys_audit
    if apt_auth_audit is not None:
        changes["apt_auth"] = apt_auth_audit

    # Issue #157 — dedicated audit row for any SSH config change
    # (non-negotiable #4). SSH access is high-blast-radius (it gates who
    # can log into every appliance host), so a durable audit entry is
    # required. Public keys are NOT secrets, so the full key list is
    # recorded (no redaction). Fires whenever this request touched any
    # ``ssh_*`` field.
    if _ssh_field_in_request:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="update",
                resource_type="platform_settings",
                resource_id="ssh",
                resource_display="SSH access",
                result="success",
                new_value={
                    "password_auth_enabled": bool(settings.ssh_password_auth_enabled),
                    "allow_root_login": bool(settings.ssh_allow_root_login),
                    "port": int(settings.ssh_port or 22),
                    "allowed_source_networks": list(settings.ssh_allowed_source_networks or []),
                    "lockdown": bool(settings.ssh_lockdown),
                    "authorized_keys": [
                        {
                            "name": (k.get("name") or "") if isinstance(k, dict) else "",
                            "comment": (k.get("comment") or "") if isinstance(k, dict) else "",
                            "public_key": (
                                (k.get("public_key") or "") if isinstance(k, dict) else ""
                            ),
                        }
                        for k in (settings.ssh_authorized_keys or [])
                    ],
                },
            )
        )

    # Issue #158 — dedicated audit row for any DNS-resolver change
    # (non-negotiable #4). Resolver config steers where every appliance
    # host sends its DNS lookups (and BIND9 binds host :53 on top), so a
    # durable audit entry is warranted. Resolver IPs / domains are not
    # secrets, so the full shape is recorded (no redaction). Fires
    # whenever this request touched any ``resolver_*`` field. Computed off
    # ``changes`` which still carries the resolver keys (they go through
    # the generic setattr loop, no special pop like ssh/syslog).
    _resolver_touched = any(f.startswith("resolver_") for f in changes)
    if _resolver_touched:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="update",
                resource_type="platform_settings",
                resource_id="resolver",
                resource_display="DNS resolver",
                result="success",
                new_value={
                    "mode": settings.resolver_mode,
                    "servers": list(settings.resolver_servers or []),
                    "fallback_servers": list(settings.resolver_fallback_servers or []),
                    "search_domains": list(settings.resolver_search_domains or []),
                    "dnssec": settings.resolver_dnssec,
                    "dns_over_tls": settings.resolver_dns_over_tls,
                },
            )
        )

    # Issue #156 — dedicated audit row for any syslog-forwarding change
    # (non-negotiable #4). The generic ``logger.info`` below is not an
    # ``audit_log`` row; syslog forwarding ships logs off-box + carries a
    # secret CA PEM, so a durable, redacted audit entry is required. Fires
    # whenever this request touched any ``syslog_*`` field (the targets
    # list shows only the redacted shape — no CA PEM bytes).
    _syslog_touched = any(f.startswith("syslog_") for f in changes)
    if _syslog_touched:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="update",
                resource_type="platform_settings",
                resource_id="syslog",
                resource_display="Syslog forwarding",
                result="success",
                new_value={
                    "enabled": bool(settings.syslog_enabled),
                    "targets": [_redact_syslog_target(t) for t in (settings.syslog_targets or [])],
                    "filter": settings.syslog_filter or "",
                    "buffer_disk": bool(settings.syslog_buffer_disk),
                },
            )
        )

    # Issue #155 — dedicated audit row for any APT config change
    # (non-negotiable #4). APT management steers every appliance host's
    # package sources + carries secrets (GPG keys + private-mirror
    # passwords), so a durable, redacted audit entry is required — the
    # generic ``logger.info`` below is not an ``audit_log`` row. The shape
    # records counts + presence only (never the armoured key / password,
    # and not the raw proxy URL which may embed credentials).
    if _apt_touched:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="update",
                resource_type="platform_settings",
                resource_id="apt",
                resource_display="APT sources",
                result="success",
                new_value={
                    "managed": bool(settings.apt_managed),
                    "source_count": len(settings.apt_sources or []),
                    "gpg_key_count": len(settings.apt_gpg_keys or []),
                    "auth_entry_count": len(settings.apt_auth or []),
                    "proxy_http_set": bool(settings.apt_proxy_http),
                    "proxy_https_set": bool(settings.apt_proxy_https),
                    "unattended_upgrades_enabled": bool(settings.apt_unattended_upgrades_enabled),
                    # Issue #164 — unattended-upgrades policy summary.
                    "unattended_origin_count": len(settings.apt_unattended_origins or []),
                    "unattended_blocklist_count": len(settings.apt_unattended_blocklist or []),
                    "unattended_automatic_reboot": bool(settings.apt_unattended_automatic_reboot),
                    "unattended_reboot_time": settings.apt_unattended_reboot_time or "",
                },
            )
        )

    # Maintenance mode flip handling (issue #57). When the enable flag
    # actually changes state, server-stamp / clear ``maintenance_started_at``
    # (never operator-supplied) and write a dedicated audit row so the
    # window is unambiguously bracketed in the audit log.
    _maintenance_flipped = (
        _maintenance_requested is not None and bool(_maintenance_requested) != _maintenance_prev
    )
    # A message-only edit (banner reworded while the enable flag stays put)
    # is still an operator-visible maintenance change and must be audited
    # (non-negotiable #4) — the flip branch only fired on enable/disable, so
    # a reword previously slipped through with no ``audit_log`` row.
    _maintenance_message_changed = (
        _maintenance_message_requested is not None
        and (settings.maintenance_message or "") != _maintenance_message_prev
    )
    if _maintenance_flipped:
        now_enabled = bool(_maintenance_requested)
        settings.maintenance_started_at = datetime.now(UTC) if now_enabled else None
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action=("maintenance_mode.enabled" if now_enabled else "maintenance_mode.disabled"),
                resource_type="platform_settings",
                resource_id="maintenance",
                resource_display="Maintenance mode",
                result="success",
                new_value={
                    "enabled": now_enabled,
                    "message": settings.maintenance_message or "",
                },
            )
        )
    elif _maintenance_message_changed:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="maintenance_mode.message_changed",
                resource_type="platform_settings",
                resource_id="maintenance",
                resource_display="Maintenance mode",
                result="success",
                new_value={
                    "enabled": bool(settings.maintenance_mode_enabled),
                    "message": settings.maintenance_message or "",
                },
            )
        )

    # #407 — audit the supervisor-registration gate flip (non-negotiable #4).
    # Security-relevant: enabling it opens the appliance-pairing endpoint.
    if (
        _supervisor_reg_requested is not None
        and bool(_supervisor_reg_requested) != _supervisor_reg_prev
    ):
        _reg_now = bool(_supervisor_reg_requested)
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action=(
                    "supervisor_registration.enabled"
                    if _reg_now
                    else "supervisor_registration.disabled"
                ),
                resource_type="platform_settings",
                resource_id="supervisor_registration",
                resource_display="Appliance registration",
                result="success",
                new_value={"enabled": _reg_now},
            )
        )

    # Branding (#885 / #887 / #888) — what an anonymous visitor sees before
    # they authenticate, so every change is on the record.
    if _branding_fields:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="update",
                resource_type="platform_settings",
                resource_id="branding",
                resource_display="Branding",
                result="success",
                new_value={
                    "app_title": str(settings.app_title or ""),
                    "login_banner_enabled": bool(settings.login_banner_enabled),
                    "login_banner_title": str(settings.login_banner_title or ""),
                    "login_banner_text": str(settings.login_banner_text or ""),
                    "login_banner_require_ack": bool(settings.login_banner_require_ack),
                    "env_banner_enabled": bool(settings.env_banner_enabled),
                    "env_banner_text": str(settings.env_banner_text or ""),
                    "env_banner_bg": str(settings.env_banner_bg or ""),
                    "env_banner_fg": str(settings.env_banner_fg or ""),
                    "env_banner_position": str(settings.env_banner_position or "top"),
                },
            )
        )

    await db.commit()
    await db.refresh(settings)

    # Drop the middleware's process-local cache so the flipping worker
    # enforces (or lifts) the read-only block on its very next request. A
    # message-only reword also changes the cached 503 body, so invalidate
    # for that case too.
    if _maintenance_flipped or _maintenance_message_changed:
        from app.core import maintenance_mode as _maintenance_mode

        _maintenance_mode.invalidate_cache()

    # The settings router has no request-scoped wake collector, so
    # publish directly after the commit. Only fire when a host-config
    # field actually changed so unrelated settings writes don't wake
    # every DHCP-agent long-poll (which subscribes to HOSTCONFIG_ALL).
    if _host_config_touched:
        await publish_wake(HOSTCONFIG_ALL)

    logger.info("platform_settings_updated", user=current_user.username, changes=changes)
    return settings


# ── Dedicated resolver endpoints (issue #158) ───────────────────────────────────


@router.get("/resolver", response_model=ResolverSettingsResponse)
async def get_resolver_settings(current_user: CurrentUser, db: DB) -> ResolverSettingsResponse:
    """Scoped read of just the appliance DNS-resolver config (issue #158).

    A focused slice of ``GET /settings`` for the Appliance → DNS Resolver
    form. The combined read is still complete (resolver_* live on
    ``SettingsResponse`` too); this endpoint exists per the spec so the form
    can fetch just its own state.
    """
    settings = await _get_or_create(db)
    return ResolverSettingsResponse.model_validate(settings)


@router.put("/resolver", response_model=ResolverSettingsResponse)
async def update_resolver_settings(
    body: ResolverSettingsUpdate, current_user: CurrentUser, db: DB
) -> ResolverSettingsResponse:
    """Scoped write of just the appliance DNS-resolver config (issue #158).

    Same guardrails as the combined PUT: demo-mode block, ``write`` on
    ``settings`` permission gate, a dedicated audit row (``resource_id=
    'resolver'``), and a HOSTCONFIG_ALL wake so parked supervisor / DHCP-agent
    long-polls pick the change up. Only the resolver_* columns are touched.
    """
    forbid_in_demo_mode("Platform settings updates are disabled")
    if not user_has_permission(current_user, "write", "settings"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: need 'write' on 'settings'",
        )

    settings = await _get_or_create(db)
    changes = body.model_dump(exclude_none=True)
    if not changes:
        # Nothing to do — return the current state without an audit row /
        # wake so a no-op PUT is cheap.
        return ResolverSettingsResponse.model_validate(settings)

    # CROSS-FIELD merged-state guard (#158). The model_validator already
    # rejects override + explicitly-empty servers in the same request; this
    # also catches the case it can't see — override selected (or already on)
    # while the RESULTING server list is empty (e.g. servers omitted and the
    # stored list is empty too). Override routes all host DNS to the global
    # ``DNS=`` list, so an empty list means zero working upstream DNS.
    _resulting_mode = changes.get("resolver_mode", settings.resolver_mode)
    _resulting_servers = (
        changes["resolver_servers"]
        if "resolver_servers" in changes
        else list(settings.resolver_servers or [])
    )
    if _resulting_mode == "override" and not _resulting_servers:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="resolver override mode requires at least one DNS server",
        )

    for field, value in changes.items():
        setattr(settings, field, value)

    # Dedicated audit row (non-negotiable #4) — resolver config steers every
    # appliance host's DNS lookups. Resolver IPs / domains are not secrets,
    # so the full shape is recorded.
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="update",
            resource_type="platform_settings",
            resource_id="resolver",
            resource_display="DNS resolver",
            result="success",
            new_value={
                "mode": settings.resolver_mode,
                "servers": list(settings.resolver_servers or []),
                "fallback_servers": list(settings.resolver_fallback_servers or []),
                "search_domains": list(settings.resolver_search_domains or []),
                "dnssec": settings.resolver_dnssec,
                "dns_over_tls": settings.resolver_dns_over_tls,
            },
        )
    )

    await db.commit()
    await db.refresh(settings)

    # Wake parked supervisor / DHCP-agent long-polls (HOSTCONFIG_ALL).
    await publish_wake(HOSTCONFIG_ALL)

    logger.info("resolver_settings_updated", user=current_user.username, changes=list(changes))
    return ResolverSettingsResponse.model_validate(settings)


class ReverseDnsRunResponse(BaseModel):
    status: str  # "queued" | "enqueue_failed"
    task_id: str | None = None


@router.post("/reverse-dns/run", response_model=ReverseDnsRunResponse)
async def trigger_reverse_dns_run(current_user: CurrentUser, db: DB) -> ReverseDnsRunResponse:
    """Queue an on-demand reverse-DNS sweep (issue #41).

    Runs the same ``sweep_reverse_dns`` task the beat dispatcher uses, with
    ``force=True`` so it bypasses the enabled-gate + per-run interval — an
    operator can sweep on demand even with the scheduled sweep off.
    """
    forbid_in_demo_mode("Reverse-DNS sweep is disabled")
    if not user_has_permission(current_user, "write", "settings"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: need 'write' on 'settings'",
        )

    from app.models.audit import AuditLog

    task_id: str | None = None
    try:
        from app.tasks.reverse_dns import sweep_reverse_dns

        result = sweep_reverse_dns.delay(force=True)
        task_id = result.id
    except Exception as exc:  # noqa: BLE001 — broker unreachable; report, don't 500
        logger.warning("reverse_dns_trigger_enqueue_failed", error=str(exc))

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="reverse-dns",
            resource_type="platform",
            resource_id="1",
            resource_display="reverse-dns-run",
            result="success" if task_id else "error",
            error_detail=None if task_id else "task broker unreachable",
        )
    )
    await db.commit()
    return ReverseDnsRunResponse(status="queued" if task_id else "enqueue_failed", task_id=task_id)


# ── OUI vendor database ───────────────────────────────────────────────────────
#
# Opt-in feature controlled by ``oui_lookup_enabled``. These endpoints let
# the Settings UI show the vendor-count + last-updated timestamp and kick
# off a manual refresh without waiting for the hourly beat tick.


class OUIStatusResponse(BaseModel):
    enabled: bool
    interval_hours: int
    last_updated_at: datetime | None
    vendor_count: int


class OUIRefreshResponse(BaseModel):
    status: str  # "queued" | "disabled"
    task_id: str | None = None


class OUITaskStatusResponse(BaseModel):
    """Shape returned by the polling endpoint the refresh modal hits.

    ``state`` mirrors Celery's task states (``PENDING``, ``STARTED``,
    ``SUCCESS``, ``FAILURE``, ``RETRY``). When ``state == "SUCCESS"`` the
    ``result`` field carries the diff counters emitted by the task's
    return value. When ``state == "FAILURE"`` the ``error`` field holds
    the exception repr — enough context for the modal to display
    without leaking internal traces to non-admin users (the endpoint is
    already admin-scoped).
    """

    task_id: str
    state: str
    ready: bool
    result: dict[str, Any] | None = None
    error: str | None = None


@router.get("/oui/status", response_model=OUIStatusResponse)
async def get_oui_status(current_user: CurrentUser, db: DB) -> OUIStatusResponse:
    ps = await _get_or_create(db)
    count = (await db.execute(select(func.count(OUIVendor.prefix)))).scalar_one()
    return OUIStatusResponse(
        enabled=ps.oui_lookup_enabled,
        interval_hours=ps.oui_update_interval_hours,
        last_updated_at=ps.oui_last_updated_at,
        vendor_count=int(count),
    )


# ── SNMP community reveal ──────────────────────────────────────────
#
# Operators legitimately need to look up the configured v2c community
# string — it's the credential they paste into their NMS / snmpwalk
# command. The flat ``GET /settings/`` response never returns the
# plaintext (only ``snmp_community_set: bool``), so this dedicated
# endpoint behind a password-confirm + superadmin gate is the path.
# Mirrors the agent-bootstrap-keys reveal pattern (see
# ``backend/app/api/v1/admin/agent_keys.py``).


class RevealCommunityRequest(BaseModel):
    # #408 — local users supply ``password``; external-auth users (no
    # local password) supply ``totp_code``. The reauth helper decides.
    password: str | None = None
    totp_code: str | None = None


class RevealCommunityResponse(BaseModel):
    configured: bool
    community: str | None


@router.post(
    "/snmp/reveal-community",
    response_model=RevealCommunityResponse,
    summary="Reveal the configured SNMP v2c community (superadmin + password)",
)
async def reveal_snmp_community(
    body: RevealCommunityRequest,
    current_user: CurrentUser,
    db: DB,
) -> RevealCommunityResponse:
    """Return the v2c community string after password re-verification.

    Same shape as ``POST /api/v1/admin/agent-keys/reveal`` — both the
    success path and every denial path emit an audit row so abuse is
    at least visible. Local-auth users only; external-auth users have
    no local password to re-confirm.
    """
    from app.core.crypto import decrypt_str
    from app.models.audit import AuditLog
    from app.services.reauth import ReauthOutcome, reverify_operator

    def _audit_denied(reason: str) -> None:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="snmp_community_reveal_denied",
                resource_type="platform_settings",
                resource_id="snmp",
                resource_display="SNMP community",
                result="forbidden",
                new_value={"reason": reason},
            )
        )

    if not is_effective_superadmin(current_user):
        _audit_denied("non_superadmin")
        await db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only superadmins can reveal the SNMP community",
        )

    # #408 — local users re-confirm with password or TOTP; external-auth
    # users with TOTP (enrol under Settings → Security if not yet enrolled).
    outcome = reverify_operator(current_user, password=body.password, totp_code=body.totp_code)
    if outcome is not ReauthOutcome.OK:
        if outcome is ReauthOutcome.MFA_REQUIRED:
            _audit_denied("mfa_required")
            await db.commit()
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Re-confirmation requires MFA. Your account has no local "
                "password — enrol TOTP under Settings → Security, then retry.",
            )
        _audit_denied("bad_credential")
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password or TOTP code is incorrect")

    settings = await _get_or_create(db)
    if not settings.snmp_community_encrypted:
        # No reveal-denied audit row — there's nothing to reveal, the
        # password-confirm path completed cleanly, and an empty row
        # is genuinely informational.
        return RevealCommunityResponse(configured=False, community=None)

    try:
        plaintext = decrypt_str(settings.snmp_community_encrypted)
    except Exception:
        _audit_denied("decrypt_failed")
        await db.commit()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Stored community could not be decrypted (key mismatch?). "
            "Re-set the community in Settings → Appliance → SNMP.",
        ) from None

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="snmp_community_revealed",
            resource_type="platform_settings",
            resource_id="snmp",
            resource_display="SNMP community",
            result="success",
        )
    )
    await db.commit()
    logger.info("snmp_community_revealed", user=current_user.username)
    return RevealCommunityResponse(configured=True, community=plaintext)


# ── APT host-config pre-apply validation (issue #155) ──────────────


class AptValidateRequest(BaseModel):
    """A candidate APT config to structurally pre-check before save.

    ``apt_gpg_key_ids`` is the set of key ids that WILL exist after the
    pending save (so a source can reference a key the operator is adding
    in the same form) — defaults to the currently-stored ids if omitted.
    """

    apt_sources: list[AptSourceUpdate]
    apt_gpg_key_ids: list[str] | None = None
    apt_proxy_http: str | None = None
    apt_proxy_https: str | None = None


class AptValidateResponse(BaseModel):
    valid: bool
    errors: list[str]
    warnings: list[str]
    sources_list_preview: str


@router.post("/apt/validate", response_model=AptValidateResponse)
async def validate_apt_config(
    body: AptValidateRequest,
    current_user: CurrentUser,
    db: DB,
) -> AptValidateResponse:
    """Structural pre-apply check for a candidate APT config (no save).

    The host runner does the *real* validation (``apt-get update`` against
    a staged config, which only the appliance host can run); this catches
    the structural mistakes that would brick that run — zero enabled
    sources, a ``signed-by`` reference to a key that won't exist, a
    malformed proxy — so the operator sees pass/fail before clicking Save.
    """
    if not user_has_permission(current_user, "write", "settings"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: need 'write' on 'settings'",
        )

    errors: list[str] = []
    warnings: list[str] = []

    enabled_sources = [s for s in body.apt_sources if s.enabled]
    if not enabled_sources:
        errors.append("No enabled sources — apt-get update would fail with no repositories.")

    # Resolve the set of key ids that will exist post-save.
    if body.apt_gpg_key_ids is not None:
        known_key_ids = {k.strip() for k in body.apt_gpg_key_ids if k.strip()}
    else:
        settings = await _get_or_create(db)
        known_key_ids = {
            str(k.get("key_id"))
            for k in (settings.apt_gpg_keys or [])
            if isinstance(k, dict) and k.get("key_id")
        }

    for src in enabled_sources:
        key_id = (src.signed_by_key_id or "").strip()
        if key_id and key_id not in known_key_ids:
            warnings.append(
                f"Source '{src.name or src.uri}' references GPG key '{key_id}' "
                "which isn't configured — apt-get update would fail with NO_PUBKEY."
            )
        if not key_id and src.uri.startswith(("http://", "https://")):
            warnings.append(
                f"Source '{src.name or src.uri}' has no signing key — apt requires "
                "a signed-by key for non-trusted repos on modern Debian."
            )

    for proxy in (body.apt_proxy_http, body.apt_proxy_https):
        if proxy and not proxy.strip().startswith(("http://", "https://")):
            errors.append(f"Proxy URL '{proxy}' must start with http:// or https://.")

    # Render a preview the operator can eyeball. Build a throwaway settings
    # shim so the renderer (which reads attributes) works without a row.
    shim = PlatformSettings(id=0)
    shim.apt_sources = [
        {
            "name": s.name,
            "uri": s.uri,
            "suites": s.suites,
            "components": s.components,
            "signed_by_key_id": s.signed_by_key_id,
            "enabled": s.enabled,
        }
        for s in body.apt_sources
    ]
    preview = render_sources_list(shim)

    return AptValidateResponse(
        valid=not errors,
        errors=errors,
        warnings=warnings,
        sources_list_preview=preview,
    )


@router.post(
    "/oui/refresh",
    response_model=OUIRefreshResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_oui_refresh(current_user: CurrentUser, db: DB) -> OUIRefreshResponse:
    if not user_has_permission(current_user, "write", "settings"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: need 'write' on 'settings'",
        )

    ps = await _get_or_create(db)
    if not ps.oui_lookup_enabled:
        return OUIRefreshResponse(status="disabled")

    # Deferred import so the web process doesn't pull the celery task graph
    # into its startup path.
    from app.tasks.oui_update import update_oui_database_now  # noqa: PLC0415

    result = update_oui_database_now.delay()
    logger.info("oui_refresh_triggered", user=current_user.username, task_id=result.id)
    return OUIRefreshResponse(status="queued", task_id=result.id)


@router.get("/oui/refresh/{task_id}", response_model=OUITaskStatusResponse)
async def get_oui_refresh_status(task_id: str, current_user: CurrentUser) -> OUITaskStatusResponse:
    """Poll an in-flight OUI refresh task.

    Celery's ``AsyncResult`` is backed by Redis (the configured
    ``CELERY_RESULT_BACKEND``) and returns ``PENDING`` for unknown task
    IDs, which is indistinguishable from "queued but not picked up
    yet" — the UI treats both the same. A ``task_id`` from a previous
    restart will stay ``PENDING`` forever; the modal caps its poll at
    a timeout to cover that case.
    """
    # Deferred import keeps the router lightweight.
    from celery.result import AsyncResult  # noqa: PLC0415

    from app.celery_app import celery_app  # noqa: PLC0415

    async_result = AsyncResult(task_id, app=celery_app)
    state = async_result.state
    payload = OUITaskStatusResponse(
        task_id=task_id,
        state=state,
        ready=async_result.ready(),
    )
    if state == "SUCCESS":
        raw = async_result.result
        payload.result = raw if isinstance(raw, dict) else {"value": str(raw)}
    elif state == "FAILURE":
        payload.error = repr(async_result.result) if async_result.result else "task failed"
    return payload


# ── Audit forward targets (multi-target + multi-format) ───────────────────

_VALID_KINDS = {"syslog", "webhook", "smtp"}
_VALID_WEBHOOK_FLAVORS = {"generic", "slack", "teams", "discord"}
_VALID_SMTP_SECURITY = {"none", "starttls", "ssl"}
_VALID_FORMATS = {
    "rfc5424_json",
    "rfc5424_cef",
    "rfc5424_leef",
    "rfc3164",
    "json_lines",
}
_VALID_PROTOCOLS = {"udp", "tcp", "tls"}
_VALID_SEVERITIES = {"info", "warn", "error", "denied"}


class AuditTargetBody(BaseModel):
    """Create / update body. kind-specific fields are ignored for
    other kinds, so a single shape fits all three (syslog/webhook/smtp)."""

    name: str
    enabled: bool = True
    kind: str
    format: str = "rfc5424_json"
    # syslog
    host: str = ""
    port: int = 514
    protocol: str = "udp"
    facility: int = 16
    ca_cert_pem: str | None = None
    # webhook. Both are write-only and Fernet-encrypted at rest (#1502):
    # for a Slack / Discord / Teams target the URL IS the credential. Same
    # three-way contract as ``smtp_password``: ``None`` (or omitted) keeps
    # the stored value, ``""`` clears it, anything else replaces it.
    url: str | None = None
    auth_header: str | None = None
    webhook_flavor: str = "generic"
    # smtp
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    # When ``None``, leave the existing encrypted password alone (so
    # the operator can edit the From-address without retyping the
    # password). Empty string ``""`` clears it. Anything else is
    # encrypted at rest.
    smtp_password: str | None = None
    smtp_from_address: str = ""
    smtp_to_addresses: list[str] | None = None
    smtp_reply_to: str = ""
    # filter
    min_severity: str | None = None
    resource_types: list[str] | None = None

    @field_validator("kind")
    @classmethod
    def _valid_kind(cls, v: str) -> str:
        if v not in _VALID_KINDS:
            raise ValueError(f"kind must be one of {sorted(_VALID_KINDS)}")
        return v

    @field_validator("format")
    @classmethod
    def _valid_format(cls, v: str) -> str:
        if v not in _VALID_FORMATS:
            raise ValueError(f"format must be one of {sorted(_VALID_FORMATS)}")
        return v

    @field_validator("protocol")
    @classmethod
    def _valid_protocol(cls, v: str) -> str:
        if v not in _VALID_PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(_VALID_PROTOCOLS)}")
        return v

    @field_validator("webhook_flavor")
    @classmethod
    def _valid_flavor(cls, v: str) -> str:
        if v not in _VALID_WEBHOOK_FLAVORS:
            raise ValueError(f"webhook_flavor must be one of {sorted(_VALID_WEBHOOK_FLAVORS)}")
        return v

    @field_validator("smtp_security")
    @classmethod
    def _valid_smtp_security(cls, v: str) -> str:
        if v not in _VALID_SMTP_SECURITY:
            raise ValueError(f"smtp_security must be one of {sorted(_VALID_SMTP_SECURITY)}")
        return v

    @field_validator("min_severity")
    @classmethod
    def _valid_severity(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if v not in _VALID_SEVERITIES:
            raise ValueError(f"min_severity must be one of {sorted(_VALID_SEVERITIES)}")
        return v

    @model_validator(mode="after")
    def _valid_kind_config(self) -> AuditTargetBody:
        # Per-kind completeness (#1581), mirroring the legacy
        # flat-settings validators below. Without this a host-less
        # syslog / URL-less webhook target was saved enabled, then
        # silently skipped by ``audit_forward._load_targets``, and an
        # SMTP target with no recipients warned on every audit row.
        if self.kind == "syslog":
            if not self.host.strip():
                raise ValueError("host is required for a syslog target")
            if not (1 <= self.port <= 65535):
                raise ValueError("port must be 1–65535")
            if not (0 <= self.facility <= 23):
                raise ValueError("facility must be 0–23 (RFC 5424)")
        elif self.kind == "webhook":
            # ``url`` is write-only (#1502): ``None`` keeps the stored URL,
            # so only an explicit blank is refused here. A webhook with no
            # URL at all is caught by ``_require_webhook_url``.
            if self.url is not None and not self.url.strip():
                raise ValueError("url is required for a webhook target")
        elif self.kind == "smtp":
            if not self.smtp_host.strip():
                raise ValueError("smtp_host is required for an smtp target")
            if not (1 <= self.smtp_port <= 65535):
                raise ValueError("smtp_port must be 1–65535")
            if not self.smtp_from_address.strip():
                raise ValueError("smtp_from_address is required for an smtp target")
            recipients = [a for a in (self.smtp_to_addresses or []) if a and a.strip()]
            if not recipients:
                raise ValueError("smtp_to_addresses must contain at least one recipient")
        return self


class AuditTargetResponse(BaseModel):
    id: str
    name: str
    enabled: bool
    kind: str
    format: str
    host: str
    port: int
    protocol: str
    facility: int
    ca_cert_pem: str | None
    # The URL and header are never returned (#1502). ``url_display`` is the
    # scheme and host only (``https://hooks.slack.com/…``), so targets can
    # still be told apart.
    url_set: bool
    url_display: str
    auth_header_set: bool
    webhook_flavor: str
    smtp_host: str
    smtp_port: int
    smtp_security: str
    smtp_username: str
    # Redact the SMTP password the same way Fingerbank does — bool only.
    smtp_password_set: bool
    smtp_from_address: str
    smtp_to_addresses: list[str] | None
    smtp_reply_to: str
    min_severity: str | None
    resource_types: list[str] | None
    created_at: datetime
    modified_at: datetime


def _target_to_response(t: AuditForwardTarget) -> AuditTargetResponse:
    return AuditTargetResponse(
        id=str(t.id),
        name=t.name,
        enabled=t.enabled,
        kind=t.kind,
        format=t.format,
        host=t.host,
        port=t.port,
        protocol=t.protocol,
        facility=t.facility,
        ca_cert_pem=t.ca_cert_pem,
        url_set=bool(t.url_encrypted),
        url_display=url_display(reveal(t.url_encrypted, field="url", target=t.name)),
        auth_header_set=bool(t.auth_header_encrypted),
        webhook_flavor=t.webhook_flavor or "generic",
        smtp_host=t.smtp_host or "",
        smtp_port=int(t.smtp_port or 587),
        smtp_security=t.smtp_security or "starttls",
        smtp_username=t.smtp_username or "",
        smtp_password_set=bool(t.smtp_password_encrypted),
        smtp_from_address=t.smtp_from_address or "",
        smtp_to_addresses=list(t.smtp_to_addresses) if t.smtp_to_addresses else None,
        smtp_reply_to=t.smtp_reply_to or "",
        min_severity=t.min_severity,
        resource_types=t.resource_types,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


def _apply_body(t: AuditForwardTarget, body: AuditTargetBody) -> None:
    from app.core.crypto import encrypt_str

    t.name = body.name
    t.enabled = body.enabled
    t.kind = body.kind
    t.format = body.format
    t.host = body.host
    t.port = body.port
    t.protocol = body.protocol
    t.facility = body.facility
    t.ca_cert_pem = body.ca_cert_pem
    t.url_encrypted = apply_write_only(t.url_encrypted, body.url)
    t.auth_header_encrypted = apply_write_only(t.auth_header_encrypted, body.auth_header)
    t.webhook_flavor = body.webhook_flavor
    t.smtp_host = body.smtp_host
    t.smtp_port = body.smtp_port
    t.smtp_security = body.smtp_security
    t.smtp_username = body.smtp_username
    t.smtp_from_address = body.smtp_from_address
    t.smtp_to_addresses = body.smtp_to_addresses
    t.smtp_reply_to = body.smtp_reply_to
    # ``smtp_password`` semantics: ``None`` = leave existing encrypted
    # value alone (operator editing other fields), ``""`` = clear,
    # anything else = encrypt + replace.
    if body.smtp_password is not None:
        t.smtp_password_encrypted = encrypt_str(body.smtp_password) if body.smtp_password else None
    t.min_severity = body.min_severity
    t.resource_types = body.resource_types


def _require_webhook_url(body: AuditTargetBody, stored: bytes | None) -> None:
    """Refuse a webhook target that would end up with no URL (#1581).

    The body validator can't see the stored value, and an omitted ``url``
    means "keep it", so this runs in the handler: on create there is
    nothing to keep, on update there is only if the row already has one.
    """
    if body.kind == "webhook" and body.url is None and stored is None:
        raise HTTPException(status_code=422, detail="url is required for a webhook target")


def _save_error(exc: Exception, body: AuditTargetBody) -> str:
    """The reason a save failed, without the statement's bound parameters.

    SQLAlchemy's message for a failed flush ends with ``[parameters: …]``,
    every value the INSERT / UPDATE carried (#1502). The driver's own
    message (``duplicate key value violates unique constraint …``) is all
    the operator needs.
    """
    reason = str(getattr(exc, "orig", None) or exc)
    return redact(reason, body.url or "", body.auth_header or "", body.smtp_password or "")


def _forward_snapshot(t: AuditForwardTarget) -> dict:
    """Audit snapshot of an audit-forward target.

    Never carries the webhook URL, ``auth_header`` or SMTP password
    (nor the CA cert) — only ``*_set`` booleans for those, per #1502 /
    PR #1506: the audit log must not become a copy of the secrets it
    describes.
    """
    return {
        "name": t.name,
        "enabled": t.enabled,
        "kind": t.kind,
        "format": t.format,
        "host": t.host,
        "port": t.port,
        "protocol": t.protocol,
        "facility": t.facility,
        "ca_cert_pem_set": bool(t.ca_cert_pem),
        "url_set": t.url_encrypted is not None,
        "auth_header_set": t.auth_header_encrypted is not None,
        "webhook_flavor": t.webhook_flavor,
        "smtp_host": t.smtp_host,
        "smtp_port": t.smtp_port,
        "smtp_security": t.smtp_security,
        "smtp_username": t.smtp_username,
        "smtp_password_set": bool(t.smtp_password_encrypted),
        "smtp_from_address": t.smtp_from_address,
        "smtp_to_addresses": list(t.smtp_to_addresses) if t.smtp_to_addresses else None,
        "smtp_reply_to": t.smtp_reply_to,
        "min_severity": t.min_severity,
        "resource_types": t.resource_types,
    }


def _audit_forward_target(
    db: DB,
    current_user: CurrentUser,
    action: str,
    row: AuditForwardTarget,
    old_value: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action=action,
            resource_type="audit_forward_target",
            resource_id=str(row.id),
            resource_display=row.name,
            result="success",
            old_value=old_value,
            new_value=None if action == "delete" else _forward_snapshot(row),
        )
    )


@router.get("/audit-forward-targets", response_model=list[AuditTargetResponse])
async def list_audit_targets(current_user: CurrentUser, db: DB) -> list[AuditTargetResponse]:
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    res = await db.execute(select(AuditForwardTarget).order_by(AuditForwardTarget.name))
    return [_target_to_response(t) for t in res.scalars().all()]


@router.post(
    "/audit-forward-targets",
    response_model=AuditTargetResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_audit_target(
    body: AuditTargetBody, current_user: CurrentUser, db: DB
) -> AuditTargetResponse:
    forbid_in_demo_mode("Audit-forward target creation is disabled")
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    _require_webhook_url(body, None)
    row = AuditForwardTarget()
    _apply_body(row, body)
    db.add(row)
    await db.flush()
    _audit_forward_target(db, current_user, "create", row)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — name collisions land here
        await db.rollback()
        raise HTTPException(
            status_code=400, detail=f"create failed: {_save_error(exc, body)}"
        ) from exc
    await db.refresh(row)
    return _target_to_response(row)


@router.put("/audit-forward-targets/{target_id}", response_model=AuditTargetResponse)
async def update_audit_target(
    # uuid.UUID, not str: a non-UUID path value used to reach the driver and
    # surface as a bind-time 500 (live: target_id='0'); typed, it is a 422.
    target_id: uuid.UUID,
    body: AuditTargetBody,
    current_user: CurrentUser,
    db: DB,
) -> AuditTargetResponse:
    forbid_in_demo_mode("Audit-forward target updates are disabled")
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = await db.get(AuditForwardTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Target not found")
    _require_webhook_url(body, row.url_encrypted)
    old_value = _forward_snapshot(row)
    _apply_body(row, body)
    _audit_forward_target(db, current_user, "update", row, old_value=old_value)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(
            status_code=400, detail=f"update failed: {_save_error(exc, body)}"
        ) from exc
    await db.refresh(row)
    return _target_to_response(row)


@router.delete("/audit-forward-targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_audit_target(target_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = await db.get(AuditForwardTarget, target_id)
    if row is None:
        return
    _audit_forward_target(db, current_user, "delete", row, old_value=_forward_snapshot(row))
    await db.delete(row)
    await db.commit()


@router.post("/audit-forward-targets/{target_id}/test")
async def test_audit_target(
    target_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> dict[str, Any]:
    """Send a synthetic event to one target and report success / error.

    The event is flagged ``action="test_forward"`` so the operator can
    filter it out in the collector if they want. Doesn't land in
    ``audit_log`` — this is explicit probe traffic, not an audit.
    """
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = await db.get(AuditForwardTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Target not found")

    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "id": "test-" + str(row.id),
        "timestamp": now.isoformat() + "Z",
        "action": "test_forward",
        "resource_type": "audit_forward_target",
        "resource_id": str(row.id),
        "resource_display": row.name,
        "result": "success",
        "user_id": str(current_user.id),
        "user_display_name": current_user.display_name,
        "auth_source": "local",
        "changed_fields": [],
        "old_value": None,
        "new_value": None,
    }
    # The webhook secrets are encrypted at rest too (#1502).
    url = reveal(row.url_encrypted, field="url", target=row.name)
    auth_header = reveal(row.auth_header_encrypted, field="auth_header", target=row.name)
    # Decrypt the SMTP password lazily — only the test path needs the
    # cleartext, and only inside this request scope.
    smtp_password = ""
    if row.kind == "smtp" and row.smtp_password_encrypted:
        try:
            from app.core.crypto import decrypt_str

            smtp_password = decrypt_str(row.smtp_password_encrypted)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=500,
                detail=f"failed to decrypt SMTP password: {exc}",
            ) from exc
    target_dict = {
        "name": row.name,
        "kind": row.kind,
        "format": row.format,
        "host": row.host,
        "port": row.port,
        "protocol": row.protocol,
        "facility": row.facility,
        "ca_cert_pem": row.ca_cert_pem,
        "url": url,
        "auth_header": auth_header,
        "webhook_flavor": row.webhook_flavor or "generic",
        "smtp_host": row.smtp_host or "",
        "smtp_port": int(row.smtp_port or 587),
        "smtp_security": row.smtp_security or "starttls",
        "smtp_username": row.smtp_username or "",
        "smtp_password": smtp_password,
        "smtp_from_address": row.smtp_from_address or "",
        "smtp_to_addresses": list(row.smtp_to_addresses or []),
        "smtp_reply_to": row.smtp_reply_to or "",
        "min_severity": None,  # ignore filter on a probe
        "resource_types": None,
    }
    try:
        outcome = await audit_forward_svc._deliver_to_target(target_dict, payload)  # noqa: SLF001
    except Exception as exc:  # noqa: BLE001
        reason = redact(str(exc), url, auth_header, smtp_password)
        raise HTTPException(status_code=502, detail=f"delivery failed: {reason}") from exc
    if outcome != audit_forward_svc.DELIVERED:
        # #1577: a filtered target, a misconfigured one, or a rejected
        # webhook used to report "ok" here because delivery was merely
        # attempted.
        raise HTTPException(status_code=502, detail=f"delivery failed: {outcome}")
    return {"status": "ok", "target": row.name}


# ── InfluxDB push export (issue #889) ──────────────────────────────────────────
#
# CRUD + test-write for ``InfluxDBTarget``. Superadmin-gated and audited
# like the audit-forward targets above, and secrets follow the same
# shape: write-only in, boolean-only out.
#
# Deliberately NOT a feature module (non-negotiable #14 asks for the
# decision to be explicit): this adds no sidebar section and no top-level
# router prefix — it is a Settings-level integration that lives under the
# existing ``/settings`` surface, same as audit forwarding. There is
# nothing for an operator to "turn off" beyond deleting or disabling a
# target, which the resource already models.


class InfluxDBTargetBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    version: str = "v2"
    url: str = ""
    verify_tls: bool = True
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    # v1
    database: str = ""
    username: str = ""
    # ``None`` = leave the stored value alone (the operator is editing
    # another field), ``""`` = clear, anything else = encrypt + replace.
    # Same three-way contract as ``AuditTargetBody.smtp_password``.
    password: str | None = None
    # v2 / v3
    org: str = ""
    bucket: str = ""
    token: str | None = None
    measurement_prefix: str = Field(default=DEFAULT_MEASUREMENT_PREFIX, max_length=64)
    push_interval_seconds: int = Field(
        default=DEFAULT_PUSH_INTERVAL_SECONDS, ge=MIN_PUSH_INTERVAL_SECONDS, le=86400
    )
    push_dns_metrics: bool = True
    push_dhcp_metrics: bool = True
    push_subnet_utilization: bool = True
    push_dhcp_scope_leases: bool = True

    @field_validator("version")
    @classmethod
    def _valid_version(cls, v: str) -> str:
        if v not in INFLUXDB_VERSIONS:
            raise ValueError(f"version must be one of {list(INFLUXDB_VERSIONS)}")
        return v

    @field_validator("url")
    @classmethod
    def _valid_url(cls, v: str) -> str:
        cleaned = v.strip()
        if cleaned and not cleaned.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return cleaned

    @field_validator("measurement_prefix")
    @classmethod
    def _valid_prefix(cls, v: str) -> str:
        # The prefix is concatenated onto a measurement name and then
        # line-protocol-escaped, so a stray comma or space would not
        # corrupt the wire format — but it would produce a measurement
        # name nobody can type into a Flux query. Reject early.
        if v and not re.fullmatch(r"[A-Za-z0-9_.:-]*", v):
            raise ValueError("measurement_prefix may only contain letters, digits, and _ . : -")
        return v


class InfluxDBTargetResponse(BaseModel):
    id: str
    name: str
    enabled: bool
    version: str
    url: str
    verify_tls: bool
    timeout_seconds: int
    database: str
    username: str
    # Secrets are never returned — only whether one is on file.
    password_set: bool
    org: str
    bucket: str
    token_set: bool
    measurement_prefix: str
    push_interval_seconds: int
    push_dns_metrics: bool
    push_dhcp_metrics: bool
    push_subnet_utilization: bool
    push_dhcp_scope_leases: bool
    last_push_at: datetime | None
    last_push_points: int
    last_push_error: str | None
    last_dns_bucket_at: datetime | None
    last_dhcp_bucket_at: datetime | None
    created_at: datetime
    modified_at: datetime


def _influx_to_response(t: InfluxDBTarget) -> InfluxDBTargetResponse:
    return InfluxDBTargetResponse(
        id=str(t.id),
        name=t.name,
        enabled=t.enabled,
        version=t.version,
        url=t.url or "",
        verify_tls=bool(t.verify_tls),
        timeout_seconds=int(t.timeout_seconds or 10),
        database=t.database or "",
        username=t.username or "",
        password_set=bool(t.password_encrypted),
        org=t.org or "",
        bucket=t.bucket or "",
        token_set=bool(t.token_encrypted),
        measurement_prefix=t.measurement_prefix or "",
        push_interval_seconds=int(t.push_interval_seconds or DEFAULT_PUSH_INTERVAL_SECONDS),
        push_dns_metrics=bool(t.push_dns_metrics),
        push_dhcp_metrics=bool(t.push_dhcp_metrics),
        push_subnet_utilization=bool(t.push_subnet_utilization),
        push_dhcp_scope_leases=bool(t.push_dhcp_scope_leases),
        last_push_at=t.last_push_at,
        last_push_points=int(t.last_push_points or 0),
        last_push_error=t.last_push_error,
        last_dns_bucket_at=t.last_dns_bucket_at,
        last_dhcp_bucket_at=t.last_dhcp_bucket_at,
        created_at=t.created_at,
        modified_at=t.modified_at,
    )


def _apply_influx_body(t: InfluxDBTarget, body: InfluxDBTargetBody) -> None:
    from app.core.crypto import encrypt_str

    t.name = body.name
    t.enabled = body.enabled
    t.version = body.version
    t.url = body.url
    t.verify_tls = body.verify_tls
    t.timeout_seconds = body.timeout_seconds
    t.database = body.database
    t.username = body.username
    t.org = body.org
    t.bucket = body.bucket
    t.measurement_prefix = body.measurement_prefix
    t.push_interval_seconds = body.push_interval_seconds
    t.push_dns_metrics = body.push_dns_metrics
    t.push_dhcp_metrics = body.push_dhcp_metrics
    t.push_subnet_utilization = body.push_subnet_utilization
    t.push_dhcp_scope_leases = body.push_dhcp_scope_leases
    if body.password is not None:
        t.password_encrypted = encrypt_str(body.password) if body.password else None
    if body.token is not None:
        t.token_encrypted = encrypt_str(body.token) if body.token else None


def _assert_influx_writable(t: InfluxDBTarget) -> None:
    """422 on a target the writer could not build a request for.

    Runs at save time so the operator finds out in the form rather than
    from a ``last_push_error`` string 60 s later. It is the *same*
    function the pusher calls, so the two can't disagree about what a
    valid target is.
    """
    from app.services.influxdb.client import InfluxTargetConfig, build_write_request

    try:
        build_write_request(
            InfluxTargetConfig(
                version=t.version,
                url=t.url or "",
                database=t.database or "",
                username=t.username or "",
                # Presence, not the value — the real secret is decrypted
                # only on the push / test paths.
                password="x" if t.password_encrypted else "",
                org=t.org or "",
                bucket=t.bucket or "",
                token="x" if t.token_encrypted else "",
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _audit_influx(db: DB, current_user: CurrentUser, action: str, row: InfluxDBTarget) -> None:
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action=action,
            resource_type="influxdb_target",
            resource_id=str(row.id),
            resource_display=row.name,
            result="success",
            # No credentials in the audit body — the encrypted columns are
            # deliberately absent rather than redacted, so a future field
            # can't leak in by being added to a dict comprehension.
            new_value=(
                None
                if action == "delete"
                else {
                    "enabled": row.enabled,
                    "version": row.version,
                    "url": row.url,
                    "database": row.database,
                    "org": row.org,
                    "bucket": row.bucket,
                    "measurement_prefix": row.measurement_prefix,
                    "push_interval_seconds": row.push_interval_seconds,
                    "push_dns_metrics": row.push_dns_metrics,
                    "push_dhcp_metrics": row.push_dhcp_metrics,
                    "push_subnet_utilization": row.push_subnet_utilization,
                    "push_dhcp_scope_leases": row.push_dhcp_scope_leases,
                }
            ),
        )
    )


@router.get("/influxdb-targets", response_model=list[InfluxDBTargetResponse])
async def list_influxdb_targets(current_user: CurrentUser, db: DB) -> list[InfluxDBTargetResponse]:
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    res = await db.execute(select(InfluxDBTarget).order_by(InfluxDBTarget.name))
    return [_influx_to_response(t) for t in res.scalars().all()]


@router.post(
    "/influxdb-targets",
    response_model=InfluxDBTargetResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_influxdb_target(
    body: InfluxDBTargetBody, current_user: CurrentUser, db: DB
) -> InfluxDBTargetResponse:
    forbid_in_demo_mode("InfluxDB target creation is disabled")
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = InfluxDBTarget()
    _apply_influx_body(row, body)
    _assert_influx_writable(row)
    db.add(row)
    await db.flush()
    _audit_influx(db, current_user, "create", row)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001 — name collisions land here
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"create failed: {exc}") from exc
    await db.refresh(row)
    return _influx_to_response(row)


@router.put("/influxdb-targets/{target_id}", response_model=InfluxDBTargetResponse)
async def update_influxdb_target(
    target_id: uuid.UUID,
    body: InfluxDBTargetBody,
    current_user: CurrentUser,
    db: DB,
) -> InfluxDBTargetResponse:
    forbid_in_demo_mode("InfluxDB target updates are disabled")
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = await db.get(InfluxDBTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Target not found")
    _apply_influx_body(row, body)
    _assert_influx_writable(row)
    _audit_influx(db, current_user, "update", row)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(status_code=400, detail=f"update failed: {exc}") from exc
    await db.refresh(row)
    return _influx_to_response(row)


@router.delete("/influxdb-targets/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_influxdb_target(target_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = await db.get(InfluxDBTarget, target_id)
    if row is None:
        return
    _audit_influx(db, current_user, "delete", row)
    await db.delete(row)
    await db.commit()


class InfluxDBTestResponse(BaseModel):
    ok: bool
    message: str
    points: int


@router.post("/influxdb-targets/{target_id}/test", response_model=InfluxDBTestResponse)
async def test_influxdb_target(
    target_id: uuid.UUID, current_user: CurrentUser, db: DB
) -> InfluxDBTestResponse:
    """Write one synthetic point and report the server's verdict.

    Deliberately a *real* write rather than a reachability ping: a
    correct URL with the wrong bucket, org or token answers a GET
    perfectly well and then rejects every point. The point lands in the
    target's own ``<prefix>export_test`` measurement so it never
    contaminates a real series, and the watermarks are untouched — this
    is a probe, not a push.
    """
    if not is_effective_superadmin(current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    row = await db.get(InfluxDBTarget, target_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Target not found")

    from app.core.ssrf import assert_safe_target
    from app.services.influxdb.client import (
        InfluxDBWriteError,
        config_from_row,
        write_lines,
    )
    from app.services.influxdb.line_protocol import Point, render_batch

    # Advisory SSRF logging only (no block=True) — an InfluxDB on the
    # same LAN, or on the appliance itself, is the common case. See
    # app/core/ssrf.py.
    assert_safe_target(row.url, label="influxdb")

    point = Point(
        measurement=f"{row.measurement_prefix or ''}export_test",
        tags={"target": row.name},
        fields={"ok": 1, "source": "spatiumddi"},
        timestamp=int(datetime.now(UTC).timestamp()),
    )
    try:
        await write_lines(config_from_row(row), render_batch([point]))
    except (InfluxDBWriteError, ValueError) as exc:
        return InfluxDBTestResponse(ok=False, message=str(exc), points=0)
    return InfluxDBTestResponse(ok=True, message="1 point written", points=1)


# ── Public branding surface (issues #885 / #886 / #887 / #888) ──────────────────
#
# These two routes are the only ones in this router with no ``CurrentUser``
# dependency, and that is deliberate: the login page renders the banner,
# the logo and the app title before anyone has a session. Nothing here may
# ever carry a value an anonymous visitor shouldn't see, which is why the
# response is an explicit whitelist rather than a filtered dump of the
# settings row — a field added to PlatformSettings tomorrow cannot leak
# through by default.


class PublicLoginBanner(BaseModel):
    enabled: bool
    title: str
    text: str
    require_ack: bool


class PublicEnvBanner(BaseModel):
    enabled: bool
    text: str
    bg: str
    fg: str
    position: str


class PublicSettingsResponse(BaseModel):
    app_title: str
    login_banner: PublicLoginBanner
    env_banner: PublicEnvBanner
    logo_sha256: str | None


@router.get("/public", response_model=PublicSettingsResponse)
async def get_public_settings(db: DB) -> PublicSettingsResponse:
    """Branding for pre-authentication rendering.

    Unauthenticated on purpose — the login screen needs the operator's
    title, acceptable-use banner, environment strip and logo before a
    session exists. Everything returned is operator-authored text intended
    for exactly that audience.
    """
    # Both lookups tolerate absence: on a fresh install the singleton
    # settings row is only created by the first write, and the logo is
    # independent of it — a logo uploaded before anyone saves settings must
    # still be served, so these two are queried separately.
    # A transient instance stands in for the missing row so the no-row case
    # answers with the same shape as a configured one. Note its columns read
    # as None, NOT the ORM ``default=`` values — SQLAlchemy applies those at
    # flush, not at construction — so the ``or`` fallbacks below are
    # load-bearing, not belt-and-braces. Real attribute access (rather than
    # ``getattr`` by string) keeps mypy and rename refactors honest: a
    # renamed column errors here instead of silently serving defaults.
    settings = await db.get(PlatformSettings, _SINGLETON_ID) or PlatformSettings()
    logo_sha: str | None = (
        await db.execute(
            select(BrandingAsset.sha256).where(BrandingAsset.kind == BRANDING_ASSET_KIND_LOGO)
        )
    ).scalar_one_or_none()

    return PublicSettingsResponse(
        app_title=settings.app_title or "SpatiumDDI",
        login_banner=PublicLoginBanner(
            enabled=bool(settings.login_banner_enabled),
            title=settings.login_banner_title or "",
            text=settings.login_banner_text or "",
            require_ack=bool(settings.login_banner_require_ack),
        ),
        env_banner=PublicEnvBanner(
            enabled=bool(settings.env_banner_enabled),
            text=settings.env_banner_text or "",
            bg=settings.env_banner_bg or "#b91c1c",
            fg=settings.env_banner_fg or "#ffffff",
            position=settings.env_banner_position or "top",
        ),
        logo_sha256=logo_sha,
    )


@router.get("/public/logo", response_model=None)
async def get_public_logo(db: DB, if_none_match: str | None = Header(default=None)) -> Response:
    """Serve the operator-uploaded logo, or 404 so the frontend falls back
    to the bundled asset.

    Unauthenticated for the same reason as ``/public`` — the browser
    fetches this straight from an ``img`` tag on the login page, where no
    Authorization header is available.
    """
    row = (
        await db.execute(
            select(BrandingAsset).where(BrandingAsset.kind == BRANDING_ASSET_KIND_LOGO)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No custom logo is configured")

    if if_none_match and etag_matches(if_none_match, row.sha256):
        return Response(status_code=304, headers={"ETag": format_etag(row.sha256)})

    return Response(
        content=row.content,
        media_type=row.media_type,
        headers={
            "ETag": format_etag(row.sha256),
            # The URL the frontend builds carries the sha as a query
            # param, so a cached copy is only ever reused for identical
            # bytes; a re-upload changes the URL and misses the cache.
            "Cache-Control": "public, max-age=300",
        },
    )


class BrandingLogoInfo(BaseModel):
    sha256: str
    byte_size: int
    media_type: str


@router.put("/branding/logo", response_model=BrandingLogoInfo)
async def upload_branding_logo(
    current_user: CurrentUser,
    db: DB,
    file: UploadFile = File(..., description="PNG image, 512 KB maximum."),
) -> BrandingLogoInfo:
    """Replace the branding logo (issue #886).

    PNG only. SVG is deliberately refused: this is served same-origin, and
    an SVG can carry script — accepting one would turn a branding upload
    into stored XSS against every visitor, including unauthenticated ones.
    """
    forbid_in_demo_mode("Branding changes are disabled")
    if not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Branding can only be changed by a superadmin",
        )

    # Read with one byte of headroom so an oversized upload is detected
    # rather than silently truncated to the limit.
    content = await file.read(BRANDING_ASSET_MAX_BYTES + 1)
    if len(content) > BRANDING_ASSET_MAX_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Logo must be {BRANDING_ASSET_MAX_BYTES // 1024} KB or smaller",
        )
    if not content:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Uploaded file is empty")
    # Trust the magic bytes, not the client-declared content type.
    if not content.startswith(PNG_MAGIC):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Logo must be a PNG image (SVG and other formats are not accepted)",
        )

    digest = hashlib.sha256(content).hexdigest()
    # Upsert rather than read-then-insert: ``kind`` is UNIQUE, so two
    # concurrent uploads would both see no row, both INSERT, and the loser
    # would 500 on uq_branding_asset_kind. ON CONFLICT makes last-write-wins
    # explicit instead.
    await db.execute(
        pg_insert(BrandingAsset)
        .values(
            id=uuid.uuid4(),
            kind=BRANDING_ASSET_KIND_LOGO,
            content=content,
            media_type=BRANDING_ASSET_MEDIA_TYPE,
            sha256=digest,
            byte_size=len(content),
        )
        .on_conflict_do_update(
            # Infer the target from the column rather than naming the
            # constraint, so this cannot break if the constraint is ever
            # renamed — and so it behaves identically on a schema built by
            # create_all versus one built by migrations.
            index_elements=["kind"],
            set_={
                "content": content,
                "media_type": BRANDING_ASSET_MEDIA_TYPE,
                "sha256": digest,
                "byte_size": len(content),
                "modified_at": func.now(),
            },
        )
    )

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="update",
            resource_type="platform_settings",
            resource_id="branding_logo",
            resource_display="Branding logo",
            result="success",
            new_value={"sha256": digest, "byte_size": len(content)},
        )
    )
    await db.commit()

    logger.info("branding_logo_updated", user=current_user.username, sha256=digest)
    return BrandingLogoInfo(
        sha256=digest,
        byte_size=len(content),
        media_type=BRANDING_ASSET_MEDIA_TYPE,
    )


@router.delete("/branding/logo", status_code=status.HTTP_204_NO_CONTENT)
async def delete_branding_logo(current_user: CurrentUser, db: DB) -> Response:
    """Drop the custom logo; the UI falls back to the bundled asset."""
    forbid_in_demo_mode("Branding changes are disabled")
    if not is_effective_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Branding can only be changed by a superadmin",
        )

    row = (
        await db.execute(
            select(BrandingAsset).where(BrandingAsset.kind == BRANDING_ASSET_KIND_LOGO)
        )
    ).scalar_one_or_none()
    if row is not None:
        await db.delete(row)
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="delete",
                resource_type="platform_settings",
                resource_id="branding_logo",
                resource_display="Branding logo",
                result="success",
            )
        )
        await db.commit()
        logger.info("branding_logo_deleted", user=current_user.username)

    return Response(status_code=status.HTTP_204_NO_CONTENT)

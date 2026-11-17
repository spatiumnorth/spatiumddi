"""Synchronous LDAP authentication helpers.

Callers must invoke these from a worker thread (``asyncio.to_thread``) — the
underlying ``ldap3`` library is blocking. See
``backend/app/api/v1/auth/router.py`` for the async wrapper used at login.
"""

from __future__ import annotations

import secrets
import ssl
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from ldap3 import ALL, FIRST, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPInvalidCredentialsResult,
    LDAPSocketOpenError,
)
from ldap3.utils.conv import escape_filter_chars

from app.core.auth.user_sync import ExternalAuthResult
from app.core.crypto import decrypt_dict
from app.models.auth_provider import AuthProvider

logger = structlog.get_logger(__name__)


class LDAPServiceError(Exception):
    """Raised when the LDAP server or service-account credentials are
    misconfigured — distinct from a user password being wrong."""


def _parse_host_port(entry: str, default_port: int) -> tuple[str, int]:
    """Parse ``host`` or ``host:port`` into (host, port). Bracketed IPv6
    literals like ``[::1]:389`` are also supported."""
    s = entry.strip()
    if not s:
        raise ValueError("empty host entry")
    # Bracketed IPv6: [::1]:389 or [::1]
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise ValueError(f"unterminated '[' in host entry: {entry!r}")
        host = s[1:end]
        rest = s[end + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError(f"expected ':port' after ']' in host entry: {entry!r}")
        return host, int(rest[1:])
    # host or host:port (plain)
    if s.count(":") == 1:
        host, _, port_s = s.partition(":")
        return host.strip(), int(port_s)
    return s, default_port


@dataclass
class LDAPConfig:
    host: str
    port: int
    # Additional LDAP hosts to try when the primary is unreachable.
    # Each entry is ``"host"`` or ``"host:port"``. Backups reuse the primary's
    # port when no ``:port`` is provided.
    backup_hosts: list[str]
    use_ssl: bool
    start_tls: bool
    bind_dn: str
    bind_password: str
    user_base_dn: str
    user_filter: str
    group_base_dn: str
    attr_username: str
    attr_email: str
    attr_display_name: str
    attr_member_of: str
    # Optional CA cert file for TLS validation (container path). None = system store.
    tls_ca_cert_file: str | None = None
    # Skip TLS certificate validation entirely. Useful when connecting by IP
    # (cert CN mismatch) or against a self-signed cert in a lab. Still encrypts
    # the channel — but does NOT authenticate the server, so don't enable this
    # in production.
    tls_insecure: bool = False

    @classmethod
    def from_provider(cls, provider: AuthProvider) -> LDAPConfig:
        cfg = provider.config or {}
        secrets = decrypt_dict(provider.secrets_encrypted) if provider.secrets_encrypted else {}

        host = str(cfg.get("host") or "").strip()
        if not host:
            raise LDAPServiceError("config.host is required")
        bind_dn = str(cfg.get("bind_dn") or "").strip()
        bind_password = str(secrets.get("bind_password") or "")
        if not bind_dn or not bind_password:
            raise LDAPServiceError("config.bind_dn and secrets.bind_password are required")
        user_base_dn = str(cfg.get("user_base_dn") or "").strip()
        if not user_base_dn:
            raise LDAPServiceError("config.user_base_dn is required")
        user_filter = str(cfg.get("user_filter") or "").strip()
        if "{username}" not in user_filter:
            raise LDAPServiceError("config.user_filter must contain the {username} placeholder")

        use_ssl = bool(cfg.get("use_ssl", True))
        port_raw = cfg.get("port")
        port = int(port_raw) if port_raw is not None else (636 if use_ssl else 389)

        backup_raw = cfg.get("backup_hosts") or []
        backup_hosts: list[str] = []
        if isinstance(backup_raw, list):
            backup_hosts = [str(h).strip() for h in backup_raw if str(h).strip()]
        elif isinstance(backup_raw, str):
            # Accept a comma-or-newline-separated string for convenience.
            backup_hosts = [
                tok.strip() for tok in backup_raw.replace("\n", ",").split(",") if tok.strip()
            ]

        return cls(
            host=host,
            port=port,
            backup_hosts=backup_hosts,
            use_ssl=use_ssl,
            start_tls=bool(cfg.get("start_tls", False)),
            bind_dn=bind_dn,
            bind_password=bind_password,
            user_base_dn=user_base_dn,
            user_filter=user_filter,
            group_base_dn=str(cfg.get("group_base_dn") or "").strip(),
            attr_username=str(cfg.get("attr_username") or "sAMAccountName"),
            attr_email=str(cfg.get("attr_email") or "mail"),
            attr_display_name=str(cfg.get("attr_display_name") or "displayName"),
            attr_member_of=str(cfg.get("attr_member_of") or "memberOf"),
            tls_ca_cert_file=(cfg.get("tls_ca_cert_file") or None),
            tls_insecure=bool(cfg.get("tls_insecure", False)),
        )


def _tls(cfg: LDAPConfig) -> Tls | None:
    if not (cfg.use_ssl or cfg.start_tls):
        return None
    if cfg.tls_insecure:
        # Channel is still encrypted; server identity is not verified. Flagged
        # as a warning so admins can see this in the logs if they forgot to
        # re-enable validation after a lab test.
        logger.warning("ldap_tls_validation_disabled", host=cfg.host)
        return Tls(
            validate=ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT,
        )
    return Tls(
        validate=ssl.CERT_REQUIRED,
        ca_certs_file=cfg.tls_ca_cert_file,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )


def _build_server(cfg: LDAPConfig, host: str, port: int) -> Server:
    return Server(
        host,
        port=port,
        use_ssl=cfg.use_ssl,
        tls=_tls(cfg),
        get_info=ALL,
        connect_timeout=5,
    )


def _server_target(cfg: LDAPConfig) -> Server | ServerPool:
    """Return a single Server if no backups are configured, otherwise a
    ServerPool that fails over to the next host on connect failure."""
    primary = _build_server(cfg, cfg.host, cfg.port)
    if not cfg.backup_hosts:
        return primary
    servers: list[Server] = [primary]
    for entry in cfg.backup_hosts:
        try:
            host, port = _parse_host_port(entry, cfg.port)
        except ValueError:
            logger.warning("ldap_backup_host_invalid", entry=entry)
            continue
        servers.append(_build_server(cfg, host, port))
    # active=True → check reachability before issuing operations.
    # exhaust=True → after a server fails, remove it for the pool's lifetime
    # so subsequent binds in this Connection don't keep retrying a dead host.
    return ServerPool(servers, pool_strategy=FIRST, active=True, exhaust=True)


def _open(cfg: LDAPConfig, user: str, password: str) -> Connection:
    """Open + bind a connection. Raises LDAPBindError on credential failure,
    LDAPSocketOpenError / LDAPException on infrastructure failure."""
    conn = Connection(
        _server_target(cfg),
        user=user,
        password=password,
        auto_bind=False,
        raise_exceptions=True,
        receive_timeout=10,
    )
    if cfg.start_tls and not cfg.use_ssl:
        conn.open()
        conn.start_tls()
    conn.bind()
    return conn


def _user_attrs(cfg: LDAPConfig) -> list[str]:
    return [
        cfg.attr_username,
        cfg.attr_email,
        cfg.attr_display_name,
        cfg.attr_member_of,
    ]


def _attr_first(entry: Any, name: str) -> str | None:
    """Pull a single string from an ldap3 entry attribute, which may be a list."""
    val = entry.get(name) if hasattr(entry, "get") else None
    if val is None:
        return None
    if isinstance(val, list):
        return str(val[0]) if val else None
    return str(val)


def _attr_list(entry: Any, name: str) -> list[str]:
    val = entry.get(name) if hasattr(entry, "get") else None
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _search_user(conn: Connection, cfg: LDAPConfig, username: str) -> dict | None:
    """Returns a dict like {'dn': ..., 'attributes': {...}} or None if not found."""
    filt = cfg.user_filter.format(username=escape_filter_chars(username))
    conn.search(
        search_base=cfg.user_base_dn,
        search_filter=filt,
        search_scope=SUBTREE,
        attributes=_user_attrs(cfg),
        size_limit=2,
    )
    entries = conn.response or []
    hits = [e for e in entries if e.get("type") == "searchResEntry"]
    if not hits:
        return None
    if len(hits) > 1:
        raise LDAPServiceError(
            f"user_filter matched {len(hits)} entries for {username!r} — refine the filter"
        )
    hit = hits[0]
    return {"dn": hit["dn"], "attributes": hit.get("attributes") or {}}


def _result_from_entry(cfg: LDAPConfig, dn: str, attrs: dict) -> ExternalAuthResult:
    return ExternalAuthResult(
        external_id=dn,
        username=(_attr_first(attrs, cfg.attr_username) or "").strip(),
        email=_attr_first(attrs, cfg.attr_email),
        display_name=_attr_first(attrs, cfg.attr_display_name),
        groups=_attr_list(attrs, cfg.attr_member_of),
    )


def _decoy_user_bind(cfg: LDAPConfig) -> None:
    """Best-effort bind that always fails; only its cost matters.

    It uses a random password, never the one the user typed: the typed
    password is only ever sent for an entry the directory itself returned.
    """
    try:
        _open(cfg, f"cn={uuid.uuid4().hex},{cfg.user_base_dn}", secrets.token_urlsafe(24)).unbind()
    except LDAPException:
        # Rejected (the expected outcome) or the server went away.
        pass


def authenticate_ldap(
    provider: AuthProvider, username: str, password: str
) -> ExternalAuthResult | None:
    """Attempt to authenticate ``username``/``password`` against ``provider``.

    Returns an ``ExternalAuthResult`` on success, ``None`` on bad credentials.
    Raises ``LDAPServiceError`` on configuration / connection failure so the
    caller can fall through to the next provider.
    """
    if not password:
        return None

    cfg = LDAPConfig.from_provider(provider)

    # 1) Service bind + user search.
    try:
        service = _open(cfg, cfg.bind_dn, cfg.bind_password)
    except LDAPInvalidCredentialsResult as exc:
        raise LDAPServiceError(f"service bind rejected: {exc}") from exc
    except LDAPBindError as exc:
        raise LDAPServiceError(f"service bind failed: {exc}") from exc
    except LDAPSocketOpenError as exc:
        raise LDAPServiceError(f"cannot reach LDAP server: {exc}") from exc
    except LDAPException as exc:
        raise LDAPServiceError(f"LDAP error during service bind: {exc}") from exc

    try:
        found = _search_user(service, cfg, username)
    finally:
        service.unbind()

    if found is None:
        # No such entry. Do the user bind a known entry gets, against a DN that
        # holds nothing, so a name the directory has never heard of costs it
        # the same two binds as one it has.
        _decoy_user_bind(cfg)
        return None

    dn = found["dn"]
    attrs = found["attributes"]

    # 2) Bind as the user to verify the password.
    try:
        user_conn = _open(cfg, dn, password)
    except (LDAPInvalidCredentialsResult, LDAPBindError):
        return None
    except LDAPSocketOpenError as exc:
        raise LDAPServiceError(f"cannot reach LDAP server: {exc}") from exc
    except LDAPException as exc:
        raise LDAPServiceError(f"LDAP error during user bind: {exc}") from exc
    user_conn.unbind()

    return _result_from_entry(cfg, dn, attrs)


def test_connection(
    provider: AuthProvider, username: str | None = None, password: str | None = None
) -> dict[str, Any]:
    """Structured probe for the admin "Test connection" button.

    Never raises — returns ``{ok, message, details}``.
    """
    try:
        cfg = LDAPConfig.from_provider(provider)
    except LDAPServiceError as exc:
        return {"ok": False, "message": str(exc), "details": {}}

    try:
        service = _open(cfg, cfg.bind_dn, cfg.bind_password)
    except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
        return {"ok": False, "message": f"service bind rejected: {exc}", "details": {}}
    except LDAPSocketOpenError as exc:
        return {"ok": False, "message": f"cannot reach server: {exc}", "details": {}}
    except LDAPException as exc:
        return {"ok": False, "message": f"LDAP error: {exc}", "details": {}}

    try:
        if username is None:
            # When a ServerPool is in use, ldap3 exposes the currently-bound
            # server via service.server. Fall back to the configured primary
            # if unavailable (single-host case).
            bound_host = getattr(getattr(service, "server", None), "host", cfg.host)
            bound_port = getattr(getattr(service, "server", None), "port", cfg.port)
            return {
                "ok": True,
                "message": "service bind OK",
                "details": {
                    "server": f"{bound_host}:{bound_port}",
                    "tls": "ssl" if cfg.use_ssl else ("starttls" if cfg.start_tls else "plain"),
                    "backups_configured": len(cfg.backup_hosts),
                },
            }

        found = _search_user(service, cfg, username)
        if found is None:
            return {
                "ok": False,
                "message": f"user {username!r} not found with user_filter",
                "details": {},
            }
        dn = found["dn"]
        attrs = found["attributes"]
        result = _result_from_entry(cfg, dn, attrs)

        details: dict[str, Any] = {
            "dn": result.external_id,
            "username": result.username,
            "email": result.email,
            "display_name": result.display_name,
            "group_dns": result.groups,
        }

        if password:
            try:
                user_conn = _open(cfg, dn, password)
                user_conn.unbind()
                details["user_bind"] = "ok"
            except (LDAPInvalidCredentialsResult, LDAPBindError):
                return {
                    "ok": False,
                    "message": "user password rejected",
                    "details": details,
                }

        return {"ok": True, "message": "OK", "details": details}
    finally:
        service.unbind()

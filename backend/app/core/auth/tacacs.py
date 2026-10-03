"""Synchronous TACACS+ authentication helpers.

Callers must invoke these from a worker thread (``asyncio.to_thread``) — the
underlying ``tacacs_plus`` library does blocking TCP I/O. See
``backend/app/api/v1/auth/router.py`` for the async wrapper used at login.

TACACS+ authorization is a separate round-trip: after ``authenticate()``
returns valid, we ask ``authorize()`` to authorize a login shell
(``service=shell``, ``cmd=``; RFC 8907 section 8.2) and extract AV-pairs from
the response. The ``priv-lvl`` AV pair is conventional; admins can also
populate a custom ``group`` pair on the TACACS+ server.

Manual test recipe (requires a reachable TACACS+ server):
    $ python -c "from app.core.auth.tacacs import authenticate_tacacs; \\
                  from app.models.auth_provider import AuthProvider; \\
                  p = AuthProvider(config={'server':'10.0.0.1'}, \\
                                   secrets_encrypted=<fernet>); \\
                  print(authenticate_tacacs(p, 'alice', 'secret'))"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from tacacs_plus.client import TACACSClient

from app.core.auth.user_sync import ExternalAuthResult
from app.core.crypto import decrypt_dict
from app.models.auth_provider import AuthProvider

logger = structlog.get_logger(__name__)


# What a sign-in asks the server to authorize: a login shell, the session a
# network device asks for when a user logs in. RFC 8907 section 8.2: the
# ``service`` argument "MUST always be included", and ``cmd`` "MUST be
# specified if service equals "shell"", with an empty value for session-based
# (rather than per-command) authorization. Servers key their authorization
# profiles on ``service`` (tac_plus-ng's sample: ``if (service == shell)``),
# so a request without it is refused, the reply carries no ``priv-lvl``, and
# no group maps (#1336). Both are mandatory (``=``), as the RFC words them.
LOGIN_AUTHORIZATION_ARGS: tuple[bytes, ...] = (b"service=shell", b"cmd=")


class TACACSServiceError(Exception):
    """Raised when the TACACS+ server is unreachable or the shared secret is
    misconfigured — distinct from an authentication failure (bad password)."""


def _parse_host_port(entry: str, default_port: int) -> tuple[str, int]:
    """Parse ``host`` or ``host:port`` into (host, port). Bracketed IPv6
    literals like ``[::1]:49`` are also supported."""
    s = entry.strip()
    if not s:
        raise ValueError("empty server entry")
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise ValueError(f"unterminated '[' in server entry: {entry!r}")
        host = s[1:end]
        rest = s[end + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError(f"expected ':port' after ']' in server entry: {entry!r}")
        return host, int(rest[1:])
    if s.count(":") == 1:
        host, _, port_s = s.partition(":")
        return host.strip(), int(port_s)
    return s, default_port


def _split_backup_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(h).strip() for h in raw if str(h).strip()]
    if isinstance(raw, str):
        return [tok.strip() for tok in raw.replace("\n", ",").split(",") if tok.strip()]
    return []


@dataclass
class TACACSConfig:
    server: str
    port: int
    # Additional TACACS+ servers tried when the primary is unreachable.
    # Each entry is ``"host"`` or ``"host:port"``. They share the shared
    # secret and timeout with the primary.
    backup_servers: list[str]
    secret: str
    timeout: int
    # Name of the AV-pair that carries group info (default ``priv-lvl``).
    # When the value is numeric we emit ``"priv-lvl:<n>"`` so it can be mapped
    # via the group-mapping UI.
    attr_groups: str

    @classmethod
    def from_provider(cls, provider: AuthProvider) -> TACACSConfig:
        cfg = provider.config or {}
        secrets = decrypt_dict(provider.secrets_encrypted) if provider.secrets_encrypted else {}

        server = str(cfg.get("server") or "").strip()
        if not server:
            raise TACACSServiceError("config.server is required")
        secret_s = str(secrets.get("secret") or "")
        if not secret_s:
            raise TACACSServiceError("secrets.secret is required")

        port_raw = cfg.get("port")
        port = int(port_raw) if port_raw is not None else 49
        timeout_raw = cfg.get("timeout")
        timeout = int(timeout_raw) if timeout_raw is not None else 5

        return cls(
            server=server,
            port=port,
            backup_servers=_split_backup_list(cfg.get("backup_servers")),
            secret=secret_s,
            timeout=timeout,
            attr_groups=str(cfg.get("attr_groups") or "priv-lvl"),
        )

    def server_targets(self) -> list[tuple[str, int]]:
        """Primary + valid backups, resolved to (host, port) pairs."""
        out: list[tuple[str, int]] = [(self.server, self.port)]
        for entry in self.backup_servers:
            try:
                out.append(_parse_host_port(entry, self.port))
            except ValueError:
                logger.warning("tacacs_backup_invalid", entry=entry)
        return out


def _client(cfg: TACACSConfig, host: str, port: int) -> TACACSClient:
    # family=AF_INET — explicit; library default is AF_UNSPEC which triggers
    # getaddrinfo. Leave to default for IPv6 compatibility.
    return TACACSClient(
        host=host,
        port=port,
        secret=cfg.secret,
        timeout=cfg.timeout,
    )


def _extract_groups(args: Any, attr_name: str) -> list[str]:
    """Turn a list of TACACS+ AV-pairs (``name=value`` or ``name*value``) into
    group identifiers. If ``attr_name`` is ``priv-lvl`` and the value is
    numeric, prefix with ``priv-lvl:`` for admin readability in the mapping UI.
    """
    if not args:
        return []
    attr_lc = attr_name.lower()
    out: list[str] = []
    for pair in args:
        if isinstance(pair, bytes):
            pair = pair.decode(errors="replace")
        elif not isinstance(pair, str):
            pair = str(pair)
        # Separator is '=' (mandatory) or '*' (optional) per RFC 8907.
        for sep in ("=", "*"):
            if sep in pair:
                k, _, v = pair.partition(sep)
                break
        else:
            continue
        if k.lower() != attr_lc:
            continue
        v = v.strip()
        if not v:
            continue
        # Emit "priv-lvl:N" for priv-lvl so admins can map e.g. "priv-lvl:15"
        # → Admins in the group-mapping UI.
        if attr_lc == "priv-lvl" and v.isdigit():
            out.append(f"priv-lvl:{v}")
        else:
            out.append(v)
    return out


def authenticate_tacacs(
    provider: AuthProvider, username: str, password: str
) -> ExternalAuthResult | None:
    """Attempt to authenticate ``username``/``password`` against ``provider``.

    Returns an ``ExternalAuthResult`` on auth success, ``None`` on auth
    failure (bad password or user unknown). Raises ``TACACSServiceError``
    on configuration / network failure so the caller can fall through to
    the next provider.
    """
    if not password:
        return None

    cfg = TACACSConfig.from_provider(provider)
    targets = cfg.server_targets()
    last_error: str | None = None
    client: TACACSClient | None = None
    auth_reply = None

    # Try primary then each backup. A valid=True/False authenticate reply is
    # a definitive answer — stop iterating. Network errors mean the server is
    # unusable, so move on.
    for host, port in targets:
        candidate = _client(cfg, host, port)
        try:
            reply = candidate.authenticate(username, password)
        except (TimeoutError, ConnectionError, OSError) as exc:
            last_error = f"cannot reach TACACS+ server {host}:{port}: {exc}"
            logger.warning("tacacs_target_unreachable", host=host, port=port, error=str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 — bad shared-secret / protocol
            last_error = f"TACACS+ protocol error from {host}:{port}: {exc}"
            logger.warning("tacacs_target_protocol_error", host=host, port=port, error=str(exc))
            continue
        client = candidate
        auth_reply = reply
        break

    if auth_reply is None:
        raise TACACSServiceError(last_error or "all TACACS+ servers unreachable")

    if not getattr(auth_reply, "valid", False):
        return None

    # Authorization is optional but typical — used to fetch AV pairs for
    # group mapping. Failure here is non-fatal; authenticate already succeeded.
    # Use the same client (and therefore the same host) that accepted auth.
    groups: list[str] = []
    try:
        assert client is not None
        author_reply = client.authorize(username, arguments=list(LOGIN_AUTHORIZATION_ARGS))
        if getattr(author_reply, "valid", False):
            args = getattr(author_reply, "arguments", None) or []
            groups = _extract_groups(args, cfg.attr_groups)
        else:
            # The server refused to authorize a login shell for this user, so
            # no AV-pair maps and the sign-in ends in no_group_mapping_match.
            # Say so here: the server's log is otherwise the only place it shows.
            server_msg = getattr(author_reply, "server_msg", b"") or b""
            if isinstance(server_msg, bytes):
                server_msg = server_msg.decode(errors="replace")
            logger.warning(
                "tacacs_authorization_refused",
                provider=provider.name,
                username=username,
                status=getattr(author_reply, "status", None),
                server_msg=str(server_msg)[:200],
            )
    except Exception as exc:  # noqa: BLE001 — no-authorize TACACS+ servers exist
        logger.warning(
            "tacacs_authorize_failed",
            provider=provider.name,
            username=username,
            error=str(exc),
        )

    return ExternalAuthResult(
        external_id=f"{provider.id}:{username}",
        username=username,
        email=None,
        display_name=username,
        groups=groups,
    )


def test_connection(provider: AuthProvider) -> dict[str, Any]:
    """Structured probe for the admin "Test connection" button.

    Attempts to authenticate a stub user. A returned ``valid=False`` proves
    the server is reachable and the shared secret matches (the failure is
    for the bogus credentials). Network / secret errors raise
    ``TACACSServiceError`` and are caught here.

    Never raises — always returns ``{ok, message, details}``.
    """
    try:
        cfg = TACACSConfig.from_provider(provider)
    except TACACSServiceError as exc:
        return {"ok": False, "message": str(exc), "details": {}}

    probe_user = "__spatium_probe__"
    probe_pass = "__probe__"
    try:
        result = authenticate_tacacs(provider, probe_user, probe_pass)
    except TACACSServiceError as exc:
        return {
            "ok": False,
            "message": str(exc),
            "details": {"server": f"{cfg.server}:{cfg.port}"},
        }

    return {
        "ok": True,
        "message": (
            "server reachable, shared secret OK (stub user unexpectedly accepted)"
            if result is not None
            else "server reachable, shared secret OK (stub user rejected)"
        ),
        "details": {"server": f"{cfg.server}:{cfg.port}"},
    }

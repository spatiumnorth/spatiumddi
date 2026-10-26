"""Synchronous RADIUS authentication helpers.

Callers must invoke these from a worker thread (``asyncio.to_thread``) — the
underlying ``pyrad`` library does blocking UDP I/O. See
``backend/app/api/v1/auth/router.py`` for the async wrapper used at login.

Manual test recipe (requires a reachable RADIUS server):
    $ python -c "from app.core.auth.radius import authenticate_radius; \\
                  from app.models.auth_provider import AuthProvider; \\
                  p = AuthProvider(config={'server':'10.0.0.1','port':1812}, \\
                                   secrets_encrypted=<fernet>); \\
                  print(authenticate_radius(p, 'alice', 'secret'))"
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog
from pyrad.client import Client
from pyrad.client import Timeout as PyradTimeout
from pyrad.dictionary import Dictionary
from pyrad.packet import AccessAccept, AccessReject, AccessRequest

from app.core.auth.user_sync import ExternalAuthResult
from app.core.crypto import decrypt_dict
from app.models.auth_provider import AuthProvider

logger = structlog.get_logger(__name__)


class RADIUSServiceError(Exception):
    """Raised when the RADIUS server is unreachable or the shared secret is
    misconfigured — distinct from Access-Reject (bad user password)."""


# Minimal built-in RADIUS dictionary. Covers the attributes we actually read;
# pyrad refuses to build packets without a Dictionary instance. Additional
# vendor-specific attributes can be added via ``dictionary_path`` if needed.
_BUILTIN_DICT = """\
ATTRIBUTE    User-Name            1    string
ATTRIBUTE    User-Password        2    string
ATTRIBUTE    NAS-IP-Address       4    ipaddr
ATTRIBUTE    NAS-Port             5    integer
ATTRIBUTE    Service-Type         6    integer
ATTRIBUTE    Filter-Id           11    string
ATTRIBUTE    Reply-Message       18    string
ATTRIBUTE    State               24    string
ATTRIBUTE    Class               25    string
ATTRIBUTE    NAS-Identifier      32    string
"""


def _parse_host_port(entry: str, default_port: int) -> tuple[str, int]:
    """Parse ``host`` or ``host:port`` into (host, port). Bracketed IPv6
    literals like ``[::1]:1812`` are also supported."""
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
    """Accept either a list of strings or a comma/newline-separated string."""
    if isinstance(raw, list):
        return [str(h).strip() for h in raw if str(h).strip()]
    if isinstance(raw, str):
        return [tok.strip() for tok in raw.replace("\n", ",").split(",") if tok.strip()]
    return []


@dataclass
class RADIUSConfig:
    server: str
    port: int
    # Additional RADIUS servers to try when the primary is unreachable.
    # Each entry is ``"host"`` or ``"host:port"``. They share the shared
    # secret, NAS-Identifier, timeout, and dictionary with the primary.
    backup_servers: list[str]
    secret: bytes
    timeout: int
    retries: int
    nas_identifier: str
    # Name of the RADIUS attribute that carries group info (default Filter-Id).
    attr_groups: str
    # Optional extra dictionary file mounted into the container.
    dictionary_path: str | None = None

    @classmethod
    def from_provider(cls, provider: AuthProvider) -> RADIUSConfig:
        cfg = provider.config or {}
        secrets = decrypt_dict(provider.secrets_encrypted) if provider.secrets_encrypted else {}

        server = str(cfg.get("server") or "").strip()
        if not server:
            raise RADIUSServiceError("config.server is required")
        secret_s = str(secrets.get("secret") or "")
        if not secret_s:
            raise RADIUSServiceError("secrets.secret is required")

        port_raw = cfg.get("port")
        port = int(port_raw) if port_raw is not None else 1812

        timeout_raw = cfg.get("timeout")
        timeout = int(timeout_raw) if timeout_raw is not None else 5
        retries_raw = cfg.get("retries")
        retries = int(retries_raw) if retries_raw is not None else 3

        return cls(
            server=server,
            port=port,
            backup_servers=_split_backup_list(cfg.get("backup_servers")),
            secret=secret_s.encode(),
            timeout=timeout,
            retries=retries,
            nas_identifier=str(cfg.get("nas_identifier") or "spatiumddi"),
            attr_groups=str(cfg.get("attr_groups") or "Filter-Id"),
            dictionary_path=(cfg.get("dictionary_path") or None),
        )

    def server_targets(self) -> list[tuple[str, int]]:
        """Primary + valid backups, resolved to (host, port) pairs."""
        out: list[tuple[str, int]] = [(self.server, self.port)]
        for entry in self.backup_servers:
            try:
                out.append(_parse_host_port(entry, self.port))
            except ValueError:
                logger.warning("radius_backup_invalid", entry=entry)
        return out


def _dictionary(cfg: RADIUSConfig) -> Dictionary:
    """Build a pyrad Dictionary from the built-in attributes plus any extra
    file the admin mounted in. pyrad accepts either a file path string or a
    file-like object to its ``Dictionary`` constructor."""
    import io

    sources: list[Any] = [io.StringIO(_BUILTIN_DICT)]
    if cfg.dictionary_path:
        sources.append(cfg.dictionary_path)
    return Dictionary(*sources)


def _client(cfg: RADIUSConfig, host: str, port: int) -> Client:
    return Client(
        server=host,
        authport=port,
        secret=cfg.secret,
        dict=_dictionary(cfg),
    )


def _attr_values(reply: Any, name: str) -> list[str]:
    """pyrad exposes attributes as a dict-like where values are lists of
    bytes/str. Normalise to a list of strings, tolerating missing keys."""
    try:
        raw = reply[name]
    except (KeyError, IndexError):
        return []
    if raw is None:
        return []
    out: list[str] = []
    for v in raw if isinstance(raw, list) else [raw]:
        if isinstance(v, bytes):
            out.append(v.decode(errors="replace"))
        else:
            out.append(str(v))
    return out


def authenticate_radius(
    provider: AuthProvider, username: str, password: str
) -> ExternalAuthResult | None:
    """Attempt to authenticate ``username``/``password`` against ``provider``.

    Returns an ``ExternalAuthResult`` on Access-Accept, ``None`` on
    Access-Reject. Raises ``RADIUSServiceError`` on configuration / network
    failure so the caller can fall through to the next provider.
    """
    if not password:
        return None

    cfg = RADIUSConfig.from_provider(provider)
    targets = cfg.server_targets()
    last_error: str | None = None
    reply = None

    # Try primary then each backup. An Access-Accept or Access-Reject is a
    # definitive answer — stop iterating. Network / protocol errors mean the
    # server is unusable, so move on to the next target.
    for host, port in targets:
        client = _client(cfg, host, port)
        client.timeout = cfg.timeout
        client.retries = cfg.retries

        try:
            req = client.CreateAuthPacket(code=AccessRequest, User_Name=username)
            # pyrad handles User-Password encryption internally.
            req["User-Password"] = req.PwCrypt(password)
            req["NAS-Identifier"] = cfg.nas_identifier
        except Exception as exc:  # noqa: BLE001 — pyrad surfaces plain Exception
            raise RADIUSServiceError(f"failed to build Access-Request: {exc}") from exc

        try:
            reply = client.SendPacket(req)
            break  # got a response — don't fail over
        except (TimeoutError, PyradTimeout):
            # pyrad raises its own ``Timeout`` (a plain Exception, not the
            # builtin TimeoutError) when no datagram comes back.
            last_error = (
                f"no reply from {host}:{port} after " f"{cfg.retries} retries × {cfg.timeout}s"
            )
            logger.warning("radius_target_unreachable", host=host, port=port, error=last_error)
            continue
        except OSError as exc:
            last_error = f"network error talking to {host}:{port}: {exc}"
            logger.warning("radius_target_unreachable", host=host, port=port, error=last_error)
            continue
        except Exception as exc:  # noqa: BLE001 — bad shared-secret → MAC mismatch
            # Some pyrad exceptions stringify to "" — name the type so the
            # reason is never blank.
            reason = str(exc) or type(exc).__name__
            last_error = f"RADIUS protocol error from {host}:{port}: {reason}"
            logger.warning("radius_target_protocol_error", host=host, port=port, error=last_error)
            continue

    if reply is None:
        raise RADIUSServiceError(last_error or "all RADIUS servers unreachable")

    if reply.code == AccessReject:
        return None
    if reply.code != AccessAccept:
        raise RADIUSServiceError(f"unexpected RADIUS reply code: {reply.code}")

    group_values = _attr_values(reply, cfg.attr_groups)
    # Some servers return a single Class string like "Admins"; others multiple.
    # Either way ExternalAuthResult.groups expects a list.
    return ExternalAuthResult(
        external_id=f"{provider.id}:{username}",
        username=username,
        email=None,
        display_name=username,
        groups=group_values,
    )


def test_connection(provider: AuthProvider) -> dict[str, Any]:
    """Structured probe for the admin "Test connection" button.

    Sends an Access-Request with a stub user + empty password.

    * Access-Reject → server reachable and shared secret accepted (the reject
      is for the bogus credentials, not the MAC).
    * ``RADIUSServiceError`` → unreachable or shared-secret mismatch.

    Never raises — always returns ``{ok, message, details}``.
    """
    try:
        cfg = RADIUSConfig.from_provider(provider)
    except RADIUSServiceError as exc:
        return {"ok": False, "message": str(exc), "details": {}}

    probe_user = "__spatium_probe__"
    probe_pass = "__probe__"
    try:
        result = authenticate_radius(provider, probe_user, probe_pass)
    except RADIUSServiceError as exc:
        return {
            "ok": False,
            "message": str(exc),
            "details": {"server": f"{cfg.server}:{cfg.port}"},
        }

    # Either Accept (unexpected — probably an AnyOne-Succeeds policy) or
    # Reject (expected). Both prove the shared secret is correct.
    return {
        "ok": True,
        "message": (
            "server reachable, shared secret OK (Access-Accept)"
            if result is not None
            else "server reachable, shared secret OK (Access-Reject for stub user)"
        ),
        "details": {"server": f"{cfg.server}:{cfg.port}"},
    }

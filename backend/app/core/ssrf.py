"""Defense-in-depth SSRF guard for operator-supplied integration targets.

SECURITY (#400 / GHSA-mj4g-hw3m-62rm, finding L5):
    The integration "Test Connection" endpoints (kubernetes / docker /
    proxmox / unifi / opnsense / tailscale / cloud / dns-import) take an
    operator-supplied host / URL and have the *server* open a connection
    to it. That is a server-side request — an authenticated SSRF surface.
    Because reaching these endpoints already requires the
    integration-write resource permission (or superadmin), the blast
    radius is small, so this is a LOW / defense-in-depth control rather
    than a primary fix.

    The honest constraint here is that almost every one of these
    integrations *legitimately* points at an RFC1918 LAN host — a
    Proxmox box on ``192.168.x.x``, a UniFi controller on ``10.x``, a
    docker daemon at ``unix:///var/run/docker.sock`` or a LAN TLS
    endpoint. We therefore MUST NOT blanket-block private ranges; doing
    so would break the product's core on-prem use case.

    What we *can* safely flag is the classic SSRF pivot targets that no
    legitimate integration target should ever resolve to:

        * loopback         127.0.0.0/8, ::1
        * link-local       169.254.0.0/16, fe80::/10
        * cloud metadata   169.254.169.254 (a link-local address; called
                           out explicitly because it is the canonical
                           SSRF-to-cloud-creds pivot)
        * unspecified      0.0.0.0/8, :: (a connect() to these is routed
                           to the local host)

    IPv4-mapped IPv6 addresses (``::ffff:127.0.0.1``) are judged by the
    IPv4 address they carry.

    ``assert_safe_target`` resolves the host and, by default, *logs* the
    resolved IP plus a ``ssrf_guard_*`` structured event so an operator
    grepping the audit/log trail can see exactly what the control plane
    was asked to dial. Loopback / link-local / metadata resolutions are
    logged at WARNING. Hard blocking is opt-in (``block=True``) and is
    deliberately NOT used by the on-box-capable integrations, because a
    full-stack appliance can legitimately reach a service on
    ``127.0.0.1`` (e.g. a co-located daemon) and we will not break that.

This module is intentionally dependency-light (stdlib ``ipaddress`` +
``socket`` + ``structlog``) and has no import-time side effects.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import structlog

logger = structlog.get_logger(__name__)

# Cloud-metadata service address — the canonical SSRF-to-creds pivot.
_CLOUD_METADATA = ipaddress.ip_address("169.254.169.254")
# RFC 1122 "this network" — the kernel routes a connect() to it locally.
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class SSRFBlockedError(Exception):
    """Raised by ``assert_safe_target(..., block=True)`` when an
    operator-supplied target resolves to a forbidden address."""


def _classify(ip: ipaddress._BaseAddress) -> str | None:
    """Return a short reason string if ``ip`` is a known SSRF-pivot
    target, else ``None``. Note RFC1918 / unique-local are intentionally
    NOT classified — those are legitimate on-prem integration targets."""

    # ``::ffff:127.0.0.1`` is 127.0.0.1 on the wire; judge the v4 address.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if ip == _CLOUD_METADATA:
        return "cloud_metadata"
    if ip.is_loopback:  # 127.0.0.0/8, ::1
        return "loopback"
    if ip.is_link_local:  # 169.254.0.0/16, fe80::/10
        return "link_local"
    # 0.0.0.0/8 and ``::`` — a connect() to these reaches the local host.
    if ip.is_unspecified or (ip.version == 4 and ip in _THIS_NETWORK):
        return "unspecified"
    return None


def classify_address(value: str) -> str | None:
    """Public form of the classifier for an IP-literal string: the reason it
    is a forbidden target, or ``None`` (including for a non-IP string)."""

    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    return _classify(ip)


def extract_host(target: str) -> str:
    """Best-effort pull of the bare hostname from a URL or ``host[:port]``.

    Accepts bare hostnames, ``host:port``, and full URLs. Returns the
    input stripped of scheme / port / path so it can be fed to
    ``socket.getaddrinfo``. Returns an empty string for inputs we cannot
    make sense of (e.g. a unix-socket ``unix://`` docker endpoint, which
    has no network host to resolve)."""

    if not target:
        return ""
    raw = target.strip()
    if "://" in raw:
        parts = urlsplit(raw)
        if parts.scheme in {"unix", "npipe"}:
            return ""  # no network host to resolve
        host = parts.hostname or ""
        return host
    # Bracketed IPv6 literal — ``[2001:db8::1]`` or ``[2001:db8::1]:443``.
    if raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            return raw[1:end]
    # bare ``host`` or ``host:port`` — split off a trailing :port only
    # when it is unambiguous (not an IPv6 literal full of colons).
    if raw.count(":") == 1:
        return raw.split(":", 1)[0]
    return raw


def assert_safe_target(
    target: str, *, label: str = "integration", block: bool = False
) -> list[str]:
    """Resolve ``target`` and log the resolved IP(s); flag SSRF pivots.

    SECURITY (#400, L5): advisory-by-default guard. ``target`` may be a
    bare host, ``host:port``, or a full URL. The host is resolved via
    ``socket.getaddrinfo`` and every resolved address is logged so the
    operator can audit what the control plane was asked to dial.

    Loopback / link-local / cloud-metadata resolutions are logged at
    WARNING. When ``block=True`` such a resolution raises
    ``SSRFBlockedError`` — callers that can legitimately reach on-box
    services leave ``block=False`` (the default) so this never breaks a
    valid flow.

    Returns the list of resolved IP strings (possibly empty when the
    target has no network host, e.g. a unix-socket docker endpoint, or
    when DNS resolution fails — resolution failure is non-fatal here
    because the downstream connect will surface the real error).
    """

    host = extract_host(target)
    if not host:
        logger.debug("ssrf_guard_no_host", label=label, target=target)
        return []

    # A bare IP literal needs no DNS; classify it directly.
    try:
        literal = ipaddress.ip_address(host)
        resolved = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
            # sockaddr[0] is the address string (AF_INET: (host, port);
            # AF_INET6: (host, port, flow, scope)) — str() pins the type.
            resolved = sorted({str(info[4][0]) for info in infos})
        except (OSError, UnicodeError) as exc:
            # Resolution failed — let the downstream connect surface the
            # real error; we just record that we tried.
            #
            # UnicodeError as well as OSError (#923): a hostname with a label
            # over 63 characters fails IDNA encoding with
            # ``UnicodeError: label too long``, which subclasses ValueError
            # and NOT OSError — so it escaped this handler and 500'd. This
            # guard is on the operator-supplied-host path of every outbound
            # integration, so that was one unhandled 500 per caller, not one.
            logger.debug("ssrf_guard_resolve_failed", label=label, host=host, error=str(exc))
            return []

    flagged: list[str] = []
    for ip_str in resolved:
        # classify_address drops an IPv6 ``%zone`` suffix, which a
        # link-local answer carries and ``ip_address`` rejects.
        reason = classify_address(ip_str)
        if reason is not None:
            flagged.append(f"{ip_str} ({reason})")

    if flagged:
        logger.warning(
            "ssrf_guard_flagged_target",
            label=label,
            host=host,
            resolved=resolved,
            flagged=flagged,
            blocked=block,
        )
        if block:
            raise SSRFBlockedError(
                f"{label}: target {host!r} resolves to a forbidden address "
                f"({', '.join(flagged)})"
            )
    else:
        logger.info("ssrf_guard_target", label=label, host=host, resolved=resolved)

    return resolved


__all__ = ["assert_safe_target", "classify_address", "extract_host", "SSRFBlockedError"]

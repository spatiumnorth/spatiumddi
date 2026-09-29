"""Helpers for safely capturing request metadata (client IP, user agent)
into audit-log + session rows.

The User-Agent header is fully attacker-controlled, so anything derived
from it that lands in a log or DB row must be sanitised first — otherwise
a crafted UA can inject control characters / newlines for log forging or
break downstream rendering (#9).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from fastapi import Request

# Strip C0 controls + DEL. Newlines/tabs in particular enable log forging
# when the value is later written to a text log.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Matches the user_agent / audit columns (String(500)). Truncate well
# inside that so a multi-byte tail can't overflow the column.
_MAX_USER_AGENT_LEN = 500


def clean_user_agent(raw: str | None) -> str | None:
    """Strip control characters and clamp the User-Agent to the column
    width. Returns ``None`` for missing / empty-after-cleaning input."""
    if not raw:
        return None
    cleaned = _CONTROL_CHARS.sub("", raw).strip()
    return cleaned[:_MAX_USER_AGENT_LEN] or None


#: The TCP peers whose ``X-Real-IP`` / ``X-Forwarded-Proto`` are believed
#: (#1221). Private, loopback, CGNAT and ULA ranges: the shipped proxies
#: (the compose frontend container, frontend pods, an appliance node reaching
#: the api Service) all sit in them, and a client can reach the api directly
#: only where it is published, which compose no longer does beyond 127.0.0.1.
#: ``TRUSTED_PROXY_CIDRS`` overrides it; ``*`` restores trust-everyone.
DEFAULT_TRUSTED_PROXY_CIDRS = (
    "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7"
)

TrustedNetworks = tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None


def parse_trusted_proxies(spec: str) -> TrustedNetworks:
    """``TRUSTED_PROXY_CIDRS`` → networks, or None for ``*`` (trust any peer).

    Raises ValueError on an entry that isn't a CIDR or address, so a typo
    fails the boot instead of quietly trusting nobody (or everybody).
    """
    entries = [e.strip() for e in spec.split(",") if e.strip()]
    if entries == ["*"]:
        return None
    if not entries:
        raise ValueError("TRUSTED_PROXY_CIDRS is empty; use '*' to trust every peer")
    return tuple(ipaddress.ip_network(e, strict=False) for e in entries)


def _is_trusted(peer: str, trusted: TrustedNetworks) -> bool:
    if trusted is None:
        return True
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in trusted)


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


class TrustedProxyMiddleware:
    """Apply ``X-Real-IP`` / ``X-Forwarded-Proto`` only from a trusted proxy.

    The api used to run uvicorn with ``--proxy-headers --forwarded-allow-ips
    *``, which rewrote ``request.client`` from the client-supplied
    ``X-Forwarded-For`` chain for every caller (#626), and then trusted
    ``X-Real-IP`` from anyone. nginx overwrites ``X-Real-IP`` with
    ``$remote_addr``, but a client that reached the api directly (compose
    publishes it) set its own (#1221).

    uvicorn now runs with ``--no-proxy-headers``, so ``scope["client"]`` here
    is the real TCP peer. When that peer is a trusted proxy, ``X-Real-IP``
    becomes the client address and ``X-Forwarded-Proto`` the scheme (the
    refresh cookie's ``Secure`` flag and the slot-image URLs depend on it).
    Otherwise both headers are ignored. ``X-Forwarded-For`` is never used: a
    chain whose client entries are LAN addresses can't be split into real and
    forged hops by a trust list that also covers the LAN, whereas nginx's
    ``X-Real-IP`` is one value it always overwrites.

    The real peer is kept in ``scope["state"]["tcp_peer"]`` for anything that
    needs to know which hop it was talking to.
    """

    def __init__(self, app: Any, trusted: TrustedNetworks) -> None:
        self.app = app
        self.trusted = trusted

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket") and scope.get("client"):
            peer, port = scope["client"][0], scope["client"][1]
            scope.setdefault("state", {})["tcp_peer"] = peer
            if _is_trusted(peer, self.trusted):
                headers = {k.lower(): v for k, v in scope.get("headers", [])}
                real = _valid_ip(headers.get(b"x-real-ip", b"").decode("latin-1"))
                if real:
                    scope["client"] = (real, port)
                proto = headers.get(b"x-forwarded-proto", b"").decode("latin-1")
                proto = proto.split(",")[0].strip().lower()
                if proto in ("http", "https"):
                    if scope["type"] == "websocket":
                        proto = "wss" if proto == "https" else "ws"
                    scope["scheme"] = proto
        await self.app(scope, receive, send)


def client_ip(request: Request) -> str | None:
    """The client address: ``request.client.host``.

    Since #1221 this is safe for security decisions too. uvicorn no longer
    derives it from ``X-Forwarded-For``, and :class:`TrustedProxyMiddleware`
    replaces it with ``X-Real-IP`` only when the TCP peer is a trusted proxy.
    Kept alongside :func:`get_trusted_client_ip` so existing callers read the
    same answer.
    """
    return request.client.host if request.client else None


def get_trusted_client_ip(request: Request) -> str | None:
    """The client source IP to trust for security decisions (#626, #1221).

    :class:`TrustedProxyMiddleware` has already resolved it: the proxy's
    ``X-Real-IP`` when the TCP peer is a trusted proxy, otherwise the peer
    itself. This must NOT read ``X-Real-IP`` on its own: any client that can
    reach the api directly can send one, which is exactly #1221.
    """
    return request.client.host if request.client else None

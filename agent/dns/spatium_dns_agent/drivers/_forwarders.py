"""A forward zone's upstream transport, rendered for BIND (#2121).

Shared, byte for byte, with ``agent/dns/spatium_dns_agent/drivers/
_forwarders.py``: the agent image cannot import ``app``, so it carries a copy,
and ``backend/tests/test_zone_forward_transport.py`` fails when the two
differ. Change them together. The agent renderer is what every agent-managed
BIND9 server runs; the control-plane template is the config preview. #878 is
what happens when two renderers of one setting disagree.

Stdlib only, for the same reason.

The rule this module exists for: a forward zone's transport is the ZONE's
own setting, defaulting to plain DNS. It does not inherit the group's
``forward_transport``, which applies to the group's resolver forwarders only.
A conditional forwarder usually points at something internal that answers
plain DNS on port 53 and nothing else (Tailscale MagicDNS at
100.100.100.100, an AD domain controller, a cloud VPC resolver); inheriting
the group's DoT sent it TLS on 853, checked against another provider's
certificate name, and every name in the zone SERVFAILed.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

#: Every transport a forward zone may carry. ``https`` and ``quic`` are
#: Technitium-only: BIND has no client-side HTTP or QUIC transport (#741).
ZONE_FORWARD_TRANSPORTS = ("do53", "tls", "https", "quic")

#: The transports BIND can render for a forward zone.
BIND_ZONE_FORWARD_TRANSPORTS = ("do53", "tls")

#: The trust store BIND validates an upstream certificate against. Shipped by
#: Alpine's ca-certificates package in the bind9 agent image.
CA_BUNDLE_PATH = "/etc/ssl/certs/ca-certificates.crt"

_TLS_NAME_PREFIX = "spatium-zone-tls-"
#: BIND parses a ``tls`` statement name as a domain name, so the generated
#: name is ONE label and a label is at most 63 octets: a longer one is "not a
#: valid name" and named refuses the whole file. Prefix (17) + "-" + digest (8)
#: leave 37 for the readable part.
_TLS_NAME_READABLE_MAX = 63 - len(_TLS_NAME_PREFIX) - 1 - 8
_SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253})$")


def zone_forward_transport(zone: Mapping[str, Any]) -> tuple[str, str | None]:
    """``(transport, tls_hostname)`` of a forward zone as the bundle carries it.

    A bundle from a control plane older than #2121 carries neither key, so a
    zone reads as plain DNS. That is the fix, not a regression: before #2121
    the zone inherited the group's transport, which is the bug. An unknown
    transport (a newer control plane) reads as the value itself so the caller
    can refuse it rather than guess.

    The hostname is lower-cased: certificate names compare case-insensitively,
    and two zones naming one provider in different case must share one ``tls``
    statement. Rendered as two, they get the same statement name (it is built
    from the lower-cased host) and named refuses the duplicate clause, i.e.
    the whole file.
    """
    transport = str(zone.get("forward_transport") or "do53").strip().lower()
    hostname = str(zone.get("forward_tls_hostname") or "").strip().rstrip(".").lower()
    return transport, (hostname or None)


def safe_tls_hostname(hostname: str | None) -> str | None:
    """``hostname`` when it is safe to interpolate into named.conf, else None.

    The API validates it as a host name; this is the renderer's own check,
    because the value lands inside ``remote-hostname "…";`` and a quote or a
    newline there makes BIND refuse the whole file.
    """
    if not hostname:
        return None
    host = hostname.strip().rstrip(".").lower()
    return host if _SAFE_HOSTNAME.match(host) else None


def zone_tls_statement_name(hostname: str) -> str:
    """The ``tls`` statement name for the upstream certificate ``hostname``.

    One statement per distinct hostname, shared by every zone that forwards
    to that provider. The name is interpolated into named.conf unquoted, so it
    is built from ``[a-z0-9-]`` only (the #934 lesson), and a digest of the
    exact hostname keeps two names that sanitise alike apart. The whole name
    is one DNS label, so it is kept within 63 octets.
    """
    host = hostname.strip().rstrip(".").lower()
    safe = re.sub(r"[^a-z0-9-]+", "-", host).strip("-")
    safe = safe[:_TLS_NAME_READABLE_MAX].strip("-") or "upstream"
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()[:8]
    return f"{_TLS_NAME_PREFIX}{safe}-{digest}"


def bind_zone_tls_statement(hostname: str) -> str:
    """The top-level ``tls`` statement a TLS forward zone's forwarders name.

    Always strict: a zone's encrypted transport requires a hostname, so there
    is no opportunistic form here. It must appear in named.conf above any
    zone that uses it.
    """
    return (
        f"tls {zone_tls_statement_name(hostname)} {{\n"
        f'    ca-file "{CA_BUNDLE_PATH}";\n'
        f'    remote-hostname "{hostname.strip().rstrip(".")}";\n'
        "    protocols { TLSv1.2; TLSv1.3; };\n"
        "};\n"
    )


def bind_zone_forwarder(entry: str, tls_name: str | None) -> str:
    """One forward-zone ``forwarders`` token for BIND.

    ``entry`` is ``ip`` or ``ip@port``, the control-plane wire shape;
    emitting it verbatim gave an unloadable ``1.1.1.1@53;``. ``tls_name`` is
    the zone's tls statement, or None for plain DNS.

    Over TLS the port defaults to 853 (RFC 7858). An entry pinning port 53
    never gets ``tls``: TLS to port 53 is a handshake nothing answers, and
    the explicit ``@53`` is the operator saying "this one is plain DNS".
    """
    ip, _, port = entry.strip().partition("@")
    ip = ip.strip()
    port = port.strip()
    if not port.isdigit():
        port = "853" if tls_name else ""
    out = ip
    if port:
        out += f" port {port}"
    if tls_name and port != "53":
        out += f" tls {tls_name}"
    return out


def bind_zone_forwarders(zone: Mapping[str, Any]) -> tuple[list[str], str | None, str | None]:
    """``(tokens, tls_hostname, refusal)`` for one forward zone on BIND.

    ``tls_hostname`` is set when the zone needs its tls statement rendered.
    ``refusal`` is a reason the zone cannot be rendered faithfully; the
    caller skips the zone and logs it rather than downgrading it to plain
    DNS or to unverified TLS, which the operator did not ask for.
    """
    transport, hostname = zone_forward_transport(zone)
    entries = [str(f) for f in (zone.get("forwarders") or []) if f]
    if transport == "do53":
        return [bind_zone_forwarder(e, None) for e in entries], None, None
    if transport != "tls":
        return [], None, f"forward_transport {transport!r} is not supported by BIND9"
    safe = safe_tls_hostname(hostname)
    if safe is None:
        return [], None, "forward_transport 'tls' without a usable forward_tls_hostname"
    name = zone_tls_statement_name(safe)
    tokens = [bind_zone_forwarder(e, name) for e in entries]
    uses_tls = any(f" tls {name}" in t for t in tokens)
    return tokens, (safe if uses_tls else None), None

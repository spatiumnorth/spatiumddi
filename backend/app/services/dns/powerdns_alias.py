"""The resolver a PowerDNS group expands ALIAS records through (#1353).

PowerDNS Authoritative answers an ALIAS by resolving its target at query
time through ``resolver=`` in ``pdns.conf``. The agent used to fall back to
``1.1.1.1,8.8.8.8`` because nothing sent it a value (#250), so every PowerDNS
server sent ALIAS targets to Cloudflare and Google: an outbound connection
nobody configured (non-negotiable #17).

The resolver is now the group's own forwarders, which an operator sets and
which a PowerDNS group otherwise does not use (pdns does not forward). With
none, ALIAS expansion is off and the API refuses a new ALIAS record rather
than store one that would answer nothing.

Only over plain DNS: ``resolver=`` speaks Do53 alone, so a group forwarding
over TLS, HTTPS or QUIC gets no resolver rather than having its upstreams
queried in plaintext against the operator's stated choice.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def alias_resolver(forwarders: Iterable[str] | None, forward_transport: str | None) -> str:
    """``pdns.conf``'s ``resolver=`` value, or ``""`` for ALIAS off.

    Forwarders are stored as ``ip`` or ``ip@port``; PowerDNS wants ``ip``,
    ``ip:port`` or ``[v6]:port``. Each entry is re-parsed rather than passed
    through, because the value is interpolated into ``pdns.conf``: an entry
    that does not parse (a row stored before forwarders were validated) is
    dropped, never written.
    """
    if (forward_transport or "do53") != "do53":
        return ""
    out: list[str] = []
    for raw in forwarders or []:
        host, sep, port = str(raw).strip().partition("@")
        try:
            addr = ipaddress.ip_address(host.strip())
        except ValueError:
            continue
        if not sep:
            out.append(str(addr))
            continue
        try:
            number = int(port.strip())
        except ValueError:
            continue
        if not 1 <= number <= 65535:
            continue
        out.append(f"[{addr}]:{number}" if addr.version == 6 else f"{addr}:{number}")
    return ",".join(out)

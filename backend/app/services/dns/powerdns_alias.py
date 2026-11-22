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
import uuid
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


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
        if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id:
            # ``fe80::1%eth0`` parses, but PowerDNS's ``resolver=`` has no
            # zone-index syntax and the agent refuses a list containing one.
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


async def group_can_resolve_alias(db: AsyncSession, group_id: uuid.UUID) -> bool:
    """Whether ``group_id`` has Do53 forwarders to expand an ALIAS through.

    The one check behind the record API's 422 and the importer's drop (#4604),
    so the two cannot disagree about which groups can serve an ALIAS.
    """
    from app.models.dns import DNSServerOptions  # models import drivers: keep it lazy

    opts = (
        await db.execute(select(DNSServerOptions).where(DNSServerOptions.group_id == group_id))
    ).scalar_one_or_none()
    return bool(
        alias_resolver(getattr(opts, "forwarders", None), getattr(opts, "forward_transport", None))
    )


ALIAS_NO_FORWARDER_MESSAGE = (
    "ALIAS records are resolved through the group's forwarders, and this "
    "group has none over plain DNS (Do53). Set forwarders under the "
    "group's server options first; SpatiumDDI no longer falls back to "
    "public resolvers."
)


async def groups_without_alias_resolver(
    db: AsyncSession, group_ids: Iterable[uuid.UUID]
) -> set[uuid.UUID]:
    """The groups among ``group_ids`` that run PowerDNS alone and have no Do53 forwarder.

    The record API's ALIAS guard applies to exactly these (a group with no
    server yet, or a mixed one, is refused or deferred elsewhere), so a Trash
    restore asks the same question (#4756).
    """
    from app.models.dns import DNSServer  # models import drivers: keep it lazy

    out: set[uuid.UUID] = set()
    for group_id in set(group_ids):
        drivers = {
            d
            for d in (
                await db.execute(select(DNSServer.driver).where(DNSServer.group_id == group_id))
            ).scalars()
            if d
        }
        if drivers == {"powerdns"} and not await group_can_resolve_alias(db, group_id):
            out.add(group_id)
    return out

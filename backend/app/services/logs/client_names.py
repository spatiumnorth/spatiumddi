"""Resolve DNS query-log client addresses to host names (#4249).

Opt-in per request (``resolve_clients`` on ``POST /logs/dns-queries`` and the
Copilot's DNS query-log tools). The distinct client IPs of ONE page of rows
are resolved in a single batch, from one of two sources:

* ``ptr``  — (REST route only, via ``client_names_ptr``; non-public client addresses only) a PTR lookup through the resolvers the platform already uses for
  reverse-DNS population (#41: ``PlatformSettings.reverse_dns_resolvers``, or
  the worker's system resolvers when none are set). No new outbound host.
  Results, including misses, are cached per address for a few minutes so a
  refreshing log does not re-query.
* ``ipam`` — the host name of the address in ONE chosen IP space. Choosing
  the space matters because overlapping spaces reuse addresses. Only rows the
  caller may read (``read`` on ``ip_address``, per row, so scoped grants
  hold) are used; anything else stays unresolved.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Awaitable, Callable, Iterable
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import user_has_permission
from app.models.auth import User
from app.models.ipam import IPAddress, IPSpace, Subnet

ResolveMode = Literal["none", "ptr", "ipam"]
NameSource = Literal["ptr", "ipam"]

# Live reverse DNS is injected by the one caller allowed to send it (the REST
# route, see ``client_names_ptr``). This module never imports a resolver, so
# the Copilot tools that share it cannot reach the network.
PtrBatch = Callable[[AsyncSession, list[str]], Awaitable[dict[str, str]]]


class ClientNameError(Exception):
    """A request the caller must fix (maps to 422)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _distinct_ips(ips: Iterable[str | None]) -> list[str]:
    out: dict[str, None] = {}
    for ip in ips:
        if not ip:
            continue
        try:
            out[str(ipaddress.ip_address(ip))] = None
        except ValueError:
            continue
    return list(out)


async def _resolve_ipam_batch(
    db: AsyncSession, user: User, ips: list[str], space_id: uuid.UUID
) -> dict[str, str]:
    stmt = (
        select(IPAddress.id, IPAddress.address, IPAddress.hostname)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .where(
            Subnet.space_id == space_id,
            IPAddress.hostname.is_not(None),
            IPAddress.hostname != "",
            func.host(IPAddress.address).in_(ips),
        )
        .order_by(IPAddress.created_at.asc())
    )
    found: dict[str, str] = {}
    for row_id, address, hostname in (await db.execute(stmt)).all():
        key = str(ipaddress.ip_address(str(address).split("/")[0]))
        if key in found or not hostname:
            continue
        if user_has_permission(user, "read", "ip_address", row_id):
            found[key] = hostname
    return found


async def resolve_client_names(
    db: AsyncSession,
    user: User,
    client_ips: Iterable[str | None],
    mode: ResolveMode,
    ip_space_id: uuid.UUID | None,
    ptr_batch: PtrBatch | None = None,
) -> dict[str, tuple[str, NameSource]]:
    """Map each resolvable client IP (normalised text) to ``(name, source)``."""
    if mode == "none":
        return {}
    if mode == "ipam":
        if ip_space_id is None:
            raise ClientNameError("ip_space_id is required when resolve_clients is 'ipam'")
        if await db.get(IPSpace, ip_space_id) is None:
            raise ClientNameError("IP space not found")
    ips = _distinct_ips(client_ips)
    if mode == "ptr":
        if ptr_batch is None:
            raise ClientNameError("reverse DNS is not available here; use an IP space")
        # Live PTR only for non-public clients (RFC 1918, 6598, ULA, loopback,
        # link-local, ...): a log full of internet clients (an open resolver)
        # must not become outbound lookups of public addresses.
        ips = [ip for ip in ips if not ipaddress.ip_address(ip).is_global]
    if not ips:
        return {}
    if mode == "ptr":
        assert ptr_batch is not None  # checked above
        resolved = await ptr_batch(db, ips)
        return {ip: (n, "ptr") for ip, n in resolved.items()}
    names = await _resolve_ipam_batch(db, user, ips, ip_space_id)  # type: ignore[arg-type]
    return {ip: (n, "ipam") for ip, n in names.items()}


def lookup(
    names: dict[str, tuple[str, NameSource]], client_ip: str | None
) -> tuple[str | None, NameSource | None]:
    if not client_ip:
        return None, None
    try:
        key = str(ipaddress.ip_address(client_ip))
    except ValueError:
        return None, None
    hit = names.get(key)
    return (hit[0], hit[1]) if hit else (None, None)


def name_fields(
    names: dict[str, tuple[str, NameSource]], client_ip: str | None
) -> dict[str, str | None]:
    """The ``client_name`` / ``client_name_source`` pair for one row."""
    name, source = lookup(names, client_ip)
    return {"client_name": name, "client_name_source": source}

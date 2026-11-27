"""DISCOVER-rate readings from the DHCP agent's DISCOVER watch (#4737).

The agent (opt-in, ``DHCP_DISCOVER_WATCH_ENABLED=1``) counts DHCPDISCOVERs per
client MAC and per relay in a fixed window and posts the sources above a floor
to ``POST /dhcp/agents/discover-rates``. This module stores the latest reading
per source (:func:`record_rates`), resolves each to the scope it would drain
(:func:`resolve_scope`), and lists them for the REST read, the MCP tool and the
``dhcp_discover_flood`` alert (:func:`list_readings`) so the three cannot
disagree.

A reading is the present, not a history: the next window replaces it, and a
reading whose window ended more than :data:`FRESH_SECONDS` ago is no longer
evidence of anything, so every reader ignores it.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPDiscoverRate, DHCPPool, DHCPScope, DHCPServer
from app.models.ipam import Subnet
from app.services.dhcp.normalize import norm_mac

KIND_MAC = "mac"
KIND_RELAY = "relay"

#: A reading older than this is stale. Four times the agent's 60 s window, so a
#: shipper that missed a push or two does not close an open alert.
FRESH_SECONDS = 300

#: Readings this old are deleted on the next ingest for the same server.
RETAIN = timedelta(hours=24)


def mac_text(raw: str) -> str | None:
    """``aa:bb:cc:dd:ee:ff`` from any separator form; ``None`` if not a MAC."""
    bare = norm_mac(raw)
    if len(bare) != 12:
        return None
    return ":".join(bare[i : i + 2] for i in range(0, 12, 2))


@dataclass
class ClientReading:
    mac: str
    discovers: int
    giaddr: str | None = None


@dataclass
class RelayReading:
    giaddr: str
    discovers: int
    distinct_macs: int


async def record_rates(
    db: AsyncSession,
    server: DHCPServer,
    *,
    window_seconds: int,
    window_end: datetime,
    clients: list[ClientReading],
    relays: list[RelayReading],
) -> dict[str, int]:
    """Upsert one window's readings for ``server``; returns per-kind counts."""
    rows: dict[tuple[str, str], dict[str, object]] = {}
    skipped = 0
    for c in clients:
        mac = mac_text(c.mac)
        if mac is None:
            skipped += 1
            continue
        rows[(KIND_MAC, mac)] = {
            "kind": KIND_MAC,
            "subject": mac,
            "giaddr": c.giaddr,
            "discovers": c.discovers,
            "distinct_macs": None,
        }
    for r in relays:
        rows[(KIND_RELAY, r.giaddr)] = {
            "kind": KIND_RELAY,
            "subject": r.giaddr,
            "giaddr": r.giaddr,
            "discovers": r.discovers,
            "distinct_macs": r.distinct_macs,
        }
    for values in rows.values():
        stmt = pg_insert(DHCPDiscoverRate).values(
            id=uuid.uuid4(),
            server_id=server.id,
            window_seconds=window_seconds,
            window_end=window_end,
            **values,
        )
        await db.execute(
            stmt.on_conflict_do_update(
                constraint="uq_dhcp_discover_rate_subject",
                set_={
                    "giaddr": stmt.excluded.giaddr,
                    "discovers": stmt.excluded.discovers,
                    "distinct_macs": stmt.excluded.distinct_macs,
                    "window_seconds": stmt.excluded.window_seconds,
                    "window_end": stmt.excluded.window_end,
                },
                # A replayed older window must not overwrite a newer reading.
                where=DHCPDiscoverRate.window_end <= stmt.excluded.window_end,
            )
        )
    await db.execute(
        delete(DHCPDiscoverRate).where(
            DHCPDiscoverRate.server_id == server.id,
            DHCPDiscoverRate.window_end < datetime.now(UTC) - RETAIN,
        )
    )
    return {
        "clients": sum(1 for k, _ in rows if k == KIND_MAC),
        "relays": sum(1 for k, _ in rows if k == KIND_RELAY),
        "skipped": skipped,
    }


@dataclass
class ScopeMatch:
    """Where a reading lands.

    ``state`` is ``live`` (a live scope with at least one live dynamic pool,
    ``scope`` / ``subnet`` set), ``unresolved`` (nothing to attribute it to --
    a direct broadcast, or a relay outside every scope; still a finding, it
    belongs to the server), or ``inert`` (it resolves to a scope in the Trash,
    or to one with no live dynamic pool: nothing there to exhaust, so no
    finding).
    """

    state: str
    scope: DHCPScope | None = None
    subnet: Subnet | None = None


@dataclass
class Reading:
    rate: DHCPDiscoverRate
    server: DHCPServer
    match: ScopeMatch

    @property
    def per_minute(self) -> float:
        return self.rate.discovers * 60.0 / max(1, self.rate.window_seconds)


async def resolve_scope(db: AsyncSession, server: DHCPServer, giaddr: str | None) -> ScopeMatch:
    """The scope of ``server``'s group whose subnet holds ``giaddr``.

    Trashed rows are looked at on purpose (``include_deleted``): a relay that
    falls only inside a scope in the Trash must come back ``inert``, not
    ``unresolved``, or trashing the scope would move its alert to the server
    instead of closing it.
    """
    if not giaddr or server.server_group_id is None:
        return ScopeMatch("unresolved")
    try:
        addr = ipaddress.ip_address(str(giaddr))
    except ValueError:
        return ScopeMatch("unresolved")
    if addr.is_unspecified:
        return ScopeMatch("unresolved")
    rows = (
        await db.execute(
            select(DHCPScope, Subnet)
            .join(Subnet, Subnet.id == DHCPScope.subnet_id)
            .where(DHCPScope.group_id == server.server_group_id)
            .execution_options(include_deleted=True)
        )
    ).all()
    best: tuple[int, DHCPScope, Subnet] | None = None
    for scope, subnet in rows:
        try:
            net = ipaddress.ip_network(str(subnet.network), strict=False)
        except ValueError:
            continue
        if addr.version != net.version or addr not in net:
            continue
        # A live scope beats a trashed one over the same range; then the more
        # specific network wins.
        live = scope.deleted_at is None and subnet.deleted_at is None
        key = (1 if live else 0) * 1000 + net.prefixlen
        if best is None or key > best[0]:
            best = (key, scope, subnet)
    if best is None:
        return ScopeMatch("unresolved")
    _, scope, subnet = best
    if scope.deleted_at is not None or subnet.deleted_at is not None:
        return ScopeMatch("inert", scope, subnet)
    has_pool = await db.scalar(
        select(DHCPPool.id)
        .where(DHCPPool.scope_id == scope.id, DHCPPool.pool_type == "dynamic")
        .limit(1)
    )
    if has_pool is None:
        return ScopeMatch("inert", scope, subnet)
    return ScopeMatch("live", scope, subnet)


async def list_readings(
    db: AsyncSession,
    *,
    kind: str | None = None,
    server_id: uuid.UUID | None = None,
    min_per_minute: float = 0.0,
) -> list[Reading]:
    """Fresh readings at or above ``min_per_minute``, highest rate first.

    Inert readings (Trash, no live dynamic pool) are left out. ``DHCPServer``
    rows are hard-deleted, and the foreign key cascades their readings with
    them.
    """
    since = datetime.now(UTC) - timedelta(seconds=FRESH_SECONDS)
    stmt = (
        select(DHCPDiscoverRate, DHCPServer)
        .join(DHCPServer, DHCPServer.id == DHCPDiscoverRate.server_id)
        .where(DHCPDiscoverRate.window_end >= since)
    )
    if kind is not None:
        stmt = stmt.where(DHCPDiscoverRate.kind == kind)
    if server_id is not None:
        stmt = stmt.where(DHCPDiscoverRate.server_id == server_id)
    out: list[Reading] = []
    for rate, server in (await db.execute(stmt)).all():
        reading = Reading(rate, server, ScopeMatch("unresolved"))
        if kind == KIND_MAC or (kind is None and rate.kind == KIND_MAC):
            if reading.per_minute < min_per_minute:
                continue
        reading.match = await resolve_scope(db, server, str(rate.giaddr) if rate.giaddr else None)
        if reading.match.state == "inert":
            continue
        out.append(reading)
    out.sort(key=lambda r: r.per_minute, reverse=True)
    return out


def source_dict(reading: Reading) -> dict[str, Any]:
    """The wire shape the REST read and the MCP tool both return."""
    rate = reading.rate
    return {
        "kind": rate.kind,
        "subject": rate.subject,
        "giaddr": str(rate.giaddr) if rate.giaddr else None,
        "discovers": rate.discovers,
        "per_minute": round(reading.per_minute, 1),
        "distinct_macs": rate.distinct_macs,
        "window_seconds": rate.window_seconds,
        "window_end": rate.window_end,
        "subnet": str(reading.match.subnet.network) if reading.match.subnet else None,
        "scope_name": reading.match.scope.name if reading.match.scope else None,
    }

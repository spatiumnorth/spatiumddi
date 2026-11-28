"""Batch device-presence lookup by MAC (#2147).

"Are these devices on the network right now?" for a presence consumer (Home
Assistant ``device_tracker``, an automation, a script) that polls a fixed set
of MACs. One call, one row per requested MAC.

**Presence rule.** A lease alone is not presence: it lingers for its whole
lifetime after the device leaves. ``present`` is true only when the MAC has an
*active, unexpired* lease **and** the freshest activity signal for it is within
``window_seconds``. The signals, freshest wins:

* ``dhcp``  — the lease's own ``last_seen_at`` (agent / pull report) and a
  ``dhcp`` stamp on an IPAM row;
* ``arp`` / ``ping`` / ``snmp`` — ``IPAddress.last_seen_at`` /
  ``last_seen_method`` for an address carrying the MAC, and ``ip_mac_history``
  sightings (``l2_sniff`` -> ``arp``, ``sweep`` -> ``ping``).

``manual`` stamps are an operator's edit, not activity, and are ignored.

**Permission scoping (non-negotiable #3).** Every row is attributed to a
subnet and only counted if the caller may ``read`` that subnet; a lease with
no scope (hence no subnet) needs the unscoped ``read`` on ``subnet``. A MAC
whose only evidence sits outside the caller's grants comes back exactly like an
unknown MAC — never a different shape that would confirm it exists.

**Trash.** Leases are joined through scope -> subnet -> space and addresses
through subnet -> space, so anything under a trashed scope, subnet or space is
never reported (the soft-delete hook filters the joined entities; ``IPAddress``
and ``DHCPLease`` carry no ``deleted_at`` of their own). Restore brings it back
with no action here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import null, or_, select

from app.core.mac import canonicalize_mac
from app.core.permissions import is_effective_superadmin, user_has_permission
from app.drivers.dhcp.registry import is_agentless
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer
from app.models.ipam import IPAddress, IpMacHistory, IPSpace, Subnet
from app.models.settings import PlatformSettings
from app.services.ipam.new_device import is_locally_administered

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.auth import User

MAX_MACS = 500
DEFAULT_WINDOW_SECONDS = 600
MAX_WINDOW_SECONDS = 86400

# ip_mac_history.source -> the signal vocabulary the API exposes.
_HISTORY_SOURCE = {"sweep": "ping", "snmp": "snmp", "dhcp_lease": "dhcp", "l2_sniff": "arp"}
_ADDRESS_METHODS = frozenset({"ping", "arp", "dhcp", "snmp"})


@dataclass
class LeaseHit:
    ip: str
    scope_id: uuid.UUID | None
    subnet_id: uuid.UUID | None
    hostname: str | None
    lease_expires_at: datetime | None
    last_seen_at: datetime
    polled: bool


@dataclass
class PresenceResult:
    mac: str
    randomized: bool
    leases: list[LeaseHit] = field(default_factory=list)
    last_seen_at: datetime | None = None
    source: str | None = None

    def observe(self, at: datetime | None, source: str) -> None:
        if at is not None and (self.last_seen_at is None or at > self.last_seen_at):
            self.last_seen_at = at
            self.source = source


def _ip_str(value: object) -> str:
    return str(value).split("/", 1)[0]


def normalise_macs(raw: list[str]) -> tuple[list[str], list[str]]:
    """``(unique canonical MACs in first-seen order, the entries that failed)``."""
    seen: dict[str, None] = {}
    bad: list[str] = []
    for item in raw:
        try:
            seen.setdefault(canonicalize_mac(item), None)
        except ValueError:
            bad.append(item)
    return list(seen), bad


async def lookup_presence(
    db: AsyncSession,
    user: User,
    macs: list[str],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    *,
    now: datetime | None = None,
) -> list[tuple[PresenceResult, bool, int | None]]:
    """Resolve ``macs`` (already canonical + unique) to presence rows.

    Returns ``(result, present, freshness_s)`` per MAC, in input order.
    """
    now = now or datetime.now(UTC)
    results = {m: PresenceResult(mac=m, randomized=is_locally_administered(m)) for m in macs}
    if not macs:
        return []

    superadmin = is_effective_superadmin(user)
    cache: dict[uuid.UUID, bool] = {}

    def can_read(subnet_id: uuid.UUID | None) -> bool:
        if subnet_id is None:
            return superadmin or user_has_permission(user, "read", "subnet")
        if superadmin:
            return True
        if subnet_id not in cache:
            cache[subnet_id] = user_has_permission(user, "read", "subnet", subnet_id)
        return cache[subnet_id]

    # ── DHCP leases: scoped ones through scope -> subnet -> space (all three
    # soft-delete filtered), then scope-less ones. Never an outer join: a
    # trashed scope would read as "no scope" and slip past the filter.
    live = or_(DHCPLease.ends_at.is_(None), DHCPLease.ends_at > now)
    scoped_stmt = (
        select(DHCPLease, DHCPScope.subnet_id, DHCPServer.driver)
        .join(DHCPServer, DHCPServer.id == DHCPLease.server_id)
        .join(DHCPScope, DHCPScope.id == DHCPLease.scope_id)
        .join(Subnet, Subnet.id == DHCPScope.subnet_id)
        .join(IPSpace, IPSpace.id == Subnet.space_id)
        .where(DHCPLease.mac_address.in_(macs), DHCPLease.state == "active", live)
    )
    unscoped_stmt = (
        select(DHCPLease, null().label("subnet_id"), DHCPServer.driver)
        .join(DHCPServer, DHCPServer.id == DHCPLease.server_id)
        .where(
            DHCPLease.mac_address.in_(macs),
            DHCPLease.state == "active",
            live,
            DHCPLease.scope_id.is_(None),
        )
    )
    lease_rows: list[Any] = list((await db.execute(scoped_stmt)).all())
    if can_read(None):
        lease_rows += list((await db.execute(unscoped_stmt)).all())
    for lease, subnet_id, driver in lease_rows:
        if not can_read(subnet_id):
            continue
        res = results[str(lease.mac_address).lower()]
        res.leases.append(
            LeaseHit(
                ip=_ip_str(lease.ip_address),
                scope_id=lease.scope_id,
                subnet_id=subnet_id,
                hostname=lease.hostname,
                lease_expires_at=lease.ends_at,
                last_seen_at=lease.last_seen_at,
                polled=is_agentless(driver),
            )
        )
        res.observe(lease.last_seen_at, "dhcp")

    # ── IPAM addresses carrying the MAC.
    addr_stmt = (
        select(IPAddress.mac_address, IPAddress.last_seen_at, IPAddress.last_seen_method)
        .add_columns(IPAddress.subnet_id)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .join(IPSpace, IPSpace.id == Subnet.space_id)
        .where(IPAddress.mac_address.in_(macs), IPAddress.last_seen_at.is_not(None))
    )
    for mac, seen, method, subnet_id in (await db.execute(addr_stmt)).all():
        if method in _ADDRESS_METHODS and can_read(subnet_id):
            results[str(mac).lower()].observe(seen, method)

    # ── ip_mac_history sightings.
    hist_stmt = (
        select(IpMacHistory.mac_address, IpMacHistory.last_seen, IpMacHistory.source)
        .add_columns(IPAddress.subnet_id)
        .join(IPAddress, IPAddress.id == IpMacHistory.ip_address_id)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .join(IPSpace, IPSpace.id == Subnet.space_id)
        .where(IpMacHistory.mac_address.in_(macs))
    )
    for mac, seen, source, subnet_id in (await db.execute(hist_stmt)).all():
        signal = _HISTORY_SOURCE.get(source)
        if signal is not None and can_read(subnet_id):
            results[str(mac).lower()].observe(seen, signal)

    # Windows DHCP (agentless) leases arrive by polling, so their state can lag
    # by one poll interval; say so rather than let a consumer assume real time.
    poll_s: int | None = None
    if any(h.polled for r in results.values() for h in r.leases):
        ps = await db.get(PlatformSettings, 1)
        poll_s = max(10, ps.dhcp_pull_leases_interval_seconds) if ps is not None else None

    cutoff = now - timedelta(seconds=window_seconds)
    out: list[tuple[PresenceResult, bool, int | None]] = []
    for m in macs:
        r = results[m]
        r.leases.sort(key=lambda h: h.last_seen_at, reverse=True)
        present = bool(r.leases) and r.last_seen_at is not None and r.last_seen_at >= cutoff
        out.append((r, present, poll_s if any(h.polled for h in r.leases) else None))
    return out


# ── Wire schemas — shared by the REST route and the MCP tool so the two
# cannot drift.


class PresenceRequest(BaseModel):
    macs: list[str] = Field(
        ...,
        max_length=MAX_MACS,
        description=(
            f"Up to {MAX_MACS} MAC addresses, any common separator form "
            "(aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff, bare hex). Duplicates collapse."
        ),
    )
    window_seconds: int = Field(
        DEFAULT_WINDOW_SECONDS,
        ge=30,
        le=MAX_WINDOW_SECONDS,
        description="A device is present only if it was seen within this many seconds.",
    )

    @field_validator("macs")
    @classmethod
    def _macs_well_formed(cls, v: list[str]) -> list[str]:
        _, bad = normalise_macs(v)
        if bad:
            raise ValueError("not a valid MAC address: " + ", ".join(repr(b) for b in bad))
        return v


class PresenceLease(BaseModel):
    ip: str
    scope_id: uuid.UUID | None
    subnet_id: uuid.UUID | None
    hostname: str | None
    lease_expires_at: datetime | None
    last_seen_at: datetime


class PresenceItem(BaseModel):
    mac: str = Field(description="Canonical lowercase colon form.")
    present: bool
    randomized: bool = Field(
        description="Locally-administered bit set: a privacy-randomised MAC that may rotate."
    )
    ip: str | None = Field(description="Address of the most recently seen active lease.")
    hostname: str | None
    last_seen_at: datetime | None = Field(
        description="Freshest activity signal across the caller's readable subnets."
    )
    source: str | None = Field(description="Signal behind last_seen_at: dhcp | arp | ping | snmp.")
    lease_expires_at: datetime | None
    leases: list[PresenceLease] = Field(description="Every active lease, newest-seen first.")
    freshness_s: int | None = Field(
        description=(
            "Set when an active lease comes from a polled (Windows DHCP) server: its state "
            "may lag by up to this many seconds. Null for agent-reported leases."
        )
    )


class PresenceResponse(BaseModel):
    window_seconds: int
    items: list[PresenceItem]


def build_item(r: PresenceResult, present: bool, freshness_s: int | None) -> PresenceItem:
    top = r.leases[0] if r.leases else None
    return PresenceItem(
        mac=r.mac,
        present=present,
        randomized=r.randomized,
        ip=top.ip if top else None,
        hostname=top.hostname if top else None,
        last_seen_at=r.last_seen_at,
        source=r.source,
        lease_expires_at=top.lease_expires_at if top else None,
        leases=[
            PresenceLease(
                ip=h.ip,
                scope_id=h.scope_id,
                subnet_id=h.subnet_id,
                hostname=h.hostname,
                lease_expires_at=h.lease_expires_at,
                last_seen_at=h.last_seen_at,
            )
            for h in r.leases
        ],
        freshness_s=freshness_s,
    )


async def presence_for(db: AsyncSession, user: User, req: PresenceRequest) -> PresenceResponse:
    macs, _ = normalise_macs(req.macs)
    rows = await lookup_presence(db, user, macs, req.window_seconds)
    return PresenceResponse(
        window_seconds=req.window_seconds,
        items=[build_item(*row) for row in rows],
    )

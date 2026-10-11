"""Which appliance owns a DNS / DHCP server row (#1715, #1749).

Agents register with ``host`` = the node's hostname and never set
``appliance_id``, so the FK alone finds nothing on a real appliance. Both
directions of the lookup therefore share one rule:

  * the FK, when set; otherwise
  * an agent-based row (``agent_id`` set, ``appliance_id`` NULL) whose
    normalised host equals the normalised hostname of exactly ONE approved
    appliance. Two approved appliances sharing a hostname disable the match
    — a hostname is only a safe claim when it can't be someone else's.

Fleet goes appliance -> servers (``own_server_condition``); the DNS and
DHCP server moves go server -> appliance (``owning_appliance_for_dns_server``
/ ``owning_appliance_for_dhcp_server``).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func as sa_func
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance

# Engine role -> the dns_server.driver its agent registers with.
DNS_ROLE_DRIVER = {
    "dns-bind9": "bind9",
    "dns-powerdns": "powerdns",
    "dns-technitium": "technitium",
}


def norm_host(value: str) -> str:
    """A hostname as compared for ownership: case-folded, trailing root dot
    dropped. Both sides come from the node's kernel nodename, so they agree
    in practice; this only absorbs the spellings a hand edit or a k8s node
    name (always lowercase) can introduce."""
    return value.strip().rstrip(".").lower()


async def hostname_is_unambiguous(db: AsyncSession, appliance: Appliance) -> bool:
    """True when no OTHER approved appliance shares this one's hostname
    (case-insensitively)."""
    others = (
        await db.execute(
            select(Appliance.hostname).where(
                Appliance.id != appliance.id,
                Appliance.state == APPLIANCE_STATE_APPROVED,
            )
        )
    ).scalars()
    mine = norm_host(appliance.hostname or "")
    return bool(mine) and all(norm_host(h or "") != mine for h in others)


async def own_server_condition(db: AsyncSession, appliance: Appliance, model: Any) -> Any:
    """SQL condition selecting ``model`` (DNSServer / DHCPServer) rows that
    belong to ``appliance``: the FK, or the unambiguous hostname match on an
    agent-based row not owned by another appliance."""
    conds = [model.appliance_id == appliance.id]
    if await hostname_is_unambiguous(db, appliance):
        conds.append(
            (
                sa_func.lower(sa_func.rtrim(sa_func.trim(model.host), "."))
                == norm_host(appliance.hostname)
            )
            & model.appliance_id.is_(None)
            & model.agent_id.is_not(None)
        )
    return or_(*conds)


def current_dns_drivers(appliance: Appliance) -> set[str]:
    return {DNS_ROLE_DRIVER[r] for r in (appliance.assigned_roles or []) if r in DNS_ROLE_DRIVER}


async def _unique_approved_by_hostname(db: AsyncSession, server: Any) -> Appliance | None:
    """The one approved appliance whose normalised hostname equals an
    agent-based, appliance_id-less ``server``'s normalised host — the
    reverse of ``own_server_condition``'s hostname branch. None when the
    row is not agent-based, or zero or several approved appliances match."""
    if server.agent_id is None or not server.host:
        return None
    host = norm_host(server.host)
    if not host:
        return None
    matches = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    sa_func.lower(sa_func.rtrim(sa_func.trim(Appliance.hostname), ".")) == host,
                )
            )
        )
        .scalars()
        .all()
    )
    return matches[0] if len(matches) == 1 else None


async def owning_appliance_for_dns_server(db: AsyncSession, server: Any) -> Appliance | None:
    """The appliance that owns ``server`` (a DNSServer), or None.

    The FK wins. Otherwise the hostname match, which is only trusted for an
    agent-based row of the appliance's CURRENT DNS engine: an engine switch
    leaves the old engine's row behind, and that row is not what the
    appliance's ``assigned_dns_group_id`` / AGENT_GROUP drive, so moving it
    must not repoint the appliance.
    """
    if server.appliance_id is not None:
        return await db.get(Appliance, server.appliance_id)
    appliance = await _unique_approved_by_hostname(db, server)
    if appliance is None or server.driver not in current_dns_drivers(appliance):
        return None
    return appliance


async def owning_appliance_for_dhcp_server(db: AsyncSession, server: Any) -> Appliance | None:
    """The appliance that owns ``server`` (a DHCPServer), or None.

    Same rule as the DNS lookup. DHCP has one engine (Kea), so "current
    engine" reduces to the appliance holding the ``dhcp`` role: a row it
    no longer runs an agent for is not what ``assigned_dhcp_group_id``
    drives.
    """
    if server.appliance_id is not None:
        return await db.get(Appliance, server.appliance_id)
    appliance = await _unique_approved_by_hostname(db, server)
    if appliance is None or "dhcp" not in (appliance.assigned_roles or []):
        return None
    return appliance

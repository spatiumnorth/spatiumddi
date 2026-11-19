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

from sqlalchemy import and_, exists, or_, select
from sqlalchemy import func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

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


def k8s_node_name(hostname: str | None) -> str:
    """The k8s Node name (and etcd-member prefix) k3s gives a host called
    ``hostname`` (#1757). k3s lowercases the hostname to satisfy RFC 1123
    (``pkg/util/net.go`` ``GetHostnameAndIPs``) and names the etcd member
    ``<node name>-<8 hex>``, but the installer accepts an uppercase hostname and
    ``Appliance.hostname`` stores it as typed. Every lookup of a Node, or of
    an appliance by Node name, goes through this so the two spellings meet."""
    return norm_host(hostname or "")


def hostname_sql(column: Any) -> Any:
    """SQL form of :func:`norm_host` for ``column`` (trim, drop the trailing
    dot, lowercase) — compare it with a :func:`norm_host`-ed value."""
    return sa_func.lower(sa_func.rtrim(sa_func.trim(column), "."))


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
    agent-based row not owned by another appliance.

    The hostname branch is for an APPROVED appliance only (#1810): a
    pending or revoked one (a stale duplicate, a re-paired box's old entry)
    never ran an agent under that identity, so a row merely sharing its
    hostname is not provably its own — deleting it must not take the live
    appliance's servers with it."""
    conds = [model.appliance_id == appliance.id]
    approved = appliance.state == APPLIANCE_STATE_APPROVED
    if approved and await hostname_is_unambiguous(db, appliance):
        conds.append(
            (
                sa_func.lower(sa_func.rtrim(sa_func.trim(model.host), "."))
                == norm_host(appliance.hostname)
            )
            & model.appliance_id.is_(None)
            & model.agent_id.is_not(None)
        )
    return or_(*conds)


def orchestrated_server_condition(model: Any) -> Any:
    """SQL condition selecting ``model`` (DNSServer / DHCPServer) rows that run
    on a node the rolling-upgrade orchestrator slot-swaps (#2179).

    That is an APPROVED appliance whose supervisor reports
    ``deployment_kind = 'appliance'`` — the same set every appliance-scoped
    upgrade preflight reads — owning the row by the FK, or by the agent's
    reported ``host`` against the appliance's hostname (the hostname branch of
    :func:`own_server_condition`, for an agent-based row with no FK).

    It deliberately does NOT read the server row's own ``deployment_kind`` as
    the primary signal: #170 Wave C1 moved deployment telemetry onto the
    supervisor's heartbeat, so neither the DNS nor the DHCP agent sends it and
    the column is NULL on every post-#170 appliance. A filter on it alone
    matches nothing. It stays in the OR for an agent that still reports it.

    Unlike :func:`own_server_condition` this answers "is it on SOME
    orchestrated appliance", not "which one", so two appliances sharing a
    hostname do not disable the match — either way the row is on a node this
    run will touch.
    """
    a = aliased(Appliance)
    owned = exists().where(
        a.state == APPLIANCE_STATE_APPROVED,
        a.deployment_kind == "appliance",
        or_(
            a.id == model.appliance_id,
            and_(
                model.appliance_id.is_(None),
                model.agent_id.is_not(None),
                hostname_sql(a.hostname) == hostname_sql(model.host),
            ),
        ),
    )
    return or_(owned, model.deployment_kind == "appliance")


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


async def owning_appliance_for_dns_agent(
    db: AsyncSession, hostname: str, driver: str
) -> Appliance | None:
    """The appliance a REGISTERING DNS agent runs on, or None (#2190).

    The same rule as :func:`owning_appliance_for_dns_server`'s hostname branch,
    applied before a row exists: one approved appliance whose normalised
    hostname is the agent's, running ``driver`` as its current DNS engine.
    The bootstrap key is platform-wide, so the hostname is the agent's only
    claim to an appliance; a hostname two approved appliances share, or an
    engine the appliance no longer runs, claims nothing.
    """
    host = norm_host(hostname or "")
    if not host:
        return None
    matches = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    hostname_sql(Appliance.hostname) == host,
                )
            )
        )
        .scalars()
        .all()
    )
    if len(matches) != 1 or driver not in current_dns_drivers(matches[0]):
        return None
    return matches[0]


async def owning_appliance_for_dhcp_agent(db: AsyncSession, hostname: str) -> Appliance | None:
    """The appliance a REGISTERING Kea agent runs on, or None (#3202).

    :func:`owning_appliance_for_dns_agent`'s rule with DHCP's one engine: one
    approved appliance whose normalised hostname is the agent's and that holds
    the ``dhcp`` role. The bootstrap key is platform-wide, so the hostname is
    the agent's only claim to an appliance; a hostname two approved appliances
    share, or an appliance that no longer holds the role, claims nothing.
    """
    host = norm_host(hostname or "")
    if not host:
        return None
    matches = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    hostname_sql(Appliance.hostname) == host,
                )
            )
        )
        .scalars()
        .all()
    )
    if len(matches) != 1 or "dhcp" not in (matches[0].assigned_roles or []):
        return None
    return matches[0]


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

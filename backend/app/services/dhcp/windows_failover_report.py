"""Read-side views over the Windows failover observations (#1110).

Built from what the topology poll stored — never a live WinRM call, so a
page load or a copilot question cannot stall on an unreachable server. Two
shapes:

* ``group_failover_report`` — a group's Windows members (and whether their
  views are current), the failover relationships they report, merged across
  the two partners, and how every scope any member holds is served.
* ``scope_serving_report`` — the same verdict for one managed scope, with a
  row per Windows member.

Both return plain JSON-able dicts: the REST routes validate them into
response models, the MCP tool hands them to the copilot as they are.

A member whose last scope enumeration is older than
``OBSERVATION_FRESH_FOR`` still contributes what it last reported, marked
``stale``. For display that is the conservative choice — hiding a stale
holder could hide the very dual-serve an operator needs to see — and it is
the opposite of the reconciler's choice for the same data, which drops a
stale view so an unreachable server cannot freeze a scope's import.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import Subnet
from app.services.dhcp.windows_failover import (
    GroupObservations,
    Holder,
    ScopeServing,
    canonical_cidr,
    classify_serving,
    is_fresh,
    load_group_observations,
    partner_member,
    relationship_dict,
)


def _member_status(obs: GroupObservations, now: datetime) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for member in obs.members:
        server = obs.servers[member.server_id]
        out.append(
            {
                "server_id": server.id,
                "server_name": server.name,
                "host": server.host,
                "scopes_observed_at": server.scopes_observed_at,
                "failover_observed_at": server.failover_observed_at,
                "failover_error": server.failover_error,
                "fresh": is_fresh(server.scopes_observed_at, now),
                "relationship_count": len(obs.relationships.get(server.id, [])),
            }
        )
    return out


def _relationships(obs: GroupObservations) -> list[dict[str, Any]]:
    """Merge each relationship's per-server observations into one entry.

    Both partners report a relationship under the same name, so the name is
    the join key; the per-side values (role, state, this side's load-balance
    percentage) stay per side. A name only one member reports is a
    relationship whose partner is outside the group — or inside it but not
    reporting it, which the partner lookup tells apart.
    """
    by_name: dict[str, list[tuple[Any, Any]]] = {}
    for member in obs.members:
        for rel in obs.relationships.get(member.server_id, []):
            by_name.setdefault(rel.name, []).append((member, rel))
    out: list[dict[str, Any]] = []
    for name in sorted(by_name):
        sides = by_name[name]
        first = sides[0][1]
        scope_ids: list[str] = []
        side_rows: list[dict[str, Any]] = []
        for member, rel in sides:
            for sid in rel.scope_ids or []:
                if sid not in scope_ids:
                    scope_ids.append(sid)
            partner_id = None
            others = [m for m, _r in sides if m.server_id != member.server_id]
            if len(others) == 1:
                partner_id = others[0].server_id
            else:
                hit = partner_member(relationship_dict(rel), obs.members)
                if hit is not None and hit.server_id != member.server_id:
                    partner_id = hit.server_id
            side_rows.append(
                {
                    "server_id": member.server_id,
                    "server_name": member.name,
                    "partner_server": rel.partner_server,
                    "partner_server_id": partner_id,
                    "server_role": rel.server_role,
                    "state": rel.state,
                    "load_balance_percent": rel.load_balance_percent,
                    "reserve_percent": rel.reserve_percent,
                    "modified_at": rel.modified_at,
                }
            )
        complete = len(sides) == 2
        partner_outside = None
        if len(sides) == 1:
            member, rel = sides[0]
            hit = partner_member(relationship_dict(rel), obs.members)
            if hit is None or hit.server_id == member.server_id:
                partner_outside = rel.partner_server or None
        out.append(
            {
                "name": name,
                "mode": first.mode,
                "max_client_lead_time_seconds": first.max_client_lead_time_seconds,
                "state_switch_interval_seconds": first.state_switch_interval_seconds,
                "auto_state_transition": first.auto_state_transition,
                "enable_auth": first.enable_auth,
                "scope_ids": scope_ids,
                "sides": side_rows,
                "complete": complete,
                "partner_outside_group": partner_outside,
            }
        )
    return out


def _serving_dict(
    cidr: str,
    serving: ScopeServing,
    obs: GroupObservations,
    now: datetime,
    *,
    scope_row_id: uuid.UUID | None,
) -> dict[str, Any]:
    held = {h.member.server_id: h for h in serving.holders}
    # The member whose view the poll imports: the lowest-named FRESH holder,
    # exactly as ``windows_failover.reconcile_owner`` picks it from inside a
    # poll. None when no holder's view is current — nothing is importing it.
    fresh = obs.holders(cidr, now=now)
    owner_id = (
        min(fresh, key=lambda h: (h.member.name, str(h.member.server_id))).member.server_id
        if fresh
        else None
    )
    owner_hash = held[owner_id].config_hash if owner_id in held else None
    servers: list[dict[str, Any]] = []
    for member in obs.members:
        server = obs.servers[member.server_id]
        holder: Holder | None = held.get(member.server_id)
        observed = server.scopes_observed_at is not None
        in_sync = None
        if holder is not None and owner_hash and holder.config_hash and len(held) > 1:
            in_sync = holder.config_hash == owner_hash
        servers.append(
            {
                "server_id": server.id,
                "server_name": server.name,
                # None — this member's scopes have never been read, so whether
                # it holds the scope is unknown, not "no".
                "holds": (holder is not None) if observed else None,
                "is_active": holder.is_active if holder else None,
                "relationship_name": (holder.relationship or {}).get("name") if holder else None,
                "in_sync": in_sync,
                "observed_at": server.scopes_observed_at,
                "stale": observed and not is_fresh(server.scopes_observed_at, now),
                "reconcile_owner": holder is not None and server.id == owner_id,
            }
        )
    rel = serving.relationship
    return {
        "scope_id": scope_row_id,
        "cidr": cidr,
        "verdict": serving.verdict.value,
        "safe": serving.safe,
        "detail": serving.detail,
        "relationship_name": rel.get("name") if rel else None,
        "relationship_mode": rel.get("mode") if rel else None,
        "drift": serving.drift,
        "servers": servers,
    }


async def _managed_scopes(
    db: AsyncSession, group_id: uuid.UUID
) -> dict[str, tuple[uuid.UUID, bool]]:
    """``{canonical cidr: (dhcp_scope.id, is_active)}`` for the group's IPv4 scopes."""
    rows = (
        await db.execute(
            select(DHCPScope.id, DHCPScope.is_active, Subnet.network)
            .join(Subnet, Subnet.id == DHCPScope.subnet_id)
            .where(DHCPScope.group_id == group_id, DHCPScope.address_family == "ipv4")
        )
    ).all()
    out: dict[str, tuple[uuid.UUID, bool]] = {}
    for scope_id, is_active, network in rows:
        cidr = canonical_cidr(network)
        if cidr is not None:
            out[cidr] = (scope_id, bool(is_active))
    return out


async def _kea_members(db: AsyncSession, group_id: uuid.UUID) -> list[str]:
    return list(
        (
            await db.execute(
                select(DHCPServer.name)
                .where(DHCPServer.server_group_id == group_id, DHCPServer.driver == "kea")
                .order_by(DHCPServer.name)
            )
        )
        .scalars()
        .all()
    )


def _with_kea(row: dict[str, Any], kea: list[str], active_in_db: bool) -> dict[str, Any]:
    """A mixed group (#1110): Kea renders every ACTIVE scope of its group into
    its own config, so a scope a Windows member also holds is served by two
    systems that cannot coordinate — whatever the Windows side looks like."""
    holders = sorted(s["server_name"] for s in row["servers"] if s["holds"])
    if not kea or not holders or not active_in_db:
        return row
    return {
        **row,
        "verdict": "uncoordinated",
        "safe": False,
        "detail": (
            f"Served by Kea ({', '.join(kea)}) from this group's configuration AND by "
            f"Windows DHCP ({', '.join(holders)}). Kea's HA and Windows failover cannot "
            f"coordinate, so both can hand out the same address. Move the Windows "
            f"server(s) to their own server group."
        ),
    }


def _classify(obs: GroupObservations, cidr: str, now: datetime) -> ScopeServing:
    return classify_serving(obs.holders(cidr, now=now, fresh_only=False), obs.members)


async def group_failover_report(db: AsyncSession, group: DHCPServerGroup) -> dict[str, Any]:
    now = datetime.now(UTC)
    obs = await load_group_observations(db, group.id)
    managed = await _managed_scopes(db, group.id)
    kea = await _kea_members(db, group.id) if obs.members else []
    cidrs = set(managed)
    for per_server in obs.scopes.values():
        cidrs.update(per_server)
    scopes = []
    if obs.members:
        for cidr in sorted(cidrs, key=_cidr_sort_key):
            scope_row_id, active = managed.get(cidr, (None, False))
            row = _serving_dict(
                cidr, _classify(obs, cidr, now), obs, now, scope_row_id=scope_row_id
            )
            scopes.append(_with_kea(row, kea, active))
    return {
        "group_id": group.id,
        "windows_member_count": len(obs.members),
        "kea_members": kea,
        "members": _member_status(obs, now),
        "relationships": _relationships(obs),
        "scopes": scopes,
    }


async def scope_serving_report(db: AsyncSession, scope: DHCPScope) -> dict[str, Any]:
    now = datetime.now(UTC)
    subnet = await db.get(Subnet, scope.subnet_id)
    cidr = canonical_cidr(subnet.network) if subnet is not None else None
    obs = await load_group_observations(db, scope.group_id)
    if cidr is None or not obs.members or scope.address_family != "ipv4":
        return {
            "scope_id": scope.id,
            "cidr": cidr or "",
            "verdict": "no_windows_members",
            "safe": True,
            "detail": (
                "This group has no Windows DHCP members."
                if not obs.members
                else "Windows failover applies to IPv4 scopes only."
            ),
            "relationship_name": None,
            "relationship_mode": None,
            "drift": None,
            "servers": [],
        }
    row = _serving_dict(cidr, _classify(obs, cidr, now), obs, now, scope_row_id=scope.id)
    return _with_kea(row, await _kea_members(db, scope.group_id), bool(scope.is_active))


def _cidr_sort_key(cidr: str) -> tuple[int, int]:
    net = ipaddress.ip_network(cidr, strict=False)
    return (int(net.network_address), net.prefixlen)


__all__ = ["group_failover_report", "scope_serving_report"]

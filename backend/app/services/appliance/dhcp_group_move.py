"""Move an appliance's own DHCP (Kea) server row(s) when its DHCP group changes.

Shared by every path that points an appliance at a DHCP server group — the
Fleet roles PUT and the Operator Copilot's ``assign_appliance_role`` (#1902) —
so the answer cannot depend on which door the operator used. Setting
``assigned_dhcp_group_id`` alone moves the appliance's env and firewall to the
new group while its registered Kea row keeps serving the old one (an agent
re-registration never moves a row, by design; #1565).

The checks are the ones the DHCP server PUT applies to a group change: Kea and
Windows DHCP cannot share a group, and a Windows server cannot take a group
that holds v6 scopes. Plus one of its own: a Kea pod on an appliance node joins
the MetalLB relay VIP Service, so it cannot join a ``direct``-mode group while a
relay VIP is set (#2899). They raise ``HTTPException`` (the Fleet PUT lets it
through unchanged); the Copilot turns it into a refusal of the whole proposal.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dhcp_group_channel, dhcp_server_channel
from app.models.appliance import Appliance
from app.models.audit import AuditLog
from app.models.dhcp import DHCPServer
from app.services.appliance.ownership import own_server_condition


@dataclass
class DhcpMoveResult:
    moved: list[dict[str, Any]] = field(default_factory=list)


async def appliance_own_dhcp_servers(
    db: AsyncSession, appliance: Appliance, roles: list[str] | None = None
) -> list[DHCPServer]:
    """The appliance's agent-based (kea) dhcp_server rows (#1715).
    ``dhcp_server.name`` is globally unique and kea is the only agent engine,
    so there is no stale-engine row to retire on this side. ``roles`` overrides
    the appliance's current roles (a preview of a role change)."""
    if "dhcp" not in ((appliance.assigned_roles if roles is None else roles) or []):
        return []
    own = await own_server_condition(db, appliance, DHCPServer)
    return list(
        (await db.execute(select(DHCPServer).where(own, DHCPServer.driver == "kea")))
        .scalars()
        .all()
    )


async def move_appliance_dhcp_servers(
    db: AsyncSession,
    appliance: Appliance,
    dhcp_group: Any,
    user: Any,
    *,
    dry_run: bool = False,
    roles: list[str] | None = None,
    prev_roles: list[str] | set[str] | None = None,
) -> DhcpMoveResult:
    """Move the appliance's own Kea row(s) into ``dhcp_group`` in the caller's
    transaction, wake the agents and both groups after the caller's commit, and
    audit each move. ``dry_run`` runs the refusals only (preview).

    ``prev_roles`` is the role set before this change, for a caller that has
    already written the new one to ``appliance.assigned_roles``; with ``roles``
    (a preview) the appliance's current roles are the previous ones."""
    from app.api.v1.dhcp.servers import (  # noqa: PLC0415
        _assert_driver_mix_allowed,
        _assert_no_v6_scopes_for_windows,
    )
    from app.services.dhcp.relay_vip import appliance_join_refusal  # noqa: PLC0415

    # #2899 — before the per-server loop, which an appliance whose agent has
    # not registered yet never enters: the pointer alone puts its Kea pod
    # behind the relay VIP Service.
    # Refused on a transition only — a new group, or the dhcp role newly
    # gained — so re-saving an appliance already in that state never is.
    if prev_roles is None and roles is not None:
        prev_roles = appliance.assigned_roles or []
    gains_dhcp = prev_roles is not None and "dhcp" not in prev_roles
    if appliance.assigned_dhcp_group_id != dhcp_group.id or gains_dhcp:
        refusal = await appliance_join_refusal(db, appliance, dhcp_group, roles)
        if refusal is not None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, refusal)

    result = DhcpMoveResult()
    for dserver in await appliance_own_dhcp_servers(db, appliance, roles):
        if dserver.server_group_id == dhcp_group.id:
            continue
        await _assert_driver_mix_allowed(
            db, dhcp_group.id, dserver.driver, exclude_server_id=dserver.id
        )
        await _assert_no_v6_scopes_for_windows(db, dhcp_group.id, dserver.driver)
        if dry_run:
            continue
        old_gid: uuid.UUID | None = dserver.server_group_id
        dserver.server_group_id = dhcp_group.id
        collect_wake(dhcp_server_channel(dserver.id))
        for gid in (old_gid, dhcp_group.id):
            if gid is not None:
                collect_wake(dhcp_group_channel(gid))
        result.moved.append({"dhcp_server": str(dserver.id), "name": dserver.name})
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=user.auth_source,
                action="update",
                resource_type="dhcp_server",
                resource_id=str(dserver.id),
                resource_display=dserver.name,
                changed_fields=["server_group_id"],
                old_value={"server_group_id": str(old_gid) if old_gid else None},
                new_value={
                    "server_group_id": str(dhcp_group.id),
                    "via_appliance_id": str(appliance.id),
                },
                result="success",
            )
        )
    return result

"""Move an appliance's own DNS server row(s) when its DNS group changes.

Shared by every path that points an appliance at a DNS server group, so the
answer cannot depend on which door the operator used:

* ``PUT /appliance/appliances/{id}/roles`` (the Fleet save);
* the Operator Copilot's ``assign_appliance_role`` operation (and so the MCP
  ``propose_assign_role`` tool, which proposes it).

The appliance's pointer alone moves its env and firewall to the new group
while its registered server keeps serving the old one, because
re-registration never moves a row (#1565). So the row moves with it, through
#934's ``move_server_to_group``, in the caller's transaction; a move it
refuses refuses the whole save.

Which row is "the appliance's" depends on the engine (#1715, #1856):

* a row already carrying the current engine's driver, when there is one;
* otherwise, when the save also switches the engine, the row the new
  engine's agent will adopt. Registration finds a row by agent id with no
  group filter, else by hostname within the appliance's assigned group
  (#2190 — not the group the pod's env names, which can be a chart
  revision behind), and an
  engine-only switch lets the new engine's agent adopt the old engine's row
  by hostname — so at the moment of an engine-AND-group save the row still
  carries the OLD driver. It moves as the new engine's row: its driver is
  set first, the way registration would set it, so the target group's
  single-driver, catalog and signer checks judge the driver the server will
  actually run.

The caller assigns the new roles before calling, and commits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dns_group_channel, dns_server_channel
from app.models.appliance import Appliance
from app.models.audit import AuditLog
from app.models.dns import DNSServer, DNSServerGroup
from app.services.appliance.ownership import current_dns_drivers, own_server_condition
from app.services.dns.server_move import (
    ServerMoveError,
    lock_server_row,
    move_server_to_group,
)

logger = structlog.get_logger(__name__)


@dataclass
class ApplianceDnsMove:
    """What moving the appliance's DNS row(s) did, for the caller's audit."""

    moved: list[dict[str, Any]] = field(default_factory=list)
    retired: list[str] = field(default_factory=list)
    # No row to move: the agent will register into the target as a new
    # server, so the caller applies the second-signer refusal itself (#1762).
    registers_new_server: bool = False


async def appliance_own_dns_servers(db: AsyncSession, appliance: Appliance) -> list[DNSServer]:
    """The dns_server row(s) of the appliance's CURRENT DNS engine (#1715).

    An engine switch leaves the old engine's row behind in its old group;
    moving it would clash on name or driver in the target, so only rows of
    the current engine are returned (``retire_stale_engine_rows`` deals
    with the old one when it is in the way).
    """
    drivers = current_dns_drivers(appliance)
    if not drivers:
        return []
    own = await own_server_condition(db, appliance, DNSServer)
    return list(
        (await db.execute(select(DNSServer).where(own, DNSServer.driver.in_(sorted(drivers)))))
        .scalars()
        .all()
    )


async def appliance_adoptable_dns_server(
    db: AsyncSession, appliance: Appliance, target_group: DNSServerGroup
) -> DNSServer | None:
    """The row the new engine's agent will adopt, when none carries its driver (#1856).

    The appliance's own row of another driver, outside ``target_group``.
    ``None`` when there is none (the agent registers a new row, or adopts
    one already in the target by hostname).

    Several such rows is a refusal (409), not a pick: the new engine's agent
    goes first to the row holding ITS agent id, wherever that row stands, and
    a row's agent id stays the one that created it whatever driver it has
    since been given — so the control plane cannot tell which row the agent
    will land on. Moving the wrong one leaves the agent re-registering into
    its own row in the old group (this bug again) with a ghost in the new
    one. Only stale rows of engines the appliance no longer runs can produce
    the extra row, and the operator deleting it makes the save unambiguous.
    """
    own = await own_server_condition(db, appliance, DNSServer)
    rows = (
        await db.execute(
            select(DNSServer, DNSServerGroup.name)
            .join(DNSServerGroup, DNSServerGroup.id == DNSServer.group_id)
            .where(own, DNSServer.group_id != target_group.id)
            .order_by(DNSServerGroup.name, DNSServer.name)
        )
    ).all()
    if not rows:
        return None
    if len(rows) > 1:
        listed = ", ".join(f"{srv.name!r} ({srv.driver}) in {gname!r}" for srv, gname in rows)
        raise ServerMoveError(
            f"This appliance has {len(rows)} DNS server rows of engines it no longer "
            f"runs: {listed}. The new engine's agent adopts one of them, and which one "
            "cannot be told from here, so none is moved. Delete the stale row(s) under "
            "DNS → Server groups, then save again.",
            status_code=409,
        )
    return rows[0][0]


async def retire_stale_engine_rows(
    db: AsyncSession, appliance: Appliance, target_group: DNSServerGroup, user: Any
) -> list[str]:
    """Delete this appliance's OWN dns_server rows in ``target_group`` that
    belong to a DNS engine it no longer runs (#1715).

    An engine switch (bind9 -> technitium) registers a new row for the new
    engine and leaves the old engine's row where it was: same name (the
    hostname), old driver, no agent behind it any more — the role swap
    removes the node label, so the old engine's DaemonSet pod is gone.
    Moving the appliance back to that group then clashes with its own dead
    row on name and on driver, and the operator gets a 409 / 422 about a
    row they can't see the point of. So the dead row is retired the way the
    server DELETE does it (audit row, wakes, delete; zone state / record ops
    / metrics cascade on the FK).

    Only ever a row that is (a) this appliance's by FK or the unambiguous
    hostname match, (b) of a driver that is NOT the currently assigned
    engine, and (c) silent for longer than the agent-stale window. A row
    whose agent is still reporting — the old pod has not stopped yet, right
    after a switch — is refused with an actionable 409 instead of deleted:
    deleting a live agent's row only makes it re-register.

    Returns the retired rows' names, for the role-assignment audit row.
    """
    from app.tasks.dns import AGENT_STALE_AFTER  # noqa: PLC0415

    drivers = current_dns_drivers(appliance)
    if not drivers:
        return []
    own = await own_server_condition(db, appliance, DNSServer)
    stale = (
        (
            await db.execute(
                select(DNSServer)
                .where(
                    own,
                    DNSServer.group_id == target_group.id,
                    DNSServer.driver.not_in(sorted(drivers)),
                )
                .order_by(DNSServer.name)
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    retired: list[str] = []
    for srv in stale:
        if srv.last_seen_at is not None and now - srv.last_seen_at < AGENT_STALE_AFTER:
            raise ServerMoveError(
                f"Group {target_group.name!r} still holds this appliance's "
                f"{srv.driver} server {srv.name!r}, and its agent reported "
                f"{int((now - srv.last_seen_at).total_seconds())}s ago. "
                "It is retired automatically once it stops reporting "
                f"(about {int(AGENT_STALE_AFTER.total_seconds())}s after the "
                "engine switch) — save again then, or delete it under DNS → "
                "Server groups.",
                status_code=409,
            )
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=getattr(user, "auth_source", "local") or "local",
                action="delete",
                resource_type="dns_server",
                resource_id=str(srv.id),
                resource_display=srv.name,
                old_value={
                    "group_id": str(srv.group_id),
                    "driver": srv.driver,
                    "host": srv.host,
                    "agent_id": str(srv.agent_id) if srv.agent_id else None,
                    "last_seen_at": srv.last_seen_at.isoformat() if srv.last_seen_at else None,
                },
                new_value={
                    "reason": "retired_stale_engine_row",
                    "appliance_id": str(appliance.id),
                    "assigned_engine": sorted(drivers),
                },
                result="success",
            )
        )
        collect_wake(dns_server_channel(srv.id), dns_group_channel(srv.group_id))
        logger.info(
            "appliance_stale_dns_row_retired",
            appliance_id=str(appliance.id),
            server_id=str(srv.id),
            server_name=srv.name,
            driver=srv.driver,
            group_id=str(srv.group_id),
        )
        retired.append(srv.name)
        await db.delete(srv)
    if retired:
        # The move's name-clash / single-driver / primary checks query the
        # target group; they must not see the rows just retired.
        await db.flush()
    return retired


async def move_appliance_dns_servers(
    db: AsyncSession, appliance: Appliance, target_group: DNSServerGroup, user: Any
) -> ApplianceDnsMove:
    """Move ``appliance``'s own DNS server row(s) into ``target_group``.

    ``appliance.assigned_roles`` must already hold the roles being saved;
    the caller sets ``assigned_dns_group_id`` afterwards and commits.
    Raises ``ServerMoveError`` (with the HTTP status to answer) on a
    refusal, before the caller commits anything.
    """
    outcome = ApplianceDnsMove()
    drivers = current_dns_drivers(appliance)
    own_dns = await appliance_own_dns_servers(db, appliance)
    for srv in own_dns:
        if srv.group_id != target_group.id:
            # #1703 — strongest lock before any write to the row (see the helper).
            await lock_server_row(db, srv.id)
    old_drivers: dict[Any, str] = {}
    if not own_dns and drivers:
        adoptee = await appliance_adoptable_dns_server(db, appliance, target_group)
        if adoptee is not None:
            # #1703 — the driver write below and the move after it hit the same
            # row: lock it first, or the driver UPDATE (flushed by the next
            # SELECT) takes the weaker lock and the move deadlocks a render.
            await lock_server_row(db, adoptee.id)
            new_driver = next(iter(drivers))
            logger.info(
                "appliance_dns_row_readopted",
                appliance_id=str(appliance.id),
                server_id=str(adoptee.id),
                old_driver=adoptee.driver,
                new_driver=new_driver,
                issue="#1856",
            )
            old_drivers[adoptee.id] = adoptee.driver
            adoptee.driver = new_driver
            own_dns = [adoptee]
    if not own_dns and drivers and target_group.id != appliance.assigned_dns_group_id:
        outcome.registers_new_server = True
    if any(srv.group_id != target_group.id for srv in own_dns):
        # #1715 — the appliance's own dead row of a previous engine would
        # block the move on name and driver; retire it first.
        outcome.retired = await retire_stale_engine_rows(db, appliance, target_group, user)
    for server in own_dns:
        old_driver = old_drivers.get(server.id, server.driver)
        try:
            result = await move_server_to_group(db, server, target_group)
        except ServerMoveError as exc:
            raise ServerMoveError(
                f"Can't move this appliance's DNS server {server.name!r}: {exc.detail}",
                status_code=exc.status_code,
            ) from exc
        if result is None:
            continue
        changed_fields = ["group_id"]
        new_value: dict[str, Any] = {
            **result.as_audit_value(),
            "via_appliance_id": str(appliance.id),
        }
        if old_driver != server.driver:
            changed_fields.append("driver")
            new_value["driver"] = server.driver
            new_value["old_driver"] = old_driver
        outcome.moved.append({"dns_server": str(server.id), "name": server.name})
        db.add(
            AuditLog(
                user_id=user.id,
                user_display_name=user.display_name,
                auth_source=getattr(user, "auth_source", "local") or "local",
                action="update",
                resource_type="dns_server",
                resource_id=str(server.id),
                resource_display=server.name,
                changed_fields=changed_fields,
                new_value=new_value,
                result="success",
            )
        )
    return outcome


__all__ = [
    "ApplianceDnsMove",
    "appliance_adoptable_dns_server",
    "appliance_own_dns_servers",
    "move_appliance_dns_servers",
    "retire_stale_engine_rows",
]

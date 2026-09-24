"""Managing Windows DHCP failover relationships from SpatiumDDI (#1110 Phase 2).

Phase 1 reads relationships and refuses what would be unsafe without one;
this module creates and changes them, so a group of two Windows DHCP servers
can be made into a coordinated pair here instead of on Windows.

**Imperative, not desired-state.** A relationship is a Windows object, and
these functions act on it and then re-read it — they do not store a desired
relationship for a reconciler to enforce. A reconciler would fight every
change an operator makes in the DHCP console, and Windows already is the
source of truth the topology poll reads. So there is no new table: each
action runs one cmdlet, records what the server reports back into the
Phase 1 observation rows, and refreshes the partner's view best-effort.

**Every action acts on both partners from ONE server**, which has to
authenticate onward to the other (see
``drivers.dhcp.windows.failover_management_blocker``). The server the
cmdlet runs on is chosen here, and it matters beyond authentication:

* ``Add-DhcpServerv4Failover`` / ``Add-DhcpServerv4FailoverScope`` COPY each
  scope from the server they run on to the partner, so they run on the
  member that holds the scopes — and each scope must not already exist on
  the partner, or Windows refuses.
* ``Remove-DhcpServerv4Failover`` / ``Remove-DhcpServerv4FailoverScope``
  DELETE the partner's copy of the scopes and keep the local one, so the
  member they run on is the one that keeps serving. The caller picks it
  (``keep_server_id``); the default is the hot-standby Active side, else
  the lowest-named member.
* ``Invoke-DhcpServerv4FailoverReplication`` copies the local configuration
  OVER the partner's, so the caller names the source explicitly — there is
  no safe default for "which side's configuration wins".

The shared secret is passed through to Windows and never stored, logged or
put in an audit row.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import get_driver
from app.drivers.dhcp.windows import (
    FailoverManagementUnavailable,
    failover_management_blocker,
)
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.dhcp.windows_failover import (
    WINDOWS_DRIVER,
    load_group_observations,
    record_failover_observation,
    record_scope_observation,
)
from app.services.dhcp.windows_writethrough import (
    WindowsPushError,
    WindowsServingRefused,
    _probe_many,
)

logger = structlog.get_logger(__name__)

MODES = ("LoadBalance", "HotStandby")
ROLES = ("Active", "Standby")


@dataclass
class FailoverActionResult:
    """What an action did, for the response and the audit row."""

    action: str
    relationship: str
    ran_on: DHCPServer
    partner: DHCPServer | None
    scope_ids: list[str]
    #: Refreshes that failed after the action succeeded — the action stands;
    #: the next topology poll catches the view up.
    warnings: list[str]


def canonical_scope_ids(values: Sequence[str]) -> list[str]:
    """Windows ``ScopeId``s (IPv4 network addresses), de-duplicated, in order."""
    out: list[str] = []
    for value in values:
        try:
            sid = str(ipaddress.IPv4Address(str(value).strip()))
        except ValueError as exc:
            raise WindowsServingRefused(
                f"'{value}' is not a Windows scope id — scopes are named by their IPv4 "
                f"network address, e.g. 10.1.2.0."
            ) from exc
        if sid not in out:
            out.append(sid)
    return out


async def windows_members(db: AsyncSession, group: DHCPServerGroup) -> list[DHCPServer]:
    return list(
        (
            await db.execute(
                select(DHCPServer)
                .where(
                    DHCPServer.server_group_id == group.id,
                    DHCPServer.driver == WINDOWS_DRIVER,
                )
                .order_by(DHCPServer.name)
            )
        )
        .scalars()
        .all()
    )


def _member(members: Sequence[DHCPServer], server_id: uuid.UUID, what: str) -> DHCPServer:
    for s in members:
        if s.id == server_id:
            return s
    raise WindowsServingRefused(
        f"The {what} must be a Windows DHCP server in this group; {server_id} is not.",
    )


def _assert_manageable(server: DHCPServer) -> None:
    blocker = failover_management_blocker(server)
    if blocker is not None:
        raise WindowsServingRefused(blocker)


async def _relationship_sides(
    db: AsyncSession, group: DHCPServerGroup, name: str
) -> tuple[list[DHCPServer], list[Any]]:
    """The members that report relationship ``name``, with their rows."""
    obs = await load_group_observations(db, group.id)
    sides: list[DHCPServer] = []
    rows: list[Any] = []
    for member in obs.members:
        for rel in obs.relationships.get(member.server_id, []):
            if rel.name == name:
                sides.append(obs.servers[member.server_id])
                rows.append(rel)
    if not sides:
        raise WindowsServingRefused(
            f"No Windows DHCP server in this group reports a failover relationship named "
            f"'{name}'. If it was created on Windows moments ago, run Sync on the server "
            f"first.",
            status_code=404,
        )
    return sides, rows


def _default_keep_side(sides: Sequence[DHCPServer], rows: Sequence[Any]) -> DHCPServer:
    """The side that keeps serving when a relationship or scope is removed:
    the hot-standby Active server, else the lowest-named side."""
    for server, rel in zip(sides, rows, strict=True):
        if (rel.mode or "").lower() == "hotstandby" and (rel.server_role or "") == "Active":
            return server
    return sorted(sides, key=lambda s: s.name)[0]


def _pick_side(
    sides: Sequence[DHCPServer], rows: Sequence[Any], server_id: uuid.UUID | None, what: str
) -> tuple[DHCPServer, Any]:
    if server_id is None:
        server = _default_keep_side(sides, rows)
    else:
        matches = [s for s in sides if s.id == server_id]
        if not matches:
            raise WindowsServingRefused(
                f"The {what} must be a side of the relationship "
                f"({', '.join(s.name for s in sides)})."
            )
        server = matches[0]
    return server, rows[list(sides).index(server)]


async def _run(server: DHCPServer, method: str, **kwargs: Any) -> dict[str, Any]:
    driver = get_driver(server.driver)
    try:
        return await getattr(driver, method)(server, **kwargs)  # type: ignore[no-any-return]
    except FailoverManagementUnavailable as exc:
        raise WindowsServingRefused(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface Windows' own message
        logger.warning(
            "windows_dhcp_failover_action_failed",
            server=str(server.id),
            method=method,
            error=str(exc),
        )
        raise WindowsPushError(f"{server.name}: {exc}") from exc


async def _refresh(
    db: AsyncSession,
    ran_on: DHCPServer,
    result: dict[str, Any],
    others: Sequence[DHCPServer],
) -> list[str]:
    """Record what the action left behind.

    ``ran_on``'s relationships come back with the action itself. Both sides'
    scope lists and the partner's relationships are re-read here, because a
    relationship action creates or deletes scopes on the PARTNER — without
    this the page would show the old state until the next poll, and a scope
    write in between would be planned against it. Best-effort: the action has
    already happened on Windows, so a failed refresh is a warning, never a
    rollback of the audit row that records it.
    """
    now = datetime.now(UTC)
    warnings: list[str] = []
    await record_failover_observation(db, ran_on, result, now=now)
    for server in [ran_on, *others]:
        driver = get_driver(server.driver)
        try:
            await record_scope_observation(db, server, await driver.get_scopes(server), now=now)
            if server is not ran_on:
                await record_failover_observation(
                    db,
                    server,
                    await driver.get_failover_relationships(server),  # type: ignore[attr-defined]
                    now=now,
                )
        except Exception as exc:  # noqa: BLE001 — see docstring
            warnings.append(f"could not re-read {server.name}: {exc}")
            logger.warning(
                "windows_dhcp_failover_refresh_failed", server=str(server.id), error=str(exc)
            )
    return warnings


def _validate_tuning(
    *,
    mode: str | None,
    server_role: str | None,
    load_balance_percent: int | None,
    reserve_percent: int | None,
    auto_state_transition: bool | None,
    state_switch_interval_seconds: int | None,
    require_role: bool = True,
) -> None:
    if mode is not None and mode not in MODES:
        raise WindowsServingRefused(f"mode must be one of {', '.join(MODES)}.")
    if server_role is not None and server_role not in ROLES:
        raise WindowsServingRefused(f"server_role must be one of {', '.join(ROLES)}.")
    if mode == "HotStandby" and server_role is None and require_role:
        raise WindowsServingRefused(
            "A hot-standby relationship needs server_role — Active or Standby — for the "
            "server it is created on."
        )
    if mode == "LoadBalance" and (server_role is not None or reserve_percent is not None):
        raise WindowsServingRefused(
            "server_role and reserve_percent apply to hot-standby mode only."
        )
    if mode == "HotStandby" and load_balance_percent is not None:
        raise WindowsServingRefused("load_balance_percent applies to load-balance mode only.")
    if state_switch_interval_seconds is not None and auto_state_transition is False:
        raise WindowsServingRefused(
            "state_switch_interval_seconds only has an effect with auto_state_transition on."
        )


async def create_relationship(
    db: AsyncSession,
    group: DHCPServerGroup,
    *,
    name: str,
    server_id: uuid.UUID,
    partner_server_id: uuid.UUID,
    scope_ids: Sequence[str],
    mode: str,
    load_balance_percent: int | None,
    server_role: str | None,
    reserve_percent: int | None,
    max_client_lead_time_seconds: int | None,
    auto_state_transition: bool | None,
    state_switch_interval_seconds: int | None,
    shared_secret: str | None,
) -> FailoverActionResult:
    """``Add-DhcpServerv4Failover`` on ``server_id`` with ``partner_server_id``.

    Checked live before anything is sent: every scope is held by the server
    and NOT by the partner (Windows copies it there, and refuses when it is
    already present), and none is already in a relationship. The partner is
    named to Windows by the host SpatiumDDI dials it on.
    """
    name = (name or "").strip()
    if not name:
        raise WindowsServingRefused("A failover relationship needs a name.")
    members = await windows_members(db, group)
    server = _member(members, server_id, "server")
    partner = _member(members, partner_server_id, "partner")
    if server.id == partner.id:
        raise WindowsServingRefused("A failover relationship needs two different servers.")
    _validate_tuning(
        mode=mode,
        server_role=server_role,
        load_balance_percent=load_balance_percent,
        reserve_percent=reserve_percent,
        auto_state_transition=auto_state_transition,
        state_switch_interval_seconds=state_switch_interval_seconds,
    )
    sids = canonical_scope_ids(scope_ids)
    if not sids:
        raise WindowsServingRefused(
            "Windows cannot create a failover relationship without at least one scope. "
            "Create the scope on the server first — in SpatiumDDI, choose that server as "
            "the scope's placement."
        )
    _assert_manageable(server)

    probes = await _probe_many([server, partner], sids)
    for sid in sids:
        mine = probes[server.id]["scopes"][sid]
        theirs = probes[partner.id]["scopes"][sid]
        if not mine["present"]:
            raise WindowsServingRefused(
                f"{server.name} does not hold scope {sid}. The relationship copies each "
                f"scope from the server it is created on, so the scope has to be there."
            )
        if theirs["present"]:
            raise WindowsServingRefused(
                f"{partner.name} already holds scope {sid}, and Windows copies the scope to "
                f"the partner — it refuses when a copy is already there. Remove the scope "
                f"from {partner.name} on Windows (Remove-DhcpServerv4Scope -ComputerName "
                f"{partner.name} -ScopeId {sid}) and add it again. Its leases come back "
                f"from {server.name} over the failover protocol."
            )
    for srv in (server, partner):
        fo = probes[srv.id]["failover"]
        if not fo["ok"]:
            raise WindowsServingRefused(
                f"Could not read {srv.name}'s failover relationships ({fo.get('error')}), "
                f"so whether these scopes or this name are already in use is unknown."
            )
        for rel in fo["relationships"]:
            if rel["name"] == name:
                raise WindowsServingRefused(
                    f"{srv.name} already has a failover relationship named '{name}'.",
                    status_code=409,
                )
            taken = sorted(set(sids) & set(rel.get("scope_ids") or []))
            if taken:
                raise WindowsServingRefused(
                    f"Scope {', '.join(taken)} is already in failover relationship "
                    f"'{rel['name']}' on {srv.name}; a scope can be in one relationship only.",
                    status_code=409,
                )

    result = await _run(
        server,
        "create_failover_relationship",
        name=name,
        partner_server=partner.host,
        scope_ids=sids,
        mode=mode,
        load_balance_percent=load_balance_percent,
        server_role=server_role,
        reserve_percent=reserve_percent,
        max_client_lead_time_seconds=max_client_lead_time_seconds,
        auto_state_transition=auto_state_transition,
        state_switch_interval_seconds=state_switch_interval_seconds,
        shared_secret=shared_secret,
    )
    warnings = await _refresh(db, server, result, [partner])
    return FailoverActionResult("create", name, server, partner, sids, warnings)


async def update_relationship(
    db: AsyncSession,
    group: DHCPServerGroup,
    name: str,
    *,
    changes: dict[str, Any],
    server_id: uuid.UUID | None = None,
) -> FailoverActionResult:
    """``Set-DhcpServerv4Failover`` on one side.

    Windows applies ``load_balance_percent`` and ``server_role`` to the server
    the cmdlet runs on (the partner gets the complement), so a change carrying
    either must say which side it means — ``server_id`` — or the same request
    could make both partners Active depending on which side SpatiumDDI happened
    to pick. Without those fields any drivable side will do.
    """
    sides, rows = await _relationship_sides(db, group, name)
    if not any(v is not None for v in changes.values()):
        raise WindowsServingRefused("Nothing to change.")
    new_mode = changes.get("mode")
    _validate_tuning(
        mode=new_mode,
        server_role=changes.get("server_role"),
        load_balance_percent=changes.get("load_balance_percent"),
        reserve_percent=changes.get("reserve_percent"),
        auto_state_transition=changes.get("auto_state_transition"),
        state_switch_interval_seconds=changes.get("state_switch_interval_seconds"),
        # A role is needed when switching INTO hot standby; while already
        # there, leaving it out leaves it as it is.
        require_role=new_mode == "HotStandby" and new_mode != rows[0].mode,
    )
    per_side = (
        changes.get("server_role") is not None or changes.get("load_balance_percent") is not None
    )
    if per_side and server_id is None:
        raise WindowsServingRefused(
            "load_balance_percent and server_role are one side's values — say which side "
            "with server_id."
        )
    if server_id is not None:
        server, _rel = _pick_side(sides, rows, server_id, "server the change runs on")
        _assert_manageable(server)
    else:
        runnable = [s for s in sides if failover_management_blocker(s) is None]
        if not runnable:
            raise WindowsServingRefused(
                failover_management_blocker(sides[0])
                or "No side of the relationship is manageable."
            )
        server = runnable[0]
    result = await _run(server, "update_failover_relationship", name=name, **changes)
    others = [s for s in sides if s.id != server.id]
    warnings = await _refresh(db, server, result, others)
    partner = others[0] if others else None
    return FailoverActionResult("update", name, server, partner, [], warnings)


async def delete_relationship(
    db: AsyncSession,
    group: DHCPServerGroup,
    name: str,
    *,
    keep_server_id: uuid.UUID | None,
) -> FailoverActionResult:
    """``Remove-DhcpServerv4Failover`` on the side that keeps the scopes.

    Windows deletes the relationship on both partners and deletes the
    PARTNER's copy of every scope it covered, so afterwards each scope is
    served by ``keep_server_id`` alone — safe, uncoordinated with nothing.
    """
    sides, rows = await _relationship_sides(db, group, name)
    server, rel = _pick_side(sides, rows, keep_server_id, "server that keeps the scopes")
    _assert_manageable(server)
    result = await _run(server, "delete_failover_relationship", name=name)
    others = [s for s in sides if s.id != server.id]
    warnings = await _refresh(db, server, result, others)
    return FailoverActionResult(
        "delete",
        name,
        server,
        others[0] if others else None,
        list(rel.scope_ids or []),
        warnings,
    )


async def add_scopes(
    db: AsyncSession, group: DHCPServerGroup, name: str, *, scope_ids: Sequence[str]
) -> FailoverActionResult:
    """``Add-DhcpServerv4FailoverScope`` on the side that holds the scopes.

    Each scope must be held by exactly one side — Windows copies it to the
    other — so the side is found by probing, not chosen.
    """
    sids = canonical_scope_ids(scope_ids)
    if not sids:
        raise WindowsServingRefused("Name at least one scope to add.")
    sides, rows = await _relationship_sides(db, group, name)
    if len(sides) != 2:
        raise WindowsServingRefused(
            f"Only one side of relationship '{name}' is a member of this group, so the "
            f"partner that would receive the scopes is not one SpatiumDDI can check. Add "
            f"the scopes on Windows."
        )
    probes = await _probe_many(sides, sids)
    source: DHCPServer | None = None
    for sid in sids:
        holders = [s for s in sides if probes[s.id]["scopes"][sid]["present"]]
        if len(holders) != 1:
            where = (
                "neither side holds it"
                if not holders
                else f"both {sides[0].name} and {sides[1].name} hold it, and Windows "
                f"refuses to copy a scope over an existing one — remove it from one of them "
                f"on Windows first"
            )
            raise WindowsServingRefused(f"Cannot add scope {sid} to '{name}': {where}.")
        if source is not None and holders[0].id != source.id:
            raise WindowsServingRefused(
                "The scopes are held by different sides; add them in two steps, one per side."
            )
        source = holders[0]
        for rel in probes[source.id]["failover"]["relationships"]:
            if sid in (rel.get("scope_ids") or []):
                raise WindowsServingRefused(
                    f"Scope {sid} is already in relationship '{rel['name']}'.",
                    status_code=409,
                )
    assert source is not None
    _assert_manageable(source)
    result = await _run(source, "add_failover_scopes", name=name, scope_ids=sids)
    others = [s for s in sides if s.id != source.id]
    warnings = await _refresh(db, source, result, others)
    return FailoverActionResult("add_scopes", name, source, others[0], sids, warnings)


async def remove_scopes(
    db: AsyncSession,
    group: DHCPServerGroup,
    name: str,
    *,
    scope_ids: Sequence[str],
    keep_server_id: uuid.UUID | None,
) -> FailoverActionResult:
    """``Remove-DhcpServerv4FailoverScope`` on the side that keeps them —
    Windows deletes the partner's copies."""
    sids = canonical_scope_ids(scope_ids)
    if not sids:
        raise WindowsServingRefused("Name at least one scope to remove.")
    sides, rows = await _relationship_sides(db, group, name)
    server, rel = _pick_side(sides, rows, keep_server_id, "server that keeps the scopes")
    missing = sorted(set(sids) - set(rel.scope_ids or []))
    if missing:
        raise WindowsServingRefused(
            f"Scope {', '.join(missing)} is not in relationship '{name}'.", status_code=409
        )
    _assert_manageable(server)
    result = await _run(server, "remove_failover_scopes", name=name, scope_ids=sids)
    others = [s for s in sides if s.id != server.id]
    warnings = await _refresh(db, server, result, others)
    return FailoverActionResult(
        "remove_scopes", name, server, others[0] if others else None, sids, warnings
    )


async def replicate(
    db: AsyncSession,
    group: DHCPServerGroup,
    name: str,
    *,
    source_server_id: uuid.UUID,
    scope_ids: Sequence[str],
) -> FailoverActionResult:
    """``Invoke-DhcpServerv4FailoverReplication`` from ``source_server_id``:
    its configuration of the scopes overwrites the partner's."""
    sids = canonical_scope_ids(scope_ids)
    sides, rows = await _relationship_sides(db, group, name)
    server, rel = _pick_side(sides, rows, source_server_id, "source server")
    missing = sorted(set(sids) - set(rel.scope_ids or []))
    if missing:
        raise WindowsServingRefused(
            f"Scope {', '.join(missing)} is not in relationship '{name}'.", status_code=409
        )
    _assert_manageable(server)
    result = await _run(server, "replicate_failover", name=name, scope_ids=sids)
    others = [s for s in sides if s.id != server.id]
    warnings = await _refresh(db, server, result, others)
    return FailoverActionResult(
        "replicate",
        name,
        server,
        others[0] if others else None,
        sids or list(rel.scope_ids or []),
        warnings,
    )


__all__ = [
    "MODES",
    "ROLES",
    "FailoverActionResult",
    "add_scopes",
    "canonical_scope_ids",
    "create_relationship",
    "delete_relationship",
    "remove_scopes",
    "replicate",
    "update_relationship",
    "windows_members",
]

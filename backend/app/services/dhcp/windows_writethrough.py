"""Write-through to Windows DHCP for scope / pool / static edits.

The SpatiumDDI scope / pool / static API endpoints call the helpers in
this module **after** the DB has been flushed but **before** commit,
so a WinRM failure surfaces as a 502 and rolls the transaction back —
the user sees the error instead of finding their DB and Windows have
drifted out of sync.

Under the group-centric model, scopes live on DHCPServerGroup. The
helpers here find the **Windows DHCP members** of the scope's group and
push per-object changes to them — to the one member of a single-Windows
group, and on a group with more than one, only to the members that hold
the scope (see "More than one Windows member" below). Kea members use
the agent bundle path and are skipped here.

Why write-through per object (instead of a bundle push):

  * Windows DHCP has no "apply this whole config" entry point. Every
    change is a cmdlet against a specific scope / reservation.
  * The driver's ``apply_scope`` call resets the scope's option-values
    to exactly what our DB says. So one call covers add/update/remove
    for every option under that scope in a single round-trip.
  * Reservations and exclusions are per-object: we push one
    ``Add/Set/Remove-DhcpServerv4*`` per user action. That keeps the
    blast radius of any failure scoped to the object being edited.

**Atomicity caveat (#426).** A reservation *relocation* (MAC change, or
an IP-only change — Windows can't move a reservation's IP via ``Set-``)
is a remove-then-add: two separate cmdlets. If the add fails after the
remove committed, the DB rolls back to the old MAC/IP while Windows is
left with no reservation for that MAC — and in the multi-server fan-out,
an earlier member can succeed while a later one fails. This window is
inherent to two-cmdlet relocation; the next ``sync-leases`` /
``get_scopes`` reconcile re-converges, and the 502 tells the operator to
retry. Simple create/delete/option edits remain single-cmdlet.

**More than one Windows member (#1110).** "Every member serves every scope"
is what the group model says and what Kea HA makes true. Two Windows DHCP
servers only share a scope safely inside a **failover relationship** that
covers it; without one they each hand out the same addresses. So a group
with two or more Windows members is not written blind:

* **Scope update / activate** probes every Windows member live
  (``driver.probe_scopes``) and classifies the result with
  ``services.dhcp.windows_failover.classify_serving``. The write goes to the
  members that already hold the scope and to no other member, and it never
  creates the scope anywhere (``create_if_missing=False``, checked in the
  same PowerShell as the write). Activating a scope held by several members
  with no relationship covering it is refused (422), and so is any write
  that would make a split scope's halves overlap — SpatiumDDI pushes one
  range and one set of exclusions to every holder.
* **Scope create** — a scope no member holds — goes to ONE member
  (``WindowsPlacement``): into a failover relationship, created on one side
  and added to the relationship so Windows copies it to the partner; or onto
  one named server alone. Creating it on every member is the outage, so a
  create with no placement is refused unless the group's members share
  exactly one relationship SpatiumDDI can drive.
* **A covered scope is written to BOTH partners.** Windows failover syncs
  leases between partners continuously but not configuration — option
  values, exclusions, reservations need an explicit
  ``Invoke-DhcpServerv4FailoverReplication``. Writing one partner and
  "letting Windows replicate" would leave the other stale until someone
  remembered to; Microsoft's own IPAM writes both, and so does this.
  Replication is available as an explicit operator action instead
  (``windows_failover_manage.replicate``), for drift made on Windows.
* **Scope delete** of a failover scope takes it out of the relationship on
  one side (deleting the partner's copy) and deletes it there, when both
  partners are members and the transport can reach the partner; otherwise
  it is refused (409) with the Windows-side step.
* **Pools and reservations** need no probe: the driver checks, in the
  script that writes, that the server holds the scope, and skips it if not.
  Only "no member holds the scope at all" is refused — plus removing or
  moving an exclusion on a split scope, which is probed and simulated.

Everything that has to act on BOTH partners from one server — joining or
leaving a relationship — needs the CredSSP WinRM transport (the PowerShell
remoting "second hop"; see ``drivers.dhcp.windows.failover_management_blocker``).

Single-Windows-member groups keep the pre-#1110 scope write — no probe,
create-or-update — with three differences, all about the failure path: a
scope delete probes first, so a failover scope gets the refusal and the
Windows-side step instead of Windows' raw error; deleting a scope already
gone from the server is the no-op it should always have been; and a
reservation / exclusion for a scope the server does not have is a 409 that
says so, instead of a 502 carrying whatever ``Add-DhcpServerv4Reservation``
printed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import structlog
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp import get_driver
from app.drivers.dhcp.base import RemoveReservationItem
from app.drivers.dhcp.windows import failover_management_blocker
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServer, DHCPStaticAssignment
from app.models.ipam import Subnet
from app.services.dhcp.cloud_writethrough import (
    push_cloud_scope_delete,
    push_cloud_scope_upsert,
)
from app.services.dhcp.normalize import norm_ip, norm_mac
from app.services.dhcp.windows_failover import (
    Holder,
    ScopeServing,
    Verdict,
    classify_serving,
    effective_ranges,
    member_of,
    ranges_overlap,
)

logger = structlog.get_logger(__name__)


# Change-detection normalisers (#426). They live in ``services.dhcp.normalize``
# because ``pull_leases`` diffs the same wire state against the same rows and
# has to agree byte-for-byte on what counts as a change (#620).
_norm_mac = norm_mac
_norm_ip = norm_ip


class WindowsPushError(HTTPException):
    """502 — a Windows DHCP write-through failed; caller rolled back."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=502, detail=f"Windows DHCP push failed: {detail}")


class WindowsServingRefused(HTTPException):
    """Refused before commit (#1110): the write would leave a scope served
    by Windows servers that do not coordinate, or cannot be carried out on
    the servers that hold it.

    422 when the request itself is the problem (create / activate across
    members no failover relationship covers); 409 when Windows' current
    state conflicts with it (deleting a failover scope, a scope that no
    member holds). Nothing has been written to any server when this raises
    from a plan; the one exception is the "disappeared mid-write" race,
    where earlier members may already hold the change — the same partial
    state the #426 caveat describes, converged by the next poll.
    """

    def __init__(self, detail: str, *, status_code: int = 422) -> None:
        super().__init__(status_code=status_code, detail=detail)


async def _windows_servers_for_group(db: AsyncSession, group_id: Any) -> list[DHCPServer]:
    """Return the Windows DHCP members of ``group_id`` (possibly empty),
    ordered by name so every multi-server message lists them the same way."""
    if group_id is None:
        return []
    res = await db.execute(
        select(DHCPServer)
        .where(
            DHCPServer.server_group_id == group_id,
            DHCPServer.driver == "windows_dhcp",
        )
        .order_by(DHCPServer.name)
    )
    return list(res.scalars().all())


def _names(servers: Sequence[DHCPServer]) -> str:
    names = [s.name for s in servers]
    if len(names) <= 1:
        return "".join(names)
    return ", ".join(names[:-1]) + " and " + names[-1]


async def _probe_many(
    servers: Sequence[DHCPServer], scope_ids: Sequence[str]
) -> dict[Any, dict[str, Any]]:
    """Probe every server live for ``scope_ids``; ``{server.id: probe}``.

    Concurrent — one WinRM round trip per server, in parallel. A server that
    cannot be probed fails the whole call (502): every caller plans from
    "which servers hold this scope", and a server whose answer is unknown
    might be one of them. Reading its silence as "does not hold it" is how
    the planner would come to activate a scope on one server while another
    is already serving it.
    """
    results = await asyncio.gather(
        *(get_driver(s.driver).probe_scopes(s, list(scope_ids)) for s in servers),  # type: ignore[attr-defined]
        return_exceptions=True,
    )
    failures = [
        f"{server.name}: {res}"
        for server, res in zip(servers, results, strict=True)
        if isinstance(res, BaseException)
    ]
    if failures:
        logger.warning("windows_dhcp_probe_failed", scopes=list(scope_ids), failures=failures)
        raise WindowsPushError(
            f"could not establish which Windows DHCP servers hold {', '.join(scope_ids)} — "
            + "; ".join(failures)
        )
    probes: dict[Any, dict[str, Any]] = {}
    for server, res in zip(servers, results, strict=True):
        assert isinstance(res, dict)  # narrowed by the failure check above
        probes[server.id] = res
    return probes


async def _probe_serving(
    servers: Sequence[DHCPServer], net: ipaddress._BaseNetwork
) -> tuple[ScopeServing, dict[Any, dict[str, Any]]]:
    """Probe every Windows member live and classify how they serve ``net``.

    Returns the classification and each member's raw probe, keyed by id.
    """
    scope_id = str(net.network_address)
    probes = await _probe_many(servers, [scope_id])
    holders: list[Holder] = []
    for server in servers:
        res = probes[server.id]
        obs = res["scopes"][scope_id]
        if not obs["present"]:
            continue
        failover = res["failover"]
        rel = next(
            (r for r in failover["relationships"] if scope_id in (r.get("scope_ids") or [])),
            None,
        )
        holders.append(
            Holder(
                member=member_of(server),
                is_active=obs["is_active"],
                relationship=rel,
                failover_known=bool(failover["ok"]),
                failover_error=failover.get("error"),
                ranges=effective_ranges(obs["start_ip"], obs["end_ip"], obs["exclusions"]),
            )
        )
    return classify_serving(holders, [member_of(s) for s in servers]), probes


@dataclass(frozen=True)
class WindowsPlacement:
    """Where a NEW scope goes on a group with two or more Windows members.

    Only consulted when no member holds the scope yet (#1110). Give one:

    * ``failover_relationship`` — create the scope on one side of that
      relationship and add it to the relationship, which makes Windows copy
      it to the partner. Needs a transport that can make the second hop.
    * ``server_id`` — create it on that one member only. Safe (one server
      serves it), and the way to seed a scope for a relationship that does
      not exist yet: Windows cannot create a relationship without a scope.

    With neither, a group whose members share exactly one relationship
    SpatiumDDI can drive uses that one; otherwise the create is refused and
    the refusal lists the choices.
    """

    server_id: uuid.UUID | None = None
    failover_relationship: str | None = None


@dataclass
class ScopePlan:
    #: ``(server, create_if_missing)`` for each member the scope write goes to.
    targets: list[tuple[DHCPServer, bool]]
    #: After the write: add the scope to this relationship, on this member.
    add_to_relationship: tuple[DHCPServer, str] | None = None
    #: Refusals for the chosen placement, for the caller's message.
    notes: list[str] = field(default_factory=list)


def _complete_relationships(
    servers: Sequence[DHCPServer], probes: dict[Any, dict]
) -> dict[str, list[tuple[DHCPServer, dict[str, Any]]]]:
    """Relationships BOTH of whose sides are members: ``{name: [(server, rel), …]}``."""
    seen: dict[str, list[tuple[DHCPServer, dict[str, Any]]]] = defaultdict(list)
    for server in servers:
        for rel in probes.get(server.id, {}).get("failover", {}).get("relationships", []):
            seen[rel["name"]].append((server, rel))
    return {name: sides for name, sides in seen.items() if len(sides) == 2}


def _creating_side(sides: Sequence[tuple[DHCPServer, dict[str, Any]]]) -> DHCPServer:
    """The side a new scope is created on before it joins the relationship:
    the hot-standby Active server, else the lowest-named side."""
    for server, rel in sides:
        if (rel.get("mode") or "").lower() == "hotstandby" and rel.get("server_role") == "Active":
            return server
    return sorted((srv for srv, _rel in sides), key=lambda srv: srv.name)[0]


def _split_collapses(
    serving: ScopeServing,
    probes: dict[Any, dict[str, Any]],
    scope_id: str,
    *,
    new_range: tuple[str, str] | None = None,
    drop_exclusion: tuple[str, str] | None = None,
    add_exclusion: tuple[str, str] | None = None,
) -> bool:
    """Would this write make a split scope's halves overlap?

    A split scope is safe only because each server's range-minus-exclusions
    is disjoint from the other's. SpatiumDDI models ONE range and ONE set of
    exclusions per scope, and pushes them to every holder — so writing a new
    range, or dropping an exclusion from both, can hand the two servers the
    same addresses. Simulated per holder from the live probe, keeping each
    holder's own exclusions. Unknown ranges count as "no" — the classifier
    only calls a scope split when it knew them.
    """
    if serving.verdict is not Verdict.SPLIT_SCOPE:
        return False
    drop = (norm_ip(drop_exclusion[0]), norm_ip(drop_exclusion[1])) if drop_exclusion else None
    unit_ranges: list[list[tuple[int, int]]] = []
    for unit in serving.units:
        merged: list[tuple[int, int]] = []
        for holder in unit:
            obs = probes[holder.member.server_id]["scopes"][scope_id]
            start, end = new_range or (obs["start_ip"], obs["end_ip"])
            exclusions = [(a, b) for a, b in obs["exclusions"] if (norm_ip(a), norm_ip(b)) != drop]
            if add_exclusion is not None:
                exclusions.append(add_exclusion)
            ranges = effective_ranges(start, end, exclusions)
            if ranges is None:
                return False
            merged.extend(ranges)
        unit_ranges.append(merged)
    return any(
        ranges_overlap(unit_ranges[i], unit_ranges[j])
        for i in range(len(unit_ranges))
        for j in range(i + 1, len(unit_ranges))
    )


def _refuse_split_collapse(net: ipaddress._BaseNetwork, serving: ScopeServing, what: str) -> None:
    raise WindowsServingRefused(
        f"Refusing to {what} on scope {net}: it is a split scope ({_names_h(serving)} each "
        f"serve their own part of it, with no failover relationship), and SpatiumDDI "
        f"writes one range and one set of exclusions to every server that holds it — "
        f"after this change their parts would overlap and both could hand out the same "
        f"address. Make the change on each server in Windows, or put the scope in a "
        f"failover relationship first."
    )


def _names_h(serving: ScopeServing) -> str:
    names = sorted(h.member.name for h in serving.holders)
    return ", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else "".join(names)


async def _plan_scope_upsert(
    scope: DHCPScope,
    net: ipaddress._BaseNetwork,
    servers: Sequence[DHCPServer],
    *,
    new_range: tuple[str, str],
    placement: WindowsPlacement | None = None,
) -> ScopePlan:
    """Which Windows members a scope write goes to, and whether each may create it.

    One member: that member, create-or-update — the pre-#1110 behaviour,
    with no probe. Two or more: the members that hold the scope now, update
    only, after refusing the transitions that would start the outage; or,
    when none holds it, the placement (see ``WindowsPlacement``).
    """
    if len(servers) <= 1:
        return ScopePlan([(s, True) for s in servers])

    serving, probes = await _probe_serving(servers, net)
    scope_id = str(net.network_address)
    by_id = {s.id: s for s in servers}

    if serving.verdict is Verdict.NOT_ON_WINDOWS:
        return _plan_new_scope(net, servers, probes, placement or WindowsPlacement())

    if serving.verdict in (Verdict.UNCOORDINATED, Verdict.UNKNOWN) and scope.is_active:
        inactive = [h.member.name for h in serving.holders if h.is_active is False]
        if inactive:
            raise WindowsServingRefused(
                f"Refusing to activate scope {net}: {serving.detail} Activating it "
                f"would start {', '.join(sorted(inactive))} handing out addresses "
                f"alongside the other holder(s). Put the scope in a failover "
                f"relationship (the group's Windows failover panel, or "
                f"Add-DhcpServerv4FailoverScope on Windows), or remove it from all but "
                f"one server, then save it again."
            )
        # Already active everywhere: the duplicate-assignment risk predates this
        # write, which neither creates nor widens it. Refusing would only block
        # the operator from editing it; the scope's Windows panel says it loudly.
        logger.warning(
            "windows_dhcp_scope_uncoordinated_write",
            scope=str(scope.id),
            cidr=str(net),
            verdict=serving.verdict.value,
            holders=[h.member.name for h in serving.holders],
        )

    if _split_collapses(serving, probes, scope_id, new_range=new_range):
        _refuse_split_collapse(net, serving, f"set the range {new_range[0]}–{new_range[1]}")

    return ScopePlan([(by_id[h.member.server_id], False) for h in serving.holders])


def _plan_new_scope(
    net: ipaddress._BaseNetwork,
    servers: Sequence[DHCPServer],
    probes: dict[Any, dict[str, Any]],
    placement: WindowsPlacement,
) -> ScopePlan:
    """A scope no Windows member holds yet, on a group with two or more.

    Creating it on every member is the outage, so it goes to ONE member —
    alone, or as the first side of a failover relationship that then copies
    it to the other.
    """
    rels = _complete_relationships(servers, probes)
    by_id = {s.id: s for s in servers}

    def via(name: str) -> ScopePlan:
        side = _creating_side(rels[name])
        blocker = failover_management_blocker(side)
        if blocker is not None:
            raise WindowsServingRefused(
                f"Cannot put scope {net} into failover relationship '{name}': {blocker}"
            )
        return ScopePlan([(side, True)], add_to_relationship=(side, name))

    if placement.failover_relationship:
        name = placement.failover_relationship
        if name not in rels:
            raise WindowsServingRefused(
                f"There is no failover relationship named '{name}' between two Windows "
                f"DHCP servers of this group"
                + (f" (there is: {', '.join(sorted(rels))})." if rels else ".")
            )
        return via(name)
    if placement.server_id is not None:
        target = by_id.get(placement.server_id)
        if target is None:
            raise WindowsServingRefused(
                f"The scope's Windows placement must be a Windows DHCP server in this "
                f"group ({_names(servers)})."
            )
        return ScopePlan([(target, True)])
    manageable = [n for n in rels if failover_management_blocker(_creating_side(rels[n])) is None]
    if len(rels) == 1 and manageable:
        return via(manageable[0])

    options = [f"failover relationship '{n}'" for n in sorted(rels)] + [
        f"only {s.name}" for s in servers
    ]
    raise WindowsServingRefused(
        f"Scope {net} would be new to the Windows DHCP servers in this group "
        f"({_names(servers)}), and creating it on all of them would have each hand out the "
        f"same addresses without coordinating — duplicate address assignment, with "
        f"nothing on either server reporting a problem. Choose where it goes "
        f"(windows_placement): {'; '.join(options)}. A scope placed on one server can "
        f"then be put in a new failover relationship from the group's Windows failover "
        f"panel. Windows DHCP servers that do not share scopes belong in separate "
        f"server groups."
    )


async def _apply_to_members(
    servers: Sequence[DHCPServer],
    net: ipaddress._BaseNetwork,
    what: str,
    write: Callable[[DHCPServer], Awaitable[bool | None]],
    *,
    log_event: str,
    log_fields: dict[str, Any],
) -> None:
    """Run a scope-guarded write on every Windows member; refuse when no
    member holds the scope.

    The driver checks presence in the same script as the write and returns
    False on a member without the scope, so the write lands on exactly the
    members that serve it — no probe round trip, and none can be skipped
    because a lookup failed (a failed enumeration raises, it does not read
    as "absent"). If NO member took it, the reservation / exclusion has
    nowhere to live and the request is refused (409) rather than committed
    to a scope Windows does not have.
    """
    applied = False
    for server in servers:
        try:
            # Only an explicit False means "this member does not hold the
            # scope"; a driver without the presence guard returns None, and
            # that is a write that happened.
            applied = (await write(server)) is not False or applied
        except WindowsPushError:
            raise
        except Exception as exc:  # noqa: BLE001 — surface the error
            logger.warning(log_event, server=str(server.id), error=str(exc), **log_fields)
            raise WindowsPushError(str(exc)) from exc
    if not applied:
        raise WindowsServingRefused(
            f"Scope {net} does not exist on "
            f"{'the Windows DHCP server' if len(servers) == 1 else 'any Windows DHCP server'} "
            f"in this group ({_names(servers)}), so there is nothing to add the {what} to. "
            f"It may have been deleted on Windows; run Sync on the server to re-read "
            f"its scopes"
            + (", or re-save the scope to create it again." if len(servers) == 1 else "."),
            status_code=409,
        )


async def _scope_cidr(db: AsyncSession, scope: DHCPScope) -> ipaddress._BaseNetwork:
    """Resolve the scope's subnet to an ``ipaddress`` network."""
    subnet = await db.get(Subnet, scope.subnet_id)
    if subnet is None:
        raise WindowsPushError(f"Scope {scope.id}'s subnet is missing from IPAM")
    try:
        return ipaddress.ip_network(str(subnet.network), strict=False)
    except (ValueError, TypeError) as exc:
        raise WindowsPushError(f"Invalid subnet CIDR on scope {scope.id}: {exc}") from exc


async def _scope_range(
    db: AsyncSession, scope: DHCPScope, net: ipaddress._BaseNetwork
) -> tuple[str, str]:
    """Derive the Windows scope Start/End range."""
    pools_res = await db.execute(
        select(DHCPPool).where(
            DHCPPool.scope_id == scope.id,
            DHCPPool.pool_type == "dynamic",
        )
    )
    dynamic_pools = list(pools_res.scalars().all())
    if len(dynamic_pools) == 1:
        return str(dynamic_pools[0].start_ip), str(dynamic_pools[0].end_ip)
    if len(dynamic_pools) > 1:
        raise WindowsPushError(
            "Windows DHCP supports only one dynamic range per scope. "
            "Collapse the overlapping dynamic pools or use exclusion "
            "ranges (pool_type='excluded') to carve out sub-ranges."
        )
    hosts = list(net.hosts())
    if not hosts:
        raise WindowsPushError(f"Subnet {net} has no usable host range")
    return str(hosts[0]), str(hosts[-1])


async def push_scope_upsert(
    db: AsyncSession,
    scope: DHCPScope,
    *,
    adopt_existing: bool = False,
    placement: WindowsPlacement | None = None,
) -> None:
    """Push a scope create/update to the agentless members of the scope's group.

    Windows members take a per-object ``apply_scope``; agentless cloud/REST
    members (FortiGate) take the whole ``system.dhcp.server`` object rebuilt
    from DB (see ``cloud_writethrough``). Both run before commit so a push
    failure surfaces as a 502 and rolls back.

    ``adopt_existing`` (cloud members only, #865) opts in to overwriting a
    provider DHCP object SpatiumDDI never created; without it such a push
    raises ``CloudAdoptionRequired`` (409) and the caller's transaction rolls
    back. Windows members have no equivalent guard, so the flag stops here.

    Windows members: see the module docstring (#1110) — one member is
    written create-or-update; two or more are probed, and only the members
    that already hold the scope are written, update-only. ``placement``
    decides where a scope no member holds yet goes (``WindowsPlacement``).
    """
    # Cloud/REST members first — independent of, and not gated by, the Windows
    # early-return below (a cloud-only group has no Windows members).
    await push_cloud_scope_upsert(db, scope, adopt_existing=adopt_existing)

    win_servers = await _windows_servers_for_group(db, scope.group_id)
    if not win_servers:
        return

    net = await _scope_cidr(db, scope)
    start, end = await _scope_range(db, scope, net)
    plan = await _plan_scope_upsert(
        scope, net, win_servers, new_range=(start, end), placement=placement
    )
    for server, create_if_missing in plan.targets:
        driver = get_driver(server.driver)
        try:
            applied = await driver.apply_scope(  # type: ignore[attr-defined]
                server,
                scope_id=str(net.network_address),
                subnet_mask=str(net.netmask),
                start_range=start,
                end_range=end,
                name=scope.name or "",
                description=scope.description or "",
                lease_seconds=int(scope.lease_time or 86400),
                is_active=bool(scope.is_active),
                options=scope.options or {},
                create_if_missing=create_if_missing,
            )
        except Exception as exc:  # noqa: BLE001 — surface the error
            logger.warning(
                "windows_dhcp_push_scope_failed",
                scope=str(scope.id),
                server=str(server.id),
                error=str(exc),
            )
            raise WindowsPushError(str(exc)) from exc
        if applied is False:
            # The probe saw it on this member seconds ago. Re-creating it here
            # could be the exact write this plan exists to refuse, so stop.
            raise WindowsServingRefused(
                f"Scope {net} disappeared from {server.name} while it was being "
                f"updated; nothing was re-created there. Run Sync on the server and "
                f"try again.",
                status_code=409,
            )
    if plan.add_to_relationship is not None:
        await _join_relationship(scope, net, *plan.add_to_relationship)


async def _join_relationship(
    scope: DHCPScope, net: ipaddress._BaseNetwork, server: DHCPServer, name: str
) -> None:
    """Add a scope just created on ``server`` to failover relationship ``name``.

    Windows copies it to the partner. If that fails, the scope is removed
    from ``server`` again before the 502 rolls the row back — otherwise
    Windows would be left holding a scope SpatiumDDI has no record of.
    """
    scope_id = str(net.network_address)
    driver = get_driver(server.driver)
    try:
        await driver.add_failover_scopes(server, name=name, scope_ids=[scope_id])  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 — compensate, then surface
        logger.warning(
            "windows_dhcp_push_scope_join_failed",
            scope=str(scope.id),
            server=str(server.id),
            relationship=name,
            error=str(exc),
        )
        cleanup = "and removed it again"
        try:
            await driver.remove_scope(server, scope_id)  # type: ignore[attr-defined]
        except Exception as cleanup_exc:  # noqa: BLE001 — report both
            cleanup = (
                f"and could NOT remove it again ({cleanup_exc}) — delete it on {server.name} "
                f"in Windows"
            )
        raise WindowsPushError(
            f"created scope {net} on {server.name} but could not add it to failover "
            f"relationship '{name}' ({exc}), {cleanup}"
        ) from exc


async def push_scope_delete(db: AsyncSession, scope: DHCPScope) -> None:
    """Remove the scope from the agentless members of its group that hold it.

    Fires on the soft-delete path too (via ``_push_agentless_scope_deletes``)
    and the permanent path — an agentless push driver only reflects the delete
    if we push it (#616). Cloud/REST members remove the whole interface DHCP
    object; Windows members remove the scope by network address.

    Windows (#1110): every member is probed first and the scope is removed
    only from the members that hold it. Windows will not delete a scope that
    is in a failover relationship, so a scope both of whose partners are
    members is first taken out of the relationship on one side (which
    deletes the partner's copy) and then deleted there — when that side's
    WinRM transport can reach the partner. Otherwise, and whenever the
    partner is NOT a member of this group, the delete is refused (409): that
    step deletes a copy on a server SpatiumDDI does not manage, which is the
    operator's call to make on Windows, not a side effect of a delete here.
    """
    await push_cloud_scope_delete(db, scope)

    win_servers = await _windows_servers_for_group(db, scope.group_id)
    if not win_servers:
        return
    net = await _scope_cidr(db, scope)
    scope_id = str(net.network_address)
    serving, _probes = await _probe_serving(win_servers, net)
    by_id = {s.id: s for s in win_servers}
    in_relationship = [h for h in serving.holders if h.relationship]
    if serving.verdict is Verdict.FAILOVER and len(serving.holders) == 2:
        rel = serving.relationship or {}
        pair = sorted(serving.holders, key=lambda h: h.member.name)
        keep_holder = next(
            (
                h
                for h in pair
                if (rel.get("mode") or "").lower() == "hotstandby"
                and (h.relationship or {}).get("server_role") == "Active"
            ),
            pair[0],
        )
        keep = by_id[keep_holder.member.server_id]
        if failover_management_blocker(keep) is None:
            driver = get_driver(keep.driver)
            try:
                await driver.remove_failover_scopes(  # type: ignore[attr-defined]
                    keep, name=rel.get("name"), scope_ids=[scope_id]
                )
                await driver.remove_scope(keep, scope_id)  # type: ignore[attr-defined]
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "windows_dhcp_push_scope_delete_failed",
                    scope=str(scope.id),
                    server=str(keep.id),
                    relationship=rel.get("name"),
                    error=str(exc),
                )
                raise WindowsPushError(
                    f"{keep.name}: {exc} — if the scope already left relationship "
                    f"'{rel.get('name')}', the partner's copy is gone and {keep.name} still "
                    f"serves it alone; retry the delete."
                ) from exc
            return
    if in_relationship:
        holder = sorted(in_relationship, key=lambda h: h.member.name)[0]
        rel = holder.relationship or {}
        raise WindowsServingRefused(
            f"Scope {net} is in Windows failover relationship '{rel.get('name')}' "
            f"({holder.member.name} ↔ {rel.get('partner_server') or 'its partner'}), and "
            f"Windows will not delete a scope that belongs to a failover relationship. "
            f"Take it out of the relationship first — Remove-DhcpServerv4FailoverScope "
            f"-ComputerName {holder.member.name} -Name '{rel.get('name')}' -ScopeId "
            f"{scope_id} deletes the partner's copy and keeps {holder.member.name}'s — "
            f"then delete it here."
            + (
                " (SpatiumDDI does that step itself when both partners are in this group "
                "and the server's WinRM transport is CredSSP.)"
                if serving.verdict is Verdict.FAILOVER
                else ""
            ),
            status_code=409,
        )
    if serving.verdict is Verdict.UNKNOWN:
        raise WindowsServingRefused(
            f"Refusing to delete scope {net}: {serving.detail} A scope in a failover "
            f"relationship cannot be deleted without first being taken out of it, "
            f"and deleting it from some holders but not others would leave the "
            f"survivors serving it alone.",
            status_code=409,
        )
    for holder in serving.holders:
        server = by_id[holder.member.server_id]
        driver = get_driver(server.driver)
        try:
            await driver.remove_scope(server, scope_id)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "windows_dhcp_push_scope_delete_failed",
                scope=str(scope.id),
                server=str(server.id),
                error=str(exc),
            )
            raise WindowsPushError(str(exc)) from exc


async def push_scope_restore(db: AsyncSession, scope: DHCPScope) -> None:
    """Re-create a restored scope, plus its pools and reservations, on Windows members.

    The counterpart to :func:`push_scope_delete` firing on the soft-delete path
    (#616). Soft-delete removes the scope from the Windows box; a restore has to
    put it back, or the operator gets it back in SpatiumDDI only and the two
    silently diverge — the exact drift the write-through exists to prevent.

    Best-effort per child, unlike the edit paths: a restore is a recovery
    action, and one un-pushable child (e.g. a ``reserved`` pool, which Windows
    has no equivalent for) must not wedge the whole thing. Failures are logged;
    the operator can re-sync. The DB restore is authoritative either way.

    Callers must invoke this *after* the rows are un-stamped, so the scope
    lookups inside the per-object helpers resolve.

    On a group with two or more Windows members a restore is a create with
    no placement (#1110): it goes into the one failover relationship the
    members share, when there is exactly one SpatiumDDI can drive, and is
    refused otherwise — putting the scope back on every member is the
    uncoordinated serving the refusal exists to prevent. A refusal lands in
    the best-effort log below; the DB restore still succeeds, and the
    operator re-saves the scope with a placement.
    """
    # Cloud/REST members: one whole-object rebuild re-creates the scope, its
    # pools and its reservations in a single push (the rows are un-stamped by
    # now, so the rebuild sees them). Best-effort like the Windows path below.
    try:
        await push_cloud_scope_upsert(db, scope)
    except Exception as exc:  # noqa: BLE001 — recovery action, don't wedge restore
        logger.warning(
            "cloud_dhcp_push_scope_restore_failed",
            scope=str(scope.id),
            error=str(exc),
        )

    win_servers = await _windows_servers_for_group(db, scope.group_id)
    if not win_servers:
        return

    # Best-effort INCLUDING the scope itself. push_scope_upsert raises
    # WindowsPushError (a 502) on failure, which would propagate out of the trash
    # restore handler and roll the DB restore back — so an unreachable Windows
    # member would make the row unrestorable, which is the opposite of what a
    # recovery action should do. Log and bail: the children cannot land if the
    # scope isn't there, so continuing would only add noise.
    try:
        await push_scope_upsert(db, scope)
    except Exception as exc:  # noqa: BLE001 — best-effort, see docstring
        logger.warning(
            "windows_dhcp_push_scope_restore_scope_failed",
            scope=str(scope.id),
            error=str(exc),
        )
        return

    pools = (
        (await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id))).scalars().all()
    )
    for pool in pools:
        if pool.pool_type == "dynamic":
            # Already covered — a dynamic range is a scope property on Windows
            # and push_scope_upsert re-applied it.
            continue
        try:
            await push_pool_change(db, pool, action="create")
        except Exception as exc:  # noqa: BLE001 — best-effort, see docstring
            logger.warning(
                "windows_dhcp_push_scope_restore_pool_failed",
                scope=str(scope.id),
                pool=str(pool.id),
                error=str(exc),
            )

    statics = (
        (
            await db.execute(
                select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
            )
        )
        .scalars()
        .all()
    )
    for st in statics:
        try:
            await push_static_change(db, st, action="create")
        except Exception as exc:  # noqa: BLE001 — best-effort, see docstring
            logger.warning(
                "windows_dhcp_push_scope_restore_static_failed",
                scope=str(scope.id),
                static=str(st.id),
                error=str(exc),
            )


async def push_pool_change(
    db: AsyncSession,
    pool: DHCPPool,
    *,
    action: str,
    prev_start: str | None = None,
    prev_end: str | None = None,
) -> None:
    """Push a pool create/update/delete to the Windows members that hold the scope.

    * ``dynamic`` pool → scope StartRange/EndRange; push via apply_scope.
    * ``excluded`` pool → exclusion range; push via apply_exclusion /
      remove_exclusion.
    * ``reserved`` pool → Windows has no direct equivalent. Refuse.
    """
    scope = await db.get(DHCPScope, pool.scope_id)
    if scope is None:
        return
    # Cloud/REST members (FortiGate) — any pool change re-pushes the whole scope
    # object (ip-range + exclude-range rebuilt from DB), covering every pool_type
    # incl. reserved. On delete the row isn't removed from the DB until after
    # this call, so exclude it explicitly. Runs before the Windows early-return
    # and the Windows-only reserved-pool refusal below.
    await push_cloud_scope_upsert(
        db, scope, exclude_pool_ids={pool.id} if action == "delete" else None
    )

    win_servers = await _windows_servers_for_group(db, scope.group_id)
    if not win_servers:
        return

    if pool.pool_type == "reserved":
        raise WindowsPushError(
            "Windows DHCP has no equivalent for pool_type='reserved'. "
            "Use individual reservations (static assignments) instead."
        )

    net = await _scope_cidr(db, scope)
    scope_id = str(net.network_address)

    # Dynamic pools → the Start/End range is a scope property on Windows, so
    # re-push the scope (member planning, #1110, happens inside).
    if pool.pool_type == "dynamic":
        await push_scope_upsert(db, scope)
        return

    # Removing (or moving) an exclusion widens every holder's range, which on
    # a split scope can make the halves overlap (#1110). Adding one only
    # narrows, so a create needs no probe.
    widens = action == "delete" or (
        action == "update"
        and prev_start
        and prev_end
        and (prev_start, prev_end) != (str(pool.start_ip), str(pool.end_ip))
    )
    if widens and len(win_servers) > 1:
        serving, probes = await _probe_serving(win_servers, net)
        dropped = (
            (str(pool.start_ip), str(pool.end_ip))
            if action == "delete"
            else (str(prev_start), str(prev_end))
        )
        added = None if action == "delete" else (str(pool.start_ip), str(pool.end_ip))
        if _split_collapses(serving, probes, scope_id, drop_exclusion=dropped, add_exclusion=added):
            _refuse_split_collapse(
                net,
                serving,
                "remove the exclusion" if action == "delete" else "move the exclusion",
            )

    if action == "delete":
        # Removal is tolerant on the driver side (``SilentlyContinue``): a
        # member that never had the exclusion, or never had the scope, is
        # already in the desired state.
        for server in win_servers:
            driver = get_driver(server.driver)
            try:
                await driver.remove_exclusion(  # type: ignore[attr-defined]
                    server,
                    scope_id=scope_id,
                    start_ip=str(pool.start_ip),
                    end_ip=str(pool.end_ip),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "windows_dhcp_push_pool_failed",
                    pool=str(pool.id),
                    scope=str(scope.id),
                    action=action,
                    error=str(exc),
                )
                raise WindowsPushError(str(exc)) from exc
        return

    async def _write(server: DHCPServer) -> bool | None:
        driver = get_driver(server.driver)
        if action == "update" and prev_start and prev_end:
            if prev_start != str(pool.start_ip) or prev_end != str(pool.end_ip):
                await driver.remove_exclusion(  # type: ignore[attr-defined]
                    server,
                    scope_id=scope_id,
                    start_ip=prev_start,
                    end_ip=prev_end,
                )
        applied: bool | None = await driver.apply_exclusion(  # type: ignore[attr-defined]
            server,
            scope_id=scope_id,
            start_ip=str(pool.start_ip),
            end_ip=str(pool.end_ip),
        )
        return applied

    await _apply_to_members(
        win_servers,
        net,
        "exclusion range",
        _write,
        log_event="windows_dhcp_push_pool_failed",
        log_fields={"pool": str(pool.id), "scope": str(scope.id), "action": action},
    )


async def push_static_change(
    db: AsyncSession,
    static: DHCPStaticAssignment,
    *,
    action: str,
    prev_mac: str | None = None,
    prev_ip: str | None = None,
) -> None:
    """Push a static assignment change to the Windows members that hold the scope.

    #426: ``prev_ip`` lets an IP-only edit (MAC unchanged) work. Windows
    keys reservations by ClientId (MAC) and ``Set-DhcpServerv4Reservation
    -IPAddress`` cannot relocate a reservation's IP, so an IP change must
    be a remove-then-add — otherwise the DB advances while Windows keeps
    the old IP (silent drift).
    """
    scope = await db.get(DHCPScope, static.scope_id)
    if scope is None:
        return
    # Cloud/REST members (FortiGate) — a static change re-pushes the whole scope
    # object (reserved-address rebuilt from DB). On delete the row isn't removed
    # from the DB until after this call, so exclude it explicitly.
    await push_cloud_scope_upsert(
        db, scope, exclude_static_ids={static.id} if action == "delete" else None
    )

    win_servers = await _windows_servers_for_group(db, scope.group_id)
    if not win_servers:
        return

    net = await _scope_cidr(db, scope)
    scope_id = str(net.network_address)

    if action == "delete":
        # Tolerant on the driver side (``SilentlyContinue``): removing a
        # reservation from a member that does not hold it — or does not hold
        # the scope — leaves that member exactly as it should be.
        for server in win_servers:
            driver = get_driver(server.driver)
            try:
                await driver.remove_reservation(  # type: ignore[attr-defined]
                    server, scope_id=scope_id, mac_address=str(static.mac_address)
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "windows_dhcp_push_static_failed",
                    static=str(static.id),
                    scope=str(scope.id),
                    server=str(server.id),
                    action=action,
                    error=str(exc),
                )
                raise WindowsPushError(str(exc)) from exc
        return

    async def _write(server: DHCPServer) -> bool | None:
        driver = get_driver(server.driver)
        if action == "update":
            # Compare canonicalised forms so a cosmetic MAC reformat
            # (case / ':' vs '-') doesn't trigger a needless
            # remove-then-add relocation (#426).
            mac_changed = prev_mac is not None and _norm_mac(prev_mac) != _norm_mac(
                str(static.mac_address)
            )
            ip_changed = prev_ip is not None and _norm_ip(prev_ip) != _norm_ip(
                str(static.ip_address)
            )
            if mac_changed:
                # Old MAC's reservation must go; the new MAC gets a
                # fresh add below.
                await driver.remove_reservation(  # type: ignore[attr-defined]
                    server, scope_id=scope_id, mac_address=prev_mac
                )
            elif ip_changed:
                # Same MAC, moved IP — remove the existing (keyed by
                # the current MAC) then re-add at the new IP, since
                # Set- can't relocate it.
                await driver.remove_reservation(  # type: ignore[attr-defined]
                    server, scope_id=scope_id, mac_address=str(static.mac_address)
                )
        applied: bool | None = await driver.apply_reservation(  # type: ignore[attr-defined]
            server,
            scope_id=scope_id,
            ip_address=str(static.ip_address),
            mac_address=str(static.mac_address),
            hostname=static.hostname or "",
            description=static.description or "",
        )
        return applied

    await _apply_to_members(
        win_servers,
        net,
        "reservation",
        _write,
        log_event="windows_dhcp_push_static_failed",
        log_fields={"static": str(static.id), "scope": str(scope.id), "action": action},
    )


async def push_statics_bulk_delete(
    db: AsyncSession, statics: Sequence[DHCPStaticAssignment]
) -> None:
    """Batch-delete many reservations on every Windows member of each scope's group."""
    if not statics:
        return

    scope_cache: dict[Any, DHCPScope] = {}
    # Group by (server, scope) across all Windows servers in each scope's group.
    grouped: dict[tuple[Any, Any], list[DHCPStaticAssignment]] = defaultdict(list)
    server_cache: dict[Any, DHCPServer] = {}

    # Cloud/REST members (FortiGate) — re-push each affected scope's whole object
    # once, excluding the reservations being deleted (the endpoint removes the
    # rows only after this call, so a plain rebuild would still see them).
    exclude_by_scope: dict[Any, set[Any]] = defaultdict(set)
    cloud_scopes: dict[Any, DHCPScope] = {}
    for st in statics:
        sc = cloud_scopes.get(st.scope_id)
        if sc is None:
            sc = await db.get(DHCPScope, st.scope_id)
            if sc is None:
                continue
            cloud_scopes[st.scope_id] = sc
        exclude_by_scope[st.scope_id].add(st.id)
    for sid, sc in cloud_scopes.items():
        await push_cloud_scope_upsert(db, sc, exclude_static_ids=exclude_by_scope.get(sid))

    for st in statics:
        scope = scope_cache.get(st.scope_id)
        if scope is None:
            scope = await db.get(DHCPScope, st.scope_id)
            if scope is None:
                continue
            scope_cache[st.scope_id] = scope
        for server in await _windows_servers_for_group(db, scope.group_id):
            server_cache[server.id] = server
            grouped[(server.id, scope.id)].append(st)

    for (server_id, scope_id), rows in grouped.items():
        server = server_cache[server_id]
        scope = scope_cache[scope_id]
        net = await _scope_cidr(db, scope)
        driver = get_driver(server.driver)
        items = [
            RemoveReservationItem(
                scope_id=str(net.network_address),
                mac_address=str(st.mac_address),
            )
            for st in rows
        ]
        try:
            results = await driver.remove_reservations(server, items=items)  # type: ignore[attr-defined]
        except Exception as exc:  # noqa: BLE001 — whole-batch failure
            logger.warning(
                "windows_dhcp_bulk_delete_batch_failed",
                server=str(server.id),
                scope=str(scope.id),
                count=len(items),
                error=str(exc),
            )
            raise WindowsPushError(str(exc)) from exc
        errors = [r.error for r in results if not r.ok and r.error]
        if errors:
            first = errors[0]
            more = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
            raise WindowsPushError(f"{first}{more}")


__all__ = [
    "ScopePlan",
    "WindowsPlacement",
    "WindowsPushError",
    "WindowsServingRefused",
    "push_pool_change",
    "push_scope_delete",
    "push_scope_restore",
    "push_scope_upsert",
    "push_static_change",
    "push_statics_bulk_delete",
]

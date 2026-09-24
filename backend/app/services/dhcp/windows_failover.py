"""Windows DHCP failover awareness (#1110).

SpatiumDDI's group model says every member of a DHCP server group serves
every scope of the group. For Kea that is what the HA hook makes true. For
Windows it is only true when a **failover relationship** covers the scope —
a first-class named object with its own explicit scope list. Two Windows
servers holding the same scope WITHOUT one are two independent DHCP
servers handing out the same addresses: duplicate address assignment, with
nothing on either server reporting a problem.

This module decides which of those a scope is. It is split in two:

* **The classifier** (``classify_serving``) is pure — no DB, no WinRM. It
  takes, per Windows member of the group, whether the member holds the
  scope, whether it is active there, over which range, and which failover
  relationship (if any) covers it, and returns a ``Verdict``. The
  write-through feeds it a live probe; the topology poll, the API and the
  MCP tool feed it the persisted observations. One classifier, so the
  refusal an operator gets and the badge they see cannot disagree.
* **The observation store** (``record_*`` / ``load_*``) persists what the
  topology poll reads: ``DHCPFailoverRelationship`` and
  ``DHCPServerScopeState``, with per-server freshness on ``DHCPServer``.

What Windows replicates matters to every caller, and it is not what the
word "failover" suggests. Partners replicate **leases** continuously, over
the failover protocol. They do **not** replicate **configuration** — scope
properties, option values, exclusions, reservations — until someone runs
``Invoke-DhcpServerv4FailoverReplication`` or the console's "Replicate
Scope". Microsoft's own IPAM applies every change to both partners for that
reason, and so does the write-through here. It also means two partners
disagreeing about a scope's configuration is ordinary drift, and the
``config_hash`` on each scope observation is how it is seen.
"""

from __future__ import annotations

import enum
import hashlib
import ipaddress
import json
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import (
    DHCPFailoverRelationship,
    DHCPServer,
    DHCPServerScopeState,
)
from app.services.dhcp.normalize import norm_ip, norm_mac

WINDOWS_DRIVER = "windows_dhcp"

# How long a member's last successful scope enumeration counts as evidence
# about what it holds. Past this, an unreachable partner's last-known view
# stops claiming the scope — otherwise a partner that has been down for a
# day would keep deciding whose view of a shared scope gets imported. The
# poll's own default cadence is 15 s, so this is many missed polls, not one.
OBSERVATION_FRESH_FOR = timedelta(minutes=15)


class Verdict(enum.StrEnum):
    """How the Windows members of a group serve one scope."""

    #: No Windows member of the group holds the scope.
    NOT_ON_WINDOWS = "not_on_windows"
    #: Exactly one member holds it, outside any failover relationship.
    SINGLE = "single_server"
    #: Two members hold it and one failover relationship covers it on both.
    FAILOVER = "failover"
    #: One member holds it inside a relationship whose other side is not a
    #: member of this group (or is, but does not report the scope).
    FAILOVER_ONE_SIDED = "failover_one_sided"
    #: Two or more members hold it with no shared relationship, over address
    #: ranges that do not overlap — the pre-2012 split-scope pattern.
    SPLIT_SCOPE = "split_scope"
    #: Two or more members hold it with no shared relationship over
    #: overlapping ranges: both can hand out the same address.
    UNCOORDINATED = "uncoordinated"
    #: Two or more members hold it, but at least one member's failover
    #: relationships could not be read, so coordination is unknown.
    UNKNOWN = "unknown"


#: Verdicts under which no two servers can hand out the same address.
SAFE_VERDICTS: frozenset[Verdict] = frozenset(
    {
        Verdict.NOT_ON_WINDOWS,
        Verdict.SINGLE,
        Verdict.FAILOVER,
        Verdict.FAILOVER_ONE_SIDED,
        Verdict.SPLIT_SCOPE,
    }
)


@dataclass(frozen=True)
class Member:
    """A Windows DHCP member of the group, as the classifier needs it."""

    server_id: uuid.UUID
    name: str
    host: str


@dataclass(frozen=True)
class Holder:
    """One member that holds the scope."""

    member: Member
    is_active: bool | None
    #: The relationship covering THIS scope on this member (shaped as the
    #: driver's ``get_failover_relationships`` returns it), or None.
    relationship: dict[str, Any] | None
    #: False when this member's failover relationships could not be read —
    #: ``relationship=None`` then means "unknown", not "not covered".
    failover_known: bool
    failover_error: str | None = None
    #: The effective dynamic ranges (range minus exclusions) as integer
    #: intervals; None when not known. Only used to recognise a split scope.
    ranges: tuple[tuple[int, int], ...] | None = None
    config_hash: str | None = None


@dataclass
class ScopeServing:
    verdict: Verdict
    holders: list[Holder]
    #: The coordinated serving units: a failover pair is one unit, every
    #: other holder is a unit of its own.
    units: list[list[Holder]] = field(default_factory=list)
    #: FAILOVER / FAILOVER_ONE_SIDED: the covering relationship.
    relationship: dict[str, Any] | None = None
    #: FAILOVER: the two partners' configuration differs.
    drift: bool | None = None
    detail: str = ""

    @property
    def safe(self) -> bool:
        return self.verdict in SAFE_VERDICTS


# ── helpers ────────────────────────────────────────────────────────────


def canonical_cidr(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_network(str(value), strict=False))
    except (ValueError, TypeError):
        return None


def scope_id_of(cidr: str) -> str:
    """Windows' ``ScopeId`` for a CIDR — its network address."""
    return str(ipaddress.ip_network(cidr, strict=False).network_address)


def effective_ranges(
    start_ip: Any, end_ip: Any, exclusions: Iterable[Sequence[Any]]
) -> tuple[tuple[int, int], ...] | None:
    """``[start, end]`` minus every exclusion, as sorted integer intervals."""
    try:
        start = int(ipaddress.ip_address(str(start_ip)))
        end = int(ipaddress.ip_address(str(end_ip)))
    except (ValueError, TypeError):
        return None
    if end < start:
        return None
    intervals: list[tuple[int, int]] = [(start, end)]
    for ex in exclusions or ():
        try:
            ex_start = int(ipaddress.ip_address(str(ex[0])))
            ex_end = int(ipaddress.ip_address(str(ex[1])))
        except (ValueError, TypeError, IndexError):
            continue
        nxt: list[tuple[int, int]] = []
        for lo, hi in intervals:
            if ex_end < lo or ex_start > hi:
                nxt.append((lo, hi))
                continue
            if ex_start > lo:
                nxt.append((lo, ex_start - 1))
            if ex_end < hi:
                nxt.append((ex_end + 1, hi))
        intervals = nxt
    return tuple(sorted(intervals))


def ranges_overlap(a: Sequence[tuple[int, int]], b: Sequence[tuple[int, int]]) -> bool:
    """Do two sets of integer address intervals share any address?"""
    return any(lo1 <= hi2 and lo2 <= hi1 for lo1, hi1 in a for lo2, hi2 in b)


def _partner_matches(partner: str, member: Member) -> bool:
    """Does a relationship's ``PartnerServer`` name this member?

    ``PartnerServer`` is whatever the relationship was created with — an
    FQDN, a short name, or an address — and ``DHCPServer.host`` is whatever
    the operator typed. Positive matches only: this is used to rule a
    pairing OUT, so a false negative costs nothing but a false positive
    would split a real pair.
    """
    p = (partner or "").strip().lower().rstrip(".")
    if not p:
        return False
    for candidate in (member.host, member.name):
        c = (candidate or "").strip().lower().rstrip(".")
        if not c:
            continue
        if p == c:
            return True
        p_is_ip = _is_ip(p)
        c_is_ip = _is_ip(c)
        if not p_is_ip and not c_is_ip and p.split(".")[0] == c.split(".")[0]:
            return True
    return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def partner_member(relationship: dict[str, Any], members: Sequence[Member]) -> Member | None:
    """The group member a relationship's ``PartnerServer`` names, if exactly one."""
    hits = [m for m in members if _partner_matches(relationship.get("partner_server", ""), m)]
    return hits[0] if len(hits) == 1 else None


def _points_elsewhere(holder: Holder, other: Holder, members: Sequence[Member]) -> bool:
    """``holder``'s relationship names a THIRD member of the group as partner."""
    rel = holder.relationship or {}
    target = partner_member(rel, members)
    return target is not None and target.server_id not in {
        holder.member.server_id,
        other.member.server_id,
    }


def _paired(a: Holder, b: Holder, members: Sequence[Member]) -> bool:
    """One failover relationship covers the scope on both ``a`` and ``b``.

    Both partners report a relationship under the same name, so matching
    names across the two is the evidence — it needs no hostname matching,
    which is what makes it robust to ``PartnerServer`` being spelled
    differently from the ``host`` SpatiumDDI dials. The one thing it cannot
    see is two DIFFERENT pairs in one group that happen to share a
    relationship name; that is ruled out by either side positively naming a
    third member as its partner.
    """
    ra, rb = a.relationship, b.relationship
    if not ra or not rb or ra.get("name") != rb.get("name"):
        return False
    return not (_points_elsewhere(a, b, members) or _points_elsewhere(b, a, members))


def _names(holders: Iterable[Holder]) -> str:
    items = sorted(h.member.name for h in holders)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _mode_label(rel: dict[str, Any]) -> str:
    mode = (rel.get("mode") or "").lower()
    if mode == "loadbalance":
        pct = rel.get("load_balance_percent")
        return f"load balance {pct}%" if pct is not None else "load balance"
    if mode == "hotstandby":
        return "hot standby"
    return rel.get("mode") or "unknown mode"


# ── the classifier ─────────────────────────────────────────────────────


def classify_serving(holders: Sequence[Holder], members: Sequence[Member]) -> ScopeServing:
    """Decide how the group's Windows members serve one scope.

    ``holders`` are the members that hold the scope (present, whatever its
    state); ``members`` is every Windows member of the group, used to
    resolve relationship partners.
    """
    holders = list(holders)
    if not holders:
        return ScopeServing(
            verdict=Verdict.NOT_ON_WINDOWS,
            holders=[],
            detail="No Windows DHCP server in this group reports this scope.",
        )

    # Union the holders that share a relationship; a pair is one unit.
    parent = list(range(len(holders)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(holders)):
        for j in range(i + 1, len(holders)):
            if _paired(holders[i], holders[j], members):
                parent[find(j)] = find(i)
    grouped: dict[int, list[Holder]] = {}
    for i, h in enumerate(holders):
        grouped.setdefault(find(i), []).append(h)
    units: list[list[Holder]] = []
    for comp in grouped.values():
        # A relationship spans exactly two servers. Three holders all claiming
        # the same relationship name is not a pair — treat each on its own.
        if len(comp) <= 2:
            units.append(comp)
        else:
            units.extend([h] for h in comp)

    if len(units) == 1:
        unit = units[0]
        if len(unit) == 2:
            a, b = sorted(unit, key=lambda h: h.member.name)
            rel = a.relationship or {}
            drift: bool | None = None
            if a.config_hash and b.config_hash:
                drift = a.config_hash != b.config_hash
            detail = (
                f"Coordinated by failover relationship '{rel.get('name')}' "
                f"({a.member.name} ↔ {b.member.name}, {_mode_label(rel)}). "
                f"SpatiumDDI writes changes to both partners: Windows keeps leases "
                f"in sync between them, but not configuration."
            )
            if drift:
                detail += (
                    " The two partners' configuration of this scope currently "
                    "differs — re-save it here to write SpatiumDDI's configuration to "
                    "both, or replicate one partner's over the other (Replicate on the "
                    "group's Windows failover panel, or "
                    "Invoke-DhcpServerv4FailoverReplication on Windows)."
                )
            return ScopeServing(
                verdict=Verdict.FAILOVER,
                holders=holders,
                units=units,
                relationship=rel,
                drift=drift,
                detail=detail,
            )
        only = unit[0]
        if only.relationship:
            rel = only.relationship
            partner = rel.get("partner_server") or "its partner"
            peer = partner_member(rel, members)
            where = (
                f"{peer.name} is in this group but does not report the scope"
                if peer is not None and peer.server_id != only.member.server_id
                else f"{partner} is not a member of this group"
            )
            return ScopeServing(
                verdict=Verdict.FAILOVER_ONE_SIDED,
                holders=holders,
                units=units,
                relationship=rel,
                detail=(
                    f"{only.member.name} has this scope in failover relationship "
                    f"'{rel.get('name')}' with {partner}, and {where}. Changes made "
                    f"here reach {only.member.name} only; Windows does not replicate "
                    f"configuration to the partner on its own."
                ),
            )
        return ScopeServing(
            verdict=Verdict.SINGLE,
            holders=holders,
            units=units,
            detail=(
                f"Served by {only.member.name} only. It is not in a failover "
                f"relationship, so no other server hands out its addresses."
            ),
        )

    # Two or more independent serving units.
    unknown = [h for h in holders if not h.failover_known]
    if unknown:
        why = "; ".join(f"{h.member.name}: {h.failover_error}" for h in unknown if h.failover_error)
        return ScopeServing(
            verdict=Verdict.UNKNOWN,
            holders=holders,
            units=units,
            detail=(
                f"Held by {_names(holders)}, but the failover relationships of "
                f"{_names(unknown)} could not be read"
                + (f" ({why})" if why else "")
                + ", so whether these servers coordinate is unknown."
            ),
        )

    unit_ranges: list[tuple[tuple[int, int], ...] | None] = []
    for unit in units:
        merged: list[tuple[int, int]] = []
        known = True
        for h in unit:
            if h.ranges is None:
                known = False
                break
            merged.extend(h.ranges)
        unit_ranges.append(tuple(merged) if known else None)
    disjoint = all(r is not None for r in unit_ranges) and not any(
        ranges_overlap(unit_ranges[i] or (), unit_ranges[j] or ())
        for i in range(len(unit_ranges))
        for j in range(i + 1, len(unit_ranges))
    )
    if disjoint:
        return ScopeServing(
            verdict=Verdict.SPLIT_SCOPE,
            holders=holders,
            units=units,
            detail=(
                f"Held by {_names(holders)} with no failover relationship between "
                f"them, over address ranges that do not overlap — a split scope. "
                f"No address is handed out twice, but SpatiumDDI models one scope "
                f"per group with one set of exclusions, so it cannot represent each "
                f"server's half: put each server in its own server group."
            ),
        )
    return ScopeServing(
        verdict=Verdict.UNCOORDINATED,
        holders=holders,
        units=units,
        detail=(
            f"Held by {_names(holders)} with no failover relationship covering it on "
            f"both, over overlapping address ranges: each server can hand out the "
            f"same address to a different client. Put the scope in a failover "
            f"relationship, or remove it from all but one server."
        ),
    )


# ── configuration fingerprint ──────────────────────────────────────────


def scope_config_hash(wscope: dict[str, Any]) -> str:
    """sha256 over the parts of a scope two failover partners should agree on.

    Takes the neutral scope dict ``get_scopes`` emits. Covers the dynamic
    range, exclusions, reservations (MAC → address), option values, lease
    time and state — what ``Invoke-DhcpServerv4FailoverReplication`` copies
    and what changes what a client is handed. Names and descriptions are left
    out: a cosmetic difference is not worth an operator-facing drift warning.
    """
    dynamic: list[list[str]] = []
    excluded: list[list[str]] = []
    for pool in wscope.get("pools") or []:
        pair = [norm_ip(str(pool.get("start_ip", ""))), norm_ip(str(pool.get("end_ip", "")))]
        if (pool.get("pool_type") or "dynamic") == "excluded":
            excluded.append(pair)
        else:
            dynamic.append(pair)
    reservations = sorted(
        [norm_mac(str(st.get("mac_address", ""))), norm_ip(str(st.get("ip_address", "")))]
        for st in wscope.get("statics") or []
    )
    options = wscope.get("options") or {}
    payload = {
        "range": sorted(dynamic),
        "exclusions": sorted(excluded),
        "reservations": reservations,
        "options": {k: options[k] for k in sorted(options)},
        "lease_time": wscope.get("lease_time"),
        "active": bool(wscope.get("is_active", True)),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _wire_range(wscope: dict[str, Any]) -> tuple[str | None, str | None, list[list[str]]]:
    start = end = None
    exclusions: list[list[str]] = []
    for pool in wscope.get("pools") or []:
        if (pool.get("pool_type") or "dynamic") == "excluded":
            exclusions.append([str(pool["start_ip"]), str(pool["end_ip"])])
        elif start is None:
            start, end = str(pool["start_ip"]), str(pool["end_ip"])
    return start, end, sorted(exclusions)


# ── observation store ──────────────────────────────────────────────────


_REL_FIELDS = (
    "partner_server",
    "mode",
    "server_role",
    "state",
    "load_balance_percent",
    "reserve_percent",
    "max_client_lead_time_seconds",
    "state_switch_interval_seconds",
    "auto_state_transition",
    "enable_auth",
    "scope_ids",
)


def _rel_values(rel: dict[str, Any]) -> dict[str, Any]:
    values = {f: rel.get(f) for f in _REL_FIELDS}
    values["partner_server"] = values["partner_server"] or ""
    values["scope_ids"] = list(values["scope_ids"] or [])
    return values


async def record_failover_observation(
    db: AsyncSession, server: DHCPServer, result: dict[str, Any], *, now: datetime
) -> None:
    """Persist one successful — or failed — failover read for ``server``.

    A successful read replaces the server's relationship rows: updated in
    place where the name persists (so an unchanged relationship is not
    written), deleted where it no longer exists. A FAILED read changes no row
    and does not move ``failover_observed_at``; it only records why, so the
    last-known relationships stay in force and visibly stale rather than
    vanishing — "the read was denied" must not become "there is no failover".
    """
    if not result.get("ok"):
        server.failover_error = str(result.get("error") or "failover read failed")[:2000]
        return
    existing = {
        row.name: row
        for row in (
            await db.execute(
                select(DHCPFailoverRelationship).where(
                    DHCPFailoverRelationship.server_id == server.id
                )
            )
        )
        .scalars()
        .all()
    }
    seen: set[str] = set()
    for rel in result.get("relationships") or []:
        name = rel["name"]
        seen.add(name)
        values = _rel_values(rel)
        row = existing.get(name)
        if row is None:
            db.add(DHCPFailoverRelationship(server_id=server.id, name=name, **values))
            continue
        for key, value in values.items():
            if getattr(row, key) != value:
                setattr(row, key, value)
    for name, row in existing.items():
        if name not in seen:
            await db.delete(row)
    server.failover_observed_at = now
    server.failover_error = None


async def record_scope_observation(
    db: AsyncSession, server: DHCPServer, wire_scopes: Sequence[dict[str, Any]], *, now: datetime
) -> None:
    """Persist which scopes ``server`` holds, from one successful ``get_scopes``.

    An EMPTY wire records nothing and does not move ``scopes_observed_at``:
    it is indistinguishable from an enumeration that failed quietly (the
    #482 ambiguity), and letting the server's view go stale — so it stops
    counting as a holder of anything — is the safe reading of it, where
    deleting its rows would be a claim.
    """
    wire: dict[str, dict[str, Any]] = {}
    for wscope in wire_scopes:
        cidr = canonical_cidr(wscope.get("subnet_cidr"))
        if cidr is None or cidr in wire:
            continue
        start, end, exclusions = _wire_range(wscope)
        wire[cidr] = {
            "is_active": bool(wscope.get("is_active", True)),
            "start_ip": start,
            "end_ip": end,
            "exclusions": exclusions,
            "config_hash": scope_config_hash(wscope),
        }
    if not wire:
        return
    rows = (
        (
            await db.execute(
                select(DHCPServerScopeState).where(DHCPServerScopeState.server_id == server.id)
            )
        )
        .scalars()
        .all()
    )
    existing = {canonical_cidr(r.scope_cidr): r for r in rows}
    for cidr, obs in wire.items():
        row = existing.get(cidr)
        if row is None:
            db.add(DHCPServerScopeState(server_id=server.id, scope_cidr=cidr, **obs))
            continue
        changed = (
            row.is_active != obs["is_active"]
            or _s(row.start_ip) != obs["start_ip"]
            or _s(row.end_ip) != obs["end_ip"]
            or list(row.exclusions or []) != obs["exclusions"]
            or row.config_hash != obs["config_hash"]
        )
        if changed:
            for key, value in obs.items():
                setattr(row, key, value)
    stale = [r.id for c, r in existing.items() if c not in wire]
    if stale:
        await db.execute(sa_delete(DHCPServerScopeState).where(DHCPServerScopeState.id.in_(stale)))
    server.scopes_observed_at = now


def _s(value: Any) -> str | None:
    return None if value is None else str(value)


def is_fresh(observed_at: datetime | None, now: datetime) -> bool:
    return observed_at is not None and now - observed_at <= OBSERVATION_FRESH_FOR


@dataclass
class GroupObservations:
    """Everything persisted about a group's Windows members, loaded once."""

    members: list[Member]
    servers: dict[uuid.UUID, DHCPServer]
    #: server_id → {canonical cidr → scope state row}
    scopes: dict[uuid.UUID, dict[str, DHCPServerScopeState]]
    #: server_id → relationship rows
    relationships: dict[uuid.UUID, list[DHCPFailoverRelationship]]

    def relationship_covering(self, server_id: uuid.UUID, cidr: str) -> dict[str, Any] | None:
        sid = scope_id_of(cidr)
        for rel in self.relationships.get(server_id, []):
            if sid in (rel.scope_ids or []):
                return relationship_dict(rel)
        return None

    def holders(
        self,
        cidr: str,
        *,
        now: datetime,
        fresh_only: bool = True,
        exclude: Iterable[uuid.UUID] = (),
    ) -> list[Holder]:
        excluded = set(exclude)
        out: list[Holder] = []
        for member in self.members:
            if member.server_id in excluded:
                continue
            server = self.servers[member.server_id]
            if fresh_only and not is_fresh(server.scopes_observed_at, now):
                continue
            row = self.scopes.get(member.server_id, {}).get(cidr)
            if row is None:
                continue
            out.append(
                Holder(
                    member=member,
                    is_active=row.is_active,
                    relationship=self.relationship_covering(member.server_id, cidr),
                    failover_known=server.failover_observed_at is not None,
                    failover_error=server.failover_error,
                    ranges=effective_ranges(row.start_ip, row.end_ip, row.exclusions or []),
                    config_hash=row.config_hash or None,
                )
            )
        return out


def relationship_dict(rel: DHCPFailoverRelationship) -> dict[str, Any]:
    out: dict[str, Any] = {"name": rel.name}
    for f in _REL_FIELDS:
        out[f] = getattr(rel, f)
    out["scope_ids"] = list(rel.scope_ids or [])
    return out


def member_of(server: DHCPServer) -> Member:
    return Member(server_id=server.id, name=server.name, host=server.host or "")


async def load_group_observations(db: AsyncSession, group_id: uuid.UUID) -> GroupObservations:
    servers = list(
        (
            await db.execute(
                select(DHCPServer)
                .where(
                    DHCPServer.server_group_id == group_id,
                    DHCPServer.driver == WINDOWS_DRIVER,
                )
                .order_by(DHCPServer.name)
            )
        )
        .scalars()
        .all()
    )
    ids = [s.id for s in servers]
    scopes: dict[uuid.UUID, dict[str, DHCPServerScopeState]] = {sid: {} for sid in ids}
    relationships: dict[uuid.UUID, list[DHCPFailoverRelationship]] = {sid: [] for sid in ids}
    if ids:
        for row in (
            (
                await db.execute(
                    select(DHCPServerScopeState).where(DHCPServerScopeState.server_id.in_(ids))
                )
            )
            .scalars()
            .all()
        ):
            cidr = canonical_cidr(row.scope_cidr)
            if cidr is not None:
                scopes[row.server_id][cidr] = row
        for rel in (
            (
                await db.execute(
                    select(DHCPFailoverRelationship)
                    .where(DHCPFailoverRelationship.server_id.in_(ids))
                    .order_by(DHCPFailoverRelationship.name)
                )
            )
            .scalars()
            .all()
        ):
            relationships[rel.server_id].append(rel)
    return GroupObservations(
        members=[member_of(s) for s in servers],
        servers={s.id: s for s in servers},
        scopes=scopes,
        relationships=relationships,
    )


def reconcile_owner(
    server: DHCPServer, cidr: str, obs: GroupObservations, *, now: datetime
) -> DHCPServer:
    """Whose view of a scope several members hold gets imported.

    The topology poll runs once per member, and each member's pass used to
    merge its own view of the group's scope — so when two members held the
    scope and disagreed (the ordinary state of two Windows failover partners,
    which do not sync configuration), each pass undid the other's, and every
    poll created and tore down DNS records for whatever differed.

    One owner per scope: the member, among those currently holding it
    (``server`` itself plus every OTHER member whose view is fresh), with the
    lowest name. Deterministic from either side, so both passes agree without
    talking, and an unreachable member drops out once its view goes stale
    instead of freezing the scope.
    """
    candidates = [server] + [
        obs.servers[h.member.server_id] for h in obs.holders(cidr, now=now, exclude=[server.id])
    ]
    return min(candidates, key=lambda s: (s.name, str(s.id)))


__all__ = [
    "OBSERVATION_FRESH_FOR",
    "SAFE_VERDICTS",
    "GroupObservations",
    "Holder",
    "Member",
    "ScopeServing",
    "Verdict",
    "canonical_cidr",
    "classify_serving",
    "effective_ranges",
    "is_fresh",
    "load_group_observations",
    "member_of",
    "partner_member",
    "ranges_overlap",
    "reconcile_owner",
    "record_failover_observation",
    "record_scope_observation",
    "relationship_dict",
    "scope_config_hash",
    "scope_id_of",
]

"""Target-selector resolution for Scheduled Wake-on-LAN — Phase 1
(issue #586).

Turns a schedule's stored ``target_selector`` JSONB into a concrete,
deduped, skip-annotated list of wake targets.  Backs the beat runner AND
the REST ``preview-targets`` endpoint AND the MCP
``preview_wol_schedule_targets`` tool — one resolver, three surfaces
(non-negotiables #1 / #13).

``target_selector`` shape::

    {
        "mode": "address_tags" | "subnet" | "subnet_tags" | "hosts",
        "tags": ["wake:nightly", "env:lab"],   # address_tags / subnet_tags
        "subnet_ids": [<uuid>, ...],            # subnet
        "address_ids": [<uuid>, ...],           # hosts
    }

The batch generalisation of :func:`app.services.wol.resolve_wake_params`:
same error taxonomy, but a bad host is accumulated into ``skipped`` rather
than raised so one un-wakeable row can't abort the whole run.  **Every
input match lands in exactly one of ``wakes`` / ``skipped`` — never
silently dropped** (the load-bearing behavioural rule from the recon).

Reuses shipped building blocks verbatim:

* :func:`app.services.tags.apply_tag_filter` — the ``?tag=key:value`` grammar.
* :func:`app.services.wol.normalize_mac` / ``broadcast_for_network``.
* :func:`app.services.nettools.schemas.is_blocked_target` — SSRF denylist.

Permission scoping is enforced at *resolve* time against the schedule
**owner** (non-negotiable #3) so a schedule can't wake hosts in subnets its
owner has since lost read access to.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import Select, select

from app.core.permissions import is_effective_superadmin, user_has_permission
from app.models.dhcp import DHCPLease, DHCPScope
from app.models.ipam import IPAddress, IpMacHistory, Subnet
from app.services import wol
from app.services.nettools.schemas import is_blocked_target
from app.services.tags import apply_tag_filter

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.models.auth import User

# Selector modes.
MODE_ADDRESS_TAGS = "address_tags"
MODE_SUBNET = "subnet"
MODE_SUBNET_TAGS = "subnet_tags"
MODE_HOSTS = "hosts"
VALID_MODES = frozenset({MODE_ADDRESS_TAGS, MODE_SUBNET, MODE_SUBNET_TAGS, MODE_HOSTS})
# Modes that select purely by tag — an empty tag list for these must match
# nothing, never everything (defence-in-depth behind the schema validator).
_TAG_MODES = frozenset({MODE_ADDRESS_TAGS, MODE_SUBNET_TAGS})

# Hard fan-out cap: the most magic packets one resolved schedule may dispatch.
# Matches beyond the cap are reported as ``over_cap`` skips (never silently
# dropped, never dispatched) so a mis-scoped selector can't detonate a
# platform-wide wake. Keep in sync with the operator-facing docs.
MAX_WAKE_TARGETS = 512

# Per-host skip reasons (stored on ``wol_run_target.skip_reason``).
SKIP_NO_MAC = "no_mac"
SKIP_NOT_FOUND = "not_found"
SKIP_BLOCKED_BROADCAST = "blocked_broadcast"
SKIP_INVALID_MAC = "invalid_mac"
SKIP_MULTICAST_SUBNET = "multicast_subnet"
SKIP_NO_PERMISSION = "no_permission"
SKIP_OVER_CAP = "over_cap"

# Which MAC-fallback step resolved the address.
MAC_SOURCE_IP = "ip"
MAC_SOURCE_HISTORY = "history"
MAC_SOURCE_LEASE = "lease"


@dataclass
class WakeTarget:
    """A host that WILL be sent a magic packet."""

    ip_address_id: uuid.UUID | None
    address: str | None
    mac: str
    subnet_id: uuid.UUID | None
    broadcast: str
    mac_source: str
    hostname: str | None = None


@dataclass
class SkippedTarget:
    """A matched input that will NOT be sent, with a reason."""

    reason: str
    ip_address_id: uuid.UUID | None = None
    address: str | None = None
    subnet_id: uuid.UUID | None = None


@dataclass
class ResolvedTargets:
    """The two output buckets — every input match lands in exactly one."""

    wakes: list[WakeTarget] = field(default_factory=list)
    skipped: list[SkippedTarget] = field(default_factory=list)


class InvalidSelector(ValueError):
    """Raised when ``target_selector.mode`` is missing or unknown — the API
    layer 422s on it verbatim."""


def _ip_str(value: Any) -> str:
    """Normalise an INET column value to a bare host string (drops any
    ``/32`` interface suffix) so it keys cleanly across IPAddress + DHCPLease.
    """
    return str(value).split("/", 1)[0]


def _coerce_uuids(values: Any) -> list[uuid.UUID]:
    """Best-effort coerce a selector id list into UUIDs, dropping junk."""
    out: list[uuid.UUID] = []
    for v in values or []:
        if isinstance(v, uuid.UUID):
            out.append(v)
            continue
        try:
            out.append(uuid.UUID(str(v)))
        except (ValueError, AttributeError, TypeError):
            continue
    return out


async def _readable_subnet_ids(
    db: AsyncSession, user: User, structural_conds: list[Any]
) -> list[uuid.UUID] | None:
    """Which subnets ``user`` may READ, for the resolve-time permission gate.

    Returns ``None`` for an effective superadmin ("no restriction", skip the
    ``IN()`` filter).  Otherwise enumerates candidate subnets (narrowed by the
    structural conds) and runs the authoritative per-row
    :func:`user_has_permission` check — subnets are far fewer than IPs, so this
    scales with the structural filter, not the address count.  Mirrors the
    ``ipam/router._readable_subnet_ids`` helper without importing the API layer
    into a service (layering).
    """
    if is_effective_superadmin(user):
        return None
    q = select(Subnet.id)
    for cond in structural_conds:
        q = q.where(cond)
    candidate_ids = [row[0] for row in (await db.execute(q)).all()]
    return [sid for sid in candidate_ids if user_has_permission(user, "read", "subnet", sid)]


async def _rows_for_selector(
    db: AsyncSession,
    user: User,
    selector: dict[str, Any],
    skipped: list[SkippedTarget],
) -> list[IPAddress]:
    """Resolve the selector into a list of ``IPAddress`` rows, appending any
    definite skips (``not_found`` / ``multicast_subnet`` / ``no_permission``
    for explicit ids) to ``skipped`` as it goes.

    Every mode filters ``Subnet.kind == "unicast"`` + ``Subnet.deleted_at IS
    NULL`` (multicast subnets hold no host MACs).
    """
    mode = selector.get("mode")
    if mode not in VALID_MODES:
        raise InvalidSelector(
            f"target_selector.mode must be one of {sorted(VALID_MODES)}, got {mode!r}"
        )
    tags = [t for t in (str(t) for t in (selector.get("tags") or [])) if t.strip()]

    # Defence-in-depth for the schema validator: a tag-mode selector with no
    # usable tags matches NOTHING, never every host in scope (``apply_tag_filter``
    # is a no-op on an empty list). Covers any row stored before the validator.
    if mode in _TAG_MODES and not tags:
        return []

    # Resolve-time permission gate against the schedule owner (non-negotiable
    # #3). Candidate set narrowed to unicast + not-deleted subnets.
    structural = [Subnet.kind == "unicast", Subnet.deleted_at.is_(None)]
    readable = await _readable_subnet_ids(db, user, structural)

    def _scoped[*Ts](stmt: Select[*Ts]) -> Select[*Ts]:
        if readable is not None:
            stmt = stmt.where(Subnet.id.in_(readable))
        return stmt

    if mode == MODE_ADDRESS_TAGS:
        stmt = (
            select(IPAddress)
            .join(Subnet, Subnet.id == IPAddress.subnet_id)
            .where(Subnet.kind == "unicast")
            .where(Subnet.deleted_at.is_(None))
        )
        stmt = apply_tag_filter(stmt, IPAddress.tags, tags)
        stmt = _scoped(stmt)
        return list((await db.execute(stmt)).scalars().all())

    if mode == MODE_SUBNET_TAGS:
        sub_q = select(Subnet.id).where(Subnet.kind == "unicast").where(Subnet.deleted_at.is_(None))
        sub_q = apply_tag_filter(sub_q, Subnet.tags, tags)
        stmt = (
            select(IPAddress)
            .join(Subnet, Subnet.id == IPAddress.subnet_id)
            .where(IPAddress.subnet_id.in_(sub_q))
        )
        stmt = _scoped(stmt)
        return list((await db.execute(stmt)).scalars().all())

    if mode == MODE_SUBNET:
        subnet_ids = _coerce_uuids(selector.get("subnet_ids"))
        if not subnet_ids:
            return []
        # Load the requested subnets so we can classify explicit bad ids
        # (not_found / multicast / no_permission) as skips rather than
        # silently returning nothing.
        loaded = {
            s.id: s
            for s in (
                await db.execute(
                    select(Subnet)
                    .where(Subnet.id.in_(subnet_ids))
                    .where(Subnet.deleted_at.is_(None))
                )
            )
            .scalars()
            .all()
        }
        valid: list[uuid.UUID] = []
        for sid in subnet_ids:
            sub = loaded.get(sid)
            if sub is None:
                skipped.append(SkippedTarget(reason=SKIP_NOT_FOUND, subnet_id=sid))
            elif sub.kind != "unicast":
                skipped.append(SkippedTarget(reason=SKIP_MULTICAST_SUBNET, subnet_id=sid))
            elif readable is not None and sid not in readable:
                skipped.append(SkippedTarget(reason=SKIP_NO_PERMISSION, subnet_id=sid))
            else:
                valid.append(sid)
        if not valid:
            return []
        stmt = select(IPAddress).where(IPAddress.subnet_id.in_(valid))
        return list((await db.execute(stmt)).scalars().all())

    # mode == MODE_HOSTS
    address_ids = _coerce_uuids(selector.get("address_ids"))
    if not address_ids:
        return []
    stmt = (
        select(IPAddress)
        .join(Subnet, Subnet.id == IPAddress.subnet_id)
        .where(IPAddress.id.in_(address_ids))
        .where(Subnet.kind == "unicast")
        .where(Subnet.deleted_at.is_(None))
    )
    stmt = _scoped(stmt)
    rows = list((await db.execute(stmt)).scalars().all())
    found = {r.id for r in rows}
    for aid in address_ids:
        if aid not in found:
            # Gone since the schedule was saved, sits in a multicast/deleted
            # subnet, or the owner can't read it — reported, never dropped.
            skipped.append(SkippedTarget(reason=SKIP_NOT_FOUND, ip_address_id=aid))
    return rows


async def _batch_history_macs(db: AsyncSession, ip_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
    """Newest ``ip_mac_history`` MAC per IP id, in one batched query."""
    if not ip_ids:
        return {}
    stmt = (
        select(IpMacHistory.ip_address_id, IpMacHistory.mac_address)
        .where(IpMacHistory.ip_address_id.in_(ip_ids))
        .distinct(IpMacHistory.ip_address_id)
        .order_by(IpMacHistory.ip_address_id, IpMacHistory.last_seen.desc())
    )
    return {row[0]: str(row[1]) for row in (await db.execute(stmt)).all()}


async def _batch_lease_macs(
    db: AsyncSession,
    ip_strs: list[str],
    sub_ids: list[uuid.UUID],
) -> tuple[dict[tuple[str, uuid.UUID], str], dict[str, str]]:
    """Newest active-lease MAC per (ip, subnet) and per ip (unscoped fallback).

    Returns ``(scoped_map, unscoped_map)``: prefer the scoped map (keyed on
    ``(ip_str, subnet_id)`` via the lease's scope) which disambiguates the
    same IP living in two spaces; the unscoped map (keyed on ``ip_str``) is
    only consulted when the scoped lookup came back empty for a row.

    The unscoped map holds an IP **only when a single unique active-lease MAC
    exists for it across all scopes** — an IP with active leases in more than
    one scope/subnet (overlapping RFC1918 space) is ambiguous, so it is left
    out rather than risk stamping the wrong host's MAC.
    """
    scoped: dict[tuple[str, uuid.UUID], str] = {}
    unscoped: dict[str, str] = {}
    if not ip_strs:
        return scoped, unscoped

    if sub_ids:
        scoped_stmt = (
            select(DHCPLease.ip_address, DHCPScope.subnet_id, DHCPLease.mac_address)
            .join(DHCPScope, DHCPScope.id == DHCPLease.scope_id)
            .where(DHCPLease.ip_address.in_(ip_strs))
            .where(DHCPScope.subnet_id.in_(sub_ids))
            .where(DHCPLease.state == "active")
            # A DHCPv6 lease identified by DUID alone has no MAC to wake
            # (#1141); ``str(None)`` would read as the MAC "None".
            .where(DHCPLease.mac_address.is_not(None))
            .distinct(DHCPLease.ip_address, DHCPScope.subnet_id)
            .order_by(
                DHCPLease.ip_address,
                DHCPScope.subnet_id,
                DHCPLease.last_seen_at.desc(),
            )
        )
        for ip_val, sub_id, mac_val in (await db.execute(scoped_stmt)).all():
            scoped[(_ip_str(ip_val), sub_id)] = str(mac_val)

    # Distinct (ip, mac) active-lease pairs; an IP that maps to more than one
    # MAC is ambiguous and dropped from the unscoped fallback entirely.
    unscoped_stmt = (
        select(DHCPLease.ip_address, DHCPLease.mac_address)
        .where(DHCPLease.ip_address.in_(ip_strs))
        .where(DHCPLease.state == "active")
        .where(DHCPLease.mac_address.is_not(None))
        .distinct()
    )
    macs_by_ip: dict[str, set[str]] = defaultdict(set)
    for ip_val, mac_val in (await db.execute(unscoped_stmt)).all():
        macs_by_ip[_ip_str(ip_val)].add(str(mac_val))
    unscoped = {ip: next(iter(macs)) for ip, macs in macs_by_ip.items() if len(macs) == 1}

    return scoped, unscoped


async def resolve_wol_targets(
    db: AsyncSession,
    user: User,
    selector: dict[str, Any],
) -> ResolvedTargets:
    """Resolve ``selector`` into ``(wakes, skipped)`` for the schedule owner.

    Steps (see module docstring + recon 03):

    1. Selector → ``IPAddress`` rows (permission-scoped, unicast-only).
    2. Per row, resolve a MAC via the 3-step fallback chain
       (``IPAddress.mac_address`` → newest ``ip_mac_history`` → newest active
       ``DHCPLease``), all batched (no N+1).  A MAC-less row → ``no_mac`` skip.
    3. Derive the IPv4 directed broadcast from the row's subnet; a
       loopback/link-local subnet → ``blocked_broadcast`` skip.
    4. Dedupe by ``(subnet_id or broadcast, mac)`` so a host matched two ways
       (or a v4+v6 pair sharing a MAC) is packeted once.
    """
    resolved = ResolvedTargets()
    rows = await _rows_for_selector(db, user, selector, resolved.skipped)
    if not rows:
        return resolved

    # Preload subnets for broadcast derivation (don't per-row db.get).
    sub_ids = list({r.subnet_id for r in rows})
    subnets = {
        s.id: s
        for s in (await db.execute(select(Subnet).where(Subnet.id.in_(sub_ids)))).scalars().all()
    }

    # ── MAC fallback chain, batched ──────────────────────────────────────
    # Step 1 is inline (row.mac_address). Collect the rows that miss it for
    # the batched steps 2 + 3.
    macless = [r for r in rows if not r.mac_address]
    hist_map = await _batch_history_macs(db, [r.id for r in macless])
    still_missing = [r for r in macless if r.id not in hist_map]
    lease_scoped, lease_unscoped = await _batch_lease_macs(
        db,
        [_ip_str(r.address) for r in still_missing],
        list({r.subnet_id for r in still_missing}),
    )

    # ── Broadcast cache per subnet (compute + SSRF-guard once) ───────────
    # None == subnet derives a blocked broadcast → every row there skips.
    broadcast_cache: dict[uuid.UUID, str | None] = {}

    def _broadcast_for(subnet: Subnet) -> str | None:
        if subnet.id in broadcast_cache:
            return broadcast_cache[subnet.id]
        bcast = wol.broadcast_for_network(str(subnet.network))
        result = None if is_blocked_target(bcast) else bcast
        broadcast_cache[subnet.id] = result
        return result

    seen: set[tuple[Any, str]] = set()

    for ip in rows:
        # Resolve MAC via the 3-step chain, stop at first hit.
        mac_raw: str | None = None
        mac_source = MAC_SOURCE_IP
        if ip.mac_address:
            mac_raw = str(ip.mac_address)
            mac_source = MAC_SOURCE_IP
        elif ip.id in hist_map:
            mac_raw = hist_map[ip.id]
            mac_source = MAC_SOURCE_HISTORY
        else:
            key = (_ip_str(ip.address), ip.subnet_id)
            if key in lease_scoped:
                mac_raw = lease_scoped[key]
                mac_source = MAC_SOURCE_LEASE
            elif _ip_str(ip.address) in lease_unscoped:
                mac_raw = lease_unscoped[_ip_str(ip.address)]
                mac_source = MAC_SOURCE_LEASE

        if not mac_raw:
            resolved.skipped.append(
                SkippedTarget(
                    reason=SKIP_NO_MAC,
                    ip_address_id=ip.id,
                    address=_ip_str(ip.address),
                    subnet_id=ip.subnet_id,
                )
            )
            continue

        try:
            mac = wol.normalize_mac(mac_raw)
        except ValueError:
            resolved.skipped.append(
                SkippedTarget(
                    reason=SKIP_INVALID_MAC,
                    ip_address_id=ip.id,
                    address=_ip_str(ip.address),
                    subnet_id=ip.subnet_id,
                )
            )
            continue

        subnet = subnets.get(ip.subnet_id)
        if subnet is None:
            # Subnet vanished mid-resolve — treat as not_found rather than
            # dropping the row.
            resolved.skipped.append(
                SkippedTarget(
                    reason=SKIP_NOT_FOUND,
                    ip_address_id=ip.id,
                    address=_ip_str(ip.address),
                    subnet_id=ip.subnet_id,
                )
            )
            continue

        broadcast = _broadcast_for(subnet)
        if broadcast is None:
            resolved.skipped.append(
                SkippedTarget(
                    reason=SKIP_BLOCKED_BROADCAST,
                    ip_address_id=ip.id,
                    address=_ip_str(ip.address),
                    subnet_id=ip.subnet_id,
                )
            )
            continue

        # Dedupe by (segment, MAC) — one packet per MAC per segment.
        dedupe_key = (ip.subnet_id or broadcast, mac)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        # Hard fan-out cap: a distinct, deduped host past the ceiling is
        # reported as an ``over_cap`` skip — never dispatched, never dropped.
        if len(resolved.wakes) >= MAX_WAKE_TARGETS:
            resolved.skipped.append(
                SkippedTarget(
                    reason=SKIP_OVER_CAP,
                    ip_address_id=ip.id,
                    address=_ip_str(ip.address),
                    subnet_id=ip.subnet_id,
                )
            )
            continue

        resolved.wakes.append(
            WakeTarget(
                ip_address_id=ip.id,
                address=_ip_str(ip.address),
                mac=mac,
                subnet_id=ip.subnet_id,
                broadcast=broadcast,
                mac_source=mac_source,
                hostname=ip.hostname,
            )
        )

    return resolved


def group_by_segment(
    wakes: list[WakeTarget],
) -> dict[Any, list[WakeTarget]]:
    """Group resolved wakes by L2 segment (``subnet_id`` when present, else
    the derived broadcast) so the dispatcher can pick a per-segment appliance
    NIC and stagger sanely across segments."""
    grouped: dict[Any, list[WakeTarget]] = defaultdict(list)
    for target in wakes:
        grouped[target.subnet_id or target.broadcast].append(target)
    return dict(grouped)

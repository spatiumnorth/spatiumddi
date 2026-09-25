"""Subnet split — divide a subnet into 2^k aligned children at a longer prefix.

Preview computes the per-child allocation map (which IP / DNS / DHCP rows
land in which child) plus a structured ``conflicts[]`` of any reason the
commit would fail; commit re-runs preview under a pg advisory lock and
performs the split as a single transaction.

Design rules the commit path enforces:

1. **Strictly longer prefix.** ``new_prefix_length > old_prefix_length``
   and ``≤ 30`` for v4 / ``≤ 126`` for v6 (we don't split into PtP /31s
   or /127s automatically — operators who want that should make the
   subnet themselves).
2. **Same address family.** Output children inherit the parent's family.
3. **Children inherit the parent's metadata.** ``vlan_id`` /
   ``vxlan_id`` / ``vlan_ref_id`` / ``custom_fields`` / ``tags`` /
   DDNS / DHCP / DNS group settings / ``router_zone_id`` / ``status``.
   ``name`` / ``description`` are not inherited — children get an
   empty name (operator can rename).
4. **Default-named placeholder rows are recreated at child boundaries.**
   The ``network`` / ``broadcast`` rows that ``POST /ipam/subnets``
   normally inserts are deleted on the parent and re-emitted on each
   child. Renamed / DNS-bearing rows survive verbatim and get
   reattached to whichever child contains the IP — operator intent
   wins (e.g. an ``anycast-vip`` row at the old broadcast).
5. **DHCP scopes attach cleanly.** A scope on the parent subnet may
   either be wholly contained in exactly one child (great — re-bind)
   or straddle a child boundary. The latter is a conflict; we don't
   silently slice a scope into two. Pools / exclusions / statics
   follow the scope they belong to (and their boundaries are checked
   against the child boundaries before commit).
6. **DNS zone bindings carry over.** ``SubnetDomain`` rows on the
   parent are duplicated onto each child so each child keeps the
   same primary + additional zones.
7. **Parent is deleted last.** All child rows must commit before the
   parent's ``ondelete=RESTRICT`` references go away.

This module is reused by the ``/subnets/{subnet_id}/split/preview`` and
``/split/commit`` endpoints. The router stays thin; everything below
is callable from a Celery task or a script if we ever want a "bulk
split" operator action.
"""

from __future__ import annotations

import ipaddress
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dhcp_server_channel
from app.drivers.dhcp import is_agentless
from app.models.dhcp import (
    DHCPConfigOp,
    DHCPLease,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPStaticAssignment,
)
from app.models.ipam import IPAddress, Subnet, SubnetDomain
from app.services.dhcp.config_bundle import build_config_bundle

logger = structlog.get_logger(__name__)

# Distinct from the resize advisory-lock namespace so a split + a resize on
# different subnets don't accidentally serialise on each other. Same key
# domain (CRC32 of the subnet UUID) so split-and-resize on the same subnet
# *do* contend on the same lock — that's the right behaviour: a resize
# while a split is mid-flight is a recipe for corruption.
_LOCK_NS_SPLIT = 0x49504D33  # "IPM3"


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class SplitConflict:
    type: str
    detail: str


@dataclass
class SplitChildPreview:
    cidr: str
    allocations_count: int
    """IP addresses (any status) that fall inside this child."""
    placeholders_default_named: int
    """``network`` / ``broadcast`` rows on the parent that match this
    child's boundaries. They will be recreated on commit (as new rows
    on the child)."""
    placeholders_renamed: int
    """``network`` / ``broadcast`` rows on the parent at this child's
    boundary that the operator renamed (or attached DNS to) — these
    survive verbatim and are reparented to the child."""
    dhcp_scope_id: uuid.UUID | None
    """The parent's DHCP scope, if any, that fits cleanly inside this
    child. Null when the parent has no scope or the parent's scope
    straddles multiple children."""
    dhcp_pool_count: int
    dhcp_static_count: int
    dns_record_count: int
    """Count of forward A/AAAA records linked to IPs in this child."""


@dataclass
class SubnetSplitPreview:
    parent_cidr: str
    new_prefix_length: int
    children: list[SplitChildPreview] = field(default_factory=list)
    conflicts: list[SplitConflict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SubnetSplitResult:
    parent_cidr: str
    children: list[Subnet]
    summary: list[str]


class SplitError(Exception):
    """Raised by the service when validation fails. Carries an HTTP status hint."""

    def __init__(self, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.status_code = status_code


def _parse_cidr(value: str, *, label: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SplitError(f"Invalid CIDR for {label}: {value}", status_code=422) from exc


def _validate_split(parent: IPNetwork, new_prefix: int) -> None:
    if new_prefix <= parent.prefixlen:
        raise SplitError(
            f"new_prefix_length must be strictly greater than the parent's "
            f"/{parent.prefixlen} (got /{new_prefix}).",
            status_code=422,
        )
    if isinstance(parent, ipaddress.IPv4Network):
        if new_prefix > 30:
            raise SplitError(
                "new_prefix_length must be ≤ 30 for IPv4 (split does not "
                "produce /31 or /32 children automatically).",
                status_code=422,
            )
    else:
        if new_prefix > 126:
            raise SplitError(
                "new_prefix_length must be ≤ 126 for IPv6.",
                status_code=422,
            )


def _children_of(parent: IPNetwork, new_prefix: int) -> list[IPNetwork]:
    return list(parent.subnets(new_prefix=new_prefix))


def _is_default_placeholder(row: IPAddress) -> bool:
    """Match ``_load_boundary_placeholders`` from resize.py — a row is
    "default-named" (safe to recreate) iff it has no operator
    customisation. Anything with a custom hostname / description, or
    with a DNS record attached, counts as renamed and survives verbatim.
    """
    if row.status not in ("network", "broadcast"):
        return False
    is_user_named = bool(row.hostname) and row.hostname not in ("network", "broadcast")
    has_custom_desc = row.description not in (
        "",
        "Network address",
        "Broadcast address",
    )
    if is_user_named or has_custom_desc or row.dns_record_id is not None:
        return False
    return True


def _ip_in(child: IPNetwork, addr_str: str) -> bool:
    try:
        return ipaddress.ip_address(addr_str) in child
    except ValueError:
        return False


def _advisory_lock_key(resource_id: uuid.UUID) -> tuple[int, int]:
    key = zlib.crc32(str(resource_id).encode("utf-8"))
    if key >= 2**31:
        key -= 2**32
    return (_LOCK_NS_SPLIT, key)


async def _try_advisory_lock(db: AsyncSession, resource_id: uuid.UUID) -> bool:
    ns, key = _advisory_lock_key(resource_id)
    row: bool = (
        await db.execute(
            text("SELECT pg_try_advisory_xact_lock(:ns, :key)"),
            {"ns": ns, "key": key},
        )
    ).scalar_one()
    return bool(row)


# ── Preview ──────────────────────────────────────────────────────────────────


async def preview_subnet_split(
    db: AsyncSession,
    subnet: Subnet,
    new_prefix_length: int,
) -> SubnetSplitPreview:
    """Pure read; safe to call from GET-style flows.

    Conflicts are accumulated (not raised) so the UI can render the
    full preview even when the commit would fail. The router lifts
    them into HTTP 200 with conflicts populated; the user gets to see
    why before clicking the button.
    """
    conflicts: list[SplitConflict] = []
    warnings: list[str] = []

    try:
        parent = _parse_cidr(str(subnet.network), label="subnet")
    except SplitError as exc:
        return SubnetSplitPreview(
            parent_cidr=str(subnet.network),
            new_prefix_length=new_prefix_length,
            conflicts=[SplitConflict(type="validation", detail=str(exc))],
        )
    try:
        _validate_split(parent, new_prefix_length)
    except SplitError as exc:
        conflicts.append(SplitConflict(type="validation", detail=str(exc)))
        return SubnetSplitPreview(
            parent_cidr=str(parent),
            new_prefix_length=new_prefix_length,
            conflicts=conflicts,
        )

    children_nets = _children_of(parent, new_prefix_length)

    # Load all the rows on the parent we need to bucket.
    addr_rows = (
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    domain_rows = (
        (await db.execute(select(SubnetDomain).where(SubnetDomain.subnet_id == subnet.id)))
        .scalars()
        .all()
    )

    # DHCP scopes / pools / statics — all of them under any scope on the
    # parent. Group-centric model: each Subnet has 0..N scopes (one per
    # group serving it), so a "split" can also involve more than one
    # scope. We preserve each scope's binding to a single child.
    scope_rows = (
        (await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == subnet.id)))
        .unique()
        .scalars()
        .all()
    )
    pools_by_scope: dict[uuid.UUID, list[DHCPPool]] = {}
    statics_by_scope: dict[uuid.UUID, list[DHCPStaticAssignment]] = {}
    if scope_rows:
        scope_ids = [s.id for s in scope_rows]
        pool_rows = (
            (await db.execute(select(DHCPPool).where(DHCPPool.scope_id.in_(scope_ids))))
            .scalars()
            .all()
        )
        for p in pool_rows:
            pools_by_scope.setdefault(p.scope_id, []).append(p)
        static_rows = (
            (
                await db.execute(
                    select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id.in_(scope_ids))
                )
            )
            .scalars()
            .all()
        )
        for s in static_rows:
            statics_by_scope.setdefault(s.scope_id, []).append(s)

    # Per-child counters.
    children_preview: list[SplitChildPreview] = []
    for child in children_nets:
        alloc_count = 0
        default_named = 0
        renamed = 0
        dns_record_count = 0
        for row in addr_rows:
            if not _ip_in(child, str(row.address)):
                continue
            alloc_count += 1
            if row.status in ("network", "broadcast"):
                if _is_default_placeholder(row):
                    default_named += 1
                else:
                    renamed += 1
            if row.dns_record_id is not None and row.status not in (
                "network",
                "broadcast",
            ):
                dns_record_count += 1

        # DHCP scope binding: which scope (if any) fits cleanly into
        # this child? A scope is bound by its subnet (the parent here);
        # we attribute each scope to the child that contains the
        # parent's network range. Since scopes themselves don't carry
        # a CIDR — they inherit the parent subnet's range — the
        # check is on the pool / static boundaries.
        bound_scope_id: uuid.UUID | None = None
        bound_pool_count = 0
        bound_static_count = 0
        for scope in scope_rows:
            scope_pools = pools_by_scope.get(scope.id, [])
            scope_statics = statics_by_scope.get(scope.id, [])
            if not scope_pools and not scope_statics:
                # Empty scope — bind to the first child arbitrarily? No:
                # an empty scope has no opinion, so we bind it to the
                # child containing the parent network address. This
                # keeps the operator's "I have a scope that points at
                # this subnet" choice intact.
                if (
                    parent.network_address in child  # type: ignore[operator]
                    and bound_scope_id is None
                ):
                    bound_scope_id = scope.id
                continue
            # A scope fits this child iff every pool start/end and every
            # static IP lives inside this child's range.
            fits = True
            for p in scope_pools:
                if not (_ip_in(child, str(p.start_ip)) and _ip_in(child, str(p.end_ip))):
                    fits = False
                    break
            if fits:
                for s in scope_statics:
                    if not _ip_in(child, str(s.ip_address)):
                        fits = False
                        break
            if fits:
                if bound_scope_id is not None:
                    # Multiple scopes fit this child cleanly. Allowed —
                    # the API only stores one scope-per-(group,subnet),
                    # and after split each child gets the scopes that
                    # fit it. We just count both, but only one
                    # ``dhcp_scope_id`` is surfaced (this is a preview
                    # quirk — operators rarely have >1 scope per
                    # subnet).
                    pass
                else:
                    bound_scope_id = scope.id
                bound_pool_count += len(scope_pools)
                bound_static_count += len(scope_statics)

        children_preview.append(
            SplitChildPreview(
                cidr=str(child),
                allocations_count=alloc_count,
                placeholders_default_named=default_named,
                placeholders_renamed=renamed,
                dhcp_scope_id=bound_scope_id,
                dhcp_pool_count=bound_pool_count,
                dhcp_static_count=bound_static_count,
                dns_record_count=dns_record_count,
            )
        )

    # Conflict pass — every scope must fit into exactly one child.
    for scope in scope_rows:
        # Find which children this scope fits into.
        matching: list[str] = []
        for child, prev in zip(children_nets, children_preview, strict=True):
            if prev.dhcp_scope_id == scope.id:
                matching.append(prev.cidr)
        if len(matching) == 0 and (pools_by_scope.get(scope.id) or statics_by_scope.get(scope.id)):
            conflicts.append(
                SplitConflict(
                    type="dhcp_scope_straddles_boundary",
                    detail=(
                        f"DHCP scope {scope.id} has pool / static boundaries "
                        "that cross a child subnet boundary. Move the offending "
                        "ranges onto one child first, or pick a different "
                        "split prefix."
                    ),
                )
            )
        elif len(matching) > 1:
            conflicts.append(
                SplitConflict(
                    type="dhcp_scope_ambiguous",
                    detail=(
                        f"DHCP scope {scope.id} fits cleanly into multiple "
                        f"children ({', '.join(matching)}). This usually "
                        "means the scope is empty — assign at least one "
                        "pool to disambiguate, or delete the scope before "
                        "splitting."
                    ),
                )
            )

    # Warning when active leases would be impacted — they survive (the
    # FK is to scope, not subnet, and the scope rebinds), but operators
    # should know.
    if scope_rows:
        active_leases = (
            await db.scalar(
                select(func.count())
                .select_from(DHCPLease)
                .where(
                    DHCPLease.scope_id.in_([s.id for s in scope_rows]),
                    DHCPLease.state == "active",
                )
            )
        ) or 0
        if active_leases:
            warnings.append(
                f"{active_leases} active DHCP lease(s) on the parent subnet's "
                "scope(s) will be re-attributed to whichever child contains "
                "their lease IP."
            )

    if domain_rows:
        warnings.append(
            f"{len(domain_rows)} DNS zone binding(s) on the parent will be "
            "duplicated onto each child. Each child keeps the same primary "
            "and additional zones."
        )

    return SubnetSplitPreview(
        parent_cidr=str(parent),
        new_prefix_length=new_prefix_length,
        children=children_preview,
        conflicts=conflicts,
        warnings=warnings,
    )


# ── Commit ───────────────────────────────────────────────────────────────────


async def commit_subnet_split(
    db: AsyncSession,
    subnet: Subnet,
    new_prefix_length: int,
    *,
    confirm_cidr: str,
    current_user: Any | None = None,
) -> SubnetSplitResult:
    """Apply the split atomically. Caller commits the session.

    Sequence:
      1. Acquire pg advisory lock (errors out 423 on contention).
      2. Re-run preview; reject if conflicts surfaced since the user
         saw the preview.
      3. Verify ``confirm_cidr`` matches the parent CIDR — defence in
         depth so a UI bug can't issue a split against the wrong row.
      4. Build child Subnet rows with inherited metadata.
      5. Migrate IPAddress rows (FK update, no copy) to whichever child
         contains the IP. Default-named placeholders at the parent's
         boundaries are deleted; renamed placeholders survive.
      6. Recreate default-named placeholders on each child.
      7. Re-bind the parent's DHCP scope(s) (and their pools / statics)
         to whichever child they fit into. Active leases follow the
         scope.
      8. Duplicate SubnetDomain rows onto each child.
      9. Bump DHCP config bundles for affected agent-based servers.
      10. Delete the parent (last — references must be clear).
    """
    if not await _try_advisory_lock(db, subnet.id):
        raise SplitError(
            "Another operation is already in progress for this subnet. " "Retry once it completes.",
            status_code=423,
        )

    parent = _parse_cidr(str(subnet.network), label="subnet")
    _validate_split(parent, new_prefix_length)
    canonical_parent = str(parent)

    if confirm_cidr != canonical_parent:
        raise SplitError(
            f"confirm_cidr {confirm_cidr!r} does not match parent CIDR " f"{canonical_parent!r}.",
            status_code=422,
        )

    # Re-run preview under the lock.
    preview = await preview_subnet_split(db, subnet, new_prefix_length)
    if preview.conflicts:
        raise SplitError(
            "Split blocked by conflicts: " + "; ".join(c.detail for c in preview.conflicts),
            status_code=409,
        )

    children_nets = _children_of(parent, new_prefix_length)

    # Snapshot fields we'll inherit. ``model_dump`` would be cleaner
    # but Subnet is an ORM model — pull explicitly.
    inherited: dict[str, Any] = dict(
        space_id=subnet.space_id,
        block_id=subnet.block_id,
        router_zone_id=subnet.router_zone_id,
        vlan_ref_id=subnet.vlan_ref_id,
        vlan_id=subnet.vlan_id,
        vxlan_id=subnet.vxlan_id,
        dns_servers=subnet.dns_servers,
        domain_name=subnet.domain_name,
        dns_group_ids=subnet.dns_group_ids,
        dns_zone_id=subnet.dns_zone_id,
        dns_additional_zone_ids=subnet.dns_additional_zone_ids,
        dns_inherit_settings=subnet.dns_inherit_settings,
        dhcp_server_group_id=subnet.dhcp_server_group_id,
        dhcp_inherit_settings=subnet.dhcp_inherit_settings,
        ddns_enabled=subnet.ddns_enabled,
        ddns_hostname_policy=subnet.ddns_hostname_policy,
        ddns_domain_override=subnet.ddns_domain_override,
        ddns_ttl=subnet.ddns_ttl,
        ddns_inherit_settings=subnet.ddns_inherit_settings,
        ipv6_allocation_policy=subnet.ipv6_allocation_policy,
        status=subnet.status,
        custom_fields=dict(subnet.custom_fields or {}),
        tags=dict(subnet.tags or {}),
    )

    # Build the children. We don't recompute total_ips / utilization at
    # construction time — the IPAM utilities at the end of the
    # transaction recompute them once IPAddress rows are migrated.
    new_children: list[Subnet] = []
    is_v6_parent = isinstance(parent, ipaddress.IPv6Network)
    for cnet in children_nets:
        # Gateway: only carry the parent's gateway onto the child that
        # contains it (otherwise the gateway field is null on the new
        # children — operators can set per-child gateways later).
        gw_str: str | None = None
        if subnet.gateway:
            try:
                if ipaddress.ip_address(str(subnet.gateway)) in cnet:
                    gw_str = str(subnet.gateway)
            except ValueError:
                gw_str = None

        # total_ips for the child — same semantics as
        # ``_total_ips`` in the resize service.
        if is_v6_parent:
            total = min(cnet.num_addresses, 2**63 - 1)
        elif cnet.prefixlen >= 31:
            total = cnet.num_addresses
        else:
            total = cnet.num_addresses - 2

        child = Subnet(
            network=str(cnet),
            name="",
            description=f"Split from {canonical_parent}",
            gateway=gw_str,
            total_ips=int(total),
            allocated_ips=0,
            utilization_percent=0.0,
            **inherited,
        )
        db.add(child)
        new_children.append(child)
    await db.flush()  # children get IDs

    # Migrate IP rows. Default-named placeholders at the parent's
    # boundaries get deleted (we'll recreate them per-child); renamed
    # rows go to whichever child contains the IP.
    addr_rows = (
        (await db.execute(select(IPAddress).where(IPAddress.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    parent_boundary_ips = {str(parent.network_address)}
    if isinstance(parent, ipaddress.IPv4Network) and parent.prefixlen <= 30:
        parent_boundary_ips.add(str(parent.broadcast_address))

    deleted_default_count = 0
    moved_count = 0
    for row in addr_rows:
        addr_str = str(row.address)
        if addr_str in parent_boundary_ips and _is_default_placeholder(row):
            await db.delete(row)
            deleted_default_count += 1
            continue
        # Find the containing child.
        new_subnet_id: uuid.UUID | None = None
        for cnet, child in zip(children_nets, new_children, strict=True):
            if _ip_in(cnet, addr_str):
                new_subnet_id = child.id
                break
        if new_subnet_id is None:
            # Shouldn't happen: every IP in the parent is contained by
            # exactly one child. If we get here something has gone wrong;
            # leave the row as-is (parent delete will then fail loudly,
            # rather than silently orphan a row).
            continue
        row.subnet_id = new_subnet_id
        moved_count += 1
    await db.flush()

    # Recreate default-named placeholders on each child.
    placeholders_created = 0
    for cnet, child in zip(children_nets, new_children, strict=True):
        if cnet.prefixlen >= 31:
            # /31 / /32 / /127 / /128 — no placeholders.
            continue
        existing = (
            (await db.execute(select(IPAddress.address).where(IPAddress.subnet_id == child.id)))
            .scalars()
            .all()
        )
        existing_set = {str(a) for a in existing}
        net_addr = str(cnet.network_address)
        if net_addr not in existing_set:
            db.add(
                IPAddress(
                    subnet_id=child.id,
                    address=net_addr,
                    status="network",
                    description="Network address",
                    created_by_user_id=(current_user.id if current_user is not None else None),
                )
            )
            placeholders_created += 1
        if isinstance(cnet, ipaddress.IPv4Network) and cnet.prefixlen <= 30:
            bcast = str(cnet.broadcast_address)
            if bcast not in existing_set:
                db.add(
                    IPAddress(
                        subnet_id=child.id,
                        address=bcast,
                        status="broadcast",
                        description="Broadcast address",
                        created_by_user_id=(current_user.id if current_user is not None else None),
                    )
                )
                placeholders_created += 1
    await db.flush()

    # Re-bind DHCP scopes. We use the same fits-cleanly arithmetic as
    # the preview to decide which child each scope attaches to.
    scope_rows = (
        (await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == subnet.id)))
        .unique()
        .scalars()
        .all()
    )
    affected_groups: set[uuid.UUID] = set()
    for scope in scope_rows:
        scope_pools = (
            (await db.execute(select(DHCPPool).where(DHCPPool.scope_id == scope.id)))
            .scalars()
            .all()
        )
        scope_statics = (
            (
                await db.execute(
                    select(DHCPStaticAssignment).where(DHCPStaticAssignment.scope_id == scope.id)
                )
            )
            .scalars()
            .all()
        )
        target_child_id: uuid.UUID | None = None
        for cnet, child in zip(children_nets, new_children, strict=True):
            fits = True
            for p in scope_pools:
                if not (_ip_in(cnet, str(p.start_ip)) and _ip_in(cnet, str(p.end_ip))):
                    fits = False
                    break
            if fits:
                for s in scope_statics:
                    if not _ip_in(cnet, str(s.ip_address)):
                        fits = False
                        break
            if fits and (scope_pools or scope_statics):
                target_child_id = child.id
                break
        if target_child_id is None:
            # Empty scope — attach to the child containing the parent's
            # network address. (Mirrors preview behaviour.)
            for cnet, child in zip(children_nets, new_children, strict=True):
                if parent.network_address in cnet:  # type: ignore[operator]
                    target_child_id = child.id
                    break
        if target_child_id is None:
            # Defensive: re-running preview should have surfaced this as
            # a conflict already and aborted commit. If we get here, the
            # safe move is to keep the scope attached to the parent and
            # let the parent-delete fail loudly.
            continue
        scope.subnet_id = target_child_id
        affected_groups.add(scope.group_id)
    await db.flush()

    # Duplicate SubnetDomain rows onto each child — same primary +
    # additional zones.
    domain_rows = (
        (await db.execute(select(SubnetDomain).where(SubnetDomain.subnet_id == subnet.id)))
        .scalars()
        .all()
    )
    for d in domain_rows:
        for child in new_children:
            db.add(
                SubnetDomain(
                    subnet_id=child.id,
                    dns_zone_id=d.dns_zone_id,
                    is_primary=d.is_primary,
                )
            )
        # Drop the parent's domain row — parent is going away anyway.
        await db.delete(d)
    await db.flush()

    # Bump DHCP config bundles for any agent-based server in an
    # affected group. The scope's subnet binding shifted; the bundle
    # ETag must change so agents re-render.
    dhcp_servers_notified = 0
    if affected_groups:
        servers = (
            (
                await db.execute(
                    select(DHCPServer).where(DHCPServer.server_group_id.in_(affected_groups))
                )
            )
            .scalars()
            .all()
        )
        for server in servers:
            if is_agentless(server.driver):
                continue
            bundle = await build_config_bundle(db, server)
            server.config_etag = bundle.etag
            existing_op = (
                await db.execute(
                    select(DHCPConfigOp).where(
                        DHCPConfigOp.server_id == server.id,
                        DHCPConfigOp.op_type == "apply_config",
                        DHCPConfigOp.status == "pending",
                    )
                )
            ).scalar_one_or_none()
            if existing_op is None:
                db.add(
                    DHCPConfigOp(
                        server_id=server.id,
                        op_type="apply_config",
                        payload={"etag": bundle.etag, "reason": "subnet_split"},
                        status="pending",
                    )
                )
            collect_wake(dhcp_server_channel(server.id))
            dhcp_servers_notified += 1
    await db.flush()

    # Recompute child utilisation totals + roll up the parent block.
    from app.api.v1.ipam.router import _update_block_utilization, _update_utilization

    for child in new_children:
        await _update_utilization(db, child.id)
    if subnet.block_id:
        # The block totals don't change semantically (one subnet → many,
        # same address space) but the row count did, and downstream
        # utilisation queries count subnets too.
        await _update_block_utilization(db, subnet.block_id)

    # Finally, delete the parent. We delete via session.delete so the
    # ondelete=RESTRICT FKs fire one last sanity check — anything we
    # missed will surface here as a clean DB error rather than silent
    # orphaning.
    await db.delete(subnet)
    await db.flush()

    summary = [
        f"Split {canonical_parent} into {len(new_children)} /{new_prefix_length} child(ren)",
        f"Migrated {moved_count} IPAddress row(s) onto children",
        f"Recreated {placeholders_created} default placeholder(s)",
    ]
    if deleted_default_count:
        summary.append(
            f"Deleted {deleted_default_count} default-named parent boundary "
            "row(s) (recreated on children)"
        )
    if dhcp_servers_notified:
        summary.append(f"Notified {dhcp_servers_notified} DHCP server(s) to re-render config")

    logger.info(
        "subnet_split",
        parent_subnet_id=str(subnet.id),
        parent_cidr=canonical_parent,
        new_prefix_length=new_prefix_length,
        child_count=len(new_children),
        moved=moved_count,
        placeholders_created=placeholders_created,
        dhcp_servers_notified=dhcp_servers_notified,
    )

    return SubnetSplitResult(
        parent_cidr=canonical_parent,
        children=new_children,
        summary=summary,
    )


__all__ = [
    "SplitChildPreview",
    "SplitConflict",
    "SplitError",
    "SubnetSplitPreview",
    "SubnetSplitResult",
    "commit_subnet_split",
    "preview_subnet_split",
]

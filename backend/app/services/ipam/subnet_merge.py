"""Subnet merge — fold N contiguous sibling subnets into one supernet.

Counterpart to ``subnet_split``. Preview verifies every constraint and
returns a structured ``conflicts[]``; commit re-runs preview under a pg
advisory lock and performs the merge in a single transaction.

Constraints (re-checked at commit):

1. **At least two subnets total.** ``target + len(siblings) ≥ 2``.
2. **Same parent block.** Every subnet in the merge set must share
   ``Subnet.block_id``. We don't re-attribute parents during a merge.
3. **Same address family.** Mixing v4 + v6 in one merge is rejected.
4. **Contiguous.** Their CIDRs, sorted, must summarise to a single
   supernet via ``ipaddress.collapse_addresses``. Any gap or overlap
   is a conflict.
5. **Compatible metadata.** Same ``vlan_id`` (or all null), same
   ``vlan_ref_id`` (or all null), same ``dns_server_group_id`` /
   ``dns_zone_id``, same DDNS settings. Mismatches are surfaced as
   conflicts; we don't pick a winner.
6. **At most one DHCP scope across the entire merge set.** When
   exactly one source has a scope, it survives and is widened
   semantically (the scope's ``subnet_id`` rebinds to the new
   merged subnet — the scope's pool / static IPs are inside the
   widened range automatically because they were inside one of
   the contributing subnets). When multiple sources have scopes
   we 409 — V1 doesn't auto-pick a survivor.
7. **No DHCP scope on a subnet that's also losing pools.** Out of
   scope — the constraint above (single survivor) catches this.

Side-effects on commit:

* Create one new ``Subnet`` row at the merged CIDR, inheriting the
  shared metadata.
* Migrate every IPAddress row from each source into the new subnet.
* Migrate the surviving DHCPScope to the new subnet.
* Migrate / dedupe SubnetDomain bindings (union of source bindings;
  primary status preserved if any source marked it primary).
* Default-named placeholder rows at every old boundary are deleted;
  new boundary placeholders are created on the merged subnet.
* Renamed / DNS-bearing placeholders are preserved (they survive on
  whichever child contained them).
* Bump DHCP config bundles for any agent-based server backing the
  surviving scope's group.
* Delete each source subnet last (ondelete=RESTRICT will fire a
  belt-and-braces check on residual references).

Audit-log writes happen in the router (one row per affected resource
plus one summary row for the merge itself).
"""

from __future__ import annotations

import ipaddress
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dhcp_server_channel
from app.drivers.dhcp import is_agentless
from app.models.dhcp import (
    DHCPConfigOp,
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPStaticAssignment,
)
from app.models.ipam import IPAddress, Subnet, SubnetDomain
from app.services.dhcp.config_bundle import build_config_bundle

logger = structlog.get_logger(__name__)

_LOCK_NS_MERGE = 0x49504D34  # "IPM4"


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class MergeConflict:
    type: str
    detail: str


@dataclass
class MergeSourceRow:
    id: uuid.UUID
    cidr: str


@dataclass
class SubnetMergePreview:
    merged_cidr: str | None
    """None when the source set doesn't summarise to a single supernet —
    look at ``conflicts[]`` for why."""
    source_subnets: list[MergeSourceRow] = field(default_factory=list)
    surviving_dhcp_scope_id: uuid.UUID | None = None
    conflicts: list[MergeConflict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SubnetMergeResult:
    merged_subnet: Subnet
    deleted_subnet_ids: list[uuid.UUID]
    summary: list[str]


class MergeError(Exception):
    def __init__(self, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.status_code = status_code


def _parse_cidr(value: str, *, label: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise MergeError(f"Invalid CIDR for {label}: {value}", status_code=422) from exc


def _advisory_lock_key(resource_id: uuid.UUID) -> tuple[int, int]:
    key = zlib.crc32(str(resource_id).encode("utf-8"))
    if key >= 2**31:
        key -= 2**32
    return (_LOCK_NS_MERGE, key)


async def _try_advisory_lock(db: AsyncSession, resource_id: uuid.UUID) -> bool:
    ns, key = _advisory_lock_key(resource_id)
    row: bool = (
        await db.execute(
            text("SELECT pg_try_advisory_xact_lock(:ns, :key)"),
            {"ns": ns, "key": key},
        )
    ).scalar_one()
    return bool(row)


def _is_default_placeholder(row: IPAddress) -> bool:
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


async def _load_sources(
    db: AsyncSession,
    target: Subnet,
    sibling_ids: list[uuid.UUID],
) -> list[Subnet]:
    """Return ``[target] + sibling rows`` with duplicates removed.

    Sibling IDs are validated to exist; missing ids cause a clean
    error in the caller via the conflicts list.
    """
    seen: set[uuid.UUID] = {target.id}
    out: list[Subnet] = [target]
    for sid in sibling_ids:
        if sid in seen:
            continue
        seen.add(sid)
        s = await db.get(Subnet, sid)
        if s is None:
            raise MergeError(f"Sibling subnet {sid} not found", status_code=404)
        out.append(s)
    return out


def _check_metadata_compat(sources: list[Subnet]) -> list[MergeConflict]:
    """Return one conflict per metadata field that disagrees across sources."""
    conflicts: list[MergeConflict] = []
    if len(sources) < 2:
        return conflicts

    def _all_eq(field: str, *, allow_none: bool = True) -> bool:
        values = [getattr(s, field) for s in sources]
        if allow_none and all(v is None for v in values):
            return True
        return all(v == values[0] for v in values)

    fields_to_check = [
        ("vlan_id", "vlan_id"),
        ("vlan_ref_id", "vlan_ref_id"),
        ("dns_zone_id", "primary DNS zone"),
        ("dhcp_server_group_id", "DHCP server group"),
        ("ddns_enabled", "ddns_enabled"),
        ("ddns_hostname_policy", "ddns_hostname_policy"),
        ("ddns_domain_override", "ddns_domain_override"),
        ("ddns_ttl", "ddns_ttl"),
        ("ddns_inherit_settings", "ddns_inherit_settings"),
        ("dns_inherit_settings", "dns_inherit_settings"),
        ("dhcp_inherit_settings", "dhcp_inherit_settings"),
        ("status", "status"),
        ("router_zone_id", "router zone"),
    ]
    for fname, label in fields_to_check:
        if not _all_eq(fname):
            values = sorted({repr(getattr(s, fname)) for s in sources})
            conflicts.append(
                MergeConflict(
                    type=f"metadata_mismatch:{fname}",
                    detail=(
                        f"Sources disagree on {label}: {', '.join(values)}. "
                        "Bring them into agreement before merging or pick a "
                        "different source set."
                    ),
                )
            )
    return conflicts


def _summarise_or_none(nets: list[IPNetwork]) -> IPNetwork | None:
    """Return the single supernet that exactly covers ``nets``, or None.

    ``ipaddress.collapse_addresses`` summarises adjacent / contained
    networks into the smallest set covering them. The set is single-
    element iff every input is contiguous and aligns to a power of two
    boundary together. We additionally require that the sum of
    addresses across inputs equals the supernet's address count — this
    rules out pathological "two contiguous /28s plus a /30 overlapping
    one of them" cases that ``collapse_addresses`` would silently
    deduplicate.
    """
    if not nets:
        return None
    try:
        # ``collapse_addresses`` requires same family — caller has
        # already filtered.
        collapsed = list(ipaddress.collapse_addresses(nets))  # type: ignore[arg-type,type-var]
    except (TypeError, ValueError):
        return None
    if len(collapsed) != 1:
        return None
    # Strict total-size match: every input must be disjoint, and the
    # sum of addresses must equal the supernet's range.
    total_inputs = sum(n.num_addresses for n in nets)
    if total_inputs != collapsed[0].num_addresses:
        return None
    return collapsed[0]


# ── Preview ──────────────────────────────────────────────────────────────────


async def preview_subnet_merge(
    db: AsyncSession,
    target: Subnet,
    sibling_subnet_ids: list[uuid.UUID],
) -> SubnetMergePreview:
    """Pure read; surfaces every reason commit would fail.

    Returns ``merged_cidr=None`` when contiguity / family checks fail
    so the UI knows there's nothing to confirm against.
    """
    conflicts: list[MergeConflict] = []
    warnings: list[str] = []

    try:
        sources = await _load_sources(db, target, sibling_subnet_ids)
    except MergeError as exc:
        return SubnetMergePreview(
            merged_cidr=None,
            source_subnets=[
                MergeSourceRow(id=target.id, cidr=str(target.network)),
            ],
            conflicts=[MergeConflict(type="not_found", detail=str(exc))],
        )

    if len(sources) < 2:
        conflicts.append(
            MergeConflict(
                type="too_few_subnets",
                detail="Merge requires at least one sibling besides the target.",
            )
        )
        return SubnetMergePreview(
            merged_cidr=None,
            source_subnets=[MergeSourceRow(id=s.id, cidr=str(s.network)) for s in sources],
            conflicts=conflicts,
        )

    # Same block.
    block_ids = {s.block_id for s in sources}
    if len(block_ids) > 1:
        conflicts.append(
            MergeConflict(
                type="block_mismatch",
                detail=(
                    "All sources must share the same parent IP block. "
                    "Move them under a common parent first."
                ),
            )
        )

    # Same family + contiguity + supernet computation.
    parsed: list[IPNetwork] = []
    family_v4 = None
    for s in sources:
        try:
            net = ipaddress.ip_network(str(s.network), strict=False)
        except ValueError as exc:
            conflicts.append(MergeConflict(type="bad_cidr", detail=str(exc)))
            continue
        is_v4 = isinstance(net, ipaddress.IPv4Network)
        if family_v4 is None:
            family_v4 = is_v4
        elif family_v4 != is_v4:
            conflicts.append(
                MergeConflict(
                    type="family_mismatch",
                    detail="Sources mix IPv4 and IPv6. Merge requires a single family.",
                )
            )
            family_v4 = None  # keep collecting for the operator to see
            break
        parsed.append(net)

    merged: IPNetwork | None = None
    if family_v4 is not None and parsed and not any(c.type == "family_mismatch" for c in conflicts):
        merged = _summarise_or_none(parsed)
        if merged is None:
            conflicts.append(
                MergeConflict(
                    type="non_contiguous",
                    detail=(
                        "Sources do not summarise to a single supernet. "
                        "They must be contiguous and aligned (e.g. two "
                        "adjacent /25s combine into a /24)."
                    ),
                )
            )

    # Metadata compatibility.
    conflicts.extend(_check_metadata_compat(sources))

    # DHCP scope handling — at most one survivor.
    scopes = (
        (
            await db.execute(
                select(DHCPScope).where(DHCPScope.subnet_id.in_([s.id for s in sources]))
            )
        )
        .unique()
        .scalars()
        .all()
    )
    surviving_scope: DHCPScope | None = None
    if len(scopes) == 1:
        surviving_scope = scopes[0]
    elif len(scopes) > 1:
        # Group scopes per (group_id, subnet_id) — different groups
        # serving different sources is the multi-scope case the V1
        # design explicitly defers.
        conflicts.append(
            MergeConflict(
                type="multiple_dhcp_scopes",
                detail=(
                    f"{len(scopes)} DHCP scope(s) found across the source "
                    "subnets. Merge supports at most one scope per merge "
                    "set in V1 — delete or relocate the others first."
                ),
            )
        )

    if scopes:
        # Even with a single survivor, surface a warning so operators
        # know what's happening.
        warnings.append(
            "DHCP scope will be re-bound to the merged subnet. Pools and "
            "static assignments stay where they are."
        )

    # SubnetDomain rows — duplicates resolved by union.
    domain_rows = (
        (
            await db.execute(
                select(SubnetDomain).where(SubnetDomain.subnet_id.in_([s.id for s in sources]))
            )
        )
        .scalars()
        .all()
    )
    if domain_rows:
        warnings.append(
            f"{len(domain_rows)} DNS zone binding(s) on source subnets will be "
            "deduplicated and re-attached to the merged subnet."
        )

    return SubnetMergePreview(
        merged_cidr=str(merged) if merged is not None else None,
        source_subnets=[MergeSourceRow(id=s.id, cidr=str(s.network)) for s in sources],
        surviving_dhcp_scope_id=surviving_scope.id if surviving_scope else None,
        conflicts=conflicts,
        warnings=warnings,
    )


# ── Commit ───────────────────────────────────────────────────────────────────


async def commit_subnet_merge(
    db: AsyncSession,
    target: Subnet,
    sibling_subnet_ids: list[uuid.UUID],
    *,
    confirm_cidr: str,
    current_user: Any | None = None,
) -> SubnetMergeResult:
    """Apply the merge atomically. Caller commits the session.

    Acquires the advisory lock on the *target* subnet — siblings might
    contend on their own resize / split operations independently, but
    contention with another merge using the same target is what we
    want to serialise. Recheck preview under the lock; reject on any
    conflict.
    """
    if not await _try_advisory_lock(db, target.id):
        raise MergeError(
            "Another operation is already in progress for this subnet. " "Retry once it completes.",
            status_code=423,
        )

    preview = await preview_subnet_merge(db, target, sibling_subnet_ids)
    if preview.conflicts or preview.merged_cidr is None:
        msg = "Merge blocked"
        if preview.conflicts:
            msg += ": " + "; ".join(c.detail for c in preview.conflicts)
        raise MergeError(msg, status_code=409)

    if confirm_cidr != preview.merged_cidr:
        raise MergeError(
            f"confirm_cidr {confirm_cidr!r} does not match computed merged "
            f"CIDR {preview.merged_cidr!r}.",
            status_code=422,
        )

    sources = await _load_sources(db, target, sibling_subnet_ids)
    merged_net = _parse_cidr(preview.merged_cidr, label="merged CIDR")

    # Build the merged subnet. Inherit metadata from the target — the
    # preview already verified every other source agrees on the
    # critical fields.
    is_v6 = isinstance(merged_net, ipaddress.IPv6Network)
    if is_v6:
        total_ips_new = min(merged_net.num_addresses, 2**63 - 1)
    elif merged_net.prefixlen >= 31:
        total_ips_new = merged_net.num_addresses
    else:
        total_ips_new = merged_net.num_addresses - 2

    # Take the gateway from whichever source contained it. If multiple
    # sources had gateways and they're equal, keep it; if they differ,
    # null it out (operator can re-set).
    gateways = {str(s.gateway) for s in sources if s.gateway}
    surviving_gateway: str | None = None
    if len(gateways) == 1:
        gw = next(iter(gateways))
        try:
            if ipaddress.ip_address(gw) in merged_net:
                surviving_gateway = gw
        except ValueError:
            pass

    merged_subnet = Subnet(
        space_id=target.space_id,
        block_id=target.block_id,
        router_zone_id=target.router_zone_id,
        vlan_ref_id=target.vlan_ref_id,
        vlan_id=target.vlan_id,
        vxlan_id=target.vxlan_id,
        network=str(merged_net),
        name=target.name or "",
        description=target.description or f"Merged from {len(sources)} subnets",
        gateway=surviving_gateway,
        dns_servers=target.dns_servers,
        domain_name=target.domain_name,
        dns_group_ids=target.dns_group_ids,
        dns_zone_id=target.dns_zone_id,
        dns_additional_zone_ids=target.dns_additional_zone_ids,
        dns_inherit_settings=target.dns_inherit_settings,
        dhcp_server_group_id=target.dhcp_server_group_id,
        dhcp_inherit_settings=target.dhcp_inherit_settings,
        ddns_enabled=target.ddns_enabled,
        ddns_hostname_policy=target.ddns_hostname_policy,
        ddns_domain_override=target.ddns_domain_override,
        ddns_ttl=target.ddns_ttl,
        ddns_inherit_settings=target.ddns_inherit_settings,
        ipv6_allocation_policy=target.ipv6_allocation_policy,
        status=target.status,
        custom_fields=dict(target.custom_fields or {}),
        tags=dict(target.tags or {}),
        total_ips=int(total_ips_new),
        allocated_ips=0,
        utilization_percent=0.0,
    )
    db.add(merged_subnet)
    await db.flush()

    # Build the set of source-boundary IPs we'll prune (only when
    # default-named). Renamed boundary rows survive into the merged
    # subnet as regular IP rows — operator intent wins.
    source_boundary_ips: set[str] = set()
    for s in sources:
        try:
            sn = ipaddress.ip_network(str(s.network), strict=False)
        except ValueError:
            continue
        source_boundary_ips.add(str(sn.network_address))
        if isinstance(sn, ipaddress.IPv4Network) and sn.prefixlen <= 30:
            source_boundary_ips.add(str(sn.broadcast_address))

    # Migrate IPAddress rows.
    moved = 0
    deleted_default = 0
    for s in sources:
        rows = (
            (await db.execute(select(IPAddress).where(IPAddress.subnet_id == s.id))).scalars().all()
        )
        for row in rows:
            if str(row.address) in source_boundary_ips and _is_default_placeholder(row):
                await db.delete(row)
                deleted_default += 1
                continue
            row.subnet_id = merged_subnet.id
            moved += 1
    await db.flush()

    # Migrate the surviving DHCP scope (if any).
    dhcp_scope_rebind = 0
    affected_groups: set[uuid.UUID] = set()
    if preview.surviving_dhcp_scope_id is not None:
        scope = await db.get(DHCPScope, preview.surviving_dhcp_scope_id)
        if scope is not None:
            scope.subnet_id = merged_subnet.id
            affected_groups.add(scope.group_id)
            dhcp_scope_rebind = 1
    await db.flush()

    # Migrate / dedupe SubnetDomain rows. Take the union; if any source
    # had ``is_primary=True`` for a given zone, the merged binding is
    # primary too.
    domain_rows = (
        (
            await db.execute(
                select(SubnetDomain).where(SubnetDomain.subnet_id.in_([s.id for s in sources]))
            )
        )
        .scalars()
        .all()
    )
    seen_zones: dict[uuid.UUID, bool] = {}
    for d in domain_rows:
        existing_primary = seen_zones.get(d.dns_zone_id, False)
        seen_zones[d.dns_zone_id] = existing_primary or d.is_primary
        await db.delete(d)
    await db.flush()
    for zone_id, is_primary in seen_zones.items():
        db.add(
            SubnetDomain(
                subnet_id=merged_subnet.id,
                dns_zone_id=zone_id,
                is_primary=is_primary,
            )
        )
    await db.flush()

    # Recreate default-named placeholders on the merged subnet.
    placeholders_created = 0
    if merged_net.prefixlen < 31:
        existing = (
            (
                await db.execute(
                    select(IPAddress.address).where(IPAddress.subnet_id == merged_subnet.id)
                )
            )
            .scalars()
            .all()
        )
        existing_set = {str(a) for a in existing}
        net_addr = str(merged_net.network_address)
        if net_addr not in existing_set:
            db.add(
                IPAddress(
                    subnet_id=merged_subnet.id,
                    address=net_addr,
                    status="network",
                    description="Network address",
                    created_by_user_id=(current_user.id if current_user is not None else None),
                )
            )
            placeholders_created += 1
        if isinstance(merged_net, ipaddress.IPv4Network) and merged_net.prefixlen <= 30:
            bcast = str(merged_net.broadcast_address)
            if bcast not in existing_set:
                db.add(
                    IPAddress(
                        subnet_id=merged_subnet.id,
                        address=bcast,
                        status="broadcast",
                        description="Broadcast address",
                        created_by_user_id=(current_user.id if current_user is not None else None),
                    )
                )
                placeholders_created += 1
    await db.flush()

    # Bump DHCP config bundles on agent-based servers in any affected
    # group.
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
                        payload={"etag": bundle.etag, "reason": "subnet_merge"},
                        status="pending",
                    )
                )
            collect_wake(dhcp_server_channel(server.id))
            dhcp_servers_notified += 1
    await db.flush()

    # Delete sources last — RESTRICT FKs catch anything we missed.
    deleted_ids: list[uuid.UUID] = []
    for s in sources:
        deleted_ids.append(s.id)
        await db.delete(s)
    await db.flush()

    # Recompute on merged subnet + parent block.
    from app.api.v1.ipam.router import _update_block_utilization, _update_utilization

    await _update_utilization(db, merged_subnet.id)
    if merged_subnet.block_id:
        await _update_block_utilization(db, merged_subnet.block_id)

    # Suppress the unused-import warning in slim deployments.
    _ = DHCPPool
    _ = DHCPStaticAssignment

    summary = [
        f"Merged {len(sources)} source subnets → {preview.merged_cidr}",
        f"Migrated {moved} IPAddress row(s) onto merged subnet",
        f"Recreated {placeholders_created} boundary placeholder(s)",
    ]
    if deleted_default:
        summary.append(f"Deleted {deleted_default} default-named source-boundary row(s)")
    if dhcp_scope_rebind:
        summary.append("Re-bound 1 DHCP scope to the merged subnet")
    if dhcp_servers_notified:
        summary.append(f"Notified {dhcp_servers_notified} DHCP server(s) to re-render config")

    logger.info(
        "subnet_merged",
        merged_subnet_id=str(merged_subnet.id),
        merged_cidr=preview.merged_cidr,
        source_count=len(sources),
        moved=moved,
        placeholders_created=placeholders_created,
        dhcp_servers_notified=dhcp_servers_notified,
    )

    return SubnetMergeResult(
        merged_subnet=merged_subnet,
        deleted_subnet_ids=deleted_ids,
        summary=summary,
    )


__all__ = [
    "MergeConflict",
    "MergeError",
    "MergeSourceRow",
    "SubnetMergePreview",
    "SubnetMergeResult",
    "commit_subnet_merge",
    "preview_subnet_merge",
]

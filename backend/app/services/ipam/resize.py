"""IPAM subnet + block resize — grow-only CIDR mutation.

This module implements the preview + commit flow for resizing a subnet or
block to a **larger** CIDR (smaller prefix length — e.g. ``/24`` → ``/23``).
Shrinking is explicitly out of scope: it silently orphans addresses and we
do not want that ambiguity in the source of truth.

Design rules the commit path enforces (all re-checked at commit time — the
tree may have changed between preview and commit):

1. **Grow only.** ``new_prefix_len < old_prefix_len``. 422 otherwise.
2. **Same address family.** v4→v4, v6→v6. No migration between families.
3. **Old CIDR ⊂ new CIDR.** Guarantees every existing IP / child / DHCP
   allocation stays inside the new network without relocation.
4. **Parent containment.** The new CIDR must fit entirely inside the
   parent block (``Subnet.block_id`` for subnets;
   ``IPBlock.parent_block_id`` for blocks). If the parent is too small
   we reject with "resize the parent first" — we do **not** chain-resize
   the parent. Chain-resize is too easy to blow a silent hole in the tree.
5. **No overlap with siblings or cousins.** Scan the **entire IPSpace**,
   not just siblings under the same parent — a cousin under a different
   block in the same space could still collide.
6. **Block resize: children must still fit.** Mathematically redundant
   (old ⊂ new ⇒ children ⊂ new) but re-checked as a belt-and-braces.
7. **Space immutable.** ``space_id`` never changes during a resize.

Side-effects committed atomically with the CIDR change:

* Delete default-named ``network`` / ``broadcast`` placeholder rows at the
  **old** boundaries, only when ``replace_default_placeholders=true``.
  Renamed placeholders (``hostname IS NOT NULL``) are **always preserved**
  because they represent user intent (e.g. ``anycast-vip``). Rows with
  ``dns_record_id IS NOT NULL`` are classified as renamed by
  ``_load_boundary_placeholders`` and therefore never reach the delete
  loop — no DNS cleanup is needed here.
* Update ``Subnet.network``, ``total_ips``, ``utilization_percent``, and
  optionally ``gateway`` (via ``move_gateway_to_first_usable``).
* Re-create default-named placeholder rows at the **new** boundaries.
* Call ``ensure_reverse_zone_for_subnet`` so any new reverse-zone
  coverage is backfilled — this is idempotent if the zone already exists.
* Bump the DHCP ``config_etag`` + enqueue an ``apply_config`` op for any
  agent-based DHCP server that serves a scope on this subnet. Agentless
  (Windows DHCP read-only) drivers are skipped — they have no write path.
* Update block utilization rollups.

Concurrency:

* ``pg_try_advisory_xact_lock`` is taken on a deterministic key derived
  from the resource UUID. A concurrent resize (or any other operation
  using the same lock key) returns **423 Locked**.
* The preview does **not** take the lock. It is read-only and runs
  against the committed state at query time.

Not covered by this module (intentional):

* Shrinking — rejected with a dedicated error message.
* Cross-space moves — rejected; the space is an invariant.
* Chain-resize of parent blocks — rejected with guidance.
* Auto-expansion of DHCP pools — pools stay where they are; the preview
  surfaces this as a warning.
* DNS record mutations beyond reverse-zone backfill — forward A/AAAA and
  PTR values do not change when the subnet grows.
* Alembic changes — the schema is unchanged (``Subnet.network`` /
  ``IPBlock.network`` are already ``CIDR`` columns).
"""

from __future__ import annotations

import ipaddress
import uuid
import zlib
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import delete as sql_delete
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
from app.models.dns import DNSRecord
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.dhcp.config_bundle import build_config_bundle

logger = structlog.get_logger(__name__)

# Namespace prefix used with PostgreSQL's two-int advisory-lock form. The
# first int partitions our locks from any other feature that also uses
# ``pg_try_advisory_xact_lock(int4, int4)`` so we never collide with, say,
# a DNS-zone lock that happens to hash to the same number.
_LOCK_NS_SUBNET = 0x49504D31  # "IPM1"
_LOCK_NS_BLOCK = 0x49504D32  # "IPM2"


# ── Public result shapes ─────────────────────────────────────────────────────
#
# The API router maps these dataclasses into Pydantic response models. Keeping
# them as dataclasses (rather than Pydantic) keeps the service layer free of
# FastAPI-specific plumbing and makes it reusable from Celery tasks.


@dataclass
class ResizeConflict:
    type: str
    detail: str


@dataclass
class SubnetResizePreview:
    old_cidr: str
    new_cidr: str
    network_address_shifts: bool
    old_network_ip: str
    new_network_ip: str
    old_broadcast_ip: str | None
    new_broadcast_ip: str | None
    total_ips_before: int
    total_ips_after: int
    gateway_current: str | None
    gateway_suggested_new_first_usable: str | None
    placeholders_default_named: list[dict[str, str]] = field(default_factory=list)
    placeholders_renamed: list[dict[str, str]] = field(default_factory=list)
    affected_ip_addresses_total: int = 0
    affected_dhcp_scopes: int = 0
    affected_dhcp_pools: int = 0
    affected_dhcp_static_assignments: int = 0
    affected_dns_records_auto: int = 0
    affected_active_leases: int = 0
    reverse_zones_existing: list[str] = field(default_factory=list)
    reverse_zones_will_be_created: list[str] = field(default_factory=list)
    conflicts: list[ResizeConflict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class BlockResizePreview:
    old_cidr: str
    new_cidr: str
    network_address_shifts: bool
    old_network_ip: str
    new_network_ip: str
    total_ips_before: int
    total_ips_after: int
    child_blocks_count: int
    child_blocks: list[dict[str, str]] = field(default_factory=list)
    child_subnets_count: int = 0
    child_subnets: list[dict[str, str]] = field(default_factory=list)
    descendant_ip_addresses_total: int = 0
    conflicts: list[ResizeConflict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class SubnetResizeResult:
    subnet: Subnet
    old_cidr: str
    new_cidr: str
    placeholders_deleted: int
    placeholders_created: int
    dhcp_servers_notified: int
    summary: list[str]


@dataclass
class BlockResizeResult:
    block: IPBlock
    old_cidr: str
    new_cidr: str
    summary: list[str]


class ResizeError(Exception):
    """Raised by the service when validation fails. Carries an HTTP status hint.

    The router layer translates the ``status_code`` attribute into an
    ``HTTPException``; we avoid importing FastAPI types from the service.
    """

    def __init__(self, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.status_code = status_code


# ── Internal helpers ─────────────────────────────────────────────────────────


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_cidr(value: str, *, label: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ResizeError(f"Invalid CIDR for {label}: {value}", status_code=422) from exc


_BIGINT_MAX = 2**63 - 1


def _total_ips(net: IPNetwork) -> int:
    """Mirror ``app.api.v1.ipam.router._total_ips`` so ``Subnet.total_ips``
    stays consistent across create / update / resize paths."""
    if isinstance(net, ipaddress.IPv6Network):
        return min(net.num_addresses, _BIGINT_MAX)
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


def _broadcast_or_none(net: IPNetwork) -> str | None:
    """IPv4 prefixlen ≤ 30 gets a broadcast IP; v4 /31+/32 and IPv6 do not."""
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen <= 30:
        return str(net.broadcast_address)
    return None


def _first_usable(net: IPNetwork) -> str | None:
    """Return the conventional first-usable host, or None when there isn't one.

    Matches the subnet-create default: ``net.network_address + 1`` as long
    as the prefix leaves room for a host above the network address. IPv6
    ranges: we still offer network + 1 for /≤126 (standard LAN /64 etc).
    Anything tighter has no meaningful first-usable and we return None.
    """
    if isinstance(net, ipaddress.IPv4Network):
        if net.prefixlen >= 31:
            return None
    else:  # IPv6
        if net.prefixlen >= 127:
            return None
    return str(net.network_address + 1)


def _advisory_lock_key(resource_id: uuid.UUID, namespace: int) -> tuple[int, int]:
    """Return ``(namespace, crc32-of-id)`` for ``pg_try_advisory_xact_lock``.

    CRC32 of the UUID string is cheap, deterministic, and fits in 32 bits.
    Collisions across distinct UUIDs are acceptable — the lock is an
    advisory serialiser, not a uniqueness guarantee.
    """
    key = zlib.crc32(str(resource_id).encode("utf-8"))
    # Postgres int4 is signed; fold to a signed 32-bit value so driver
    # binding treats it as int4 cleanly.
    if key >= 2**31:
        key -= 2**32
    return (namespace, key)


async def _try_advisory_lock(db: AsyncSession, resource_id: uuid.UUID, namespace: int) -> bool:
    ns, key = _advisory_lock_key(resource_id, namespace)
    row: bool = (
        await db.execute(
            text("SELECT pg_try_advisory_xact_lock(:ns, :key)"),
            {"ns": ns, "key": key},
        )
    ).scalar_one()
    return bool(row)


# ── Shared validation ────────────────────────────────────────────────────────


def _validate_grow(old_net: IPNetwork, new_net: IPNetwork) -> None:
    if isinstance(old_net, ipaddress.IPv4Network) != isinstance(new_net, ipaddress.IPv4Network):
        raise ResizeError(
            "Address family change is not supported (v4 ↔ v6). Create a new "
            "subnet in the target family instead.",
            status_code=422,
        )
    if new_net.prefixlen >= old_net.prefixlen:
        raise ResizeError(
            "Resize is grow-only — the new CIDR must have a smaller prefix "
            f"length (shorter mask) than the current /{old_net.prefixlen}. "
            "To reduce a subnet, delete it and recreate at the smaller size.",
            status_code=422,
        )
    if not old_net.subnet_of(new_net):  # type: ignore[arg-type]
        raise ResizeError(
            f"{old_net} is not contained within {new_net} — resize only grows; "
            "it does not move the network address outside the original range.",
            status_code=422,
        )


async def _overlap_conflicts_space_subnets(
    db: AsyncSession,
    space_id: uuid.UUID,
    new_cidr: str,
    *,
    exclude_subnet_id: uuid.UUID | None = None,
    old_cidr: str | None = None,
) -> list[ResizeConflict]:
    """Find subnets in the space that overlap the proposed new CIDR.

    We exclude the subnet being resized (naturally, the old CIDR is inside
    the new one — that is not a conflict). We also exclude any subnet whose
    CIDR equals the caller's ``old_cidr`` since the CIDR column is being
    atomically rewritten to the new value; the "overlap" detected by the
    PostgreSQL ``&&`` operator is with the row being mutated.
    """
    q = (
        "SELECT id, network FROM subnet "
        "WHERE space_id = CAST(:space_id AS uuid) "
        "AND network && CAST(:network AS cidr) "
        "AND deleted_at IS NULL"  # raw SQL skips the ORM soft-delete filter (#490)
    )
    params: dict[str, Any] = {"space_id": str(space_id), "network": new_cidr}
    if exclude_subnet_id:
        q += " AND id != CAST(:exclude_id AS uuid)"
        params["exclude_id"] = str(exclude_subnet_id)
    rows = (await db.execute(text(q), params)).fetchall()
    conflicts: list[ResizeConflict] = []
    for row in rows:
        other = str(row[1])
        # The row being resized is already excluded by id; we still filter
        # defensively in case the column rewrite race-conditions let an old
        # value leak through here.
        if old_cidr and other == old_cidr:
            continue
        conflicts.append(
            ResizeConflict(
                type="subnet_overlap",
                detail=f"New CIDR overlaps existing subnet {other} (id={row[0]})",
            )
        )
    return conflicts


async def _ancestor_block_ids_for_subnet(db: AsyncSession, subnet: Subnet) -> set[uuid.UUID]:
    """Walk ``block_id`` → ``parent_block_id`` → … up to the root.

    A subnet sits inside its parent block, which itself sits inside the
    parent's parent, etc. Those ancestors are *expected* to contain the
    subnet's CIDR — their `&&` overlap with the new CIDR is not a conflict.
    Everything else (cousins, nested children of an ancestor that aren't
    on this subnet's path) must still be flagged.
    """
    ancestors: set[uuid.UUID] = set()
    if subnet.block_id is None:
        return ancestors
    current: uuid.UUID | None = subnet.block_id
    # Guard against a cyclic parent chain — the materialized path isn't
    # present in this schema, so we cap the walk at a sensible depth.
    for _ in range(64):
        if current is None or current in ancestors:
            break
        ancestors.add(current)
        row = (
            await db.execute(
                text("SELECT parent_block_id FROM ip_block WHERE id = CAST(:id AS uuid)"),
                {"id": str(current)},
            )
        ).first()
        if row is None or row[0] is None:
            break
        current = row[0]
    return ancestors


async def _overlap_conflicts_space_blocks_for_subnet(
    db: AsyncSession,
    space_id: uuid.UUID,
    new_cidr: str,
    *,
    exclude_block_ids: set[uuid.UUID],
) -> list[ResizeConflict]:
    """Find blocks in the space that overlap the proposed new subnet CIDR.

    The subnet being resized has ancestor blocks that legitimately contain
    it; those are supplied in ``exclude_block_ids`` and filtered out.
    Anything else (cousins, nested children of ancestors) is a true conflict
    — the subnet would claim address space already attributed to a block.
    """
    q = (
        "SELECT id, network FROM ip_block "
        "WHERE space_id = CAST(:space_id AS uuid) "
        "AND network && CAST(:network AS cidr) "
        "AND deleted_at IS NULL"  # raw SQL skips the ORM soft-delete filter (#490)
    )
    params: dict[str, Any] = {"space_id": str(space_id), "network": new_cidr}
    rows = (await db.execute(text(q), params)).fetchall()
    conflicts: list[ResizeConflict] = []
    for row in rows:
        block_id = row[0]
        # Normalise DB row value → uuid.UUID for set comparison.
        if not isinstance(block_id, uuid.UUID):
            try:
                block_id = uuid.UUID(str(block_id))
            except (ValueError, TypeError):
                continue
        if block_id in exclude_block_ids:
            continue
        conflicts.append(
            ResizeConflict(
                type="block_overlap",
                detail=f"New CIDR overlaps existing block {row[1]} (id={row[0]})",
            )
        )
    return conflicts


async def _overlap_conflicts_space_blocks(
    db: AsyncSession,
    space_id: uuid.UUID,
    new_cidr: str,
    *,
    exclude_block_id: uuid.UUID | None,
) -> list[ResizeConflict]:
    """Check every block in the space for CIDR overlap with the proposed new CIDR.

    We *do not* filter to siblings: a block growing can collide with a
    cousin in a different subtree. The block being resized is excluded
    explicitly; its own descendants are excluded because the new CIDR is a
    strict superset of the old and therefore of the old's descendants
    (that containment is re-validated in commit with the recursive CTE
    "child_outside_new_cidr" check).
    """
    q = (
        "SELECT id, network FROM ip_block "
        "WHERE space_id = CAST(:space_id AS uuid) "
        "AND network && CAST(:network AS cidr) "
        "AND deleted_at IS NULL"  # raw SQL skips the ORM soft-delete filter (#490)
    )
    params: dict[str, Any] = {"space_id": str(space_id), "network": new_cidr}
    if exclude_block_id:
        # Exclude the subject block itself + the entire descendant tree.
        q += (
            " AND id NOT IN ("
            "  WITH RECURSIVE descendants AS ("
            "    SELECT id FROM ip_block WHERE id = CAST(:exclude_id AS uuid)"
            "    UNION ALL"
            "    SELECT b.id FROM ip_block b"
            "      INNER JOIN descendants d ON b.parent_block_id = d.id"
            "  )"
            "  SELECT id FROM descendants"
            ")"
        )
        params["exclude_id"] = str(exclude_block_id)
    rows = (await db.execute(text(q), params)).fetchall()
    return [
        ResizeConflict(
            type="block_overlap",
            detail=f"New CIDR overlaps existing block {row[1]} (id={row[0]})",
        )
        for row in rows
    ]


async def _overlap_conflicts_space_subnets_for_block(
    db: AsyncSession,
    space_id: uuid.UUID,
    new_cidr: str,
    *,
    block_id: uuid.UUID,
) -> list[ResizeConflict]:
    """Find subnets in the space that overlap the proposed new block CIDR.

    A block growing can swallow a subnet that lives under an entirely
    different parent. The subject block's own descendant subnets are
    excluded because old ⊂ new ⇒ those stay inside.
    """
    q = (
        "SELECT id, network FROM subnet "
        "WHERE space_id = CAST(:space_id AS uuid) "
        "AND network && CAST(:network AS cidr) "
        "AND deleted_at IS NULL "  # raw SQL skips the ORM soft-delete filter (#490)
        "AND (block_id IS NULL OR block_id NOT IN ("
        "  WITH RECURSIVE descendants AS ("
        "    SELECT id FROM ip_block WHERE id = CAST(:bid AS uuid)"
        "    UNION ALL"
        "    SELECT b.id FROM ip_block b"
        "      INNER JOIN descendants d ON b.parent_block_id = d.id"
        "  )"
        "  SELECT id FROM descendants"
        "))"
    )
    params: dict[str, Any] = {
        "space_id": str(space_id),
        "network": new_cidr,
        "bid": str(block_id),
    }
    rows = (await db.execute(text(q), params)).fetchall()
    return [
        ResizeConflict(
            type="subnet_overlap",
            detail=f"New CIDR overlaps existing subnet {row[1]} (id={row[0]})",
        )
        for row in rows
    ]


async def _parent_containment_conflicts_subnet(
    db: AsyncSession, subnet: Subnet, new_net: IPNetwork
) -> list[ResizeConflict]:
    """The subnet's parent block must still contain the new CIDR."""
    if subnet.block_id is None:
        # Historical schema drift — a subnet without a block is an orphan;
        # there is nothing to contain it. Treat as an implicit fit.
        return []
    parent = await db.get(IPBlock, subnet.block_id)
    if parent is None:
        return []
    parent_net = _parse_cidr(str(parent.network), label="parent block")
    if not new_net.subnet_of(parent_net):  # type: ignore[arg-type]
        return [
            ResizeConflict(
                type="parent_too_small",
                detail=(
                    f"Proposed CIDR {new_net} does not fit inside the parent block "
                    f"{parent.network}. Resize the parent block first."
                ),
            )
        ]
    return []


async def _parent_containment_conflicts_block(
    db: AsyncSession, block: IPBlock, new_net: IPNetwork
) -> list[ResizeConflict]:
    if block.parent_block_id is None:
        return []  # Top-level block — bounded only by the space.
    parent = await db.get(IPBlock, block.parent_block_id)
    if parent is None:
        return []
    parent_net = _parse_cidr(str(parent.network), label="parent block")
    if not new_net.subnet_of(parent_net):  # type: ignore[arg-type]
        return [
            ResizeConflict(
                type="parent_too_small",
                detail=(
                    f"Proposed CIDR {new_net} does not fit inside the parent block "
                    f"{parent.network}. Resize the parent block first."
                ),
            )
        ]
    return []


# ── Placeholder row helpers ──────────────────────────────────────────────────


async def _load_boundary_placeholders(
    db: AsyncSession, subnet_id: uuid.UUID, old_net: IPNetwork
) -> tuple[list[IPAddress], list[IPAddress]]:
    """Return (default_named, renamed) placeholder rows at the old boundaries.

    A "placeholder" is any IPAddress row whose ``status`` is ``network`` or
    ``broadcast`` — those statuses are only ever written by the subnet-create
    path and the manage-auto-addresses update. A row is "default-named"
    (safe to replace) when ``hostname`` is NULL and no user DNS record is
    attached; anything else is "renamed" and preserved verbatim.
    """
    boundary_ips = {str(old_net.network_address)}
    bcast = _broadcast_or_none(old_net)
    if bcast:
        boundary_ips.add(bcast)
    result = await db.execute(
        select(IPAddress).where(
            IPAddress.subnet_id == subnet_id,
            IPAddress.status.in_(("network", "broadcast")),
        )
    )
    default_named: list[IPAddress] = []
    renamed: list[IPAddress] = []
    for row in result.scalars().all():
        if str(row.address) not in boundary_ips:
            # Not at an old boundary — shouldn't happen in practice, but
            # keep it if so. (Defensive: if an operator manually inserted a
            # network/broadcast row at a weird address, leave it alone.)
            renamed.append(row)
            continue
        is_user_named = bool(row.hostname) and row.hostname not in (
            "network",
            "broadcast",
        )
        has_custom_desc = row.description not in (
            "",
            "Network address",
            "Broadcast address",
        )
        if is_user_named or has_custom_desc or row.dns_record_id is not None:
            renamed.append(row)
        else:
            default_named.append(row)
    return default_named, renamed


# ── Preview: subnets ─────────────────────────────────────────────────────────


async def preview_subnet_resize(
    db: AsyncSession,
    subnet: Subnet,
    new_cidr: str,
    *,
    move_gateway_to_first_usable: bool = False,
) -> SubnetResizePreview:
    """Compute the blast radius of resizing ``subnet`` to ``new_cidr``.

    Pure read — safe to call from GETs. Accumulates ``conflicts`` rather
    than raising, so the UI can disable the confirm button based on the
    returned payload. Malformed input (unparseable CIDR, wrong family,
    shrink attempt, etc.) comes back as a ``validation`` conflict; the
    endpoint must never 4xx on preview.
    """
    conflicts: list[ResizeConflict] = []
    warnings: list[str] = []

    # Parse both CIDRs defensively — malformed input lands in conflicts[]
    # rather than raising, so the preview endpoint stays HTTP 200.
    try:
        old_net = _parse_cidr(str(subnet.network), label="subnet")
    except ResizeError as exc:
        # If the stored subnet CIDR is un-parseable we can't compute
        # anything — return the best-effort shell so the UI can show the
        # error without 500-ing.
        conflicts.append(ResizeConflict(type="validation", detail=str(exc)))
        return SubnetResizePreview(
            old_cidr=str(subnet.network),
            new_cidr=new_cidr,
            network_address_shifts=False,
            old_network_ip="",
            new_network_ip="",
            old_broadcast_ip=None,
            new_broadcast_ip=None,
            total_ips_before=0,
            total_ips_after=0,
            gateway_current=str(subnet.gateway) if subnet.gateway else None,
            gateway_suggested_new_first_usable=None,
            conflicts=conflicts,
            warnings=warnings,
        )

    try:
        new_net = _parse_cidr(new_cidr, label="new CIDR")
    except ResizeError as exc:
        conflicts.append(ResizeConflict(type="validation", detail=str(exc)))
        return SubnetResizePreview(
            old_cidr=str(old_net),
            new_cidr=new_cidr,
            network_address_shifts=False,
            old_network_ip=str(old_net.network_address),
            new_network_ip="",
            old_broadcast_ip=_broadcast_or_none(old_net),
            new_broadcast_ip=None,
            total_ips_before=_total_ips(old_net),
            total_ips_after=0,
            gateway_current=str(subnet.gateway) if subnet.gateway else None,
            gateway_suggested_new_first_usable=None,
            conflicts=conflicts,
            warnings=warnings,
        )

    # Translate family/grow errors to conflicts so the UI shows them
    # instead of 4xx-ing the preview.
    try:
        _validate_grow(old_net, new_net)
    except ResizeError as exc:
        conflicts.append(ResizeConflict(type="validation", detail=str(exc)))

    canonical_new = str(new_net)
    canonical_old = str(old_net)

    # Space-wide overlap scan (siblings + cousins) across BOTH subnet and
    # block tables. A cousin block whose CIDR overlaps the new subnet CIDR
    # would silently re-attribute that address space on commit without this
    # scan.
    if not conflicts:
        conflicts.extend(
            await _overlap_conflicts_space_subnets(
                db,
                subnet.space_id,
                canonical_new,
                exclude_subnet_id=subnet.id,
                old_cidr=canonical_old,
            )
        )
        ancestor_block_ids = await _ancestor_block_ids_for_subnet(db, subnet)
        conflicts.extend(
            await _overlap_conflicts_space_blocks_for_subnet(
                db,
                subnet.space_id,
                canonical_new,
                exclude_block_ids=ancestor_block_ids,
            )
        )
        conflicts.extend(await _parent_containment_conflicts_subnet(db, subnet, new_net))

    # Placeholder classification — independent of conflicts so the UI can
    # show the distribution even when the preview is otherwise blocked.
    default_named, renamed = await _load_boundary_placeholders(db, subnet.id, old_net)
    placeholders_default_named = [
        {
            "ip": str(row.address),
            "hostname": row.hostname or ("network" if row.status == "network" else "broadcast"),
        }
        for row in default_named
    ]
    placeholders_renamed = [
        {
            "ip": str(row.address),
            "hostname": row.hostname or "(default)",
        }
        for row in renamed
    ]

    # Affected-resource counters.
    total_addresses = (
        await db.scalar(
            select(func.count()).select_from(IPAddress).where(IPAddress.subnet_id == subnet.id)
        )
    ) or 0

    scope_ids = [
        row[0]
        for row in (
            await db.execute(select(DHCPScope.id).where(DHCPScope.subnet_id == subnet.id))
        ).all()
    ]
    pool_count = 0
    static_count = 0
    if scope_ids:
        pool_count = (
            await db.scalar(
                select(func.count()).select_from(DHCPPool).where(DHCPPool.scope_id.in_(scope_ids))
            )
        ) or 0
        static_count = (
            await db.scalar(
                select(func.count())
                .select_from(DHCPStaticAssignment)
                .where(DHCPStaticAssignment.scope_id.in_(scope_ids))
            )
        ) or 0

    # Auto-generated DNS records attached to IPs in this subnet.
    auto_dns_count = (
        await db.scalar(
            select(func.count())
            .select_from(DNSRecord)
            .join(IPAddress, IPAddress.id == DNSRecord.ip_address_id)
            .where(
                IPAddress.subnet_id == subnet.id,
                DNSRecord.auto_generated.is_(True),
            )
        )
    ) or 0

    active_leases = 0
    if scope_ids:
        active_leases = (
            await db.scalar(
                select(func.count())
                .select_from(DHCPLease)
                .where(
                    DHCPLease.scope_id.in_(scope_ids),
                    DHCPLease.state == "active",
                )
            )
        ) or 0

    # Reverse-zone coverage — compute the aligned zone names for old and
    # new to surface what will be backfilled. ``compute_reverse_zone_name``
    # is idempotent; nothing here writes anything.
    from app.services.dns.reverse_zone import compute_reverse_zone_name

    try:
        old_rev = compute_reverse_zone_name(canonical_old)
    except ValueError:
        old_rev = ""
    try:
        new_rev = compute_reverse_zone_name(canonical_new)
    except ValueError:
        new_rev = ""
    reverse_existing = [old_rev] if old_rev else []
    reverse_will_create = [new_rev] if new_rev and new_rev != old_rev else []

    # Warnings (non-blocking).
    if pool_count:
        warnings.append(
            f"{pool_count} DHCP pool(s) on this subnet will not auto-expand "
            "into the new address space. Create a new pool if you want the "
            "extra range served."
        )
    warnings.append(
        f"Clients on this subnet must have their netmask updated from "
        f"/{old_net.prefixlen} to /{new_net.prefixlen}."
    )
    if str(new_net.network_address) != str(old_net.network_address):
        warnings.append(
            f"The network address shifts from {old_net.network_address} to "
            f"{new_net.network_address}. Update router ACLs, firewall rules, "
            "monitoring, and documentation that reference the old network."
        )

    # If the user asked to move the gateway but the new CIDR has no usable
    # host range (/31, /32, /127, /128), that's an explicit ask we can't
    # satisfy — surface it as a conflict so commit is blocked. Silently
    # leaving the gateway in place would misrepresent what happened.
    if move_gateway_to_first_usable and _first_usable(new_net) is None:
        conflicts.append(
            ResizeConflict(
                type="gateway_move_impossible",
                detail=(
                    f"Cannot move gateway to first-usable: new CIDR /{new_net.prefixlen} "
                    "has no usable host range. Uncheck 'Move gateway to new first-usable "
                    "IP' or pick a larger CIDR."
                ),
            )
        )

    return SubnetResizePreview(
        old_cidr=canonical_old,
        new_cidr=canonical_new,
        network_address_shifts=(str(new_net.network_address) != str(old_net.network_address)),
        old_network_ip=str(old_net.network_address),
        new_network_ip=str(new_net.network_address),
        old_broadcast_ip=_broadcast_or_none(old_net),
        new_broadcast_ip=_broadcast_or_none(new_net),
        total_ips_before=_total_ips(old_net),
        total_ips_after=_total_ips(new_net),
        gateway_current=str(subnet.gateway) if subnet.gateway else None,
        gateway_suggested_new_first_usable=_first_usable(new_net),
        placeholders_default_named=placeholders_default_named,
        placeholders_renamed=placeholders_renamed,
        affected_ip_addresses_total=int(total_addresses),
        affected_dhcp_scopes=len(scope_ids),
        affected_dhcp_pools=int(pool_count),
        affected_dhcp_static_assignments=int(static_count),
        affected_dns_records_auto=int(auto_dns_count),
        affected_active_leases=int(active_leases),
        reverse_zones_existing=reverse_existing,
        reverse_zones_will_be_created=reverse_will_create,
        conflicts=conflicts,
        warnings=warnings,
    )


# ── Preview: blocks ──────────────────────────────────────────────────────────


async def preview_block_resize(
    db: AsyncSession, block: IPBlock, new_cidr: str
) -> BlockResizePreview:
    conflicts: list[ResizeConflict] = []
    warnings: list[str] = []

    # Parse both CIDRs defensively — malformed input lands in conflicts[]
    # rather than raising, so the preview endpoint stays HTTP 200.
    try:
        old_net = _parse_cidr(str(block.network), label="block")
    except ResizeError as exc:
        conflicts.append(ResizeConflict(type="validation", detail=str(exc)))
        return BlockResizePreview(
            old_cidr=str(block.network),
            new_cidr=new_cidr,
            network_address_shifts=False,
            old_network_ip="",
            new_network_ip="",
            total_ips_before=0,
            total_ips_after=0,
            child_blocks_count=0,
            child_subnets_count=0,
            descendant_ip_addresses_total=0,
            conflicts=conflicts,
            warnings=warnings,
        )

    try:
        new_net = _parse_cidr(new_cidr, label="new CIDR")
    except ResizeError as exc:
        conflicts.append(ResizeConflict(type="validation", detail=str(exc)))
        return BlockResizePreview(
            old_cidr=str(old_net),
            new_cidr=new_cidr,
            network_address_shifts=False,
            old_network_ip=str(old_net.network_address),
            new_network_ip="",
            total_ips_before=int(min(old_net.num_addresses, _BIGINT_MAX)),
            total_ips_after=0,
            child_blocks_count=0,
            child_subnets_count=0,
            descendant_ip_addresses_total=0,
            conflicts=conflicts,
            warnings=warnings,
        )

    try:
        _validate_grow(old_net, new_net)
    except ResizeError as exc:
        conflicts.append(ResizeConflict(type="validation", detail=str(exc)))

    canonical_new = str(new_net)

    if not conflicts:
        # Space-wide block overlap (not limited to siblings) + subnet overlap.
        conflicts.extend(
            await _overlap_conflicts_space_blocks(
                db,
                block.space_id,
                canonical_new,
                exclude_block_id=block.id,
            )
        )
        conflicts.extend(
            await _overlap_conflicts_space_subnets_for_block(
                db,
                block.space_id,
                canonical_new,
                block_id=block.id,
            )
        )
        conflicts.extend(await _parent_containment_conflicts_block(db, block, new_net))

    # Walk the full descendant tree (recursive CTE) — for the count summary
    # and to confirm every child still fits. Mathematically old ⊂ new
    # already guarantees this, but a mismatched DB row (historical drift)
    # would be caught here.
    descendants = await db.execute(
        text("""
            WITH RECURSIVE descendants AS (
                SELECT id, network, name FROM ip_block
                    WHERE id = CAST(:bid AS uuid)
                UNION ALL
                SELECT b.id, b.network, b.name FROM ip_block b
                    INNER JOIN descendants d ON b.parent_block_id = d.id
            )
            SELECT id, network, name FROM descendants
                WHERE id != CAST(:bid AS uuid)
            """),
        {"bid": str(block.id)},
    )
    child_blocks_rows = descendants.fetchall()
    child_blocks = [
        {"id": str(r[0]), "network": str(r[1]), "name": r[2] or ""} for r in child_blocks_rows
    ]

    subnets_result = await db.execute(
        text("""
            WITH RECURSIVE descendants AS (
                SELECT id FROM ip_block WHERE id = CAST(:bid AS uuid)
                UNION ALL
                SELECT b.id FROM ip_block b
                    INNER JOIN descendants d ON b.parent_block_id = d.id
            )
            SELECT s.id, s.network, s.name FROM subnet s
                WHERE s.block_id IN (SELECT id FROM descendants)
            """),
        {"bid": str(block.id)},
    )
    child_subnet_rows = subnets_result.fetchall()
    child_subnets = [
        {"id": str(r[0]), "network": str(r[1]), "name": r[2] or ""} for r in child_subnet_rows
    ]

    # Every descendant must still fit (belt-and-braces).
    for row in child_blocks_rows:
        try:
            cn = ipaddress.ip_network(str(row[1]), strict=False)
        except ValueError:
            continue
        if not cn.subnet_of(new_net):  # type: ignore[arg-type]
            conflicts.append(
                ResizeConflict(
                    type="child_outside_new_cidr",
                    detail=f"Descendant block {row[1]} would no longer fit inside {new_net}",
                )
            )
    for row in child_subnet_rows:
        try:
            cn = ipaddress.ip_network(str(row[1]), strict=False)
        except ValueError:
            continue
        if not cn.subnet_of(new_net):  # type: ignore[arg-type]
            conflicts.append(
                ResizeConflict(
                    type="child_outside_new_cidr",
                    detail=f"Descendant subnet {row[1]} would no longer fit inside {new_net}",
                )
            )

    # Descendant IP total.
    descendant_ip_total = 0
    if child_subnet_rows:
        subnet_ids = [row[0] for row in child_subnet_rows]
        descendant_ip_total = (
            await db.scalar(
                select(func.count())
                .select_from(IPAddress)
                .where(IPAddress.subnet_id.in_(subnet_ids))
            )
        ) or 0

    if str(new_net.network_address) != str(old_net.network_address):
        warnings.append(
            f"The block network address shifts from {old_net.network_address} to "
            f"{new_net.network_address}. Child subnets are unchanged; only the "
            "block's displayed container CIDR moves."
        )

    return BlockResizePreview(
        old_cidr=str(old_net),
        new_cidr=canonical_new,
        network_address_shifts=(str(new_net.network_address) != str(old_net.network_address)),
        old_network_ip=str(old_net.network_address),
        new_network_ip=str(new_net.network_address),
        total_ips_before=int(min(old_net.num_addresses, _BIGINT_MAX)),
        total_ips_after=int(min(new_net.num_addresses, _BIGINT_MAX)),
        child_blocks_count=len(child_blocks),
        child_blocks=child_blocks,
        child_subnets_count=len(child_subnets),
        child_subnets=child_subnets,
        descendant_ip_addresses_total=int(descendant_ip_total),
        conflicts=conflicts,
        warnings=warnings,
    )


# ── Commit: subnets ──────────────────────────────────────────────────────────


async def commit_subnet_resize(
    db: AsyncSession,
    subnet: Subnet,
    new_cidr: str,
    *,
    move_gateway_to_first_usable: bool = False,
    replace_default_placeholders: bool = True,
    current_user: Any | None = None,
) -> SubnetResizeResult:
    """Apply the resize in a single transaction. Caller commits the session.

    Call sequence (see module docstring for the contract):

    1. Acquire a pg advisory xact lock on the subnet id.
    2. Re-run validation (TOCTOU guard).
    3. Delete default-named placeholder rows at the old boundaries.
       Renamed / DNS-backed placeholders are filtered out by
       ``_load_boundary_placeholders`` and never reach this loop.
    4. Mutate the CIDR / totals / gateway.
    5. Re-create default-named placeholder rows at the new boundaries.
    6. ``ensure_reverse_zone_for_subnet`` — idempotent backfill.
    7. Bump DHCP config bundles on any agent-based server serving a scope
       on this subnet. Skip agentless (Windows DHCP read-only) drivers.
    8. Update block utilization rollup.
    """
    # Lazy import to avoid the router → service → router cycle.
    from app.api.v1.ipam.router import (
        _update_block_utilization,
        _update_utilization,
    )

    if not await _try_advisory_lock(db, subnet.id, _LOCK_NS_SUBNET):
        raise ResizeError(
            "Another operation is already in progress for this subnet. " "Retry once it completes.",
            status_code=423,
        )

    old_net = _parse_cidr(str(subnet.network), label="subnet")
    new_net = _parse_cidr(new_cidr, label="new CIDR")

    # TOCTOU re-validation.
    _validate_grow(old_net, new_net)
    canonical_new = str(new_net)
    canonical_old = str(old_net)

    # Explicit gateway-move request on a /31/32/127/128 can't be satisfied.
    if move_gateway_to_first_usable and _first_usable(new_net) is None:
        raise ResizeError(
            f"Cannot move gateway to first-usable: new CIDR /{new_net.prefixlen} "
            "has no usable host range.",
            status_code=422,
        )

    overlap = await _overlap_conflicts_space_subnets(
        db,
        subnet.space_id,
        canonical_new,
        exclude_subnet_id=subnet.id,
        old_cidr=canonical_old,
    )
    if overlap:
        raise ResizeError(
            "New CIDR overlaps another subnet in the same space: "
            + "; ".join(c.detail for c in overlap),
            status_code=409,
        )
    # Sibling/cousin BLOCK overlap — a subnet resize must not silently
    # swallow a block in the same space. Ancestors of the subject subnet
    # (its parent, grandparent, …) legitimately contain it and are
    # excluded.
    ancestor_block_ids = await _ancestor_block_ids_for_subnet(db, subnet)
    block_overlap = await _overlap_conflicts_space_blocks_for_subnet(
        db,
        subnet.space_id,
        canonical_new,
        exclude_block_ids=ancestor_block_ids,
    )
    if block_overlap:
        raise ResizeError(
            "New CIDR overlaps an existing block in the same space: "
            + "; ".join(c.detail for c in block_overlap),
            status_code=409,
        )
    parent_conflicts = await _parent_containment_conflicts_subnet(db, subnet, new_net)
    if parent_conflicts:
        raise ResizeError(parent_conflicts[0].detail, status_code=422)

    # Snapshot old state for audit + summary.
    old_gateway = str(subnet.gateway) if subnet.gateway else None
    old_total = subnet.total_ips

    # 1. Delete default-named placeholder rows at the old boundaries.
    # ``_load_boundary_placeholders`` routes any row with ``dns_record_id
    # IS NOT NULL`` into ``renamed`` (preserved), so ``default_named`` is
    # guaranteed to have no attached DNS records here.
    default_named, _renamed = await _load_boundary_placeholders(db, subnet.id, old_net)
    placeholders_deleted = 0
    if replace_default_placeholders:
        for row in default_named:
            await db.delete(row)
            placeholders_deleted += 1
        await db.flush()

    # 2. Mutate subnet CIDR + computed fields.
    subnet.network = canonical_new
    subnet.total_ips = _total_ips(new_net)
    if move_gateway_to_first_usable:
        fu = _first_usable(new_net)
        if fu is not None:
            subnet.gateway = fu

    # 3. Re-create default-named placeholder rows at the new boundaries.
    placeholders_created = 0
    is_v6 = isinstance(new_net, ipaddress.IPv6Network)
    if replace_default_placeholders and new_net.prefixlen < 31:
        # Only emit the rows that are "missing" — a renamed placeholder at
        # the new boundary would still be covered by the rows we preserved
        # above. Guard against accidentally creating a duplicate at the
        # same address.
        existing_addr_rows = (
            (await db.execute(select(IPAddress.address).where(IPAddress.subnet_id == subnet.id)))
            .scalars()
            .all()
        )
        existing_addrs = {str(a) for a in existing_addr_rows}

        if str(new_net.network_address) not in existing_addrs:
            db.add(
                IPAddress(
                    subnet_id=subnet.id,
                    address=str(new_net.network_address),
                    status="network",
                    description="Network address",
                    created_by_user_id=(current_user.id if current_user is not None else None),
                )
            )
            placeholders_created += 1
        if not is_v6:
            bcast = str(new_net.broadcast_address)
            if bcast not in existing_addrs:
                db.add(
                    IPAddress(
                        subnet_id=subnet.id,
                        address=bcast,
                        status="broadcast",
                        description="Broadcast address",
                        created_by_user_id=(current_user.id if current_user is not None else None),
                    )
                )
                placeholders_created += 1
        await db.flush()

    # 4. Recompute utilization on this subnet and roll the parent block chain.
    await _update_utilization(db, subnet.id)
    if subnet.block_id:
        await _update_block_utilization(db, subnet.block_id)

    # 5. Reverse-zone backfill — idempotent, safe to always call.
    # If this fails, fail the whole resize loudly: the reverse zone is a
    # required piece of the commit contract, and a silent failure here
    # would poison the session and produce a confusing 500 at the
    # subsequent commit anyway. Retries are safe — ``new_cidr ==
    # current_cidr`` on the second attempt means zero delta. The function
    # returns None (not raises) for the legitimate "no DNS group
    # configured" case; any exception therefore represents a real issue
    # the operator needs to see.
    from app.services.dns.reverse_zone import ensure_reverse_zone_for_subnet

    await ensure_reverse_zone_for_subnet(db, subnet, current_user)

    # 6. Notify agent-based DHCP servers with a scope on this subnet.
    dhcp_servers_notified = await _bump_dhcp_bundles_for_subnet(db, subnet.id)

    summary = [
        f"Grew {canonical_old} → {canonical_new}",
        f"Total usable IPs: {old_total} → {subnet.total_ips}",
    ]
    if placeholders_deleted:
        summary.append(
            f"Replaced {placeholders_deleted} default-named placeholder row(s) "
            f"with {placeholders_created} new one(s)"
        )
    if move_gateway_to_first_usable and subnet.gateway != old_gateway:
        summary.append(f"Gateway moved {old_gateway} → {subnet.gateway}")
    elif old_gateway:
        summary.append(f"Gateway unchanged ({old_gateway}) — still inside new CIDR")
    if dhcp_servers_notified:
        summary.append(f"Notified {dhcp_servers_notified} DHCP server(s) to re-render config")

    logger.info(
        "subnet_resized",
        subnet_id=str(subnet.id),
        old_cidr=canonical_old,
        new_cidr=canonical_new,
        placeholders_deleted=placeholders_deleted,
        placeholders_created=placeholders_created,
        dhcp_servers_notified=dhcp_servers_notified,
    )

    return SubnetResizeResult(
        subnet=subnet,
        old_cidr=canonical_old,
        new_cidr=canonical_new,
        placeholders_deleted=placeholders_deleted,
        placeholders_created=placeholders_created,
        dhcp_servers_notified=dhcp_servers_notified,
        summary=summary,
    )


async def _bump_dhcp_bundles_for_subnet(db: AsyncSession, subnet_id: uuid.UUID) -> int:
    """Rebuild the DHCP ConfigBundle for every agent-based server whose
    group has a scope targeting this subnet, and enqueue an
    ``apply_config`` op if one isn't already pending. Returns the number
    of servers notified.

    Under the group-centric model, one scope change cascades to every
    member of the scope's group — all peers render the same config.
    """
    # scope.subnet_id → scope.group_id → servers in that group
    scope_rows = (
        (await db.execute(select(DHCPScope).where(DHCPScope.subnet_id == subnet_id)))
        .scalars()
        .all()
    )
    group_ids = {sc.group_id for sc in scope_rows}
    if not group_ids:
        return 0
    servers_res = await db.execute(
        select(DHCPServer).where(DHCPServer.server_group_id.in_(group_ids))
    )
    servers = list(servers_res.scalars().all())
    seen: set[uuid.UUID] = set()
    for server in servers:
        if server is None or server.id in seen:
            continue
        # Agentless (Windows DHCP read-only) has no write path — skip.
        if is_agentless(server.driver):
            continue
        bundle = await build_config_bundle(db, server)
        server.config_etag = bundle.etag
        existing = (
            await db.execute(
                select(DHCPConfigOp).where(
                    DHCPConfigOp.server_id == server.id,
                    DHCPConfigOp.op_type == "apply_config",
                    DHCPConfigOp.status == "pending",
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            db.add(
                DHCPConfigOp(
                    server_id=server.id,
                    op_type="apply_config",
                    payload={"etag": bundle.etag, "reason": "subnet_resize"},
                    status="pending",
                )
            )
        collect_wake(dhcp_server_channel(server.id))
        seen.add(server.id)
    return len(seen)


# ── Commit: blocks ───────────────────────────────────────────────────────────


async def commit_block_resize(
    db: AsyncSession,
    block: IPBlock,
    new_cidr: str,
    *,
    current_user: Any | None = None,
) -> BlockResizeResult:
    """Resize a block to a larger CIDR. No placeholder rows, no DHCP/DNS
    side effects at the block level itself — the block is a pure
    containment node.
    """
    from app.api.v1.ipam.router import _update_block_utilization

    # ``current_user`` is accepted for symmetry with the subnet path and for
    # audit-log plumbing in the router; the block resize itself makes no
    # per-user decisions, but we silence the "unused" warning explicitly so
    # callers can rely on the signature in future extensions.
    del current_user

    if not await _try_advisory_lock(db, block.id, _LOCK_NS_BLOCK):
        raise ResizeError(
            "Another operation is already in progress for this block. " "Retry once it completes.",
            status_code=423,
        )

    old_net = _parse_cidr(str(block.network), label="block")
    new_net = _parse_cidr(new_cidr, label="new CIDR")
    _validate_grow(old_net, new_net)
    canonical_new = str(new_net)
    canonical_old = str(old_net)

    # Space-wide block overlap — a block growing can collide with a
    # cousin under a different parent, not just a same-level sibling.
    # Descendant blocks are excluded because old ⊂ new guarantees they
    # stay inside (belt-and-braces check below confirms).
    block_overlap = await _overlap_conflicts_space_blocks(
        db,
        block.space_id,
        canonical_new,
        exclude_block_id=block.id,
    )
    if block_overlap:
        raise ResizeError(
            "New CIDR overlaps an existing block: " + "; ".join(c.detail for c in block_overlap),
            status_code=409,
        )
    # Space-wide subnet overlap — a block growing can swallow a subnet
    # from an entirely different subtree.
    subnet_overlap = await _overlap_conflicts_space_subnets_for_block(
        db,
        block.space_id,
        canonical_new,
        block_id=block.id,
    )
    if subnet_overlap:
        raise ResizeError(
            "New CIDR overlaps an existing subnet: " + "; ".join(c.detail for c in subnet_overlap),
            status_code=409,
        )
    parent_conflicts = await _parent_containment_conflicts_block(db, block, new_net)
    if parent_conflicts:
        raise ResizeError(parent_conflicts[0].detail, status_code=422)

    # Belt-and-braces: every descendant must still fit.
    descendants = await db.execute(
        text("""
            WITH RECURSIVE descendants AS (
                SELECT id, network FROM ip_block
                    WHERE id = CAST(:bid AS uuid)
                UNION ALL
                SELECT b.id, b.network FROM ip_block b
                    INNER JOIN descendants d ON b.parent_block_id = d.id
            )
            SELECT network FROM descendants WHERE id != CAST(:bid AS uuid)
            """),
        {"bid": str(block.id)},
    )
    for row in descendants.fetchall():
        cn = ipaddress.ip_network(str(row[0]), strict=False)
        if not cn.subnet_of(new_net):  # type: ignore[arg-type]
            raise ResizeError(
                f"Descendant block {row[0]} would no longer fit inside {new_net}",
                status_code=422,
            )
    subnets_check = await db.execute(
        text("""
            WITH RECURSIVE descendants AS (
                SELECT id FROM ip_block WHERE id = CAST(:bid AS uuid)
                UNION ALL
                SELECT b.id FROM ip_block b
                    INNER JOIN descendants d ON b.parent_block_id = d.id
            )
            SELECT s.network FROM subnet s
                WHERE s.block_id IN (SELECT id FROM descendants)
            """),
        {"bid": str(block.id)},
    )
    for row in subnets_check.fetchall():
        cn = ipaddress.ip_network(str(row[0]), strict=False)
        if not cn.subnet_of(new_net):  # type: ignore[arg-type]
            raise ResizeError(
                f"Descendant subnet {row[0]} would no longer fit inside {new_net}",
                status_code=422,
            )

    # Apply.
    block.network = canonical_new

    # Recompute utilisation on the block chain — the block's denominator
    # (block size) changed, so the percentage is stale even though the
    # allocated_ips total didn't move.
    await _update_block_utilization(db, block.id)

    summary = [
        f"Grew block {canonical_old} → {canonical_new}",
        "Child blocks and subnets are unchanged — only the container widened.",
    ]
    logger.info(
        "block_resized",
        block_id=str(block.id),
        old_cidr=canonical_old,
        new_cidr=canonical_new,
    )

    return BlockResizeResult(
        block=block,
        old_cidr=canonical_old,
        new_cidr=canonical_new,
        summary=summary,
    )


__all__ = [
    "BlockResizePreview",
    "BlockResizeResult",
    "ResizeConflict",
    "ResizeError",
    "SubnetResizePreview",
    "SubnetResizeResult",
    "commit_block_resize",
    "commit_subnet_resize",
    "preview_block_resize",
    "preview_subnet_resize",
]


# Silence "unused import" for a re-export-style helper only used by tests.
_ = sql_delete

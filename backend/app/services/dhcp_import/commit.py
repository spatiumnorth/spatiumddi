"""Source-agnostic commit pipeline for the DHCP configuration importer.

Takes a parsed :class:`ImportPreview` plus a per-scope strategy map and
writes the canonical IR to the DB, stamping ``import_source`` +
``imported_at`` on every row it creates. The Kea / Windows / ISC source
modules each emit the same IR; this module is the only place that
touches the DB so all three sources share IPAM linkage, conflict
handling, audit logging, and the per-scope savepoint commit pattern.

Per the issue spec, each scope commits independently — a failure on
scope N doesn't roll back scopes 1..N-1. The commit ledger we return
carries one row per attempted scope so the operator sees the
partial-success state cleanly.

IPAM linkage (the DHCP-specific wrinkle the DNS importer doesn't have):
``DHCPScope.subnet_id`` is mandatory, so every imported scope must bind
to an IPAM ``Subnet``. For each scope we either **link** to an existing
subnet whose CIDR matches, or **auto-create** one under the
operator-chosen IPSpace + IPBlock. A scope with no CIDR match and no
chosen block fails with a clear, actionable error.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import (
    DHCPClientClass,
    DHCPPool,
    DHCPScope,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.static_ipam import remove_ipam_for_scope_statics

from .canonical import (
    ConflictAction,
    ImportedScope,
    ImportPreview,
    ImportSource,
    ScopeConflict,
)


@dataclass
class CommitScopeResult:
    """One scope's outcome from the commit run."""

    subnet_cidr: str
    action_taken: str  # "created" | "overwrote" | "skipped" | "failed"
    scope_id: str | None = None
    subnet_id: str | None = None
    subnet_created: bool = False
    pools_created: int = 0
    reservations_created: int = 0
    error: str | None = None


@dataclass
class CommitResult:
    """Return shape from :func:`commit_import`. Mirrored 1:1 by the
    Pydantic ``CommitOut`` the API endpoint returns."""

    target_group_id: uuid.UUID
    scopes: list[CommitScopeResult]
    client_classes_created: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def total_scopes_created(self) -> int:
        return sum(1 for s in self.scopes if s.action_taken == "created")

    @property
    def total_scopes_overwrote(self) -> int:
        return sum(1 for s in self.scopes if s.action_taken == "overwrote")

    @property
    def total_scopes_skipped(self) -> int:
        return sum(1 for s in self.scopes if s.action_taken == "skipped")

    @property
    def total_scopes_failed(self) -> int:
        return sum(1 for s in self.scopes if s.action_taken == "failed")

    @property
    def total_subnets_created(self) -> int:
        return sum(1 for s in self.scopes if s.subnet_created)

    @property
    def total_pools_created(self) -> int:
        return sum(s.pools_created for s in self.scopes)

    @property
    def total_reservations_created(self) -> int:
        return sum(s.reservations_created for s in self.scopes)


def _canonical_cidr(raw: str) -> str:
    return str(ipaddress.ip_network(raw, strict=False))


async def _find_subnet(db: AsyncSession, cidr: str, space_id: uuid.UUID | None) -> Subnet | None:
    stmt = select(Subnet).where(Subnet.network == cidr, Subnet.deleted_at.is_(None))
    if space_id is not None:
        stmt = stmt.where(Subnet.space_id == space_id)
    return (await db.execute(stmt.limit(1))).scalars().first()


async def _existing_scope(
    db: AsyncSession,
    group_id: uuid.UUID,
    subnet_id: uuid.UUID,
    *,
    include_deleted: bool = False,
) -> DHCPScope | None:
    """Find the scope on ``(group_id, subnet_id)``.

    ``include_deleted=True`` bypasses the global soft-delete filter so
    the importer also catches a *soft-deleted* scope — it still occupies
    the ``uq_dhcp_scope_group_subnet`` unique slot, so a blind create
    would raise IntegrityError. Surfacing it lets the operator overwrite
    (which hard-deletes the trashed row + recreates)."""
    stmt = select(DHCPScope).where(
        DHCPScope.group_id == group_id,
        DHCPScope.subnet_id == subnet_id,
    )
    if include_deleted:
        # Disable the global ``deleted_at IS NULL`` filter for this query.
        stmt = stmt.execution_options(include_deleted=True)
    return (await db.execute(stmt)).scalars().first()


async def detect_conflicts(
    db: AsyncSession,
    *,
    scope_cidrs: list[str],
    target_group_id: uuid.UUID,
    ipam_space_id: uuid.UUID | None,
) -> list[ScopeConflict]:
    """For each parsed scope CIDR, report whether an IPAM subnet already
    matches (drives link-vs-create) and whether the target group already
    serves a scope on it (the blocking conflict — skip / overwrite).

    Used by both the preview endpoints (so the UI's per-scope strategy
    picker has accurate data) and the commit endpoint (so a stale plan
    still honours the up-to-date conflict state)."""
    out: list[ScopeConflict] = []
    for raw in scope_cidrs:
        try:
            cidr = _canonical_cidr(raw)
        except ValueError:
            continue
        subnet = await _find_subnet(db, cidr, ipam_space_id)
        existing_scope_id: str | None = None
        pool_count = res_count = 0
        soft_deleted = False
        if subnet is not None:
            scope = await _existing_scope(db, target_group_id, subnet.id, include_deleted=True)
            if scope is not None:
                existing_scope_id = str(scope.id)
                soft_deleted = scope.deleted_at is not None
                # Safe on a trashed scope: ``_existing_scope`` opted in with
                # include_deleted, and that propagates to the selectin child
                # loads — so these counts are the real blast radius the operator
                # is about to hard-delete with ``overwrite`` (see DHCPScope.pools).
                pool_count = len(scope.pools)
                res_count = len(scope.statics)
        # Emit a row when there's anything to tell the operator: an
        # existing scope (blocking) or an existing subnet (link vs
        # create). Pure-new scopes don't generate a row.
        if existing_scope_id is not None or subnet is not None:
            out.append(
                ScopeConflict(
                    subnet_cidr=cidr,
                    existing_scope_id=existing_scope_id,
                    existing_subnet_id=str(subnet.id) if subnet else None,
                    existing_subnet_name=(subnet.name or cidr) if subnet else None,
                    existing_pool_count=pool_count,
                    existing_reservation_count=res_count,
                    soft_deleted=soft_deleted,
                )
            )
    return out


async def _create_subnet(
    db: AsyncSession,
    *,
    cidr: str,
    space_id: uuid.UUID,
    block_id: uuid.UUID,
    now: datetime,
) -> Subnet:
    """Auto-create an IPAM subnet for an imported scope under the
    operator-chosen space + block. Validates containment + no overlap;
    skips the network/broadcast/gateway placeholder rows the manual
    create path adds (the imported pools + reservations are the real
    occupancy)."""
    block = await db.get(IPBlock, block_id)
    if block is None or block.space_id != space_id or block.deleted_at is not None:
        raise ValueError("chosen IPAM block is not in the chosen IP space")

    net = ipaddress.ip_network(cidr, strict=False)
    block_net = ipaddress.ip_network(str(block.network), strict=False)
    if isinstance(net, ipaddress.IPv4Network) and isinstance(block_net, ipaddress.IPv4Network):
        contained = net.subnet_of(block_net)
    elif isinstance(net, ipaddress.IPv6Network) and isinstance(block_net, ipaddress.IPv6Network):
        contained = net.subnet_of(block_net)
    else:
        contained = False
    if not contained:
        raise ValueError(f"scope {cidr} is not contained by block {block.network}")

    # Overlap guard — any non-identical subnet in this space whose range
    # intersects ours blocks the create (operator should link, not
    # duplicate). An exact match would have been resolved as a link
    # upstream, so reaching here with an overlap means a partial overlap.
    existing = (
        (
            await db.execute(
                select(Subnet).where(Subnet.space_id == space_id, Subnet.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    for other in existing:
        try:
            other_net = ipaddress.ip_network(str(other.network), strict=False)
        except ValueError:
            continue
        if other_net.version != net.version:
            continue
        if net.overlaps(other_net):
            raise ValueError(
                f"scope {cidr} overlaps existing subnet {other.network} in the chosen space — "
                "link to it or resolve the overlap first"
            )

    if isinstance(net, ipaddress.IPv6Network):
        is_multicast = net.subnet_of(ipaddress.IPv6Network("ff00::/8"))
    else:
        is_multicast = net.subnet_of(ipaddress.IPv4Network("224.0.0.0/4"))

    subnet = Subnet(
        space_id=space_id,
        block_id=block_id,
        network=cidr,
        name="",
        kind="multicast" if is_multicast else "unicast",
        total_ips=net.num_addresses,
        utilization_percent=0.0,
        allocated_ips=0,
    )
    db.add(subnet)
    await db.flush()
    return subnet


def _scope_kwargs(
    parsed: ImportedScope,
    *,
    group_id: uuid.UUID,
    subnet_id: uuid.UUID,
    source: ImportSource,
    now: datetime,
) -> dict[str, Any]:
    return dict(
        group_id=group_id,
        subnet_id=subnet_id,
        is_active=parsed.is_active,
        name=parsed.name or "",
        description=parsed.description or "",
        address_family=parsed.address_family,
        v6_address_mode=parsed.v6_address_mode or "stateful",
        lease_time=parsed.lease_time,
        min_lease_time=parsed.min_lease_time,
        max_lease_time=parsed.max_lease_time,
        options=dict(parsed.options or {}),
        ddns_enabled=parsed.ddns_enabled,
        ddns_hostname_policy=parsed.ddns_hostname_policy or "client",
        import_source=source,
        imported_at=now,
    )


async def _commit_one_scope(
    db: AsyncSession,
    *,
    parsed: ImportedScope,
    target_group_id: uuid.UUID,
    ipam_space_id: uuid.UUID | None,
    ipam_block_id: uuid.UUID | None,
    source: ImportSource,
    action: ConflictAction,
    current_user: User,
    now: datetime,
) -> CommitScopeResult:
    """Apply one parsed scope: resolve its IPAM subnet, honour the
    operator's skip/overwrite choice on an existing scope, then create
    the scope + pools + reservations. Caller wraps in try/except +
    rollback so a failed scope doesn't poison the next one."""
    cidr = _canonical_cidr(parsed.subnet_cidr)

    subnet = await _find_subnet(db, cidr, ipam_space_id)
    subnet_created = False
    if subnet is None:
        if ipam_space_id is None or ipam_block_id is None:
            return CommitScopeResult(
                subnet_cidr=cidr,
                action_taken="failed",
                error=(
                    f"No IPAM subnet matches {cidr}. Pick an IP space + block to auto-create the "
                    "subnet, or create it first and re-run."
                ),
            )
        subnet = await _create_subnet(
            db, cidr=cidr, space_id=ipam_space_id, block_id=ipam_block_id, now=now
        )
        subnet_created = True

    # include_deleted so a soft-deleted scope (still holding the unique
    # slot) is handled via skip/overwrite rather than blowing up on the
    # constraint at flush time.
    existing = await _existing_scope(db, target_group_id, subnet.id, include_deleted=True)
    overwrote = False
    if existing is not None:
        if action == "skip":
            return CommitScopeResult(
                subnet_cidr=cidr,
                action_taken="skipped",
                subnet_id=str(subnet.id),
                subnet_created=subnet_created,
            )
        # overwrite — hard-delete the existing scope (cascades pools +
        # statics, and purges it from Trash if it was soft-deleted),
        # freeing the unique slot before the recreate flush.
        #
        # The reservations go via FK CASCADE, which runs no Python, so their
        # IPAM mirrors have to be removed here or the addresses are stranded at
        # ``status="static_dhcp"`` pointing at rows Postgres has dropped (#618).
        # Delete the mirror rows (not just free them) so the IPs fold back into
        # free gaps in the subnet view.
        await remove_ipam_for_scope_statics(db, existing.id)
        await db.delete(existing)
        await db.flush()
        overwrote = True

    scope = DHCPScope(
        **_scope_kwargs(
            parsed, group_id=target_group_id, subnet_id=subnet.id, source=source, now=now
        )
    )
    db.add(scope)
    await db.flush()

    # Link the subnet to the group so IPAM reflects DHCP ownership.
    subnet.dhcp_server_group_id = target_group_id

    pools_created = 0
    for p in parsed.pools:
        db.add(
            DHCPPool(
                scope_id=scope.id,
                name=p.name or "",
                start_ip=p.start_ip,
                end_ip=p.end_ip,
                pool_type=p.pool_type or "dynamic",
                class_restriction=p.class_restriction,
                import_source=source,
                imported_at=now,
            )
        )
        pools_created += 1

    res_created = 0
    seen_mac: set[str] = set()
    seen_ip: set[str] = set()
    for r in parsed.reservations:
        if r.mac_address in seen_mac or r.ip_address in seen_ip:
            continue
        seen_mac.add(r.mac_address)
        seen_ip.add(r.ip_address)
        db.add(
            DHCPStaticAssignment(
                scope_id=scope.id,
                ip_address=r.ip_address,
                mac_address=r.mac_address,
                hostname=r.hostname or "",
                client_id=r.client_id,
                options_override=dict(r.options) if r.options else None,
                import_source=source,
                imported_at=now,
            )
        )
        res_created += 1

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="update" if overwrote else "create",
            resource_type="dhcp_scope",
            resource_id=str(scope.id),
            resource_display=cidr,
            result="success",
            new_value={
                "import_source": source,
                "subnet_cidr": cidr,
                "subnet_created": subnet_created,
                "pools_created": pools_created,
                "reservations_created": res_created,
                "overwrote_existing": overwrote,
            },
        )
    )
    await db.commit()
    await db.refresh(scope)

    return CommitScopeResult(
        subnet_cidr=cidr,
        action_taken="overwrote" if overwrote else "created",
        scope_id=str(scope.id),
        subnet_id=str(subnet.id),
        subnet_created=subnet_created,
        pools_created=pools_created,
        reservations_created=res_created,
    )


async def _commit_client_classes(
    db: AsyncSession,
    *,
    preview: ImportPreview,
    target_group_id: uuid.UUID,
    source: ImportSource,
    now: datetime,
    current_user: User,
) -> int:
    """Create the supported client classes group-wide, skipping any that
    already exist by name and any flagged unsupported (manual review).
    Each class commits in its own savepoint."""
    created = 0
    for cc in preview.client_classes:
        if not cc.supported:
            continue
        try:
            existing = (
                (
                    await db.execute(
                        select(DHCPClientClass).where(
                            DHCPClientClass.group_id == target_group_id,
                            DHCPClientClass.name == cc.name,
                        )
                    )
                )
                .scalars()
                .first()
            )
            if existing is not None:
                continue
            row = DHCPClientClass(
                group_id=target_group_id,
                name=cc.name,
                match_expression=cc.match_expression or "",
                description=cc.description or "",
                address_family=cc.address_family or "ipv4",
                options=dict(cc.options or {}),
                import_source=source,
                imported_at=now,
            )
            db.add(row)
            await db.flush()
            db.add(
                AuditLog(
                    user_id=current_user.id,
                    user_display_name=current_user.display_name,
                    auth_source=current_user.auth_source,
                    action="create",
                    resource_type="dhcp_client_class",
                    resource_id=str(row.id),
                    resource_display=cc.name,
                    result="success",
                    new_value={"import_source": source},
                )
            )
            await db.commit()
            created += 1
        except Exception:  # noqa: BLE001 — one bad class shouldn't poison the rest
            await db.rollback()
    return created


async def commit_import(
    db: AsyncSession,
    *,
    preview: ImportPreview,
    target_group_id: uuid.UUID,
    ipam_space_id: uuid.UUID | None,
    ipam_block_id: uuid.UUID | None,
    conflict_actions: dict[str, ConflictAction],
    current_user: User,
) -> CommitResult:
    """Apply ``preview`` to the DB inside per-scope savepoints.

    ``conflict_actions`` is keyed by the scope's canonical CIDR.
    Scopes the operator left untouched default to ``skip`` on conflict
    (don't trample an existing scope) and plain-create otherwise."""
    grp = (
        await db.execute(select(DHCPServerGroup).where(DHCPServerGroup.id == target_group_id))
    ).scalar_one_or_none()
    if grp is None:
        raise ValueError(f"Target DHCP server group {target_group_id} does not exist")

    if ipam_space_id is not None:
        space = await db.get(IPSpace, ipam_space_id)
        if space is None:
            raise ValueError(f"IP space {ipam_space_id} does not exist")
    if ipam_block_id is not None:
        if ipam_space_id is None:
            raise ValueError("ipam_block_id requires ipam_space_id")
        block = await db.get(IPBlock, ipam_block_id)
        if block is None or block.space_id != ipam_space_id:
            raise ValueError("IPAM block does not exist in the chosen IP space")

    now = datetime.now(UTC)
    results: list[CommitScopeResult] = []

    for parsed in preview.scopes:
        try:
            cidr = _canonical_cidr(parsed.subnet_cidr)
        except ValueError:
            results.append(
                CommitScopeResult(
                    subnet_cidr=parsed.subnet_cidr,
                    action_taken="failed",
                    error="unparseable subnet CIDR",
                )
            )
            continue
        action: ConflictAction = conflict_actions.get(cidr, "skip")
        try:
            result = await _commit_one_scope(
                db,
                parsed=parsed,
                target_group_id=target_group_id,
                ipam_space_id=ipam_space_id,
                ipam_block_id=ipam_block_id,
                source=preview.source,
                action=action,
                current_user=current_user,
                now=now,
            )
        except Exception as exc:  # noqa: BLE001 — operator-facing error capture
            await db.rollback()
            result = CommitScopeResult(
                subnet_cidr=cidr,
                action_taken="failed",
                error=str(exc),
            )
        results.append(result)

    classes_created = await _commit_client_classes(
        db,
        preview=preview,
        target_group_id=target_group_id,
        source=preview.source,
        now=now,
        current_user=current_user,
    )

    return CommitResult(
        target_group_id=target_group_id,
        scopes=results,
        client_classes_created=classes_created,
        warnings=list(preview.warnings),
    )

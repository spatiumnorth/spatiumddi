"""Source-agnostic commit pipeline for the NetBox one-shot importer (issue #36 §4.3).

Takes the canonical :class:`ImportPreview` the preview endpoint produced
(round-tripped verbatim by the operator as ``CommitIn.plan``) and writes
every chosen entity into native IPAM rows, stamping ``import_source=
"netbox"`` + ``imported_at`` + the NetBox primary key on every row it
creates. This is the only module that touches the DB.

It clones the DHCP importer's committer mechanics
(:mod:`app.services.dhcp_import.commit`) **exactly**:

* **Per-row savepoint** — each entity gets its own ``db.commit()`` inside
  the loop; on exception ``db.rollback()`` + a ``failed`` ledger row, so a
  failure on entity N never rolls back entities 1..N-1. Not one giant
  transaction.
* **Audit before commit** — exactly one :class:`AuditLog` row per
  successfully-committed entity, written **inside** the committer before
  ``db.commit()`` (non-negotiable #4). ``resource_type`` ∈
  ``{ip_space, ip_block, subnet, ip_address, vrf, vlan, customer, site}``,
  ``action = update`` when it overwrote a conflict else ``create``.
* **Idempotent re-run** — entities are re-matched by their stable natural
  key (customer/VRF/space by name|rd; block/subnet by ``(space, CIDR)``;
  VLAN by ``(router, vid|name)``; address by ``(subnet, address)``) and the
  match is handled per ``conflict_actions`` (default ``skip``), so a second
  run of an unchanged NetBox is a no-op. ``netbox_id`` is stamped onto each
  created row's ``custom_fields``/``tags`` for provenance, but is **not**
  itself the re-match key — an entity renamed/re-CIDR'd in NetBox between
  runs is matched on its NEW natural key (so it creates rather than updates;
  matching on the persisted ``netbox_id`` to follow renames is a documented
  follow-up). **No absence-delete** — a row deleted in NetBox is left alone
  (one-shot migration, not a reconciler).
* **No wake_publishing** — NetBox seeds IPAM only, touches no DNS / DHCP
  agent config.

Commit ordering (FK + overlap correctness, ``netbox_ctx/03_models.md`` §13):

    Customers → Sites (region-parent-first) → VRFs → IPSpaces (per_vrf:
    one per VRF + Global; single: target_space_id) → Router (+ VLANs) →
    IPBlocks (largest-prefix-first) → Subnets (largest-first; auto-create
    an ``auto:<cidr>`` wrapper block if none encloses) → IPAddresses
    (most-specific subnet).

Overlap guards replicate the IPAM router's ``_assert_no_overlap`` /
``_assert_no_block_overlap`` semantics + the DHCP ``_create_subnet``
containment guard, but raise plain :class:`ValueError` (not the router's
``HTTPException``) so a per-row failure lands as a clean ``failed`` ledger
row instead of an uncaught 409 aborting the batch.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import sanitize_hostname
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.ownership import Customer, Site
from app.models.vlans import VLAN, Router
from app.models.vrf import VRF
from app.services.import_savepoint import entity_savepoint as _entity_savepoint
from app.services.router_naming import pick_unique_router_name

from .canonical import (
    ConflictAction,
    EntityConflict,
    ImportedAddress,
    ImportedBlock,
    ImportedSubnet,
    ImportPreview,
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_SOURCE = "netbox"


# --------------------------------------------------------------------------- #
# Commit ledger (return shape — mirrored 1:1 by the Pydantic ``CommitOut``).
# --------------------------------------------------------------------------- #


@dataclass
class CommitEntityResult:
    """One entity's outcome from the commit run."""

    kind: str  # ip_space | ip_block | subnet | ip_address | vrf | vlan | customer | site
    key: str  # stable per-kind key (name / CIDR / vid / address)
    action_taken: str  # "created" | "overwrote" | "skipped" | "failed"
    entity_id: str | None = None
    error: str | None = None


@dataclass
class CommitResult:
    """Return shape from :func:`commit_import`. Mirrored 1:1 by the
    Pydantic ``CommitOut`` the API endpoint returns."""

    source: str
    entities: list[CommitEntityResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def _count(self, kind: str, action: str) -> int:
        return sum(1 for e in self.entities if e.kind == kind and e.action_taken == action)

    def _count_action(self, action: str) -> int:
        return sum(1 for e in self.entities if e.action_taken == action)

    # Per-kind created rollups (the Pydantic layer surfaces these).
    @property
    def customers_created(self) -> int:
        return self._count("customer", "created")

    @property
    def sites_created(self) -> int:
        return self._count("site", "created")

    @property
    def vrfs_created(self) -> int:
        return self._count("vrf", "created")

    @property
    def spaces_created(self) -> int:
        return self._count("ip_space", "created")

    @property
    def vlans_created(self) -> int:
        return self._count("vlan", "created")

    @property
    def blocks_created(self) -> int:
        return self._count("ip_block", "created")

    @property
    def subnets_created(self) -> int:
        return self._count("subnet", "created")

    @property
    def addresses_created(self) -> int:
        return self._count("ip_address", "created")

    @property
    def total_created(self) -> int:
        return self._count_action("created")

    @property
    def total_overwrote(self) -> int:
        return self._count_action("overwrote")

    @property
    def total_skipped(self) -> int:
        return self._count_action("skipped")

    @property
    def total_failed(self) -> int:
        return self._count_action("failed")


# --------------------------------------------------------------------------- #
# CIDR / parse helpers.
# --------------------------------------------------------------------------- #


def _canonical_cidr(raw: str) -> str:
    return str(ipaddress.ip_network(raw, strict=False))


def _parse_net(cidr: str) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def _key_cidr(raw: str) -> str:
    """CIDR form used in conflict keys — canonical when parseable, else raw.

    ``detect_conflicts`` (which stamps ``EntityConflict.key``) and the commit
    loop (which looks up the operator's ``conflict_actions``) MUST agree on
    this, or an ``overwrite`` decision on a non-canonical CIDR silently
    degrades to ``skip``.
    """
    return _canonical_cidr(raw) if _parse_net(raw) else raw


def _contained(net: IPNetwork, outer: IPNetwork) -> bool:
    """Version-matched ``net.subnet_of(outer)`` (False on a version mismatch)."""
    if isinstance(net, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return net.subnet_of(outer)
    if isinstance(net, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return net.subnet_of(outer)
    return False


# --------------------------------------------------------------------------- #
# Conflict keys — stable per-kind identity the operator's conflict_actions
# is keyed on (and the preview's EntityConflict.key carries).
# --------------------------------------------------------------------------- #


def _vrf_key(vrf_name: str, rd: str | None) -> str:
    return f"vrf:{rd}" if rd else f"vrf:{vrf_name}"


def _customer_key(name: str) -> str:
    return f"customer:{name}"


def _site_key(name: str, code: str | None) -> str:
    return f"site:{code or name}"


def _space_key(name: str) -> str:
    return f"ip_space:{name}"


def _block_key(space_name: str | None, cidr: str) -> str:
    return f"ip_block:{space_name or ''}:{cidr}"


def _subnet_key(space_name: str | None, cidr: str) -> str:
    return f"subnet:{space_name or ''}:{cidr}"


def _address_key(subnet_cidr: str | None, address: str) -> str:
    return f"ip_address:{subnet_cidr or ''}:{address}"


def _vlan_key(vid: int) -> str:
    return f"vlan:{vid}"


# --------------------------------------------------------------------------- #
# DB lookups for conflict detection (re-used by preview + the commit re-detect).
# --------------------------------------------------------------------------- #


async def _find_customer(db: AsyncSession, name: str) -> Customer | None:
    return (
        (await db.execute(select(Customer).where(Customer.name == name).limit(1))).scalars().first()
    )


async def _find_site(db: AsyncSession, name: str, code: str | None) -> Site | None:
    stmt = select(Site).where(Site.name == name)
    if code:
        stmt = select(Site).where(Site.code == code)
    return (await db.execute(stmt.limit(1))).scalars().first()


async def _find_vrf(db: AsyncSession, name: str, rd: str | None) -> VRF | None:
    """Match an existing VRF by rd first (upsert key #1), else by name (#2)."""
    if rd:
        row = (
            (await db.execute(select(VRF).where(VRF.route_distinguisher == rd).limit(1)))
            .scalars()
            .first()
        )
        if row is not None:
            return row
    return (await db.execute(select(VRF).where(VRF.name == name).limit(1))).scalars().first()


async def _find_space(db: AsyncSession, name: str) -> IPSpace | None:
    return (
        (
            await db.execute(
                select(IPSpace).where(IPSpace.name == name, IPSpace.deleted_at.is_(None)).limit(1)
            )
        )
        .scalars()
        .first()
    )


async def _find_block(db: AsyncSession, space_id: uuid.UUID, cidr: str) -> IPBlock | None:
    return (
        (
            await db.execute(
                select(IPBlock)
                .where(
                    IPBlock.space_id == space_id,
                    IPBlock.network == cidr,
                    IPBlock.deleted_at.is_(None),
                )
                .limit(1)
            )
        )
        .scalars()
        .first()
    )


async def _find_subnet(db: AsyncSession, space_id: uuid.UUID, cidr: str) -> Subnet | None:
    return (
        (
            await db.execute(
                select(Subnet)
                .where(
                    Subnet.space_id == space_id,
                    Subnet.network == cidr,
                    Subnet.deleted_at.is_(None),
                )
                .limit(1)
            )
        )
        .scalars()
        .first()
    )


async def _find_address(db: AsyncSession, subnet_id: uuid.UUID, address: str) -> IPAddress | None:
    return (
        (
            await db.execute(
                select(IPAddress)
                .where(IPAddress.subnet_id == subnet_id, IPAddress.address == address)
                .limit(1)
            )
        )
        .scalars()
        .first()
    )


async def _resolve_target_space(
    db: AsyncSession,
    *,
    space_strategy: str,
    target_space_id: uuid.UUID | None,
    space_name: str | None,
) -> IPSpace | None:
    """Resolve the IPSpace an entity targets, per strategy.

    ``single`` → the operator-chosen ``target_space_id``. ``per_vrf`` →
    the existing space whose name matches the IR ``space_name`` (the
    committer will have created it earlier in the run). Returns ``None``
    when it can't be resolved yet (caller treats as "no DB row to
    conflict against").
    """
    if space_strategy == "single":
        if target_space_id is None:
            return None
        return await db.get(IPSpace, target_space_id)
    if space_name:
        return await _find_space(db, space_name)
    return None


# --------------------------------------------------------------------------- #
# detect_conflicts — per-entity collision report.
# --------------------------------------------------------------------------- #


async def detect_conflicts(
    db: AsyncSession,
    *,
    preview: ImportPreview,
    space_strategy: str = "per_vrf",
    target_space_id: uuid.UUID | None = None,
) -> list[EntityConflict]:
    """Flag every imported entity whose key already exists in the target.

    Walks the IR and emits one :class:`EntityConflict` per entity that
    collides with a live DB row (existing IPSpace by name, VRF by
    rd|name, Customer by name, Site by name/code, Subnet by
    ``(space, network)``, IPBlock by ``(space, network)``, IPAddress by
    ``(subnet, address)``). VLANs are conflict-checked at commit time
    against the synthetic router (no stable pre-router key exists at
    preview time), so they're omitted here.

    Used by both the preview endpoint (advisory) and the commit endpoint
    (re-detected fresh so a stale plan honours up-to-date state)."""
    out: list[EntityConflict] = []

    # Customers — UNIQUE name.
    for c in preview.customers:
        existing = await _find_customer(db, c.name)
        if existing is not None:
            out.append(
                EntityConflict(
                    kind="customer",
                    key=_customer_key(c.name),
                    existing_id=str(existing.id),
                    reason=f"Customer {c.name!r} already exists",
                )
            )

    # Sites — name / code per parent.
    for s in preview.sites:
        existing_site = await _find_site(db, s.name, s.code)
        if existing_site is not None:
            out.append(
                EntityConflict(
                    kind="site",
                    key=_site_key(s.name, s.code),
                    existing_id=str(existing_site.id),
                    reason=f"Site {s.name!r} already exists",
                )
            )

    # VRFs — rd|name.
    for v in preview.vrfs:
        existing_vrf = await _find_vrf(db, v.name, v.rd)
        if existing_vrf is not None:
            out.append(
                EntityConflict(
                    kind="vrf",
                    key=_vrf_key(v.name, v.rd),
                    existing_id=str(existing_vrf.id),
                    reason=f"VRF {v.rd or v.name!r} already exists",
                )
            )

    # Spaces — UNIQUE name (only synthesised under per_vrf).
    for sp in preview.spaces:
        existing_space = await _find_space(db, sp.name)
        if existing_space is not None:
            out.append(
                EntityConflict(
                    kind="ip_space",
                    key=_space_key(sp.name),
                    existing_id=str(existing_space.id),
                    reason=f"IP space {sp.name!r} already exists (will be reused)",
                )
            )

    # Blocks — (space, network).
    for b in preview.blocks:
        cidr = _key_cidr(b.network)
        space = await _resolve_target_space(
            db,
            space_strategy=space_strategy,
            target_space_id=target_space_id,
            space_name=b.space_name,
        )
        if space is None:
            continue
        existing_block = await _find_block(db, space.id, cidr)
        if existing_block is not None:
            out.append(
                EntityConflict(
                    kind="ip_block",
                    key=_block_key(b.space_name, cidr),
                    existing_id=str(existing_block.id),
                    reason=f"Block {cidr} already exists in space {space.name!r}",
                )
            )

    # Subnets — (space, network).
    for sub in preview.subnets:
        cidr = _key_cidr(sub.network)
        space = await _resolve_target_space(
            db,
            space_strategy=space_strategy,
            target_space_id=target_space_id,
            space_name=sub.space_name,
        )
        if space is None:
            continue
        existing_subnet = await _find_subnet(db, space.id, cidr)
        if existing_subnet is not None:
            out.append(
                EntityConflict(
                    kind="subnet",
                    key=_subnet_key(sub.space_name, cidr),
                    existing_id=str(existing_subnet.id),
                    reason=f"Subnet {cidr} already exists in space {space.name!r}",
                )
            )

    # Addresses — (subnet, address). Resolve the enclosing subnet by
    # CIDR within the resolved space; only conflict-flag when both the
    # subnet AND the address row already exist.
    for a in preview.addresses:
        space = await _resolve_target_space(
            db,
            space_strategy=space_strategy,
            target_space_id=target_space_id,
            space_name=a.space_name,
        )
        if space is None or not a.subnet_cidr:
            continue
        net = _parse_net(a.subnet_cidr)
        if net is None:
            continue
        existing_subnet = await _find_subnet(db, space.id, str(net))
        if existing_subnet is None:
            continue
        existing_addr = await _find_address(db, existing_subnet.id, a.address)
        if existing_addr is not None:
            out.append(
                EntityConflict(
                    kind="ip_address",
                    key=_address_key(a.subnet_cidr, a.address),
                    existing_id=str(existing_addr.id),
                    reason=f"Address {a.address} already exists in {existing_subnet.network}",
                )
            )

    return out


# --------------------------------------------------------------------------- #
# Overlap guards — ValueError-raising replicas of the IPAM router validators.
# --------------------------------------------------------------------------- #


async def _assert_subnet_no_overlap(db: AsyncSession, *, space_id: uuid.UUID, network: str) -> None:
    """Raise ValueError if ``network`` overlaps any live subnet in the space.

    Replicates ``_assert_no_overlap`` (ipam/router.py) — subnet overlap is
    forbidden space-wide (the PG ``&&`` operator) — but as a ValueError so
    a per-row failure lands cleanly in the commit ledger.
    """
    q = (
        "SELECT network FROM subnet "
        "WHERE space_id = CAST(:space_id AS uuid) "
        "AND deleted_at IS NULL AND network && CAST(:network AS cidr) LIMIT 1"
    )
    row = (await db.execute(text(q), {"space_id": str(space_id), "network": network})).fetchone()
    if row is not None:
        raise ValueError(f"Subnet {network} overlaps existing subnet {row[0]} in the space")


async def _block_overlap_reparent(
    db: AsyncSession,
    *,
    space_id: uuid.UUID,
    network: str,
    parent_block_id: uuid.UUID | None,
) -> list[uuid.UUID]:
    """Validate a new block against same-level siblings; return reparent IDs.

    Replicates ``_assert_no_block_overlap`` (ipam/router.py) — exact
    duplicate / strict-subset / partial-overlap raise ValueError; a strict
    supernet of a sibling returns that sibling for reparenting after
    insert. Sibling scope is same-level (``parent_block_id`` match).
    """
    q = (
        "SELECT id, network FROM ip_block "
        "WHERE space_id = CAST(:space_id AS uuid) "
        "AND deleted_at IS NULL AND network && CAST(:network AS cidr)"
    )
    params: dict[str, Any] = {"space_id": str(space_id), "network": network}
    if parent_block_id is None:
        q += " AND parent_block_id IS NULL"
    else:
        q += " AND parent_block_id = CAST(:parent_id AS uuid)"
        params["parent_id"] = str(parent_block_id)
    rows = (await db.execute(text(q), params)).fetchall()
    if not rows:
        return []

    new_net = ipaddress.ip_network(network, strict=False)
    reparent: list[uuid.UUID] = []
    for row in rows:
        sibling_id = row[0]
        sibling_net = ipaddress.ip_network(str(row[1]), strict=False)
        if sibling_net == new_net:
            raise ValueError(f"Block {network} already exists at this level")
        if _contained(sibling_net, new_net):
            # new block is a strict supernet of the sibling — reparent it.
            reparent.append(sibling_id)
            continue
        if _contained(new_net, sibling_net):
            raise ValueError(
                f"Block {network} is contained in existing block {sibling_net}; "
                "it should nest under that block, not sit at the same level"
            )
        raise ValueError(f"Block {network} overlaps existing block {sibling_net}")
    return reparent


# --------------------------------------------------------------------------- #
# Audit helper — one row per committed entity, written before db.commit().
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Actor:
    """Plain-value snapshot of the signed-in user for ``_audit`` (#2816)."""

    id: uuid.UUID
    display_name: str
    auth_source: str


def _audit(
    db: AsyncSession,
    *,
    actor: _Actor,
    action: str,
    resource_type: str,
    resource_id: str,
    resource_display: str,
    netbox_id: int | None,
    extra: dict[str, Any] | None = None,
) -> None:
    new_value: dict[str, Any] = {"import_source": _SOURCE}
    if netbox_id is not None:
        new_value["netbox_id"] = netbox_id
    if extra:
        new_value.update(extra)
    db.add(
        AuditLog(
            user_id=actor.id,
            user_display_name=actor.display_name,
            auth_source=actor.auth_source,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_display=resource_display[:500],
            result="success",
            new_value=new_value,
        )
    )


# --------------------------------------------------------------------------- #
# Idempotency helper — has this NetBox row already been imported?
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Per-entity committers. Each does its own db.commit(); the caller wraps in
# try/except + db.rollback() + a 'failed' ledger row.
# --------------------------------------------------------------------------- #


async def _commit_customer(
    db: AsyncSession,
    imported: Any,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
) -> CommitEntityResult:
    key = _customer_key(imported.name)
    existing = await _find_customer(db, imported.name)
    if existing is not None:
        # Idempotent: an existing netbox-imported row is a no-op skip; a
        # hand-created row honours the operator's action.
        if action == "skip":
            return CommitEntityResult(
                kind="customer", key=key, action_taken="skipped", entity_id=str(existing.id)
            )
        # overwrite — update provenance + notes/tags onto the existing row.
        existing.notes = imported.notes or existing.notes
        if imported.tags:
            existing.tags = {**(existing.tags or {}), **imported.tags}
        if imported.custom_fields:
            existing.custom_fields = {**(existing.custom_fields or {}), **imported.custom_fields}
        existing.import_source = _SOURCE
        existing.imported_at = now
        _audit(
            db,
            actor=actor,
            action="update",
            resource_type="customer",
            resource_id=str(existing.id),
            resource_display=imported.name,
            netbox_id=imported.netbox_id,
        )
        await db.commit()
        return CommitEntityResult(
            kind="customer", key=key, action_taken="overwrote", entity_id=str(existing.id)
        )

    row = Customer(
        name=imported.name,
        status="active",
        notes=imported.notes or "",
        tags=dict(imported.tags or {}),
        custom_fields=dict(imported.custom_fields or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="customer",
        resource_id=str(row.id),
        resource_display=imported.name,
        netbox_id=imported.netbox_id,
    )
    await db.commit()
    return CommitEntityResult(
        kind="customer", key=key, action_taken="created", entity_id=str(row.id)
    )


async def _commit_site(
    db: AsyncSession,
    imported: Any,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
    code_to_id: dict[str, uuid.UUID],
) -> CommitEntityResult:
    key = _site_key(imported.name, imported.code)
    parent_id = code_to_id.get(imported.parent_code) if imported.parent_code else None

    existing = await _find_site(db, imported.name, imported.code)
    if existing is not None:
        if imported.code:
            code_to_id[imported.code] = existing.id
        if action == "skip":
            return CommitEntityResult(
                kind="site", key=key, action_taken="skipped", entity_id=str(existing.id)
            )
        existing.notes = imported.notes or existing.notes
        if imported.tags:
            existing.tags = {**(existing.tags or {}), **imported.tags}
        existing.import_source = _SOURCE
        existing.imported_at = now
        _audit(
            db,
            actor=actor,
            action="update",
            resource_type="site",
            resource_id=str(existing.id),
            resource_display=imported.name,
            netbox_id=imported.netbox_id,
        )
        await db.commit()
        return CommitEntityResult(
            kind="site", key=key, action_taken="overwrote", entity_id=str(existing.id)
        )

    row = Site(
        name=imported.name,
        code=imported.code or None,
        kind=imported.kind or "datacenter",
        region=imported.region,
        parent_site_id=parent_id,
        notes=imported.notes or "",
        tags=dict(imported.tags or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    if imported.code:
        code_to_id[imported.code] = row.id
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="site",
        resource_id=str(row.id),
        resource_display=imported.name,
        netbox_id=imported.netbox_id,
    )
    await db.commit()
    return CommitEntityResult(kind="site", key=key, action_taken="created", entity_id=str(row.id))


async def _commit_vrf(
    db: AsyncSession,
    imported: Any,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
    customer_id: uuid.UUID | None,
) -> tuple[CommitEntityResult, uuid.UUID | None]:
    key = _vrf_key(imported.name, imported.rd)
    existing = await _find_vrf(db, imported.name, imported.rd)
    if existing is not None:
        if action == "skip":
            return (
                CommitEntityResult(
                    kind="vrf", key=key, action_taken="skipped", entity_id=str(existing.id)
                ),
                existing.id,
            )
        existing.import_targets = list(imported.import_targets or existing.import_targets)
        existing.export_targets = list(imported.export_targets or existing.export_targets)
        if imported.custom_fields:
            existing.custom_fields = {**(existing.custom_fields or {}), **imported.custom_fields}
        if customer_id is not None:
            existing.customer_id = customer_id
        existing.import_source = _SOURCE
        existing.imported_at = now
        _audit(
            db,
            actor=actor,
            action="update",
            resource_type="vrf",
            resource_id=str(existing.id),
            resource_display=imported.rd or imported.name,
            netbox_id=imported.netbox_id,
        )
        await db.commit()
        return (
            CommitEntityResult(
                kind="vrf", key=key, action_taken="overwrote", entity_id=str(existing.id)
            ),
            existing.id,
        )

    row = VRF(
        name=imported.name,
        description=imported.description or "",
        route_distinguisher=imported.rd,
        import_targets=list(imported.import_targets or []),
        export_targets=list(imported.export_targets or []),
        customer_id=customer_id,
        custom_fields=dict(imported.custom_fields or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="vrf",
        resource_id=str(row.id),
        resource_display=imported.rd or imported.name,
        netbox_id=imported.netbox_id,
    )
    await db.commit()
    return (
        CommitEntityResult(kind="vrf", key=key, action_taken="created", entity_id=str(row.id)),
        row.id,
    )


async def _commit_space(
    db: AsyncSession,
    imported: Any,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
    vrf_id: uuid.UUID | None,
    customer_id: uuid.UUID | None,
) -> tuple[CommitEntityResult, uuid.UUID]:
    key = _space_key(imported.name)
    existing = await _find_space(db, imported.name)
    if existing is not None:
        # Reuse an existing space — never trample it. Link the VRF /
        # customer only if the existing row has none, and only stamp
        # provenance if the operator chose overwrite.
        changed = False
        if action == "overwrite":
            if vrf_id is not None and existing.vrf_id is None:
                existing.vrf_id = vrf_id
                changed = True
            if customer_id is not None and existing.customer_id is None:
                existing.customer_id = customer_id
                changed = True
            if existing.import_source is None:
                existing.import_source = _SOURCE
                existing.imported_at = existing.imported_at or now
                changed = True
            if changed:
                # A mutation lands — audit it (non-negotiable #4) before commit.
                _audit(
                    db,
                    actor=actor,
                    action="update",
                    resource_type="ip_space",
                    resource_id=str(existing.id),
                    resource_display=imported.name,
                    netbox_id=None,
                )
                await db.commit()
        return (
            CommitEntityResult(
                kind="ip_space",
                key=key,
                action_taken="overwrote" if changed else "skipped",
                entity_id=str(existing.id),
            ),
            existing.id,
        )

    row = IPSpace(
        name=imported.name,
        description=imported.description or "",
        is_default=False,  # never claim the default flag from an import
        vrf_id=vrf_id,
        customer_id=customer_id,
        tags=dict(imported.tags or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="ip_space",
        resource_id=str(row.id),
        resource_display=imported.name,
        netbox_id=None,
    )
    await db.commit()
    return (
        CommitEntityResult(kind="ip_space", key=key, action_taken="created", entity_id=str(row.id)),
        row.id,
    )


async def _commit_vlan(
    db: AsyncSession,
    imported: Any,
    *,
    actor: _Actor,
    now: datetime,
    router_id: uuid.UUID,
) -> tuple[CommitEntityResult, uuid.UUID | None]:
    key = _vlan_key(imported.vid)
    # Idempotency / conflict keys are (router_id, vid) and (router_id,
    # name) — VLAN has no tags/CF to stash netbox_id.
    by_vid = (
        (
            await db.execute(
                select(VLAN)
                .where(VLAN.router_id == router_id, VLAN.vlan_id == imported.vid)
                .limit(1)
            )
        )
        .scalars()
        .first()
    )
    by_name = (
        (
            await db.execute(
                select(VLAN).where(VLAN.router_id == router_id, VLAN.name == imported.name).limit(1)
            )
        )
        .scalars()
        .first()
    )
    if by_vid is not None:
        # Same vid already on the router — idempotent reuse; link subnets to it.
        return (
            CommitEntityResult(
                kind="vlan", key=key, action_taken="skipped", entity_id=str(by_vid.id)
            ),
            by_vid.id,
        )
    if by_name is not None:
        # Name clash with a DIFFERENT vid (UNIQUE name on the router blocks a
        # create). Skip with a warning and leave the vid UNMAPPED — linking a
        # subnet to a wrong-vid VLAN would silently mis-tag it.
        return (
            CommitEntityResult(
                kind="vlan",
                key=key,
                action_taken="skipped",
                entity_id=str(by_name.id),
                error=(
                    f"name {imported.name!r} already used by vid {by_name.vlan_id} "
                    "on the import router — vid left unlinked"
                ),
            ),
            None,
        )

    row = VLAN(
        router_id=router_id,
        vlan_id=imported.vid,
        name=imported.name,
        description=imported.description or "",
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="vlan",
        resource_id=str(row.id),
        resource_display=f"{imported.vid} {imported.name}",
        netbox_id=imported.netbox_id,
    )
    await db.commit()
    return (
        CommitEntityResult(kind="vlan", key=key, action_taken="created", entity_id=str(row.id)),
        row.id,
    )


# Default name(s) the synthetic VLAN router shipped under before
# ``default_router_name`` was renamed. A re-import must reuse an existing
# router created under any of these rather than spawn a duplicate.
_LEGACY_ROUTER_NAMES: tuple[str, ...] = ("NetBox import",)


async def _ensure_router(db: AsyncSession, name: str) -> Router:
    """Find-or-create the synthetic router VLANs hang off (UNIQUE name).

    Matches the requested ``name`` first, then its ``(NetBox)``-suffixed
    form, then any legacy alias, so renaming the default no longer orphans
    a router an earlier import already created (and leaves the imported
    VLANs hanging off a duplicate). Adopting an operator Router of that
    name is deliberate — the operator typed it into the import form.

    A Router an integration owns (``unifi_controller_id`` set) is never
    adopted: the UniFi reconciler deletes VLANs on its Router that UniFi
    does not report, so it would delete every VLAN this import hung off
    it. Its name is taken, so the new router gets a suffixed one (#2140).
    """
    seen: set[str] = set()
    for candidate in (name, f"{name} (NetBox)", *_LEGACY_ROUTER_NAMES):
        if candidate in seen:
            continue
        seen.add(candidate)
        existing = (
            (
                await db.execute(
                    select(Router)
                    .where(Router.name == candidate)
                    .where(Router.unifi_controller_id.is_(None))
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            return existing
    row = Router(
        name=await pick_unique_router_name(db, name, tag="NetBox"),
        description="Synthetic router for NetBox-imported VLANs",
    )
    db.add(row)
    await db.flush()
    await db.commit()
    return row


async def _commit_block(
    db: AsyncSession,
    imported: ImportedBlock,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
    space_id: uuid.UUID,
    customer_id: uuid.UUID | None,
    site_id: uuid.UUID | None,
) -> tuple[CommitEntityResult, uuid.UUID | None]:
    cidr = _canonical_cidr(imported.network)
    key = _block_key(imported.space_name, cidr)
    net = _parse_net(cidr)
    if net is None:
        return (
            CommitEntityResult(
                kind="ip_block", key=key, action_taken="failed", error="unparseable CIDR"
            ),
            None,
        )

    existing = await _find_block(db, space_id, cidr)
    if existing is not None:
        if action == "skip":
            return (
                CommitEntityResult(
                    kind="ip_block", key=key, action_taken="skipped", entity_id=str(existing.id)
                ),
                existing.id,
            )
        existing.import_source = _SOURCE
        existing.imported_at = now
        if imported.custom_fields:
            existing.custom_fields = {**(existing.custom_fields or {}), **imported.custom_fields}
        _audit(
            db,
            actor=actor,
            action="update",
            resource_type="ip_block",
            resource_id=str(existing.id),
            resource_display=cidr,
            netbox_id=imported.netbox_id,
        )
        await db.commit()
        return (
            CommitEntityResult(
                kind="ip_block", key=key, action_taken="overwrote", entity_id=str(existing.id)
            ),
            existing.id,
        )

    # Find the most-specific enclosing imported/existing block as parent.
    parent_id = await _find_parent_block_id(db, space_id, net)
    reparent = await _block_overlap_reparent(
        db, space_id=space_id, network=cidr, parent_block_id=parent_id
    )

    row = IPBlock(
        space_id=space_id,
        parent_block_id=parent_id,
        network=cidr,
        name=imported.name or f"auto:{net}",
        description=imported.description or "",
        customer_id=customer_id,
        site_id=site_id,
        custom_fields=dict(imported.custom_fields or {}),
        tags=dict(imported.tags or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    # Reparent strict-subset siblings under the new supernet block.
    for sib_id in reparent:
        sib = await db.get(IPBlock, sib_id)
        if sib is not None:
            sib.parent_block_id = row.id
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="ip_block",
        resource_id=str(row.id),
        resource_display=cidr,
        netbox_id=imported.netbox_id,
        extra={"reparented": len(reparent)} if reparent else None,
    )
    await db.commit()
    return (
        CommitEntityResult(kind="ip_block", key=key, action_taken="created", entity_id=str(row.id)),
        row.id,
    )


async def _find_parent_block_id(
    db: AsyncSession, space_id: uuid.UUID, net: IPNetwork
) -> uuid.UUID | None:
    """Smallest live block in the space that strictly contains ``net``."""
    blocks = (
        (
            await db.execute(
                select(IPBlock).where(IPBlock.space_id == space_id, IPBlock.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    best: tuple[int, uuid.UUID] | None = None
    for b in blocks:
        b_net = _parse_net(str(b.network))
        if b_net is None or b_net == net:
            continue
        if _contained(net, b_net):
            if best is None or b_net.prefixlen > best[0]:
                best = (b_net.prefixlen, b.id)
    return best[1] if best is not None else None


async def _auto_wrapper_block(
    db: AsyncSession,
    *,
    space_id: uuid.UUID,
    net: IPNetwork,
    actor: _Actor,
    now: datetime,
) -> uuid.UUID:
    """Create an ``auto:<cidr>`` wrapper block at the subnet's own CIDR.

    Used when no existing/imported block encloses a leaf subnet
    (mirrors ipam_io ``_find_parent_block`` + DHCP ``_create_subnet``
    fallback). Nests under any enclosing block; reparents strict-subset
    siblings. Commits in its own savepoint via the caller's surrounding
    block/subnet commit (this helper does NOT commit — the subnet commit
    that follows commits both rows together)."""
    cidr = str(net)
    parent_id = await _find_parent_block_id(db, space_id, net)
    reparent = await _block_overlap_reparent(
        db, space_id=space_id, network=cidr, parent_block_id=parent_id
    )
    row = IPBlock(
        space_id=space_id,
        parent_block_id=parent_id,
        network=cidr,
        name=f"auto:{cidr}",
        description="Auto-created wrapper block for a NetBox-imported subnet",
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    for sib_id in reparent:
        sib = await db.get(IPBlock, sib_id)
        if sib is not None:
            sib.parent_block_id = row.id
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="ip_block",
        resource_id=str(row.id),
        resource_display=cidr,
        netbox_id=None,
        extra={"auto_wrapper": True},
    )
    return row.id


async def _commit_subnet(
    db: AsyncSession,
    imported: ImportedSubnet,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
    space_id: uuid.UUID,
    customer_id: uuid.UUID | None,
    site_id: uuid.UUID | None,
    vlan_id: uuid.UUID | None,
) -> tuple[CommitEntityResult, uuid.UUID | None, list[CommitEntityResult]]:
    # The 3rd return is extra ledger entities (a synthesized wrapper block,
    # when one was created with this subnet) so blocks_created counts it — but
    # only on the success path, since the wrapper shares the subnet's commit
    # and would roll back with it on failure.
    cidr = _canonical_cidr(imported.network)
    key = _subnet_key(imported.space_name, cidr)
    net = _parse_net(cidr)
    if net is None:
        return (
            CommitEntityResult(
                kind="subnet", key=key, action_taken="failed", error="unparseable CIDR"
            ),
            None,
            [],
        )

    existing = await _find_subnet(db, space_id, cidr)
    if existing is not None:
        if action == "skip":
            return (
                CommitEntityResult(
                    kind="subnet", key=key, action_taken="skipped", entity_id=str(existing.id)
                ),
                existing.id,
                [],
            )
        existing.import_source = _SOURCE
        existing.imported_at = now
        if imported.custom_fields:
            existing.custom_fields = {**(existing.custom_fields or {}), **imported.custom_fields}
        if vlan_id is not None and existing.vlan_ref_id is None:
            existing.vlan_ref_id = vlan_id
        _audit(
            db,
            actor=actor,
            action="update",
            resource_type="subnet",
            resource_id=str(existing.id),
            resource_display=cidr,
            netbox_id=imported.netbox_id,
        )
        await db.commit()
        return (
            CommitEntityResult(
                kind="subnet", key=key, action_taken="overwrote", entity_id=str(existing.id)
            ),
            existing.id,
            [],
        )

    # Space-wide overlap guard before we create anything.
    await _assert_subnet_no_overlap(db, space_id=space_id, network=cidr)

    # Resolve the parent block; auto-create an ``auto:<cidr>`` wrapper if
    # none encloses (Subnet.block_id is mandatory).
    wrapper_entities: list[CommitEntityResult] = []
    block_id = await _find_parent_block_id(db, space_id, net)
    if block_id is None:
        block_id = await _auto_wrapper_block(db, space_id=space_id, net=net, actor=actor, now=now)
        wrapper_entities.append(
            CommitEntityResult(
                kind="ip_block",
                key=_block_key(imported.space_name, cidr),
                action_taken="created",
                entity_id=str(block_id),
            )
        )

    total = net.num_addresses
    row = Subnet(
        space_id=space_id,
        block_id=block_id,
        vlan_ref_id=vlan_id,
        network=cidr,
        name=imported.name or "",
        description=imported.description or "",
        kind=imported.kind or "unicast",
        status=imported.status or "active",
        subnet_role=imported.subnet_role,
        customer_id=customer_id,
        site_id=site_id,
        total_ips=min(total, 2**63 - 1),
        allocated_ips=0,
        utilization_percent=0.0,
        custom_fields=dict(imported.custom_fields or {}),
        tags=dict(imported.tags or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="subnet",
        resource_id=str(row.id),
        resource_display=cidr,
        netbox_id=imported.netbox_id,
    )
    await db.commit()
    return (
        CommitEntityResult(kind="subnet", key=key, action_taken="created", entity_id=str(row.id)),
        row.id,
        wrapper_entities,
    )


async def _commit_address(
    db: AsyncSession,
    imported: ImportedAddress,
    *,
    action: ConflictAction,
    actor: _Actor,
    now: datetime,
    space_id: uuid.UUID,
) -> CommitEntityResult:
    key = _address_key(imported.subnet_cidr, imported.address)
    addr = _parse_addr(imported.address)
    if addr is None:
        return CommitEntityResult(
            kind="ip_address", key=key, action_taken="failed", error="unparseable address"
        )

    # Resolve the most-specific imported/existing subnet in the space that
    # contains the address.
    subnet = await _most_specific_subnet(db, space_id, addr)
    if subnet is None:
        return CommitEntityResult(
            kind="ip_address",
            key=key,
            action_taken="failed",
            error=f"no imported subnet contains {imported.address}",
        )
    if subnet.kind == "multicast":
        return CommitEntityResult(
            kind="ip_address",
            key=key,
            action_taken="skipped",
            error="address falls in a multicast subnet; not stamped",
        )

    existing = await _find_address(db, subnet.id, imported.address)
    if existing is not None:
        if action == "skip":
            return CommitEntityResult(
                kind="ip_address", key=key, action_taken="skipped", entity_id=str(existing.id)
            )
        existing.status = imported.status or existing.status
        existing.role = imported.role or existing.role
        # Fold a NetBox device/dns name to a valid LDH host name (#597) — a
        # migration should keep the IP with a cleaned name rather than store a
        # non-conforming one; a valid FQDN passes through unchanged.
        existing.hostname = sanitize_hostname(imported.hostname) or existing.hostname
        existing.fqdn = imported.fqdn or existing.fqdn
        if imported.description:
            existing.description = imported.description
        if imported.custom_fields:
            existing.custom_fields = {**(existing.custom_fields or {}), **imported.custom_fields}
        existing.import_source = _SOURCE
        existing.imported_at = now
        _audit(
            db,
            actor=actor,
            action="update",
            resource_type="ip_address",
            resource_id=str(existing.id),
            resource_display=imported.address,
            netbox_id=imported.netbox_id,
        )
        await db.commit()
        return CommitEntityResult(
            kind="ip_address", key=key, action_taken="overwrote", entity_id=str(existing.id)
        )

    managed_by = None
    cf = dict(imported.custom_fields or {})
    if "netbox_managed_by" in cf:
        managed_by = str(cf["netbox_managed_by"])
    row = IPAddress(
        subnet_id=subnet.id,
        address=imported.address,
        status=imported.status or "allocated",
        role=imported.role,
        hostname=sanitize_hostname(imported.hostname) or None,
        fqdn=imported.fqdn,
        description=imported.description or "",
        managed_by=managed_by,
        custom_fields=cf,
        tags=dict(imported.tags or {}),
        import_source=_SOURCE,
        imported_at=now,
    )
    db.add(row)
    await db.flush()
    _audit(
        db,
        actor=actor,
        action="create",
        resource_type="ip_address",
        resource_id=str(row.id),
        resource_display=imported.address,
        netbox_id=imported.netbox_id,
    )
    await db.commit()
    return CommitEntityResult(
        kind="ip_address", key=key, action_taken="created", entity_id=str(row.id)
    )


def _parse_addr(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


async def _most_specific_subnet(
    db: AsyncSession,
    space_id: uuid.UUID,
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> Subnet | None:
    """Smallest live subnet in the space that contains ``addr``."""
    subnets = (
        (
            await db.execute(
                select(Subnet).where(Subnet.space_id == space_id, Subnet.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    best: tuple[int, Subnet] | None = None
    for s in subnets:
        net = _parse_net(str(s.network))
        if net is None or net.version != addr.version:
            continue
        if addr in net:
            if best is None or net.prefixlen > best[0]:
                best = (net.prefixlen, s)
    return best[1] if best is not None else None


# --------------------------------------------------------------------------- #
# commit_import — the orchestrator.
# --------------------------------------------------------------------------- #


async def commit_import(
    db: AsyncSession,
    *,
    preview: ImportPreview,
    conflict_actions: dict[str, ConflictAction],
    space_strategy: str = "per_vrf",
    target_space_id: uuid.UUID | None = None,
    default_router_name: str = "Imported VLANs (NetBox)",
    actor: User,
) -> CommitResult:
    """Apply ``preview`` to the DB, one entity per savepoint.

    ``conflict_actions`` is keyed by each entity's stable conflict key
    (see the ``_*_key`` helpers; the preview's ``EntityConflict.key``
    carries the same string). An entity the operator left untouched
    defaults to ``skip`` on a real conflict (don't trample) and plain
    create otherwise.

    Ordering follows the FK + overlap invariant (``netbox_ctx/03_models.md``
    §13). A ``ValueError`` raised before any row (bad ``target_space_id``)
    aborts the whole commit with a 422 upstream; per-row failures land as
    ``failed`` ledger rows and never abort the batch.
    """
    if space_strategy not in ("per_vrf", "single"):
        raise ValueError(f"unknown space_strategy {space_strategy!r}")
    if space_strategy == "single" and target_space_id is None:
        raise ValueError("space_strategy='single' requires target_space_id")

    # Preflight: the single target space must exist (422 before any row).
    single_space: IPSpace | None = None
    if space_strategy == "single":
        single_space = await db.get(IPSpace, target_space_id)
        if single_space is None or single_space.deleted_at is not None:
            raise ValueError(f"target IP space {target_space_id} does not exist")

    # Plain values, never the ORM row: a failed entity's savepoint rollback
    # (or any rollback) expires loaded objects, and the next ``_audit`` would
    # lazy-load the user outside the greenlet (#2816).
    snap = _Actor(id=actor.id, display_name=actor.display_name, auth_source=actor.auth_source)
    now = datetime.now(UTC)
    result = CommitResult(source=_SOURCE, warnings=list(preview.warnings))

    def _action(key: str) -> ConflictAction:
        return conflict_actions.get(key, "skip")

    # ── 1. Customers ──────────────────────────────────────────────────
    customer_name_to_id: dict[str, uuid.UUID] = {}
    for c in preview.customers:
        key = _customer_key(c.name)
        try:
            async with _entity_savepoint(db):
                res = await _commit_customer(db, c, action=_action(key), actor=snap, now=now)
                if res.entity_id:
                    customer_name_to_id[c.name] = uuid.UUID(res.entity_id)
        except Exception as exc:  # noqa: BLE001 — per-row failure capture
            res = CommitEntityResult(
                kind="customer", key=key, action_taken="failed", error=str(exc)
            )
        result.entities.append(res)

    # ── 2. Sites (region-parent-first; ImportedSite list is already
    # region-then-site ordered by the preview). ──
    site_code_to_id: dict[str, uuid.UUID] = {}
    for s in preview.sites:
        key = _site_key(s.name, s.code)
        try:
            async with _entity_savepoint(db):
                res = await _commit_site(
                    db, s, action=_action(key), actor=snap, now=now, code_to_id=site_code_to_id
                )
        except Exception as exc:  # noqa: BLE001
            res = CommitEntityResult(kind="site", key=key, action_taken="failed", error=str(exc))
        result.entities.append(res)

    # ── 3. VRFs ───────────────────────────────────────────────────────
    vrf_name_to_id: dict[str, uuid.UUID] = {}
    for v in preview.vrfs:
        key = _vrf_key(v.name, v.rd)
        cust_id = customer_name_to_id.get(v.customer_name) if v.customer_name else None
        try:
            async with _entity_savepoint(db):
                res, vid = await _commit_vrf(
                    db, v, action=_action(key), actor=snap, now=now, customer_id=cust_id
                )
                if vid is not None:
                    vrf_name_to_id[v.name] = vid
        except Exception as exc:  # noqa: BLE001
            res = CommitEntityResult(kind="vrf", key=key, action_taken="failed", error=str(exc))
        result.entities.append(res)

    # ── 4. IPSpaces (per_vrf only) ────────────────────────────────────
    space_name_to_id: dict[str, uuid.UUID] = {}
    if space_strategy == "per_vrf":
        for sp in preview.spaces:
            key = _space_key(sp.name)
            vrf_id = vrf_name_to_id.get(sp.vrf_name) if sp.vrf_name else None
            cust_id = customer_name_to_id.get(sp.customer_name) if sp.customer_name else None
            try:
                async with _entity_savepoint(db):
                    res, sid = await _commit_space(
                        db,
                        sp,
                        action=_action(key),
                        actor=snap,
                        now=now,
                        vrf_id=vrf_id,
                        customer_id=cust_id,
                    )
                    space_name_to_id[sp.name] = sid
            except Exception as exc:  # noqa: BLE001
                res = CommitEntityResult(
                    kind="ip_space", key=key, action_taken="failed", error=str(exc)
                )
            result.entities.append(res)

    def _space_id_for(space_name: str | None) -> uuid.UUID | None:
        if space_strategy == "single":
            return target_space_id
        if space_name and space_name in space_name_to_id:
            return space_name_to_id[space_name]
        return None

    # ── 5. Router + VLANs ─────────────────────────────────────────────
    vlan_vid_to_id: dict[int, uuid.UUID] = {}
    if preview.vlans:
        router_id: uuid.UUID | None = None
        try:
            async with _entity_savepoint(db):
                router_id = (await _ensure_router(db, default_router_name)).id
        except Exception as exc:  # noqa: BLE001 — never let the whole import 500
            result.entities.append(
                CommitEntityResult(
                    kind="vlan",
                    key=_vlan_key(0),
                    action_taken="failed",
                    error=f"could not create import router {default_router_name!r}: {exc}",
                )
            )
        if router_id is not None:
            for vl in preview.vlans:
                key = _vlan_key(vl.vid)
                try:
                    async with _entity_savepoint(db):
                        res, vlid = await _commit_vlan(
                            db, vl, actor=snap, now=now, router_id=router_id
                        )
                        if vlid is not None:
                            vlan_vid_to_id[vl.vid] = vlid
                except Exception as exc:  # noqa: BLE001
                    res = CommitEntityResult(
                        kind="vlan", key=key, action_taken="failed", error=str(exc)
                    )
                result.entities.append(res)

    # ── 6. IPBlocks largest-prefix-first ──────────────────────────────
    sorted_blocks = sorted(preview.blocks, key=_block_sort_key)
    for b in sorted_blocks:
        key = _block_key(b.space_name, _key_cidr(b.network))
        space_id = _space_id_for(b.space_name)
        if space_id is None:
            res = CommitEntityResult(
                kind="ip_block",
                key=key,
                action_taken="failed",
                error=f"no target space resolved for {b.network}",
            )
            result.entities.append(res)
            continue
        cust_id = customer_name_to_id.get(b.customer_name) if b.customer_name else None
        site_id = site_code_to_id.get(b.site_code) if b.site_code else None
        try:
            async with _entity_savepoint(db):
                res, _bid = await _commit_block(
                    db,
                    b,
                    action=_action(key),
                    actor=snap,
                    now=now,
                    space_id=space_id,
                    customer_id=cust_id,
                    site_id=site_id,
                )
        except Exception as exc:  # noqa: BLE001
            res = CommitEntityResult(
                kind="ip_block", key=key, action_taken="failed", error=str(exc)
            )
        result.entities.append(res)

    # ── 7. Subnets largest-prefix-first ───────────────────────────────
    sorted_subnets = sorted(preview.subnets, key=_subnet_sort_key)
    for sub in sorted_subnets:
        key = _subnet_key(sub.space_name, _key_cidr(sub.network))
        space_id = _space_id_for(sub.space_name)
        if space_id is None:
            res = CommitEntityResult(
                kind="subnet",
                key=key,
                action_taken="failed",
                error=f"no target space resolved for {sub.network}",
            )
            result.entities.append(res)
            continue
        cust_id = customer_name_to_id.get(sub.customer_name) if sub.customer_name else None
        site_id = site_code_to_id.get(sub.site_code) if sub.site_code else None
        vlan_id = vlan_vid_to_id.get(sub.vlan_vid) if sub.vlan_vid is not None else None
        try:
            async with _entity_savepoint(db):
                res, _sid, wrapper_entities = await _commit_subnet(
                    db,
                    sub,
                    action=_action(key),
                    actor=snap,
                    now=now,
                    space_id=space_id,
                    customer_id=cust_id,
                    site_id=site_id,
                    vlan_id=vlan_id,
                )
                # Wrapper block(s) committed together with the subnet — record them
                # before the subnet row so blocks_created reflects reality.
                result.entities.extend(wrapper_entities)
        except Exception as exc:  # noqa: BLE001
            res = CommitEntityResult(kind="subnet", key=key, action_taken="failed", error=str(exc))
        result.entities.append(res)

    # ── 8. IPAddresses (most-specific subnet) ─────────────────────────
    for a in preview.addresses:
        key = _address_key(a.subnet_cidr, a.address)
        space_id = _space_id_for(a.space_name)
        if space_id is None:
            res = CommitEntityResult(
                kind="ip_address",
                key=key,
                action_taken="failed",
                error=f"no target space resolved for {a.address}",
            )
            result.entities.append(res)
            continue
        try:
            async with _entity_savepoint(db):
                res = await _commit_address(
                    db, a, action=_action(key), actor=snap, now=now, space_id=space_id
                )
        except Exception as exc:  # noqa: BLE001
            res = CommitEntityResult(
                kind="ip_address", key=key, action_taken="failed", error=str(exc)
            )
        result.entities.append(res)

    return result


def _block_sort_key(b: ImportedBlock) -> tuple[int, int]:
    """Largest-prefix-first: shorter prefixlen (bigger net) sorts first."""
    net = _parse_net(b.network)
    if net is None:
        return (999, 0)
    return (net.prefixlen, int(net.network_address))


def _subnet_sort_key(s: ImportedSubnet) -> tuple[int, int]:
    net = _parse_net(s.network)
    if net is None:
        return (999, 0)
    return (net.prefixlen, int(net.network_address))

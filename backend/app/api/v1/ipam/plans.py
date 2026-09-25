"""Subnet plans — multi-level CIDR designs applied transactionally.

A plan is a JSON tree of nodes, each carrying a CIDR + name + description.
Nodes with children become IPBlocks on apply; leaves become Subnets.
Validation enforces that every node fits inside its parent and siblings
don't overlap.

Apply runs validate-then-create in a single transaction. If state has
drifted between save and apply (someone added an overlapping block in
the meantime), apply returns 409 with the conflict list and the
operator re-validates.

Once applied, the plan flips read-only — the materialised IPAM rows
are the source of truth.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DB, CurrentUser
from app.api.v1.dhcp._audit import write_audit
from app.core.permissions import require_resource_permission, user_has_permission
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet, SubnetPlan

_V4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
_V6_MULTICAST = ipaddress.ip_network("ff00::/8")


def _subnet_kind(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """Mirror create_subnet's #126 discriminator so a planned multicast leaf
    isn't left ``unicast`` (which would wrongly accept per-IP allocation) (#505)."""
    mcast = _V4_MULTICAST if isinstance(net, ipaddress.IPv4Network) else _V6_MULTICAST
    return "multicast" if net.subnet_of(mcast) else "unicast"  # type: ignore[arg-type]


router = APIRouter(
    prefix="/plans",
    tags=["ipam"],
    dependencies=[Depends(require_resource_permission("ip_block"))],
)


# ── Schemas ───────────────────────────────────────────────────────────────


class PlanNode(BaseModel):
    """A node in the plan tree.

    ``id`` is a client-stable identifier the frontend assigns when the
    operator builds the tree (used for drag-and-drop and re-ordering).
    The backend treats it as opaque and only validates uniqueness within
    a single tree.

    ``existing_block_id`` is only meaningful on the root node — it
    anchors the plan inside an existing IPBlock. Ignored on descendants.
    """

    id: str = Field(min_length=1, max_length=64)
    network: str
    name: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=2000)
    existing_block_id: str | None = None

    # ``kind`` is what the node materialises as. Blocks may have children
    # (any kind); subnets cannot (validated). Root must be a block — a
    # subnet without a parent block can't exist in the IPAM data model.
    # Default is ``block`` to keep historical plans (which had no kind
    # field) interpreting their root as a block.
    kind: str = Field(default="block")

    # Optional resource bindings — None = inherit from parent on apply. The
    # materialise step sets the corresponding ``*_inherit_settings`` flag to
    # True when a field is None and to False when it's explicit.
    # ``dns_group_id`` / ``dns_zone_id`` / ``dhcp_server_group_id`` apply to
    # both blocks and subnets; ``vlan_ref_id`` and ``gateway`` only apply
    # to subnets.
    dns_group_id: str | None = None
    dns_zone_id: str | None = None
    dhcp_server_group_id: str | None = None
    vlan_ref_id: str | None = None
    gateway: str | None = None

    children: list[PlanNode] = Field(default_factory=list)

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, v: str) -> str:
        if v not in {"block", "subnet"}:
            raise ValueError("kind must be 'block' or 'subnet'")
        return v

    @field_validator("network")
    @classmethod
    def _validate_network(cls, v: str) -> str:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {v}")
        return str(net)


PlanNode.model_rebuild()


class SubnetPlanRead(BaseModel):
    id: str
    name: str
    description: str
    space_id: str
    tree: PlanNode | None
    applied_at: datetime | None
    applied_resource_ids: dict[str, list[str]] | None
    created_by_user_id: str | None
    created_at: datetime
    modified_at: datetime


class SubnetPlanCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    space_id: str
    tree: PlanNode


class SubnetPlanUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    tree: PlanNode | None = None


class ValidationConflict(BaseModel):
    node_id: str
    network: str
    kind: str  # "overlap_existing" | "out_of_parent" | "sibling_overlap" | "duplicate_id" | "missing_block"
    message: str


class ValidationResult(BaseModel):
    ok: bool
    conflicts: list[ValidationConflict]
    summary: dict[str, int]  # block_count, subnet_count


class ApplyResult(BaseModel):
    block_ids: list[str]
    subnet_ids: list[str]
    applied_at: datetime


# ── Tree helpers ──────────────────────────────────────────────────────────


def _walk(node: PlanNode) -> list[PlanNode]:
    """Depth-first list of every node in the tree."""
    out = [node]
    for child in node.children:
        out.extend(_walk(child))
    return out


def _node_count(tree: PlanNode) -> tuple[int, int]:
    """Return (block_count, subnet_count) the plan would create on apply."""
    blocks = 0
    subnets = 0
    for n in _walk(tree):
        if n.kind == "block":
            blocks += 1
        else:
            subnets += 1
    # Anchored root → existing block is reused, not created.
    if tree.existing_block_id:
        blocks -= 1
    return blocks, subnets


def _to_read(plan: SubnetPlan) -> SubnetPlanRead:
    tree_payload = plan.tree if isinstance(plan.tree, dict) and plan.tree else None
    parsed: PlanNode | None = None
    if tree_payload:
        try:
            parsed = PlanNode.model_validate(tree_payload)
        except Exception:
            parsed = None
    return SubnetPlanRead(
        id=str(plan.id),
        name=plan.name,
        description=plan.description,
        space_id=str(plan.space_id),
        tree=parsed,
        applied_at=plan.applied_at,
        applied_resource_ids=plan.applied_resource_ids,
        created_by_user_id=str(plan.created_by_user_id) if plan.created_by_user_id else None,
        created_at=plan.created_at,
        modified_at=plan.modified_at,
    )


# ── Validation ────────────────────────────────────────────────────────────


async def _validate_tree(
    db: AsyncSession, space_id: uuid.UUID, tree: PlanNode
) -> list[ValidationConflict]:
    """Run every check and return the full conflict list (empty = OK)."""
    conflicts: list[ValidationConflict] = []

    # 1. Node IDs unique within the tree.
    seen_ids: dict[str, str] = {}
    for n in _walk(tree):
        if n.id in seen_ids:
            conflicts.append(
                ValidationConflict(
                    node_id=n.id,
                    network=n.network,
                    kind="duplicate_id",
                    message=f"Duplicate node id '{n.id}' in tree",
                )
            )
        seen_ids[n.id] = n.network

    # 1b. Kind rules: root must be a block (subnets need a block parent),
    #     and a subnet may not have children (the IPAM data model has no
    #     subnet → subnet relationship — sub-divisions live under blocks).
    if tree.kind != "block":
        conflicts.append(
            ValidationConflict(
                node_id=tree.id,
                network=tree.network,
                kind="invalid_kind",
                message="Root node must be a block — subnets need a block parent",
            )
        )
    for n in _walk(tree):
        if n.kind == "subnet" and n.children:
            conflicts.append(
                ValidationConflict(
                    node_id=n.id,
                    network=n.network,
                    kind="invalid_kind",
                    message=(
                        f"Subnet {n.network} cannot have children — " "convert it to a block first"
                    ),
                )
            )

    # 2. If the root references an existing block, the block must exist
    #    AND its CIDR must equal the root's CIDR (the operator can't
    #    redefine the root's network when anchoring to an existing block).
    if tree.existing_block_id:
        try:
            block_id = uuid.UUID(tree.existing_block_id)
        except ValueError:
            conflicts.append(
                ValidationConflict(
                    node_id=tree.id,
                    network=tree.network,
                    kind="missing_block",
                    message=f"existing_block_id is not a valid UUID: {tree.existing_block_id}",
                )
            )
            return conflicts
        block = await db.get(IPBlock, block_id)
        if block is None or block.space_id != space_id:
            conflicts.append(
                ValidationConflict(
                    node_id=tree.id,
                    network=tree.network,
                    kind="missing_block",
                    message="Existing block referenced by root not found in this space",
                )
            )
            return conflicts
        if str(block.network) != tree.network:
            conflicts.append(
                ValidationConflict(
                    node_id=tree.id,
                    network=tree.network,
                    kind="missing_block",
                    message=(
                        f"Root CIDR {tree.network} does not match existing block "
                        f"CIDR {block.network}"
                    ),
                )
            )
            return conflicts

    # 3. Tree-internal: every node must fit inside its parent; siblings
    #    must not overlap.
    def check_subtree(node: PlanNode) -> None:
        parent_net = ipaddress.ip_network(node.network, strict=False)
        seen: list[tuple[PlanNode, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for child in node.children:
            child_net = ipaddress.ip_network(child.network, strict=False)
            if child_net.version != parent_net.version:
                conflicts.append(
                    ValidationConflict(
                        node_id=child.id,
                        network=child.network,
                        kind="out_of_parent",
                        message=(
                            f"{child.network} (IPv{child_net.version}) is not in "
                            f"parent {node.network} (IPv{parent_net.version})"
                        ),
                    )
                )
                continue
            if not child_net.subnet_of(parent_net):  # type: ignore[arg-type]
                conflicts.append(
                    ValidationConflict(
                        node_id=child.id,
                        network=child.network,
                        kind="out_of_parent",
                        message=f"{child.network} is not contained by parent {node.network}",
                    )
                )
            for prev, prev_net in seen:
                if child_net.overlaps(prev_net):
                    conflicts.append(
                        ValidationConflict(
                            node_id=child.id,
                            network=child.network,
                            kind="sibling_overlap",
                            message=f"{child.network} overlaps sibling {prev.network}",
                        )
                    )
            seen.append((child, child_net))
            check_subtree(child)

    check_subtree(tree)

    # 4. Cross-reference against existing IPAM state. Anything in the
    #    plan tree (excluding the existing-block root, if any) that
    #    overlaps a current block / subnet is a conflict.
    existing_blocks = (
        await db.execute(select(IPBlock.id, IPBlock.network).where(IPBlock.space_id == space_id))
    ).all()
    existing_subnets = (
        await db.execute(select(Subnet.id, Subnet.network).where(Subnet.space_id == space_id))
    ).all()
    existing_nets = [
        (str(rid), ipaddress.ip_network(str(net), strict=False), "block")
        for rid, net in existing_blocks
    ] + [
        (str(rid), ipaddress.ip_network(str(net), strict=False), "subnet")
        for rid, net in existing_subnets
    ]

    skip_id = tree.existing_block_id if tree.existing_block_id else None
    nodes_to_check = _walk(tree)
    if skip_id:
        # The root's network IS the existing block; descendants still need checks
        # but only against networks other than that block itself.
        nodes_to_check = [n for n in nodes_to_check if n.id != tree.id]

    for n in nodes_to_check:
        node_net = ipaddress.ip_network(n.network, strict=False)
        for rid, ex_net, ex_kind in existing_nets:
            if rid == skip_id:
                continue
            if ex_net.version != node_net.version:
                continue
            if node_net.overlaps(ex_net):
                # Don't flag containment by the existing-block-root itself —
                # that's expected (descendants live inside the root block).
                if (
                    skip_id
                    and rid == skip_id
                    and node_net.subnet_of(ex_net)  # type: ignore[arg-type]
                ):
                    continue
                conflicts.append(
                    ValidationConflict(
                        node_id=n.id,
                        network=n.network,
                        kind="overlap_existing",
                        message=(f"{n.network} overlaps existing {ex_kind} {ex_net} (id={rid})"),
                    )
                )

    return conflicts


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get("", response_model=list[SubnetPlanRead])
async def list_plans(
    current_user: CurrentUser,
    db: DB,
    space_id: str | None = None,
) -> list[SubnetPlanRead]:
    stmt = select(SubnetPlan).order_by(SubnetPlan.modified_at.desc())
    if space_id:
        try:
            sid = uuid.UUID(space_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="space_id is not a valid UUID",
            )
        stmt = stmt.where(SubnetPlan.space_id == sid)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_read(p) for p in rows]


@router.get("/{plan_id}", response_model=SubnetPlanRead)
async def get_plan(plan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> SubnetPlanRead:
    plan = await db.get(SubnetPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")
    return _to_read(plan)


@router.post("", response_model=SubnetPlanRead, status_code=status.HTTP_201_CREATED)
async def create_plan(body: SubnetPlanCreate, current_user: CurrentUser, db: DB) -> SubnetPlanRead:
    try:
        space_id = uuid.UUID(body.space_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="space_id is not a valid UUID",
        )
    space = await db.get(IPSpace, space_id)
    if space is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IPSpace not found")
    plan = SubnetPlan(
        name=body.name,
        description=body.description,
        space_id=space_id,
        tree=body.tree.model_dump(),
        created_by_user_id=current_user.id,
    )
    db.add(plan)
    await db.flush()
    write_audit(
        db,
        user=current_user,
        action="subnet_plan_created",
        resource_type="subnet_plan",
        resource_id=str(plan.id),
        resource_display=plan.name,
        new_value={"name": plan.name, "space_id": str(space_id)},
    )
    await db.commit()
    await db.refresh(plan)
    return _to_read(plan)


@router.patch("/{plan_id}", response_model=SubnetPlanRead)
async def update_plan(
    plan_id: uuid.UUID,
    body: SubnetPlanUpdate,
    current_user: CurrentUser,
    db: DB,
) -> SubnetPlanRead:
    plan = await db.get(SubnetPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")
    if plan.applied_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Plan has already been applied; create a new plan to design further changes",
        )
    changed: list[str] = []
    if body.name is not None and body.name != plan.name:
        plan.name = body.name
        changed.append("name")
    if body.description is not None and body.description != plan.description:
        plan.description = body.description
        changed.append("description")
    if body.tree is not None:
        plan.tree = body.tree.model_dump()
        changed.append("tree")
    if changed:
        write_audit(
            db,
            user=current_user,
            action="subnet_plan_updated",
            resource_type="subnet_plan",
            resource_id=str(plan.id),
            resource_display=plan.name,
            changed_fields=changed,
        )
        await db.commit()
        await db.refresh(plan)
    return _to_read(plan)


@router.delete("/{plan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_plan(plan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> None:
    plan = await db.get(SubnetPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")
    write_audit(
        db,
        user=current_user,
        action="subnet_plan_deleted",
        resource_type="subnet_plan",
        resource_id=str(plan.id),
        resource_display=plan.name,
    )
    await db.delete(plan)
    await db.commit()


@router.post("/{plan_id}/validate", response_model=ValidationResult)
async def validate_plan(plan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> ValidationResult:
    plan = await db.get(SubnetPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")
    if not plan.tree:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Plan has no tree"
        )
    tree = PlanNode.model_validate(plan.tree)
    conflicts = await _validate_tree(db, plan.space_id, tree)
    blocks, subnets = _node_count(tree)
    return ValidationResult(
        ok=len(conflicts) == 0,
        conflicts=conflicts,
        summary={"block_count": blocks, "subnet_count": subnets},
    )


@router.post("/validate-tree", response_model=ValidationResult)
async def validate_unsaved_tree(
    body: SubnetPlanCreate, current_user: CurrentUser, db: DB
) -> ValidationResult:
    """Dry-run validation of an in-flight tree (not yet persisted).

    Lets the planner UI show conflicts as the operator drags / resizes,
    without forcing them to save first. Same rules as ``/{id}/validate``.
    """
    try:
        space_id = uuid.UUID(body.space_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="space_id is not a valid UUID",
        )
    conflicts = await _validate_tree(db, space_id, body.tree)
    blocks, subnets = _node_count(body.tree)
    return ValidationResult(
        ok=len(conflicts) == 0,
        conflicts=conflicts,
        summary={"block_count": blocks, "subnet_count": subnets},
    )


@router.post("/{plan_id}/reopen", response_model=SubnetPlanRead)
async def reopen_plan(plan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> SubnetPlanRead:
    """Flip an applied plan back to draft state.

    Only succeeds if every resource the plan created (recorded in
    ``applied_resource_ids``) has been deleted from IPAM. The intent is
    to support the workflow where the operator applies a plan, then
    deletes the materialised rows (e.g. lab teardown, mistake), and now
    wants to iterate on the same plan rather than start a new one.
    Surviving rows would mean re-applying creates duplicates → 409.
    """
    plan = await db.get(SubnetPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")
    if plan.applied_at is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Plan is already a draft",
        )
    ids = plan.applied_resource_ids or {}
    block_ids = [uuid.UUID(b) for b in ids.get("block_ids", [])]
    subnet_ids = [uuid.UUID(s) for s in ids.get("subnet_ids", [])]
    survivors: list[dict[str, str]] = []
    if block_ids:
        rows = (
            await db.execute(select(IPBlock.id, IPBlock.network).where(IPBlock.id.in_(block_ids)))
        ).all()
        for rid, net in rows:
            survivors.append({"kind": "block", "id": str(rid), "network": str(net)})
    if subnet_ids:
        rows = (
            await db.execute(select(Subnet.id, Subnet.network).where(Subnet.id.in_(subnet_ids)))
        ).all()
        for rid, net in rows:
            survivors.append({"kind": "subnet", "id": str(rid), "network": str(net)})
    if survivors:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": (
                    "Plan cannot be reopened — some resources it created still "
                    "exist in IPAM. Delete them first, then retry."
                ),
                "survivors": survivors,
            },
        )
    plan.applied_at = None
    plan.applied_resource_ids = None
    write_audit(
        db,
        user=current_user,
        action="subnet_plan_reopened",
        resource_type="subnet_plan",
        resource_id=str(plan.id),
        resource_display=plan.name,
    )
    await db.commit()
    await db.refresh(plan)
    return _to_read(plan)


@router.post("/{plan_id}/apply", response_model=ApplyResult)
async def apply_plan(plan_id: uuid.UUID, current_user: CurrentUser, db: DB) -> ApplyResult:
    """Materialise the plan tree into IPBlocks + Subnets atomically.

    Re-runs validation as the first step inside the transaction; if any
    conflict is present, returns 409 with the full conflict list and
    nothing is written.
    """
    # The plans router gates on ``ip_block`` write, but apply also materialises
    # Subnets — require subnet write too so a block-only grant can't create
    # subnets through the plan path (#508). Superadmin/wildcard pass.
    if not user_has_permission(current_user, "write", "subnet"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: applying a plan needs 'write' on 'subnet'",
        )
    plan = await db.get(SubnetPlan, plan_id)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")
    if plan.applied_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Plan has already been applied",
        )
    if not plan.tree:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Plan has no tree"
        )

    tree = PlanNode.model_validate(plan.tree)
    conflicts = await _validate_tree(db, plan.space_id, tree)
    if conflicts:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "Plan validation failed",
                "conflicts": [c.model_dump() for c in conflicts],
            },
        )

    created_blocks: list[str] = []
    created_subnets: list[str] = []

    # Lazy: the IPAM router includes this module's router at import time.
    from app.api.v1.ipam.router import _sync_dns_record  # noqa: PLC0415
    from app.services.dns.reverse_zone import ensure_reverse_zone_for_subnet  # noqa: PLC0415

    async def materialise(
        node: PlanNode,
        parent_block_id: uuid.UUID | None,
        is_root: bool,
    ) -> None:
        # Anchored root → reuse the existing block; recurse into children only.
        if is_root and node.existing_block_id:
            existing = await db.get(IPBlock, uuid.UUID(node.existing_block_id))
            assert existing is not None  # validated above
            for child in node.children:
                await materialise(child, existing.id, is_root=False)
            return

        node_net = ipaddress.ip_network(node.network, strict=False)
        # Branch on the explicit ``kind`` field. Root is always a block
        # (validation enforces this). Subnets cannot have children, so a
        # node with kind="subnet" never recurses.
        if node.kind == "block":
            # Anchored root path is handled above; we only get here for
            # to-be-created blocks. Set DNS / DHCP fields when explicit on
            # the node, otherwise let inheritance fill them at read time.
            dns_group_ids = [node.dns_group_id] if node.dns_group_id else None
            dns_explicit = bool(node.dns_group_id or node.dns_zone_id)
            dhcp_explicit = bool(node.dhcp_server_group_id)
            block = IPBlock(
                space_id=plan.space_id,
                parent_block_id=parent_block_id,
                network=node.network,
                name=node.name or "",
                description=node.description or "",
                dns_group_ids=dns_group_ids,
                dns_zone_id=node.dns_zone_id,
                dns_inherit_settings=not dns_explicit,
                dhcp_server_group_id=(
                    uuid.UUID(node.dhcp_server_group_id) if node.dhcp_server_group_id else None
                ),
                dhcp_inherit_settings=not dhcp_explicit,
            )
            db.add(block)
            await db.flush()
            created_blocks.append(str(block.id))
            for child in node.children:
                await materialise(child, block.id, is_root=False)
        else:
            # Leaf descendant → Subnet. total_ips matches the IPAM router:
            # exclude network/broadcast for IPv4 prefix < 31; full count for v6.
            if node_net.version == 6:
                total = min(node_net.num_addresses, 2**63 - 1)
            elif node_net.prefixlen >= 31:
                total = node_net.num_addresses
            else:
                total = node_net.num_addresses - 2
            dns_explicit = bool(node.dns_group_id or node.dns_zone_id)
            dhcp_explicit = bool(node.dhcp_server_group_id)
            node_kind = _subnet_kind(node_net)
            # Validate the gateway is inside the subnet — create_subnet enforces
            # this and plan-apply didn't, so a bad gateway could land unchecked
            # (#505).
            gateway = node.gateway or None
            if gateway is not None:
                try:
                    gw = ipaddress.ip_address(gateway)
                except ValueError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Invalid gateway {gateway!r} on {node.network}",
                    ) from exc
                if gw not in node_net:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=f"Gateway {gateway} is not within subnet {node.network}",
                    )
            subnet = Subnet(
                space_id=plan.space_id,
                block_id=parent_block_id,
                network=node.network,
                name=node.name or "",
                description=node.description or "",
                total_ips=total,
                allocated_ips=0,
                utilization_percent=0.0,
                kind=node_kind,
                dns_group_ids=[node.dns_group_id] if node.dns_group_id else None,
                dns_zone_id=node.dns_zone_id,
                dns_inherit_settings=not dns_explicit,
                dhcp_server_group_id=(
                    uuid.UUID(node.dhcp_server_group_id) if node.dhcp_server_group_id else None
                ),
                dhcp_inherit_settings=not dhcp_explicit,
                vlan_ref_id=(uuid.UUID(node.vlan_ref_id) if node.vlan_ref_id else None),
                gateway=gateway,
            )
            db.add(subnet)
            await db.flush()
            created_subnets.append(str(subnet.id))
            # Placeholder network/broadcast/gateway rows, mirroring create_subnet
            # (#505). Multicast leaves and v4 /31+/32 / v6 /127+/128 get none.
            is_v6 = isinstance(node_net, ipaddress.IPv6Network)
            gw_row: IPAddress | None = None
            if node_kind != "multicast" and node_net.prefixlen < (127 if is_v6 else 31):
                db.add(
                    IPAddress(
                        subnet_id=subnet.id,
                        address=str(node_net.network_address),
                        status="network",
                        description="Network address",
                        created_by_user_id=current_user.id,
                    )
                )
                if not is_v6:
                    db.add(
                        IPAddress(
                            subnet_id=subnet.id,
                            address=str(node_net.broadcast_address),
                            status="broadcast",
                            description="Broadcast address",
                            created_by_user_id=current_user.id,
                        )
                    )
                gw_addr = gateway or str(node_net.network_address + 1)
                gw_row = IPAddress(
                    subnet_id=subnet.id,
                    address=gw_addr,
                    status="reserved",
                    description="Gateway",
                    hostname="gateway",
                    created_by_user_id=current_user.id,
                )
                db.add(gw_row)
                subnet.gateway = gw_addr
                await db.flush()
            # spatiumddi#1150 — the two DNS steps create_subnet runs, so a
            # planned subnet is in sync with DNS from apply rather than from
            # its first allocation: the reverse zone its effective DNS names
            # (explicit or inherited, #1149), then the gateway placeholder's
            # PTR. Apply never ran either, so the reverse zone waited for the
            # first allocation's catch-up and the gateway's PTR was missing
            # from then on.
            await ensure_reverse_zone_for_subnet(db, subnet, current_user)
            if gw_row is not None:
                await _sync_dns_record(db, gw_row, subnet, backfill_reverse_zone=False)

    await materialise(tree, None, is_root=True)

    plan.applied_at = datetime.now(UTC)
    plan.applied_resource_ids = {
        "block_ids": created_blocks,
        "subnet_ids": created_subnets,
    }
    write_audit(
        db,
        user=current_user,
        action="subnet_plan_applied",
        resource_type="subnet_plan",
        resource_id=str(plan.id),
        resource_display=plan.name,
        new_value={
            "block_count": len(created_blocks),
            "subnet_count": len(created_subnets),
        },
    )
    await db.commit()

    return ApplyResult(
        block_ids=created_blocks,
        subnet_ids=created_subnets,
        applied_at=plan.applied_at,
    )

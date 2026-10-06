"""Active block-sync — operator REST surface (#601).

The *enforcement* half of the detect→block loop. Manages the
SpatiumDDI-owned ``network_block`` desired-state (blocked IPs / MACs) and
arms per-target write-back into OPNsense (firewall alias membership),
UniFi (L2 client quarantine), and Palo Alto PAN-OS (Dynamic Address Group
tag register via the User-ID API, #605 — the extra
``manage_firewall_enforcement`` permission gates arming that target).

Guardrails, all enforced here:

* Whole surface gated behind the ``security.block_sync`` feature module
  (applied at the router include in ``app.api.v1.router``).
* ``manage_block_sync`` RBAC on every endpoint; superadmin bypasses.
* Every block create routes through the two-person approval gate (#62)
  when ``governance.approvals`` is on and a policy matches.
* No silent writes: ``POST /blocks?preview=true`` returns the exact
  per-target add/remove diff without persisting or pushing; every real
  mutation is audited and immediately reconciled.
* Distinct write-scoped credentials, Fernet-encrypted, never returned
  (password-confirm reveal, mirroring agent-bootstrap-key reveal).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import DB
from app.api.stepup import require_operator_stepup
from app.core.crypto import decrypt_str, encrypt_str
from app.core.demo_mode import forbid_in_demo_mode
from app.core.permissions import require_permission
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.block_sync import (
    BLOCK_SOURCES,
    NetworkBlock,
    NetworkBlockPush,
)
from app.models.meraki import MerakiOrg
from app.models.opnsense import OPNsenseRouter
from app.models.panos import PANOSFirewall
from app.models.unifi import UnifiController
from app.services.ai.operations import get_operation
from app.services.ai.operations_risky import CreateNetworkBlockArgs
from app.services.approvals.gate import gate_or_execute
from app.services.block_sync.reconcile import (
    applicable_targets_for_kind,
    meraki_config_error,
    normalize_block_value,
    opnsense_config_error,
    panos_config_error,
    preview_meraki,
    preview_opnsense,
    preview_panos,
    preview_unifi,
    unifi_config_error,
)

PERMISSION = "manage_block_sync"

router = APIRouter(
    prefix="/block-sync",
    tags=["block-sync"],
    dependencies=[Depends(require_permission("admin", PERMISSION))],
)

ManageUser = Annotated[User, Depends(require_permission("admin", PERMISSION))]


# ── Value normalisation ──────────────────────────────────────────────


def _normalize_value(kind: str, value: str) -> str:
    try:
        return normalize_block_value(kind, value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


# ── Schemas ──────────────────────────────────────────────────────────


class BlockPushOut(BaseModel):
    target_kind: str
    target_id: uuid.UUID
    push_status: str
    last_pushed_at: datetime | None
    last_error: str | None


class BlockOut(BaseModel):
    id: uuid.UUID
    kind: str
    value: str
    reason: str
    description: str
    source: str
    source_ref: str | None
    enabled: bool
    expires_at: datetime | None
    created_at: datetime
    modified_at: datetime
    pushes: list[BlockPushOut] = []


class BlockCreate(BaseModel):
    kind: Literal["ip", "mac"]
    value: str
    reason: str = "quarantine"
    description: str = ""
    source: str = "manual"
    source_ref: str | None = None
    expires_at: datetime | None = None

    @field_validator("source")
    @classmethod
    def _valid_source(cls, v: str) -> str:
        if v not in BLOCK_SOURCES:
            raise ValueError(f"source must be one of {BLOCK_SOURCES}")
        return v


class TargetDiffOut(BaseModel):
    target_kind: str
    target_id: uuid.UUID
    target_name: str
    to_add: list[str]
    to_remove: list[str]
    error: str | None = None


class TargetOut(BaseModel):
    target_kind: str
    target_id: uuid.UUID
    name: str
    block_sync_enabled: bool
    # OPNsense-only
    block_alias_name: str | None = None
    # UniFi-only
    block_sync_site: str | None = None
    block_sync_auth_kind: str | None = None
    # PAN-OS-only
    block_tag_name: str | None = None
    is_panorama: bool | None = None
    # Meraki-only
    block_policy_name: str | None = None
    write_credentials_present: bool
    last_block_sync_at: datetime | None
    last_block_sync_error: str | None


class OpnsenseArm(BaseModel):
    block_sync_enabled: bool | None = None
    block_alias_name: str | None = None
    block_sync_api_key: str | None = None
    # Omit / empty keeps the stored secret; non-empty rotates it.
    block_sync_api_secret: str | None = None


class UnifiArm(BaseModel):
    block_sync_enabled: bool | None = None
    block_sync_site: str | None = None
    block_sync_auth_kind: Literal["api_key", "user_password"] | None = None
    block_sync_api_key: str | None = None
    block_sync_username: str | None = None
    block_sync_password: str | None = None


class PanosArm(BaseModel):
    block_sync_enabled: bool | None = None
    block_tag_name: str | None = None
    # The User-ID-capable write API key. Omit / empty keeps the stored key.
    block_sync_api_key: str | None = None


class MerakiArm(BaseModel):
    block_sync_enabled: bool | None = None
    block_policy_name: str | None = None
    # The write-scoped Dashboard API key. Omit / empty keeps the stored key.
    block_sync_api_key: str | None = None


class RevealRequest(BaseModel):
    password: str | None = None
    totp_code: str | None = None


# ── Helpers ──────────────────────────────────────────────────────────


def _audit(
    db: DB,
    *,
    user: User,
    action: str,
    resource_id: str,
    resource_display: str,
    new_value: dict | None = None,
    changed_fields: list[str] | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action=action,
            resource_type="network_block",
            resource_id=resource_id,
            resource_display=resource_display,
            new_value=new_value,
            changed_fields=changed_fields,
        )
    )


async def _pushes_for(
    db: DB, block_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[NetworkBlockPush]]:
    if not block_ids:
        return {}
    rows = (
        (await db.execute(select(NetworkBlockPush).where(NetworkBlockPush.block_id.in_(block_ids))))
        .scalars()
        .all()
    )
    out: dict[uuid.UUID, list[NetworkBlockPush]] = {}
    for r in rows:
        out.setdefault(r.block_id, []).append(r)
    return out


def _block_out(block: NetworkBlock, pushes: list[NetworkBlockPush]) -> BlockOut:
    return BlockOut(
        id=block.id,
        kind=block.kind,
        value=block.value,
        reason=block.reason,
        description=block.description,
        source=block.source,
        source_ref=block.source_ref,
        enabled=block.enabled,
        expires_at=block.expires_at,
        created_at=block.created_at,
        modified_at=block.modified_at,
        pushes=[
            BlockPushOut(
                target_kind=p.target_kind,
                target_id=p.target_id,
                push_status=p.push_status,
                last_pushed_at=p.last_pushed_at,
                last_error=p.last_error,
            )
            for p in pushes
        ],
    )


def _opnsense_target_out(r: OPNsenseRouter) -> TargetOut:
    return TargetOut(
        target_kind="opnsense",
        target_id=r.id,
        name=r.name,
        block_sync_enabled=r.block_sync_enabled,
        block_alias_name=r.block_alias_name or "",
        write_credentials_present=bool(r.block_sync_api_key and r.block_sync_api_secret_encrypted),
        last_block_sync_at=r.last_block_sync_at,
        last_block_sync_error=r.last_block_sync_error,
    )


def _unifi_target_out(c: UnifiController) -> TargetOut:
    kind = c.block_sync_auth_kind or "api_key"
    creds = (
        bool(c.block_sync_api_key_encrypted)
        if kind == "api_key"
        else bool(c.block_sync_username_encrypted and c.block_sync_password_encrypted)
    )
    return TargetOut(
        target_kind="unifi",
        target_id=c.id,
        name=c.name,
        block_sync_enabled=c.block_sync_enabled,
        block_sync_site=c.block_sync_site or "default",
        block_sync_auth_kind=kind,
        write_credentials_present=creds,
        last_block_sync_at=c.last_block_sync_at,
        last_block_sync_error=c.last_block_sync_error,
    )


def _panos_target_out(f: PANOSFirewall) -> TargetOut:
    return TargetOut(
        target_kind="paloalto",
        target_id=f.id,
        name=f.name,
        block_sync_enabled=f.block_sync_enabled,
        block_tag_name=f.block_tag_name or "",
        is_panorama=f.is_panorama,
        write_credentials_present=bool(f.block_sync_api_key_encrypted),
        last_block_sync_at=f.last_block_sync_at,
        last_block_sync_error=f.last_block_sync_error,
    )


def _meraki_target_out(o: MerakiOrg) -> TargetOut:
    return TargetOut(
        target_kind="meraki",
        target_id=o.id,
        name=o.name,
        block_sync_enabled=o.block_sync_enabled,
        block_policy_name=o.block_policy_name or "Blocked",
        write_credentials_present=bool(o.block_sync_api_key_encrypted),
        last_block_sync_at=o.last_block_sync_at,
        last_block_sync_error=o.last_block_sync_error,
    )


def _enqueue_reconcile(targets: list[tuple[str, uuid.UUID]]) -> None:
    """Fire an immediate converge on each applicable target so enforcement
    lands within seconds. Broker-unavailable is non-fatal — the 60 s sweep
    catches up."""
    from app.tasks.block_sync import reconcile_target_now  # noqa: PLC0415

    for target_kind, target_id in targets:
        try:
            reconcile_target_now.delay(target_kind, str(target_id))
        except Exception:  # noqa: BLE001 — broker down; sweep converges later
            pass


def _enqueue_lift(targets: list[tuple[str, uuid.UUID]]) -> None:
    """Fire a disarm-cleanup lift: remove everything SpatiumDDI pushed to a
    target that is being disarmed. Broker-unavailable is non-fatal (the target
    is disabled, so no sweep will re-push — but the stale device state stays;
    surfaced via the target's last_block_sync_error on the next successful run)."""
    from app.tasks.block_sync import lift_target_now  # noqa: PLC0415

    for target_kind, target_id in targets:
        try:
            lift_target_now.delay(target_kind, str(target_id))
        except Exception:  # noqa: BLE001 — broker down; the target is disarmed
            pass  # so no sweep re-pushes; stale device state surfaces on next run


# ── Block endpoints ──────────────────────────────────────────────────


@router.get("/blocks", response_model=list[BlockOut])
async def list_blocks(db: DB, _: ManageUser) -> list[BlockOut]:
    blocks = (
        (await db.execute(select(NetworkBlock).order_by(NetworkBlock.created_at.desc())))
        .scalars()
        .all()
    )
    pushes = await _pushes_for(db, [b.id for b in blocks])
    return [_block_out(b, pushes.get(b.id, [])) for b in blocks]


@router.post("/blocks/preview", response_model=list[TargetDiffOut])
async def preview_block(body: BlockCreate, db: DB, _: ManageUser) -> list[TargetDiffOut]:
    """Show which armed targets a new block would land on, and the exact
    add — WITHOUT persisting or pushing anything (NN#5)."""
    value = _normalize_value(body.kind, body.value)
    targets = await applicable_targets_for_kind(db, body.kind)
    out: list[TargetDiffOut] = []
    # Target-independent: is this value already actively enforced? (A
    # disabled/lifted row will be re-enabled + re-pushed by create, so it
    # still counts as an add — match only currently-enabled rows.)
    already_active = (
        await db.execute(
            select(NetworkBlock.id).where(
                NetworkBlock.kind == body.kind,
                NetworkBlock.value == value,
                NetworkBlock.enabled.is_(True),
            )
        )
    ).scalar_one_or_none() is not None
    for target_kind, target_id in targets:
        name = await _target_name(db, target_kind, target_id)
        out.append(
            TargetDiffOut(
                target_kind=target_kind,
                target_id=target_id,
                target_name=name or str(target_id),
                to_add=[] if already_active else [value],
                to_remove=[],
            )
        )
    return out


@router.post("/blocks", status_code=status.HTTP_201_CREATED, response_model=None)
async def create_block(
    body: BlockCreate,
    db: DB,
    user: ManageUser,
    request: Request,
) -> BlockOut | JSONResponse:
    """Create (or re-arm) a network block and immediately converge it onto
    every armed target of the matching kind.

    Routes through the two-person approval gate (#62): when
    ``governance.approvals`` is on and a policy matches ``admin:manage_
    block_sync``, this returns ``202 Accepted`` with a pending change
    request instead of writing. Module-off / no policy → executes inline
    via the operation's ``apply``. The actual persist + audit + push all
    live in the ``create_network_block`` operation so the inline path and
    the approve path share one mutation."""
    forbid_in_demo_mode("Block-sync writes are disabled in demo mode")
    value = _normalize_value(body.kind, body.value)  # 422 early on bad input

    op = get_operation("create_network_block")
    assert op is not None  # registered at import
    args = CreateNetworkBlockArgs(
        kind=body.kind,
        value=value,
        reason=body.reason,
        description=body.description,
        source=body.source,
        source_ref=body.source_ref,
        expires_at=body.expires_at,
    )
    pending = await gate_or_execute(db, user, request, operation=op, args=args)
    if pending is not None:
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content=pending.as_dict())

    result = await op.apply(db, user, args)
    block = await db.get(NetworkBlock, uuid.UUID(str(result["block_id"])))
    assert block is not None
    pushes = await _pushes_for(db, [block.id])
    return _block_out(block, pushes.get(block.id, []))


@router.delete("/blocks/{block_id}", response_model=BlockOut)
async def lift_block(block_id: uuid.UUID, db: DB, user: ManageUser) -> BlockOut:
    """Lift a block — disables it and pushes the removal to every target it
    landed on. The row is kept (disabled) as audit history; re-creating the
    same value re-enables it."""
    forbid_in_demo_mode("Block-sync writes are disabled in demo mode")
    block = await db.get(NetworkBlock, block_id)
    if block is None:
        raise HTTPException(status_code=404, detail="block not found")
    block.enabled = False
    block.updated_by_user_id = user.id
    targets = await applicable_targets_for_kind(db, block.kind)
    _audit(
        db,
        user=user,
        action="lift",
        resource_id=str(block.id),
        resource_display=f"{block.kind}:{block.value}",
    )
    await db.commit()
    await db.refresh(block)
    _enqueue_reconcile(targets)
    pushes = await _pushes_for(db, [block.id])
    return _block_out(block, pushes.get(block.id, []))


# ── Target endpoints ─────────────────────────────────────────────────


async def _target_name(db: DB, target_kind: str, target_id: uuid.UUID) -> str | None:
    if target_kind == "opnsense":
        r = await db.get(OPNsenseRouter, target_id)
        return r.name if r else None
    if target_kind == "paloalto":
        f = await db.get(PANOSFirewall, target_id)
        return f.name if f else None
    if target_kind == "meraki":
        o = await db.get(MerakiOrg, target_id)
        return o.name if o else None
    c = await db.get(UnifiController, target_id)
    return c.name if c else None


@router.get("/targets", response_model=list[TargetOut])
async def list_targets(db: DB, _: ManageUser) -> list[TargetOut]:
    """Every OPNsense router / UniFi controller / Palo Alto firewall / Meraki
    org that CAN be a block-sync target, with its current arming state."""
    routers = (
        (await db.execute(select(OPNsenseRouter).order_by(OPNsenseRouter.name))).scalars().all()
    )
    controllers = (
        (await db.execute(select(UnifiController).order_by(UnifiController.name))).scalars().all()
    )
    firewalls = (
        (await db.execute(select(PANOSFirewall).order_by(PANOSFirewall.name))).scalars().all()
    )
    orgs = (await db.execute(select(MerakiOrg).order_by(MerakiOrg.name))).scalars().all()
    return (
        [_opnsense_target_out(r) for r in routers]
        + [_unifi_target_out(c) for c in controllers]
        + [_panos_target_out(f) for f in firewalls]
        + [_meraki_target_out(o) for o in orgs]
    )


@router.put("/targets/opnsense/{target_id}", response_model=TargetOut)
async def arm_opnsense(
    target_id: uuid.UUID, body: OpnsenseArm, db: DB, user: ManageUser
) -> TargetOut:
    forbid_in_demo_mode("Block-sync arming is disabled in demo mode")
    r = await db.get(OPNsenseRouter, target_id)
    if r is None:
        raise HTTPException(status_code=404, detail="OPNsense target not found")
    was_enabled = r.block_sync_enabled
    changes = body.model_dump(exclude_unset=True)
    if "block_sync_enabled" in changes:
        r.block_sync_enabled = bool(changes["block_sync_enabled"])
    if "block_alias_name" in changes:
        r.block_alias_name = (changes["block_alias_name"] or "").strip()
    if "block_sync_api_key" in changes and changes["block_sync_api_key"] is not None:
        r.block_sync_api_key = changes["block_sync_api_key"].strip()
    if changes.get("block_sync_api_secret"):
        r.block_sync_api_secret_encrypted = encrypt_str(changes["block_sync_api_secret"])
    if r.block_sync_enabled:
        # Reuse the reconcile-side validator so arm-time and push-time agree.
        cfg_err = opnsense_config_error(r)
        if cfg_err is not None:
            raise HTTPException(
                status_code=422,
                detail=f"cannot arm OPNsense block sync: {cfg_err}",
            )
    _audit(
        db,
        user=user,
        action="arm_target",
        resource_id=str(r.id),
        resource_display=f"opnsense:{r.name}",
        changed_fields=[k for k in changes if k != "block_sync_api_secret"],
        new_value={"block_sync_enabled": r.block_sync_enabled},
    )
    await db.commit()
    await db.refresh(r)
    if r.block_sync_enabled:
        _enqueue_reconcile([("opnsense", r.id)])
    elif was_enabled:
        # Disarm: lift everything SpatiumDDI pushed to this target so a
        # disabled firewall doesn't keep blocking IPs with no reconcile path.
        _enqueue_lift([("opnsense", r.id)])
    return _opnsense_target_out(r)


@router.put("/targets/unifi/{target_id}", response_model=TargetOut)
async def arm_unifi(target_id: uuid.UUID, body: UnifiArm, db: DB, user: ManageUser) -> TargetOut:
    forbid_in_demo_mode("Block-sync arming is disabled in demo mode")
    c = await db.get(UnifiController, target_id)
    if c is None:
        raise HTTPException(status_code=404, detail="UniFi target not found")
    was_enabled = c.block_sync_enabled
    changes = body.model_dump(exclude_unset=True)
    if "block_sync_enabled" in changes:
        c.block_sync_enabled = bool(changes["block_sync_enabled"])
    if "block_sync_site" in changes:
        c.block_sync_site = (changes["block_sync_site"] or "default").strip() or "default"
    if changes.get("block_sync_auth_kind"):
        c.block_sync_auth_kind = changes["block_sync_auth_kind"]
    if changes.get("block_sync_api_key"):
        c.block_sync_api_key_encrypted = encrypt_str(changes["block_sync_api_key"])
    if changes.get("block_sync_username"):
        c.block_sync_username_encrypted = encrypt_str(changes["block_sync_username"])
    if changes.get("block_sync_password"):
        c.block_sync_password_encrypted = encrypt_str(changes["block_sync_password"])
    if c.block_sync_enabled:
        # Reuse the reconcile-side validator so arm-time and push-time agree —
        # this also rejects the cloud-mode + user_password combo the reconciler
        # refuses (previously armable but silently inert, #601 review).
        cfg_err = unifi_config_error(c)
        if cfg_err is not None:
            raise HTTPException(
                status_code=422,
                detail=f"cannot arm UniFi block sync: {cfg_err}",
            )
    _audit(
        db,
        user=user,
        action="arm_target",
        resource_id=str(c.id),
        resource_display=f"unifi:{c.name}",
        changed_fields=[
            k
            for k in changes
            if k not in {"block_sync_api_key", "block_sync_username", "block_sync_password"}
        ],
        new_value={"block_sync_enabled": c.block_sync_enabled},
    )
    await db.commit()
    await db.refresh(c)
    if c.block_sync_enabled:
        _enqueue_reconcile([("unifi", c.id)])
    elif was_enabled:
        _enqueue_lift([("unifi", c.id)])
    return _unifi_target_out(c)


@router.put("/targets/paloalto/{target_id}", response_model=TargetOut)
async def arm_paloalto(
    target_id: uuid.UUID,
    body: PanosArm,
    db: DB,
    user: ManageUser,
    # DAG enforcement is off-prem, broad-blast-radius write — it needs a
    # DISTINCT permission on top of manage_block_sync (issue #605 guardrail 5).
    _enforce: Annotated[User, Depends(require_permission("admin", "manage_firewall_enforcement"))],
) -> TargetOut:
    forbid_in_demo_mode("Block-sync arming is disabled in demo mode")
    f = await db.get(PANOSFirewall, target_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Palo Alto target not found")
    was_enabled = f.block_sync_enabled
    changes = body.model_dump(exclude_unset=True)
    if "block_sync_enabled" in changes:
        f.block_sync_enabled = bool(changes["block_sync_enabled"])
    if "block_tag_name" in changes and changes["block_tag_name"] is not None:
        f.block_tag_name = changes["block_tag_name"].strip()
    if changes.get("block_sync_api_key"):
        f.block_sync_api_key_encrypted = encrypt_str(changes["block_sync_api_key"])
    if f.block_sync_enabled:
        cfg_err = panos_config_error(f)
        if cfg_err is not None:
            raise HTTPException(
                status_code=422, detail=f"cannot arm Palo Alto DAG enforcement: {cfg_err}"
            )
    _audit(
        db,
        user=user,
        action="arm_target",
        resource_id=str(f.id),
        resource_display=f"paloalto:{f.name}",
        changed_fields=[k for k in changes if k != "block_sync_api_key"],
        new_value={"block_sync_enabled": f.block_sync_enabled},
    )
    await db.commit()
    await db.refresh(f)
    if f.block_sync_enabled:
        _enqueue_reconcile([("paloalto", f.id)])
    elif was_enabled:
        _enqueue_lift([("paloalto", f.id)])
    return _panos_target_out(f)


@router.put("/targets/meraki/{target_id}", response_model=TargetOut)
async def arm_meraki(
    target_id: uuid.UUID,
    body: MerakiArm,
    db: DB,
    user: ManageUser,
    # Per-client block enforcement is an off-prem, broad-blast-radius write — it
    # needs a DISTINCT permission on top of manage_block_sync (mirrors #605).
    _enforce: Annotated[User, Depends(require_permission("admin", "manage_firewall_enforcement"))],
) -> TargetOut:
    forbid_in_demo_mode("Block-sync arming is disabled in demo mode")
    o = await db.get(MerakiOrg, target_id)
    if o is None:
        raise HTTPException(status_code=404, detail="Meraki target not found")
    was_enabled = o.block_sync_enabled
    changes = body.model_dump(exclude_unset=True)
    if "block_sync_enabled" in changes:
        o.block_sync_enabled = bool(changes["block_sync_enabled"])
    if "block_policy_name" in changes and changes["block_policy_name"] is not None:
        o.block_policy_name = changes["block_policy_name"].strip() or "Blocked"
    if changes.get("block_sync_api_key"):
        o.block_sync_api_key_encrypted = encrypt_str(changes["block_sync_api_key"])
    if o.block_sync_enabled:
        cfg_err = meraki_config_error(o)
        if cfg_err is not None:
            raise HTTPException(
                status_code=422, detail=f"cannot arm Meraki client-block enforcement: {cfg_err}"
            )
    _audit(
        db,
        user=user,
        action="arm_target",
        resource_id=str(o.id),
        resource_display=f"meraki:{o.name}",
        changed_fields=[k for k in changes if k != "block_sync_api_key"],
        new_value={"block_sync_enabled": o.block_sync_enabled},
    )
    await db.commit()
    await db.refresh(o)
    if o.block_sync_enabled:
        _enqueue_reconcile([("meraki", o.id)])
    elif was_enabled:
        _enqueue_lift([("meraki", o.id)])
    return _meraki_target_out(o)


@router.post(
    "/targets/{target_kind}/{target_id}/reconcile",
    response_model=TargetDiffOut,
)
async def reconcile_target(
    target_kind: Literal["opnsense", "unifi", "paloalto", "meraki"],
    target_id: uuid.UUID,
    db: DB,
    user: ManageUser,
    preview: Annotated[bool, Query()] = False,
) -> TargetDiffOut:
    """Force-converge one target. ``?preview=true`` reads the device +
    returns the diff without pushing; otherwise it enqueues the reconcile."""
    if target_kind == "opnsense":
        r = await db.get(OPNsenseRouter, target_id)
        if r is None:
            raise HTTPException(status_code=404, detail="OPNsense target not found")
        diff = await preview_opnsense(db, r, read_device=preview)
    elif target_kind == "paloalto":
        f = await db.get(PANOSFirewall, target_id)
        if f is None:
            raise HTTPException(status_code=404, detail="Palo Alto target not found")
        diff = await preview_panos(db, f, read_device=preview)
    elif target_kind == "meraki":
        o = await db.get(MerakiOrg, target_id)
        if o is None:
            raise HTTPException(status_code=404, detail="Meraki target not found")
        diff = await preview_meraki(db, o)
    else:
        c = await db.get(UnifiController, target_id)
        if c is None:
            raise HTTPException(status_code=404, detail="UniFi target not found")
        diff = await preview_unifi(db, c)

    if not preview and diff.error is None:
        forbid_in_demo_mode("Block-sync writes are disabled in demo mode")
        _enqueue_reconcile([(target_kind, target_id)])
    return TargetDiffOut(
        target_kind=diff.target_kind,
        target_id=diff.target_id,
        target_name=diff.target_name,
        to_add=diff.to_add,
        to_remove=diff.to_remove,
        error=diff.error,
    )


@router.post("/targets/{target_kind}/{target_id}/reveal")
async def reveal_credentials(
    target_kind: Literal["opnsense", "unifi", "paloalto", "meraki"],
    target_id: uuid.UUID,
    body: RevealRequest,
    db: DB,
    user: ManageUser,
) -> dict[str, str]:
    """Reveal the stored write-scoped secret after re-confirming the
    operator (password / TOTP), mirroring the agent-bootstrap-key reveal.
    Audited. ``manage_block_sync`` holders only (router-level gate)."""
    # #1413 — through the shared step-up, so a wrong answer spends the
    # per-account budget like every other step-up.
    await require_operator_stepup(
        db,
        user,
        password=body.password,
        totp_code=body.totp_code,
        action="block_sync_reveal_denied",
        resource_type="network_block_target",
        resource_id=str(target_id),
        resource_display=f"{target_kind}:{target_id}",
    )

    revealed: dict[str, str] = {}
    if target_kind == "opnsense":
        r = await db.get(OPNsenseRouter, target_id)
        if r is None:
            raise HTTPException(status_code=404, detail="OPNsense target not found")
        if r.block_sync_api_secret_encrypted:
            revealed["api_secret"] = decrypt_str(r.block_sync_api_secret_encrypted)
        name = r.name
    elif target_kind == "paloalto":
        f = await db.get(PANOSFirewall, target_id)
        if f is None:
            raise HTTPException(status_code=404, detail="Palo Alto target not found")
        if f.block_sync_api_key_encrypted:
            revealed["api_key"] = decrypt_str(f.block_sync_api_key_encrypted)
        name = f.name
    elif target_kind == "meraki":
        o = await db.get(MerakiOrg, target_id)
        if o is None:
            raise HTTPException(status_code=404, detail="Meraki target not found")
        if o.block_sync_api_key_encrypted:
            revealed["api_key"] = decrypt_str(o.block_sync_api_key_encrypted)
        name = o.name
    else:
        c = await db.get(UnifiController, target_id)
        if c is None:
            raise HTTPException(status_code=404, detail="UniFi target not found")
        if c.block_sync_api_key_encrypted:
            revealed["api_key"] = decrypt_str(c.block_sync_api_key_encrypted)
        if c.block_sync_password_encrypted:
            revealed["password"] = decrypt_str(c.block_sync_password_encrypted)
        name = c.name

    db.add(
        AuditLog(
            user_id=user.id,
            user_display_name=user.display_name,
            auth_source=user.auth_source,
            action="block_sync_reveal",
            resource_type="network_block_target",
            resource_id=str(target_id),
            resource_display=f"{target_kind}:{name}",
        )
    )
    await db.commit()
    return revealed


__all__ = ["router"]

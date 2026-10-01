"""Fleet-firewall policy / rule / alias CRUD (#285 Phase 3c-1).

The operator surface over the declarative policy model (3a) that the merge
engine (3b) compiles. Everything here is DARK twice over: behind the
``appliance.firewall`` feature module (the router-level ``require_module`` in
``router.py`` 404s when off) AND the ``platform_settings.firewall_enabled``
master switch (editing a policy never touches a node until enforcement is on
AND the next heartbeat renders).

Permissions reuse the existing ``appliance`` resource (read = GET, admin =
writes) — the firewall family is appliance-fleet administration, so anyone
who administers the fleet administers its firewall. (The design's separate
``firewall`` permission string is a future refinement; reusing ``appliance``
keeps the builtin-role seeds untouched.)

Builtin policies (``is_builtin=True``) lock their IDENTITY (``name`` /
``scope_kind`` / ``scope_role``) — clone to re-scope — but their RULES stay
fully editable (the whole point: operators tune role ports). The no-drop-22
DB CHECK is the floor backstop; this layer rejects it with a friendly 422.

Mutations write an ``AuditLog`` row whose ``resource_type`` is mapped in
``event_publisher._RESOURCE_NAMESPACE``, so ``firewall.{policy,rule,alias}.*``
typed webhook events fire automatically — no explicit publish call. Every
mutation also drops the merge's policy cache so the next heartbeat re-reads.

The ``effective`` + ``preview`` read surfaces (which re-derive the per-node
render inputs the heartbeat uses) land in 3c-2 alongside the heartbeat-input
extraction; this commit is the CRUD contract.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload

from app.api.deps import DB, CurrentUser
from app.core.agent_wake import HOSTCONFIG_ALL, publish_wake
from app.core.permissions import user_has_permission
from app.core.request_meta import get_trusted_client_ip
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.audit import AuditLog
from app.models.firewall import (
    _POLICY_ROLES,
    FirewallAlias,
    FirewallApplyState,
    FirewallPolicy,
    FirewallRule,
)
from app.models.settings import PlatformSettings
from app.services.appliance.access import (
    SSH_REACHABILITY_CAVEAT,
    console_only_detail,
    covers,
    effective_doors,
)
from app.services.appliance.firewall_lease import upgrade_in_flight
from app.services.appliance.firewall_merge import (
    MergeContext,
    PolicySet,
    _Policy,
    _Rule,
    compile_firewall_from_policies,
    load_appliance_policy,
    load_policy_set,
    reset_policy_cache,
)

router = APIRouter()

FIREWALL_RESOURCE = "appliance"

_SCOPE_KINDS = frozenset({"fleet", "role", "appliance"})
_ROLES = frozenset(_POLICY_ROLES)
_SOURCE_KINDS = frozenset(
    {
        "any",
        "cidr",
        "alias",
        "cluster_peers",
        "pod_cidr",
        "service_cidr",
        "kubeapi",
        # #993 — pod ∪ service, deliberately WITHOUT the operator's
        # kubeapi_expose allowlist: that widens the RBAC-guarded apiserver,
        # and the kubelet API is not the same proposition.
        "kubelet",
        "mgmt",
        "vip",
    }
)
_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "icmpv6"})
_ACTIONS = frozenset({"accept", "drop"})
_FAMILIES = frozenset({"v4", "v6", "both"})
_ALIAS_KINDS = frozenset({"port", "cidr"})

# Builtin policies accept only these; identity (name/scope_*) is locked.
_BUILTIN_MUTABLE_FIELDS = frozenset({"enabled", "priority", "description"})


# ── Permission helpers ──────────────────────────────────────────────


def _require_read(user: object) -> None:
    if not user_has_permission(user, "read", FIREWALL_RESOURCE):  # type: ignore[arg-type]
        raise HTTPException(status_code=403, detail="Permission denied: need 'read' on 'appliance'")


def _require_admin(user: object) -> None:
    if not user_has_permission(user, "admin", FIREWALL_RESOURCE):  # type: ignore[arg-type]
        raise HTTPException(
            status_code=403, detail="Permission denied: need 'admin' on 'appliance'"
        )


# ── Schemas ─────────────────────────────────────────────────────────


class RuleIn(BaseModel):
    seq: int = Field(..., ge=0)
    action: str = "accept"
    protocol: str
    ports: list[int] = Field(default_factory=list)
    source_kind: str = "any"
    source_cidrs: list[str] = Field(default_factory=list)
    source_alias: str | None = None
    family: str = "both"
    comment: str | None = Field(None, max_length=120)
    render_guard: dict[str, Any] | None = None
    enabled: bool = True

    @field_validator("action")
    @classmethod
    def _v_action(cls, v: str) -> str:
        if v not in _ACTIONS:
            raise ValueError(f"action must be one of {sorted(_ACTIONS)}")
        return v

    @field_validator("protocol")
    @classmethod
    def _v_proto(cls, v: str) -> str:
        if v not in _PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(_PROTOCOLS)}")
        return v

    @field_validator("source_kind")
    @classmethod
    def _v_skind(cls, v: str) -> str:
        if v not in _SOURCE_KINDS:
            raise ValueError(f"source_kind must be one of {sorted(_SOURCE_KINDS)}")
        return v

    @field_validator("family")
    @classmethod
    def _v_family(cls, v: str) -> str:
        if v not in _FAMILIES:
            raise ValueError(f"family must be one of {sorted(_FAMILIES)}")
        return v

    @field_validator("ports")
    @classmethod
    def _v_ports(cls, v: list[int]) -> list[int]:
        for p in v:
            if not (0 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
        return v

    @model_validator(mode="after")
    def _v_shape(self) -> RuleIn:
        # Floor backstop (the DB CHECK is authoritative; this is the friendly 422).
        if self.action == "drop" and 22 in self.ports:
            raise ValueError(
                "a rule may not DROP port 22 (ssh) — the mgmt floor is not " "removable by a rule"
            )
        if self.source_kind == "cidr":
            if not self.source_cidrs:
                raise ValueError("source_kind='cidr' requires source_cidrs")
            for c in self.source_cidrs:
                try:
                    ipaddress.ip_network(c, strict=False)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"invalid CIDR {c!r}: {exc}") from exc
        if self.source_kind == "alias" and not self.source_alias:
            raise ValueError("source_kind='alias' requires source_alias")
        return self


class RuleResponse(RuleIn):
    id: uuid.UUID
    policy_id: uuid.UUID

    model_config = {"from_attributes": True}


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(None, max_length=2000)
    scope_kind: str
    scope_role: str | None = None
    scope_appliance_id: uuid.UUID | None = None
    enabled: bool = True
    priority: int = 100

    @field_validator("scope_kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in _SCOPE_KINDS:
            raise ValueError(f"scope_kind must be one of {sorted(_SCOPE_KINDS)}")
        return v

    @model_validator(mode="after")
    def _v_scope(self) -> PolicyCreate:
        if self.scope_kind == "fleet":
            if self.scope_role is not None or self.scope_appliance_id is not None:
                raise ValueError("fleet scope takes neither scope_role nor scope_appliance_id")
        elif self.scope_kind == "role":
            if self.scope_role not in _ROLES:
                raise ValueError(f"scope_role must be one of {sorted(_ROLES)}")
            if self.scope_appliance_id is not None:
                raise ValueError("role scope takes no scope_appliance_id")
        elif self.scope_kind == "appliance":
            if self.scope_appliance_id is None:
                raise ValueError("appliance scope requires scope_appliance_id")
            if self.scope_role is not None:
                raise ValueError("appliance scope takes no scope_role")
        return self


class PolicyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=120)
    description: str | None = Field(None, max_length=2000)
    enabled: bool | None = None
    priority: int | None = None


class PolicyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    scope_kind: str
    scope_role: str | None
    scope_appliance_id: uuid.UUID | None
    enabled: bool
    is_builtin: bool
    priority: int
    rules: list[RuleResponse]

    model_config = {"from_attributes": True}


class RulesBulkReplace(BaseModel):
    rules: list[RuleIn]


class AliasCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    kind: str
    port_members: list[int] = Field(default_factory=list)
    v4_members: list[str] = Field(default_factory=list)
    v6_members: list[str] = Field(default_factory=list)
    description: str | None = Field(None, max_length=2000)

    @field_validator("kind")
    @classmethod
    def _v_kind(cls, v: str) -> str:
        if v not in _ALIAS_KINDS:
            raise ValueError(f"kind must be one of {sorted(_ALIAS_KINDS)}")
        return v

    @model_validator(mode="after")
    def _v_members(self) -> AliasCreate:
        for fam, members, want in (("v4", self.v4_members, 4), ("v6", self.v6_members, 6)):
            for c in members:
                try:
                    net = ipaddress.ip_network(c, strict=False)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"invalid {fam} CIDR {c!r}: {exc}") from exc
                if net.version != want:
                    raise ValueError(f"{c!r} is not a v{want} network (family-split is at rest)")
        for p in self.port_members:
            if not (0 <= p <= 65535):
                raise ValueError(f"port out of range: {p}")
        return self


class AliasUpdate(BaseModel):
    port_members: list[int] | None = None
    v4_members: list[str] | None = None
    v6_members: list[str] | None = None
    description: str | None = Field(None, max_length=2000)


class AliasResponse(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    port_members: list[int]
    v4_members: list[str]
    v6_members: list[str]
    description: str | None
    is_builtin: bool

    model_config = {"from_attributes": True}


# ── Policy CRUD ─────────────────────────────────────────────────────


async def _get_policy(db: DB, policy_id: uuid.UUID) -> FirewallPolicy:
    # populate_existing so a re-query after a mutation refreshes the
    # identity-map instance's rules collection (rather than returning a stale
    # one) — matters when a long-lived session issues several ops in a row.
    p = (
        (
            await db.execute(
                select(FirewallPolicy)
                .where(FirewallPolicy.id == policy_id)
                .options(selectinload(FirewallPolicy.rules))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .first()
    )
    if p is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return p


@router.get("/policies", response_model=list[PolicyResponse])
async def list_policies(
    db: DB,
    current_user: CurrentUser,
    scope_kind: str | None = Query(None),
    scope_role: str | None = Query(None),
    scope_appliance_id: uuid.UUID | None = Query(None),
) -> list[FirewallPolicy]:
    _require_read(current_user)
    q = (
        select(FirewallPolicy)
        .options(selectinload(FirewallPolicy.rules))
        .order_by(FirewallPolicy.scope_kind, FirewallPolicy.scope_role, FirewallPolicy.name)
    )
    if scope_kind:
        q = q.where(FirewallPolicy.scope_kind == scope_kind)
    if scope_role:
        q = q.where(FirewallPolicy.scope_role == scope_role)
    if scope_appliance_id:
        q = q.where(FirewallPolicy.scope_appliance_id == scope_appliance_id)
    return list((await db.execute(q)).scalars().all())


@router.post("/policies", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(body: PolicyCreate, db: DB, current_user: CurrentUser) -> FirewallPolicy:
    _require_admin(current_user)
    # Friendly pre-check for the scope-uniqueness constraints (one fleet
    # singleton / one policy per role / one override per appliance) so a
    # collision returns 409, not a raw IntegrityError 500.
    dup = select(FirewallPolicy.id)
    if body.scope_kind == "fleet":
        dup = dup.where(FirewallPolicy.scope_kind == "fleet")
    elif body.scope_kind == "role":
        dup = dup.where(FirewallPolicy.scope_role == body.scope_role)
    else:
        dup = dup.where(
            FirewallPolicy.scope_kind == "appliance",
            FirewallPolicy.scope_appliance_id == body.scope_appliance_id,
        )
    if (await db.execute(dup)).first() is not None:
        raise HTTPException(
            status_code=409, detail=f"a {body.scope_kind} policy for this scope already exists"
        )
    p = FirewallPolicy(**body.model_dump(), is_builtin=False, updated_by_id=current_user.id)
    db.add(p)
    db.add(
        AuditLog(
            action="create",
            resource_type="firewall_policy",
            resource_id=str(p.id),
            resource_display=body.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={
                "name": body.name,
                "scope_kind": body.scope_kind,
                "scope_role": body.scope_role,
            },
        )
    )
    await db.commit()
    reset_policy_cache()
    return await _get_policy(db, p.id)


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(policy_id: uuid.UUID, db: DB, current_user: CurrentUser) -> FirewallPolicy:
    _require_read(current_user)
    return await _get_policy(db, policy_id)


@router.patch("/policies/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: uuid.UUID, body: PolicyUpdate, db: DB, current_user: CurrentUser
) -> FirewallPolicy:
    _require_admin(current_user)
    p = await _get_policy(db, policy_id)
    payload = body.model_dump(exclude_unset=True)
    if p.is_builtin:
        offending = sorted(set(payload) - _BUILTIN_MUTABLE_FIELDS)
        if offending:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Built-in policies only accept updates to {sorted(_BUILTIN_MUTABLE_FIELDS)}; "
                    f"rejected: {offending}. Clone the policy first to change identity fields."
                ),
            )
    changed: dict[str, Any] = {}
    for key, value in payload.items():
        old = getattr(p, key)
        if old != value:
            changed[key] = {"old": str(old)[:200], "new": str(value)[:200]}
            setattr(p, key, value)
    if changed:
        p.updated_by_id = current_user.id
        db.add(
            AuditLog(
                action="update",
                resource_type="firewall_policy",
                resource_id=str(p.id),
                resource_display=p.name,
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                changed_fields=list(changed),
                new_value=changed,
            )
        )
    await db.commit()
    reset_policy_cache()
    return await _get_policy(db, policy_id)


@router.delete("/policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(policy_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    _require_admin(current_user)
    p = await _get_policy(db, policy_id)
    if p.is_builtin:
        raise HTTPException(
            status_code=400,
            detail="Built-in policies cannot be deleted. Disable instead (PATCH enabled=false).",
        )
    name = p.name
    db.add(
        AuditLog(
            action="delete",
            resource_type="firewall_policy",
            resource_id=str(p.id),
            resource_display=name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
        )
    )
    await db.execute(delete(FirewallPolicy).where(FirewallPolicy.id == policy_id))
    await db.commit()
    reset_policy_cache()


# ── Rule CRUD (rules editable even on builtins) ─────────────────────


def _rule_kwargs(r: RuleIn) -> dict[str, Any]:
    return r.model_dump()


@router.put("/policies/{policy_id}/rules", response_model=PolicyResponse)
async def replace_rules(
    policy_id: uuid.UUID, body: RulesBulkReplace, db: DB, current_user: CurrentUser
) -> FirewallPolicy:
    """Bulk-replace a policy's rules in one shot — single audit row."""
    _require_admin(current_user)
    p = await _get_policy(db, policy_id)
    seqs = [r.seq for r in body.rules]
    if len(seqs) != len(set(seqs)):
        raise HTTPException(status_code=422, detail="duplicate seq in rules")
    await db.execute(delete(FirewallRule).where(FirewallRule.policy_id == p.id))
    for r in body.rules:
        db.add(FirewallRule(policy_id=p.id, **_rule_kwargs(r)))
    db.add(
        AuditLog(
            action="update",
            resource_type="firewall_rule",
            resource_id=str(p.id),
            resource_display=f"{p.name} rules",
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            changed_fields=["rules"],
            new_value={"count": len(body.rules)},
        )
    )
    await db.commit()
    reset_policy_cache()
    return await _get_policy(db, policy_id)


@router.post(
    "/policies/{policy_id}/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED
)
async def add_rule(
    policy_id: uuid.UUID, body: RuleIn, db: DB, current_user: CurrentUser
) -> FirewallRule:
    _require_admin(current_user)
    p = await _get_policy(db, policy_id)
    if any(r.seq == body.seq for r in p.rules):
        raise HTTPException(status_code=409, detail=f"seq {body.seq} already exists in this policy")
    rule = FirewallRule(policy_id=p.id, **_rule_kwargs(body))
    db.add(rule)
    db.add(
        AuditLog(
            action="create",
            resource_type="firewall_rule",
            resource_id=str(p.id),
            resource_display=f"{p.name} seq {body.seq}",
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={"seq": body.seq, "protocol": body.protocol, "action": body.action},
        )
    )
    await db.commit()
    await db.refresh(rule)
    reset_policy_cache()
    return rule


@router.patch("/policies/{policy_id}/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    policy_id: uuid.UUID, rule_id: uuid.UUID, body: RuleIn, db: DB, current_user: CurrentUser
) -> FirewallRule:
    _require_admin(current_user)
    rule = await db.get(FirewallRule, rule_id)
    if rule is None or rule.policy_id != policy_id:
        raise HTTPException(status_code=404, detail="Rule not found")
    for key, value in _rule_kwargs(body).items():
        setattr(rule, key, value)
    db.add(
        AuditLog(
            action="update",
            resource_type="firewall_rule",
            resource_id=str(policy_id),
            resource_display=f"rule {rule_id}",
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            changed_fields=["rule"],
        )
    )
    await db.commit()
    await db.refresh(rule)
    reset_policy_cache()
    return rule


@router.delete("/policies/{policy_id}/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    policy_id: uuid.UUID, rule_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> None:
    _require_admin(current_user)
    rule = await db.get(FirewallRule, rule_id)
    if rule is None or rule.policy_id != policy_id:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.add(
        AuditLog(
            action="delete",
            resource_type="firewall_rule",
            resource_id=str(policy_id),
            resource_display=f"rule {rule_id}",
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
        )
    )
    await db.execute(delete(FirewallRule).where(FirewallRule.id == rule_id))
    await db.commit()
    reset_policy_cache()


# ── Alias CRUD ──────────────────────────────────────────────────────


@router.get("/aliases", response_model=list[AliasResponse])
async def list_aliases(db: DB, current_user: CurrentUser) -> list[FirewallAlias]:
    _require_read(current_user)
    return list(
        (await db.execute(select(FirewallAlias).order_by(FirewallAlias.name))).scalars().all()
    )


@router.post("/aliases", response_model=AliasResponse, status_code=status.HTTP_201_CREATED)
async def create_alias(body: AliasCreate, db: DB, current_user: CurrentUser) -> FirewallAlias:
    _require_admin(current_user)
    a = FirewallAlias(**body.model_dump(), is_builtin=False)
    db.add(a)
    db.add(
        AuditLog(
            action="create",
            resource_type="firewall_alias",
            resource_id=str(a.id),
            resource_display=body.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            new_value={"name": body.name, "kind": body.kind},
        )
    )
    await db.commit()
    await db.refresh(a)
    reset_policy_cache()
    return a


@router.patch("/aliases/{alias_id}", response_model=AliasResponse)
async def update_alias(
    alias_id: uuid.UUID, body: AliasUpdate, db: DB, current_user: CurrentUser
) -> FirewallAlias:
    _require_admin(current_user)
    a = await db.get(FirewallAlias, alias_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alias not found")
    payload = body.model_dump(exclude_unset=True)
    # Re-validate CIDR family-split on member edits via AliasCreate's validator.
    if any(k in payload for k in ("v4_members", "v6_members", "port_members")):
        AliasCreate(
            name=a.name,
            kind=a.kind,
            port_members=payload.get("port_members", a.port_members),
            v4_members=payload.get("v4_members", a.v4_members),
            v6_members=payload.get("v6_members", a.v6_members),
        )
    for key, value in payload.items():
        setattr(a, key, value)
    db.add(
        AuditLog(
            action="update",
            resource_type="firewall_alias",
            resource_id=str(a.id),
            resource_display=a.name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            changed_fields=list(payload),
        )
    )
    await db.commit()
    await db.refresh(a)
    reset_policy_cache()
    return a


@router.delete("/aliases/{alias_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alias(alias_id: uuid.UUID, db: DB, current_user: CurrentUser) -> None:
    _require_admin(current_user)
    a = await db.get(FirewallAlias, alias_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alias not found")
    if a.is_builtin:
        raise HTTPException(status_code=400, detail="Built-in aliases cannot be deleted.")
    name = a.name
    db.add(
        AuditLog(
            action="delete",
            resource_type="firewall_alias",
            resource_id=str(a.id),
            resource_display=name,
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
        )
    )
    await db.execute(delete(FirewallAlias).where(FirewallAlias.id == alias_id))
    await db.commit()
    reset_policy_cache()


# ── Effective render + staged preview (read-only) ───────────────────
#
# Both re-derive the per-node render inputs the heartbeat uses (via
# supervisor.firewall_render_inputs) and run the SAME merge, so the body
# matches what the node would receive. effective works regardless of
# firewall_enabled (dark-state preview — the frontend shows an "enforcement
# OFF" banner off the returned flag). preview overlays staged operator rules
# and diffs. The supervisor import is lazy (load-order + keeps the heavy
# heartbeat module off this router's import path).

_SECTION_HEADERS: tuple[tuple[str, str], ...] = (
    ("# ── Management (always open)", "management"),
    ("# ── Per-role service ports", "role"),
    ("# ── Control-plane derived", "control_plane"),
    ("# ── Fleet / appliance overlay", "overlay"),
    ("# ── Operator override (firewall_extra)", "firewall_extra"),
)


def _layer_breakdown(body: str) -> dict[str, list[str]]:
    """Bucket the rendered rule lines (non-comment, non-blank) by section."""
    layers: dict[str, list[str]] = {
        "header": [],
        "management": [],
        "role": [],
        "control_plane": [],
        "overlay": [],
        "firewall_extra": [],
    }
    current = "header"
    for line in body.splitlines():
        hit = next((key for prefix, key in _SECTION_HEADERS if line.startswith(prefix)), None)
        if hit:
            current = hit
            continue
        if line.strip() and not line.startswith("#"):
            layers[current].append(line)
    return layers


def _rulein_to_rule(r: RuleIn) -> _Rule:
    return _Rule(
        seq=r.seq,
        action=r.action,
        protocol=r.protocol,
        ports=tuple(r.ports),
        source_kind=r.source_kind,
        source_cidrs=tuple(r.source_cidrs),
        source_alias=r.source_alias,
        family=r.family,
        comment=r.comment,
        render_guard=r.render_guard,
        enabled=r.enabled,
    )


def _apply_staged(
    ps: PolicySet,
    ap: _Policy | None,
    fleet_rules: list[RuleIn] | None,
    appliance_rules: list[RuleIn] | None,
) -> tuple[PolicySet, _Policy | None]:
    """Overlay staged operator rules onto a copy of the live policy set.
    A ``None`` list means "leave that layer as-is"; an empty list clears it.
    """
    staged = PolicySet(fleet=ps.fleet, roles=ps.roles, aliases=ps.aliases)
    if fleet_rules is not None:
        staged.fleet = _Policy("fleet", None, True, tuple(_rulein_to_rule(r) for r in fleet_rules))
    staged_ap = ap
    if appliance_rules is not None:
        staged_ap = _Policy(
            "appliance", None, True, tuple(_rulein_to_rule(r) for r in appliance_rules)
        )
    return staged, staged_ap


def _content_lines(body: str) -> list[str]:
    return [ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]


def _line_diff(current: str, staged: str) -> tuple[list[str], list[str]]:
    cur, stg = _content_lines(current), _content_lines(staged)
    cur_set, stg_set = set(cur), set(stg)
    return ([ln for ln in stg if ln not in cur_set], [ln for ln in cur if ln not in stg_set])


def _rule_nets(r: _Rule, ctx: MergeContext) -> tuple[bool, list[Any]]:
    """(matches_all, networks) — source_kind='any' matches everything;
    a derived kind that resolves empty on this node matches nothing here."""
    if r.source_kind == "any":
        return True, []
    v4, v6 = ctx.resolve_source(r)
    nets: list[Any] = []
    for c in list(v4) + list(v6):
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return False, nets


def _ports_overlap(a: list[int], b: list[int]) -> bool:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return True
    if not sa or not sb:
        return False
    return bool(sa & sb)


def _nets_overlap(a_all: bool, a: list[Any], b_all: bool, b: list[Any]) -> bool:
    if a_all or b_all:
        return True
    return any(x.version == y.version and x.overlaps(y) for x in a for y in b)


def _analyze_overlay(rules: list[RuleIn], ctx: MergeContext) -> list[dict[str, Any]]:
    """Advisory analysis of the staged operator overlay: accept↔drop conflicts
    on overlapping (proto, port, source) — deny-wins means the drop takes the
    overlap — and exact-duplicate redundancy. (Full CIDR-containment shadow
    analysis is a future refinement.)"""
    out: list[dict[str, Any]] = []
    parsed = [(r, _rule_nets(_rulein_to_rule(r), ctx)) for r in rules]
    for i in range(len(parsed)):
        ri, (ai_all, ai_nets) = parsed[i]
        for j in range(i + 1, len(parsed)):
            rj, (aj_all, aj_nets) = parsed[j]
            if ri.protocol != rj.protocol or not _ports_overlap(ri.ports, rj.ports):
                continue
            if not _nets_overlap(ai_all, ai_nets, aj_all, aj_nets):
                continue
            if ri.action != rj.action:
                out.append(
                    {
                        "kind": "conflict",
                        "detail": (
                            f"seq {ri.seq} ({ri.action}) and seq {rj.seq} ({rj.action}) overlap on "
                            f"{ri.protocol} {sorted(set(ri.ports) & set(rj.ports)) or ri.ports}; "
                            "deny-wins means the drop takes the overlap"
                        ),
                        "seqs": [ri.seq, rj.seq],
                    }
                )
            elif (ri.source_kind, sorted(ri.source_cidrs), ri.source_alias) == (
                rj.source_kind,
                sorted(rj.source_cidrs),
                rj.source_alias,
            ):
                out.append(
                    {
                        "kind": "redundant",
                        "detail": f"seq {rj.seq} duplicates seq {ri.seq} ({ri.protocol} {ri.ports})",
                        "seqs": [ri.seq, rj.seq],
                    }
                )
    return out


class EffectiveResponse(BaseModel):
    appliance_id: uuid.UUID
    hostname: str
    firewall_enabled: bool
    config_hash: str
    firewall_conf: str
    layers: dict[str, list[str]]
    rendered_hash: str | None
    applied_hash: str | None
    applied_status: str | None
    base_conf_marker: str | None
    drift: bool


class PreviewRequest(BaseModel):
    appliance_id: uuid.UUID
    fleet_rules: list[RuleIn] | None = None
    appliance_rules: list[RuleIn] | None = None


class PreviewWarning(BaseModel):
    kind: str
    detail: str
    seqs: list[int]


class PreviewResponse(BaseModel):
    appliance_id: uuid.UUID
    added: list[str]
    removed: list[str]
    warnings: list[PreviewWarning]
    upgrade_in_flight: bool
    staging_id: str


def _render_for(inputs: dict[str, Any], ps: PolicySet, ap: _Policy | None) -> str:
    return compile_firewall_from_policies(
        inputs["role_assignment"],
        inputs["cluster_peer_cidrs"],
        pod_cidrs=inputs["pod_cidrs"],
        service_cidrs=inputs["service_cidrs"],
        cp_member_count=inputs["cp_member_count"],
        vip_configured=inputs["vip_configured"],
        policy_set=ps,
        appliance_policy=ap,
        web_ui_allowed_cidrs=inputs.get("web_ui_allowed_cidrs") or [],
        ssh_scope_cidrs=inputs.get("ssh_scope_cidrs") or [],
    )


@router.get("/appliances/{appliance_id}/effective", response_model=EffectiveResponse)
async def effective(
    appliance_id: uuid.UUID, db: DB, current_user: CurrentUser
) -> EffectiveResponse:
    _require_read(current_user)
    row = await db.get(Appliance, appliance_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Appliance not found")
    from app.api.v1.appliance.supervisor import firewall_render_inputs

    inputs = await firewall_render_inputs(db, row)
    ps = await load_policy_set(db)
    ap = await load_appliance_policy(db, row.id)
    body = _render_for(inputs, ps, ap)
    state = await db.get(FirewallApplyState, row.id)
    return EffectiveResponse(
        appliance_id=row.id,
        hostname=row.hostname,
        firewall_enabled=bool(inputs["firewall_enabled"]),
        config_hash=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        firewall_conf=body,
        layers=_layer_breakdown(body),
        rendered_hash=getattr(state, "rendered_hash", None),
        applied_hash=getattr(state, "applied_hash", None),
        applied_status=getattr(state, "applied_status", None),
        base_conf_marker=getattr(state, "base_conf_marker", None),
        drift=bool(state and state.rendered_hash and state.rendered_hash != state.applied_hash),
    )


@router.post("/preview", response_model=PreviewResponse)
async def preview(body: PreviewRequest, db: DB, current_user: CurrentUser) -> PreviewResponse:
    _require_read(current_user)
    row = await db.get(Appliance, body.appliance_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Appliance not found")
    from app.api.v1.appliance.supervisor import firewall_render_inputs

    inputs = await firewall_render_inputs(db, row)
    ps = await load_policy_set(db)
    ap = await load_appliance_policy(db, row.id)
    ctx = MergeContext.build(
        inputs["role_assignment"],
        inputs["cluster_peer_cidrs"],
        pod_cidrs=inputs["pod_cidrs"],
        service_cidrs=inputs["service_cidrs"],
        cp_member_count=inputs["cp_member_count"],
        vip_configured=inputs["vip_configured"],
        aliases=ps.aliases,
    )
    current_body = _render_for(inputs, ps, ap)
    staged_ps, staged_ap = _apply_staged(ps, ap, body.fleet_rules, body.appliance_rules)
    staged_body = _render_for(inputs, staged_ps, staged_ap)
    added, removed = _line_diff(current_body, staged_body)
    overlay = list(body.fleet_rules or []) + list(body.appliance_rules or [])
    staging_input = json.dumps(
        {
            "a": str(body.appliance_id),
            "f": [r.model_dump(mode="json") for r in (body.fleet_rules or [])],
            "p": [r.model_dump(mode="json") for r in (body.appliance_rules or [])],
        },
        sort_keys=True,
    )
    return PreviewResponse(
        appliance_id=row.id,
        added=added,
        removed=removed,
        warnings=[PreviewWarning(**w) for w in _analyze_overlay(overlay, ctx)],
        upgrade_in_flight=await upgrade_in_flight(db),
        staging_id=hashlib.sha256(staging_input.encode("utf-8")).hexdigest()[:16],
    )


# ── Enforcement master switch + all-CP-hardened gate (#285 Phase 4a) ──
#
# The keystone that turns the whole (otherwise-dark) feature ON. Flipping
# `platform_settings.firewall_enabled` is what makes the server-side render
# authoritative on the fleet — but enabling it while a node still runs the
# legacy LAN-wide base /etc/nftables.conf would be a no-op on that node
# (its base accept still fires first) AND a false "hardened" compliance
# claim. So the gate refuses to ENABLE until every reporting appliance node
# is hardened (`base_lanwide_k3s == False`), unless the operator explicitly
# overrides. DISABLING is never gated (always safe to fall back to dark).
# `base_lanwide_k3s` is None for a node that hasn't reported a usable base
# marker (incl. the empty-FileOrCreate case) → counted as "unknown", which
# also blocks the un-overridden enable.


class EnforcementNode(BaseModel):
    appliance_id: uuid.UUID
    hostname: str
    hardened: bool
    base_lanwide_k3s: bool | None
    last_seen_at: str | None


class EnforcementStatus(BaseModel):
    enabled: bool
    # #404 — opt-in firewall logging master switch (independent of the
    # enforcement gate; logging is harmless so it has no hardened-node guard).
    logging_enabled: bool = False
    reported_count: int
    hardened_count: int
    lanwide_count: int
    all_hardened: bool
    safe_to_enable: bool
    nodes: list[EnforcementNode]


class SetEnforcementRequest(BaseModel):
    enabled: bool
    override_unhardened: bool = False


class SetFirewallLoggingRequest(BaseModel):
    enabled: bool


async def _enforcement_status(db: DB) -> EnforcementStatus:
    cfg = await db.get(PlatformSettings, 1)
    enabled = bool(cfg.firewall_enabled) if cfg else False
    logging_enabled = bool(cfg.firewall_logging_enabled) if cfg else False
    rows = list(
        (
            await db.execute(
                select(Appliance)
                .where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.deployment_kind == "appliance",
                    Appliance.base_conf_marker.isnot(None),
                )
                .order_by(Appliance.hostname)
            )
        )
        .scalars()
        .all()
    )
    nodes: list[EnforcementNode] = []
    hardened = lanwide = 0
    for r in rows:
        is_hardened = r.base_lanwide_k3s is False
        if is_hardened:
            hardened += 1
        elif r.base_lanwide_k3s is True:
            lanwide += 1
        nodes.append(
            EnforcementNode(
                appliance_id=r.id,
                hostname=r.hostname,
                hardened=is_hardened,
                base_lanwide_k3s=r.base_lanwide_k3s,
                last_seen_at=r.last_seen_at.isoformat() if r.last_seen_at else None,
            )
        )
    reported = len(nodes)
    all_hardened = reported > 0 and hardened == reported
    return EnforcementStatus(
        enabled=enabled,
        logging_enabled=logging_enabled,
        reported_count=reported,
        hardened_count=hardened,
        lanwide_count=lanwide,
        all_hardened=all_hardened,
        safe_to_enable=all_hardened,
        nodes=nodes,
    )


@router.get("/enforcement", response_model=EnforcementStatus)
async def get_enforcement(db: DB, current_user: CurrentUser) -> EnforcementStatus:
    _require_read(current_user)
    return await _enforcement_status(db)


@router.put("/enforcement", response_model=EnforcementStatus)
async def set_enforcement(
    body: SetEnforcementRequest, db: DB, current_user: CurrentUser
) -> EnforcementStatus:
    _require_admin(current_user)
    status = await _enforcement_status(db)
    if body.enabled and not status.all_hardened and not body.override_unhardened:
        blocked = status.reported_count - status.hardened_count
        detail = (
            f"Refusing to enable fleet-firewall enforcement: {blocked} of "
            f"{status.reported_count} reporting appliance node(s) are not yet hardened "
            f"({status.lanwide_count} still on the legacy LAN-wide base, "
            f"{blocked - status.lanwide_count} not reporting a base marker). Wait for the "
            "hardened slot image to roll out, or pass override_unhardened=true to enable anyway."
        )
        if status.reported_count == 0:
            detail = (
                "Refusing to enable: no appliance node has reported a base-conf marker yet, "
                "so the hardened state can't be confirmed. Pass override_unhardened=true to "
                "enable regardless."
            )
        raise HTTPException(status_code=409, detail=detail)

    cfg = await db.get(PlatformSettings, 1)
    if cfg is None:
        cfg = PlatformSettings(id=1)
        db.add(cfg)
        await db.flush()
    if cfg.firewall_enabled != body.enabled:
        cfg.firewall_enabled = body.enabled
        db.add(
            AuditLog(
                action="update",
                resource_type="platform_settings",
                resource_id="1",
                resource_display="firewall enforcement",
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                changed_fields=["firewall_enabled"],
                new_value={
                    "firewall_enabled": body.enabled,
                    "override_unhardened": body.override_unhardened,
                    "hardened_count": status.hardened_count,
                    "reported_count": status.reported_count,
                },
            )
        )
    await db.commit()
    # Wake every supervisor's heartbeat hold so the enforcement flip converges
    # at ~0 s instead of waiting out the parked long-poll (≤28 s). Firewall
    # state feeds firewall_render_inputs() in the heartbeat.
    await publish_wake(HOSTCONFIG_ALL)
    return await _enforcement_status(db)


@router.put("/logging", response_model=EnforcementStatus)
async def set_logging(
    body: SetFirewallLoggingRequest, db: DB, current_user: CurrentUser
) -> EnforcementStatus:
    """#404 — toggle opt-in firewall drop-logging. Independent of the
    enforcement master switch + hardened gate (logging is harmless): it just
    makes the rendered nft drop-in carry a rate-limited catch-all log rule, so
    the Firewall → Logs viewer has something to tail. Takes effect on the next
    supervisor heartbeat render (only matters while firewall_enabled is on)."""
    _require_admin(current_user)
    cfg = await db.get(PlatformSettings, 1)
    if cfg is None:
        cfg = PlatformSettings(id=1)
        db.add(cfg)
        await db.flush()
    if cfg.firewall_logging_enabled != body.enabled:
        cfg.firewall_logging_enabled = body.enabled
        db.add(
            AuditLog(
                action="update",
                resource_type="platform_settings",
                resource_id="1",
                resource_display="firewall logging",
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                changed_fields=["firewall_logging_enabled"],
                new_value={"firewall_logging_enabled": body.enabled},
            )
        )
    await db.commit()
    return await _enforcement_status(db)


# ── Posture presets (#285 Phase 4) ──────────────────────────────────
#
# A one-click fleet-baseline posture. A preset replaces the FLEET policy's
# rules (creating the fleet policy if absent); role + appliance scopes and the
# builtins are untouched. The knob is how reachable the common management /
# monitoring services are fleet-wide:
#   locked   — builtins + mgmt floor only (nothing extra).
#   balanced — SNMP (161/udp) + node-exporter (9100/tcp) from RFC1918 only.
#   open     — those same services from anywhere (flat trusted LAN).
# Operators tune the fleet policy freely afterwards; the preset is a starting
# point, not a lock.
_RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
_POSTURE_PRESETS: dict[str, list[dict[str, Any]]] = {
    "locked": [],
    "balanced": [
        {
            "seq": 10,
            "protocol": "udp",
            "ports": [161],
            "source_kind": "cidr",
            "source_cidrs": _RFC1918,
            "comment": "snmp (rfc1918)",
        },
        {
            "seq": 20,
            "protocol": "tcp",
            "ports": [9100],
            "source_kind": "cidr",
            "source_cidrs": _RFC1918,
            "comment": "node-exporter (rfc1918)",
        },
    ],
    "open": [
        {
            "seq": 10,
            "protocol": "udp",
            "ports": [161],
            "source_kind": "any",
            "comment": "snmp (any)",
        },
        {
            "seq": 20,
            "protocol": "tcp",
            "ports": [9100],
            "source_kind": "any",
            "comment": "node-exporter (any)",
        },
    ],
}


class ApplyPostureRequest(BaseModel):
    preset: str


@router.post("/posture", response_model=PolicyResponse)
async def apply_posture(
    body: ApplyPostureRequest, db: DB, current_user: CurrentUser
) -> FirewallPolicy:
    _require_admin(current_user)
    if body.preset not in _POSTURE_PRESETS:
        raise HTTPException(
            status_code=422,
            detail=f"preset must be one of {sorted(_POSTURE_PRESETS)}",
        )
    fleet = (
        (await db.execute(select(FirewallPolicy).where(FirewallPolicy.scope_kind == "fleet")))
        .scalars()
        .first()
    )
    if fleet is None:
        fleet = FirewallPolicy(
            name="Fleet baseline",
            scope_kind="fleet",
            enabled=True,
            is_builtin=False,
            updated_by_id=current_user.id,
        )
        db.add(fleet)
        await db.flush()
    await db.execute(delete(FirewallRule).where(FirewallRule.policy_id == fleet.id))
    for raw in _POSTURE_PRESETS[body.preset]:
        rule = RuleIn(**raw)  # validate (no-drop-22, cidr shape, …)
        db.add(FirewallRule(policy_id=fleet.id, **rule.model_dump()))
    fleet.updated_by_id = current_user.id
    db.add(
        AuditLog(
            action="update",
            resource_type="firewall_policy",
            resource_id=str(fleet.id),
            resource_display=f"fleet posture → {body.preset}",
            user_id=current_user.id,
            user_display_name=current_user.username,
            result="success",
            changed_fields=["rules"],
            new_value={"preset": body.preset, "rule_count": len(_POSTURE_PRESETS[body.preset])},
        )
    )
    await db.commit()
    reset_policy_cache()
    return await _get_policy(db, fleet.id)


# ── Web UI source restriction (#285 Phase 6) ────────────────────────
#
# Source-scope the appliance Web UI (frontend hostPort 80/443) without an
# external firewall. Empty list = open (the shipped default). The value
# rides ``platform_settings.web_ui_allowed_cidrs`` → ``firewall_render_inputs``
# → every renderer's Web-UI accept (see services/appliance/firewall.py), and
# also drives ``loadBalancerSourceRanges`` on the MetalLB VIP Service so BOTH
# the node-IP hostPort door and the VIP door are governed by one setting.
#
# ANTI-LOCKOUT, in two tiers (#285 Phase 6, then #1013).
#
# Tier 1 — this door. A non-empty set that doesn't cover the operator's
# CURRENT source IP would brick the very session making the change (the
# request is arriving through the frontend right now). Rejected 422 unless
# the operator explicitly passes override_lockout=true. Losing this door is
# survivable while another remains, which is what that override accepts.
#
# Tier 2 — every door. Since #1009 the port-22 floor is a retireable
# sentinel, so SSH is a recoverable path rather than a guaranteed one: an
# operator who has also turned on ``ssh_lockdown`` with a scope that excludes
# them is left with the console. Both guards used to be blind to each other,
# so both could be passed one at a time and neither would say so. They now
# share ``services/appliance/access`` and this path escalates to a distinct
# 422 with its own acknowledgement when the RESULTING state of both settings
# admits the caller nowhere.
#
# The caller's address comes from ``get_trusted_client_ip``, not ``client_ip``
# — see the two docstrings in ``core/request_meta``. This is a source-IP
# allowlist gate, and an X-Forwarded-For-derived value is also simply the
# WRONG address on a real topology: with a reverse proxy in front of the
# appliance, the XFF chain names the browser's own IP while nftables judges
# the packet source, which is the proxy. The guard would clear an operator who
# is about to be locked out. ``get_trusted_client_ip`` is nginx's
# ``$remote_addr`` via X-Real-IP from a trusted proxy peer (#1221), i.e. the
# address nftables sees.


class WebUIAccessResponse(BaseModel):
    allowed_cidrs: list[str]
    open: bool
    caller_ip: str | None
    caller_covered: bool


class SetWebUIAccessRequest(BaseModel):
    allowed_cidrs: list[str] = Field(default_factory=list)
    #: Accept losing THIS door: the resulting list does not cover you, but
    #: another remote path still does.
    override_lockout: bool = False
    #: Accept losing EVERY remote door: after this change neither restriction
    #: admits you and only the console does (#1013). Deliberately separate
    #: from ``override_lockout`` — that one is a smaller statement, and may
    #: have been ticked for an unrelated reason.
    acknowledge_console_only: bool = False

    @field_validator("allowed_cidrs")
    @classmethod
    def _v_cidrs(cls, v: list[str]) -> list[str]:
        # Validate + canonicalise (dedupe, stable order) so the persisted value
        # matches the renderers' _split_families canonicalisation and the
        # config_hash is stable under benign reordering.
        seen: set[str] = set()
        out: list[str] = []
        for c in v:
            s = (c or "").strip()
            if not s:
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"invalid CIDR {c!r}: {exc}") from exc
            canon = str(net)
            if canon not in seen:
                seen.add(canon)
                out.append(canon)
        return out


@router.get("/web-ui-access", response_model=WebUIAccessResponse)
async def get_web_ui_access(
    request: Request, db: DB, current_user: CurrentUser
) -> WebUIAccessResponse:
    _require_read(current_user)
    cfg = await db.get(PlatformSettings, 1)
    cidrs = list(cfg.web_ui_allowed_cidrs or []) if cfg else []
    ip = get_trusted_client_ip(request)
    return WebUIAccessResponse(
        allowed_cidrs=cidrs,
        open=not cidrs,
        caller_ip=ip,
        caller_covered=(not cidrs) or covers(ip, cidrs),
    )


@router.put("/web-ui-access", response_model=WebUIAccessResponse)
async def set_web_ui_access(
    body: SetWebUIAccessRequest, request: Request, db: DB, current_user: CurrentUser
) -> WebUIAccessResponse:
    _require_admin(current_user)
    ip = get_trusted_client_ip(request)
    cfg = await db.get(PlatformSettings, 1)
    # Tier 2 first: it is the strictly more serious finding, and its message
    # subsumes tier 1's. Checked against the state this request WOULD
    # produce, with the SSH half read from storage — this endpoint cannot
    # change it.
    #
    # Unlike the SSH side, this is NOT gated on a transition. There, the same
    # PUT carries unrelated edits (a key, a port) and re-warning about a state
    # the operator did not change is how a tick stops being read. Here the
    # request's entire payload IS the door, so there is no unrelated edit to
    # protect — and re-sending a list that already excludes you has always
    # re-raised tier 1 for the same reason.
    report = effective_doors(cfg, ip, web_ui_cidrs=body.allowed_cidrs)
    if report.console_only and not body.acknowledge_console_only:
        raise HTTPException(status_code=422, detail=console_only_detail(report))
    if (
        body.allowed_cidrs
        # ``report.console_only`` here means the acknowledgement above was
        # given: accepting "the console is my only way in" already contains
        # "this door closes on me", so demanding a second tick for the
        # smaller statement would be the reflex-training pattern. It cannot
        # widen anything — when the escalation did NOT fire, this term is
        # False and ``override_lockout`` stands on its own.
        and not (body.override_lockout or report.console_only)
        and not covers(ip, body.allowed_cidrs)
    ):
        # Reaching here proves the SSH door did not exclude this address:
        # the condition above IS "the Web UI door would not admit you", and
        # had SSH excluded you too, the escalation would already have raised.
        #
        # That is a fact about an ADDRESS, not a promise about a session —
        # see SSH_REACHABILITY_CAVEAT. State the list; do not assert that the
        # operator will be able to SSH, which needs an assumption about where
        # they SSH from that this request cannot support.
        ssh_desc = (
            f"SSH is allowed from {', '.join(report.ssh.allowed_cidrs)}, "
            f"{SSH_REACHABILITY_CAVEAT}"
            if report.ssh.restricted
            else "SSH is not source-restricted"
        )
        raise HTTPException(
            status_code=422,
            detail=(
                f"Refusing to restrict the Web UI: your current source IP ({ip or 'unknown'}) "
                "is not covered by the allow-list, so this would lock you out of the very "
                "session making the change. Add your IP / network to the list, or pass "
                f"override_lockout=true. {ssh_desc}, and the appliance console recovers "
                "this either way."
            ),
        )
    if cfg is None:
        cfg = PlatformSettings(id=1)
        db.add(cfg)
        await db.flush()
    old = list(cfg.web_ui_allowed_cidrs or [])
    if old != body.allowed_cidrs:
        cfg.web_ui_allowed_cidrs = body.allowed_cidrs
        db.add(
            AuditLog(
                action="update",
                resource_type="platform_settings",
                resource_id="1",
                resource_display="web UI source restriction",
                user_id=current_user.id,
                user_display_name=current_user.username,
                result="success",
                changed_fields=["web_ui_allowed_cidrs"],
                old_value={"web_ui_allowed_cidrs": old},
                new_value={
                    "web_ui_allowed_cidrs": body.allowed_cidrs,
                    "override_lockout": body.override_lockout,
                    "acknowledge_console_only": body.acknowledge_console_only,
                    "console_only_result": report.console_only,
                    "caller_ip": ip,
                },
            )
        )
    await db.commit()
    # Mgmt-UI CIDR lock is security-critical — wake the fleet so the new
    # allow-list lands immediately rather than at the next heartbeat tick.
    await publish_wake(HOSTCONFIG_ALL)
    cidrs = list(cfg.web_ui_allowed_cidrs or [])
    return WebUIAccessResponse(
        allowed_cidrs=cidrs,
        open=not cidrs,
        caller_ip=ip,
        caller_covered=(not cidrs) or covers(ip, cidrs),
    )

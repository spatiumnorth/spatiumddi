"""Operator Copilot tools for the fleet firewall (#285 Phase 3e).

Read tools (default-enabled — discovery):

* ``find_firewall_policies`` — list policies (fleet / role / appliance) with a
  compact rule summary, filterable by scope.
* ``count_firewall_policies`` — scope + enabled roll-up.
* ``find_firewall_aliases`` — named CIDR / port sets.
* ``find_firewall_effective`` — server-render any node's MERGED drop-in (the
  same merge the heartbeat ships), with the layer breakdown + drift + the
  enforcement-on flag. Answers "what does node X's firewall actually look
  like?" without the operator opening the Fleet → Firewall tab.

Write proposal (default-DISABLED — a firewall change can sever a node's
reachability, so it's opt-in per non-negotiable #13's broad-blast-radius
rule):

* ``propose_toggle_firewall_policy`` — enable / disable a policy via the
  preview→apply proposal flow.

All superadmin-gated (firewall is appliance-fleet administration), mirroring
the ``appliance.fleet`` tool cluster. Tagged ``module="appliance.firewall"``
so they vanish with the feature module.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.models.firewall import FirewallAlias, FirewallPolicy
from app.services.ai import operations
from app.services.ai.tools.base import register_tool
from app.services.ai.tools.proposals import _persist_proposal, _proposal_result

_MODULE = "appliance.firewall"


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Fleet firewall management is restricted to superadmin users. "
                "Ask your platform admin to run the query."
            )
        }
    return None


def _rule_summary(p: FirewallPolicy) -> list[str]:
    out: list[str] = []
    for r in sorted(p.rules, key=lambda r: r.seq):
        if not r.enabled:
            continue
        ports = ",".join(str(x) for x in (r.ports or [])) or "-"
        src = (
            "any"
            if r.source_kind == "any"
            else (
                r.source_alias
                if r.source_kind == "alias"
                else (",".join(r.source_cidrs) if r.source_kind == "cidr" else r.source_kind)
            )
        )
        out.append(f"{r.seq}: {r.action} {r.protocol} {ports} from {src}")
    return out


# ── find_firewall_policies ─────────────────────────────────────────


class FindFirewallPoliciesArgs(BaseModel):
    scope_kind: Literal["fleet", "role", "appliance"] | None = Field(
        default=None, description="Filter by scope kind. Omit for all."
    )
    scope_role: str | None = Field(
        default=None,
        description="Filter to one role token (dns-bind9 / dhcp / control-plane / …).",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_firewall_policies",
    description=(
        "List fleet-firewall policies (superadmin only, #285). Each row carries "
        "name / scope (fleet|role|appliance) / role / enabled / is_builtin / "
        "priority + a compact enabled-rule summary (seq: action proto ports from "
        "source). Filter by scope_kind or scope_role. Use to answer 'what does "
        "the dhcp role open?', 'is the control-plane policy enabled?', or 'which "
        "policies has someone customised?'. Read-only — toggles go through "
        "propose_toggle_firewall_policy; rule edits through the Fleet → Firewall "
        "tab."
    ),
    args_model=FindFirewallPoliciesArgs,
    category="admin",
    default_enabled=True,
    module=_MODULE,
)
async def find_firewall_policies(
    db: AsyncSession, user: User, args: FindFirewallPoliciesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    stmt = (
        select(FirewallPolicy)
        .options(selectinload(FirewallPolicy.rules))
        .order_by(FirewallPolicy.scope_kind, FirewallPolicy.scope_role, FirewallPolicy.name)
    )
    if args.scope_kind:
        stmt = stmt.where(FirewallPolicy.scope_kind == args.scope_kind)
    if args.scope_role:
        stmt = stmt.where(FirewallPolicy.scope_role == args.scope_role)
    rows = list((await db.execute(stmt.limit(args.limit))).scalars().all())
    return {
        "policies": [
            {
                "id": str(p.id),
                "name": p.name,
                "scope_kind": p.scope_kind,
                "scope_role": p.scope_role,
                "scope_appliance_id": (str(p.scope_appliance_id) if p.scope_appliance_id else None),
                "enabled": p.enabled,
                "is_builtin": p.is_builtin,
                "priority": p.priority,
                "rules": _rule_summary(p),
            }
            for p in rows
        ],
        "count": len(rows),
    }


# ── count_firewall_policies ────────────────────────────────────────


class CountFirewallPoliciesArgs(BaseModel):
    pass


@register_tool(
    name="count_firewall_policies",
    description=(
        "Roll up fleet-firewall policy counts (superadmin only, #285): total, "
        "per scope_kind, and enabled vs disabled. Use for 'how many firewall "
        "policies are there?' or 'are any disabled?'."
    ),
    args_model=CountFirewallPoliciesArgs,
    category="admin",
    default_enabled=True,
    module=_MODULE,
)
async def count_firewall_policies(
    db: AsyncSession, user: User, args: CountFirewallPoliciesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    scope_rows = (
        await db.execute(
            select(FirewallPolicy.scope_kind, func.count()).group_by(FirewallPolicy.scope_kind)
        )
    ).all()
    by_scope: dict[str, int] = {row[0]: int(row[1]) for row in scope_rows}
    enabled = (
        await db.execute(select(func.count()).where(FirewallPolicy.enabled.is_(True)))
    ).scalar_one()
    total = (await db.execute(select(func.count()).select_from(FirewallPolicy))).scalar_one()
    return {
        "total": total,
        "by_scope_kind": by_scope,
        "enabled": enabled,
        "disabled": total - enabled,
    }


# ── find_firewall_aliases ──────────────────────────────────────────


class FindFirewallAliasesArgs(BaseModel):
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_firewall_aliases",
    description=(
        "List firewall aliases (superadmin only, #285) — named, reusable CIDR "
        "or port sets referenced by rules. Each row carries name / kind / "
        "members (family-split v4 + v6 for cidr aliases). Read-only."
    ),
    args_model=FindFirewallAliasesArgs,
    category="admin",
    default_enabled=True,
    module=_MODULE,
)
async def find_firewall_aliases(
    db: AsyncSession, user: User, args: FindFirewallAliasesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    rows = list(
        (await db.execute(select(FirewallAlias).order_by(FirewallAlias.name).limit(args.limit)))
        .scalars()
        .all()
    )
    return {
        "aliases": [
            {
                "id": str(a.id),
                "name": a.name,
                "kind": a.kind,
                "port_members": list(a.port_members or []),
                "v4_members": list(a.v4_members or []),
                "v6_members": list(a.v6_members or []),
                "is_builtin": a.is_builtin,
            }
            for a in rows
        ],
        "count": len(rows),
    }


# ── find_firewall_effective ────────────────────────────────────────


class FindFirewallEffectiveArgs(BaseModel):
    appliance_id: str = Field(
        description="UUID of the appliance to render. Use find_appliance_fleet to discover it."
    )


@register_tool(
    name="find_firewall_effective",
    description=(
        "Server-render a node's EFFECTIVE merged firewall drop-in (superadmin "
        "only, #285) — the exact body the supervisor heartbeat would ship, "
        "compiled from the fleet + role + appliance policies the same way. "
        "Returns the rendered nftables body, a per-layer breakdown (management "
        "floor / role ports / control-plane derived / overlay / firewall_extra), "
        "the rendered/applied drift flag, and whether enforcement is actually on "
        "(firewall_enabled). Works even when enforcement is off — it's the dark "
        "preview. Use for 'what does node X's firewall look like?' or 'why is "
        "port 53 open on that DNS box?'."
    ),
    args_model=FindFirewallEffectiveArgs,
    category="admin",
    default_enabled=True,
    module=_MODULE,
)
async def find_firewall_effective(
    db: AsyncSession, user: User, args: FindFirewallEffectiveArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    from app.api.v1.appliance.supervisor import firewall_render_inputs  # noqa: PLC0415
    from app.models.appliance import Appliance  # noqa: PLC0415
    from app.models.firewall import FirewallApplyState  # noqa: PLC0415
    from app.services.appliance.firewall_merge import (  # noqa: PLC0415
        compile_firewall_from_policies,
        load_appliance_policy,
        load_policy_set,
    )

    try:
        aid = uuid.UUID(args.appliance_id)
    except ValueError:
        return {"error": f"appliance_id must be a UUID, got {args.appliance_id!r}"}
    row = await db.get(Appliance, aid)
    if row is None:
        return {"error": f"No appliance with id {args.appliance_id}."}

    inputs = await firewall_render_inputs(db, row)
    ps = await load_policy_set(db)
    ap = await load_appliance_policy(db, row.id)
    body = compile_firewall_from_policies(
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
    state = await db.get(FirewallApplyState, row.id)
    return {
        "appliance_id": str(row.id),
        "hostname": row.hostname,
        "firewall_enabled": bool(inputs["firewall_enabled"]),
        "firewall_conf": body,
        "rendered_hash": getattr(state, "rendered_hash", None),
        "applied_hash": getattr(state, "applied_hash", None),
        "applied_status": getattr(state, "applied_status", None),
        "drift": bool(state and state.rendered_hash and state.rendered_hash != state.applied_hash),
    }


# ── find_web_ui_access (#285 Phase 6) ─────────────────────────────


class FindWebUIAccessArgs(BaseModel):
    pass


@register_tool(
    name="find_web_ui_access",
    description=(
        "Report the appliance Web UI source restriction (superadmin "
        "only). Returns the allow-list of source CIDRs (empty = open to all) that "
        "governs both the per-node HTTP/HTTPS door (nftables :80/:443) and the "
        "MetalLB control-plane VIP (loadBalancerSourceRanges). Use for 'who can "
        "reach the web UI?' or 'is the dashboard locked down?'. No secrets — just "
        "the CIDR list and whether it's open."
    ),
    args_model=FindWebUIAccessArgs,
    category="admin",
    default_enabled=True,
    module=_MODULE,
)
async def find_web_ui_access(
    db: AsyncSession, user: User, args: FindWebUIAccessArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    from app.models.settings import PlatformSettings  # noqa: PLC0415

    cfg = await db.get(PlatformSettings, 1)
    cidrs = list(cfg.web_ui_allowed_cidrs or []) if cfg else []
    return {
        "open": not cidrs,
        "allowed_cidrs": cidrs,
        "summary": (
            "Web UI is open to all source IPs."
            if not cidrs
            else f"Web UI is restricted to {len(cidrs)} source range(s): {', '.join(cidrs)}."
        ),
    }


# ── propose_toggle_firewall_policy (default-DISABLED) ──────────────


class ProposeToggleFirewallPolicyArgs(BaseModel):
    policy_id: str = Field(
        description="UUID of the firewall policy. Use find_firewall_policies to discover it."
    )
    enabled: bool = Field(description="Desired enabled state (true = on, false = off).")


@register_tool(
    name="propose_toggle_firewall_policy",
    description=(
        "Propose enabling or disabling a fleet-firewall policy (superadmin only, "
        "#285). Disabled by default — a firewall change can sever a node's "
        "reachability, so the operator opts this tool in. The model proposes the "
        "toggle; the operator clicks Apply for it to take effect on the next "
        "supervisor heartbeat (only if the firewall_enabled master switch is on). "
        "Rule edits + new policies go through the Fleet → Firewall tab, not the "
        "Copilot."
    ),
    args_model=ProposeToggleFirewallPolicyArgs,
    category="admin",
    default_enabled=False,
    module=_MODULE,
)
async def propose_toggle_firewall_policy(
    db: AsyncSession, user: User, args: ProposeToggleFirewallPolicyArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    op = operations.get_operation("toggle_firewall_policy")
    if op is None:
        return {"error": "Operation 'toggle_firewall_policy' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "toggle_firewall_policy",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="toggle_firewall_policy",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


__all__ = [
    "count_firewall_policies",
    "find_firewall_aliases",
    "find_firewall_effective",
    "find_firewall_policies",
    "propose_toggle_firewall_policy",
]

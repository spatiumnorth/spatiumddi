"""Operator Copilot tools for multi-node rolling upgrades (#296 Phases A + D).

Two read-only tools today:

* ``find_upgrade_preflight`` (Phase A) — runs preflight against a
  target version; same aggregator the Fleet UI's preflight panel uses.
* ``find_upgrade_runs`` (Phase D) — lists recent SystemUpgradeRun rows
  so the chat drawer can answer "what's the upgrade history?" /
  "what's the current upgrade doing?".

Phase G will likely add ``propose_start_upgrade`` (apply-gated write)
when the Fleet UI lands; today the chat-driven path is read-only —
operators start upgrades through the REST endpoint.

Superadmin-gated like every other appliance/fleet tool — operator
access only.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.services.ai.tools.base import register_tool
from app.services.upgrades import mutex, orchestrator, preflight


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {"error": ("Rolling-upgrade preflight is restricted to superadmin users.")}
    return None


class FindUpgradePreflightArgs(BaseModel):
    target_version: str = Field(
        description=(
            "Release tag to evaluate the upgrade path against: CalVer "
            "(``2026.06.01-1``) before 1.0.0, SemVer (``1.0.0``) from it. "
            "Must be a 1-64 char string."
        ),
        min_length=1,
        max_length=64,
    )


@register_tool(
    name="find_upgrade_preflight",
    description=(
        "Run pre-flight safety checks for a multi-node rolling upgrade to "
        "the given target version (superadmin only, read-only). Returns "
        "the same structured report the Fleet UI's preflight panel shows: "
        "quorum (cluster size + Ready state), CNPG replication lag, "
        "``/var`` disk headroom, version-path validity (the target must be "
        "a release newer than the running one, CalVer or SemVer, with a "
        "warning when two CalVer tags are more than 90 days apart), and whether another upgrade "
        "is already in flight (Lease holder). Use to answer 'is the "
        "cluster ready for an upgrade to <tag>?', 'which check is "
        "blocking the next upgrade?', or 'what's the replication lag "
        "right now?'. Does not start an upgrade — that requires the "
        "REST start endpoint (Phase D)."
    ),
    args_model=FindUpgradePreflightArgs,
    category="admin",
    default_enabled=True,
    # The upgrade surface doesn't have a feature module — it's
    # cluster-shape infrastructure, always on for multi-node deploys.
    module=None,
)
async def find_upgrade_preflight(
    db: AsyncSession,  # noqa: ARG001 — registered tools share signature
    user: User,
    args: FindUpgradePreflightArgs,
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    report = await preflight.run_all(target_version=args.target_version)
    return report.to_dict()


# ── find_upgrade_runs (Phase D) ──────────────────────────────────────


class FindUpgradeRunsArgs(BaseModel):
    limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Most-recent-first limit on the returned rows.",
    )
    state: str | None = Field(
        default=None,
        description=(
            "Optional filter on lifecycle state: planned / running / "
            "succeeded / failed / halted / aborted. Omit for all states."
        ),
    )


@register_tool(
    name="find_upgrade_runs",
    description=(
        "List recent SystemUpgradeRun rows from the multi-node rolling-"
        "upgrade orchestrator (superadmin only, read-only). Each row "
        "carries target_version + state (planned|running|succeeded|"
        "failed|halted|aborted) + node_order from the plan + per-node "
        "progress (which nodes succeeded, which failed at what step). "
        "Use to answer 'is an upgrade running right now?', 'why did "
        "yesterday's upgrade fail?', 'which node bombed?', or 'when "
        "was the last successful rolling upgrade?'."
    ),
    args_model=FindUpgradeRunsArgs,
    category="admin",
    default_enabled=True,
    module=None,
)
async def find_upgrade_runs(
    db: AsyncSession,
    user: User,
    args: FindUpgradeRunsArgs,
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    rows = await orchestrator.list_recent_runs(db, limit=args.limit)
    if args.state:
        rows = [r for r in rows if r.state == args.state]
    return {
        "runs": [
            {
                "id": str(r.id),
                "kind": r.kind,
                "state": r.state,
                "target_version": r.target_version,
                "lease_holder": r.lease_holder,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "last_error": r.last_error,
                "node_order": (r.plan or {}).get("node_order") or [],
                "per_node_summary": {
                    node: {
                        "ok": entry.get("ok"),
                        "failed_at": entry.get("failed_at"),
                        "error": entry.get("error"),
                    }
                    for node, entry in ((r.progress or {}).get("per_node") or {}).items()
                },
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ── find_upgrade_lease (Phase A + Phase H review) ────────────────────


class FindUpgradeLeaseArgs(BaseModel):
    """No args — the lease is a singleton per cluster."""


@register_tool(
    name="find_upgrade_lease",
    description=(
        "Read the cluster-wide rolling-upgrade single-upgrader Lease "
        "state (superadmin only, read-only). Mirrors the "
        "``GET /api/v1/upgrades/lease`` REST endpoint. Returns "
        "``held`` (whether a holder is currently claiming it), "
        "``holder`` (the api-pod hostname if held), ``renew_time`` "
        "(last RFC3339 renewal stamp), ``transitions`` (k8s "
        "leader-election change counter), and ``expired`` (true when "
        "renewTime + leaseDurationSeconds is in the past — the "
        "previous holder crashed before releasing). Use to answer "
        "'is the upgrade orchestrator running right now?' / 'which "
        "api pod is driving the current upgrade?' / 'is the lease "
        "stuck after a crash?' without needing the full "
        "``find_upgrade_runs`` history. Closes the MCP coverage gap "
        "for /upgrades/lease that the Phase H code review surfaced."
    ),
    args_model=FindUpgradeLeaseArgs,
    category="admin",
    default_enabled=True,
    module=None,
)
async def find_upgrade_lease(
    db: AsyncSession,  # noqa: ARG001 — registered tools share signature
    user: User,
    args: FindUpgradeLeaseArgs,  # noqa: ARG001 — no args
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    state = mutex.get_state()
    return {
        "held": state.held,
        "holder": state.holder,
        "renew_time": state.renew_time,
        "transitions": state.transitions,
        "expired": state.expired,
    }

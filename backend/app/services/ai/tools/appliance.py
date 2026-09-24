"""Operator Copilot tools for the appliance fleet (#170 Wave D2).

Four tools land here:

* ``find_pending_appliances`` — read-only list of supervisors
  sitting in pending_approval, so a superadmin can ask the Copilot
  "any pairings waiting for approval?" without clicking into the
  Fleet tab.
* ``find_appliance_fleet`` — read-only roll-up of every
  appliance row (pending + approved + rejected), with capability
  flags, role assignment, deployment kind, slot info, last-seen.
  Filterable by state / role / tag.
* ``propose_approve_appliance`` — apply-gated write proposal. The
  model proposes "approve appliance X"; the operator clicks Apply
  to actually sign the cert. Cert issuance is irreversible (the
  CA logs the serial; revoking later means a re-key), so the
  proposal contract here is load-bearing.
* ``propose_assign_role`` — apply-gated write proposal for role +
  group + tag assignment.

All four are superadmin-gated (the same gate the underlying REST
endpoints + the existing ``find_pairing_codes`` tool use). A
non-superadmin user's chat session sees a structured "ask your
platform admin" error.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance.supervisor import mtu_fields
from app.core.permissions import is_effective_superadmin
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    APPLIANCE_STATE_PENDING_APPROVAL,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
    ApplianceUpgradeImage,
)
from app.models.auth import User
from app.services.ai import operations
from app.services.ai.tools.base import register_tool
from app.services.ai.tools.proposals import _persist_proposal, _proposal_result
from app.services.appliance.network_mtu import (
    fleet_summary as mtu_fleet_summary,
)


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Appliance fleet management is restricted to superadmin "
                "users. Ask your platform admin to run the query."
            )
        }
    return None


def _row_to_dict(row: Appliance) -> dict[str, Any]:
    """Compact JSON shape used by both ``find_pending_appliances``
    and ``find_appliance_fleet``. Cert bytes + pubkey blob are
    intentionally omitted — they're large and not Copilot-useful."""
    return {
        "id": str(row.id),
        "hostname": row.hostname,
        "state": row.state,
        "fingerprint_short": (
            row.public_key_fingerprint[:8] + "…" + row.public_key_fingerprint[-6:]
            if row.public_key_fingerprint
            else None
        ),
        "supervisor_version": row.supervisor_version,
        "capabilities": row.capabilities or {},
        "assigned_roles": list(row.assigned_roles or []),
        "assigned_dns_group_id": (
            str(row.assigned_dns_group_id) if row.assigned_dns_group_id else None
        ),
        "assigned_dhcp_group_id": (
            str(row.assigned_dhcp_group_id) if row.assigned_dhcp_group_id else None
        ),
        "tags": dict(row.tags or {}),
        "deployment_kind": row.deployment_kind,
        "installed_appliance_version": row.installed_appliance_version,
        "current_slot": row.current_slot,
        "durable_default": row.durable_default,
        "is_trial_boot": row.is_trial_boot,
        "last_upgrade_state": row.last_upgrade_state,
        "desired_appliance_version": row.desired_appliance_version,
        "reboot_requested": row.reboot_requested,
        "paired_at": row.paired_at.isoformat(),
        "approved_at": (row.approved_at.isoformat() if row.approved_at else None),
        "last_seen_at": (row.last_seen_at.isoformat() if row.last_seen_at else None),
        # #1017 — the interface MTU etc-render actually APPLIED, not what
        # STATE asked for. Through the same helper the REST row uses, so
        # the two surfaces cannot disagree about how to read the field,
        # and so the copilot gets ``mtu_reported`` (UNKNOWN vs "no MTU
        # set"), ``mtu_requested`` and the refusal reason rather than the
        # bare value.
        **mtu_fields(row.cluster_health),
        "last_seen_ip": row.last_seen_ip,
        "cert_serial": row.cert_serial,
        "cert_expires_at": (row.cert_expires_at.isoformat() if row.cert_expires_at else None),
        # #272 control-plane cluster membership (Phase 7+).
        "cluster_role": row.cluster_role,
        "desired_cluster_role": row.desired_cluster_role,
        "cluster_join_state": row.cluster_join_state,
        "node_ip": row.node_ip,
    }


# ── find_pending_appliances ────────────────────────────────────────


class FindPendingAppliancesArgs(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_pending_appliances",
    description=(
        "List Application appliances sitting in pending_approval state "
        "(superadmin only). Each row carries the supervisor's hostname, "
        "fingerprint, advertised capabilities (can_run_dns_bind9 / "
        "can_run_dhcp / has_baked_images / cpu_count / memory_mb), and "
        "the paired-from IP + timestamp. Use to answer 'any pairings "
        "waiting for approval?', 'has dns-east-2 paired yet?', or "
        "'how many appliances are stuck in pending?'. Returns the most "
        "recent ``limit`` pending rows."
    ),
    args_model=FindPendingAppliancesArgs,
    category="admin",
    default_enabled=True,
)
async def find_pending_appliances(
    db: AsyncSession, user: User, args: FindPendingAppliancesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    stmt = (
        select(Appliance)
        .where(Appliance.state == APPLIANCE_STATE_PENDING_APPROVAL)
        .order_by(Appliance.paired_at.desc())
        .limit(args.limit)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return {
        "appliances": [_row_to_dict(r) for r in rows],
        "count": len(rows),
    }


# ── find_appliance_fleet ───────────────────────────────────────────


class FindApplianceFleetArgs(BaseModel):
    state: Literal["pending_approval", "approved", "rejected"] | None = Field(
        default=None,
        description="Filter by appliance state. Omit for all states.",
    )
    role: (
        Literal["dns-bind9", "dns-powerdns", "dns-technitium", "dhcp", "observer", "custom"] | None
    ) = Field(
        default=None,
        description=(
            "Filter by an assigned role. Returns rows whose "
            "``assigned_roles`` includes this value."
        ),
    )
    tag_key: str | None = Field(
        default=None,
        description=(
            "Filter by a tag key. Pair with ``tag_value`` to require "
            "an exact match; supply only ``tag_key`` to require "
            "presence of the key with any value."
        ),
    )
    tag_value: str | None = Field(
        default=None,
        description="Required value for ``tag_key`` (exact match).",
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_appliance_fleet",
    description=(
        "Roll up the SpatiumDDI appliance fleet (superadmin only). "
        "Returns every appliance row — pending + approved + rejected — "
        "with the supervisor's capabilities, assigned roles, group "
        "FKs, deployment kind, installed appliance version, slot info, "
        "last-seen timestamps, and each node's applied interface MTU. "
        "Filterable by state, by an assigned role, or by a tag "
        "key/value. Use to answer questions like 'which boxes can run "
        "DHCP?', 'which appliances tagged site=prod-east are running "
        "BIND9?', 'what version is the fleet on?', or 'are my nodes all "
        "on the same MTU?'. The top-level ``mtu_fleet`` block answers "
        "that last one for the CLUSTER — k3s runs flannel host-gw, so a "
        "mixed-MTU cluster black-holes pod-to-pod traffic — and is "
        "always computed over every control-plane cluster member, never "
        "over the filtered page. Per row, ``mtu_reported: false`` means "
        "the supervisor is too old to report: that is UNKNOWN and must "
        "NOT be described as 'no MTU is set'. ``mtu_applied`` says which "
        "of applied / default / dropped / n-a, and ``dropped`` means the "
        "operator configured a value the appliance REFUSED, with the "
        "reason in ``mtu_findings``. The result is read-only — write "
        "actions go through ``propose_approve_appliance`` / "
        "``propose_assign_role``."
    ),
    args_model=FindApplianceFleetArgs,
    category="admin",
    default_enabled=True,
)
async def find_appliance_fleet(
    db: AsyncSession, user: User, args: FindApplianceFleetArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err

    stmt = select(Appliance).order_by(Appliance.paired_at.desc())
    if args.state is not None:
        stmt = stmt.where(Appliance.state == args.state)
    rows = list((await db.execute(stmt)).scalars().all())
    # Role + tag filters are JSONB — easier to filter in Python than
    # to fold them into the SQL with @> operators (the role filter
    # would need a JSONB containment expression that's awkward to
    # express in SQLAlchemy core).
    if args.role is not None:
        rows = [r for r in rows if args.role in (r.assigned_roles or [])]
    if args.tag_key is not None:
        if args.tag_value is not None:
            rows = [r for r in rows if (r.tags or {}).get(args.tag_key) == args.tag_value]
        else:
            rows = [r for r in rows if args.tag_key in (r.tags or {})]

    # #1017 — the fleet MTU verdict, computed over every cluster MEMBER
    # rather than over the filtered + truncated page. A consistency
    # answer that changed with the caller's ``role`` filter or ``limit``
    # would be worse than none: the whole claim is about the cluster, and
    # "consistent" derived from three of nine nodes is a green light
    # nobody should act on.
    #
    # Its own NARROW query — two columns, filtered in SQL — rather than a
    # second ``select(Appliance)``. That model has ~90 columns including
    # 15 JSONB, an encrypted kubeconfig and an upgrade-log tail, none
    # deferred, so re-hydrating the fleet to read two fields shipped
    # ~100 KB a second time and threw the decode away. Membership is
    # cluster ROLE, not approval: an approved-but-unpromoted Additional
    # node runs its own single-node k3s and shares no flannel network.
    mtu = mtu_fleet_summary(
        [
            (hostname or "", cluster_health)
            for hostname, cluster_health in (
                await db.execute(
                    select(Appliance.hostname, Appliance.cluster_health).where(
                        Appliance.state == APPLIANCE_STATE_APPROVED,
                        Appliance.revoked_at.is_(None),
                        Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                    )
                )
            ).all()
        ]
    )

    rows = rows[: args.limit]
    return {
        "appliances": [_row_to_dict(r) for r in rows],
        "count": len(rows),
        "mtu_fleet": asdict(mtu),
    }


# ── find_appliance_storage ─────────────────────────────────────────


class FindApplianceStorageArgs(BaseModel):
    degraded_only: bool = Field(
        default=True,
        description=(
            "Return only appliances with a storage finding (degraded / "
            "failed array, or a multipath map short of paths). Set false "
            "to list every appliance's storage, including healthy ones "
            "and ones with no arrays at all."
        ),
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_appliance_storage",
    description=(
        "Report software-RAID (md) and multipath storage redundancy "
        "across the appliance fleet (superadmin only, #999). Each row "
        "carries the arrays and multipath maps the node's supervisor "
        "read out of the host's sysfs, plus classified findings with a "
        "severity that keys off REDUNDANCY REMAINING — '2 of 3 members' "
        "in a three-way mirror and '1 of 2' in a pair both report "
        "'degraded', and only the second has nothing left to lose. Use "
        "to answer 'is anything degraded across the fleet?', 'is the "
        "rebuild on ddi1 finished?', or 'which boxes are actually "
        "mirrored?'. IMPORTANT: with the default degraded_only=true, an "
        "appliance missing from `appliances` is NOT necessarily healthy "
        "— it may simply never have reported storage. Every result "
        "therefore carries `not_reporting` (hostnames whose supervisor "
        "has not reported storage at all, whatever the filter) and "
        "`not_reporting_count`; say so rather than reading absence as "
        "health. Pass degraded_only=false to list every appliance, "
        "including healthy ones and ones with no arrays. A quiet "
        "multipath map is also not proof of health: per-path state needs "
        "multipathd, which the appliance image does not ship. Read-only."
    ),
    args_model=FindApplianceStorageArgs,
    category="admin",
    default_enabled=True,
)
async def find_appliance_storage(
    db: AsyncSession, user: User, args: FindApplianceStorageArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err

    from app.services.appliance.storage_health import (  # noqa: PLC0415
        evaluate_storage,
        worst_severity,
    )

    stmt = select(Appliance).where(Appliance.revoked_at.is_(None)).order_by(Appliance.hostname)
    rows = list((await db.execute(stmt)).scalars().all())

    out: list[dict[str, Any]] = []
    # Tracked regardless of ``degraded_only``: an appliance filtered out
    # of the list because it has no findings, and one filtered out
    # because nobody ever looked, are the same absence to a reader —
    # and the second one is the case where a degraded array hides.
    not_reporting: list[str] = []
    for row in rows:
        ch = row.cluster_health if isinstance(row.cluster_health, dict) else {}
        raw = ch.get("storage")
        reported = isinstance(raw, dict)
        if not reported:
            not_reporting.append(row.hostname)
        storage: dict[str, Any] = raw if reported else {}
        findings = evaluate_storage(storage if reported else None)
        if args.degraded_only and not findings:
            continue
        out.append(
            {
                "appliance_id": str(row.id),
                "hostname": row.hostname,
                "state": row.state,
                # False means the supervisor never looked (too old to
                # collect it) — distinct from "looked and found nothing".
                "reported": reported,
                # None, not False: an unreported node has no md verdict
                # either way, and False would read as "md is unavailable".
                "md_supported": storage.get("md_supported") if reported else None,
                "md_arrays": storage.get("md_arrays") or [],
                "multipath_maps": storage.get("multipath_maps") or [],
                "worst_severity": worst_severity(findings),
                "findings": [
                    {
                        "severity": f.severity,
                        "kind": f.kind,
                        "name": f.name,
                        "detail": f.detail,
                    }
                    for f in findings
                ],
            }
        )
    out = out[: args.limit]
    return {
        "appliances": out,
        "count": len(out),
        # UNKNOWN, never a clean bill of health — see the tool
        # description. Reported even when ``degraded_only`` filtered
        # these rows out of ``appliances``.
        "not_reporting": not_reporting,
        "not_reporting_count": len(not_reporting),
    }


# ── find_appliance_removable ───────────────────────────────────────


class FindApplianceRemovableArgs(BaseModel):
    configured_only: bool = Field(
        default=False,
        description=(
            "Return only appliances with at least one removable mount "
            "configured. False (the default) also lists nodes that can "
            "see a USB disk nobody has mounted yet."
        ),
    )
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_appliance_removable",
    description=(
        "Report removable (USB) backup disks across the appliance fleet "
        "(superadmin only, #989). Each configured mount carries a state: "
        "'mounted' (the disk is there and live), 'waiting' (configured "
        "and armed, disk not plugged in) or 'unreported' (the node has "
        "not said). IMPORTANT: 'waiting' is NOT a fault — a rotated "
        "off-site disk is legitimately absent for days — so do not "
        "report it as an outage. It IS the reason a backup to that "
        "destination will fail, which is the useful thing to say when "
        "asked why a backup did not run. Also carries the destination "
        "path a Local volume backup target should use, and the "
        "Kubernetes node the disk is plugged into (a removable "
        "destination is node-local: a run scheduled on another node "
        "refuses rather than writing to the wrong host). Use to answer "
        "'is the backup disk on ddi1 plugged in?', 'how much room is "
        "left on it?' or 'which nodes have a USB disk I have not set up "
        "yet?'. Read-only."
    ),
    args_model=FindApplianceRemovableArgs,
    category="admin",
    default_enabled=True,
)
async def find_appliance_removable(
    db: AsyncSession, user: User, args: FindApplianceRemovableArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err

    from app.services.appliance.removable import (  # noqa: PLC0415
        merge_state,
        removable_disk_fields,
    )
    from app.services.appliance.removable import (
        report as removable_report,
    )

    stmt = select(Appliance).where(Appliance.revoked_at.is_(None)).order_by(Appliance.hostname)
    rows = list((await db.execute(stmt)).scalars().all())

    out: list[dict[str, Any]] = []
    # Same reasoning as find_appliance_storage: a node filtered out for
    # having nothing, and one filtered out because nobody looked, read
    # as the same absence — and only the second can hide a disk.
    not_reporting: list[str] = []
    for row in rows:
        block = removable_report(row.cluster_health)
        if block is None:
            not_reporting.append(row.hostname)
        mounts = merge_state(row.desired_removable_mounts, row.cluster_health)
        disks = [d for d in (block or {}).get("disks") or [] if isinstance(d, dict)]
        if args.configured_only and not mounts:
            continue
        if not args.configured_only and not mounts and not disks:
            continue
        out.append(
            {
                "appliance_id": str(row.id),
                "hostname": row.hostname,
                "state": row.state,
                "reported": block is not None,
                "node_name": (block or {}).get("node_name") or None,
                "mounts": mounts,
                # Shared with the REST row builder so the two surfaces
                # cannot disagree about how to read one heartbeat blob —
                # the ``mtu_fields`` rule. Hand-written in the first
                # draft, and the two lists had already diverged (this
                # one omitted the vendor and model an operator
                # identifies a disk by, and left ``size_bytes``
                # uncoerced where REST would have nulled it).
                "detected_disks": [removable_disk_fields(d) for d in disks],
            }
        )
    out = out[: args.limit]
    return {
        "appliances": out,
        "count": len(out),
        "not_reporting": not_reporting,
        "not_reporting_count": len(not_reporting),
    }


# ── propose_storage_action ─────────────────────────────────────────


class ProposeStorageActionArgs(BaseModel):
    appliance_id: str = Field(
        description="UUID of the appliance. Use find_appliance_storage to discover it."
    )
    action: Literal[
        "scrub_start",
        "scrub_cancel",
        "fail_member",
        "remove_member",
        "add_member",
        "mpath_reinstate",
    ] = Field(description="The management action to propose.")
    array: str | None = Field(
        default=None,
        description="The md array, e.g. /dev/md/root_a. Required for every action except mpath_reinstate.",
    )
    device: str | None = Field(
        default=None,
        description="The member or path device, e.g. /dev/sdb4. Required for fail/remove/add and mpath_reinstate.",
    )


@register_tool(
    name="propose_storage_action",
    description=(
        "Propose an md / multipath management action on an appliance "
        "(superadmin only, #999 Part B) — fail or remove an array "
        "member, add a replacement, start or cancel a consistency "
        "scrub, or reinstate a downed multipath path. Returns a "
        "PROPOSAL for a human to approve; it never executes anything. "
        "Adding a member ERASES that device, and the approving human "
        "must type the device path back before it runs. Removing the "
        "last in-sync member, or the member the bootloader lives on, is "
        "REFUSED outright rather than confirmed — there would be no "
        "array left to inspect in the first case, and in the second the "
        "array stays green while the machine silently stops booting."
    ),
    args_model=ProposeStorageActionArgs,
    category="admin",
    # Default OFF per non-negotiable #13's stated exception: these are
    # broad-blast-radius writes that overwrite disks, and the safety of
    # the destructive ones rests on a human reading what is about to
    # happen and typing a device path back — none of which survives being
    # driven from a chat window.
    default_enabled=False,
)
async def propose_storage_action(
    db: AsyncSession, user: User, args: ProposeStorageActionArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err

    from app.services.appliance.storage_actions import (  # noqa: PLC0415
        DESTRUCTIVE,
        ActionRefused,
        summarize,
        validate_action,
    )

    try:
        appliance_uuid = uuid.UUID(args.appliance_id)
    except (ValueError, AttributeError):
        return {"error": f"{args.appliance_id!r} is not a valid appliance UUID."}
    row = await db.get(Appliance, appliance_uuid)
    if row is None:
        return {"error": f"No appliance with id {args.appliance_id}."}

    try:
        # Validated with the confirmation PRE-SUPPLIED so the shape check
        # runs; the real confirmation is typed by the human approving the
        # proposal, against the REST endpoint.
        validate_action(args.action, array=args.array, device=args.device, confirm=args.device)
    except ActionRefused as exc:
        return {"error": str(exc)}

    summary = summarize(args.action, args.array, args.device)
    return {
        "kind": "proposal",
        "operation": "appliance_storage_action",
        "appliance_id": str(row.id),
        "hostname": row.hostname,
        "destructive": args.action in DESTRUCTIVE,
        "preview_text": f"On {row.hostname}: {summary}.",
        "how_to_apply": (
            "POST /api/v1/appliance/appliances/{id}/storage/action with "
            "{action, array, device, confirm}. Destructive actions require "
            "'confirm' to equal the device path exactly."
        ),
    }


# ── find_control_plane_vip ─────────────────────────────────────────


class FindControlPlaneVipArgs(BaseModel):
    pass


@register_tool(
    name="find_control_plane_vip",
    description=(
        "Read the cluster-wide MetalLB VIP config (superadmin only, "
        "#272). Returns whether MetalLB is enabled, the L2 address pool, "
        "the floating control-plane VIP that fronts the Web UI across "
        "control-plane nodes, and the data-plane resolver VIPs (DNS :53 "
        "and DHCP relay :67). Read-only — changing a VIP "
        "is a high-blast-radius operation (it can sever Web UI / agent / "
        "resolver reachability) and is done in Fleet → Control plane, "
        "not via the Copilot."
    ),
    args_model=FindControlPlaneVipArgs,
    category="admin",
    default_enabled=True,
)
async def find_control_plane_vip(
    db: AsyncSession, user: User, args: FindControlPlaneVipArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    from app.models.settings import PlatformSettings

    row = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if row is None:
        return {
            "enabled": False,
            "pool_addresses": [],
            "control_plane_vip": "",
            "dns_vip": "",
            "dhcp_relay_vip": "",
        }
    return {
        "enabled": bool(row.metallb_enabled),
        "pool_addresses": list(row.metallb_pool_addresses or []),
        "control_plane_vip": row.control_plane_vip or "",
        "dns_vip": row.dns_vip or "",
        "dhcp_relay_vip": row.dhcp_relay_vip or "",
    }


# ── find_k8s_pods ──────────────────────────────────────────────────


class FindK8sPodsArgs(BaseModel):
    namespace: str | None = Field(
        default="spatium",
        description=(
            "Namespace to list pods in (default 'spatium', where the "
            "control-plane workloads live). Pass an empty string for the "
            "api pod's own namespace; there is no all-namespaces mode."
        ),
    )
    only_unhealthy: bool = Field(
        default=False,
        description="Return only pods that aren't Running + fully Ready.",
    )
    limit: int = Field(default=100, ge=1, le=500)


@register_tool(
    name="find_k8s_pods",
    description=(
        "List Kubernetes pods on the appliance control plane (superadmin "
        "only, #272). Returns per-pod namespace / name / phase / node / "
        "ready / restarts — the same view as `kubectl get pods`. Use to "
        "answer 'is anything crash-looping?' or 'which node is the "
        "primary postgres on?'. Appliance control plane only; read-only."
    ),
    args_model=FindK8sPodsArgs,
    category="admin",
    default_enabled=True,
)
async def find_k8s_pods(db: AsyncSession, user: User, args: FindK8sPodsArgs) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    import asyncio  # noqa: PLC0415

    from app.config import settings  # noqa: PLC0415
    from app.services.appliance import k8s  # noqa: PLC0415

    if not settings.appliance_mode:
        return {
            "error": (
                "Kubernetes introspection is only available on the "
                "SpatiumDDI OS appliance control plane."
            )
        }
    try:
        items = await asyncio.to_thread(k8s.list_pods, args.namespace or None)
    except k8s.KubeapiUnavailableError as exc:
        return {"error": f"kubeapi unreachable: {exc}"}

    pods: list[dict[str, Any]] = []
    for it in items:
        meta = it.get("metadata") or {}
        spec = it.get("spec") or {}
        st = it.get("status") or {}
        cs = st.get("containerStatuses") or []
        ready_n = sum(1 for c in cs if c.get("ready"))
        restarts = sum(int(c.get("restartCount") or 0) for c in cs)
        all_ready = bool(cs) and ready_n == len(cs)
        phase = st.get("phase")
        if args.only_unhealthy and phase in ("Running", "Succeeded") and all_ready:
            continue
        pods.append(
            {
                "namespace": meta.get("namespace"),
                "name": meta.get("name"),
                "phase": phase,
                "node": spec.get("nodeName"),
                "ready": f"{ready_n}/{len(cs)}" if cs else "0/0",
                "restarts": restarts,
            }
        )
    pods = pods[: args.limit]
    return {"pods": pods, "count": len(pods)}


# ── find_cluster_health ────────────────────────────────────────────


class FindClusterHealthArgs(BaseModel):
    pass


@register_tool(
    name="find_cluster_health",
    description=(
        "Roll up the appliance control-plane cluster health (superadmin "
        "only, #272). Returns the settled control-plane member count, an "
        "etcd-quorum assessment (odd count + all members reporting "
        "ready), and a per-node summary (hostname / node IP / cluster "
        "role / join state / last-seen). Use to answer 'is the control "
        "plane healthy?' or 'did node X finish joining?'. Read-only."
    ),
    args_model=FindClusterHealthArgs,
    category="admin",
    default_enabled=True,
)
async def find_cluster_health(
    db: AsyncSession, user: User, args: FindClusterHealthArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    from app.models.appliance import (  # noqa: PLC0415
        CLUSTER_ROLE_MEMBER,
        CLUSTER_ROLE_PRIMARY,
    )

    rows = list(
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                )
            )
        )
        .scalars()
        .all()
    )
    nodes = [
        {
            "hostname": r.hostname,
            "node_ip": r.node_ip,
            "cluster_role": r.cluster_role,
            "cluster_join_state": r.cluster_join_state,
            "last_seen_at": (r.last_seen_at.isoformat() if r.last_seen_at else None),
        }
        for r in sorted(rows, key=lambda r: (r.cluster_role != CLUSTER_ROLE_PRIMARY, r.hostname))
    ]
    member_count = len(rows)
    all_ready = all(r.cluster_join_state in (None, "ready") for r in rows)
    has_primary = any(r.cluster_role == CLUSTER_ROLE_PRIMARY for r in rows)
    odd = member_count % 2 == 1
    quorum_ok = member_count >= 1 and odd and all_ready and has_primary
    return {
        "member_count": member_count,
        "etcd_quorum_ok": quorum_ok,
        "quorum_notes": {
            "odd_member_count": odd,
            "all_members_ready": all_ready,
            "has_primary_seed": has_primary,
            "tolerates_node_loss": max(0, (member_count - 1) // 2),
        },
        "nodes": nodes,
    }


# ── find_cluster_metrics ───────────────────────────────────────────


class FindClusterMetricsArgs(BaseModel):
    pass


@register_tool(
    name="find_cluster_metrics",
    description=(
        "Live resource metrics for the appliance k3s cluster (superadmin "
        "only, #402). Unlike ``find_cluster_health`` (control-plane "
        "membership from heartbeats), this reads the cluster *now* via the "
        "api pod's ServiceAccount: per-node CPU / memory / disk from the "
        "kubelet Summary API, pod counts by phase, a per-component workload "
        "health rollup, the top pods by CPU + memory, and per-node PSI "
        "stall percentages (#983). Use to answer 'how loaded is the "
        "appliance?', 'what's eating memory?', 'are all workloads healthy?' "
        "'is cluster DNS healthy?', or 'is anything actually WAITING on CPU?' "
        "— the last one is what "
        "utilisation cannot answer, since a node at 70% CPU with a run queue "
        "and one without look identical by usage alone. A null PSI figure "
        "means the kubelet did not report it (below Kubernetes 1.36), which "
        "is NOT the same as no pressure. The ``cluster_dns`` block carries "
        "CoreDNS replica count, node spread, and a live resolve probe — "
        "replicas existing and DNS actually answering are different facts, "
        "and a failed probe with healthy replicas points at kube-proxy or "
        "the pod network rather than at CoreDNS. Appliance control plane only; "
        "read-only — the same data the Cluster → Overview dashboard renders."
    ),
    args_model=FindClusterMetricsArgs,
    category="admin",
    default_enabled=True,
)
async def find_cluster_metrics(
    db: AsyncSession, user: User, args: FindClusterMetricsArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    import asyncio  # noqa: PLC0415

    from app.config import settings  # noqa: PLC0415
    from app.services.appliance import cluster_health, k8s  # noqa: PLC0415

    if not settings.appliance_mode:
        return {
            "error": (
                "Cluster metrics are only available on the SpatiumDDI OS "
                "appliance control plane."
            )
        }
    try:
        snap = await asyncio.to_thread(cluster_health.get_cluster_health)
    except k8s.KubeapiUnavailableError as exc:
        return {"error": f"kubeapi unreachable: {exc}"}
    if not snap.get("available"):
        return {"available": False, "detail": snap.get("detail")}

    def _pct(used: float | None, cap: float | None) -> float | None:
        return round(100.0 * used / cap, 1) if used is not None and cap else None

    def _psi(block: Any, kind: str) -> float | None:
        """``avg300`` out of one PSI series, or None when unreported."""
        series = (block or {}).get(kind) if isinstance(block, dict) else None
        val = series.get("avg300") if isinstance(series, dict) else None
        return round(float(val), 1) if isinstance(val, (int, float)) else None

    nodes = [
        {
            "name": n["name"],
            "ready": n["ready"],
            "roles": n["roles"],
            "cpu_pct": _pct(n.get("cpu_usage_cores"), n.get("cpu_capacity_cores")),
            "mem_pct": _pct(n.get("memory_working_set_bytes"), n.get("memory_capacity_bytes")),
            "pods_running": n.get("pods_running"),
            # #983 Phase 2 — the share of the last 5 minutes something spent
            # stalled. ``some`` = at least one task blocked; memory ``full``
            # = every runnable task blocked. null = not reported, never zero.
            "cpu_stall_pct_5m": _psi(n.get("psi_cpu"), "some"),
            "mem_stall_pct_5m": _psi(n.get("psi_memory"), "some"),
            "mem_full_stall_pct_5m": _psi(n.get("psi_memory"), "full"),
            "io_stall_pct_5m": _psi(n.get("psi_io"), "some"),
        }
        for n in snap.get("nodes", [])
    ]
    return {
        "available": True,
        "nodes_ready": snap["nodes_ready"],
        "nodes_total": snap["nodes_total"],
        "pods_running": snap["pods_running"],
        "pods_total": snap["pods_total"],
        "pods_by_phase": snap["pods_by_phase"],
        "kubelet_version": snap["kubelet_version"],
        "is_ha": snap["is_ha"],
        "metrics_available": snap["metrics_available"],
        # Which transport served the kubelet Summary API, and why the direct
        # one is off if it is (#983 Phase 2 item 6).
        "kubelet_transport": snap.get("kubelet_transport"),
        # Cluster DNS (#985). Nulls inside this block mean UNKNOWN, never
        # zero — a cluster whose kube-system pods we cannot list reports
        # ``available: false`` with a reason rather than "no replicas".
        "cluster_dns": snap.get("cluster_dns"),
        "cluster_cpu_pct": _pct(snap.get("cpu_usage_cores"), snap.get("cpu_capacity_cores")),
        "cluster_mem_pct": _pct(
            snap.get("memory_working_set_bytes"), snap.get("memory_capacity_bytes")
        ),
        "nodes": nodes,
        "workloads": snap["workloads"],
        "top_pods_cpu": [
            {"name": p["name"], "namespace": p["namespace"], "cpu_cores": p["cpu_usage_cores"]}
            for p in snap.get("top_pods_cpu", [])[:5]
        ],
        "top_pods_mem": [
            {
                "name": p["name"],
                "namespace": p["namespace"],
                "mem_bytes": p["memory_working_set_bytes"],
            }
            for p in snap.get("top_pods_mem", [])[:5]
        ],
    }


# ── find_etcd_snapshots ────────────────────────────────────────────


class FindEtcdSnapshotsArgs(BaseModel):
    pass


@register_tool(
    name="find_etcd_snapshots",
    description=(
        "List recoverable etcd snapshots reported by the appliance "
        "control-plane seed (superadmin only). Returns "
        "each snapshot's name / node / size / creation time, plus any "
        "in-flight restore state. Use to answer 'what etcd snapshots can "
        "we recover from?' or 'is a restore running?'. Read-only — a "
        "restore is a destructive single-node cluster-reset and is done "
        "in Fleet → Control plane, never via the Copilot."
    ),
    args_model=FindEtcdSnapshotsArgs,
    category="admin",
    default_enabled=True,
)
async def find_etcd_snapshots(
    db: AsyncSession, user: User, args: FindEtcdSnapshotsArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    from app.models.appliance import (  # noqa: PLC0415
        APPLIANCE_STATE_APPROVED,
        CLUSTER_ROLE_PRIMARY,
    )

    # Resolve the seed: prefer the etcd primary, else the lone
    # control-plane-variant appliance (single-node, pre-promote).
    seed = (
        (
            await db.execute(
                select(Appliance).where(
                    Appliance.state == APPLIANCE_STATE_APPROVED,
                    Appliance.cluster_role == CLUSTER_ROLE_PRIMARY,
                )
            )
        )
        .scalars()
        .first()
    )
    if seed is None:
        seed = (
            (
                await db.execute(
                    select(Appliance)
                    .where(
                        Appliance.state == APPLIANCE_STATE_APPROVED,
                        Appliance.appliance_variant.in_(
                            ("control-plane", "full-stack", "frontend-core")
                        ),
                        Appliance.last_seen_at.is_not(None),
                    )
                    .order_by(Appliance.created_at.asc())
                )
            )
            .scalars()
            .first()
        )
    if seed is None:
        return {
            "available": False,
            "snapshots": [],
            "note": "No appliance control-plane seed found (docker / k8s control plane).",
        }
    return {
        "available": True,
        "seed_hostname": seed.hostname,
        "snapshots": list(seed.etcd_snapshots or []),
        "desired_restore_snapshot": seed.desired_restore_snapshot,
        "restore_state": seed.restore_state,
        "restore_reason": seed.restore_reason,
    }


# ── find_upgrade_images ────────────────────────────────────────────


class FindUpgradeImagesArgs(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)


@register_tool(
    name="find_upgrade_images",
    description=(
        "List appliance upgrade images stored on the control plane "
        "(superadmin only, #199). These are the ``.raw.xz`` artifacts an "
        "operator uploaded (air-gap) or imported from a GitHub release — "
        "the pool a fleet / per-box OS upgrade can point at. Each row "
        "carries filename / appliance_version / architecture / size / a "
        "short SHA-256 / upload time / notes. ``architecture`` is null for "
        "an image nobody labelled — that means UNKNOWN, never amd64 "
        "(#1026). Use to answer 'which upgrade images do we "
        "have staged?' or 'is 2026.06.01-1 already uploaded?'. Read-only "
        "— upload / import / delete happen in Fleet → Upgrade images."
    ),
    args_model=FindUpgradeImagesArgs,
    category="admin",
    default_enabled=True,
)
async def find_upgrade_images(
    db: AsyncSession, user: User, args: FindUpgradeImagesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    rows = list(
        (
            await db.execute(
                select(ApplianceUpgradeImage)
                .order_by(ApplianceUpgradeImage.uploaded_at.desc())
                .limit(args.limit)
            )
        )
        .scalars()
        .all()
    )
    return {
        "images": [
            {
                "id": str(r.id),
                "filename": r.filename,
                "appliance_version": r.appliance_version,
                # #1026 — null is UNKNOWN, not amd64. Said explicitly so
                # the copilot cannot answer "which of these fits my arm64
                # node" with an image nobody has labelled.
                "architecture": r.architecture,
                "size_bytes": r.size_bytes,
                "sha256_short": (r.sha256[:12] + "…" + r.sha256[-6:]) if r.sha256 else None,
                "uploaded_at": r.uploaded_at.isoformat(),
                "notes": r.notes,
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ── find_available_upgrade_images ──────────────────────────────────


class FindAvailableUpgradeImagesArgs(BaseModel):
    pass


@register_tool(
    name="find_available_upgrade_images",
    description=(
        "List GitHub releases that carry an importable appliance upgrade "
        "image (superadmin only, #199). Returns each release tag + name + "
        "architecture + prerelease/installed flags + the image size, plus "
        "whether GitHub was reachable at all. A release that publishes "
        "both architectures appears ONCE PER ARCHITECTURE, so the same tag "
        "can be listed twice (#1026). Use to answer 'what upgrade images can I "
        "import?' before pointing the operator at Fleet → Upgrade images "
        "to do the import. Read-only — and it makes an outbound call to "
        "github.com, so it's opt-in (disabled by default)."
    ),
    args_model=FindAvailableUpgradeImagesArgs,
    category="admin",
    default_enabled=False,
)
async def find_available_upgrade_images(
    db: AsyncSession, user: User, args: FindAvailableUpgradeImagesArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    from app.services.appliance import releases as releases_service  # noqa: PLC0415

    reachable, rows = await releases_service.list_available_upgrade_images()
    return {
        "github_reachable": reachable,
        "available": [
            {
                "tag": r.tag,
                "name": r.name,
                "is_prerelease": r.is_prerelease,
                "is_installed": r.is_installed,
                "architecture": r.architecture,
                "size_bytes": r.size_bytes,
                "published_at": r.published_at.isoformat(),
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ── propose_approve_appliance ──────────────────────────────────────


class ProposeApproveApplianceArgs(BaseModel):
    appliance_id: str = Field(
        description=(
            "UUID of the pending appliance row to approve. Use "
            "``find_pending_appliances`` first to discover it."
        )
    )


@register_tool(
    name="propose_approve_appliance",
    description=(
        "Propose approving a pending Application appliance "
        "(superadmin only). Approval is irreversible cryptographically "
        "— the control plane's internal CA signs an X.509 cert against "
        "the supervisor's submitted Ed25519 pubkey + records the "
        "serial in the audit log. The model proposes the approval "
        "and the operator must click Apply for the cert to issue. "
        "Use this when the operator confirms a pending pairing is "
        "expected; otherwise prefer ``find_pending_appliances`` to "
        "let the operator inspect the row in the Fleet tab and "
        "approve from there."
    ),
    args_model=ProposeApproveApplianceArgs,
    category="admin",
    default_enabled=True,
)
async def propose_approve_appliance(
    db: AsyncSession, user: User, args: ProposeApproveApplianceArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    op = operations.get_operation("approve_appliance")
    if op is None:
        return {"error": "Operation 'approve_appliance' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "approve_appliance",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="approve_appliance",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


# ── propose_assign_role ───────────────────────────────────────────


class ProposeAssignRoleArgs(BaseModel):
    appliance_id: str = Field(description="UUID of the approved appliance row.")
    roles: list[str] = Field(
        description=(
            "Subset of dns-bind9 / dns-powerdns / dns-technitium / dhcp / "
            "observer / custom. The three dns-* roles are mutually "
            "exclusive. Empty list = idle (no service containers will run)."
        )
    )
    dns_group_id: str | None = Field(
        default=None,
        description=(
            "Optional DNSServerGroup UUID. Required if roles include "
            "a DNS role and there's no existing assignment."
        ),
    )
    dhcp_group_id: str | None = Field(
        default=None,
        description=(
            "Optional DHCPServerGroup UUID. Required if roles include "
            "dhcp and there's no existing assignment."
        ),
    )


@register_tool(
    name="propose_assign_role",
    description=(
        "Propose role + group assignment for an approved appliance "
        "(superadmin only). The model proposes the assignment + the "
        "operator clicks Apply for the supervisor to actually start / "
        "stop service containers on the next heartbeat. Server-side "
        "validation rejects roles the supervisor doesn't advertise "
        "capability for, and rejects combining more than one dns-* role "
        "(one engine per appliance). For tags or firewall edits, point "
        "the operator at the Fleet tab drilldown."
    ),
    args_model=ProposeAssignRoleArgs,
    category="admin",
    default_enabled=True,
)
async def propose_assign_role(
    db: AsyncSession, user: User, args: ProposeAssignRoleArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    op = operations.get_operation("assign_appliance_role")
    if op is None:
        return {"error": "Operation 'assign_appliance_role' is not registered"}
    preview = await op.preview(db, user, args)
    if not preview.ok:
        return {
            "kind": "proposal_rejected",
            "operation": "assign_appliance_role",
            "detail": preview.detail,
        }
    proposal = await _persist_proposal(
        db,
        user=user,
        operation="assign_appliance_role",
        args=args.model_dump(),
        preview_text=preview.preview_text,
    )
    return _proposal_result(proposal, preview_text=preview.preview_text)


__all__ = [
    "find_pending_appliances",
    "find_appliance_fleet",
    "find_appliance_storage",
    "propose_storage_action",
    "find_upgrade_images",
    "find_available_upgrade_images",
    "propose_approve_appliance",
    "propose_assign_role",
]


# Tell mypy + ruff these uuid imports are intentional — we accept
# string-form UUIDs from the LLM but resolve them server-side via
# the operations' apply functions.
_ = uuid

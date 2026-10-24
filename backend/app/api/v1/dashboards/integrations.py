"""Integrations dashboard tab summary (issue #108).

Per-integration health rollup. Returns one panel per *enabled*
integration (Kubernetes / Docker / Proxmox / Tailscale) so the
front-end doesn't have to know which feature flags are on. Each
target row contributes its ``last_synced_at`` + ``last_sync_error``
+ ``sync_interval_seconds`` so the panel can colour "stale" rows
red without per-target heuristics.

The "stale" threshold is ``2 × sync_interval_seconds`` — if a
target hasn't been seen within twice its configured cadence the
sweep loop is genuinely behind, not just mid-cycle.

Recent reconciler errors come from the audit log (every
integration writes an audit row on failed sync) filtered to the
matching ``resource_type`` set. Capped at 20 rows.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import desc, select

from app.api.deps import DB, CurrentUser
from app.core.permissions import require_any_permission, user_has_permission
from app.models.audit import AuditLog
from app.models.cloud import CloudEndpoint
from app.models.docker import DockerHost
from app.models.fortinet import FortinetFirewall
from app.models.kubernetes import KubernetesCluster
from app.models.meraki import MerakiOrg
from app.models.netbird import NetbirdInstance
from app.models.opnsense import OPNsenseRouter
from app.models.panos import PANOSFirewall
from app.models.proxmox import ProxmoxNode
from app.models.tailscale import TailscaleTenant
from app.models.unifi import UnifiController
from app.services.feature_modules import get_enabled_modules
from app.services.integration_credentials import (
    CREDENTIAL_PROBLEM_STATES,
    CredentialStatus,
    credential_status,
)
from app.services.tailscale.client import is_auth_rejected

router = APIRouter()


# ── Schemas ─────────────────────────────────────────────────────────


class IntegrationTargetRow(BaseModel):
    id: str
    display: str
    sync_interval_seconds: int
    last_synced_at: datetime | None
    last_sync_error: str | None
    # #797 — non-fatal findings from the last pass. A reconcile can be on
    # time and error-free and still mirror nothing; without this the tab
    # shows such a target green while the IPAM-tab panel shows it amber,
    # which is the "both surfaces" rule (non-negotiable #15) broken.
    # ``None`` for integrations that don't compute warnings.
    last_sync_warning: str | None
    is_stale: bool  # last_synced_at older than 2× sync_interval, or never
    # #2221 — a disabled target is switched off, so its old ``last_sync_error``
    # is history: still returned, but never a live problem or a red count.
    enabled: bool = True
    # #2138 — the target's credential: ok | expiring | expired | rejected |
    # unknown, from app/services/integration_credentials.py. ``None`` for
    # integrations that don't record a credential expiry (yet).
    credential_state: str | None = None
    credential_expires_at: datetime | None = None
    credential_days_left: int | None = None


class IntegrationPanel(BaseModel):
    kind: str  # "kubernetes" | "docker" | "proxmox" | "tailscale"
    label: str
    enabled: bool
    target_count: int
    healthy_count: int
    stale_count: int
    error_count: int
    warning_count: int
    # #2221 — targets switched off. Counted here instead of in the
    # healthy / stale / error / warning buckets, which describe live syncs.
    disabled_count: int = 0
    # #2192 — counted over EVERY target, not the capped ``targets`` list, so
    # the card's counts stay right when the row list is trimmed. A "problem"
    # is a credential that is rejected / expired / expiring, or a sync error;
    # ``credential_dead_count`` is rejected + expired.
    problem_count: int = 0
    credential_dead_count: int = 0
    credential_expiring_count: int = 0
    targets: list[IntegrationTargetRow]


class IntegrationErrorRow(BaseModel):
    id: str
    integration: str  # resource_type from audit_log
    target_id: str
    target_display: str
    error_detail: str | None
    timestamp: datetime


class IntegrationsDashboardSummary(BaseModel):
    generated_at: datetime
    panels: list[IntegrationPanel]
    recent_errors: list[IntegrationErrorRow]


_TARGET_LIMIT = 20
# #2192 — problem rows are listed past ``_TARGET_LIMIT``, but not without
# bound: 200 failing nodes must not become a 200-row payload. Beyond this the
# card says "+N more with problems" from ``problem_count``.
_PROBLEM_TARGET_LIMIT = 50
_RECENT_ERROR_LIMIT = 20

# Resource_type values audit-logged by each integration's reconciler.
# Mirrors the strings emitted in ``services/{kubernetes,docker,
# proxmox,tailscale}/reconcile.py``.
_INTEGRATION_RESOURCE_TYPES = (
    "kubernetes_cluster",
    "docker_host",
    "proxmox_node",
    "tailscale_tenant",
    "unifi_controller",
    "cloud_endpoint",
    "opnsense_router",
    "netbird_instance",
    "panos_firewall",
    "fortinet_firewall",
    "meraki_org",
)


def _is_stale(last: datetime | None, interval_seconds: int, now: datetime) -> bool:
    """A target is stale when it's never synced (last is None) or its
    last sync is older than 2× its configured interval. Rounded up to
    a 60 s minimum so a freshly-edited interval doesn't immediately
    flag every target red while the next tick is in flight."""
    if last is None:
        return True
    threshold = max(60, interval_seconds * 2)
    return (now - last) > timedelta(seconds=threshold)


def _has_problem(r: IntegrationTargetRow) -> bool:
    if not r.enabled:
        # #2221 — a disabled target's leftover error is history, not a
        # problem to act on (``credential_state`` already reads "disabled").
        return False
    return r.credential_state in CREDENTIAL_PROBLEM_STATES or bool(r.last_sync_error)


def _cap_rows(rows: list[IntegrationTargetRow]) -> list[IntegrationTargetRow]:
    """Cap the row list, but never let the cap hide a problem first (#2192).

    Targets with a credential problem or a sync error come first (stable
    within each group) and are kept past ``_TARGET_LIMIT``, up to the hard
    ``_PROBLEM_TARGET_LIMIT``; healthy rows only fill what ``_TARGET_LIMIT``
    leaves. The panel's ``problem_count`` carries the true total.
    """
    problems = [r for r in rows if _has_problem(r)][:_PROBLEM_TARGET_LIMIT]
    rest = [r for r in rows if not _has_problem(r)]
    return problems + rest[: max(0, _TARGET_LIMIT - len(problems))]


def _build_panel(
    *,
    kind: str,
    label: str,
    enabled: bool,
    targets: list[Any],
    display_attr: str,
    now: datetime,
    credential: Callable[[Any], CredentialStatus] | None = None,
) -> IntegrationPanel:
    """Aggregate one integration's targets into the dashboard panel."""
    rows: list[IntegrationTargetRow] = []
    healthy = 0
    stale = 0
    errors = 0
    warnings = 0
    disabled = 0
    for t in targets:
        last = getattr(t, "last_synced_at", None)
        interval = int(getattr(t, "sync_interval_seconds", 60) or 60)
        last_err = getattr(t, "last_sync_error", None)
        # getattr default — only integrations that compute non-fatal
        # findings carry the column; the rest report None.
        last_warn = getattr(t, "last_sync_warning", None)
        is_stale = _is_stale(last, interval, now)
        target_enabled = bool(getattr(t, "enabled", True))
        if not target_enabled:
            disabled += 1
        elif last_err:
            errors += 1
        elif is_stale:
            stale += 1
        elif last_warn:
            # Warned targets are counted separately rather than folded
            # into healthy: the sync IS working, but it is not producing
            # what the operator configured it to produce.
            warnings += 1
        else:
            healthy += 1
        # A disabled target reads ``disabled`` (#2191): the rule lives in
        # integration_credentials.credential_status.
        cred = credential(t) if credential is not None else None
        rows.append(
            IntegrationTargetRow(
                id=str(t.id),
                display=str(getattr(t, display_attr, "") or ""),
                sync_interval_seconds=interval,
                last_synced_at=last,
                last_sync_error=last_err,
                last_sync_warning=last_warn,
                is_stale=is_stale,
                enabled=target_enabled,
                credential_state=cred.state if cred else None,
                credential_expires_at=cred.expires_at if cred else None,
                credential_days_left=cred.days_left if cred else None,
            )
        )
    return IntegrationPanel(
        kind=kind,
        label=label,
        enabled=enabled,
        target_count=len(targets),
        healthy_count=healthy,
        stale_count=stale,
        error_count=errors,
        warning_count=warnings,
        disabled_count=disabled,
        problem_count=sum(1 for r in rows if _has_problem(r)),
        credential_dead_count=sum(
            1 for r in rows if r.enabled and r.credential_state in ("rejected", "expired")
        ),
        credential_expiring_count=sum(
            1 for r in rows if r.enabled and r.credential_state == "expiring"
        ),
        targets=_cap_rows(rows),
    )


# ── Route ───────────────────────────────────────────────────────────


# One row per integration: (panel kind, label, feature module, target
# model, the resource_type its own router gates on). A panel reads as
# enabled when its feature module does — the module is the integration's
# switch (#2196), the same answer its beat sweep acts on. A caller sees a panel
# only when it may read that integration's targets through the integration's
# own router, so this rollup never shows more than those routes would.
def _tailscale_credential(now: datetime) -> Callable[[Any], CredentialStatus]:
    """#2138 — a Tailscale tenant's API-key state for its dashboard row."""

    def status(t: Any) -> CredentialStatus:
        return credential_status(
            expires_at=t.api_key_expires_at,
            rejected=is_auth_rejected(t.last_sync_error),
            now=now,
            enabled=bool(getattr(t, "enabled", True)),
        )

    return status


_PANELS: tuple[tuple[str, str, str, Any, str], ...] = (
    (
        "kubernetes",
        "Kubernetes",
        "integrations.kubernetes",
        KubernetesCluster,
        "kubernetes_cluster",
    ),
    ("docker", "Docker", "integrations.docker", DockerHost, "docker_host"),
    # ProxmoxNode has `name`/`host`, not `hostname` — the panel uses `name` so
    # the Integrations dashboard shows the same node label as the IPAM panel.
    ("proxmox", "Proxmox VE", "integrations.proxmox", ProxmoxNode, "proxmox_node"),
    (
        "tailscale",
        "Tailscale",
        "integrations.tailscale",
        TailscaleTenant,
        "tailscale_tenant",
    ),
    ("unifi", "UniFi", "integrations.unifi", UnifiController, "unifi_controller"),
    (
        "cloud",
        "Cloud (AWS / Azure / GCP)",
        "integrations.cloud",
        CloudEndpoint,
        "cloud_endpoint",
    ),
    ("opnsense", "OPNsense", "integrations.opnsense", OPNsenseRouter, "opnsense_router"),
    ("netbird", "NetBird", "integrations.netbird", NetbirdInstance, "netbird_instance"),
    (
        "paloalto",
        "Palo Alto (PAN-OS / Panorama)",
        "integrations.paloalto",
        PANOSFirewall,
        "panos_firewall",
    ),
    (
        "fortinet",
        "Fortinet (FortiGate)",
        "integrations.fortinet",
        FortinetFirewall,
        "fortinet_firewall",
    ),
    ("meraki", "Cisco Meraki (MX)", "integrations.meraki", MerakiOrg, "meraki_org"),
)


@router.get(
    "/integrations/summary",
    response_model=IntegrationsDashboardSummary,
    dependencies=[
        Depends(require_any_permission(*(("read", rt) for rt in _INTEGRATION_RESOURCE_TYPES)))
    ],
)
async def integrations_summary(db: DB, current_user: CurrentUser) -> IntegrationsDashboardSummary:
    """Single-shot rollup for the Integrations dashboard tab.

    Holds the caller to the same ``read`` grants as each integration's own
    router: the route needs one of them, and each panel and each recent
    error row is included only for an integration the caller may read.
    """
    now = datetime.now(UTC)
    enabled_modules = await get_enabled_modules(db)

    readable = [row for row in _PANELS if user_has_permission(current_user, "read", row[4])]
    panels = []
    for kind, label, module_id, model, _rtype in readable:
        targets = list((await db.execute(select(model))).scalars().all())
        panels.append(
            _build_panel(
                kind=kind,
                label=label,
                enabled=module_id in enabled_modules,
                targets=targets,
                display_attr="name",
                now=now,
                credential=_tailscale_credential(now) if kind == "tailscale" else None,
            )
        )
    readable_types = [row[4] for row in readable]

    # Recent reconciler errors — one filtered audit query covers all
    # integrations at once.
    err_rows = list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.result == "error")
                .where(AuditLog.resource_type.in_(readable_types))
                .order_by(desc(AuditLog.timestamp))
                .limit(_RECENT_ERROR_LIMIT)
            )
        )
        .scalars()
        .all()
    )
    recent_errors = [
        IntegrationErrorRow(
            id=str(r.id),
            integration=r.resource_type,
            target_id=r.resource_id,
            target_display=r.resource_display or "",
            error_detail=r.error_detail,
            timestamp=r.timestamp,
        )
        for r in err_rows
    ]

    return IntegrationsDashboardSummary(
        generated_at=now,
        panels=panels,
        recent_errors=recent_errors,
    )

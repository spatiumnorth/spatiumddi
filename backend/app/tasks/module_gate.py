"""Feature-module gate for Celery tasks (#2279).

Disabling a feature module 404s its router and hides its sidebar entry
(non-negotiable #14), but a Celery task never goes through a router. A
task that does not ask keeps running after the operator turned its
module off — an nmap auto-profile of every new DHCP client, SNMP polls,
TLS probes, off-prem RDAP / RPKI fetches — against rows the operator can
no longer even see.

``module_gated("<module id>")`` is the one place that question is asked.
Put it directly under ``@celery_app.task``::

    @celery_app.task(name="app.tasks.snmp_poll.dispatch_due_devices", bind=True)
    @module_gated("network.device")
    def dispatch_due_devices(self): ...

When the module resolves disabled — including through a disabled parent
in its ``requires=`` chain (#1068), since this reuses
``feature_modules.get_enabled_modules`` — the task body never runs and
the call returns ``{"status": "module_disabled", "module": id}``. The
skip is logged at debug, once per task per process until the module is
seen enabled again, so a 30 s beat tick does not repeat it forever.

The decorator stamps ``__module_gate__`` on the wrapper, which is what
``tests/test_module_gated_tasks_2279.py`` reads: every task in the beat
schedule must carry a gate or appear in :data:`UNGATED_BEAT_TASKS` with
the reason it runs regardless. A new beat task therefore cannot ship
ungated by omission.

Cost: one short-lived connection per gated task run, and none at all
when the process-local enabled-set cache (``_CACHE_TTL_S``) is warm —
beat fires many tasks on the same tick, so most checks hit it.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any, Final, TypeVar

import structlog

from app.db import task_session
from app.services import feature_modules

logger = structlog.get_logger(__name__)

_F = TypeVar("_F", bound=Callable[..., Any])

# Tasks whose skip has already been logged in this process. Cleared for a
# task the next time it runs enabled, so a later disable logs again.
_logged_skips: set[str] = set()


async def _module_enabled(module_id: str) -> bool:
    async with task_session() as db:
        return await feature_modules.is_module_enabled(db, module_id)


def module_gated(module_id: str) -> Callable[[_F], _F]:
    """Skip the decorated Celery task while ``module_id`` is disabled."""
    if not feature_modules.is_known(module_id):
        # Same reasoning as ``require_module``: fail at import, never ship
        # a gate against a module id that does not exist (``is_module_enabled``
        # resolves unknown ids to True, so a typo would gate nothing).
        raise RuntimeError(f"module_gated: unknown module {module_id!r}")

    def decorator(fn: _F) -> _F:
        task_label = f"{fn.__module__}.{fn.__name__}"

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not asyncio.run(_module_enabled(module_id)):
                if task_label not in _logged_skips:
                    _logged_skips.add(task_label)
                    logger.debug(
                        "task_skipped_module_disabled",
                        task=task_label,
                        module=module_id,
                    )
                return {"status": "module_disabled", "module": module_id}
            _logged_skips.discard(task_label)
            return fn(*args, **kwargs)

        # Celery derives the task's call-signature check from the function
        # via ``getfullargspec``, which does not follow ``__wrapped__`` but
        # does honour ``__signature__`` — keep the real signature so a call
        # with the wrong arguments still fails at ``.delay()``.
        wrapper.__signature__ = inspect.signature(fn)  # type: ignore[attr-defined]
        wrapper.__module_gate__ = module_id  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


# Beat tasks that deliberately run whatever the feature modules say. Every
# entry carries the reason; ``tests/test_module_gated_tasks_2279.py`` fails
# any beat task that is neither gated nor listed here, and any entry here
# that is not in the schedule (a stale allowlist hides nothing, but it
# reads as coverage that is not there).
UNGATED_BEAT_TASKS: Final[dict[str, str]] = {
    # ── Core platform: no feature module owns these ──────────────────
    "app.tasks.heartbeat.beat_tick": "core: the beat/worker liveness round trip /health reads",
    "app.tasks.schema_check.check_schema_at_head": "core: Alembic-head health check",
    "app.tasks.alerts.evaluate_alerts": (
        "core: alerting is not a module; the evaluator already skips rules whose "
        "module is disabled (services/alerts.py, get_enabled_modules)"
    ),
    "app.tasks.event_outbox.process_event_outbox": "core: typed-event webhook delivery",
    "app.tasks.audit_chain_verify.verify_audit_chain": "core: audit-log tamper evidence",
    "app.tasks.backup_sweep.sweep_backup_targets": "core: scheduled backups",
    "app.tasks.backup_drill.sweep_restore_drills": "core: scheduled restore drills",
    "app.tasks.time_bound_grant_sweep.sweep_expired_grants": (
        "core RBAC: expiring a grant late would leave a permission live past its end"
    ),
    "app.tasks.change_request_expiry.sweep_expired_change_requests": (
        "housekeeping shared by governance.approvals and governance.requests; "
        "DB-only, and expiring a stale request is right with either module off"
    ),
    "app.tasks.update_check.check_github_release": (
        "core: own opt-out (Settings → Updates), documented in PRIVACY.md §3.1"
    ),
    "app.tasks.oui_update.auto_update_oui_database": "core IPAM: own opt-in setting",
    "app.tasks.influxdb_push.push_influxdb_metrics": (
        "not a feature module by decision (#889): off is enabled=false on the target row"
    ),
    "app.tasks.upgrade_orchestrator.resume_orphaned_runs": "core appliance upgrade orchestration",
    "app.tasks.upgrade_image_reclaim.reclaim_upgrade_images": (
        "core appliance upgrade orchestration: frees stored upgrade-image bytes on /var"
    ),
    "app.tasks.upgrade_orchestrator.release_lingering_shared_tag_hold": (
        "core appliance upgrade orchestration"
    ),
    "app.tasks.firewall_lint_scan.scan_firewall_extra": (
        "one-time advisory audit of stored firewall_extra values; DB-only, writes "
        "audit rows, never touches a host"
    ),
    "app.tasks.agent_bundles.render_missing_sweep": (
        "DNS agent bundle render backstop; already skips disabled servers, and the "
        "agent long-poll it serves is mounted outside the core.dns gate on purpose"
    ),
    "app.tasks.acme.renew_due_certificates": (
        "security.certificates is a discovery toggle only (see its description); "
        "renewal of an issued Web UI cert is gated on acme_enabled + acme_auto_renew, "
        "and stopping it would let the live UI cert expire"
    ),
    "app.tasks.acme.sweep_stale_acme_txt_records": (
        "cleanup of challenge TXT records an order left behind"
    ),
    # ── Core IPAM: no module; each has its own per-row / platform opt-in ──
    "app.tasks.ipam_discovery.dispatch_due_subnets": "core IPAM: per-subnet discovery opt-in (#23)",
    "app.tasks.reverse_dns.sweep_reverse_dns": "core IPAM: platform opt-in (#41)",
    "app.tasks.ipam_reservation_sweep.sweep_expired_reservations": "core IPAM",
    "app.tasks.ipam_utilization_recount.recount_ipam_utilization": "core IPAM",
    "app.tasks.subnet_utilization_snapshot.snapshot_subnet_utilization": "core IPAM (#44)",
    "app.tasks.domain_whois_refresh.refresh_due_domains": (
        "no feature module owns Domains (router.py mounts domains_router ungated), so "
        "there is nothing to gate on; a module for Domains is a follow-up — the "
        "scheduled RDAP call itself is documented under #2280"
    ),
    # ── Retention / prune: must run regardless, or data a disabled module
    #    left behind is kept past its retention window ──
    "app.tasks.trash_purge.purge_expired_soft_deletes": "retention",
    "app.tasks.log_partitions.maintain_log_partitions": "retention (the log tables' partitions)",
    "app.tasks.prune_logs.prune_log_entries": "retention",
    "app.tasks.prune_metrics.prune_metric_samples": "retention",
    "app.tasks.prune_internal_errors.prune_internal_errors": "retention",
    "app.tasks.prune_pairing_codes.prune_pairing_codes": "retention",
    "app.tasks.prune_revoked_appliances.prune_revoked_appliances": "retention",
    "app.tasks.prune_multicast_memberships.prune_stale_igmp_memberships": "retention",
    "app.tasks.pcap.prune_captures": "retention",
    "app.tasks.snmp_poll.purge_stale_arp_entries": "retention (network.device data)",
    "app.tasks.tls_certs.prune_probes": "retention (security.tls_certs data)",
}

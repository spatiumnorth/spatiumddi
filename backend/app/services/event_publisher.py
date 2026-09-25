"""Typed-event publisher.

Hooks the same SQLAlchemy ``after_flush`` + ``after_commit`` lifecycle
that ``audit_forward`` uses, but instead of dispatching directly to
log collectors it writes one ``EventOutbox`` row per matching
``EventSubscription`` per audit row. The Celery beat worker
(``app.tasks.event_outbox.process_event_outbox``) drains the outbox
with HMAC-signed POSTs + exponential-backoff retry + a dead-letter
state.

Mapping is from ``(AuditLog.action, AuditLog.resource_type)`` to a
typed event name like ``subnet.created`` / ``ip.allocated``. Audit
rows whose ``(action, resource_type)`` pair doesn't map to a known
event type are silently skipped — this surface is for typed
automation, not raw audit forwarding (which has its own pipeline).

Design choices:

* **At-least-once via outbox**, not transactional. The audit row
  commits before the outbox write, so a process crash between the
  two drops the event. Acceptable for webhooks — the receiver should
  be idempotent on ``event_id`` anyway, and operators wanting
  guaranteed delivery have audit-forward.
* **One outbox row per (event × subscription)**. Per-subscription
  retry state is naturally tracked; one slow consumer can't block
  the others.
* **No event-type wildcards yet.** ``EventSubscription.event_types``
  is an explicit list. Glob support (``subnet.*``) is cheap to add
  later when an operator asks.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings as _app_settings
from app.models.audit import AuditLog
from app.models.event_subscription import EventOutbox, EventSubscription
from app.services.after_commit_dispatch import dispatch

logger = structlog.get_logger(__name__)

_PENDING_ATTR = "__spatium_event_publish_pending__"


# ── Audit → typed event mapping ────────────────────────────────────────────
#
# Source-of-truth for the typed-event vocabulary. Audit rows whose
# (action, resource_type) pair isn't in this map are silently skipped.
# The keys are deliberately concrete — no glob matching, no inference —
# so the published surface is documented and testable.

# Verb mapping: AuditLog.action → event verb. ``create`` / ``update`` /
# ``delete`` cover ~95% of audit rows; specialised actions get their
# own entry below.
_VERB_MAP: dict[str, str] = {
    "create": "created",
    "update": "updated",
    "delete": "deleted",
}

# Resource type → namespace prefix. Anything not in here is skipped
# (the "internal" rows like ``audit_forward_target`` /
# ``platform_settings`` shouldn't fire typed events for downstream
# automation; operators who want those wire audit-forward instead).
_RESOURCE_NAMESPACE: dict[str, str] = {
    # IPAM
    "ip_space": "space",
    "ip_block": "block",
    "subnet": "subnet",
    "ip_address": "ip",
    "nat_mapping": "ipam.nat",
    "subnet_plan": "ipam.plan",
    "address_set": "ipam.address_set",
    # DNS
    "dns_zone": "dns.zone",
    "dns_record": "dns.record",
    "dns_server": "dns.server",
    "dns_server_group": "dns.group",
    "dns_pool": "dns.pool",
    "dns_pool_member": "dns.pool.member",
    "dns_view": "dns.view",
    "dns_blocklist": "dns.blocklist",
    "tsig_key": "dns.tsig",
    # DHCP
    "dhcp_scope": "dhcp.scope",
    "dhcp_server": "dhcp.server",
    "dhcp_server_group": "dhcp.group",
    "dhcp_pool": "dhcp.pool",
    "dhcp_static_assignment": "dhcp.static",
    "dhcp_lease": "dhcp.lease",
    "dhcp_mac_block": "dhcp.macblock",
    # VLAN / network
    "vlan": "vlan",
    "router": "router",
    # Auth
    "user": "auth.user",
    "group": "auth.group",
    "role": "auth.role",
    "auth_provider": "auth.provider",
    # Integrations
    "kubernetes_cluster": "integration.kubernetes",
    "docker_host": "integration.docker",
    "proxmox_node": "integration.proxmox",
    "tailscale_tenant": "integration.tailscale",
    # Backup + restore (issue #117 Phase 3)
    "platform": "system",
    "backup_target": "backup.target",
    # Appliance management (issue #134 Phase 4)
    "appliance_certificate": "appliance.tls",
    # Fleet firewall (issue #285 Phase 3)
    "firewall_policy": "firewall.policy",
    "firewall_rule": "firewall.rule",
    "firewall_alias": "firewall.alias",
    # NOTE: ``change_request`` (#62) is deliberately NOT here. Its lifecycle
    # uses non-CRUD verbs (requested / approved / rejected / cancelled /
    # executed / failed / expired), so a namespace entry would make the
    # catalog advertise the never-fired change_request.created/updated/deleted
    # trio. Instead every change_request event is an explicit
    # _SPECIAL_EVENT_MAP row below — checked before this map at publish time
    # AND unioned into the event-type catalog.
}


# Direct ``(action, resource_type)`` → event-name overrides for cases
# where the regular ``namespace.verb`` synthesis produces an awkward
# name. Backup is the headline use case: scheduled runs land as
# ``backup_target_run_success`` audit rows but operators want to
# subscribe to ``system.backup_completed``.
_SPECIAL_EVENT_MAP: dict[tuple[str, str], str] = {
    ("backup_created", "platform"): "system.backup_completed",
    ("backup_restored", "platform"): "system.restore_performed",
    ("backup_target_run_success", "backup_target"): "system.backup_completed",
    ("backup_target_run_failed", "backup_target"): "system.backup_failed",
    ("backup_restored", "backup_target"): "system.restore_performed",
    # Factory reset (issue #116). The synthetic
    # ``factory_reset_performed`` audit row is inserted by the
    # runner via raw asyncpg (not the SQLAlchemy session) so the
    # publisher's flush hook doesn't see it. The endpoint also
    # writes a separate session-flush audit row so the event
    # fires through the standard pipeline.
    ("factory_reset_performed", "platform"): "system.factory_reset",
    # Appliance certificate lifecycle — beyond the auto-derived
    # appliance.tls.{created,updated,deleted}, the operator-driven
    # transitions get distinct event names so external subscribers
    # can wire e.g. "alert me on activation" without false positives
    # from upload-without-activate.
    ("activate_certificate", "appliance_certificate"): "appliance.tls.activated",
    ("generate_csr", "appliance_certificate"): "appliance.tls.csr_generated",
    ("import_signed_cert", "appliance_certificate"): "appliance.tls.csr_signed",
    # Appliance pairing-code lifecycle (issue #169 Phase 5). Maps the
    # audit ``action`` strings to clean event names downstream
    # subscribers can pattern-match on — e.g. wire a Slack webhook to
    # ``appliance.pairing_code.claimed`` to celebrate the moment a new
    # agent finishes joining. ``consume_denied`` is deliberately left
    # out: it's high-frequency noise (every wrong-code attempt fires
    # one) and operators who actually want it can read the audit log.
    ("appliance.pairing_code_created", "pairing_code"): "appliance.pairing_code.created",
    ("appliance.pairing_code_claimed", "pairing_code"): "appliance.pairing_code.claimed",
    ("appliance.pairing_code_revoked", "pairing_code"): "appliance.pairing_code.revoked",
    # Multi-node rolling upgrade orchestrator lifecycle (#296 Phase H).
    # The orchestrator writes AuditLog rows with ``action=upgrade.<verb>``
    # + ``resource_type='system_upgrade_run'`` on every state transition;
    # this map collapses the redundant ``upgrade.upgrade.<verb>`` that
    # the auto-derivation would produce into clean
    # ``system.upgrade.<verb>`` event names downstream subscribers can
    # pattern-match on.
    ("upgrade.planned", "system_upgrade_run"): "system.upgrade.planned",
    ("upgrade.started", "system_upgrade_run"): "system.upgrade.started",
    ("upgrade.succeeded", "system_upgrade_run"): "system.upgrade.succeeded",
    ("upgrade.halted", "system_upgrade_run"): "system.upgrade.halted",
    ("upgrade.resumed", "system_upgrade_run"): "system.upgrade.resumed",
    ("upgrade.aborted", "system_upgrade_run"): "system.upgrade.aborted",
    # The orchestrator's three failure-path transitions all fold into
    # the single ``system.upgrade.failed`` event so downstream
    # subscribers wire one webhook for "the upgrade failed; go
    # investigate" rather than three separate ones. The audit row's
    # ``action`` + ``new_value.failure_category`` (Phase F) tell the
    # operator which subtype + which node + what the next step is.
    ("upgrade.failed", "system_upgrade_run"): "system.upgrade.failed",
    ("upgrade.node_failed", "system_upgrade_run"): "system.upgrade.failed",
    ("upgrade.chart_bump_failed", "system_upgrade_run"): "system.upgrade.failed",
    ("upgrade.post_upgrade_verify_failed", "system_upgrade_run"): "system.upgrade.failed",
    # Approval workflow lifecycle (#62). The service layer writes plain-verb
    # audit actions (requested / approved / …); without these explicit
    # entries the auto-derivation still yields ``change_request.<verb>`` (the
    # action passes through as the verb), but the event-type CATALOG
    # enumeration only knows the create/update/delete trio per namespace — so
    # it would advertise the never-fired change_request.created/updated/deleted
    # and miss the real lifecycle. Listing them here makes them authoritative
    # AND surfaces them in the catalog (which unions _SPECIAL_EVENT_MAP.values).
    ("requested", "change_request"): "change_request.requested",
    ("approved", "change_request"): "change_request.approved",
    ("rejected", "change_request"): "change_request.rejected",
    ("cancelled", "change_request"): "change_request.cancelled",
    ("executed", "change_request"): "change_request.executed",
    ("failed", "change_request"): "change_request.failed",
    ("expired", "change_request"): "change_request.expired",
    # Self-governance break-glass (#62). A superadmin forced a protected
    # control change (disable module / disable-delete-or-weaken a policy /
    # unlock) past the two-person gate. HIGH-severity by intent — there is no
    # severity column, so this distinct event name is the signal operators
    # wire a dedicated alert / SIEM rule on. Special-map-only (like
    # change_request): no _RESOURCE_NAMESPACE entry for ``approval_control``.
    ("approvals.break_glass", "approval_control"): "governance.break_glass",
    # New-device watch (issue #459). A never-before-seen MAC was observed
    # (``device.first_seen``) or an operator dismissed one (``device.acknowledged``).
    # Special-map-only (like change_request): ``ip_mac_observation`` has no
    # _RESOURCE_NAMESPACE entry, so these names are authoritative here AND
    # unioned into the event-type catalog. first_seen is the real-time
    # "something new joined" signal external automation/SIEM subscribes to.
    ("first_seen", "ip_mac_observation"): "device.first_seen",
    ("acknowledged", "ip_mac_observation"): "device.acknowledged",
}


def _audit_to_event_type(action: str, resource_type: str) -> str | None:
    """Translate ``(action, resource_type)`` → typed event name."""
    special = _SPECIAL_EVENT_MAP.get((action, resource_type))
    if special is not None:
        return special
    namespace = _RESOURCE_NAMESPACE.get(resource_type)
    if namespace is None:
        return None
    verb = _VERB_MAP.get(action)
    if verb is None:
        # Specialised verb that didn't fit the create/update/delete trio.
        # Pass through with the action name itself ("bulk_allocate",
        # "resize", "stamp_discovered", etc) so the event type is
        # readable and operators can subscribe to specific power-user
        # events.
        verb = action
    return f"{namespace}.{verb}"


def _serialize_audit(row: AuditLog, event_type: str) -> dict[str, Any]:
    """Render the JSON body the receiver sees."""
    return {
        "event_id": str(row.id),
        "event_type": event_type,
        "occurred_at": (row.timestamp or datetime.now(UTC)).isoformat(),
        "actor": {
            "user_id": str(row.user_id) if row.user_id else None,
            "display_name": row.user_display_name,
            "auth_source": row.auth_source,
        },
        "resource": {
            "type": row.resource_type,
            "id": row.resource_id,
            "display": row.resource_display,
        },
        "action": row.action,
        "result": row.result,
        "old_value": row.old_value,
        "new_value": row.new_value,
        "changed_fields": list(row.changed_fields or []),
    }


# ── Subscription matching ──────────────────────────────────────────────────


def _subscription_matches(sub: EventSubscription, event_type: str) -> bool:
    """``event_types`` empty / NULL = subscribe to everything."""
    types = sub.event_types
    if not types:
        return True
    return event_type in types


# ── Ephemeral session (mirrors audit_forward._ephemeral_session) ──────────


@asynccontextmanager
async def _ephemeral_session() -> AsyncIterator[AsyncSession]:
    """Short-lived engine + session used by the after-commit publisher.

    Why a fresh engine per dispatch — see
    ``audit_forward._ephemeral_session``: in FastAPI we'd pin to the
    request loop, in Celery the loop is per-task. NullPool keeps the
    connection lifetime explicit; the cost is one fresh
    connection/dispatch which is fine for audit-rate write volumes.
    """
    engine = create_async_engine(
        _app_settings.database_url,
        poolclass=NullPool,
        echo=False,
    )
    try:
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session
    finally:
        await engine.dispose()


# ── Outbox writer ──────────────────────────────────────────────────────────


async def _publish_outbox_rows(snapshots: list[dict[str, Any]]) -> None:
    """Translate audit snapshots → typed events → outbox rows.

    Called after the commit through ``after_commit_dispatch.dispatch``
    (the request loop in the api, a per-process background loop in a
    Celery worker — #1168), so a failure here doesn't roll back the
    parent transaction — at worst the event is dropped (logged at
    warning).
    """
    if not snapshots:
        return
    try:
        async with _ephemeral_session() as session:
            res = await session.execute(
                select(EventSubscription).where(EventSubscription.enabled.is_(True))
            )
            subs = list(res.scalars().all())
            if not subs:
                return

            now = datetime.now(UTC)
            written = 0
            for snap in snapshots:
                event_type = snap["event_type"]
                payload = snap["payload"]
                for sub in subs:
                    if not _subscription_matches(sub, event_type):
                        continue
                    session.add(
                        EventOutbox(
                            subscription_id=sub.id,
                            event_type=event_type,
                            payload=payload,
                            state="pending",
                            attempts=0,
                            next_attempt_at=now,
                        )
                    )
                    written += 1
            if written:
                await session.commit()
                logger.debug(
                    "event_publisher_outbox_written",
                    rows=written,
                    sub_count=len(subs),
                )
    except Exception as exc:  # noqa: BLE001 — never let publisher errors leak
        logger.warning(
            "event_publisher_dispatch_failed",
            error=str(exc),
            count=len(snapshots),
        )


# ── Listener wiring ────────────────────────────────────────────────────────


def _register_session_listener() -> None:
    """Install the ``after_flush`` + ``after_commit`` listeners.

    Same pattern as ``audit_forward`` so the two surfaces share the
    same cadence: capture audit rows in flush, dispatch in commit.
    Idempotent — SQLAlchemy de-dups listener identity.
    """

    @event.listens_for(AsyncSession.sync_session_class, "after_flush")
    def _after_flush(session: Any, flush_context: Any) -> None:  # noqa: ARG001
        new_audits = [obj for obj in session.new if isinstance(obj, AuditLog)]
        if not new_audits:
            return
        snapshots = getattr(session, _PENDING_ATTR, None) or []
        for row in new_audits:
            event_type = _audit_to_event_type(row.action, row.resource_type)
            if event_type is None:
                continue
            snapshots.append(
                {
                    "event_type": event_type,
                    "payload": _serialize_audit(row, event_type),
                }
            )
        setattr(session, _PENDING_ATTR, snapshots)

    @event.listens_for(AsyncSession.sync_session_class, "after_commit")
    def _after_commit(session: Any) -> None:
        snapshots = getattr(session, _PENDING_ATTR, None)
        if not snapshots:
            return
        setattr(session, _PENDING_ATTR, [])
        # #1168 — not a bare ``loop.create_task``: in a Celery task the loop
        # is the task's own ``asyncio.run``, which cancelled this write as it
        # returned. ``dispatch`` uses a per-process background loop there.
        dispatch(
            "event_publisher",
            lambda: _publish_outbox_rows(snapshots),
            count=len(snapshots),
        )

    @event.listens_for(AsyncSession.sync_session_class, "after_rollback")
    def _after_rollback(session: Any) -> None:
        if getattr(session, _PENDING_ATTR, None):
            setattr(session, _PENDING_ATTR, [])


_register_session_listener()


# Public for the task worker / smoke tests.
__all__ = [
    "_audit_to_event_type",
    "_serialize_audit",
    "_subscription_matches",
    "_publish_outbox_rows",
]

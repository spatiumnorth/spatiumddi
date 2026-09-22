"""Mark DNS agent bundles dirty IN the transaction that changes their inputs (#1111).

The agent config bundle is rendered once per (server, watermark) and served
from ``dns_agent_bundle``. Something has to say when a stored bundle is no
longer current, and it has to be something that cannot be lost: the failure
mode of getting this wrong is an agent serving stale config while every
surface reports converged — the #882 class, the worst one in the system.

So the signal is not the wake bus. ``publish_wake`` is fire-and-forget by
design (#358: a Redis outage must never 500 a CRUD write) and every one of
its ~130 publish sites is a place a new mutation path can forget. Instead an
``after_flush`` listener looks at what the flush actually wrote — the
session's ``new`` / ``dirty`` / ``deleted`` lists — maps every model the
bundle reads to the servers whose bundle it feeds, and issues one
``UPDATE dns_server SET bundle_dirty_seq = bundle_dirty_seq + 1`` on the
flush's own connection. The bump commits or rolls back WITH the change.

Over-triggering is the safe direction and the only one this takes: a
spurious bump costs one render, exactly as a spurious wake costs one
rebuild today. Under-triggering is prevented by construction for every
contributor written through the ORM; the render-missing sweep in
``app.tasks.agent_bundles`` is the belt and braces for the enqueue.

What does NOT bump, deliberately:

* a ``DNSRecordOp`` state transition (``pending`` → ``in_flight`` →
  ``applied``) — that is the ops lifecycle the long-poll and the
  heartbeat drive, not a config change; only a NEW op row counts, so an
  op created without a record change (a DNSSEC op, a restore) still
  forces a fresher snapshot for the ops-page gate;
* a ``DNSServer`` heartbeat / status / apply-verdict / ``last_config_etag``
  write — only the columns the bundle reads are checked, with real
  attribute history, or every heartbeat would trigger a render.

After commit the marked servers' renders are enqueued (best effort — the
sweep covers a lost broker message within 30 s).
"""

from __future__ import annotations

import asyncio
import itertools
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import event, or_, select, true, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import attributes

from app.config import settings
from app.drivers.dns import AGENTLESS_DRIVERS
from app.models.appliance import ApplianceCertificate
from app.models.dns import (
    DNSAcl,
    DNSAclEntry,
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSPool,
    DNSPoolMember,
    DNSRecord,
    DNSRecordOp,
    DNSSECPolicy,
    DNSServer,
    DNSServerGroup,
    DNSServerOptions,
    DNSTSIGKey,
    DNSView,
    DNSZone,
    DNSZoneUpdateAcl,
)
from app.models.settings import PlatformSettings

logger = structlog.get_logger(__name__)

_PENDING_ATTR = "_spatium_bundle_dirty_server_ids"

# Contributors keyed straight by group_id.
_GROUP_MODELS: tuple[type, ...] = (DNSZone, DNSView, DNSAcl, DNSServerOptions, DNSTSIGKey)
# Contributors keyed by zone_id (resolved to the zone's group in the flush).
_ZONE_MODELS: tuple[type, ...] = (DNSRecord, DNSZoneUpdateAcl)
# Contributors every agent-based server reads: the platform singletons the
# snmp / ntp blocks render from, DNSSEC policies, the DoT/DoH certificate,
# blocklists (attached to groups and views through association tables the
# ORM folds into the parent's flush), and pools (geo steering).
_GLOBAL_MODELS: tuple[type, ...] = (
    PlatformSettings,
    DNSSECPolicy,
    ApplianceCertificate,
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSPool,
    DNSPoolMember,
)
# DNSServer columns a SIBLING's bundle reads (the catalog producer pick:
# is_primary / driver / host, and the group a server belongs to) — bump the
# whole group, the old one too on a move.
_SERVER_GROUP_COLUMNS: tuple[str, ...] = ("group_id", "driver", "host", "is_primary")
# DNSServer columns only the server's OWN bundle reads.
_SERVER_SELF_COLUMNS: tuple[str, ...] = (
    "is_enabled",
    "desired_appliance_version",
    "desired_slot_image_url",
    "reboot_requested",
)


@dataclass
class Affected:
    """What one flush touched, before resolution to server rows."""

    groups: set[uuid.UUID] = field(default_factory=set)
    servers: set[uuid.UUID] = field(default_factory=set)
    zones: set[uuid.UUID] = field(default_factory=set)
    acls: set[uuid.UUID] = field(default_factory=set)
    everyone: bool = False

    def is_empty(self) -> bool:
        return not (self.groups or self.servers or self.zones or self.acls or self.everyone)


def _changed(obj: Any, column: str) -> tuple[bool, list[Any]]:
    """Whether ``column`` has a net change on ``obj``, plus its old values."""
    try:
        hist = attributes.get_history(obj, column)
    except Exception:  # noqa: BLE001 — an unmapped attribute name; treat as unchanged
        return False, []
    return bool(hist.has_changes()), list(hist.deleted or [])


def collect_affected(session: Any) -> Affected:
    """PURE over the session's flush lists: which bundles this flush dirtied."""
    aff = Affected()
    new = session.new
    deleted = session.deleted
    for obj in itertools.chain(new, session.dirty, deleted):
        if isinstance(obj, DNSRecordOp):
            if obj in new:
                aff.servers.add(obj.server_id)
        elif isinstance(obj, DNSServer):
            if obj in new or obj in deleted:
                aff.groups.add(obj.group_id)
                continue
            for col in _SERVER_GROUP_COLUMNS:
                changed, old = _changed(obj, col)
                if changed:
                    aff.groups.add(obj.group_id)
                    if col == "group_id":
                        aff.groups.update(v for v in old if v is not None)
            for col in _SERVER_SELF_COLUMNS:
                if _changed(obj, col)[0]:
                    aff.servers.add(obj.id)
        elif isinstance(obj, DNSServerGroup):
            aff.groups.add(obj.id)
        elif isinstance(obj, _GROUP_MODELS):
            gid = getattr(obj, "group_id", None)
            if gid is not None:
                aff.groups.add(gid)
            # A zone moved between groups (server_move / zone_move): the
            # group it left must re-render without it.
            changed, old = _changed(obj, "group_id")
            if changed:
                aff.groups.update(v for v in old if v is not None)
        elif isinstance(obj, _ZONE_MODELS):
            zid = getattr(obj, "zone_id", None)
            if zid is not None:
                aff.zones.add(zid)
        elif isinstance(obj, DNSAclEntry):
            aid = getattr(obj, "acl_id", None)
            if aid is not None:
                aff.acls.add(aid)
        elif isinstance(obj, _GLOBAL_MODELS):
            aff.everyone = True
    return aff


def mark_dirty(session: Any, aff: Affected) -> list[uuid.UUID]:
    """Bump ``bundle_dirty_seq`` for every agent-based server ``aff`` names,
    on the session's current connection (inside the same transaction).
    Returns the bumped server ids.

    A Core UPDATE, so ``DNSServer`` instances already in the session keep
    their loaded value until refreshed — the long-poll refreshes on every
    wake and the render reads the row fresh, which is where it matters.
    """
    if aff.is_empty():
        return []
    conn = session.connection()
    groups: set[uuid.UUID] = set(aff.groups)
    if aff.zones:
        groups.update(
            conn.execute(select(DNSZone.group_id).where(DNSZone.id.in_(list(aff.zones))))
            .scalars()
            .all()
        )
    if aff.acls:
        groups.update(
            g
            for g in conn.execute(select(DNSAcl.group_id).where(DNSAcl.id.in_(list(aff.acls))))
            .scalars()
            .all()
            if g is not None
        )
    if aff.everyone:
        scope = true()
    else:
        conds = []
        if groups:
            conds.append(DNSServer.group_id.in_(list(groups)))
        if aff.servers:
            conds.append(DNSServer.id.in_(list(aff.servers)))
        if not conds:
            return []
        scope = or_(*conds)
    stmt = (
        update(DNSServer)
        .where(scope, DNSServer.driver.not_in(list(AGENTLESS_DRIVERS)))
        .values(bundle_dirty_seq=DNSServer.bundle_dirty_seq + 1)
        .returning(DNSServer.id)
    )
    ids = list(conn.execute(stmt).scalars().all())
    if ids:
        logger.debug(
            "dns_agent_bundle_marked_dirty",
            servers=len(ids),
            groups=len(groups),
            everyone=aff.everyone,
        )
    return ids


# ── Enqueue after commit ───────────────────────────────────────────────────


def _enqueue_sync(server_ids: list[str]) -> None:
    """Best effort: one broker publish per server. A failure is logged and
    left to the render-missing sweep (30 s) — never raised into whatever
    committed."""
    if not settings.dns_agent_bundle_enqueue_renders:
        return
    try:
        from app.tasks.agent_bundles import (  # noqa: PLC0415 — tasks import services
            enqueue_render,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("dns_agent_bundle_enqueue_unavailable", error=str(exc))
        return
    for sid in server_ids:
        if not enqueue_render(sid):
            # One broker failure means every publish in this batch fails; the
            # sweep picks the rest up. Don't hammer a dead broker.
            return


async def enqueue_renders(server_ids: Iterable[uuid.UUID | str]) -> None:
    ids = [str(s) for s in server_ids]
    if ids:
        await asyncio.to_thread(_enqueue_sync, ids)


def schedule_renders(server_ids: Iterable[uuid.UUID | str]) -> None:
    """Enqueue from wherever the commit happened: a running loop (the api,
    a Celery task's ``asyncio.run``) gets a task; no loop runs inline."""
    ids = [str(s) for s in server_ids]
    if not ids:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _enqueue_sync(ids)
        return
    loop.create_task(enqueue_renders(ids))


# ── Listener wiring ────────────────────────────────────────────────────────


def _register_session_listener() -> None:
    """Install the ``after_flush`` / ``after_commit`` / ``after_rollback``
    listeners once (SQLAlchemy de-dups listener identity)."""

    @event.listens_for(AsyncSession.sync_session_class, "after_flush")
    def _after_flush(session: Any, flush_context: Any) -> None:  # noqa: ARG001
        aff = collect_affected(session)
        if aff.is_empty():
            return
        try:
            ids = mark_dirty(session, aff)
        except Exception:  # noqa: BLE001 — never turn a CRUD write into a 500
            logger.exception("dns_agent_bundle_mark_dirty_failed")
            return
        if ids:
            pending = getattr(session, _PENDING_ATTR, None) or set()
            pending.update(ids)
            setattr(session, _PENDING_ATTR, pending)

    @event.listens_for(AsyncSession.sync_session_class, "after_commit")
    def _after_commit(session: Any) -> None:
        pending = getattr(session, _PENDING_ATTR, None)
        if not pending:
            return
        setattr(session, _PENDING_ATTR, set())
        schedule_renders(pending)

    @event.listens_for(AsyncSession.sync_session_class, "after_rollback")
    def _after_rollback(session: Any) -> None:
        if getattr(session, _PENDING_ATTR, None):
            setattr(session, _PENDING_ATTR, set())


_register_session_listener()


__all__ = [
    "Affected",
    "collect_affected",
    "enqueue_renders",
    "mark_dirty",
    "schedule_renders",
]

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

EVERY PROCESS THAT WRITES DNS ROWS MUST LOAD THIS MODULE. The listener is
installed by importing it; ``app.main`` does that for the api and
``app.celery_app`` for the worker and beat. A process without it commits
its changes unmarked — the stored bundle stays "current", the long-poll
keeps serving it, and because the ops page is gated to that bundle's
snapshot the new ops never ship either (pool failover, ACME DNS-01,
lease-expiry DDNS, IPAM auto-sync: every write a Celery task makes).
``tests/test_dns_agent_bundle_dirty.py`` pins the worker's import graph.

Two ways to get this wrong, and the rules below exist for both:

* **Under-marking** serves stale config as current. Only ORM unit-of-work
  writes are seen, so a Core ``insert()`` / ``update()`` / ``delete()`` on a
  bundle input must call ``mark_bundles_dirty`` itself.
* **Over-marking** is not free at scale. A stale bundle is never served —
  not even its ops page — and renders run one at a time fleet-wide, so a
  mark that arrives faster than a render finishes keeps the bundle stale
  forever and the agent receives nothing. A group of a million rows renders
  in about a minute; a write every 15–30 s that the bundle never reads
  (a health-check timestamp, a beat task's ``*_last_run_at``) would freeze
  it. So a DIRTY object marks only when a column the bundle renders has a
  net change (``_rendered_change``); new and deleted rows always mark.

What does NOT mark, deliberately:

* a ``DNSRecordOp`` state transition (``pending`` → ``in_flight`` →
  ``applied``) — that is the ops lifecycle the long-poll and the
  heartbeat drive, not a config change; only a NEW op row counts, so an
  op created without a record change (a DNSSEC op, a restore) still
  forces a fresher snapshot for the ops-page gate;
* a ``DNSServer`` heartbeat / status / apply-verdict / ``last_config_etag``
  write — only the columns the bundle reads are checked, with real
  attribute history, or every heartbeat would trigger a render;
* bookkeeping columns the bundle never renders (``_NOT_RENDERED``), and on
  the two models where the bundle reads a small known set, anything outside
  it (``_RENDERED_ONLY`` / ``_RENDERED_PREFIXES``).

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
from sqlalchemy import event, func, or_, select, true, update
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.models.ipam import Subnet
from app.models.ownership import Site
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
# Geo steering (``pool_geo._site_cidrs``) resolves a pool member's Site to
# the CIDRs of the live subnets linked to it, so a subnet's link, prefix or
# soft-delete state is a bundle input whenever it sits in a Site.
_SUBNET_GEO_COLUMNS: tuple[str, ...] = ("site_id", "network", "deleted_at")
# Every model handled by the generic branches of ``collect_affected`` (the
# ones filtered by ``_rendered_change``). Anything else is skipped before its
# history is read — the listener runs on every flush in the process.
_CONTRIBUTORS: tuple[type, ...] = (
    DNSServerGroup,
    *_GROUP_MODELS,
    *_ZONE_MODELS,
    DNSAclEntry,
    *_GLOBAL_MODELS,
)

# Written on every model without the rendered output changing.
_ALWAYS_BOOKKEEPING: frozenset[str] = frozenset({"created_at", "modified_at", "updated_at"})
# Columns the bundle never renders that something writes on a schedule. A
# dirty object whose only net change is here does not mark. Leaving a column
# out of this map costs renders; putting a RENDERED column in it serves stale
# config, so a column goes here only when nothing under
# ``render_bundle_body`` reads it.
_NOT_RENDERED: dict[type, frozenset[str]] = {
    # The agents' /dnssec-state report stamps these after every structural
    # reload; the DS set is for the operator and the registrar, not BIND.
    DNSZone: frozenset({"dnssec_synced_at", "dnssec_ds_records", "last_pushed_at"}),
    # The 30 s pool health check (``tasks.dns_pool_healthcheck``).
    DNSPool: frozenset({"last_checked_at", "next_check_at"}),
    # Feed refresh bookkeeping; the entries themselves are their own rows.
    DNSBlockList: frozenset(
        {"last_synced_at", "last_sync_status", "last_sync_error", "entry_count"}
    ),
}
# Models where the bundle reads a small, known set of columns: only these
# mark. A pool member's health, address and weight reach the bundle as
# records (``pool_apply`` creates and deletes them, and a record marks its
# zone's group); geo steering reads only its scope.
_RENDERED_ONLY: dict[type, frozenset[str]] = {
    DNSPoolMember: frozenset({"pool_id", "site_id", "serving_cidrs"}),
}
# The platform singleton is read only by ``snmp_bundle`` / ``ntp_bundle``,
# whose every column is prefixed — pinned by a test that scans both
# renderers. Its other few hundred columns (release check, lease-pull and
# sync ``*_last_run_at`` stamps written by beat tasks) must not mark.
_RENDERED_PREFIXES: dict[type, tuple[str, ...]] = {
    PlatformSettings: ("snmp_", "ntp_"),
}


@dataclass
class Affected:
    """What one flush touched, before resolution to server rows."""

    groups: set[uuid.UUID] = field(default_factory=set)
    servers: set[uuid.UUID] = field(default_factory=set)
    zones: set[uuid.UUID] = field(default_factory=set)
    acls: set[uuid.UUID] = field(default_factory=set)
    # Sites whose subnet set changed — resolved to the groups whose pools
    # have a member scoped to one of them.
    sites: set[uuid.UUID] = field(default_factory=set)
    everyone: bool = False

    def is_empty(self) -> bool:
        return not (
            self.groups or self.servers or self.zones or self.acls or self.sites or self.everyone
        )


def _changed(obj: Any, column: str) -> tuple[bool, list[Any]]:
    """Whether ``column`` has a net change on ``obj``, plus its old values.

    Reads the pre-flush history passively: an attribute that was never
    loaded is reported unchanged rather than loaded, so this never issues a
    SELECT from inside the flush (or tries to refresh a row just deleted).
    """
    try:
        hist = sa_inspect(obj).attrs[column].history
    except KeyError:  # an unmapped attribute name; treat as unchanged
        return False, []
    return bool(hist.has_changes()), list(hist.deleted or [])


def _rendered_change(obj: Any) -> bool:
    """Whether a DIRTY ``obj`` changed anything the bundle renders."""
    state = sa_inspect(obj)
    cls = type(obj)
    only = _RENDERED_ONLY.get(cls)
    prefixes = _RENDERED_PREFIXES.get(cls)
    skip = _ALWAYS_BOOKKEEPING | _NOT_RENDERED.get(cls, frozenset())
    for key in state.mapper.attrs.keys():
        if only is not None and key not in only:
            continue
        if prefixes is not None and not key.startswith(prefixes):
            continue
        if key in skip:
            continue
        if state.attrs[key].history.has_changes():
            return True
    return False


def collect_affected(session: Any) -> Affected:
    """PURE over the session's flush lists: which bundles this flush dirtied."""
    aff = Affected()
    new = session.new
    deleted = session.deleted
    for obj in itertools.chain(new, session.dirty, deleted):
        created_or_deleted = obj in new or obj in deleted
        if isinstance(obj, DNSRecordOp):
            if obj in new:
                aff.servers.add(obj.server_id)
        elif isinstance(obj, DNSServer):
            if created_or_deleted:
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
        elif isinstance(obj, Subnet):
            geo = created_or_deleted
            old_sites: list[Any] = []
            for col in _SUBNET_GEO_COLUMNS:
                changed, old = _changed(obj, col)
                if changed:
                    geo = True
                    if col == "site_id":
                        old_sites = old
            if geo:
                current = sa_inspect(obj).dict.get("site_id")
                aff.sites.update(s for s in (current, *old_sites) if s is not None)
        elif isinstance(obj, Site):
            # A Site delete nulls ``dns_pool_member.site_id`` in the database
            # (ON DELETE SET NULL), after which nothing can say which pools
            # scoped to it. Rare enough to mark everyone.
            if obj in deleted:
                aff.everyone = True
        elif not isinstance(obj, _CONTRIBUTORS):
            continue
        elif not created_or_deleted and not _rendered_change(obj):
            # A contributor written with no rendered net change — a scheduled
            # bookkeeping stamp, or an assignment of the same value
            # (``session.dirty`` is optimistic).
            continue
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
            # A record moved between zones in place (the Kubernetes
            # reconciler does this): the zone it left re-renders too.
            changed, old = _changed(obj, "zone_id")
            if changed:
                aff.zones.update(v for v in old if v is not None)
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
    if aff.sites and not aff.everyone:
        groups.update(
            conn.execute(
                select(DNSPool.group_id)
                .join(DNSPoolMember, DNSPoolMember.pool_id == DNSPool.id)
                .where(DNSPoolMember.site_id.in_(list(aff.sites)))
            )
            .scalars()
            .all()
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
        .values(
            bundle_dirty_seq=DNSServer.bundle_dirty_seq + 1,
            # When the stored bundle first fell behind. Kept across further
            # marks; the store clears it (or restarts it, when changes landed
            # mid-render). What the stalled-render alert measures.
            bundle_dirty_at=func.coalesce(DNSServer.bundle_dirty_at, func.now()),
        )
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


def _remember(session: Any, ids: Iterable[uuid.UUID]) -> None:
    """Queue ``ids`` for the render enqueue that follows the commit."""
    ids = list(ids)
    if not ids:
        return
    pending = getattr(session, _PENDING_ATTR, None) or set()
    pending.update(ids)
    setattr(session, _PENDING_ATTR, pending)


async def mark_bundles_dirty(
    db: AsyncSession,
    *,
    zone_ids: Iterable[uuid.UUID] = (),
    group_ids: Iterable[uuid.UUID] = (),
    server_ids: Iterable[uuid.UUID] = (),
    everyone: bool = False,
) -> list[uuid.UUID]:
    """Mark bundles dirty for a write the listener cannot see.

    The listener sees ORM unit-of-work writes only. A Core ``insert()`` /
    ``update()`` / ``delete()`` on a bundle input bypasses it, and the
    stored bundle then stays "current" without the change — so every such
    site calls this in the same transaction. Same semantics as the
    listener: commits or rolls back with the caller's transaction, and the
    renders are enqueued after the commit.
    """
    aff = Affected(
        zones={z for z in zone_ids if z is not None},
        groups={g for g in group_ids if g is not None},
        servers={s for s in server_ids if s is not None},
        everyone=everyone,
    )

    def _run(session: Any) -> list[uuid.UUID]:
        ids = mark_dirty(session, aff)
        _remember(session, ids)
        return ids

    return await db.run_sync(_run)


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


def _after_flush(session: Any, flush_context: Any) -> None:  # noqa: ARG001
    aff = collect_affected(session)
    if aff.is_empty():
        return
    # Deliberately not guarded. A mark that fails leaves the change without
    # its bump, and a change without its bump is stale config served as
    # current — the failure this module exists to rule out. A database
    # error here has already aborted the transaction, so the write fails
    # either way; raising it here names the real cause instead of the
    # "current transaction is aborted" the commit would report later.
    _remember(session, mark_dirty(session, aff))


def _after_commit(session: Any) -> None:
    pending = getattr(session, _PENDING_ATTR, None)
    if not pending:
        return
    setattr(session, _PENDING_ATTR, set())
    schedule_renders(pending)


def _after_rollback(session: Any) -> None:
    if getattr(session, _PENDING_ATTR, None):
        setattr(session, _PENDING_ATTR, set())


_LISTENERS = (
    ("after_flush", _after_flush),
    ("after_commit", _after_commit),
    ("after_rollback", _after_rollback),
)


def install() -> None:
    """Attach the listeners to every session class. Idempotent.

    Runs on import; ``app.main`` and ``app.celery_app`` import this module
    so the api, the worker and beat all carry it.
    """
    target = AsyncSession.sync_session_class
    for name, fn in _LISTENERS:
        if not event.contains(target, name, fn):
            event.listen(target, name, fn)


def installed() -> bool:
    target = AsyncSession.sync_session_class
    return all(event.contains(target, name, fn) for name, fn in _LISTENERS)


install()


__all__ = [
    "Affected",
    "collect_affected",
    "enqueue_renders",
    "install",
    "installed",
    "mark_bundles_dirty",
    "mark_dirty",
    "schedule_renders",
]

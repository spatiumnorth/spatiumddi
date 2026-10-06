"""DNS background tasks (blocklist feed refresh, agent stale sweep, health checks)."""

from __future__ import annotations

import asyncio
import socket
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from app.celery_app import celery_app
from app.config import settings
from app.core.agent_wake import dns_group_channel, publish_wake
from app.models.dns import DNSBlockList, DNSBlockListEntry, DNSServer
from app.services.dns_blocklist import parse_feed_detailed
from app.services.feature_modules import is_module_enabled

# If an agent hasn't heartbeat'd in this long, we fall back to an active probe.
AGENT_STALE_AFTER = timedelta(seconds=120)
# Timeout for a SOA probe against the server.
DNS_PROBE_TIMEOUT = 3.0

logger = structlog.get_logger(__name__)


async def _refresh_blocklist_feed_async(list_id: str) -> dict[str, int | str]:
    """Core async logic for refresh_blocklist_feed, reusable from tests."""
    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return {"status": "disabled"}
            bl = (
                await db.execute(
                    select(DNSBlockList)
                    .where(DNSBlockList.id == list_id)
                    .options(
                        selectinload(DNSBlockList.server_groups),
                        selectinload(DNSBlockList.views),
                    )
                )
            ).scalar_one_or_none()
            if bl is None:
                return {"status": "not_found", "added": 0, "removed": 0}

            if not bl.feed_url:
                bl.last_sync_status = "error"
                bl.last_sync_error = "No feed_url configured"
                bl.last_synced_at = datetime.now(UTC)
                await db.commit()
                return {"status": "error", "added": 0, "removed": 0}

            try:
                async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
                    resp = await client.get(bl.feed_url)
                    resp.raise_for_status()
                    text = resp.text
            except (httpx.HTTPError, socket.gaierror) as e:
                # Transient — write the per-row error state then re-raise
                # so Celery's ``autoretry_for`` (configured on the task
                # below) backs off + retries. Issue #219 — pre-fix the
                # broad ``except`` swallowed every exception and the
                # task's ``max_retries=3`` was decorative.
                bl.last_sync_status = "error"
                bl.last_sync_error = f"Fetch failed: {e}"
                bl.last_synced_at = datetime.now(UTC)
                await db.commit()
                logger.warning(
                    "blocklist_feed_fetch_failed",
                    list_id=list_id,
                    error=str(e),
                )
                raise
            except Exception as e:  # noqa: BLE001
                # Permanent (parse error, unexpected shape) — same DB
                # shape but don't bubble; retrying won't help.
                bl.last_sync_status = "error"
                bl.last_sync_error = f"Fetch failed: {e}"
                bl.last_synced_at = datetime.now(UTC)
                await db.commit()
                logger.exception("blocklist_feed_fetch_failed", list_id=list_id, error=str(e))
                return {"status": "error", "added": 0, "removed": 0}

            parsed = parse_feed_detailed(text, bl.feed_format)
            domains = set(parsed.domains)
            wildcard = bool(bl.feed_entries_are_wildcard)

            # A `*.`-prefixed feed is DECLARING it means "and every
            # subdomain". Honouring an apex-only list setting against such
            # a feed is the operator's call, but doing it silently would
            # leave them wondering why subdomains still resolve.
            if not wildcard and parsed.wildcard_count:
                logger.warning(
                    "blocklist_feed_wildcard_intent_overridden",
                    list_id=list_id,
                    list_name=bl.name,
                    wildcard_lines=parsed.wildcard_count,
                    detail=(
                        "This feed publishes wildcard syntax, but the list is "
                        "set to apex-only, so subdomains of its entries are "
                        "NOT blocked. Enable 'Block subdomains' on the list if "
                        "that is not intended."
                    ),
                )

            # Load current feed-sourced entries
            existing_result = await db.execute(
                select(DNSBlockListEntry).where(
                    DNSBlockListEntry.list_id == bl.id,
                    DNSBlockListEntry.source == "feed",
                )
            )
            existing = {e.domain: e for e in existing_result.scalars().all()}

            # Compute diff
            to_add = domains - set(existing.keys())
            to_remove = set(existing.keys()) - domains

            for d in to_add:
                db.add(
                    DNSBlockListEntry(
                        list_id=bl.id,
                        domain=d,
                        entry_type="block",
                        source="feed",
                        # Per-list, defaulting on (#878 made it universal,
                        # #894 made it a choice): a list naming
                        # `tracker.example` normally means
                        # `cdn.tracker.example` too, which is what every
                        # consumer of these feeds does — but a
                        # host-specific feed wants apex-only.
                        is_wildcard=wildcard,
                    )
                )

            for d in to_remove:
                await db.delete(existing[d])

            # Recompute count — plain COUNT, no arithmetic on top: a query autoflushes
            # the pending adds and deletes, so the result ALREADY reflects
            # them. Adding ``len(to_add)`` on top double-counted every row on
            # a first sync — a 16k-domain feed reported 33k (#878). It also
            # loads ids instead of dragging every ORM row into memory, which
            # matters on the 460k-entry feeds.
            bl.entry_count = int(
                await db.scalar(
                    select(func.count())
                    .select_from(DNSBlockListEntry)
                    .where(DNSBlockListEntry.list_id == bl.id)
                )
                or 0
            )
            bl.last_synced_at = datetime.now(UTC)
            bl.last_sync_status = "success"
            bl.last_sync_error = None

            # Groups whose rendered config folds in this blocklist: groups it's
            # assigned to directly, plus the owning groups of any views it's
            # assigned to. Resolved before commit off the eager-loaded
            # relationships (no lazy access in async); published after.
            wake_group_ids: set[str] = {str(sg.id) for sg in bl.server_groups}
            wake_group_ids.update(str(v.group_id) for v in bl.views if v.group_id is not None)
            feed_changed = bool(to_add or to_remove)

            await db.commit()

            # Worker process — no request collector, so publish directly AFTER
            # commit, and only when the entry set actually changed (otherwise
            # the effective blocklist is identical and the bundle ETag is
            # unchanged, making a wake a wasted no-op rebuild).
            if feed_changed:
                for gid in wake_group_ids:
                    await publish_wake(dns_group_channel(gid))

            logger.info(
                "blocklist_feed_refreshed",
                list_id=list_id,
                added=len(to_add),
                removed=len(to_remove),
            )
            return {
                "status": "success",
                "added": len(to_add),
                "removed": len(to_remove),
            }
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.dns.refresh_blocklist_feed",
    bind=True,
    autoretry_for=(httpx.HTTPError, socket.gaierror),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
)
def refresh_blocklist_feed(self: object, list_id: str) -> dict[str, int | str]:  # type: ignore[type-arg]
    """Fetch feed_url, parse as hosts/domain/adblock list, sync entries with source=feed.

    Idempotent — safe to retry. Only manages entries with source="feed"; manual
    entries added by users are never touched.

    Issue #219 — ``autoretry_for=(httpx.HTTPError, socket.gaierror)`` +
    exponential backoff so transient feed-fetch failures retry up to 3
    times instead of giving up on the first hiccup. The async core
    re-raises those two classes after persisting the per-row error
    state to the DB; other exceptions stay swallowed (no retry —
    parse-shape failures don't get fixed by retrying).
    """
    logger.info("refresh_blocklist_feed_started", list_id=list_id)
    return asyncio.run(_refresh_blocklist_feed_async(list_id))


# ── Agent stale-sweep ──────────────────────────────────────────────────────────

AGENT_STALE_AFTER_SECONDS = 90  # 3× heartbeat interval per DNS_AGENT.md §4


async def _dns_agent_stale_sweep_async() -> dict[str, int]:
    """Mark agents stale when no heartbeat seen for AGENT_STALE_AFTER_SECONDS.

    Idempotent — only flips status for servers whose status is currently
    'active' but whose last_seen_at is beyond the threshold.
    """
    from datetime import timedelta

    from sqlalchemy import update

    from app.models.dns import DNSServer

    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                # Typed dict[str, int] — a "status" string would not type
                # check, and zero marked is the honest count anyway.
                return {"marked_unreachable": 0}
            cutoff = datetime.now(UTC) - timedelta(seconds=AGENT_STALE_AFTER_SECONDS)
            # Issue #182: paused servers are deliberately offline —
            # don't trip the heartbeat-stale state transition for them.
            # The Maintenance chip in the UI is the operator-meaningful
            # indicator while they're paused.
            res = await db.execute(
                update(DNSServer)
                .where(
                    DNSServer.status == "active",
                    DNSServer.last_seen_at.isnot(None),
                    DNSServer.last_seen_at < cutoff,
                    DNSServer.maintenance_mode.is_(False),
                )
                .values(status="unreachable")
                .returning(DNSServer.id)
            )
            changed = len(res.all())
            await db.commit()
            if changed:
                logger.info("dns_agent_stale_sweep", marked_unreachable=changed)
            return {"marked_unreachable": changed}
    finally:
        await engine.dispose()


@celery_app.task(name="app.tasks.dns.agent_stale_sweep")
def agent_stale_sweep() -> dict[str, int]:
    """Celery beat task — runs every 60s, flips stale agents to 'unreachable'."""
    return asyncio.run(_dns_agent_stale_sweep_async())


async def _probe_server_soa(host: str, port: int) -> bool:
    """Send an SOA query for "." to ``host:port`` using ``dnspython``.

    Returns True if any response is received, False otherwise. Kept deliberately
    minimal — a deep health driver for BIND9 lives in the Wave 2
    driver abstraction layer.
    """
    try:
        import dns.asyncquery
        import dns.message
        import dns.rdatatype
    except ImportError:  # dnspython optional — treat as unreachable
        logger.warning("dns_probe_dnspython_missing")
        return False

    try:
        msg = dns.message.make_query(".", dns.rdatatype.SOA)
        # Resolve hostname if needed (a.k.a. "10.0.0.5" also works)
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = host
        await dns.asyncquery.udp(msg, ip, port=port, timeout=DNS_PROBE_TIMEOUT)
        return True
    except Exception as exc:  # noqa: BLE001 — any failure = unreachable
        logger.debug("dns_probe_failed", host=host, port=port, error=str(exc))
        return False


async def _check_health(server_id: uuid.UUID) -> None:
    # Per-task engine — the shared AsyncSessionLocal binds to the first event
    # loop that touches it, which turns into "Future attached to a different
    # loop" errors when multiple Celery tasks share a worker. See the matching
    # pattern in ``app.tasks.dns_pull`` / ``app.tasks.dhcp_pull_leases``.
    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return
            from app.drivers.dns import get_driver, is_agentless  # noqa: PLC0415

            server = await db.get(DNSServer, server_id)
            if server is None:
                logger.info("dns_health_server_missing", server_id=str(server_id))
                return

            now = datetime.now(UTC)

            # User-disabled servers don't get probed — we set status="disabled"
            # so the UI can surface the explicit "not our doing" state instead
            # of flapping to "unreachable" because we stopped poking it.
            if not server.is_enabled:
                server.status = "disabled"
                server.last_health_check_at = now
                await db.commit()
                return

            new_status: str
            health_detail: str | None = None

            if is_agentless(server.driver):
                # Agentless drivers have no heartbeat — the control plane has
                # to do the poking. Cloud drivers and ``technitium_api`` check
                # the API they are driven through (``health_check`` on
                # ``CloudDNSDriverBase``, #1455); ``windows_dns`` doesn't
                # implement one yet and falls back to the raw SOA probe.
                try:
                    driver = get_driver(server.driver)
                    health_check = getattr(driver, "health_check", None)
                    if callable(health_check):
                        ok, health_detail = await health_check(server)
                    else:
                        ok = await _probe_server_soa(server.host, server.port)
                    new_status = "active" if ok else "unreachable"
                except Exception as exc:  # noqa: BLE001 — surface any driver error
                    new_status = "unreachable"
                    logger.warning(
                        "dns_health_driver_probe_failed",
                        server_id=str(server_id),
                        driver=server.driver,
                        host=server.host,
                        error=str(exc),
                    )
            else:
                # Agent-based: trust a fresh heartbeat; otherwise SOA probe.
                last_seen = server.last_health_check_at
                if (
                    last_seen is not None
                    and (now - last_seen) <= AGENT_STALE_AFTER
                    and server.status == "active"
                ):
                    new_status = "active"
                else:
                    reachable = await _probe_server_soa(server.host, server.port)
                    new_status = "active" if reachable else "unreachable"

            server.status = new_status
            server.last_health_check_at = now
            await db.commit()

            logger.info(
                "dns_health_checked",
                server_id=str(server_id),
                driver=server.driver,
                agentless=is_agentless(server.driver),
                status=new_status,
                host=server.host,
                detail=health_detail,
            )
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.tasks.dns.check_dns_server_health",
    bind=True,
    max_retries=3,
    acks_late=True,
)
def check_dns_server_health(self: object, server_id: str) -> None:  # type: ignore[type-arg]
    """Celery entry point for a single-server health check. Idempotent."""
    try:
        asyncio.run(_check_health(uuid.UUID(server_id)))
    except Exception as exc:  # noqa: BLE001
        logger.warning("dns_health_check_error", server_id=server_id, error=str(exc))
        raise self.retry(exc=exc, countdown=30) from exc  # type: ignore[attr-defined]


async def _enqueue_all() -> None:
    engine = create_async_engine(settings.database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as db:
            # #1068 — the DHCP/DNS subsystem can be switched off wholesale;
            # do no work (and open no driver connections) when it is.
            if not await is_module_enabled(db, "core.dns"):
                return
            result = await db.execute(select(DNSServer.id))
            ids = [str(row[0]) for row in result.all()]
    finally:
        await engine.dispose()
    for sid in ids:
        check_dns_server_health.delay(sid)


@celery_app.task(name="app.tasks.dns.check_all_dns_servers_health", bind=True)
def check_all_dns_servers_health(self: object) -> None:  # type: ignore[type-arg]
    """Fan-out task: enqueue one health check per registered DNS server.

    Scheduled every 60s by Celery Beat — see ``app.celery_app.beat_schedule``.
    """
    asyncio.run(_enqueue_all())

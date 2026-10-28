"""Health probe endpoints consumed by Docker/Kubernetes."""

import asyncio
from collections.abc import Awaitable
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Any, cast

import structlog
from fastapi import APIRouter
from sqlalchemy import text
from starlette import status
from starlette.responses import JSONResponse

from app.core.schema_check import SchemaCheck, missing_from_database, schema_at_head
from app.db import AsyncSessionLocal, ProbeSessionLocal

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["health"])


# ── Schema-at-head check (issue #299 phase 1) ──────────────────────
#
# On the appliance shape the migrate Job lands the head into the DB
# AFTER the api Deployment starts (CNPG bootstrap takes 1-2 min on a
# multi-node cluster), so without a schema-aware readiness probe the
# api passes /health/ready the moment Postgres accepts a SELECT 1 —
# even though every route handler then 500s against missing tables.
# The operator-visible symptom is a ~1-2 min window of bare nginx
# 502s on every login attempt (issue #299). Fixing /health/ready to
# require the schema at head makes the k8s readinessProbe accurately
# reflect "can serve traffic".
#
# The comparison itself lives in the framework-agnostic
# ``app.core.schema_check`` module (extracted in #565 so the Celery
# worker/beat startup + periodic checks share one implementation);
# this wrapper keeps the ``(verdict, detail)`` shape the readiness
# verdict folds in alongside DB + Redis.
#
# #2777 — a DB *ahead* of the image is the mixed-version window of a
# rolling upgrade: the new release's migration commits while the old
# release's pods still serve (expand/contract keeps the old code safe on
# the new schema, docs/DEVELOPMENT.md). Refusing it took EVERY old api
# pod out of the Service at once, before any new pod was ready: ~80 s of
# 502 on a three-node roll. So a process that has been Ready at its own
# head (a whole probe answered 200 there) keeps serving there. One that
# never was (a new pod, a restarted container, an older release rolled
# back onto a newer database) still refuses it, as wait-for-migrate and
# #1227's guard do. Behind, unstamped and failed checks stay 503 whatever
# the history.
#
# ``ahead`` only says the image's tree lacks the revision, which is also
# true of a forked or squashed head, a mistyped ``alembic stamp`` and a
# restore made with ``allow_newer_schema``. So a Ready pod keeps serving on
# a newer schema only while every table and column its models map is in
# the database: read once per revision, and a read that fails or times
# out answers 503 and is not kept.
@dataclass(slots=True)
class _SchemaReadiness:
    """This process's schema history across probes (#2777).

    ``seen_head`` latches the first time a whole readiness probe answers
    200 with the DB exactly at this image's own head: the pod has been
    Ready at its own head (one uvicorn worker per api container, so the
    process is the pod). A probe that found the schema at head but failed
    on Redis answered 503 and does not set it. ``logged`` is the last
    (verdict, detail) logged, so a mismatch logs once per change, not
    once per probe. ``checked`` is the last newer revision whose tables
    and columns were read, with what it lacks of them (empty: nothing);
    only a read that finished is kept.
    """

    seen_head: bool = False
    logged: tuple[str, str] | None = None
    checked: tuple[str, tuple[str, ...]] | None = None


_schema_readiness = _SchemaReadiness()

# How many missing tables and columns a refusal names, and its warning logs.
_MISSING_SHOWN = 5
_MISSING_LOGGED = 20


def reset_schema_readiness() -> None:
    """Forget this process's schema history, as if it had just started:
    the latch, the last state logged and the newer revision whose tables
    and columns were read (tests)."""
    global _schema_readiness
    _schema_readiness = _SchemaReadiness()


def _log_schema_change(
    verdict: str, detail: str, result: SchemaCheck, missing: tuple[str, ...] = ()
) -> None:
    """Log a schema mismatch at warning once per change of what readiness
    answers (#2777), with what a newer schema lacks when it lacks something."""
    key = (verdict, detail)
    previous = _schema_readiness.logged
    if key == previous:
        return
    _schema_readiness.logged = key
    if verdict == "ok":
        if previous is not None:
            logger.info("readiness_schema_at_head", expected=result.expected, previous=previous[1])
        return
    lacks: dict[str, Any] = {}
    if missing:
        lacks = {"missing": list(missing[:_MISSING_LOGGED]), "missing_count": len(missing)}
    logger.warning(
        "readiness_schema_mismatch",
        expected=result.expected,
        actual=result.actual,
        ahead=result.ahead,
        serving=verdict == "newer",
        detail=detail,
        **lacks,
    )


async def _judge_newer_schema(
    actual: str, expected: str | None
) -> tuple[str, str, tuple[str, ...]]:
    """Keep a Ready pod serving on a newer schema only while every table and
    column its image uses is there (#2777).

    Returns ``(verdict, detail, missing)``. The schema is read once per
    revision: a revision's DDL and its ``alembic_version`` commit together
    (one transaction per revision). A read that raises answers 503 and is
    not kept, so the next probe reads again; one cut off by readiness's
    timeout keeps nothing either.
    """
    newer = f"schema at {actual} is newer than this image's head {expected}"
    checked = _schema_readiness.checked
    if checked is not None and checked[0] == actual:
        missing = checked[1]
    else:
        try:
            tables, columns = await missing_from_database(session_factory=ProbeSessionLocal)
        except Exception as exc:  # noqa: BLE001
            # A read that could not run proves nothing: fail closed, keep nothing.
            first = (str(exc).splitlines() or [""])[0][:160]
            reason = f"{type(exc).__name__}: {first}"
            return (
                "error",
                f"{newer}, and its tables and columns could not be checked: {reason}",
                (),
            )
        missing = (*tables, *columns)
        _schema_readiness.checked = (actual, missing)
    if missing:
        count = len(missing)
        names = ", ".join(missing[:_MISSING_SHOWN])
        if count > _MISSING_SHOWN:
            names += f" and {count - _MISSING_SHOWN} more"
        what = "table or column" if count == 1 else "tables and columns"
        return "error", f"{newer} and lacks {count} {what} this image uses: {names}", missing
    return (
        "newer",
        f"{newer}: a newer release migrated the database, and this pod keeps serving "
        "until it is replaced",
        (),
    )


async def _check_schema_ready() -> tuple[str, str]:
    """Verify the DB schema is at the head this api image expects.

    Returns ``("ok", "<detail>")`` if the schema matches;
    ``("newer", "<detail>")`` when a newer release migrated the DB, this
    process has been Ready at its own head, and every table and column its
    image uses is in the database, so it keeps serving (#2777); else
    ``("error", "<detail>")`` with an operator-actionable message. It reads
    the latch; only ``readiness`` sets it.
    """
    result = await schema_at_head(session_factory=ProbeSessionLocal)
    missing: tuple[str, ...] = ()
    if result.ok:
        verdict, detail = "ok", result.detail
    elif result.ahead and result.actual is not None and _schema_readiness.seen_head:
        verdict, detail, missing = await _judge_newer_schema(result.actual, result.expected)
    else:
        verdict, detail = "error", result.detail
    _log_schema_change(verdict, detail, result, missing)
    return verdict, detail


@router.get("/health/live", status_code=status.HTTP_200_OK)
async def liveness() -> dict:
    """Liveness probe — returns 200 if the process is running."""
    return {"status": "ok"}


@router.get("/health/ready")
async def readiness() -> JSONResponse:
    """
    Readiness probe — checks DB connectivity, DB SCHEMA-at-head, and
    Redis connectivity. Returns 200 if ready, 503 with failed-check
    details if not.

    Schema-at-head is the key check for the cold-boot + post-restore
    + mid-rolling-upgrade windows where Postgres is up + accepting
    connections but the migrate Job hasn't landed the bundled
    alembic revisions yet. Without this check the api passes the
    readiness probe the moment a ``SELECT 1`` succeeds, gets added to
    the Service endpoint set, and serves 500s on every actual route
    handler until migrations finish — which the operator sees as
    bare nginx 502s through the frontend proxy (issue #299).

    A schema AHEAD of this image (a newer release migrated it) keeps a
    process that has been Ready at its own head (this probe answered 200
    there) in service: ``checks.schema`` reads ``ok: …`` naming both
    revisions (#2777).
    """
    checks: dict[str, str] = {}
    healthy = True

    # Database connectivity check. Same SELECT 1 as before — separate
    # from the schema check so an operator looking at a 503 response
    # can tell "Postgres is down" apart from "Postgres is up but the
    # schema is behind."
    #
    # #590 — each check is wait_for-bounded so the ENDPOINT answers in
    # seconds no matter what state the pool is in. During a node loss a
    # pooled connection to the dead primary black-holes (no RST), and a
    # checkout that waits on it held this endpoint open for minutes —
    # the kubelet's probe timeout read that as NotReady on every api
    # pod at once, which emptied the api Service and 502'd the cluster
    # (observed live 2026-07-12). db.py's command_timeout now culls
    # such connections in bounded time; the wait_for here keeps the
    # probe response itself honest-and-fast while that happens.
    try:
        async with asyncio.timeout(4):
            async with ProbeSessionLocal() as session:
                await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except TimeoutError:
        logger.warning(
            "readiness_check_failed",
            check="database",
            error="timed out after 4s (pool draining dead connections?)",
        )
        checks["database"] = "error: timed out after 4s"
        healthy = False
    except Exception as exc:
        logger.warning("readiness_check_failed", check="database", error=str(exc))
        checks["database"] = f"error: {exc}"
        healthy = False

    # Schema-at-head check. Only run when the DB connect succeeded —
    # otherwise the schema check would surface a confusing
    # "could not connect" error on top of the database error above.
    # Bounded like the database check: it opens its own session, so an
    # unlucky checkout could land on a not-yet-culled dead connection.
    if checks["database"] == "ok":
        try:
            async with asyncio.timeout(4):
                verdict, detail = await _check_schema_ready()
        except TimeoutError:
            verdict, detail = "error", "timed out after 4s"
            _log_schema_change(verdict, detail, SchemaCheck(False, None, None, detail))
        if verdict == "ok":
            checks["schema"] = "ok"
        elif verdict == "newer":
            checks["schema"] = f"ok: {detail}"
        else:
            checks["schema"] = f"error: {detail}"
            healthy = False

    # Redis check
    try:
        from app.config import settings
        from app.core.redis_client import make_async_redis

        # #590 — socket_timeout too, and both knobs now reach the SENTINEL
        # hops as well (redis_client._sentinel_kwargs): an unbounded
        # connect to a dead-but-still-resolving sentinel hung this check
        # for minutes, which the kubelet's 1 s probe timeout reads as
        # NotReady — on every api pod at once, during exactly the
        # node-loss window readiness exists to survive.
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        await cast(Awaitable[bool], r.ping())
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as exc:
        logger.warning("readiness_check_failed", check="redis", error=str(exc))
        checks["redis"] = f"error: {exc}"
        healthy = False

    if healthy and checks.get("schema") == "ok":
        # #2777: the latch means "has been Ready at its own head", so only a
        # probe that answers 200 with the schema exactly at head sets it.
        _schema_readiness.seen_head = True

    body = {"status": "ok" if healthy else "degraded", "checks": checks}
    code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=code, content=body)


@router.get("/health/startup")
async def startup() -> JSONResponse:
    """Startup probe (Kubernetes slow-start containers) — same logic as readiness."""
    return await readiness()


# ── Celery worker ping: single-flight + short cache (GHSA-c58p-8cq9-g3gm) ──
#
# ``/health/platform`` is unauthenticated, and ``inspect().ping()`` is a
# broadcast that holds one pooled broker connection while it acquires a
# second for its producer. Run once per request, a burst of anonymous
# callers filled kombu's connection pool with these hold-and-wait pings —
# and ``asyncio.wait_for`` abandons the *request* at the timeout but not the
# thread, so stuck pings accumulated. The next inline ``.delay()`` on the
# event loop then blocked forever on the pool, hanging the whole api.
#
# So at most ONE ping is in flight per process: concurrent callers await the
# same task, a caller arriving while a ping is still hung past its timeout
# joins it rather than starting another, and a finished result (or error)
# answers every caller for ``WORKER_PING_CACHE_TTL_S``.
WORKER_PING_TIMEOUT_S = 3.0
WORKER_PING_CACHE_TTL_S = 5.0

_ping_task: asyncio.Future[dict[str, Any] | None] | None = None
# (completed_at, result, exception) — exactly one of result/exception is meaningful.
_ping_cached: tuple[float, dict[str, Any] | None, BaseException | None] | None = None


def _inspect_ping() -> dict[str, Any] | None:
    from app.celery_app import celery_app  # noqa: PLC0415

    return celery_app.control.inspect(timeout=2).ping()


def invalidate_worker_ping_cache() -> None:
    """Forget the cached / in-flight ping (tests; the next call re-pings)."""
    global _ping_task, _ping_cached
    _ping_task = None
    _ping_cached = None


def _store_ping(fut: asyncio.Future[dict[str, Any] | None]) -> None:
    global _ping_cached
    if fut.cancelled():
        return
    exc = fut.exception()
    _ping_cached = (monotonic(), None if exc else fut.result(), exc)


async def _worker_ping() -> dict[str, Any] | None:
    """Return the worker ping, issuing at most one broadcast at a time.

    Raises ``TimeoutError`` when the ping has not answered within
    ``WORKER_PING_TIMEOUT_S`` (the ping keeps running and later callers join
    it), or whatever the ping itself raised.
    """
    global _ping_task
    cached = _ping_cached
    if cached is not None and monotonic() - cached[0] < WORKER_PING_CACHE_TTL_S:
        if cached[2] is not None:
            # Fresh traceback each time, or every re-raise appends to it.
            raise cached[2].with_traceback(None)
        return cached[1]

    loop = asyncio.get_running_loop()
    # No await between the check and the assignment, so two coroutines on
    # this loop cannot both start a ping. A task from another (closed) loop
    # can never complete here, so it is replaced rather than awaited.
    if _ping_task is None or _ping_task.done() or _ping_task.get_loop() is not loop:
        _ping_task = asyncio.ensure_future(asyncio.to_thread(_inspect_ping))
        _ping_task.add_done_callback(_store_ping)
    # shield: one caller timing out must not cancel the ping the others await
    # (cancelling would not stop the thread anyway, only orphan it).
    return await asyncio.wait_for(asyncio.shield(_ping_task), timeout=WORKER_PING_TIMEOUT_S)


@router.get("/health/platform")
async def platform_health() -> JSONResponse:
    """Dashboard-oriented rollup of every control-plane component.

    Distinct from ``/health/ready`` in that this one is dashboard-
    facing rather than an orchestrator probe: it enumerates the
    individual pieces (db, redis, celery workers, celery beat) instead
    of returning a single binary verdict, so the UI can show a
    per-component status dot and explain what's wrong. Individual
    failures never make the endpoint itself fail — the caller always
    gets a 200 with the rollup. The top-level ``status`` folds the
    components into a single ``ok`` / ``degraded`` verdict for headline
    display.

    SECURITY (#400 / M5): this endpoint is mounted UNAUTHENTICATED
    (the AppLayout polls it before login for the demo-mode /
    maintenance banner), so component ``detail`` fields must never echo
    raw backend exception strings — those can leak DSNs, internal
    hostnames, driver versions, and stack-frame paths to an anonymous
    caller. On error we log the full ``str(exc)`` server-side (where
    operators can see it) and return only a fixed, generic detail
    string. The ``ok`` / ``error`` / ``warn`` status semantics are
    unchanged, so the per-component dots still render correctly.
    """
    components: list[dict[str, Any]] = [{"name": "api", "status": "ok", "detail": "responding"}]

    # Database
    t0 = monotonic()
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        components.append(
            {
                "name": "postgres",
                "status": "ok",
                "detail": f"SELECT 1 in {(monotonic() - t0) * 1000:.0f} ms",
            }
        )
    except Exception as exc:
        # SECURITY (#400 / M5): never echo str(exc) to this unauthenticated
        # endpoint — it can leak the Postgres DSN / host. Log it server-side.
        logger.warning("platform_health_check_failed", component="postgres", error=str(exc))
        components.append({"name": "postgres", "status": "error", "detail": "postgres error"})

    # Redis
    t0 = monotonic()
    try:
        from app.config import settings
        from app.core.redis_client import make_async_redis

        # #590 — socket_timeout too, and both knobs now reach the SENTINEL
        # hops as well (redis_client._sentinel_kwargs): an unbounded
        # connect to a dead-but-still-resolving sentinel hung this check
        # for minutes, which the kubelet's 1 s probe timeout reads as
        # NotReady — on every api pod at once, during exactly the
        # node-loss window readiness exists to survive.
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        await cast(Awaitable[bool], r.ping())
        await r.aclose()
        components.append(
            {
                "name": "redis",
                "status": "ok",
                "detail": f"ping in {(monotonic() - t0) * 1000:.0f} ms",
            }
        )
    except Exception as exc:
        # SECURITY (#400 / M5): generic detail only — str(exc) would leak the
        # Redis URL / host to an unauthenticated caller.
        logger.warning("platform_health_check_failed", component="redis", error=str(exc))
        components.append({"name": "redis", "status": "error", "detail": "redis error"})

    # Celery workers — `inspect().ping()` is a sync, broker-backed RPC
    # that can hang, so run it in a threadpool with a short overall
    # timeout. Returns a mapping like ``{"celery@worker-1": {"ok": "pong"}}``
    # or ``None`` when no worker responds in time.
    #
    # KNOWN LIMIT (#925), stated because it misleads exactly when it
    # matters: ping is answered by the worker's MainProcess pidbox
    # consumer, which is independent of the prefork pool. A worker whose
    # every pool slot is blocked still answers "pong" and reports here as
    # ok, while nothing it is given can actually run. Verified directly
    # against a 2-slot worker with both slots occupied.
    #
    # Deliberately NOT fixed by adding an ``inspect.active()`` round trip:
    # this endpoint is unauthenticated, so every extra broadcast RPC here
    # is amplification an anonymous caller controls. The celery-beat
    # component BELOW is the signal that does surface a wedged pool —
    # which is why its detail must not blame beat for it.
    #
    # The ping itself is single-flight + cached — see ``_worker_ping``.
    try:
        ping = await _worker_ping()
    except TimeoutError:
        ping = None
        workers_detail = "inspect timed out"
    except Exception as exc:  # noqa: BLE001
        # SECURITY (#400 / M5): generic detail only — str(exc) here can carry
        # the broker URL / host. Log the real error server-side.
        logger.warning("platform_health_check_failed", component="celery-workers", error=str(exc))
        ping = None
        workers_detail = "inspect error"
    else:
        workers_detail = None

    if ping:
        workers = sorted(ping.keys())
        components.append(
            {
                "name": "celery-workers",
                "status": "ok",
                "detail": f"{len(workers)} alive",
                "workers": workers,
            }
        )
    else:
        components.append(
            {
                "name": "celery-workers",
                "status": "error",
                "detail": workers_detail or "no workers responding",
                "workers": [],
            }
        )

    # Celery beat — written by ``app.tasks.heartbeat.beat_tick`` every 30 s
    # to ``spatium:beat:heartbeat`` with a 5-minute TTL. Missing key → no
    # tick has landed for >5 min. Present but older than 90 s → degraded
    # (two beat intervals missed).
    #
    # #925 — the detail below says "no tick" and NOT "beat is stopped",
    # which is what it used to say and could not know. beat *schedules*
    # this task; a **worker** executes it, so the key is a round trip and
    # its absence indicts either end. The wording mattered: an operator
    # (and a QA gate) reading "beat is stopped" went and looked at a beat
    # pod that was running perfectly, while the actual fault was every
    # worker pool slot wedged on an unbounded Redis connect — a state
    # ``inspect ping`` reports as healthy, because the MainProcess answers
    # it without involving the pool at all.
    try:
        from app.config import settings
        from app.core.redis_client import make_async_redis
        from app.tasks.heartbeat import BEAT_HEARTBEAT_KEY  # noqa: PLC0415

        # Sentinel-aware (HA Redis uses ``sentinel://``, which raw
        # ``aioredis.from_url`` rejects with "must specify one of redis:// …"
        # — the same helper the redis + workers checks above use).
        # #590 — socket_timeout too, and both knobs now reach the SENTINEL
        # hops as well (redis_client._sentinel_kwargs): an unbounded
        # connect to a dead-but-still-resolving sentinel hung this check
        # for minutes, which the kubelet's 1 s probe timeout reads as
        # NotReady — on every api pod at once, during exactly the
        # node-loss window readiness exists to survive.
        r = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        raw = await r.get(BEAT_HEARTBEAT_KEY)
        await r.aclose()
        if raw is None:
            components.append(
                {
                    "name": "celery-beat",
                    "status": "error",
                    "detail": (
                        "no beat tick in the last 5 min — beat is not "
                        "scheduling, or no worker is executing its tick"
                    ),
                }
            )
        else:
            ts_str = raw.decode() if isinstance(raw, bytes) else raw
            ts = datetime.fromisoformat(ts_str)
            age_s = (datetime.now(UTC) - ts).total_seconds()
            if age_s > 90:
                status_str = "warn"
                detail = f"last tick {age_s:.0f}s ago (stalled)"
            elif age_s < -90:
                # A tick stamped in the future is clock skew between the
                # node that ran it and this one, not a healthy beat — and
                # the plain ``age_s > 90`` test read it as perfectly fresh,
                # so a skewed clock could hide a genuinely dead beat.
                status_str = "warn"
                detail = f"last tick {-age_s:.0f}s in the future (clock skew)"
            elif age_s < 0:
                # Skew too small to be worth warning about, but "last tick
                # -12s ago" is nonsense on a dashboard. Clamp the wording;
                # sub-threshold skew between two nodes is normal.
                status_str = "ok"
                detail = "last tick just now"
            else:
                status_str = "ok"
                detail = f"last tick {age_s:.0f}s ago"
            components.append(
                {
                    "name": "celery-beat",
                    "status": status_str,
                    "detail": detail,
                    "last_tick": ts.isoformat(),
                }
            )
    except Exception as exc:
        # SECURITY (#400 / M5): generic detail only — str(exc) would leak the
        # Redis URL / internal state to an unauthenticated caller.
        logger.warning("platform_health_check_failed", component="celery-beat", error=str(exc))
        components.append({"name": "celery-beat", "status": "error", "detail": "celery-beat error"})

    rollup = "ok"
    for c in components:
        if c["status"] == "error":
            rollup = "degraded"
            break
        if c["status"] == "warn" and rollup == "ok":
            rollup = "degraded"

    # Surface demo-mode to the frontend so AppLayout can render a
    # persistent banner. Cheap to bundle here — every authenticated
    # page already polls /health/platform for the status dots, so we
    # avoid a separate round-trip on every page load.
    from app.config import settings as _settings

    # Maintenance mode (issue #57) — same rationale: bundle the read-only
    # banner state into the existing poll instead of a separate request.
    # Failure to read it never fails the endpoint (it's a UI hint, not a
    # gate — the middleware is the real enforcement point).
    maintenance_enabled = False
    maintenance_message = ""
    maintenance_started_at: str | None = None
    try:
        from app.core import maintenance_mode as _maintenance_mode

        async with AsyncSessionLocal() as session:
            (
                maintenance_enabled,
                maintenance_message,
                _started,
            ) = await _maintenance_mode.get_maintenance_state(session)
        maintenance_started_at = _started.isoformat() if _started else None
    except Exception:  # noqa: BLE001 — UI hint only
        pass

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": rollup,
            "components": components,
            "demo_mode": bool(_settings.demo_mode),
            "maintenance_mode": maintenance_enabled,
            "maintenance_message": maintenance_message,
            "maintenance_started_at": maintenance_started_at,
        },
    )

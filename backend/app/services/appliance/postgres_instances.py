"""Per-instance PostgreSQL health for a CNPG cluster (#2856).

The database row on Cluster → Overview read ``status.readyInstances`` of
``spec.instances`` (#1387). That counts pods whose readiness probe passes,
and CNPG's default probe passes for a standby that is up but not
replicating: during a three-node failover drill, standbys looped on removed
WAL for more than ten minutes while CNPG reported "Cluster in healthy
state" 3/3, the row read healthy, and no alert fired.

So the verdict here is per INSTANCE, and an instance is unhealthy when:

* its pod is not Ready (kubeapi, ``Ready`` condition of the pod);
* it is a standby and the current primary has no streaming WAL sender for
  it (``pg_stat_replication`` on the primary);
* the supervisor on its node reported it looping or stuck (#2765's
  ``postgres_instance_looping`` / ``postgres_instance_stuck`` verdicts,
  when a supervisor ships them in ``cluster_health["postgres_instances"]``).

**Why ``pg_stat_replication``.** It is the primary's own list of standbys
it is sending WAL to, and the api already holds a connection to the
primary (the CNPG ``-rw`` Service), so it needs no new grant and no new
collector. A standby looping on removed WAL connects, asks for a segment
the primary no longer has, and is disconnected within milliseconds, so it
is absent from the view almost all of the time. CNPG names each WAL
sender after the instance (``application_name`` is the pod name), which is
what joins the two lists.

The app's role is not in ``pg_monitor`` (CNPG manages the role and reverts
a manual GRANT, #1445), so it sees each WAL sender's ``application_name``
but not its ``state``. Presence is therefore the signal: a WAL sender we
can see but whose state is hidden is UNVERIFIED and is not flagged; a
visible state other than ``streaming`` is flagged; no WAL sender at all is
flagged. ``None`` from :func:`read_walsenders` (the query failed, or the
connection is not on the primary) means the streaming half is UNKNOWN,
which is never treated as healthy or as broken.

Everything that decides is in :func:`evaluate`, used by the Cluster
screen, the ``postgres_instance_unhealthy`` alert and the copilot's
``find_cluster_metrics`` tool, so the three cannot disagree.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

KIND_NOT_READY = "not_ready"
KIND_NOT_STREAMING = "not_streaming"
KIND_SUPERVISOR = "supervisor_reported"

#: Supervisor verdicts (#2765) that mean the instance is not replicating.
SUPERVISOR_VERDICTS = frozenset({"looping", "stuck"})

#: A supervisor verdict older than this says nothing about now (the node
#: stopped heartbeating; ``appliance_heartbeat_stale`` reports that).
_SUPERVISOR_REPORT_MAX_AGE = timedelta(minutes=5)

#: Redis key holding when each instance was first seen unhealthy, for the
#: alert's duration threshold. Redis rather than a row: the clock is
#: volatile and per instance, and instances have no row in this database.
UNHEALTHY_SINCE_KEY = "spatium:alerts:postgres_instance_unhealthy_since"
_UNHEALTHY_SINCE_TTL_S = 24 * 3600


def evaluate(
    row: dict[str, Any],
    walsenders: dict[str, str | None] | None,
    supervisor: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Per-instance findings for a CNPG database row, and ``streaming`` on
    each instance (True / False / None = not checked or unverified).

    ``walsenders`` maps a WAL sender's ``application_name`` to its visible
    ``state`` (None when hidden from the app's role); ``None`` for the whole
    map means the streaming check could not run. ``supervisor`` maps an
    instance name to its supervisor-reported verdict.

    One finding per instance, worst first: not Ready, then a supervisor
    verdict, then not streaming. No streaming verdict is made mid-switchover
    (``targetPrimary`` differs from ``currentPrimary``): standbys are
    expected to reconnect to the new primary then, and the instance that is
    about to be primary is not a standby of the old one.
    """
    instances: list[dict[str, Any]] = row.get("instances") or []
    primary = row.get("current_primary")
    target = row.get("target_primary")
    switching = bool(target) and target != primary
    findings: list[dict[str, Any]] = []
    for inst in instances:
        name = inst.get("name") or "?"
        node = inst.get("node")
        inst["streaming"] = None
        if not inst.get("ready"):
            findings.append(
                {
                    "instance": name,
                    "node": node,
                    "kind": KIND_NOT_READY,
                    "detail": "is not Ready",
                    "since": inst.get("ready_since"),
                }
            )
            continue
        verdict = (supervisor or {}).get(name)
        if verdict and verdict.get("verdict") in SUPERVISOR_VERDICTS:
            what = verdict.get("detail") or f"is {verdict['verdict']}"
            findings.append(
                {
                    "instance": name,
                    "node": node,
                    "kind": KIND_SUPERVISOR,
                    "detail": f"was reported by the supervisor as {verdict['verdict']} ({what})",
                    "since": verdict.get("since"),
                }
            )
            continue
        if inst.get("role") != "standby" or walsenders is None or switching or not primary:
            continue
        if name not in walsenders:
            inst["streaming"] = False
            findings.append(
                {
                    "instance": name,
                    "node": node,
                    "kind": KIND_NOT_STREAMING,
                    "detail": f"is not streaming: the primary ({primary}) has no WAL sender for it",
                    "since": None,
                }
            )
            continue
        state = walsenders[name]
        if state is None:
            continue  # connected, state hidden from the app's role: unverified
        if state != "streaming":
            inst["streaming"] = False
            findings.append(
                {
                    "instance": name,
                    "node": node,
                    "kind": KIND_NOT_STREAMING,
                    "detail": f"is not streaming: its WAL sender on {primary} is in state {state}",
                    "since": None,
                }
            )
            continue
        inst["streaming"] = True
    return findings


def apply(
    row: dict[str, Any],
    walsenders: dict[str, str | None] | None,
    supervisor: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Record the findings on the database row and degrade a healthy row.

    Only ever lowers ``healthy`` to ``degraded``: a ``down`` row stays down,
    and a row with no findings keeps the CNPG verdict it already had.
    ``replication_checked`` says whether the streaming half ran at all.
    """
    findings = evaluate(row, walsenders, supervisor)
    row["findings"] = findings
    row["replication_checked"] = walsenders is not None
    if findings and row.get("status") == "healthy":
        row["status"] = "degraded"


def database_row(snap: dict[str, Any]) -> dict[str, Any] | None:
    """The CNPG database row carrying per-instance data, or None."""
    for w in snap.get("workloads") or []:
        if w.get("instances"):
            return w
    return None


async def read_walsenders(db: AsyncSession) -> dict[str, str | None] | None:
    """``application_name -> state`` for every WAL sender on the primary.

    ``None`` when it cannot be read, or when this connection is on a
    standby (whose view lists no standbys at all, and would make every one
    of them read as not streaming). Runs in a SAVEPOINT so a failed query
    does not abort the caller's transaction.
    """
    try:
        async with db.begin_nested():
            in_recovery = await db.scalar(text("SELECT pg_is_in_recovery()"))
            if in_recovery is not False:
                return None
            rows = (
                await db.execute(text("SELECT application_name, state FROM pg_stat_replication"))
            ).all()
    except Exception as exc:  # noqa: BLE001 - any failure means "unknown"
        logger.info("postgres_walsenders_unreadable", error=str(exc)[:200])
        return None
    out: dict[str, str | None] = {}
    for name, state in rows:
        if not name:
            continue
        # Two senders under one name (a reconnect racing the old one's exit):
        # one streaming is enough.
        if out.get(name) == "streaming":
            continue
        out[name] = state
    return out


async def read_supervisor_verdicts(db: AsyncSession, now: datetime) -> dict[str, dict[str, Any]]:
    """Fresh ``looping`` / ``stuck`` verdicts the supervisors reported.

    Read from ``appliance.cluster_health["postgres_instances"]``, a list of
    ``{"instance", "verdict", "detail"?, "since"?}``. A supervisor that ships
    no such key (every one before #2765) contributes nothing; the
    ``pg_stat_replication`` check stands on its own without it.
    """
    from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance  # noqa: PLC0415

    try:
        async with db.begin_nested():
            rows = (
                await db.execute(
                    select(Appliance.cluster_health, Appliance.last_seen_at).where(
                        Appliance.state == APPLIANCE_STATE_APPROVED
                    )
                )
            ).all()
    except Exception as exc:  # noqa: BLE001 - decoration only
        logger.info("postgres_supervisor_verdicts_unreadable", error=str(exc)[:200])
        return {}
    out: dict[str, dict[str, Any]] = {}
    for ch, last_seen_at in rows:
        if not isinstance(ch, dict) or last_seen_at is None:
            continue
        seen = last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=UTC)
        if now - seen > _SUPERVISOR_REPORT_MAX_AGE:
            continue
        reports = ch.get("postgres_instances")
        if not isinstance(reports, list):
            continue
        for rep in reports:
            if not isinstance(rep, dict):
                continue
            name = rep.get("instance")
            verdict = rep.get("verdict")
            if isinstance(name, str) and verdict in SUPERVISOR_VERDICTS:
                out[name] = {
                    "verdict": verdict,
                    "detail": rep.get("detail") if isinstance(rep.get("detail"), str) else None,
                    "since": rep.get("since") if isinstance(rep.get("since"), str) else None,
                }
    return out


async def enrich_snapshot(db: AsyncSession, snap: dict[str, Any]) -> dict[str, Any] | None:
    """Add the streaming and supervisor halves to the snapshot's database
    row. Returns the row, or None when the snapshot has no CNPG instances."""
    row = database_row(snap)
    if row is None:
        return None
    walsenders = await read_walsenders(db)
    supervisor = await read_supervisor_verdicts(db, datetime.now(UTC))
    apply(row, walsenders, supervisor)
    return row


async def enrich_snapshot_best_effort(db: AsyncSession, snap: dict[str, Any]) -> None:
    """:func:`enrich_snapshot` for the dashboard: a database that is failing
    over leaves the kube-only verdict standing rather than failing the
    response (the #1083 rule)."""
    try:
        await enrich_snapshot(db, snap)
    except Exception as exc:  # noqa: BLE001 - the decoration must never sink the snapshot
        logger.warning(
            "cluster_health_postgres_instances_unavailable",
            error_class=type(exc).__name__,
            error=str(exc)[:200],
        )


# ── unhealthy-since clock (alert duration threshold) ─────────────────────


async def load_unhealthy_since() -> dict[str, datetime]:
    """Instance name -> when it was first seen unhealthy. Raises on a Redis
    failure; the caller treats that as "unknown", not as "recovered"."""
    from app.config import settings  # noqa: PLC0415
    from app.core.redis_client import make_async_redis  # noqa: PLC0415

    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        raw = await r.get(UNHEALTHY_SINCE_KEY)
    finally:
        await r.aclose()
    if not raw:
        return {}
    data = json.loads(raw)
    out: dict[str, datetime] = {}
    for name, iso in (data or {}).items():
        try:
            out[str(name)] = parse_ts(iso)
        except (TypeError, ValueError):
            continue
    return out


async def save_unhealthy_since(clocks: dict[str, datetime]) -> None:
    """Replace the stored clocks (an instance that recovered is dropped)."""
    from app.config import settings  # noqa: PLC0415
    from app.core.redis_client import make_async_redis  # noqa: PLC0415

    r = make_async_redis(settings.redis_url, socket_connect_timeout=2)
    try:
        if clocks:
            payload = json.dumps({k: v.isoformat() for k, v in clocks.items()})
            await r.set(UNHEALTHY_SINCE_KEY, payload, ex=_UNHEALTHY_SINCE_TTL_S)
        else:
            await r.delete(UNHEALTHY_SINCE_KEY)
    finally:
        await r.aclose()


def parse_ts(value: Any) -> datetime:
    """An ISO-8601 timestamp (kube's trailing ``Z`` included), as UTC."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)

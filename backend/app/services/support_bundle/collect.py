"""Section collectors for the support bundle (issue #875).

Each collector returns ``(path, text)`` or None, and each is wrapped so
a failure becomes a ``.error`` file inside the bundle rather than a
failed generation. That is deliberate: a bundle is requested when
something is already broken, and the sections most likely to raise are
exactly the ones describing the breakage. Half a bundle beats a 500.

Deployment-shape neutrality is the other rule. The appliance-only
diagnostics endpoint that shipped before this one degrades to a 503 on
docker-compose and plain Kubernetes because its pod-log and self-test
halves go through kubeapi. Here, anything kubeapi-backed is optional and
its absence is recorded as a note explaining *why* it is absent — an
empty section and an inapplicable one look identical otherwise.
"""

from __future__ import annotations

import json
import os
import platform
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.alerts import AlertEvent
from app.models.audit import AuditLog
from app.models.diagnostics import InternalError
from app.models.settings import PlatformSettings
from app.services.appliance.apt import mask_proxy_url
from app.services.support_bundle.scrub import Scrubber, looks_secret_key

logger = structlog.get_logger(__name__)

# Per-section byte caps. The archive is assembled in memory, so these are
# what bound peak RSS — not a cosmetic nicety. A section that hits its cap
# is truncated with a marker rather than silently cut, so a reader can
# tell "there was no more" from "there was more and you can't see it".
CAP_LOG_BYTES = 2 * 1024 * 1024
CAP_SECTION_BYTES = 1 * 1024 * 1024
CAP_TOTAL_BYTES = 48 * 1024 * 1024

TRUNCATION_MARKER = "\n\n[... truncated by support-bundle size cap ...]\n"

# Row limits. Generous enough to show a pattern, small enough that a
# long-lived install does not produce a 200 MB archive.
MAX_INTERNAL_ERRORS = 200
MAX_ALERT_EVENTS = 500
MAX_AUDIT_ROWS = 1000


def cap(content: str, limit: int = CAP_SECTION_BYTES) -> str:
    """Truncate to ``limit`` bytes, keeping the TAIL for logs-like text.

    The end of a log is where the failure is. Truncating the head would
    reliably discard the only part anyone opens the file for.
    """
    encoded = content.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return content
    kept = encoded[-limit:].decode("utf-8", errors="replace")
    return TRUNCATION_MARKER + kept


def _json(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str, sort_keys=True)


async def _guarded(db: AsyncSession, run: Callable[[], Any], default: Any = None) -> Any:
    """Run one query, returning ``default`` (or an error string) on failure.

    The SAVEPOINT is the point. Catching a failed statement is not enough
    on PostgreSQL: the transaction stays in "current transaction is
    aborted, commands ignored until end of transaction block", so the
    NEXT query fails too — and so does the enclosing savepoint's RELEASE.
    A collector that swallows its own error without rolling back
    therefore breaks every section after it, and the resulting bundle
    blames the wrong ones.

    Sections that want to degrade *within* themselves — reporting one
    unavailable figure while still emitting the rest — must route each
    query through here rather than through a bare ``try``.
    """
    try:
        async with db.begin_nested():
            result = run()
            return await result if hasattr(result, "__await__") else result
    except Exception as exc:  # noqa: BLE001 — reported inline, never raised
        return default(exc) if callable(default) else f"error: {type(exc).__name__}: {exc}"


# ── Versions ────────────────────────────────────────────────────────────


async def collect_versions(db: AsyncSession) -> str:
    """Product / schema / runtime versions.

    The schema head is the single most useful line in a bug report:
    "which migration is this install on" decides whether a reported
    symptom is even possible on their code.
    """
    from app.core.schema_check import expected_alembic_head

    bundled_head, head_error = expected_alembic_head()
    db_head: str | None = None
    db_head_error: str | None = None

    async def _read_head() -> str | None:
        row = (await db.execute(text("SELECT version_num FROM alembic_version"))).first()
        return row[0] if row else None

    probed = await _guarded(db, _read_head)
    if isinstance(probed, str) and probed.startswith("error: "):
        db_head_error = probed.removeprefix("error: ")
    else:
        db_head = probed

    return _json(
        {
            "product_version": settings.version,
            "appliance_mode": settings.appliance_mode,
            "appliance_version": settings.appliance_version or None,
            "schema": {
                "bundled_head": bundled_head,
                "bundled_head_error": head_error,
                "database_head": db_head,
                "database_head_error": db_head_error,
                "at_head": bool(bundled_head and db_head and bundled_head == db_head),
            },
            "runtime": {
                "python": sys.version.split()[0],
                "platform": platform.platform(),
            },
            # Image tags come from the environment the orchestrator set,
            # which is the only place they exist at runtime.
            "image_tags": {
                k: v
                for k, v in sorted(os.environ.items())
                if k.endswith("_IMAGE") or k.endswith("_TAG") or k == "SPATIUMDDI_VERSION"
            },
        }
    )


# ── Errors / alerts ─────────────────────────────────────────────────────


async def collect_internal_errors(db: AsyncSession, scrub: Scrubber) -> str:
    """Recent unhandled exceptions (#123).

    Tracebacks go through the scrubber like any other freeform text —
    they routinely carry hostnames and addresses in exception messages,
    and a traceback is the single likeliest place for an unanticipated
    identifier to appear.
    """
    rows = (
        (
            await db.execute(
                select(InternalError)
                .order_by(InternalError.last_seen_at.desc())
                .limit(MAX_INTERNAL_ERRORS)
            )
        )
        .scalars()
        .all()
    )
    return _json(
        [
            {
                "timestamp": r.timestamp,
                "last_seen_at": r.last_seen_at,
                "service": r.service,
                "kind": r.kind,
                "route_or_task": r.route_or_task,
                "exception_class": r.exception_class,
                "message": scrub.text(r.message or ""),
                "traceback": scrub.text(r.traceback or ""),
                "context": scrub.value("context", r.context_json or {}),
                "fingerprint": r.fingerprint,
                "occurrence_count": r.occurrence_count,
                "acknowledged": r.acknowledged_at is not None,
            }
            for r in rows
        ]
    )


async def collect_alert_events(db: AsyncSession, scrub: Scrubber) -> str:
    rows = (
        (
            await db.execute(
                select(AlertEvent).order_by(AlertEvent.fired_at.desc()).limit(MAX_ALERT_EVENTS)
            )
        )
        .scalars()
        .all()
    )
    return _json(
        [
            {
                "fired_at": r.fired_at,
                "resolved_at": r.resolved_at,
                "severity": r.severity,
                "subject_type": r.subject_type,
                # The subject is an id or a name — a hostname, a subnet,
                # a server — so it goes through the scrubber.
                "subject_display": scrub.text(r.subject_display or ""),
                "message": scrub.text(r.message or ""),
                "delivered": {
                    "syslog": r.delivered_syslog,
                    "webhook": r.delivered_webhook,
                    "smtp": r.delivered_smtp,
                },
            }
            for r in rows
        ]
    )


async def collect_audit_tail(db: AsyncSession, scrub: Scrubber) -> str:
    """Last N mutations — the "what changed just before it broke" section."""
    rows = (
        (
            await db.execute(
                select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(MAX_AUDIT_ROWS)
            )
        )
        .scalars()
        .all()
    )
    return _json(
        [
            {
                "timestamp": r.timestamp,
                "user": scrub.username(r.user_display_name or ""),
                "auth_source": r.auth_source,
                # The audit row records where the change came from; an
                # operator's workstation address is exactly the kind of
                # thing the scrubber exists for.
                "source_ip": scrub.text(r.source_ip or ""),
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_display": scrub.text(r.resource_display or ""),
                "changed_fields": r.changed_fields,
                "result": r.result,
            }
            for r in rows
        ]
    )


# ── Config ──────────────────────────────────────────────────────────────


async def collect_feature_modules(db: AsyncSession) -> str:
    from app.services.feature_modules import MODULES, get_enabled_modules

    enabled = await get_enabled_modules(db)
    return _json(
        {
            "enabled": sorted(enabled),
            "disabled": sorted({m.id for m in MODULES} - enabled),
        }
    )


def _can_hold_a_secret(column: Any) -> bool:
    """Whether a column's TYPE could carry a credential.

    The name-based denylist is deliberately broad, which means it also
    catches policy knobs — ``password_min_length``,
    ``password_require_digit``, ``ai_per_user_daily_token_cap``. Those
    are integers and booleans; no Fernet blob or API key fits in one,
    and "what is their password policy?" is a routine support question
    whose answer is not a secret. So the name test decides *suspicion*
    and the type test decides whether suspicion is even possible.

    Anything textual or structured stays redacted on name alone.
    """
    try:
        python_type = column.type.python_type
    except (NotImplementedError, AttributeError):
        # An exotic type we cannot introspect — assume the worst.
        return True
    return python_type not in (int, float, bool)


async def collect_platform_settings(db: AsyncSession, scrub: Scrubber) -> str:
    """The settings row with every credential-shaped column dropped.

    Column-name matching rather than an allowlist, because the table has
    ~180 columns and grows most releases: an allowlist would silently
    stop covering new settings, while a denylist that over-matches only
    costs a redacted diagnostic field. ``value()`` also runs the text
    scrubber over what survives, so a hostname stored in a settings
    column is pseudonymised like one in a log.
    """
    row = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    if row is None:
        return _json({"_note": "no platform_settings row exists yet (fresh install)"})

    out: dict[str, Any] = {}
    redacted: list[str] = []
    for column in PlatformSettings.__table__.columns:
        name = column.name
        value = getattr(row, name, None)
        if looks_secret_key(name) and _can_hold_a_secret(column):
            # Report that the key EXISTS and whether it is set, without
            # the value — "is LDAP configured at all?" is a real support
            # question and the answer is not itself a secret.
            redacted.append(name)
            out[name] = "[REDACTED]" if value not in (None, "", [], {}) else None
            continue
        if isinstance(value, (int, float, bool)) or value is None:
            # Already cleared by _can_hold_a_secret, and a number carries
            # no hostname to pseudonymise. Passing it through scrub.value
            # would re-apply that function's own name-based check and
            # redact it after all — the very over-matching the type test
            # exists to undo.
            out[name] = value
            continue
        if name in ("apt_proxy_http", "apt_proxy_https"):
            # A token-only userinfo (``http://token@proxy``) has no
            # ``user:pass`` shape for the text scrubber to catch
            # (GHSA-j77h-pqg7-h2g4).
            value = mask_proxy_url(value)
        out[name] = scrub.value(name, value)
    out["_redacted_columns"] = sorted(redacted)
    return _json(out)


async def collect_integration_state(db: AsyncSession) -> str:
    """Which read-only mirrors are switched on.

    Flags only, no credentials and no target hostnames — those live in
    per-integration tables and are exactly the kind of thing that should
    not ride along by default.
    """
    row = (await db.execute(select(PlatformSettings).limit(1))).scalar_one_or_none()
    flags = {
        c.name: getattr(row, c.name, None)
        for c in PlatformSettings.__table__.columns
        if c.name.startswith("integration_") and c.name.endswith("_enabled")
    }
    return _json({"flags": flags if row is not None else {}, "row_present": row is not None})


# ── Runtime / host ──────────────────────────────────────────────────────


def collect_environment(scrub: Scrubber) -> str:
    """Process environment, with credential-named vars dropped.

    Values still go through the scrubber: a DATABASE_URL is not
    secret-*named* once its password is stripped, but it carries a
    hostname.
    """
    lines = []
    for key, value in sorted(os.environ.items()):
        lines.append(f"{key}=[REDACTED]" if looks_secret_key(key) else f"{key}={scrub.text(value)}")
    return "\n".join(lines)


def collect_proc(scrub: Scrubber) -> dict[str, str]:
    """Kernel / memory / CPU basics.

    Read from the api container's ``/proc``, which shares the host
    kernel — so ``/proc/version`` reports the host's kernel even though
    the mount is the container's.
    """
    out: dict[str, str] = {}
    for proc in (
        "/proc/version",
        "/proc/uptime",
        "/proc/meminfo",
        "/proc/cpuinfo",
        "/proc/loadavg",
    ):
        try:
            out[proc.lstrip("/")] = cap(
                Path(proc).read_text(encoding="utf-8", errors="replace"), 256 * 1024
            )
        except OSError as exc:
            out[f"{proc.lstrip('/')}.error"] = f"{type(exc).__name__}: {exc}"
    return out


def collect_container_logs(scrub: Scrubber) -> dict[str, str]:
    """Per-pod stdout, when kubeapi is reachable.

    Unlike the appliance-only endpoint this does not 503 when it is not:
    a compose install has no kubeapi and that is a normal state, not an
    error. The note says which shape produced the absence so a reader
    does not read "no logs" as "logs were empty".
    """
    from app.services.appliance.containers import (
        DockerUnavailableError,
        get_container_logs,
        list_containers,
    )

    if not settings.appliance_mode:
        return {
            "_note.txt": (
                "Container logs are collected through the Kubernetes API, which "
                "this deployment does not expose (appliance_mode is off — a "
                "docker-compose or plain-Kubernetes install). Collect them with "
                "`docker compose logs` or `kubectl logs` and attach separately "
                "if the issue needs them."
            )
        }
    out: dict[str, str] = {}
    try:
        for container in list_containers():
            if not container.is_spatium:
                continue
            try:
                raw = get_container_logs(container.name, tail=500)
            except DockerUnavailableError as exc:
                raw = f"[unable to fetch logs: {exc}]"
            out[f"{container.name}.log"] = cap(scrub.text(raw), CAP_LOG_BYTES)
    except DockerUnavailableError as exc:
        out["_error.txt"] = (
            f"Kubernetes API unreachable: {exc}\n"
            "This is expected on an agent-only appliance or when the api "
            "ServiceAccount lacks pod-log permission."
        )
    return out


def collect_host_logs(scrub: Scrubber) -> dict[str, str]:
    """Host log files, when the appliance bind-mount is present."""
    from app.services.appliance.diagnostics import _log_dir, list_log_sources

    # Installer logs FIRST, and the emptiness verdict after both, because
    # the two early returns below used to sit above the installer
    # collector: a box whose host log dir holds only ``install/`` — an
    # install that died before firstboot opened its own log, i.e. exactly
    # the case #995 item 1 exists for — got the "not mounted" note and no
    # install logs, while the directory it says is absent was right there.
    out: dict[str, str] = _collect_installer_logs(scrub)
    try:
        names = list_log_sources()
    except OSError as exc:
        out["_error.txt"] = f"{type(exc).__name__}: {exc}"
        return out
    for name in names:
        try:
            raw = (_log_dir() / name).read_text(encoding="utf-8", errors="replace")
            out[name] = cap(scrub.text(raw), CAP_LOG_BYTES)
        except OSError as exc:
            out[f"{name}.error"] = f"{type(exc).__name__}: {exc}"
    if not out:
        return {
            "_note.txt": (
                "No host log directory is mounted. Expected on docker-compose "
                "and plain-Kubernetes installs, where the api container has no "
                "view of the host filesystem."
            )
        }
    return out


def _collect_installer_logs(scrub: Scrubber) -> dict[str, str]:
    """The installer's own logs, if this box was built by spatium-install.

    #995 item 1. spatium-install copies its install / trace / launch logs
    to ``/var/log/spatiumddi/install/`` immediately before unmounting the
    target, because until then they lived on the live ISO's tmpfs and the
    rsync excludes ``/var/log/*`` — so the one artefact explaining how a
    box was built was the one artefact the build threw away.

    Read here rather than through ``list_log_sources`` because that
    globs ``*.log`` non-recursively and is the allowlist behind the Logs
    tab's ``read_log_tail``: widening it to walk subdirectories would put
    three static install-time files in the live-log dropdown and would
    mean touching the path-injection sanitizer that endpoint depends on.
    Nothing reaches the filesystem here that a request supplied.

    Absent on every install that was not made from the ISO (compose,
    plain Kubernetes, an appliance imaged some other way), which is why a
    missing directory is silence rather than a note.
    """
    from app.services.appliance.diagnostics import _log_dir

    out: dict[str, str] = {}
    base = _log_dir() / "install"
    try:
        if not base.is_dir():
            return out
        entries = sorted(p for p in base.iterdir() if p.is_file())
    except OSError as exc:
        return {"install/_error.txt": f"{type(exc).__name__}: {exc}"}
    for path in entries:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            out[f"install/{path.name}.error"] = f"{type(exc).__name__}: {exc}"
            continue
        out[f"install/{path.name}"] = cap(scrub.text(raw), CAP_LOG_BYTES)
    return out


def collect_self_test(scrub: Scrubber) -> str:
    """Appliance self-test, when applicable.

    Reports inapplicability instead of failing: on a compose install the
    checks are all kubeapi-shaped and would report a wall of red that
    means nothing.
    """
    if not settings.appliance_mode:
        return (
            "Self-test is appliance-only — it probes the Kubernetes API and "
            "per-role pods, neither of which exists on a docker-compose or "
            "plain-Kubernetes install. See health/versions.json for the "
            "deployment-neutral checks."
        )
    from app.services.appliance.diagnostics import _format_self_test_report, run_self_test

    try:
        # Scrubbed: the report names pods and prints the cluster
        # addresses each check probed.
        return scrub.text(_format_self_test_report(run_self_test()))
    except Exception as exc:  # noqa: BLE001
        return f"self-test failed to run: {type(exc).__name__}: {exc}"


async def collect_agent_state(db: AsyncSession, scrub: Scrubber) -> str:
    """DNS / DHCP server rows — driver, enabled, last-seen.

    No credentials: ``credentials_encrypted`` and the agent PSKs are
    matched by :func:`looks_secret_key` and never selected here in the
    first place.
    """
    from app.models.dhcp import DHCPServer
    from app.models.dns import DNSServer

    dns_rows = (await db.execute(select(DNSServer))).scalars().all()
    dhcp_rows = (await db.execute(select(DHCPServer))).scalars().all()

    def _server(row: Any, kind: str) -> dict[str, Any]:
        return {
            "kind": kind,
            "name": scrub.text(getattr(row, "name", "") or ""),
            "address": scrub.text(str(getattr(row, "address", "") or "")),
            "driver": getattr(row, "driver", None),
            "enabled": getattr(row, "enabled", None),
            "is_primary": getattr(row, "is_primary", None),
            "last_seen_at": getattr(row, "last_seen_at", None),
            "agent_version": getattr(row, "agent_version", None),
            "health_status": getattr(row, "health_status", None),
        }

    return _json([_server(r, "dns") for r in dns_rows] + [_server(r, "dhcp") for r in dhcp_rows])


async def collect_recent_app_logs(db: AsyncSession, scrub: Scrubber) -> str:
    """Recent structured log lines, sourced from the DB rather than files.

    Container stdout is unavailable on compose installs (above), so the
    deployment-neutral substitute is what the app persisted itself:
    ``internal_error`` covers failures and ``audit_log`` covers
    mutations. Both have their own sections; this one is a merged,
    time-ordered view because "what happened, in order" is the question
    a reader actually asks.
    """
    since = datetime.now(UTC) - timedelta(days=7)
    errors = (
        (
            await db.execute(
                select(InternalError)
                .where(InternalError.last_seen_at >= since)
                .order_by(InternalError.last_seen_at.desc())
                .limit(MAX_INTERNAL_ERRORS)
            )
        )
        .scalars()
        .all()
    )
    audits = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.timestamp >= since)
                .order_by(AuditLog.timestamp.desc())
                .limit(MAX_AUDIT_ROWS)
            )
        )
        .scalars()
        .all()
    )
    merged: list[tuple[datetime, str]] = []
    for e in errors:
        merged.append(
            (
                e.last_seen_at,
                f"ERROR  [{e.service}] {e.route_or_task or '-'} "
                f"{e.exception_class}: {scrub.text(e.message or '')[:300]}",
            )
        )
    for a in audits:
        merged.append(
            (
                a.timestamp,
                f"AUDIT  {a.action} {a.resource_type} "
                f"{scrub.text(a.resource_display or '')[:120]} "
                f"by {scrub.username(a.user_display_name or '')} -> {a.result}",
            )
        )
    merged.sort(key=lambda item: item[0], reverse=True)
    body = "\n".join(f"{ts.isoformat()}  {line}" for ts, line in merged)
    return cap(body or "(no errors or audited mutations in the last 7 days)")


async def collect_db_pool(db: AsyncSession) -> str:
    """Connection counts — the first thing to check on a hang."""
    rows = await _guarded(
        db,
        lambda: db.execute(
            text(
                "SELECT state, count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() GROUP BY state"
            )
        ),
    )
    if isinstance(rows, str):
        return _json({"error": rows})
    return _json({str(state): int(n) for state, n in rows.all()})


async def collect_table_sizes(db: AsyncSession) -> str:
    """Approximate row counts + on-disk size per table.

    ``reltuples`` is the planner's estimate, maintained by ANALYZE, and
    it costs one indexed read for the whole catalogue. Exact ``COUNT(*)``
    is a sequential scan per table — 300 of them on a large install is
    minutes of held connection to answer "roughly how big is this",
    which is the only question this section exists for. Estimates are
    labelled as such so nobody quotes them as row counts.
    """
    # Through ``_guarded``, not a bare try/except: a swallowed statement
    # error leaves PostgreSQL in "current transaction is aborted", which
    # takes out every LATER section and the caller's own commit. The
    # savepoint is what confines the damage to this one section.
    result = await _guarded(
        db,
        lambda: db.execute(text("""
                    SELECT c.relname,
                           GREATEST(c.reltuples, 0)::bigint AS approx_rows,
                           pg_total_relation_size(c.oid)     AS total_bytes
                      FROM pg_class c
                      JOIN pg_namespace n ON n.oid = c.relnamespace
                     WHERE c.relkind = 'r' AND n.nspname = 'public'
                     ORDER BY pg_total_relation_size(c.oid) DESC
                    """)),
    )
    if isinstance(result, str):
        return _json({"error": result})
    rows = result.all()

    payload: dict[str, Any] = {
        "_note": (
            "approx_rows is the PostgreSQL planner estimate (pg_class.reltuples), "
            "refreshed by ANALYZE — not an exact count."
        ),
        "tables": [
            {"table": name, "approx_rows": int(approx), "total_bytes": int(size)}
            for name, approx, size in rows
        ],
    }
    payload["database_size_bytes"] = await _guarded(
        db, lambda: db.scalar(text("SELECT pg_database_size(current_database())"))
    )
    return _json(payload)

"""Capture path for unhandled exceptions (issue #123).

Two callers:

* ``record_unhandled_exception_async`` — used by the FastAPI
  exception handler in :mod:`app.main`. Runs inside an active event
  loop with the async DB session available.
* ``record_unhandled_exception`` — synchronous variant for the
  Celery ``task_failure`` signal. Celery is sync, so it runs the async
  variant on a short-lived thread with its own event loop and a fresh
  asyncpg engine.

Both share:

* :func:`_sanitise_context` — strips ``Authorization`` / ``Cookie`` /
  ``X-API-Token`` and any header / body field whose name matches
  ``password|secret|token|key`` (case-insensitive). Bodies > 4 KB are
  replaced with ``<truncated: N bytes>``. The whole ``context_json``
  blob is capped at 16 KB.
* :func:`_compute_fingerprint` — sha256(exception_class + top-2
  frames). Used to dedupe noisy crashes — repeated occurrences of
  the same fingerprint within the suppression window bump
  ``occurrence_count`` instead of inserting a new row.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import traceback as tb_mod
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.diagnostics import InternalError

logger = structlog.get_logger(__name__)

# Headers whose value we never want to land in ``context_json``.
_REDACT_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-token",
        "x-auth-token",
        "x-csrf-token",
        "proxy-authorization",
    }
)

# Field-name pattern for body / params dicts. Anything matching gets
# replaced with the literal string ``"<redacted>"``.
_REDACT_FIELD_RE = re.compile(r"(?i)(password|secret|token|key|credential)")

# Caps. ``_BODY_CAP`` triggers per-body truncation; ``_CONTEXT_CAP``
# truncates the whole serialised JSON blob if the per-field truncation
# wasn't enough.
_BODY_CAP = 4 * 1024
_CONTEXT_CAP = 16 * 1024
_TRACEBACK_CAP = 16 * 1024

# How long the Celery hook waits for a capture. The capture carries on
# past this on its own thread; the wait only bounds how long a failing
# task holds its worker slot, which a database outage would otherwise
# stretch to asyncpg's full connect timeout.
_SYNC_CAPTURE_WAIT_S = 15.0


def _sanitise_dict(d: dict[str, Any], *, redact_headers: bool = False) -> dict[str, Any]:
    """Walk ``d`` and replace sensitive values with ``"<redacted>"``.

    ``redact_headers=True`` additionally replaces values for keys
    matching :data:`_REDACT_HEADERS` (case-insensitive).
    """
    out: dict[str, Any] = {}
    for k, v in d.items():
        kl = k.lower()
        if redact_headers and kl in _REDACT_HEADERS:
            out[k] = "<redacted>"
            continue
        if _REDACT_FIELD_RE.search(k):
            out[k] = "<redacted>"
            continue
        if isinstance(v, dict):
            out[k] = _sanitise_dict(v, redact_headers=redact_headers)
        elif isinstance(v, list):
            out[k] = [
                (
                    _sanitise_dict(item, redact_headers=redact_headers)
                    if isinstance(item, dict)
                    else item
                )
                for item in v
            ]
        else:
            out[k] = v
    return out


def _truncate_body(body: Any) -> Any:
    """Replace oversized request/task bodies with a marker.

    Bodies under 4 KB pass through unchanged. Larger payloads are
    replaced with a string carrying the original byte size so the
    operator can tell *something* big was in flight.
    """
    if body is None:
        return None
    try:
        encoded = json.dumps(body, default=str)
    except Exception:
        return f"<unserialisable: {type(body).__name__}>"
    if len(encoded) > _BODY_CAP:
        return f"<truncated: {len(encoded)} bytes>"
    return body


def _sanitise_context(context: dict[str, Any] | None) -> dict[str, Any]:
    """Top-level sanitisation entry point. Idempotent + safe on input
    that's already partially redacted.
    """
    if not context:
        return {}
    cleaned: dict[str, Any] = {}
    for key, value in context.items():
        if key in {"headers", "request_headers"} and isinstance(value, dict):
            cleaned[key] = _sanitise_dict(value, redact_headers=True)
        elif key in {"body", "request_body", "task_args", "task_kwargs"}:
            if isinstance(value, dict):
                cleaned[key] = _truncate_body(_sanitise_dict(value))
            else:
                cleaned[key] = _truncate_body(value)
        elif isinstance(value, dict):
            cleaned[key] = _sanitise_dict(value)
        else:
            cleaned[key] = value
    # Final cap on the serialised blob — covers pathological inputs
    # that snuck past per-field truncation (e.g. 200 small fields each
    # under 4 KB but adding up to 800 KB).
    encoded = json.dumps(cleaned, default=str)
    if len(encoded) > _CONTEXT_CAP:
        return {
            "_truncated": True,
            "_original_size": len(encoded),
            "_note": (
                "context_json exceeded 16 KB even after per-field "
                "truncation; full payload dropped"
            ),
        }
    return cleaned


def _compute_fingerprint(exception_class: str, traceback_str: str) -> str:
    """Hash exception class + top-2 frames into a 64-char sha256 hex.

    Top frames are the most stable identifier of "same crash" across
    runs — file/line numbers in the deepest frame change with code
    edits, but the entry point + first hop usually holds steady. Two
    frames is enough signal to disambiguate without making the
    fingerprint too volatile to dedup against.
    """
    frames = [
        line.strip() for line in traceback_str.splitlines() if line.strip().startswith("File ")
    ][:2]
    payload = exception_class + "\n" + "\n".join(frames)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _format_traceback(exc: BaseException) -> str:
    raw = "".join(tb_mod.format_exception(type(exc), exc, exc.__traceback__))
    if len(raw) > _TRACEBACK_CAP:
        return raw[:_TRACEBACK_CAP] + f"\n... <truncated, full was {len(raw)} bytes>"
    return raw


def _exception_class_name(exc: BaseException) -> str:
    cls = type(exc)
    return f"{cls.__module__}.{cls.__qualname__}"


async def record_unhandled_exception_async(
    db: AsyncSession,
    *,
    service: str,
    exc: BaseException,
    route_or_task: str | None = None,
    request_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    """Persist an unhandled exception via the async DB session.

    Failures here are swallowed: the diagnostic surface must never
    raise a second exception inside the original request's error
    handler. We log the swallowing at WARNING so operators can spot
    the meta-bug if the diagnostics surface itself is sick.
    """
    try:
        cls_name = _exception_class_name(exc)
        message = (str(exc) or cls_name)[:1000]
        traceback_str = _format_traceback(exc)
        fingerprint = _compute_fingerprint(cls_name, traceback_str)
        clean_context = _sanitise_context(context)
        now = datetime.now(UTC)

        # Dedupe path — bump occurrence_count + last_seen_at on an
        # active fingerprint match. ``suppressed_until`` lets
        # operators silence noisy crashes for a while; while it's in
        # the future we still bump the counter (so the unack'd row's
        # last_seen_at refreshes) but don't insert a new row.
        result = await db.execute(
            update(InternalError)
            .where(InternalError.fingerprint == fingerprint)
            .values(
                occurrence_count=InternalError.occurrence_count + 1,
                last_seen_at=now,
            )
            .returning(InternalError.id)
        )
        if result.first() is not None:
            await db.commit()
            return
        row = InternalError(
            service=service,
            request_id=request_id,
            route_or_task=route_or_task,
            exception_class=cls_name,
            message=message,
            traceback=traceback_str,
            context_json=clean_context,
            fingerprint=fingerprint,
            last_seen_at=now,
        )
        db.add(row)
        await db.commit()
    except Exception as inner_exc:
        # Never re-raise — the caller is already handling a real
        # exception and the user response is what matters.
        logger.warning(
            "diagnostics_capture_failed",
            error=str(inner_exc),
            inner_class=type(inner_exc).__name__,
            captured_class=_exception_class_name(exc),
        )


def record_unhandled_exception(
    *,
    service: str,
    exc: BaseException,
    route_or_task: str | None = None,
    request_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    """Synchronous variant for Celery's ``task_failure`` signal.

    Runs :func:`record_unhandled_exception_async` on a fresh asyncpg engine
    (``task_session``), on a short-lived thread with its own event loop. The
    backend ships no sync PostgreSQL driver: this used to open a
    ``postgresql://`` engine, which loads psycopg2 (psycopg 3 from
    SQLAlchemy 2.1), so every worker failure was dropped with a warning
    (#1193). The thread keeps the capture out of the failing task's event
    loop state, and lets it run when the signal fires inside a running loop
    (an eager task, or a test), where ``asyncio.run`` would refuse.

    Failure-tolerant for the same reason as the async variant.
    """
    try:
        from app.db import task_session  # noqa: PLC0415

        async def _capture() -> None:
            async with task_session() as db:
                await record_unhandled_exception_async(
                    db,
                    service=service,
                    exc=exc,
                    route_or_task=route_or_task,
                    request_id=request_id,
                    context=context,
                )

        def _run() -> None:
            try:
                asyncio.run(_capture())
            except Exception as inner_exc:
                logger.warning(
                    "diagnostics_capture_failed_sync",
                    error=str(inner_exc),
                    inner_class=type(inner_exc).__name__,
                    captured_class=_exception_class_name(exc),
                )

        thread = threading.Thread(target=_run, name="diagnostics-capture", daemon=True)
        thread.start()
        thread.join(_SYNC_CAPTURE_WAIT_S)
        if thread.is_alive():
            logger.warning(
                "diagnostics_capture_slow_sync",
                waited_s=_SYNC_CAPTURE_WAIT_S,
                captured_class=_exception_class_name(exc),
            )
    except Exception as inner_exc:
        logger.warning(
            "diagnostics_capture_failed_sync",
            error=str(inner_exc),
            inner_class=type(inner_exc).__name__,
            captured_class=_exception_class_name(exc),
        )

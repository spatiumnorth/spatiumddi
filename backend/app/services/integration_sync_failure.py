"""Record a crashed integration reconcile on its target row (#2141).

Every integration reconciler persists ``last_sync_error`` /
``last_synced_at`` itself — but inside the same transaction as the
mirror writes. When a reconcile *raises* (rather than returning a
summary with ``ok=False``) the sweep task rolls that transaction back,
and the row is left exactly as it was: a target that has never synced
shows no data and no error, the per-target interval gate (keyed on
``last_synced_at``) never engages so the target is retried on every
beat tick, and the error audit row the Integrations dashboard reads
(non-negotiable #15) is rolled back with everything else.

``record_sync_crash`` is the one place every sweep task and every
"Sync Now" task sends that case. It runs AFTER the caller's rollback,
so the partial reconcile stays discarded, and commits the failure in
its own transaction so it survives. It never raises: failing to
record a crash must not abort the rest of the sweep.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.exc import StatementError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog

logger = structlog.get_logger(__name__)

# Long enough for a Postgres DETAIL line, short enough for a card.
_MAX_ERROR_CHARS = 1000

# ``https://user:secret@host`` — userinfo in a URL an HTTP client echoed.
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@'\"]+@")
# ``?token=…`` / ``&api_key=…`` — a credential an API takes as a query
# parameter, echoed by httpx in "… for url '<url>'".
_SECRET_QUERY = re.compile(
    r"(?i)([?&][a-z0-9_.-]*(?:token|key|secret|passw(?:or)?d|pass|auth|sig|signature|"
    r"credential|session)[a-z0-9_.-]*=)[^&\s'\"]*"
)
# Postgres NOT NULL / CHECK violations print the whole offending row in
# DETAIL — on an integration row that includes the encrypted credentials.
# Redacted to the end of its line, since a value may itself contain ")".
_FAILING_ROW = re.compile(r"(?i)(Failing row contains ).*")


def _scrub(text: str) -> str:
    text = _URL_USERINFO.sub(r"\1***@", text)
    text = _SECRET_QUERY.sub(r"\1***", text)
    return _FAILING_ROW.sub(r"\1(…)", text)


def describe_sync_crash(exc: BaseException) -> str:
    """The operator-facing text for a reconcile crash.

    A SQLAlchemy ``StatementError`` stringifies with the full SQL and its
    bound ``[parameters: …]`` — which on an integration row can include
    encrypted credential columns — so only the driver's own message is
    kept. Anything else is ``<Type>: <message>``, cut at any trailing
    ``[SQL:`` block for the same reason. URL userinfo, credential-shaped
    query parameters and a Postgres "Failing row contains (…)" detail are
    redacted, because the text is persisted on the row and in an audit
    row that may be forwarded off-box. Then truncated.
    """
    if isinstance(exc, StatementError) and exc.orig is not None:
        text = str(exc.orig)
    else:
        text = str(exc)
    text = _scrub(text.split("[SQL:", 1)[0].strip())
    text = f"{type(exc).__name__}: {text}" if text else type(exc).__name__
    if len(text) > _MAX_ERROR_CHARS:
        text = text[: _MAX_ERROR_CHARS - 1] + "…"
    return text


async def record_sync_crash(
    db: AsyncSession,
    model: type[Any],
    target_id: uuid.UUID,
    *,
    resource_type: str,
    action: str,
    exc: BaseException,
    error_field: str = "last_sync_error",
    stamp_field: str = "last_synced_at",
) -> str:
    """Persist a crashed reconcile on ``model`` row ``target_id``.

    The caller must already have rolled ``db`` back. Stamps
    ``error_field`` with the (sanitised) exception text and
    ``stamp_field`` with now — the same pair the reconcilers' own
    fetch-failure paths stamp, so the interval gate backs off — and adds
    a ``result="error"`` audit row under ``resource_type``, then commits.
    Returns the recorded text.
    """
    message = describe_sync_crash(exc)
    try:
        row = await db.get(model, target_id, populate_existing=True)
        if row is None:  # deleted mid-sweep — nothing to record on
            return message
        setattr(row, error_field, message)
        setattr(row, stamp_field, datetime.now(UTC))
        db.add(
            AuditLog(
                user_display_name="system",
                auth_source="system",
                action=action,
                resource_type=resource_type,
                resource_id=str(target_id),
                resource_display=getattr(row, "name", None) or str(target_id),
                result="error",
                error_detail=message,
            )
        )
        await db.commit()
    except Exception as record_exc:  # noqa: BLE001 — never abort the sweep over this
        await db.rollback()
        logger.warning(
            "integration_sync_crash_record_failed",
            resource_type=resource_type,
            target=str(target_id),
            error=str(record_exc),
        )
    return message


__all__ = ["describe_sync_crash", "record_sync_crash"]

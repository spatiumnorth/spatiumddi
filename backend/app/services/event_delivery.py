"""Event-outbox delivery worker — pulls pending rows, signs with HMAC,
POSTs, and on failure retries with exponential backoff up to the
subscription's ``max_attempts`` ceiling. Anything beyond that flips to
``state='dead'`` for operator review.

Wire format (every delivery POST):

* Body: the ``EventOutbox.payload`` JSON object (matches
  ``event_publisher._serialize_audit``).
* Headers:
    * ``Content-Type: application/json``
    * ``User-Agent: SpatiumDDI/<version>``
    * ``X-SpatiumDDI-Event: <event_type>``
    * ``X-SpatiumDDI-Delivery: <outbox_id>``
    * ``X-SpatiumDDI-Timestamp: <unix-seconds>``
    * ``X-SpatiumDDI-Signature: sha256=<hex>``
      where the digest is ``hmac(secret, ts + "." + body, sha256)``.
      Receivers verify by recomputing the HMAC and ensuring the
      timestamp is within their tolerance window (default 5 min).

Backoff: 2^attempt seconds, capped at 600 (10 min) to keep the next-
attempt timeline readable. Eight default attempts ≈
2+4+8+16+32+64+128+256s ≈ 8.5 min cumulative wait.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as _app_settings
from app.core.crypto import decrypt_dict, decrypt_str
from app.models.event_subscription import EventOutbox, EventSubscription

logger = structlog.get_logger(__name__)

_BATCH_SIZE = 100
_MAX_BACKOFF_SECONDS = 600


def _backoff_seconds(attempt: int) -> int:
    """``attempt`` is the number of attempts ALREADY made (1+ when
    we're retrying after a failure). Returns the wait before the next
    attempt — 2, 4, 8, 16, …, capped at ``_MAX_BACKOFF_SECONDS``."""
    return min(2 ** max(1, attempt), _MAX_BACKOFF_SECONDS)


def _sign(secret: str, ts: str, body: bytes) -> str:
    """Compute the canonical signature header value."""
    if not secret:
        return ""
    payload = ts.encode("ascii") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def subscription_headers(sub: EventSubscription) -> dict[str, str]:
    """The subscription's custom headers, decrypted (#1579).

    Returns ``{}`` when none are stored. Raises ``ValueError`` when the
    stored ciphertext won't decrypt under this install's key — callers
    decide whether that fails the delivery or just the header names.
    """
    if not sub.headers_encrypted:
        return {}
    return {str(k): str(v) for k, v in decrypt_dict(sub.headers_encrypted).items()}


async def _deliver_one(
    client: httpx.AsyncClient,
    sub: EventSubscription,
    row: EventOutbox,
    secret: str,
    sw_version: str,
) -> tuple[int | None, str | None]:
    """POST one outbox row. Returns ``(status_code | None, error | None)``."""
    import json as _json

    body_bytes = _json.dumps(row.payload, separators=(",", ":"), default=str).encode("utf-8")
    ts = str(int(time.time()))
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": f"SpatiumDDI/{sw_version}",
        "X-SpatiumDDI-Event": row.event_type,
        "X-SpatiumDDI-Delivery": str(row.id),
        "X-SpatiumDDI-Timestamp": ts,
    }
    sig = _sign(secret, ts, body_bytes)
    if sig:
        headers["X-SpatiumDDI-Signature"] = sig
    # Operator-supplied custom headers — applied last so the SpatiumDDI-
    # owned ones above can't be silently overridden. Decrypted here, at
    # send time only (#1579); the values never leave this function.
    try:
        custom_headers = subscription_headers(sub)
    except Exception as exc:  # noqa: BLE001
        return None, f"headers decrypt failed: {exc}"
    for k, v in custom_headers.items():
        if k.lower().startswith("x-spatiumddi-"):
            continue
        headers[k] = v

    try:
        resp = await client.post(
            sub.url,
            content=body_bytes,
            headers=headers,
            timeout=max(1, min(30, sub.timeout_seconds or 10)),
        )
    except httpx.HTTPError as exc:
        return None, f"transport: {exc}"

    if 200 <= resp.status_code < 300:
        return resp.status_code, None
    return resp.status_code, f"http {resp.status_code}: {resp.text[:200]}"


async def process_due_outbox(db: AsyncSession) -> dict[str, int]:
    """Drain a batch of due outbox rows.

    Returns a counter dict suitable for the scheduled-task audit row.
    Uses ``FOR UPDATE SKIP LOCKED`` so two workers ticking in parallel
    don't deliver the same row twice.
    """
    now = datetime.now(UTC)

    # Single query: lock the next batch atomically. ``SELECT … FOR
    # UPDATE SKIP LOCKED`` is the standard outbox-claiming idiom on
    # Postgres — it lets concurrent workers cooperate without a
    # leader-election dance.
    res = await db.execute(
        text("""
            SELECT id FROM event_outbox
            WHERE state IN ('pending', 'failed')
              AND next_attempt_at <= :now
            ORDER BY next_attempt_at ASC
            LIMIT :batch
            FOR UPDATE SKIP LOCKED
            """),
        {"now": now, "batch": _BATCH_SIZE},
    )
    ids = [r[0] for r in res.all()]
    if not ids:
        return {"claimed": 0, "delivered": 0, "failed": 0, "dead": 0}

    # Hydrate the rows + their subscriptions in one round trip.
    rows_res = await db.execute(select(EventOutbox).where(EventOutbox.id.in_(ids)))
    rows = list(rows_res.scalars().all())
    sub_ids = {r.subscription_id for r in rows}
    subs_res = await db.execute(select(EventSubscription).where(EventSubscription.id.in_(sub_ids)))
    subs = {s.id: s for s in subs_res.scalars().all()}

    # Mark all claimed rows in_flight before we make any HTTP calls so
    # they don't get re-claimed if a parallel worker ticks before we
    # commit. The state flip happens inside the locking transaction.
    for row in rows:
        row.state = "in_flight"
    await db.flush()

    delivered = 0
    failed = 0
    dead = 0
    sw_version = getattr(_app_settings, "version", "dev")

    async with httpx.AsyncClient() as client:
        for row in rows:
            sub = subs.get(row.subscription_id)
            if sub is None or not sub.enabled:
                # Subscription disappeared or was disabled — drop the row
                # rather than retrying forever. Dead-letter so it shows
                # up in the operator's failed-deliveries view.
                row.state = "dead"
                row.last_error = "subscription not enabled"
                dead += 1
                continue

            secret = ""
            if sub.secret_encrypted:
                try:
                    secret = decrypt_str(sub.secret_encrypted)
                except Exception as exc:  # noqa: BLE001
                    row.state = "dead"
                    row.last_error = f"secret decrypt failed: {exc}"
                    dead += 1
                    continue

            status_code, error = await _deliver_one(client, sub, row, secret, sw_version)
            row.attempts = (row.attempts or 0) + 1
            row.last_status_code = status_code
            row.last_error = error

            if error is None:
                row.state = "delivered"
                row.delivered_at = datetime.now(UTC)
                delivered += 1
                continue

            # Failed — decide retry vs dead.
            if row.attempts >= max(1, sub.max_attempts or 8):
                row.state = "dead"
                dead += 1
            else:
                row.state = "failed"
                row.next_attempt_at = datetime.now(UTC) + timedelta(
                    seconds=_backoff_seconds(row.attempts)
                )
                failed += 1

    await db.commit()
    if delivered or failed or dead:
        logger.info(
            "event_delivery_pass",
            claimed=len(rows),
            delivered=delivered,
            failed=failed,
            dead=dead,
        )
    return {"claimed": len(rows), "delivered": delivered, "failed": failed, "dead": dead}


__all__ = ["process_due_outbox", "subscription_headers", "_sign", "_backoff_seconds"]


# Manual retry helper used by the API "retry now" endpoint. Flips a
# dead/failed row back to pending with attempts=0 so the next worker
# tick re-tries immediately.
async def reset_outbox_row(db: AsyncSession, row: EventOutbox, _: Any | None = None) -> None:
    row.state = "pending"
    row.attempts = 0
    row.last_error = None
    row.last_status_code = None
    row.next_attempt_at = datetime.now(UTC)

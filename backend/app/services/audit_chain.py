"""Audit-log tamper-evidence chain (issue #73).

Every ``AuditLog`` insert goes through ``compute_audit_hashes`` —
hooked into the ``before_flush`` event in
``app.db.session_event_listeners`` — which:

1. Filters ``session.new`` for AuditLog rows whose ``row_hash`` is
   still empty (so re-flushes after a transient error don't
   double-hash).
2. Sorts the new rows by ``(timestamp, id)`` for a deterministic
   ordering.
3. Takes a Postgres transaction-scoped advisory lock so concurrent
   transactions can't interleave their "fetch previous hash, hash my
   row, write it" sequence.
4. Fetches the latest existing ``row_hash`` (where ``seq = MAX(seq)``)
   to seed ``prev_hash`` for the first new row.
5. Walks the new rows in order, computing
   ``row_hash = sha256(prev_hash || canonical_json(row))``.

Verifier ``verify_chain`` walks the table in seq order, recomputes
the hash for every row, and returns the first break so an alert
event / Conformity result can call out the offending row.

Canonical JSON shape MUST stay aligned with the migration's backfill
helper (``alembic/versions/d92f4a18c763_audit_chain_hash.py``) — any
new audit-log column you add and want included in the hash needs to
land in both places, or the verifier will mark every old row as
broken on the next run.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import structlog
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.audit import AuditLog

logger = structlog.get_logger(__name__)

# Constant advisory-lock key; doesn't conflict with anything else
# because we own this namespace. Must fit in BIGINT.
_AUDIT_CHAIN_LOCK_KEY = 0x4144495441554449  # ASCII "ADITAUDI" — close enough


def canonical_json(row: AuditLog) -> str:
    """Deterministic JSON over the columns that participate in the
    hash. ``seq``, ``row_hash``, ``prev_hash`` are NEVER in the
    payload — they describe the row's chain position, not its
    content. Keep in sync with the backfill helper in the migration.
    """
    payload: dict[str, Any] = {
        "id": str(row.id),
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "user_id": str(row.user_id) if row.user_id else None,
        "user_display_name": row.user_display_name,
        "auth_source": row.auth_source,
        "source_ip": row.source_ip,
        "user_agent": row.user_agent,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "resource_display": row.resource_display,
        "old_value": row.old_value,
        "new_value": row.new_value,
        "changed_fields": row.changed_fields,
        "request_id": row.request_id,
        "result": row.result,
        "error_detail": row.error_detail,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


#: The JSONB columns that participate in the hash.
_JSONB_HASHED_COLUMNS = ("old_value", "new_value", "changed_fields")


def _pg_number(token: str) -> int | float:
    """The number PostgreSQL hands back for a JSON number ``token``.

    JSONB stores numbers as ``numeric`` and prints them in plain decimal
    notation with no exponent and no negative zero, so ``1e+16`` comes back
    as the integer ``10000000000000000`` and ``-0.0`` as ``0.0``. A token
    whose decimal exponent is non-negative has no fractional digits and
    therefore reads back as an int; any other token reads back as the same
    float (``repr`` is round-trip exact), bar the sign of zero.
    """
    exponent = Decimal(token).as_tuple().exponent
    if isinstance(exponent, int) and exponent >= 0:
        return int(Decimal(token))
    value = float(token)
    return 0.0 if value == 0 else value


def normalise_jsonb_value(value: Any) -> Any:
    """``value`` exactly as a JSONB column will return it (GHSA-8288-8vg9-82gr).

    ``compute_audit_hashes`` hashes before the INSERT and ``verify_chain``
    re-hashes what PostgreSQL returns, so anything the JSONB round trip
    rewrites made an honest row report ``row_hash_mismatch``. Serialises the
    way the engine's ``json_serializer`` does (``default=str``, so UUIDs,
    datetimes and Decimals become the strings that are stored), then maps
    every number to what ``numeric`` prints. ``NaN`` / ``Infinity``, which
    JSONB rejects outright (failing the INSERT and the audited change with
    it), are kept as the strings ``"NaN"`` / ``"Infinity"`` / ``"-Infinity"``.
    """
    if value is None:
        return None
    return json.loads(
        json.dumps(value, default=str),
        parse_float=_pg_number,
        parse_constant=str,
    )


#: ``AuditLog.request_id`` is ``String(64)``.
_REQUEST_ID_MAX = 64


def _current_request_id() -> str | None:
    """The ``request_id`` bound in structlog's context, if any.

    ``RequestContextMiddleware`` binds it for every API request, and the
    Celery ``task_prerun`` hook binds the task id (#1246), so a row written
    by either carries the id its log lines carry. Capped to the column: an
    over-long value would fail the INSERT, and with it the audited change.
    """
    value = structlog.contextvars.get_contextvars().get("request_id")
    if value is None:
        return None
    return str(value)[:_REQUEST_ID_MAX] or None


def hash_row(prev_hash: str | None, canonical: str) -> str:
    h = hashlib.sha256()
    if prev_hash is not None:
        h.update(prev_hash.encode())
    h.update(b"|")
    h.update(canonical.encode())
    return h.hexdigest()


def compute_audit_hashes(session: Session) -> None:
    """``before_flush`` listener target. Synchronous — runs in the
    same DB session the request is using.

    Looks up the latest persisted row's hash inside an advisory lock
    so two concurrent transactions both inserting audit rows can't
    end up with the same ``prev_hash`` and produce a fork.
    """
    new_rows = [obj for obj in session.new if isinstance(obj, AuditLog) and not obj.row_hash]
    if not new_rows:
        return

    # Materialise the Python + server defaults BEFORE we hash. Defaults
    # (``id`` via ``default=uuid.uuid4``, ``timestamp`` via
    # ``server_default=now()``, plus scalar defaults like
    # ``auth_source`` / ``result``) fire during SQLAlchemy's flush phase,
    # AFTER this ``before_flush`` event. Without this step the hash sees
    # the not-yet-defaulted values while the DB later stores the real
    # ones, and the verifier reports row_hash_mismatch on every row.
    # Setting the attributes here forces SQLAlchemy to carry the explicit
    # values through to the INSERT, overriding the defaults with the same
    # values we just hashed over.
    now = datetime.now(UTC)
    request_id = _current_request_id()
    for row in new_rows:
        if row.id is None:
            row.id = uuid.uuid4()
        if row.timestamp is None:
            row.timestamp = now
        # #1245 — the column existed, was in the hash, and no writer ever
        # set it, although the docs say it links an audit row to its
        # request's log lines. Filled here, the one path every AuditLog
        # insert takes, and BEFORE hashing, so the stored value is the
        # hashed one. An explicit value on the row wins.
        if row.request_id is None and request_id is not None:
            row.request_id = request_id
        # Also materialise any Python-side *scalar* column defaults that
        # are still unset. Columns like ``auth_source`` (default "local")
        # and ``result`` (default "success") are None at before_flush time
        # but the ORM fills them during flush — so the hash MUST see the
        # same value the DB will store, or ``verify_chain`` reports a false
        # ``row_hash_mismatch`` for every row that didn't pass those fields
        # explicitly (e.g. system-generated audit rows). This was the
        # residual half of #73: the original fix only materialised ``id`` +
        # ``timestamp`` and missed the scalar string defaults. Driving it
        # off column metadata (not a hand-list) keeps it correct if a
        # future defaulted column is added. Callable defaults (uuid4) are
        # is_scalar=False and handled above; server_default columns
        # (timestamp) carry ``col.default = None`` and are handled above.
        for col in row.__table__.columns:
            default = col.default
            if (
                default is not None
                and getattr(default, "is_scalar", False)
                and getattr(row, col.key, None) is None
            ):
                setattr(row, col.key, default.arg)
        # Store what is hashed: hand the row the JSONB-round-tripped form of
        # its JSON payloads, so the verifier's re-hash of the read-back row
        # sees the same values. ``canonical_json`` itself is untouched —
        # every existing hash and the migration backfill depend on it.
        for key in _JSONB_HASHED_COLUMNS:
            current = getattr(row, key)
            if current is not None:
                setattr(row, key, normalise_jsonb_value(current))

    # DO NOT re-sort. ``verify_chain`` walks rows by ``seq`` (the DB
    # sequence assigned at INSERT) and checks each row's ``prev_hash``
    # against the previous-by-seq row, so the chain MUST be built in the
    # same order the rows will be inserted. ``session.new`` iterates in
    # insertion (add) order in SQLAlchemy 2.x, and same-mapper inserts
    # preserve that order — so add-order == insert-order == seq-order.
    # The previous ``sort(key=(timestamp, id))`` broke this whenever
    # several audit rows landed in one flush with the same timestamp:
    # the uuid tie-break reordered the chain away from seq order and
    # verify_chain reported a false ``prev_hash_mismatch``.

    # Transaction-scoped advisory lock; auto-released at COMMIT/ROLLBACK.
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_CHAIN_LOCK_KEY})

    # Fetch the most-recent persisted row's hash. Empty table → None.
    last_hash = session.execute(
        text(
            "SELECT row_hash FROM audit_log "
            "WHERE row_hash IS NOT NULL "
            "ORDER BY seq DESC LIMIT 1"
        )
    ).scalar()

    prev: str | None = last_hash
    for row in new_rows:
        canonical = canonical_json(row)
        row.prev_hash = prev
        row.row_hash = hash_row(prev, canonical)
        prev = row.row_hash


# ── Verifier ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ChainBreak:
    seq: int
    audit_id: str
    expected_hash: str
    actual_hash: str
    reason: str  # "row_hash_mismatch" | "prev_hash_mismatch"
    # Which row broke, so an operator (and the restore drill) can name the
    # audited change without a second lookup (#1615).
    action: str = ""
    resource_type: str = ""
    resource_id: str = ""


@dataclass(frozen=True)
class ChainVerifyResult:
    ok: bool
    rows_checked: int
    breaks: list[ChainBreak]


async def verify_chain(db: AsyncSession, *, max_rows: int | None = None) -> ChainVerifyResult:
    """Walk the audit_log in seq order and check each row's hash.

    A break can be one of two flavours:

    * ``prev_hash_mismatch`` — the row's stored ``prev_hash`` doesn't
      match the previous row's ``row_hash``. Indicates someone
      inserted a row, deleted a row, or rewrote a hash field.
    * ``row_hash_mismatch`` — the row's stored ``row_hash`` doesn't
      match what we recompute from its content + recorded
      ``prev_hash``. Indicates a content edit on the row itself.

    Distinct codes so the alert message can tell operators *what*
    kind of tampering they're looking at.
    """
    stmt = select(AuditLog).order_by(AuditLog.seq.asc())
    if max_rows is not None:
        stmt = stmt.limit(max_rows)
    rows = (await db.execute(stmt)).scalars().all()

    breaks: list[ChainBreak] = []
    expected_prev: str | None = None
    rows_checked = 0
    for row in rows:
        rows_checked += 1
        if row.prev_hash != expected_prev:
            breaks.append(
                ChainBreak(
                    seq=row.seq,
                    audit_id=str(row.id),
                    expected_hash=expected_prev or "",
                    actual_hash=row.prev_hash or "",
                    reason="prev_hash_mismatch",
                    action=row.action,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                )
            )
        canonical = canonical_json(row)
        recomputed = hash_row(row.prev_hash, canonical)
        if recomputed != row.row_hash:
            breaks.append(
                ChainBreak(
                    seq=row.seq,
                    audit_id=str(row.id),
                    expected_hash=recomputed,
                    actual_hash=row.row_hash,
                    reason="row_hash_mismatch",
                    action=row.action,
                    resource_type=row.resource_type,
                    resource_id=row.resource_id,
                )
            )
        expected_prev = row.row_hash
    return ChainVerifyResult(ok=not breaks, rows_checked=rows_checked, breaks=breaks)

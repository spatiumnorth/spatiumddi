"""Per-table retention overview (#2274 items 6 and 7).

One answer to "what is eating my disk, and what governs it?": for each table
that has a retention policy (or that is deliberately kept forever), its size,
its row estimate, the setting that governs it and its oldest row.

Cheap by construction: the row count is ``pg_class.reltuples`` (an estimate,
never ``count(*)``), and the oldest row is one ``MIN()`` on the table's
timestamp column, taken only where that column is the leading column of an
index, so it is an index probe. Where it is not, the oldest row is reported
as unknown with the reason; a sequential scan of a large table is exactly
what this page must not cause.

Shared by ``GET /admin/postgres/retention`` and the ``find_data_retention``
copilot tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.settings import PlatformSettings
from app.services import retention


@dataclass(frozen=True)
class _Entry:
    table: str
    ts_column: str
    #: PlatformSettings column(s) governing the table; empty = none.
    fields: tuple[str, ...]
    unit: str = "days"
    note: str = ""
    #: Window when the settings row is missing (the prune's own fallback).
    default: int | None = None


_FOREVER = "Never pruned."

# Tables governed by settings that predate the batched sweep (part 1 of #2274
# covers the rest, via ``retention.RULES``).
_EXISTING: tuple[_Entry, ...] = (
    _Entry("dns_query_log_entry", "ts", ("log_retention_hours",), "hours", default=24),
    _Entry("dhcp_log_entry", "ts", ("log_retention_hours",), "hours", default=24),
    _Entry("dns_metric_sample", "bucket_at", ("metric_retention_days",), default=7),
    _Entry("dhcp_metric_sample", "bucket_at", ("metric_retention_days",), default=7),
    _Entry("dhcp_lease_history", "expired_at", ("dhcp_lease_history_retention_days",), default=90),
    _Entry(
        "e911_resolution_log", "queried_at", ("e911_resolution_log_retention_days",), default=90
    ),
    _Entry("audit_log", "timestamp", (), note=_FOREVER + " Compliance record."),
)

# The timestamp the prune reads, per swept table.
_RULE_TS: dict[str, str] = {
    "alert_event": "fired_at",
    "ip_mac_history": "last_seen",
    "nmap_scan": "created_at",
    "conformity_result": "evaluated_at",
    "event_outbox": "created_at",
    "user_session": "created_at",
    "ai_chat_session": "created_at",
    "change_request": "created_at",
    "wol_run": "started_at",
    "system_upgrade_run": "started_at",
}

_RULE_NOTE: dict[str, str] = {
    "alert_event": "Resolved events only; the newest per rule and subject is kept.",
    "ip_mac_history": "Acknowledged and known MACs are kept.",
    "nmap_scan": "Finished scans only.",
    "conformity_result": "The newest result per policy and resource is kept.",
    "event_outbox": "Delivered rows only.",
    "user_session": "Expired, or revoked and idle.",
    "ai_chat_session": "Idle sessions; messages and proposals go with them.",
    "change_request": "Closed requests only.",
    "wol_run": "Finished runs only.",
    "system_upgrade_run": "Finished runs only.",
}


def _entries() -> list[_Entry]:
    out = list(_EXISTING)
    for rule in retention.RULES:
        out.append(
            _Entry(
                rule.model.__tablename__,
                _RULE_TS[rule.name],
                (rule.field,),
                note=_RULE_NOTE.get(rule.name, ""),
                default=rule.default_days,
            )
        )
    return out


def _policy(entry: _Entry, ps: PlatformSettings | None) -> tuple[str, int | None, bool]:
    """``(setting name, window, keeps_forever)`` for an entry."""
    if not entry.fields:
        return "", None, True
    field = entry.fields[0]
    value = getattr(ps, field, None) if ps is not None else None
    if value is None:
        return field, entry.default, False
    forever = value <= 0 and field in _ZERO_KEEPS_FOREVER
    return field, int(value), forever


# Windows where 0 means keep forever. For the logs, metrics and the E911
# trail a 0 is not accepted and the prune falls back to its default.
_ZERO_KEEPS_FOREVER = frozenset(
    {"dhcp_lease_history_retention_days"} | {r.field for r in retention.RULES}
)


async def build_retention_overview(db: AsyncSession) -> list[dict[str, Any]]:
    ps = await db.get(PlatformSettings, 1)
    entries = _entries()
    names = [e.table for e in entries]

    meta = {
        r[0]: r
        for r in (
            await db.execute(
                text("""
                    SELECT c.relname,
                           pg_total_relation_size(c.oid),
                           GREATEST(c.reltuples, 0)::bigint
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE c.relkind IN ('r', 'p')
                      AND n.nspname = current_schema()
                      AND c.relname = ANY(:names)
                    """),
                {"names": names},
            )
        ).all()
    }
    # (table, column) pairs that lead an index: a MIN() on them is a probe.
    indexed = {
        (r[0], r[1])
        for r in (
            await db.execute(
                text("""
                    SELECT c.relname, a.attname
                    FROM pg_index i
                    JOIN pg_class c ON c.oid = i.indrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
                    WHERE n.nspname = current_schema()
                      AND c.relname = ANY(:names)
                    """),
                {"names": names},
            )
        ).all()
    }

    rows: list[dict[str, Any]] = []
    for e in entries:
        m = meta.get(e.table)
        if m is None:
            continue  # table absent (module not installed): nothing to report
        field, window, forever = _policy(e, ps)
        oldest: str | None = None
        oldest_note: str | None = None
        if (e.table, e.ts_column) in indexed:
            # Identifiers come from the registry above, never from input.
            val = (await db.execute(text(f'SELECT MIN("{e.ts_column}") FROM "{e.table}"'))).scalar()
            oldest = val.isoformat() if val is not None else None
        else:
            oldest_note = f"{e.ts_column} is not indexed; skipped to avoid a table scan"
        rows.append(
            {
                "table": e.table,
                "total_bytes": int(m[1] or 0),
                "estimated_rows": int(m[2] or 0),
                "retention_setting": field or None,
                "retention_window": window,
                "retention_unit": e.unit if field else None,
                "keeps_forever": forever,
                "oldest_row_column": e.ts_column,
                "oldest_row": oldest,
                "oldest_row_note": oldest_note,
                "note": e.note or None,
            }
        )
    rows.sort(key=lambda r: r["total_bytes"], reverse=True)
    return rows

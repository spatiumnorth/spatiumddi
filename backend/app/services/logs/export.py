"""Streamed CSV / JSON Lines export of the agent query logs (#4171).

The export runs the very statement the list endpoint runs
(``dns_queries_stmt`` / ``dhcp_activity_stmt``), so it carries exactly the
rows the filters select. Rows are pulled through a server-side cursor in
batches and yielded as they are formatted; nothing here holds the result set.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.services.e911.exports import csv_safe

ExportFormat = Literal["csv", "jsonl"]

#: Most rows one export returns. Past it the response is cut and says so
#: (``X-Export-Capped: true``); the operator narrows the filter.
EXPORT_ROW_CAP = 100_000

#: Rows fetched per round trip from the server-side cursor.
_BATCH = 1000

DNS_COLUMNS: tuple[str, ...] = (
    "ts",
    "server",
    "client_ip",
    "client_port",
    "qname",
    "qclass",
    "qtype",
    "flags",
    "view",
    "rcode",
    "answer_count",
    "raw",
)

DHCP_COLUMNS: tuple[str, ...] = (
    "ts",
    "server",
    "severity",
    "code",
    "mac_address",
    "ip_address",
    "transaction_id",
    "raw",
)

_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def dns_record(r: DNSQueryLogEntry, names: Mapping[uuid.UUID, str]) -> dict[str, Any]:
    return {
        "ts": _iso(r.ts),
        "server": names.get(r.server_id, str(r.server_id)),
        "client_ip": str(r.client_ip) if r.client_ip is not None else None,
        "client_port": r.client_port,
        "qname": r.qname,
        "qclass": r.qclass,
        "qtype": r.qtype,
        "flags": r.flags,
        "view": r.view,
        "rcode": r.rcode,
        "answer_count": r.answer_count,
        "raw": r.raw,
    }


def dhcp_record(r: DHCPLogEntry, names: Mapping[uuid.UUID, str]) -> dict[str, Any]:
    return {
        "ts": _iso(r.ts),
        "server": names.get(r.server_id, str(r.server_id)),
        "severity": r.severity,
        "code": r.code,
        "mac_address": str(r.mac_address) if r.mac_address is not None else None,
        "ip_address": str(r.ip_address) if r.ip_address is not None else None,
        "transaction_id": r.transaction_id,
        "raw": r.raw,
    }


def export_filename(label: str, ext: str, *, now: datetime | None = None) -> str:
    """``<label>-YYYYMMDDTHHMMZ.<ext>``, UTC, ``label`` reduced to a safe slug."""
    stamp = (now or datetime.now(UTC)).astimezone(UTC).strftime("%Y%m%dT%H%MZ")
    return f"{_SLUG.sub('-', label).strip('-') or 'all'}-{stamp}.{ext}"


async def count_capped(db: AsyncSession, stmt: Select[Any]) -> int:
    """How many rows the export will emit: ``min(matches, cap + 1)``.

    Counted up to one past the cap so ``> EXPORT_ROW_CAP`` means "capped"
    without a full count over a large table.
    """
    sub = stmt.order_by(None).limit(EXPORT_ROW_CAP + 1).subquery()
    return (await db.execute(select(func.count()).select_from(sub))).scalar_one()


async def stream_export(
    db: AsyncSession,
    stmt: Select[Any],
    *,
    fmt: ExportFormat,
    columns: Sequence[str],
    to_record: Callable[[Any], dict[str, Any]],
) -> AsyncIterator[str]:
    """Yield the export body in chunks, at most ``EXPORT_ROW_CAP`` rows."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    if fmt == "csv":
        writer.writerow(columns)
        yield buf.getvalue()
        buf.seek(0)
        buf.truncate()
    result = await db.stream_scalars(stmt.limit(EXPORT_ROW_CAP).execution_options(yield_per=_BATCH))
    async for row in result:
        rec = to_record(row)
        if fmt == "csv":
            writer.writerow([csv_safe(rec[c]) for c in columns])
        else:
            buf.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if buf.tell() >= 64 * 1024:
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
    tail = buf.getvalue()
    if tail:
        yield tail

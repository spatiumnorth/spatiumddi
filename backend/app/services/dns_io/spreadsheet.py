"""A zone's records as a spreadsheet: CSV / XLSX export, template, import plan (#2139).

The zone-file import (``parser`` / ``diff``) moves a zone between servers; this
module is for the other job, editing many records at once in a spreadsheet.
It owns the spreadsheet *format* and the import *plan* — which rows add, change
or delete which records — and nothing else. Validation is the record API's own:
the router hands :func:`plan_import` a callback that runs the same checks
``POST …/records`` runs, so a row the API would refuse is a per-row error here.
The plan is applied by the same commit path the zone-file import uses (one
serial bump, one ``enqueue_record_ops_batch``), so agents receive record ops.

Columns (``RECORD_COLUMNS``), one row per record::

    id, name, type, ttl, value, priority, weight, port, view, comment, managed

* ``id`` — the record's UUID on export. On import it is how a row finds its
  record, so a rename or a value change is an update of THAT record rather than
  a delete plus a create. Blank means "match by content, else create".
  ``EXAMPLE`` marks a template example row, which import ignores.
* ``priority`` / ``weight`` / ``port`` — the model's structured columns: MX
  takes ``priority``; SRV takes all three. Every other type (CAA, TLSA, SSHFP,
  NAPTR, SVCB, …) is stored as one presentation-format rdata string, so it is
  edited in ``value`` exactly as the record API takes it.
* ``ttl`` — blank inherits the zone's ``$TTL``.
* ``view`` — the split-horizon view's name; blank renders into every view.
* ``comment`` — free text, stored as the record's ``comment`` tag. It never
  reaches a DNS server.
* ``managed`` — export only, ignored on import: why a row is read-only
  (``ipam``, ``pool``, ``acme``, ``ddns``, …). Blank for an operator-owned record.

Match rule, per row, in this order:

1. ``id`` set → that record, which must be a live record in this zone of the
   same type (a record's type is immutable, as on the record API). Any other
   column may change.
2. ``id`` blank → the zone's record with the same view, name (case-insensitive),
   type and value; of several identical twins, the first one not already
   matched. A row that matches nothing is a create.

A record claimed by two rows makes the second an error. ``merge`` (default)
never deletes; ``replace`` also deletes every record no row matched. Records an
integration owns (IPAM, a DNS pool, Tailscale, NetBird, Kubernetes) are never
changed or deleted from a spreadsheet: an unchanged row for one is reported
unchanged, a changed one is skipped with the reason.
"""

from __future__ import annotations

import codecs
import csv
import io
import uuid
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSView, DNSZone
from app.services.dns.cname_conflict import NameRow, refused_by_cname_rule
from app.services.dns.ingest import EXTERNAL_IMPORT_SOURCE
from app.services.integration_ownership import ACME_RECORD_TAG
from app.services.ipam_io.export import FORMULA_TRIGGERS, sanitize_cell

RECORD_COLUMNS: list[str] = [
    "id",
    "name",
    "type",
    "ttl",
    "value",
    "priority",
    "weight",
    "port",
    "view",
    "comment",
    "managed",
]
REQUIRED_COLUMNS = ("name", "type", "value")
# The ``id`` cell that marks a template example row; import ignores the row.
EXAMPLE_MARKER = "EXAMPLE"
# The tag key ``comment`` is stored under.
COMMENT_TAG = "comment"
# Bound per request: rows in one file (one transaction, one op batch).
MAX_ROWS = 10_000
# Rows read at all, blank ones included: the cap above counts only rows with
# data, so without this a file of a few million empty rows would still be
# walked (and, for CSV, held) in full before anything refused it.
MAX_SHEET_ROWS = 100_000
# An XLSX is a zip: the upload cap bounds the compressed size only, and
# openpyxl holds the shared-strings part in memory whole. The declared
# uncompressed size of every member is checked before openpyxl sees the file
# (zipfile never inflates a member past its declared size, so the sum is a
# real bound, not the archive's say-so).
MAX_XLSX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
SHEET_TITLE = "records"


class SpreadsheetError(ValueError):
    """The file as a whole cannot be read (a 422, not a per-row error)."""


# ── Export ──────────────────────────────────────────────────────────────────


def managed_by(record: DNSRecord) -> str | None:
    """What owns *record*, or None for an operator-owned row.

    The record API refuses edits to a pool's or a synthesising integration's
    rows; IPAM's, ACME's and dynamic-update clients' are protected here too,
    so an import (spreadsheet or zone file, #2167) cannot make DNS and IPAM
    disagree or delete a record another writer holds.
    """
    if record.pool_member_id is not None:
        return "pool"
    if record.tailscale_tenant_id is not None:
        return "tailscale"
    if record.netbird_instance_id is not None:
        return "netbird"
    if record.kubernetes_cluster_id is not None:
        return "kubernetes"
    # ACME challenge TXT rows are ``auto_generated`` too, but IPAM did not
    # write them and editing an IP address does nothing to them (#2167).
    if (record.tags or {}).get(ACME_RECORD_TAG):
        return "acme"
    if record.auto_generated or record.ip_alias or record.ip_address_id is not None:
        return "ipam"
    # A record a dynamic-update client (an AD domain controller, a DHCP
    # server) wrote straight into the live zone, mirrored back by the agent
    # (#641). No file the operator imports knows about it, so a replace would
    # delete a registration the client believes it still holds (#2167).
    if record.import_source == EXTERNAL_IMPORT_SOURCE:
        return "ddns"
    return None


_MANAGED_REASON = {
    "ipam": "generated by IPAM; edit the IP address instead",
    "pool": "managed by a DNS pool; edit the pool member instead",
    "tailscale": "synthesised by the Tailscale integration",
    "netbird": "synthesised by the NetBird integration",
    "kubernetes": "mirrored from a Kubernetes cluster",
    "acme": "an ACME challenge record; its certificate order removes it",
    "ddns": (
        "registered by a dynamic-update client in the live zone; "
        "delete it from the record list to remove it"
    ),
}


def managed_reason(record: DNSRecord) -> str | None:
    """Why *record* is read-only to an import, or None when the operator owns
    it. Shared with the zone-file import (#2167), so the two importers protect
    the same rows with the same words."""
    owner = managed_by(record)
    return None if owner is None else _MANAGED_REASON[owner]


def record_comment(record: DNSRecord) -> str | None:
    tags = record.tags or {}
    value = tags.get(COMMENT_TAG)
    return str(value) if value not in (None, "") else None


def record_rows(records: Iterable[DNSRecord], view_names: dict[uuid.UUID, str]) -> list[dict]:
    """One export row per record, sorted by name then type then value."""
    rows: list[dict[str, Any]] = []
    for r in sorted(records, key=lambda x: (x.name.lower(), x.record_type, x.value)):
        rows.append(
            {
                "id": str(r.id),
                "name": r.name,
                "type": r.record_type,
                "ttl": r.ttl,
                "value": r.value,
                "priority": r.priority,
                "weight": r.weight,
                "port": r.port,
                "view": view_names.get(r.view_id) if r.view_id else None,
                "comment": record_comment(r),
                "managed": managed_by(r),
            }
        )
    return rows


async def zone_record_rows(db: AsyncSession, zone: DNSZone) -> list[dict[str, Any]]:
    """The export rows for *zone* (every live record, every view): shared by
    the REST export and the ``export_dns_zone_records`` Copilot tool, so the
    two cannot disagree."""
    records = (
        (await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).scalars().all()
    )
    views = (
        (await db.execute(select(DNSView).where(DNSView.group_id == zone.group_id))).scalars().all()
    )
    return record_rows(records, {v.id: v.name for v in views})


def to_csv(rows: list[dict[str, Any]]) -> bytes:
    """CSV with the #523 formula-injection escape on every cell."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=RECORD_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: sanitize_cell(row.get(k)) for k in RECORD_COLUMNS})
    return buf.getvalue().encode("utf-8")


def to_xlsx(rows: list[dict[str, Any]]) -> bytes:
    """One ``records`` sheet. Escaped as the CSV is: openpyxl stores a string
    starting with ``=`` as a formula, so the escape matters more here."""
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = SHEET_TITLE
    ws.append(RECORD_COLUMNS)
    for row in rows:
        ws.append([sanitize_cell(row.get(k)) for k in RECORD_COLUMNS])
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def template_rows() -> list[dict[str, Any]]:
    """One example per common type. ``id`` is ``EXAMPLE`` so import ignores
    them: an operator can fill rows in below and upload the sheet as it is."""
    ex = EXAMPLE_MARKER
    return [
        {"id": ex, "name": "www", "type": "A", "ttl": 3600, "value": "192.0.2.10"},
        {"id": ex, "name": "www", "type": "AAAA", "value": "2001:db8::10"},
        {"id": ex, "name": "app", "type": "CNAME", "value": "www"},
        {"id": ex, "name": "@", "type": "MX", "value": "mail", "priority": 10},
        {
            "id": ex,
            "name": "@",
            "type": "TXT",
            "value": '"v=spf1 mx -all"',
            "comment": "example rows are ignored on import",
        },
        {
            "id": ex,
            "name": "_sip._tcp",
            "type": "SRV",
            "value": "sip",
            "priority": 10,
            "weight": 60,
            "port": 5060,
        },
    ]


# ── Import: reading the file ────────────────────────────────────────────────


@dataclass
class SheetRow:
    """One data row as read, before validation. ``row`` is the spreadsheet's
    own row number (the header is row 1), so errors point at the right line."""

    row: int
    id: str | None = None
    name: str | None = None
    type: str | None = None
    ttl: Any = None
    value: str | None = None
    priority: Any = None
    weight: Any = None
    port: Any = None
    view: str | None = None
    comment: str | None = None


def _norm_header(h: Any) -> str:
    return str(h).strip().lower().replace(" ", "_") if h is not None else ""


def unescape_cell(value: Any) -> Any:
    """Undo the export's formula escape, and nothing more.

    A cell exported as ``'=x`` reads back as ``'=x`` (CSV, and openpyxl, keep
    the apostrophe), so a round trip would otherwise change the value. Only an
    apostrophe in front of a formula trigger is removed. Nothing is ever
    evaluated: a leading ``=`` is text.
    """
    if isinstance(value, str) and len(value) > 1 and value[0] == "'":
        if value[1:].startswith(FORMULA_TRIGGERS):
            return value[1:]
    return value


def _cell(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, str):
        value = unescape_cell(value.strip())
        return value if value != "" else None
    return value


def _text(value: Any) -> str | None:
    v = _cell(value)
    return None if v is None else str(v)


def _rows_from_table(headers: list[Any], data: Iterable[tuple[int, list[Any]]]) -> list[SheetRow]:
    norm = [_norm_header(h) for h in headers]
    if "record_type" in norm and "type" not in norm:
        norm = ["type" if h == "record_type" else h for h in norm]
    missing = [c for c in REQUIRED_COLUMNS if c not in norm]
    if missing:
        raise SpreadsheetError(
            "the header row is missing the column(s) "
            + ", ".join(missing)
            + f"; expected {', '.join(RECORD_COLUMNS)} (download the template)"
        )
    out: list[SheetRow] = []
    for seen, (rownum, cells) in enumerate(data, start=1):
        if seen > MAX_SHEET_ROWS:
            raise SpreadsheetError(
                f"the file has more than {MAX_SHEET_ROWS} rows (blank ones included); "
                f"import at most {MAX_ROWS} records at a time"
            )
        values = {norm[i]: cells[i] for i in range(min(len(norm), len(cells))) if norm[i]}
        if all(_cell(v) is None for v in values.values()):
            continue
        out.append(
            SheetRow(
                row=rownum,
                id=_text(values.get("id")),
                name=_text(values.get("name")),
                type=_text(values.get("type")),
                ttl=_cell(values.get("ttl")),
                value=_text(values.get("value")),
                priority=_cell(values.get("priority")),
                weight=_cell(values.get("weight")),
                port=_cell(values.get("port")),
                view=_text(values.get("view")),
                comment=_text(values.get("comment")),
            )
        )
        if len(out) > MAX_ROWS:
            raise SpreadsheetError(f"the file has more than {MAX_ROWS} rows; split it")
    return out


def _decode_csv(data: bytes) -> str:
    """UTF-8 (with or without the BOM Excel writes), or UTF-16 when the file
    carries a UTF-16 BOM (Excel's "Unicode text" export). Anything else is
    read as UTF-8 with replacement, so a stray byte is one odd character in
    one cell, not a 500."""
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise SpreadsheetError(f"the file is not valid UTF-16: {exc}") from exc
    return data.decode("utf-8-sig", errors="replace")


def parse_csv(data: bytes) -> list[SheetRow]:
    """Streamed row by row (newline handling as ``csv_text``, #1370), so the
    row caps refuse a huge file before it is all held in memory."""
    text = _decode_csv(data)
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader, None)
        if not header or not any(h.strip() for h in header):
            raise SpreadsheetError("the file is empty")

        def data_rows() -> Iterable[tuple[int, list[Any]]]:
            for i, cells in enumerate(reader):
                yield i + 2, list(cells)

        return _rows_from_table(list(header), data_rows())
    except csv.Error as exc:
        raise SpreadsheetError(f"CSV could not be read: {exc}") from exc


def _check_xlsx_size(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            total = sum(info.file_size for info in zf.infolist())
    except (zipfile.BadZipFile, ValueError) as exc:
        raise SpreadsheetError(f"not a readable XLSX workbook: {exc}") from exc
    if total > MAX_XLSX_UNCOMPRESSED_BYTES:
        raise SpreadsheetError(
            f"the workbook expands to more than "
            f"{MAX_XLSX_UNCOMPRESSED_BYTES // (1024 * 1024)} MB; save it as CSV or split it"
        )


def parse_xlsx(data: bytes) -> list[SheetRow]:
    """The ``records`` sheet, or the first sheet when there is none.

    Opened with ``data_only=True``: a formula cell reads as its cached value
    (empty if the workbook was never calculated), never as code.
    """
    from openpyxl import load_workbook

    _check_xlsx_size(data)
    try:
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:  # noqa: BLE001 — any unreadable workbook is the file's fault
        raise SpreadsheetError(f"not a readable XLSX workbook: {exc}") from exc
    try:
        if not wb.sheetnames:
            raise SpreadsheetError("the workbook has no sheets")
        ws = wb[SHEET_TITLE] if SHEET_TITLE in wb.sheetnames else wb[wb.sheetnames[0]]
        rows = ws.iter_rows(values_only=True)
        header = next(rows, None)
        if header is None:
            raise SpreadsheetError("the sheet is empty")
        data_rows = ((i + 2, list(r)) for i, r in enumerate(rows))
        return _rows_from_table(list(header), data_rows)
    except SpreadsheetError:
        raise
    except Exception as exc:  # noqa: BLE001 — read_only parses the sheet lazily, here
        # A worksheet's XML is only parsed as its rows are read, so a corrupt
        # (or entity-expanding, refused by expat) sheet fails in this loop,
        # not in load_workbook: still the file's fault, a 422 and not a 500.
        raise SpreadsheetError(f"not a readable XLSX workbook: {exc}") from exc
    finally:
        wb.close()


def parse_spreadsheet(data: bytes, filename: str, content_type: str | None) -> tuple[str, list]:
    """``(format, rows)``; the format from the extension, else the MIME type."""
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    if name.endswith(".xlsx") or "spreadsheetml" in ctype:
        return "xlsx", parse_xlsx(data)
    if name.endswith(".csv") or "csv" in ctype or name.endswith(".txt"):
        return "csv", parse_csv(data)
    raise SpreadsheetError(
        f"unsupported file type {filename or content_type or 'unknown'!r}; upload CSV or XLSX"
    )


# ── Import: the plan ────────────────────────────────────────────────────────


@dataclass
class Candidate:
    """A row after validation: what the record would be once written."""

    row: int
    name: str
    record_type: str
    value: str
    ttl: int | None
    priority: int | None
    weight: int | None
    port: int | None
    view_id: uuid.UUID | None
    view: str | None
    comment: str | None


@dataclass
class PlannedUpdate:
    candidate: Candidate
    record: DNSRecord
    changed: list[str]

    @property
    def renamed(self) -> bool:
        return "name" in self.changed

    @property
    def wire_changed(self) -> bool:
        """Whether anything a DNS server serves changes (``comment`` does not)."""
        return any(f != "comment" for f in self.changed)


@dataclass
class RowIssue:
    row: int | None
    reason: str
    name: str | None = None
    record_type: str | None = None
    value: str | None = None


@dataclass
class ImportPlan:
    creates: list[Candidate] = field(default_factory=list)
    updates: list[PlannedUpdate] = field(default_factory=list)
    deletes: list[DNSRecord] = field(default_factory=list)
    unchanged: list[tuple[int, DNSRecord]] = field(default_factory=list)
    errors: list[RowIssue] = field(default_factory=list)
    skipped: list[RowIssue] = field(default_factory=list)
    examples_ignored: int = 0
    row_count: int = 0


# validate(row, existing record or None) -> Candidate, or the reason it is refused.
RowValidator = Callable[[SheetRow, uuid.UUID | None, DNSRecord | None], "Candidate | str"]


def _key(view_id: uuid.UUID | None, name: str, rtype: str, value: str) -> tuple[Any, ...]:
    return (view_id, name.strip().lower(), rtype.upper(), value.strip())


def changed_fields(c: Candidate, r: DNSRecord) -> list[str]:
    out: list[str] = []
    if c.name.lower() != (r.name or "").lower():
        out.append("name")
    if c.value.strip() != (r.value or "").strip():
        out.append("value")
    for f in ("ttl", "priority", "weight", "port", "view_id"):
        if getattr(c, f) != getattr(r, f):
            out.append(f)
    if (c.comment or None) != record_comment(r):
        out.append("comment")
    return out


def _issue(row: SheetRow, reason: str) -> RowIssue:
    return RowIssue(
        row=row.row, reason=reason, name=row.name, record_type=row.type, value=row.value
    )


def plan_import(
    rows: list[SheetRow],
    existing: list[DNSRecord],
    *,
    views_by_name: dict[str, uuid.UUID],
    mode: str,
    validate: RowValidator,
) -> ImportPlan:
    """Work out what importing *rows* into a zone holding *existing* does.

    Pure: nothing is written. *validate* is the record API's checks for one
    row (see the module docstring for the match rule).
    """
    plan = ImportPlan()
    by_id = {str(r.id): r for r in existing}
    by_key: dict[tuple[Any, ...], list[DNSRecord]] = {}
    for r in existing:
        by_key.setdefault(_key(r.view_id, r.name, r.record_type, r.value), []).append(r)
    claimed: dict[str, int] = {}  # record id -> row number that claimed it

    views_lower = {k.lower(): v for k, v in views_by_name.items()}

    for row in rows:
        if (row.id or "").strip().upper() == EXAMPLE_MARKER:
            plan.examples_ignored += 1
            continue
        plan.row_count += 1

        view_id: uuid.UUID | None = None
        if row.view:
            view_id = views_by_name.get(row.view) or views_lower.get(row.view.lower())
            if view_id is None:
                plan.errors.append(_issue(row, f"view {row.view!r} does not exist in this group"))
                continue

        target: DNSRecord | None = None
        if row.id:
            target = by_id.get(row.id.strip())
            if target is None:
                plan.errors.append(
                    _issue(
                        row,
                        f"id {row.id!r} is not a record in this zone; clear the id "
                        "cell to add the row as a new record",
                    )
                )
                continue
            if row.type and row.type.strip().upper() != target.record_type.upper():
                plan.errors.append(
                    _issue(
                        row,
                        f"a record's type cannot change ({target.record_type} → "
                        f"{row.type.strip().upper()}); clear the id cell to add a new "
                        "record and remove this one",
                    )
                )
                claimed.setdefault(str(target.id), row.row)
                continue
            if str(target.id) in claimed:
                plan.errors.append(
                    _issue(row, f"row {claimed[str(target.id)]} already names this record")
                )
                continue
            claimed[str(target.id)] = row.row

        result = validate(row, view_id, target)
        if isinstance(result, str):
            plan.errors.append(_issue(row, result))
            continue
        cand = result
        cand.view_id = view_id

        if target is None:
            twins = by_key.get(_key(view_id, cand.name, cand.record_type, cand.value), [])
            free = [t for t in twins if str(t.id) not in claimed]
            if twins and not free:
                plan.errors.append(
                    _issue(
                        row,
                        f"row {claimed[str(twins[0].id)]} already names this record "
                        "(same view, name, type and value)",
                    )
                )
                continue
            if free:
                # Prefer the twin whose structured fields match outright.
                target = next(
                    (
                        t
                        for t in free
                        if (t.priority, t.weight, t.port) == (cand.priority, cand.weight, cand.port)
                    ),
                    free[0],
                )
                claimed[str(target.id)] = row.row

        if target is None:
            plan.creates.append(cand)
            continue

        changed = changed_fields(cand, target)
        owner = managed_by(target)
        if not changed:
            plan.unchanged.append((row.row, target))
        elif owner is not None:
            plan.skipped.append(
                _issue(row, f"not changed: this record is {_MANAGED_REASON[owner]}")
            )
        else:
            plan.updates.append(PlannedUpdate(candidate=cand, record=target, changed=changed))

    if mode == "replace":
        for r in existing:
            if str(r.id) in claimed:
                continue
            owner = managed_by(r)
            if owner is not None:
                plan.skipped.append(
                    RowIssue(
                        row=None,
                        reason=f"not deleted: this record is {_MANAGED_REASON[owner]}",
                        name=r.name,
                        record_type=r.record_type,
                        value=r.value,
                    )
                )
                continue
            plan.deletes.append(r)

    _refuse_twins(plan, existing)
    _apply_cname_rule(plan, existing)
    return plan


def _identity(
    view_id: uuid.UUID | None,
    name: str,
    rtype: str,
    value: str,
    priority: int | None,
    weight: int | None,
    port: int | None,
) -> tuple[Any, ...]:
    """What makes two records the same RR (#1230's ``find_identical_record``)."""
    return (view_id, name.lower(), rtype.upper(), value.strip(), priority, weight, port)


def _refuse_twins(plan: ImportPlan, existing: list[DNSRecord]) -> None:
    """A row that would leave the zone holding the same RR twice is an error,
    as the record API's create and edit refuse it with a 409 (#1230): two
    identical new rows in one sheet, or an edit that turns a record into a
    copy of another. Twins the zone already holds are left alone — only a
    row this import writes is judged."""
    written = {str(u.record.id) for u in plan.updates} | {str(r.id) for r in plan.deletes}
    holder: dict[tuple[Any, ...], str] = {}
    for r in existing:
        if str(r.id) in written:
            continue
        key = _identity(r.view_id, r.name, r.record_type, r.value, r.priority, r.weight, r.port)
        holder.setdefault(key, "a record the zone already holds")

    def clash(c: Candidate) -> str | None:
        key = _identity(c.view_id, c.name, c.record_type, c.value, c.priority, c.weight, c.port)
        if key in holder:
            return holder[key]
        holder[key] = f"row {c.row}"
        return None

    identity_fields = {"name", "value", "priority", "weight", "port", "view_id"}
    kept_updates: list[PlannedUpdate] = []
    for u in plan.updates:
        if not identity_fields.intersection(u.changed):
            # A TTL / comment edit keeps the RR it is; as on the record API it
            # is not re-judged against a twin that predates the rule.
            kept_updates.append(u)
            c = u.candidate
            holder.setdefault(
                _identity(c.view_id, c.name, c.record_type, c.value, c.priority, c.weight, c.port),
                f"row {c.row}",
            )
            continue
        other = clash(u.candidate)
        if other is None:
            kept_updates.append(u)
        else:
            plan.errors.append(_twin_issue(u.candidate, other))
    kept_creates: list[Candidate] = []
    for c in plan.creates:
        other = clash(c)
        if other is None:
            kept_creates.append(c)
        else:
            plan.errors.append(_twin_issue(c, other))
    plan.updates, plan.creates = kept_updates, kept_creates


def _twin_issue(c: Candidate, other: str) -> RowIssue:
    return RowIssue(
        row=c.row,
        reason=f"the same record as {other} (same view, name, type and value); remove one",
        name=c.name,
        record_type=c.record_type,
        value=c.value,
    )


def _apply_cname_rule(plan: ImportPlan, existing: list[DNSRecord]) -> None:
    """Skip, with the reason, every create and every moved record the CNAME
    rule refuses (#2089): the zone-file import's rule, over the same
    ``refused_by_cname_rule``. Records that stay where they are win."""
    moved = [u for u in plan.updates if u.renamed or "view_id" in u.changed]
    leaving = {str(r.id) for r in plan.deletes} | {str(u.record.id) for u in moved}
    standing = [
        NameRow(r.name, r.record_type, r.value, r.view_id)
        for r in existing
        if str(r.id) not in leaving
    ]
    arriving: list[tuple[str, Any]] = [("create", c) for c in plan.creates] + [
        ("update", u) for u in moved
    ]
    rows = []
    for kind, item in arriving:
        c = item if kind == "create" else item.candidate
        rows.append(NameRow(c.name, c.record_type, c.value, c.view_id))
    refused = refused_by_cname_rule(rows, standing)
    if not refused:
        return
    drop_creates: set[int] = set()
    drop_updates: set[int] = set()
    for i, reason in refused.items():
        kind, item = arriving[i]
        c = item if kind == "create" else item.candidate
        plan.skipped.append(
            RowIssue(
                row=c.row,
                reason=f"skipped - {reason}",
                name=c.name,
                record_type=c.record_type,
                value=c.value,
            )
        )
        (drop_creates if kind == "create" else drop_updates).add(id(item))
    plan.creates = [c for c in plan.creates if id(c) not in drop_creates]
    plan.updates = [u for u in plan.updates if id(u) not in drop_updates]

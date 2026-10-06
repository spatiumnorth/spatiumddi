"""CSV import of an estate's existing AE Title table — issue #723.

Every hospital that runs DICOM already has this table. It is a
spreadsheet, it is out of date, and it is the only record of which AE
Titles are taken — which is exactly why PS3.15's registry object exists
and exactly why nobody deploys it. So the first thing this module has to
do well is ingest that spreadsheet without arguing with it.

Shape follows the tree's other importers (``services/ot/importer.py``,
``services/ipam_io``): a **preview** that is pure planning with zero
writes, then a **commit** that re-plans from the same request body and
applies it. Re-planning on commit is what keeps the server stateless
between the two calls — no preview token to expire, and a concurrent
change lands as a plan difference rather than a stale write.

Two contracts differ from the OT importer, both because an AE Title is
not an address:

* **The join key is ``ae_title``, not the IP.** That is the identity
  DICOM cares about, and it is what the unique constraint is on. Two
  rows in one file sharing a title is a per-row error, because that is
  the collision the whole registry exists to surface — reporting it at
  import is strictly better than letting the second row win silently.
* **The address column is optional.** A blank address is not an error,
  it is an *unbound reservation*: a title still burned into peer
  configuration across the estate whose host has been decommissioned.
  Refusing those would force operators to omit exactly the rows most at
  risk of being re-issued to someone else. A *supplied* address that
  IPAM does not know is still an error, matching the OT importer — an
  export is an enrichment source, not an address-plan source.

Per-row errors never abort the batch: a 400-row table with three bad
cells imports 397 and reports three.

No network I/O, and no PHI: the columns below are network identity only.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import structlog
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dicom import (
    DICOM_AE_ROLES,
    DICOM_DEVICE_CLASSES,
    DICOMApplicationEntity,
)
from app.models.ipam import IPAddress, Subnet
from app.services.dicom.titles import AETitleError, validate_ae_title

logger = structlog.get_logger(__name__)

# Sized for "one institution's AE table". The commit writes one audit row
# per affected AE inside a single transaction, so an unbounded batch
# would turn a fat-fingered paste into a multi-minute lock.
MAX_IMPORT_ROWS = 2000

# Refused before a CSV reader is built over the body, so a multi-megabyte
# paste fails fast. Generous enough that MAX_IMPORT_ROWS is always the
# binding constraint for a real table.
MAX_CSV_CHARS = 2_000_000

# Fields an operator may map a CSV column onto. ``ae_title`` is the join
# key and is mandatory; everything else is optional. The router's
# column-map schema mirrors this tuple — keep the two in step.
IMPORTABLE_FIELDS: tuple[str, ...] = (
    "ae_title",
    "address",
    "port",
    "tls_enabled",
    "role",
    "device_class",
    "vendor",
    "model_name",
    "department",
    "location",
    "notes",
)

# Column widths from the model. Over-long values are reported as row
# errors rather than silently truncated: a truncated vendor string is
# worse than a rejected one, because nothing downstream can tell.
_MAX_FIELD_LEN: dict[str, int] = {
    "vendor": 255,
    "model_name": 255,
    "department": 255,
    "location": 255,
}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Spellings that appear in real AE tables, mapped onto our vocabulary.
# Applied after ``_normalize_token``, so casing / spaces / hyphens are
# already flattened. Deliberately conservative — a guess that puts the
# wrong class on a modality is worse than leaving it ``other``.
_ROLE_ALIASES: dict[str, str] = {
    "provider": "scp",
    "server": "scp",
    "service_class_provider": "scp",
    "user": "scu",
    "client": "scu",
    "service_class_user": "scu",
    "scu_scp": "both",
    "scp_scu": "both",
    "both_scu_and_scp": "both",
}

_CLASS_ALIASES: dict[str, str] = {
    "ct": "modality",
    "mr": "modality",
    "mri": "modality",
    "us": "modality",
    "xr": "modality",
    "cr": "modality",
    "dx": "modality",
    "nm": "modality",
    "pet": "modality",
    "scanner": "modality",
    "pacs_archive": "archive",
    "vna": "archive",
    "long_term_archive": "archive",
    "viewer": "workstation",
    "reading_station": "workstation",
    "diagnostic_workstation": "workstation",
    "mwl": "worklist",
    "modality_worklist": "worklist",
    "ris": "worklist",
    "gateway": "router",
    "broker": "router",
    "film_printer": "printer",
    "dry_camera": "printer",
}

# Cell values accepted as booleans for ``tls_enabled``. Anything else is
# a row error rather than a silent False — "was this AE recorded as
# encrypted" is a question the ``dicom_ae_no_tls`` check reports on, so
# guessing would put a wrong answer into a compliance report.
_TRUE_CELLS: frozenset[str] = frozenset({"1", "true", "t", "yes", "y", "on", "tls", "enabled"})
_FALSE_CELLS: frozenset[str] = frozenset({"0", "false", "f", "no", "n", "off", "none"})
# Empty is deliberately NOT in ``_FALSE_CELLS``: "the operator left this
# blank" and "the operator wrote no" are different statements, and only
# the second should overwrite a stored ``true``.
_BLANK_CELLS: frozenset[str] = frozenset({""})


class DICOMImportError(ValueError):
    """The import request is unusable as a whole (bad header, over cap).

    Distinct from a per-row error: this aborts before any planning
    happens and the router turns it into a 422. Per-row problems ride on
    :class:`PlannedRow` and never stop the batch.
    """


@dataclass
class ParsedRow:
    """One CSV data row after column mapping + value validation."""

    line: int
    raw_title: str
    ae_title: str | None
    address: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class PlannedRow:
    """What the import would do (preview) or did do (commit) to one row.

    ``action`` is one of ``create`` / ``update`` / ``skip`` / ``error``.
    The commit path re-plans and mutates ``action`` in place only where
    reality differed from the plan, so the response always describes what
    actually happened.
    """

    line: int
    ae_title: str
    action: str
    reason: str = ""
    address: str = ""
    ip_address_id: uuid.UUID | None = None
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportOutcome:
    """Counters returned by :func:`apply_plan`."""

    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: int = 0
    ae_ids: list[uuid.UUID] = field(default_factory=list)


def _normalize_token(value: str) -> str:
    """Flatten a free-text enum-ish cell to ``lower_snake``."""
    return _NON_ALNUM.sub("_", value.strip().lower()).strip("_")


def _normalize_header(value: str) -> str:
    """Canonicalise a CSV header so column mapping is case/space blind."""
    return _normalize_token(value)


def _canonical_address(raw: str) -> str | None:
    """Strip any ``/prefix`` an export tacked on and canonicalise the IP."""
    text = raw.strip()
    if "/" in text:
        text = text.split("/", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _resolve_headers(
    fieldnames: Sequence[str] | None, column_map: Mapping[str, str]
) -> dict[str, str]:
    """Map each requested field onto the real header string in the file.

    Raises :class:`DICOMImportError` when a mapped column isn't in the
    file. Failing loudly beats importing a column of blanks: a mistyped
    mapping otherwise looks like a successful import that silently
    dropped the department for every AE.
    """
    if not fieldnames:
        raise DICOMImportError("CSV has no header row")
    available = {_normalize_header(h): h for h in fieldnames if h}
    resolved: dict[str, str] = {}
    missing: list[str] = []
    for target, wanted in column_map.items():
        if target not in IMPORTABLE_FIELDS or not wanted:
            continue
        actual = available.get(_normalize_header(wanted))
        if actual is None:
            missing.append(wanted)
            continue
        resolved[target] = actual
    if missing:
        raise DICOMImportError(
            "column(s) not found in the CSV header: "
            + ", ".join(sorted(missing))
            + f" (header is: {', '.join(h for h in fieldnames if h)})"
        )
    if "ae_title" not in resolved:
        raise DICOMImportError("column_map.ae_title must name a column present in the CSV header")
    return resolved


def _cell(raw_row: Mapping[str, Any], headers: Mapping[str, str], target: str) -> str:
    """Read one mapped cell as a stripped string ("" when absent/blank)."""
    header = headers.get(target)
    if header is None:
        return ""
    value = raw_row.get(header)
    if value is None:
        return ""
    return str(value).strip()


def _parse_one(
    *,
    line: int,
    raw_row: Mapping[str, Any],
    headers: Mapping[str, str],
    default_port: int,
    default_department: str,
) -> ParsedRow:
    raw_title = _cell(raw_row, headers, "ae_title")
    if not raw_title:
        return ParsedRow(line=line, raw_title="", ae_title=None, error="missing AE Title")
    try:
        ae_title = validate_ae_title(raw_title)
    except AETitleError as exc:
        return ParsedRow(line=line, raw_title=raw_title, ae_title=None, error=str(exc))

    fields: dict[str, Any] = {}

    # A blank address is an unbound reservation, not an error — see the
    # module docstring. Only a *supplied* value that doesn't parse fails.
    address_cell = _cell(raw_row, headers, "address")
    address: str | None = None
    if address_cell:
        address = _canonical_address(address_cell)
        if address is None:
            return ParsedRow(
                line=line,
                raw_title=raw_title,
                ae_title=ae_title,
                error=f"{address_cell!r} is not a valid IP address",
            )

    port_cell = _cell(raw_row, headers, "port")
    if port_cell:
        try:
            port = int(port_cell)
        except ValueError:
            return ParsedRow(
                line=line,
                raw_title=raw_title,
                ae_title=ae_title,
                error=f"port {port_cell!r} is not a number",
            )
        if not 1 <= port <= 65535:
            return ParsedRow(
                line=line,
                raw_title=raw_title,
                ae_title=ae_title,
                error=f"port {port} is outside 1-65535",
            )
        fields["port"] = port
    elif "port" in headers:
        # Column mapped but this row's cell is blank — fall back to the
        # request default, which is what the default is for.
        fields["port"] = default_port
    # No port column mapped at all: leave the key out entirely so an
    # ``overwrite_existing`` re-import cannot silently reset every AE to
    # 11112. The create path fills it from the model default instead.

    tls_cell = _normalize_token(_cell(raw_row, headers, "tls_enabled"))
    if tls_cell in _TRUE_CELLS:
        fields["tls_enabled"] = True
    elif "tls_enabled" not in headers or tls_cell in _BLANK_CELLS:
        # Same reasoning as ``port``, and it matters more here: a blank
        # or absent TLS column re-importing as ``false`` would flip every
        # encrypted AE to plaintext in the registry and poison
        # ``dicom_ae_no_tls`` — a compliance report reading worse than
        # reality is its own kind of wrong answer.
        pass
    elif tls_cell in _FALSE_CELLS:
        fields["tls_enabled"] = False
    else:
        return ParsedRow(
            line=line,
            raw_title=raw_title,
            ae_title=ae_title,
            error=(
                f"tls_enabled {tls_cell!r} is not a yes/no value — "
                "leave it blank rather than guessing"
            ),
        )

    role_cell = _cell(raw_row, headers, "role")
    if role_cell:
        role = _normalize_token(role_cell)
        role = _ROLE_ALIASES.get(role, role)
        if role not in DICOM_AE_ROLES:
            return ParsedRow(
                line=line,
                raw_title=raw_title,
                ae_title=ae_title,
                error=(
                    f"unknown role {role_cell!r} "
                    f"(expected one of {', '.join(sorted(DICOM_AE_ROLES))})"
                ),
            )
        fields["role"] = role

    class_cell = _cell(raw_row, headers, "device_class")
    if class_cell:
        device_class = _normalize_token(class_cell)
        device_class = _CLASS_ALIASES.get(device_class, device_class)
        if device_class not in DICOM_DEVICE_CLASSES:
            return ParsedRow(
                line=line,
                raw_title=raw_title,
                ae_title=ae_title,
                error=(
                    f"unknown device_class {class_cell!r} "
                    f"(expected one of {', '.join(sorted(DICOM_DEVICE_CLASSES))})"
                ),
            )
        fields["device_class"] = device_class

    for target in ("vendor", "model_name", "department", "location", "notes"):
        value = _cell(raw_row, headers, target)
        if not value and target == "department":
            value = default_department
        if not value:
            continue
        limit = _MAX_FIELD_LEN.get(target)
        if limit is not None and len(value) > limit:
            return ParsedRow(
                line=line,
                raw_title=raw_title,
                ae_title=ae_title,
                error=f"{target} is longer than {limit} characters",
            )
        fields[target] = value

    return ParsedRow(
        line=line,
        raw_title=raw_title,
        ae_title=ae_title,
        address=address,
        fields=fields,
    )


def parse_rows(
    csv_text: str,
    *,
    column_map: Mapping[str, str],
    delimiter: str = ",",
    default_port: int,
    default_department: str = "",
) -> list[ParsedRow]:
    """Parse + validate the pasted CSV into per-row field dicts.

    Only cells the operator mapped *and* filled land in
    ``ParsedRow.fields`` — a blank cell means "no opinion", not "clear
    this value", so re-importing a partial export cannot wipe a vendor
    string someone typed in the UI. That rule is what makes
    ``overwrite_existing`` safe to re-run against a table that is missing
    columns, and it is why ``port`` falls back to ``default_port`` only
    when a port column was actually mapped, and why a blank
    ``tls_enabled`` cell is left alone rather than read as ``false``.

    Raises :class:`DICOMImportError` for whole-request problems (empty
    body, missing mapped column, over the row cap, text the CSV reader
    cannot read). Per-row problems are reported on the row.
    """
    if len(csv_text) > MAX_CSV_CHARS:
        raise DICOMImportError(f"CSV body exceeds {MAX_CSV_CHARS} characters")
    # Spreadsheets on Windows prepend a UTF-8 BOM, which would otherwise
    # become part of the first header name and break its mapping.
    body = csv_text.lstrip("﻿").strip()
    if not body:
        raise DICOMImportError("CSV body is empty")

    # ``newline=""`` leaves line endings to the csv module, which reads
    # ``\n``, ``\r\n`` and a bare ``\r`` alike. The default splits on ``\n``
    # only, so a file saved with classic Mac line endings reached the reader
    # with a ``\r`` inside an unquoted field and the import answered 500
    # (#1370).
    reader = csv.DictReader(io.StringIO(body, newline=""), delimiter=delimiter)
    rows: list[ParsedRow] = []
    try:
        headers = _resolve_headers(reader.fieldnames, column_map)
        for line, raw_row in enumerate(reader, start=1):
            if line > MAX_IMPORT_ROWS:
                raise DICOMImportError(
                    f"CSV has more than {MAX_IMPORT_ROWS} data rows; split the table by department"
                )
            if not any((v or "").strip() for v in raw_row.values() if isinstance(v, str)):
                # Trailing blank lines are normal in exported files.
                continue
            rows.append(
                _parse_one(
                    line=line,
                    raw_row=raw_row,
                    headers=headers,
                    default_port=default_port,
                    default_department=default_department,
                )
            )
    except csv.Error as exc:
        # Anything else the reader refuses (a cell over its field size
        # limit, say) is a property of the file: a 422 that says why, not
        # a 500.
        raise DICOMImportError(f"CSV could not be read: {exc}") from exc
    return rows


async def _resolve_ipam_addresses(
    db: AsyncSession, addresses: Sequence[str], *, space_id: uuid.UUID | None
) -> dict[str, list[uuid.UUID]]:
    """Bulk-resolve IP literals to IPAM address ids.

    Returns every match per literal, because the same IP can legitimately
    exist in more than one IPSpace. The caller turns a multi-match into a
    row error telling the operator to scope the import with ``space_id``
    rather than guessing which occupant they meant.

    Casting the bind parameters to ``INET`` keeps the
    ``ix_ip_address_address`` index usable; comparing ``host(address)``
    as text would not.
    """
    if not addresses:
        return {}
    stmt = select(IPAddress.id, IPAddress.address).where(
        IPAddress.address.in_([cast(a, INET) for a in addresses])
    )
    if space_id is not None:
        stmt = stmt.join(Subnet, Subnet.id == IPAddress.subnet_id).where(
            Subnet.space_id == space_id
        )
    found: dict[str, list[uuid.UUID]] = {}
    for row_id, row_address in (await db.execute(stmt)).all():
        found.setdefault(str(row_address), []).append(row_id)
    return found


async def plan_import(
    db: AsyncSession,
    parsed: Sequence[ParsedRow],
    *,
    overwrite_existing: bool = False,
    space_id: uuid.UUID | None = None,
) -> list[PlannedRow]:
    """Turn parsed rows into a create/update/skip/error plan. No writes.

    Failure modes, each reported per row rather than aborting the batch:

    * the same AE Title appears twice in the file — the collision this
      registry exists to surface, so it is reported rather than resolved
      by last-write-wins;
    * a supplied IP isn't in IPAM — the importer enriches inventory, it
      does not invent it;
    * a supplied IP exists in several IPSpaces — ambiguous, resolve by
      passing ``space_id``;
    * the title is already registered — ``skip`` unless
      ``overwrite_existing`` flips it to ``update``.
    """
    wanted = sorted({r.address for r in parsed if r.address})
    resolved = await _resolve_ipam_addresses(db, wanted, space_id=space_id)

    titles = [r.ae_title for r in parsed if r.ae_title]
    existing_titles: set[str] = set()
    if titles:
        existing_titles = {
            title
            for (title,) in (
                await db.execute(
                    select(DICOMApplicationEntity.ae_title).where(
                        DICOMApplicationEntity.ae_title.in_(titles)
                    )
                )
            ).all()
        }

    plan: list[PlannedRow] = []
    seen: set[str] = set()
    for row in parsed:
        if row.error or row.ae_title is None:
            plan.append(
                PlannedRow(
                    line=row.line,
                    ae_title=row.raw_title,
                    action="error",
                    reason=row.error or "unusable row",
                )
            )
            continue
        if row.ae_title in seen:
            plan.append(
                PlannedRow(
                    line=row.line,
                    ae_title=row.ae_title,
                    action="error",
                    reason=(
                        "duplicate AE Title earlier in this file — AE Titles are "
                        "unique institution-wide, so this is a real collision to resolve"
                    ),
                )
            )
            continue
        seen.add(row.ae_title)

        ip_id: uuid.UUID | None = None
        if row.address:
            matches = resolved.get(row.address, [])
            if not matches:
                plan.append(
                    PlannedRow(
                        line=row.line,
                        ae_title=row.ae_title,
                        action="error",
                        address=row.address,
                        reason=(
                            "no IPAM address matches — allocate it in IPAM first, or "
                            "leave the address blank to register the title as a reservation"
                        ),
                    )
                )
                continue
            if len(matches) > 1:
                plan.append(
                    PlannedRow(
                        line=row.line,
                        ae_title=row.ae_title,
                        action="error",
                        address=row.address,
                        reason=(
                            f"{len(matches)} IPAM addresses share this IP across spaces; "
                            "re-run with space_id set to disambiguate"
                        ),
                    )
                )
                continue
            ip_id = matches[0]

        if row.ae_title in existing_titles and not overwrite_existing:
            plan.append(
                PlannedRow(
                    line=row.line,
                    ae_title=row.ae_title,
                    action="skip",
                    reason="AE Title already registered; set overwrite_existing to update",
                    address=row.address or "",
                    ip_address_id=ip_id,
                    fields=row.fields,
                )
            )
            continue

        plan.append(
            PlannedRow(
                line=row.line,
                ae_title=row.ae_title,
                action="update" if row.ae_title in existing_titles else "create",
                address=row.address or "",
                ip_address_id=ip_id,
                fields=row.fields,
            )
        )
    return plan


def _audit_row(
    user: Any,
    action: str,
    ae_id: uuid.UUID,
    display: str,
    payload: dict[str, Any],
) -> AuditLog:
    """Build the per-AE audit row the import writes before commit.

    One row per created/updated AE rather than a batch summary: "who
    re-pointed the archive's AE Title at a different host" is
    unanswerable from a summary, and it is exactly the question asked
    after an imaging outage.
    """
    return AuditLog(
        user_id=getattr(user, "id", None),
        user_display_name=getattr(user, "display_name", "system"),
        auth_source=getattr(user, "auth_source", "system"),
        action=action,
        resource_type="dicom_ae",
        resource_id=str(ae_id),
        resource_display=display,
        new_value=payload,
        result="success",
    )


async def apply_plan(
    db: AsyncSession,
    plan: Sequence[PlannedRow],
    *,
    user: Any,
) -> ImportOutcome:
    """Apply a plan produced by :func:`plan_import`. Caller commits.

    Re-reads by title immediately before writing and flips the row's
    ``action`` when reality moved under the plan — a create whose title
    was registered in the meantime becomes an ``update`` rather than an
    ``IntegrityError`` on ``uq_dicom_ae_title``, and an update whose row
    was deleted becomes a create. The returned plan therefore describes
    what happened, not what was intended.

    Audit rows are written here (non-negotiable #4); the caller owns the
    transaction so the whole import lands or none of it does.
    """
    outcome = ImportOutcome()
    actionable = [r for r in plan if r.action in {"create", "update"}]
    outcome.errors = sum(1 for r in plan if r.action == "error")
    outcome.skipped = sum(1 for r in plan if r.action == "skip")

    existing: dict[str, DICOMApplicationEntity] = {}
    if actionable:
        rows = (
            (
                await db.execute(
                    select(DICOMApplicationEntity).where(
                        DICOMApplicationEntity.ae_title.in_([r.ae_title for r in actionable])
                    )
                )
            )
            .scalars()
            .all()
        )
        existing = {r.ae_title: r for r in rows}

    # Subnet ids for the anchors we're about to bind, resolved in one
    # query rather than one per row — ``sync_subnet_id`` is per-row by
    # design for the CRUD path, but an import is a batch.
    anchor_ids = [r.ip_address_id for r in actionable if r.ip_address_id is not None]
    subnet_by_ip: dict[uuid.UUID, uuid.UUID | None] = {}
    if anchor_ids:
        subnet_by_ip = {
            row_id: subnet_id
            for row_id, subnet_id in (
                await db.execute(
                    select(IPAddress.id, IPAddress.subnet_id).where(IPAddress.id.in_(anchor_ids))
                )
            ).all()
        }

    for row in actionable:
        ae = existing.get(row.ae_title)
        if ae is None:
            ae = DICOMApplicationEntity(ae_title=row.ae_title, seen_via="import")
            _apply_fields(ae, row.fields)
            ae.ip_address_id = row.ip_address_id
            ae.subnet_id = subnet_by_ip.get(row.ip_address_id) if row.ip_address_id else None
            db.add(ae)
            await db.flush()
            existing[row.ae_title] = ae
            row.action = "create"
            outcome.created += 1
            db.add(_audit_row(user, "create", ae.id, f"AE {row.ae_title}", dict(row.fields)))
        else:
            _apply_fields(ae, row.fields)
            # Only re-point the anchor when the file actually supplied
            # one. A table exported without an address column must not
            # silently demote every AE to an unbound reservation.
            if row.ip_address_id is not None:
                ae.ip_address_id = row.ip_address_id
                ae.subnet_id = subnet_by_ip.get(row.ip_address_id)
            # The row was just re-stamped from the estate's AE table, so
            # its provenance is the import even if it started as a manual
            # entry — ``seen_via`` answers "where did the values currently
            # in this row come from".
            ae.seen_via = "import"
            row.action = "update"
            outcome.updated += 1
            db.add(_audit_row(user, "update", ae.id, f"AE {row.ae_title}", dict(row.fields)))
        outcome.ae_ids.append(ae.id)

    logger.info(
        "dicom_ae_import_applied",
        created=outcome.created,
        updated=outcome.updated,
        skipped=outcome.skipped,
        errors=outcome.errors,
    )
    return outcome


def _apply_fields(ae: DICOMApplicationEntity, fields: Mapping[str, Any]) -> None:
    """Copy validated cells onto the ORM row."""
    for key, value in fields.items():
        setattr(ae, key, value)


__all__ = [
    "IMPORTABLE_FIELDS",
    "MAX_CSV_CHARS",
    "MAX_IMPORT_ROWS",
    "DICOMImportError",
    "ImportOutcome",
    "ParsedRow",
    "PlannedRow",
    "apply_plan",
    "parse_rows",
    "plan_import",
]

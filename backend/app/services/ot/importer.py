"""CSV import of an engineering-tool device export — issue #542.

Plant inventories live in TIA Portal / Studio 5000 exports and in the
spreadsheets those exports become. This module ingests one of those
files and stamps the OT descriptor onto IPAM addresses that **already
exist**. It never creates an ``ip_address`` row: an engineering export
is an enrichment source, not an address-plan source, and letting it
invent IPAM rows would quietly turn a typo'd column into a fake subnet
occupant that nothing ever cleans up. Rows whose IP is unknown to IPAM
come back as per-row errors so the operator can decide — allocate the
address properly first, or fix the export.

Shape follows the tree's other importers (``services/ipam_io``,
``services/dhcp_import``): a **preview** that is pure planning with zero
writes, then a **commit** that re-plans from the same request body and
applies it. Re-planning on commit is what keeps the server stateless
between the two calls — there is no preview token to expire, and a
concurrent change lands as a plan difference rather than a stale write.

Per-row errors never abort the batch. A 400-row export with three bad
cells imports 397 rows and reports three errors, matching the IPAM
address importer's contract; an operator fixing a plant inventory wants
the good rows in, not an all-or-nothing rejection.

No network I/O — this is CSV text in, database rows out.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

import structlog
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.ipam import IPAddress, Subnet
from app.models.ot import (
    OT_PROTOCOLS,
    OT_ROLES,
    PURDUE_LEVELS,
    OTDevice,
)
from app.services.csv_text import CSVReadError, read_csv_table

logger = structlog.get_logger(__name__)

# Upper bound on a single import. Sized for "one plant's export", not
# "every device the company owns" — the commit writes one audit row per
# affected device inside a single transaction, and an unbounded batch
# would turn a fat-fingered paste into a multi-minute lock. An operator
# with more rows splits the file by area, which is how the exports are
# organised anyway.
MAX_IMPORT_ROWS = 2000

# Upper bound on the pasted body. Generous enough that MAX_IMPORT_ROWS
# is always the binding constraint for a real export; present so a
# multi-megabyte paste is refused before we build a CSV reader over it.
MAX_CSV_CHARS = 2_000_000

# Fields an operator may map a CSV column onto. ``address`` is the join
# key and is mandatory; everything else is optional enrichment. The
# router's column-map schema mirrors this tuple — keep the two in step.
IMPORTABLE_FIELDS: tuple[str, ...] = (
    "address",
    "ot_protocol",
    "ot_role",
    "profinet_device_name",
    "ot_vendor",
    "ot_product",
    "ot_serial",
    "firmware_rev",
    "purdue_level",
    "cell_area",
    "notes",
)

# Column widths from the model. Over-long values are reported as row
# errors rather than silently truncated — a truncated serial number is
# worse than a rejected one, because nothing downstream can tell it
# happened.
_MAX_FIELD_LEN: dict[str, int] = {
    "profinet_device_name": 255,
    "ot_vendor": 255,
    "ot_product": 255,
    "ot_serial": 128,
    "firmware_rev": 128,
    "cell_area": 255,
}

# Spellings engineering tools actually emit, mapped onto our canonical
# protocol values. Applied *after* ``_normalize_token`` so casing,
# spaces, slashes and hyphens are already flattened: "EtherNet/IP" and
# "Ethernet-IP" both arrive here as ``ethernet_ip`` and need no alias,
# while "ENIP" and "Modbus" do.
_PROTOCOL_ALIASES: dict[str, str] = {
    "enip": "ethernet_ip",
    "ethernetip": "ethernet_ip",
    "cip": "ethernet_ip",
    "modbus": "modbus_tcp",
    "modbustcp": "modbus_tcp",
    "opcua": "opc_ua",
    "s7": "s7comm",
    "s7_comm": "s7comm",
    "iso_tsap": "s7comm",
    "profinet_io": "profinet",
    "pnio": "profinet",
    "pn_io": "profinet",
    "bacnet": "bacnet_ip",
    "dnp_3": "dnp3",
    "iec_61850": "iec61850",
}

# Same idea for roles. Deliberately short — an alias that guesses (say,
# "panel" → HMI) would put a wrong role on a plant inventory, which is
# the failure mode #542 is most careful about. Only unambiguous vendor
# vocabulary is listed: Studio 5000 calls a PLC a "controller", Siemens
# calls a drive a "VFD".
_ROLE_ALIASES: dict[str, str] = {
    "io": "io_device",
    "iodevice": "io_device",
    "io_module": "io_device",
    "remote_io": "io_device",
    "controller": "plc",
    "cpu": "plc",
    "vfd": "drive",
    "inverter": "drive",
    "engineering_workstation": "ews",
    "engineering_station": "ews",
    "engineering_pc": "ews",
}

# Prefixes an operator may put in front of a Purdue level. Ordered
# longest-first so "level" is consumed before the bare "l" rule would
# eat its first character.
_PURDUE_PREFIXES: tuple[str, ...] = ("purdue", "level", "lvl", "l")

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


class OTImportError(ValueError):
    """The import request is unusable as a whole (bad header, over cap).

    Distinct from a per-row error: this aborts before any planning
    happens and the router turns it into a 422. Per-row problems ride on
    :class:`PlannedRow` instead and never stop the batch.
    """


@dataclass
class ParsedRow:
    """One CSV data row after column mapping + value validation."""

    line: int
    raw_address: str
    address: str | None
    fields: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class PlannedRow:
    """What the import would do (preview) or did do (commit) to one row.

    ``action`` is one of ``create`` / ``update`` / ``skip`` / ``error``.
    The commit path re-plans and then mutates ``action`` in place only
    where reality differed from the plan (a descriptor appearing between
    the two passes), so the response always describes what actually
    happened.
    """

    line: int
    address: str
    action: str
    reason: str = ""
    ip_address_id: uuid.UUID | None = None
    fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class ImportOutcome:
    """Counters returned by :func:`apply_plan`."""

    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: int = 0
    device_ids: list[uuid.UUID] = field(default_factory=list)


def _normalize_token(value: str) -> str:
    """Flatten a free-text enum-ish cell to ``lower_snake``.

    ``"EtherNet/IP"`` → ``ethernet_ip``, ``"Modbus TCP"`` →
    ``modbus_tcp``, ``"OPC-UA"`` → ``opc_ua``. Engineering tools have no
    shared spelling convention, and demanding the operator hand-edit
    every cell before import is the kind of friction that sends them back
    to the spreadsheet.
    """
    return _NON_ALNUM.sub("_", value.strip().lower()).strip("_")


def _normalize_header(value: str) -> str:
    """Canonicalise a CSV header so column mapping is case/space blind."""
    return _normalize_token(value)


def canonicalize_purdue(raw: str) -> str | None:
    """Coerce ``"Level 3.5"`` / ``"L2"`` / ``"2.0"`` to a canonical level.

    Returns a member of :data:`~app.models.ot.PURDUE_LEVELS`, or ``None``
    when the cell isn't a level we recognise. ``Decimal`` normalisation
    is what makes ``"2.0"`` and ``"2"`` the same level while keeping
    ``3.5`` — the manufacturing/enterprise DMZ — a first-class value.
    """
    cleaned = raw.strip().lower()
    for prefix in _PURDUE_PREFIXES:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :].strip(" -_:")
            break
    try:
        parsed = Decimal(cleaned)
    except (InvalidOperation, ValueError):
        return None
    canonical = format(parsed.normalize(), "f")
    return canonical if canonical in PURDUE_LEVELS else None


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

    Raises :class:`OTImportError` when a mapped column simply isn't in
    the file. Failing loudly beats importing a column of blanks: a
    mistyped mapping otherwise looks like a successful import that
    silently dropped the vendor for every device.
    """
    if not fieldnames:
        raise OTImportError("CSV has no header row")
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
        raise OTImportError(
            "column(s) not found in the CSV header: "
            + ", ".join(sorted(missing))
            + f" (header is: {', '.join(h for h in fieldnames if h)})"
        )
    if "address" not in resolved:
        raise OTImportError("column_map.address must name a column present in the CSV header")
    return resolved


def parse_rows(
    csv_text: str,
    *,
    column_map: Mapping[str, str],
    delimiter: str = ",",
    default_ot_protocol: str | None = None,
    default_cell_area: str = "",
) -> list[ParsedRow]:
    """Parse + validate the pasted CSV into per-row field dicts.

    Only cells the operator mapped *and* filled land in
    ``ParsedRow.fields``. A blank cell is "no opinion", not "clear this
    value" — so re-importing a partial export can't wipe a vendor string
    an operator typed in the UI. Same contract as the IPAM address
    importer.

    Raises :class:`OTImportError` for whole-request problems (empty body,
    missing mapped column, over the row cap, text the CSV reader cannot
    read). Per-row problems are reported on the row.
    """
    if len(csv_text) > MAX_CSV_CHARS:
        raise OTImportError(f"CSV body exceeds {MAX_CSV_CHARS} characters")
    # Spreadsheets on Windows prepend a UTF-8 BOM, which would otherwise
    # become part of the first header name and break its mapping.
    body = csv_text.lstrip("\ufeff").strip()
    if not body:
        raise OTImportError("CSV body is empty")

    # The shared reader handles \n, \r\n and a bare \r alike, and raises
    # anything else the csv module refuses as CSVReadError: a property of
    # the file, so a 422 that says why rather than a 500 (#1637, #1711).
    try:
        table = read_csv_table(body, delimiter=delimiter)
    except CSVReadError as exc:
        raise OTImportError(str(exc)) from exc
    headers = _resolve_headers(table.fieldnames, column_map)

    default_protocol = _normalize_token(default_ot_protocol) if default_ot_protocol else ""
    rows: list[ParsedRow] = []
    for line, raw_row in enumerate(table.rows, start=1):
        if line > MAX_IMPORT_ROWS:
            raise OTImportError(
                f"CSV has more than {MAX_IMPORT_ROWS} data rows; split the export by area"
            )
        if not any((v or "").strip() for v in raw_row.values() if isinstance(v, str)):
            # Trailing blank lines are normal in exported files.
            continue
        rows.append(
            _parse_one(
                line=line,
                raw_row=raw_row,
                headers=headers,
                default_protocol=default_protocol,
                default_cell_area=default_cell_area,
            )
        )
    return rows


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
    default_protocol: str,
    default_cell_area: str,
) -> ParsedRow:
    raw_address = _cell(raw_row, headers, "address")
    address = _canonical_address(raw_address) if raw_address else None
    if not raw_address:
        return ParsedRow(line=line, raw_address="", address=None, error="missing IP address")
    if address is None:
        return ParsedRow(
            line=line,
            raw_address=raw_address,
            address=None,
            error=f"{raw_address!r} is not a valid IP address",
        )

    fields: dict[str, Any] = {}

    protocol_cell = _cell(raw_row, headers, "ot_protocol")
    protocol = _normalize_token(protocol_cell) if protocol_cell else default_protocol
    protocol = _PROTOCOL_ALIASES.get(protocol, protocol)
    if not protocol:
        return ParsedRow(
            line=line,
            raw_address=raw_address,
            address=address,
            error=(
                "ot_protocol is required — map a protocol column or set "
                "default_ot_protocol on the request"
            ),
        )
    if protocol not in OT_PROTOCOLS:
        return ParsedRow(
            line=line,
            raw_address=raw_address,
            address=address,
            error=(
                f"unknown ot_protocol {protocol_cell or default_protocol!r} "
                f"(expected one of {', '.join(sorted(OT_PROTOCOLS))})"
            ),
        )
    fields["ot_protocol"] = protocol

    role_cell = _cell(raw_row, headers, "ot_role")
    if role_cell:
        role = _normalize_token(role_cell)
        role = _ROLE_ALIASES.get(role, role)
        if role not in OT_ROLES:
            return ParsedRow(
                line=line,
                raw_address=raw_address,
                address=address,
                error=(
                    f"unknown ot_role {role_cell!r} "
                    f"(expected one of {', '.join(sorted(OT_ROLES))})"
                ),
            )
        fields["ot_role"] = role

    purdue_cell = _cell(raw_row, headers, "purdue_level")
    if purdue_cell:
        level = canonicalize_purdue(purdue_cell)
        if level is None:
            return ParsedRow(
                line=line,
                raw_address=raw_address,
                address=address,
                error=(
                    f"unknown purdue_level {purdue_cell!r} "
                    f"(expected one of {', '.join(sorted(PURDUE_LEVELS))})"
                ),
            )
        fields["purdue_level"] = level

    for target in (
        "profinet_device_name",
        "ot_vendor",
        "ot_product",
        "ot_serial",
        "firmware_rev",
        "cell_area",
        "notes",
    ):
        value = _cell(raw_row, headers, target)
        if not value and target == "cell_area":
            value = default_cell_area
        if not value:
            continue
        limit = _MAX_FIELD_LEN.get(target)
        if limit is not None and len(value) > limit:
            return ParsedRow(
                line=line,
                raw_address=raw_address,
                address=address,
                error=f"{target} is longer than {limit} characters",
            )
        fields[target] = value

    return ParsedRow(line=line, raw_address=raw_address, address=address, fields=fields)


async def _resolve_ipam_addresses(
    db: AsyncSession, addresses: Sequence[str], *, space_id: uuid.UUID | None
) -> dict[str, list[uuid.UUID]]:
    """Bulk-resolve IP literals to IPAM address ids.

    Returns every match per literal, because the same IP can legitimately
    exist in more than one IPSpace (overlapping RFC 1918 plans are the
    norm across plants). The caller turns a multi-match into a row error
    telling the operator to scope the import with ``space_id`` rather
    than guessing which occupant they meant.

    Casting the bind parameters to ``INET`` keeps the ``ix_ip_address_address``
    index usable; comparing ``host(address)`` as text would not.
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

    The three failure modes an operator actually hits, each reported per
    row rather than aborting the batch:

    * the IP isn't in IPAM at all — the importer enriches inventory, it
      does not invent it, so this is an error and not an auto-create;
    * the IP exists in several IPSpaces — ambiguous, resolve by passing
      ``space_id``;
    * the address already carries an OT descriptor — ``skip`` unless
      ``overwrite_existing`` flips it to ``update``.
    """
    wanted = sorted({r.address for r in parsed if r.address})
    resolved = await _resolve_ipam_addresses(db, wanted, space_id=space_id)

    ip_ids = [ids[0] for ids in resolved.values() if len(ids) == 1]
    existing_ids: set[uuid.UUID] = set()
    if ip_ids:
        existing_ids = {
            row_id
            for (row_id,) in (
                await db.execute(
                    select(OTDevice.ip_address_id).where(OTDevice.ip_address_id.in_(ip_ids))
                )
            ).all()
        }

    plan: list[PlannedRow] = []
    seen: set[str] = set()
    for row in parsed:
        if row.error or row.address is None:
            plan.append(
                PlannedRow(
                    line=row.line,
                    address=row.raw_address,
                    action="error",
                    reason=row.error or "unusable row",
                )
            )
            continue
        if row.address in seen:
            plan.append(
                PlannedRow(
                    line=row.line,
                    address=row.address,
                    action="error",
                    reason="duplicate address earlier in this file",
                )
            )
            continue
        seen.add(row.address)

        matches = resolved.get(row.address, [])
        if not matches:
            plan.append(
                PlannedRow(
                    line=row.line,
                    address=row.address,
                    action="error",
                    reason=(
                        "no IPAM address matches — allocate it in IPAM first; "
                        "this importer enriches existing addresses only"
                    ),
                )
            )
            continue
        if len(matches) > 1:
            plan.append(
                PlannedRow(
                    line=row.line,
                    address=row.address,
                    action="error",
                    reason=(
                        f"{len(matches)} IPAM addresses share this IP across spaces; "
                        "re-run with space_id set to disambiguate"
                    ),
                )
            )
            continue

        ip_id = matches[0]
        if ip_id in existing_ids and not overwrite_existing:
            plan.append(
                PlannedRow(
                    line=row.line,
                    address=row.address,
                    action="skip",
                    reason="address already has an OT descriptor; set overwrite_existing to update",
                    ip_address_id=ip_id,
                    fields=row.fields,
                )
            )
            continue

        plan.append(
            PlannedRow(
                line=row.line,
                address=row.address,
                action="update" if ip_id in existing_ids else "create",
                ip_address_id=ip_id,
                fields=row.fields,
            )
        )
    return plan


def _audit_row(
    user: Any,
    action: str,
    device_id: uuid.UUID,
    display: str,
    payload: dict[str, Any],
) -> AuditLog:
    """Build the per-device audit row the import writes before commit.

    One row per created/updated descriptor rather than a single batch
    summary: an OT inventory is exactly the kind of record an auditor
    reconstructs device-by-device, and "who set this PLC to Level 4" is
    unanswerable from a summary row.
    """
    return AuditLog(
        user_id=getattr(user, "id", None),
        user_display_name=getattr(user, "display_name", "system"),
        auth_source=getattr(user, "auth_source", "system"),
        action=action,
        resource_type="ot_device",
        resource_id=str(device_id),
        resource_display=display,
        new_value=payload,
        result="success",
    )


def _apply_fields(device: OTDevice, fields: Mapping[str, Any]) -> None:
    """Copy validated cells onto the ORM row.

    ``purdue_level`` is the only conversion: it travels as a canonical
    string (``"3.5"``) through parsing + the API, and lands in a
    ``Numeric(2,1)`` column as a ``Decimal``.
    """
    for key, value in fields.items():
        if key == "purdue_level":
            device.purdue_level = Decimal(str(value))
        else:
            setattr(device, key, value)


async def apply_plan(
    db: AsyncSession,
    plan: Sequence[PlannedRow],
    *,
    user: Any,
) -> ImportOutcome:
    """Apply a plan produced by :func:`plan_import`. Caller commits.

    Re-checks descriptor existence immediately before writing and flips
    the row's ``action`` when reality moved under the plan — a create
    whose descriptor appeared in the meantime becomes a ``skip`` rather
    than an ``IntegrityError`` on ``uq_ot_device_ip_address``, and an
    update whose descriptor was deleted becomes a create. The returned
    plan therefore describes what happened, not what was intended.

    Audit rows are written here (non-negotiable #4); the caller owns the
    transaction so the whole import lands or none of it does.
    """
    outcome = ImportOutcome()
    actionable = [r for r in plan if r.action in {"create", "update"} and r.ip_address_id]
    outcome.errors = sum(1 for r in plan if r.action == "error")
    outcome.skipped = sum(1 for r in plan if r.action == "skip")

    existing: dict[uuid.UUID, OTDevice] = {}
    if actionable:
        rows = (
            (
                await db.execute(
                    select(OTDevice).where(
                        OTDevice.ip_address_id.in_([r.ip_address_id for r in actionable])
                    )
                )
            )
            .scalars()
            .all()
        )
        existing = {r.ip_address_id: r for r in rows}

    for row in actionable:
        ip_id = row.ip_address_id
        if ip_id is None:  # unreachable: filtered out of ``actionable`` above
            continue
        device = existing.get(ip_id)
        if device is None:
            device = OTDevice(
                ip_address_id=ip_id,
                ot_protocol=str(row.fields.get("ot_protocol", "other")),
                seen_via="import",
            )
            _apply_fields(device, row.fields)
            db.add(device)
            await db.flush()
            existing[ip_id] = device
            row.action = "create"
            outcome.created += 1
            db.add(
                _audit_row(user, "create", device.id, f"OT device {row.address}", dict(row.fields))
            )
        else:
            _apply_fields(device, row.fields)
            # The row was just re-stamped from an engineering export, so
            # its provenance is the import even if it started as a manual
            # entry. Operators reading ``seen_via`` want "where did the
            # values currently in this row come from".
            device.seen_via = "import"
            row.action = "update"
            outcome.updated += 1
            db.add(
                _audit_row(user, "update", device.id, f"OT device {row.address}", dict(row.fields))
            )
        outcome.device_ids.append(device.id)

    logger.info(
        "ot_device_import_applied",
        created=outcome.created,
        updated=outcome.updated,
        skipped=outcome.skipped,
        errors=outcome.errors,
    )
    return outcome


__all__ = [
    "IMPORTABLE_FIELDS",
    "MAX_CSV_CHARS",
    "MAX_IMPORT_ROWS",
    "ImportOutcome",
    "OTImportError",
    "ParsedRow",
    "PlannedRow",
    "apply_plan",
    "canonicalize_purdue",
    "parse_rows",
    "plan_import",
]

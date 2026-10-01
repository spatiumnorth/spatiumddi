"""Source-agnostic commit pipeline for the DNS configuration importer.

Takes a parsed :class:`ImportPreview` plus a per-zone strategy map and
writes the canonical IR to the DB stamping ``import_source`` +
``imported_at`` on every row it creates. The :mod:`bind9` /
:mod:`windows_dns` / :mod:`powerdns` source modules each emit the
same IR; this module is the only place that touches the DB so all
three sources share conflict handling, audit logging, and the
per-zone savepoint commit pattern.

Per the issue spec, each zone commits independently — a parse error
on zone N doesn't roll back zones 1..N-1. The commit ledger we
return carries one row per attempted zone so the operator sees the
partial-success state cleanly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import contains_control_chars
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.dns.named_conf_validation import split_zone_forwarders
from app.services.dns.record_ops import enqueue_record_ops_bulk, record_op_payload

from .canonical import (
    ConflictAction,
    ImportedZone,
    ImportPreview,
    ImportSource,
    ZoneConflict,
)


@dataclass
class CommitZoneResult:
    """One zone's outcome from the commit run."""

    zone_name: str
    action_taken: str  # "created" | "overwrote" | "renamed" | "skipped" | "failed"
    zone_id: str | None = None
    records_created: int = 0
    records_deleted: int = 0
    error: str | None = None


@dataclass
class CommitResult:
    """Return shape from :func:`commit_import`. Mirrored 1:1 by the
    Pydantic ``CommitOut`` the API endpoint returns."""

    target_group_id: uuid.UUID
    zones: list[CommitZoneResult]
    warnings: list[str] = field(default_factory=list)

    @property
    def total_zones_created(self) -> int:
        return sum(1 for z in self.zones if z.action_taken == "created")

    @property
    def total_zones_overwrote(self) -> int:
        return sum(1 for z in self.zones if z.action_taken == "overwrote")

    @property
    def total_zones_renamed(self) -> int:
        return sum(1 for z in self.zones if z.action_taken == "renamed")

    @property
    def total_zones_skipped(self) -> int:
        return sum(1 for z in self.zones if z.action_taken == "skipped")

    @property
    def total_zones_failed(self) -> int:
        return sum(1 for z in self.zones if z.action_taken == "failed")

    @property
    def total_records_created(self) -> int:
        return sum(z.records_created for z in self.zones)


async def detect_conflicts(
    db: AsyncSession,
    *,
    zone_names: list[str],
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
) -> list[ZoneConflict]:
    """Look up every zone name from the parsed preview against the
    target group + view and return the matching :class:`ZoneConflict`
    rows. Used by both the preview endpoint (so the UI can render
    the per-zone strategy picker) and the commit endpoint (so a
    stale plan still honours the up-to-date conflict state).

    Match is exact on ``DNSZone.name`` — case-sensitive in DNS spec
    is irrelevant since we always normalise to lowercase + trailing
    dot upstream of this call.
    """

    if not zone_names:
        return []

    stmt = (
        select(
            DNSZone.id,
            DNSZone.name,
            func.count(DNSRecord.id),
        )
        .outerjoin(DNSRecord, DNSRecord.zone_id == DNSZone.id)
        .where(
            DNSZone.group_id == target_group_id,
            DNSZone.name.in_(zone_names),
        )
        .group_by(DNSZone.id, DNSZone.name)
    )
    if target_view_id is None:
        stmt = stmt.where(DNSZone.view_id.is_(None))
    else:
        stmt = stmt.where(DNSZone.view_id == target_view_id)

    rows = (await db.execute(stmt)).all()
    return [
        ZoneConflict(
            zone_name=name,
            existing_zone_id=str(zid),
            existing_record_count=int(count),
        )
        for (zid, name, count) in rows
    ]


def _normalize_fqdn(name: str) -> str:
    return name if name.endswith(".") else name + "."


def _validate_rename(rename_to: str | None) -> str:
    if not rename_to or not rename_to.strip():
        raise ValueError("rename_to is required when action='rename'")
    target = rename_to.strip().lower()
    return _normalize_fqdn(target)


async def _build_records_for_zone(
    db: AsyncSession,
    *,
    zone_id: uuid.UUID,
    zone_fqdn: str,
    parsed: ImportedZone,
    source: ImportSource,
    now: datetime,
) -> tuple[list[DNSRecord], list[str]]:
    """Create the DNSRecord rows for one parsed zone.

    Returns ``(created_rows, skipped_reasons)``. The caller needs the rows
    themselves (not just a count) to enqueue the matching record ops — see
    :func:`_create_zone_at`. Skips the SOA (its
    fields live as columns on the parent zone) and, per issue #597, any
    record whose owner name or rdata carries a control character / newline
    — those can't be safely rendered into a zone-file line, so the row is
    dropped with a reported reason rather than silently imported.
    """

    rows: list[DNSRecord] = []
    skipped: list[str] = []
    for r in parsed.records:
        if r.record_type == "SOA":
            continue
        if contains_control_chars(r.name) or contains_control_chars(r.value):
            skipped.append(
                f"{r.name or '@'} {r.record_type}: dropped — control character "
                "in the record name or value"
            )
            continue
        # FQDN is "<label>.<zone_fqdn>" with the apex label "@"
        # collapsing to just the zone fqdn.
        rel = r.name
        if rel == "@" or rel == "":
            fqdn = zone_fqdn.rstrip(".") + "."
        else:
            fqdn = rel.rstrip(".") + "." + zone_fqdn.rstrip(".") + "."
        rows.append(
            DNSRecord(
                zone_id=zone_id,
                name=rel,
                fqdn=fqdn.lower(),
                record_type=r.record_type,
                value=r.value,
                ttl=r.ttl,
                priority=r.priority,
                weight=r.weight,
                port=r.port,
                import_source=source,
                imported_at=now,
            )
        )
    if rows:
        db.add_all(rows)
    return rows, skipped


def _zone_kwargs_from_parsed(
    parsed: ImportedZone,
    *,
    name: str,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
    source: ImportSource,
    now: datetime,
) -> dict[str, Any]:
    """Translate one parsed zone into kwargs for ``DNSZone(...)``.

    SOA → DB columns: defaults match the model column defaults so a
    forward / stub zone with no SOA still creates with sensible
    values (3600 / 86400 / etc). ``last_serial`` is seeded from the
    parsed SOA serial so the agent's first push doesn't roll the
    zone back to zero.
    """

    soa = parsed.soa
    return dict(
        group_id=target_group_id,
        view_id=target_view_id,
        name=name,
        zone_type=parsed.zone_type,
        kind=parsed.kind,
        ttl=soa.ttl if soa else 3600,
        refresh=soa.refresh if soa else 86400,
        retry=soa.retry if soa else 7200,
        expire=soa.expire if soa else 3600000,
        minimum=soa.minimum if soa else 3600,
        primary_ns=soa.primary_ns.rstrip(".") if soa and soa.primary_ns else "",
        admin_email=soa.admin_email.rstrip(".") if soa and soa.admin_email else "",
        last_serial=soa.serial if soa else 0,
        forwarders=parsed.forwarders or [],
        forward_only=parsed.zone_type == "forward",
        import_source=source,
        imported_at=now,
    )


async def _create_zone_at(
    db: AsyncSession,
    *,
    parsed: ImportedZone,
    target_name: str,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
    source: ImportSource,
    current_user: User,
    now: datetime,
    overwrote_records: int,
    audit_action: str,
    audit_extra: dict[str, Any] | None = None,
) -> CommitZoneResult:
    """Build the DNSZone + DNSRecord rows + audit log for one parsed
    zone and commit them in one transaction.

    Pre-conditions: the target slot is empty (no zone with this
    name in this group + view). Caller deletes any existing zone
    before invoking. ``audit_action`` is ``create`` for plain creates
    + renames, ``update`` for overwrites — the audit metadata
    distinguishes the case via ``audit_extra``.
    """

    zone_kwargs = _zone_kwargs_from_parsed(
        parsed,
        name=target_name,
        target_group_id=target_group_id,
        target_view_id=target_view_id,
        source=source,
        now=now,
    )
    zone = DNSZone(**zone_kwargs)
    db.add(zone)
    await db.flush()  # populate zone.id for the FK

    record_rows, skipped_records = await _build_records_for_zone(
        db,
        zone_id=zone.id,
        zone_fqdn=target_name,
        parsed=parsed,
        source=source,
        now=now,
    )
    records_created = len(record_rows)

    # Issue #707 — writing DNSRecord rows is NOT enough to make imported
    # records resolvable. Records are deliberately excluded from the agent
    # bundle's ``structural_etag`` (``agent_config.py`` drops the ``records``
    # key from ``zones_structural`` unless the group has views), so a
    # record-only change never triggers the agent's re-render/reload path.
    # The only route from a committed record to the live daemon is a
    # ``DNSRecordOp`` row, which the agent drains via nsupdate/RFC 2136
    # (BIND9) or the zone API (PowerDNS).
    #
    # This bites hardest on BIND9 overwrites: named already has the zone
    # loaded with a journal (zones render with ``allow-update``), so the
    # re-rendered master file is ignored on ``rndc reload`` and the records
    # stay invisible until an operator edits each one by hand. PowerDNS
    # recovers on the next unrelated structural reload (``_reconcile_zones``
    # PATCHes REPLACE rrsets) but is equally stale until then.
    #
    # ``target_serial`` is the zone's own serial rather than a bump: the
    # importer always creates the zone fresh (overwrites delete + recreate),
    # so ``last_serial`` was just seeded from the parsed SOA and already
    # describes the state these records belong to.
    if record_rows:
        await db.flush()  # populate record PKs before snapshotting payloads
        await enqueue_record_ops_bulk(
            db,
            zone,
            [
                {
                    "op": "create",
                    "record": record_op_payload(rec),
                    "target_serial": zone.last_serial or None,
                }
                for rec in record_rows
            ],
        )

    audit_meta: dict[str, Any] = {
        "import_source": source,
        "view_name": parsed.view_name,
        "records_created": records_created,
        "skipped_record_types": parsed.skipped_record_types,
    }
    if skipped_records:
        audit_meta["records_skipped_unsafe"] = skipped_records
    if overwrote_records:
        audit_meta["records_deleted_on_overwrite"] = overwrote_records
    if audit_extra:
        audit_meta.update(audit_extra)

    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action=audit_action,
            resource_type="dns_zone",
            resource_id=str(zone.id),
            resource_display=target_name,
            result="success",
            new_value=audit_meta,
        )
    )
    await db.commit()
    await db.refresh(zone)

    if overwrote_records:
        action_taken = "overwrote"
    elif audit_extra and "original_zone_name" in audit_extra:
        action_taken = "renamed"
    else:
        action_taken = "created"
    return CommitZoneResult(
        zone_name=parsed.name,
        action_taken=action_taken,
        zone_id=str(zone.id),
        records_created=records_created,
        records_deleted=overwrote_records,
    )


async def _existing_zone_at(
    db: AsyncSession,
    *,
    name: str,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
) -> DNSZone | None:
    stmt = select(DNSZone).where(
        DNSZone.group_id == target_group_id,
        DNSZone.name == name,
    )
    if target_view_id is None:
        stmt = stmt.where(DNSZone.view_id.is_(None))
    else:
        stmt = stmt.where(DNSZone.view_id == target_view_id)
    return (await db.execute(stmt)).scalar_one_or_none()


async def _delete_zone(db: AsyncSession, zone: DNSZone) -> int:
    """Soft-CASCADE the records first then delete the zone, returning
    the count of deleted records for audit metadata."""
    n = (
        await db.execute(select(func.count(DNSRecord.id)).where(DNSRecord.zone_id == zone.id))
    ).scalar_one() or 0
    await db.delete(zone)
    await db.flush()
    return int(n)


async def _commit_one_zone(
    db: AsyncSession,
    *,
    parsed: ImportedZone,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
    source: ImportSource,
    action: ConflictAction,
    rename_to: str | None,
    has_conflict: bool,
    current_user: User,
    now: datetime,
) -> CommitZoneResult:
    """Apply one parsed zone with the operator-supplied action.

    The action vocabulary, as resolved by :func:`commit_import`:

    * ``skip`` — only emitted when there *is* a conflict; never
      called as a create-plainly signal. (Plain creates pass
      ``action='skip'`` *and* ``has_conflict=False`` — we treat that
      as "no conflict, create freely". This is the historic
      collapse path; see the dispatch in commit_import below.)
    * ``overwrite`` — only valid when there's a conflict.
    * ``rename`` — valid in either state; takes ``rename_to`` as the
      new FQDN. If the rename target is itself occupied we fail the
      zone (we don't chain-rename — that's an operator workflow,
      not an importer one).

    Per-zone savepoint: caller wraps in try/except + rollback so a
    failed zone doesn't poison the next one.
    """

    target_name = _normalize_fqdn(parsed.name).lower()
    audit_extra: dict[str, Any] = {}

    if action == "rename":
        try:
            target_name = _validate_rename(rename_to)
        except ValueError as exc:
            return CommitZoneResult(
                zone_name=parsed.name,
                action_taken="failed",
                error=str(exc),
            )
        audit_extra["original_zone_name"] = parsed.name
        # Rename target must be unoccupied — chained renames are out
        # of scope.
        clash = await _existing_zone_at(
            db,
            name=target_name,
            target_group_id=target_group_id,
            target_view_id=target_view_id,
        )
        if clash is not None:
            return CommitZoneResult(
                zone_name=parsed.name,
                action_taken="failed",
                error=f"Rename target {target_name!r} is already occupied",
            )
        return await _create_zone_at(
            db,
            parsed=parsed,
            target_name=target_name,
            target_group_id=target_group_id,
            target_view_id=target_view_id,
            source=source,
            current_user=current_user,
            now=now,
            overwrote_records=0,
            audit_action="create",
            audit_extra=audit_extra,
        )

    if action == "overwrite":
        if not has_conflict:
            # Operator picked overwrite but the conflict's gone —
            # treat as a plain create.
            return await _create_zone_at(
                db,
                parsed=parsed,
                target_name=target_name,
                target_group_id=target_group_id,
                target_view_id=target_view_id,
                source=source,
                current_user=current_user,
                now=now,
                overwrote_records=0,
                audit_action="create",
            )
        existing = await _existing_zone_at(
            db,
            name=target_name,
            target_group_id=target_group_id,
            target_view_id=target_view_id,
        )
        if existing is None:
            # Race: between detect_conflicts and now somebody else
            # deleted the conflicting zone. Treat as plain create.
            return await _create_zone_at(
                db,
                parsed=parsed,
                target_name=target_name,
                target_group_id=target_group_id,
                target_view_id=target_view_id,
                source=source,
                current_user=current_user,
                now=now,
                overwrote_records=0,
                audit_action="create",
            )
        records_deleted = await _delete_zone(db, existing)
        return await _create_zone_at(
            db,
            parsed=parsed,
            target_name=target_name,
            target_group_id=target_group_id,
            target_view_id=target_view_id,
            source=source,
            current_user=current_user,
            now=now,
            overwrote_records=records_deleted,
            audit_action="update",
        )

    # action == "skip"
    if has_conflict:
        return CommitZoneResult(zone_name=parsed.name, action_taken="skipped")
    # No conflict + skip = "create plainly" (this is the default
    # path for zones the operator left alone).
    return await _create_zone_at(
        db,
        parsed=parsed,
        target_name=target_name,
        target_group_id=target_group_id,
        target_view_id=target_view_id,
        source=source,
        current_user=current_user,
        now=now,
        overwrote_records=0,
        audit_action="create",
    )


async def commit_import(
    db: AsyncSession,
    *,
    preview: ImportPreview,
    target_group_id: uuid.UUID,
    target_view_id: uuid.UUID | None,
    conflict_actions: dict[str, tuple[ConflictAction, str | None]],
    current_user: User,
) -> CommitResult:
    """Apply ``preview`` to the DB inside per-zone savepoints.

    ``conflict_actions`` is keyed by the zone's *original* name
    (``ImportedZone.name`` as parsed) so the operator's per-row
    decision survives a rename. Zones the operator left untouched
    default to action=skip on conflict, plain-create on no
    conflict.
    """

    grp = (
        await db.execute(select(DNSServerGroup).where(DNSServerGroup.id == target_group_id))
    ).scalar_one_or_none()
    if grp is None:
        raise ValueError(f"Target group {target_group_id} does not exist")
    if target_view_id is not None:
        view = (
            await db.execute(
                select(DNSView).where(
                    DNSView.id == target_view_id,
                    DNSView.group_id == target_group_id,
                )
            )
        ).scalar_one_or_none()
        if view is None:
            raise ValueError(
                f"Target view {target_view_id} does not exist in group {target_group_id}"
            )

    # Re-detect conflicts in case the world moved between preview
    # and commit. The set is keyed by FQDN-with-trailing-dot lower-case.
    zone_names = [_normalize_fqdn(z.name).lower() for z in preview.zones]
    fresh_conflicts = await detect_conflicts(
        db,
        zone_names=zone_names,
        target_group_id=target_group_id,
        target_view_id=target_view_id,
    )
    conflicting = {c.zone_name for c in fresh_conflicts}

    # #1357 — a BIND9 group renders a forward zone's forwarders as
    # ``ip[ port n]``; an imported entry it cannot (a hostname, a DoH URL, a
    # ``tls`` clause naming a definition that was not imported) would be
    # dropped at render with only a log line. Drop it here instead and say
    # so in the result. No servers yet reads as BIND9, as the API does.
    drivers = set(
        (
            await db.execute(
                select(DNSServer.driver).where(DNSServer.group_id == target_group_id).distinct()
            )
        )
        .scalars()
        .all()
    )
    bind9_target = not drivers or "bind9" in drivers
    warnings = list(preview.warnings)

    now = datetime.now(UTC)
    results: list[CommitZoneResult] = []

    for parsed in preview.zones:
        if bind9_target and parsed.forwarders:
            kept, dropped = split_zone_forwarders(parsed.forwarders)
            if dropped:
                warnings.append(
                    f"Zone {parsed.name!r}: dropped forwarder(s) "
                    f"{', '.join(repr(v) for v, _ in dropped)} — a BIND9 group "
                    "forwards to an IP address with an optional port only"
                )
            parsed = replace(parsed, forwarders=kept)
        target_name = _normalize_fqdn(parsed.name).lower()
        # Operator entry keyed by either the parsed name (preferred,
        # what the UI hands back) or the normalized form.
        entry = conflict_actions.get(parsed.name) or conflict_actions.get(target_name)
        if entry is None:
            action: ConflictAction = "skip"
            rename_to: str | None = None
        else:
            action, rename_to = entry
        has_conflict = target_name in conflicting

        try:
            result = await _commit_one_zone(
                db,
                parsed=parsed,
                target_group_id=target_group_id,
                target_view_id=target_view_id,
                source=preview.source,
                action=action,
                rename_to=rename_to,
                has_conflict=has_conflict,
                current_user=current_user,
                now=now,
            )
        except Exception as exc:  # noqa: BLE001 — operator-facing error capture
            await db.rollback()
            result = CommitZoneResult(
                zone_name=parsed.name,
                action_taken="failed",
                error=str(exc),
            )
        results.append(result)

    return CommitResult(
        target_group_id=target_group_id,
        zones=results,
        warnings=warnings,
    )

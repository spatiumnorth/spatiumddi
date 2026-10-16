"""Phase 3a pre-flight — drop DNS TTLs so a rollback is measured in minutes.

The switch itself is a delegation or forwarder change made outside SpatiumDDI.
Its blast radius is therefore governed entirely by how long resolvers keep
serving the old answers, and that is the TTL. A zone sitting on the common
3600 default means a bad cutover is visible for an hour after it is reverted;
lowered to 300 well ahead of the window, the same mistake clears in five
minutes. Nothing else in the cutover buys as much safety for as little effort.

What this module does, on the SpatiumDDI side:

* Snapshots the zone SOA (``ttl`` / ``minimum`` / ``refresh`` / ``retry``) and
  **every** record's ``ttl`` into ``CutoverItem.ttl_snapshot`` — once. A second
  apply (say, dropping from 300 to 60) must not overwrite that snapshot, or the
  restore would put the zone back to an intermediate value that was never the
  operator's configuration.
* Lowers ``zone.ttl`` / ``zone.minimum`` and every record whose ``ttl`` exceeds
  the target. Records with ``ttl IS NULL`` inherit ``zone.ttl``, so lowering the
  zone changes them implicitly; they are set **explicitly** to the target and
  snapshotted as ``None``, so a restore can put the inheritance back rather than
  leaving them pinned to whatever the zone default happened to be.
* Pushes the changes through the ordinary record pipeline: one
  ``bump_zone_serial`` for the whole batch, then ``enqueue_record_ops_batch``.
  No private fan-out — the batch path already handles agentless (one driver
  call) and agent-based (queued rows per server) correctly.

What it deliberately does **not** do is lower the TTLs on the Windows source,
even though those are the values resolvers are actually caching today and are
therefore the ones that matter. Record writes to a Windows DNS server ride
RFC 2136 by default, where "change the TTL" is expressed as a delete of the
rrset followed by an add — and we are not issuing an unattended delete against
a zone that is still live and authoritative for production. (The WinRM Path B
alternative is no better here: it is a clone-and-``Set`` per record against
that same live zone.) Instead ``TTLPreflightPlan.source_side_instructions``
carries a copy-pasteable PowerShell block for the operator to run there, and
the runbook repeats it. A TTL drop applied to only one side is worse than none
at all — it looks done and buys nothing — so the instructions are part of every
preview and apply response, not an optional extra.

Neither :func:`apply_ttl_preflight` nor :func:`restore_ttl_preflight` commits;
the caller owns the transaction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import collect_wake, dns_group_channel
from app.drivers.dns import is_agentless
from app.models.auth import User
from app.models.cutover import CutoverItem
from app.models.dns import DNSRecord, DNSZone
from app.services.cutover.canonical import TTLPreflightPlan, TTLRecordChange
from app.services.dns.record_ops import (
    enqueue_record_ops_batch,
    record_op_payload,
    resolve_primary_server,
)
from app.services.dns.serial import bump_zone_serial

logger = structlog.get_logger(__name__)

#: Floor. Below ~30 s the query load on the authoritative servers stops being
#: negligible and cache-miss latency starts showing up for clients, for a
#: rollback window that is already short enough.
MIN_TARGET_TTL = 30

#: Ceiling — one day. A "pre-flight" that leaves the TTL at a day is not a
#: pre-flight, and accepting an arbitrarily large value here would let an
#: operator quietly *raise* every TTL in the zone through a screen labelled
#: "lower TTLs".
MAX_TARGET_TTL = 86400

#: Zone SOA fields captured in the snapshot. ``refresh`` / ``retry`` are not
#: modified, but are recorded so the snapshot is a complete picture of the SOA
#: timing as it stood before the migration.
_SOA_FIELDS = ("ttl", "minimum", "refresh", "retry")


def validate_target_ttl(target_ttl: int) -> int:
    """Return ``target_ttl`` or raise ``ValueError`` describing the bounds."""
    try:
        value = int(target_ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError("target_ttl must be an integer number of seconds.") from exc
    if value < MIN_TARGET_TTL or value > MAX_TARGET_TTL:
        raise ValueError(
            f"target_ttl must be between {MIN_TARGET_TTL} and {MAX_TARGET_TTL} seconds "
            f"(got {value})."
        )
    return value


async def _assert_target_is_not_the_source(db: AsyncSession, zone: DNSZone) -> None:
    """Refuse to run when the zone's group writes through to an agentless server.

    The module's central promise is that it does not touch the Windows source.
    ``enqueue_record_ops_batch`` does not know that: it resolves the zone
    group's ``is_primary`` server and, when that server is agentless, dispatches
    the change straight at the provider — for ``windows_dns`` that is a
    delete+add per record over RFC 2136, against a zone that is still live and
    authoritative for production.

    A plan can legitimately point at a group the Windows server is also
    registered in (``shadow._collect_targets`` documents exactly that case), and
    nothing else stops the operator choosing one. So check here and refuse with
    an explanation, rather than quietly doing the thing the docstring says we
    never do.
    """
    primary = await resolve_primary_server(db, zone)
    if primary is None or not is_agentless(primary.driver):
        return
    raise ValueError(
        f"The primary server of {zone.name}'s group is {primary.name!r}, which uses the "
        f"agentless {primary.driver!r} driver — record writes to it are applied directly "
        "to that server. Lowering TTLs here would rewrite records on the very server "
        "this migration is moving away from, which the pre-flight deliberately never "
        "does. Point the item at a group whose primary is an agent-managed server "
        "(BIND9 / PowerDNS / Technitium), and lower the source's TTLs with the "
        "PowerShell in the pre-flight preview instead."
    )


def _ttl_ops(records: list[DNSRecord], zone: DNSZone) -> list[dict[str, Any]]:
    """Build the record-op batch for a TTL rewrite, RRset-aware.

    #773 stamps the complete desired RRset onto ordinary record ops, which
    would cover this too — but setting ``rrset_action`` opts an op out of that
    stamping, and this path keeps doing so on purpose. The grouping below is
    what protects an agent that predates the ``rrset`` field, and agents deploy
    on their own schedule; this is the one path where getting it wrong costs
    the operator addresses at exactly the moment they are migrating.

    The hazard it guards: an agent that knows only ``rrset_action`` turns a
    ``create`` / ``update`` op into an RFC 2136 ``replace``, which swaps the
    **whole RRset** for the single value in that op. That is right for the
    one-value-per-name case the record CRUD path was written for, and silently
    destructive for anything else: a name with three round-robin A records
    would be rewritten three times and end up serving only the last one.
    Lowering a TTL must not cost the operator two thirds of their addresses.

    That is the agent contract. Agentless drivers never see ``rrset_action``
    (``RecordChange`` has no such field), so on that path the record-op layer
    stamps the ``update`` + ``add`` siblings with the whole folded RRset
    (``stamp_rrsets_for_ops(agentless=True)``, #1983) and each driver writes it
    as one set. ``_assert_target_is_not_the_source`` still keeps this module off a
    live Windows source; this covers any agentless server that is reached.

    So ops are grouped by ``(name, type)``. The first op in a group keeps the
    default ``replace`` — which clears the old RRset — and every sibling carries
    ``rrset_action="add"`` to append onto it. The result is one RRset with every
    original value at the new TTL. Groups of one are unchanged, so the common
    case emits exactly what it did before.

    A ``None`` TTL is resolved to ``zone.ttl`` **on the wire**. The row keeps its
    NULL — that is how "inherit the zone default" is stored, and the restore path
    depends on it — but an older agent's record-op branch falls back to a
    hardcoded 3600 rather than the zone's own default, so shipping the null
    would silently write 3600 onto every inheriting record of a zone whose
    default is anything else. Resolving here keeps the wire honest without
    touching the row — and since these ops opt out of #773's stamping, this
    is still the only place it happens for them.
    """
    grouped: dict[tuple[str, str], list[DNSRecord]] = {}
    for rec in records:
        grouped.setdefault(((rec.name or "@").lower(), rec.record_type.upper()), []).append(rec)

    ops: list[dict[str, Any]] = []
    for group in grouped.values():
        for index, rec in enumerate(group):
            payload = record_op_payload(rec)
            if payload.get("ttl") is None:
                payload["ttl"] = zone.ttl
            if index:
                payload["rrset_action"] = "add"
            ops.append({"op": "update", "record": payload})
    return ops


def _needs_lowering(record: DNSRecord, target_ttl: int) -> bool:
    """True when this record's TTL has to be written to reach ``target_ttl``.

    ``None`` counts: it means "inherit ``zone.ttl``", and leaving it that way
    would make the record's effective TTL a side effect of the zone change
    rather than something the snapshot can restore exactly.
    """
    return record.ttl is None or record.ttl > target_ttl


async def _load_records(db: AsyncSession, zone: DNSZone) -> list[DNSRecord]:
    """Every live record in the zone. Soft-deleted rows are filtered by the
    session-wide ``deleted_at IS NULL`` criterion in ``app.db``."""
    return list(
        (
            await db.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone.id)
                .order_by(DNSRecord.name, DNSRecord.record_type)
            )
        )
        .scalars()
        .all()
    )


def windows_ttl_powershell(
    zone_name: str,
    target_ttl: int,
    current_zone_ttl: int,
    *,
    computer_name: str | None = None,
) -> str:
    """The Windows-side TTL drop, ready to paste into an elevated shell.

    The single source for this script. It is surfaced twice — inline as
    ``TTLPreflightPlan.source_side_instructions`` on every preview and apply
    response, and again in the generated runbook — and an operator who is handed
    two subtly different versions of the same command has been handed a bug. So
    :mod:`app.services.cutover.runbook` calls this rather than keeping a copy.

    ``computer_name`` adds ``-ComputerName`` so the block can be run from an
    admin workstation instead of on the server itself; omit it for the
    run-it-on-the-box form.
    """
    label = zone_name.strip().rstrip(".")
    escaped = label.replace("'", "''")
    where = "" if computer_name is None else " -ComputerName $Server"
    server_line = (
        ""
        if computer_name is None
        else f"$Server = '{computer_name.replace(chr(39), chr(39) * 2)}'\n"
    )
    ran_on = (
        f"# Run on the Windows DNS server that is still authoritative for {label},"
        if computer_name is None
        else f"# Lower the Windows-side TTLs for {label} on {computer_name}."
    )
    return f"""{ran_on}
# in an elevated PowerShell session, BEFORE the cutover window.
#
# These are the TTLs resolvers are caching right now, so lowering them here is
# what actually shortens a rollback. Lowering only the SpatiumDDI side changes
# nothing until after the switch has already happened.
#
# Allow at least the CURRENT TTL ({current_zone_ttl}s) to pass after running
# this, so every cached copy of the old value has expired before you cut over.

{server_line}$Zone   = '{escaped}'
$NewTtl = [TimeSpan]::FromSeconds({target_ttl})

# 1. SOA — the zone default, and the negative-caching TTL. MinimumTimeToLive
#    governs how long a resolver remembers an NXDOMAIN from the old server,
#    which is exactly the failure mode a rollback has to clear.
$soa = Get-DnsServerResourceRecord{where} -ZoneName $Zone -RRType SOA
$new = $soa.Clone()
$new.TimeToLive = $NewTtl
$new.RecordData.MinimumTimeToLive = $NewTtl
Set-DnsServerResourceRecord{where} -ZoneName $Zone -OldInputObject $soa -NewInputObject $new -Force

# 2. Every other record currently above the target.
Get-DnsServerResourceRecord{where} -ZoneName $Zone |
    Where-Object {{ $_.RecordType -ne 'SOA' -and $_.TimeToLive -gt $NewTtl }} |
    ForEach-Object {{
        $old = $_
        $rec = $_.Clone()
        $rec.TimeToLive = $NewTtl
        Set-DnsServerResourceRecord{where} -ZoneName $Zone `
            -OldInputObject $old -NewInputObject $rec -Force
    }}

# To put it back after the migration is finished (or abandoned), re-run the
# same block with $NewTtl = [TimeSpan]::FromSeconds({current_zone_ttl}).
"""


def _build_plan(zone: DNSZone, records: list[DNSRecord], target_ttl: int) -> TTLPreflightPlan:
    """Describe what lowering ``zone`` to ``target_ttl`` would change."""
    changed = [r for r in records if _needs_lowering(r, target_ttl)]
    zone_current = {f: int(getattr(zone, f)) for f in _SOA_FIELDS}
    zone_after = dict(zone_current)
    zone_after["ttl"] = min(zone_current["ttl"], target_ttl)
    zone_after["minimum"] = min(zone_current["minimum"], target_ttl)

    plan = TTLPreflightPlan(
        target_ttl=target_ttl,
        zone_current=zone_current,
        zone_after=zone_after,
        records=[
            TTLRecordChange(
                record_id=str(r.id),
                name=r.name or "@",
                record_type=r.record_type,
                current_ttl=r.ttl,
                new_ttl=target_ttl,
            )
            for r in changed
        ],
        unchanged=len(records) - len(changed),
        source_side_instructions=windows_ttl_powershell(zone.name, target_ttl, zone_current["ttl"]),
    )

    # The single most common way to get no benefit from this step: run it an
    # hour before the window, when the value being replaced has an hour of
    # cache lifetime left. Say the number rather than "plan ahead".
    plan.warnings.append(
        f"Resolvers may keep serving the previous values for up to "
        f"{zone_current['ttl']}s. Apply this at least that long before the "
        f"cutover window, on both sides."
    )
    if zone_current["ttl"] <= target_ttl and not changed:
        plan.warnings.append(
            "Nothing to lower — the zone and every record are already at or below "
            f"{target_ttl}s."
        )
    if any(r.ttl is None for r in changed):
        plan.warnings.append(
            "Records that inherit the zone TTL will be given an explicit TTL so the "
            "original inheritance can be restored exactly on rollback."
        )
    if zone.view_id is not None:
        plan.warnings.append(
            "This zone is scoped to a DNS view. Its other views are separate zone rows "
            "and are not touched here — lower each one you are migrating."
        )
    return plan


async def preview_ttl_preflight(
    db: AsyncSession, *, zone: DNSZone, target_ttl: int
) -> TTLPreflightPlan:
    """Read-only: what :func:`apply_ttl_preflight` would do. Mutates nothing."""
    ttl = validate_target_ttl(target_ttl)
    records = await _load_records(db, zone)
    return _build_plan(zone, records, ttl)


async def apply_ttl_preflight(
    db: AsyncSession,
    *,
    zone: DNSZone,
    item: CutoverItem,
    target_ttl: int,
    current_user: User | None = None,
) -> TTLPreflightPlan:
    """Lower the zone + record TTLs, snapshotting the originals first.

    The returned plan describes the state as it was *before* the mutation —
    ``records[].current_ttl`` is what each record held on the way in — so it
    doubles as the report of what was changed.

    The snapshot is written only on the first apply. Re-applying with a lower
    target still lowers TTLs, but leaves the pristine snapshot alone and says so
    in ``warnings``; ``restore_ttl_preflight`` therefore always returns the zone
    to its true pre-migration values, however many times this ran.

    Does not commit.
    """
    ttl = validate_target_ttl(target_ttl)
    await _assert_target_is_not_the_source(db, zone)
    records = await _load_records(db, zone)
    plan = _build_plan(zone, records, ttl)
    changed = [r for r in records if _needs_lowering(r, ttl)]

    if item.ttl_snapshot is None:
        item.ttl_snapshot = {
            "target_ttl": ttl,
            "taken_at": datetime.now(UTC).isoformat(),
            "zone": {f: int(getattr(zone, f)) for f in _SOA_FIELDS},
            # Every record, not only the ones being changed now: a later apply
            # at a lower target can touch rows this one left alone, and the
            # snapshot has to cover those too.
            "records": [{"id": str(r.id), "ttl": r.ttl} for r in records],
        }
    else:
        taken_at = item.ttl_snapshot.get("taken_at") or "an earlier run"
        plan.warnings.append(
            f"A TTL snapshot was already taken ({taken_at}) and has been kept, so a "
            "restore still returns the original pre-migration values."
        )

    zone_changed = False
    if zone.ttl > ttl:
        zone.ttl = ttl
        zone_changed = True
    if zone.minimum > ttl:
        zone.minimum = ttl
        zone_changed = True

    for record in changed:
        record.ttl = ttl

    if changed or zone_changed:
        # One serial for the whole batch — a serial per record would make every
        # secondary transfer the zone N times for a single logical change.
        target_serial = bump_zone_serial(zone)
        if changed:
            ops = _ttl_ops(changed, zone)
            for op in ops:
                op["target_serial"] = target_serial
            await enqueue_record_ops_batch(db, zone, ops)
        # The SOA change alone shifts the rendered config bundle, and the
        # record-op path only wakes the group when there were record ops.
        collect_wake(dns_group_channel(zone.group_id))

    item.ttl_lowered_at = datetime.now(UTC)
    if item.stage in ("pending", "parity_checked"):
        item.stage = "preflight_done"
    await db.flush()

    logger.info(
        "cutover.preflight.applied",
        zone=zone.name,
        item=str(item.id),
        target_ttl=ttl,
        records_changed=len(changed),
        zone_changed=zone_changed,
        user=current_user.username if current_user else None,
    )
    return plan


async def restore_ttl_preflight(
    db: AsyncSession,
    *,
    zone: DNSZone,
    item: CutoverItem,
    current_user: User | None = None,
) -> int:
    """Put the snapshotted TTLs back and clear the snapshot.

    Returns the number of **record** rows whose TTL was rewritten; the zone SOA
    restore is not counted. Returns 0 when no snapshot exists (nothing was ever
    lowered, or a previous restore already ran) — that is not an error, so a
    rollback can call this unconditionally.

    Does not commit.
    """
    snapshot = item.ttl_snapshot
    if not snapshot:
        return 0
    await _assert_target_is_not_the_source(db, zone)

    zone_snapshot: dict = snapshot.get("zone") or {}
    zone_changed = False
    for field_name in _SOA_FIELDS:
        original = zone_snapshot.get(field_name)
        if original is None:
            continue
        if getattr(zone, field_name) != int(original):
            setattr(zone, field_name, int(original))
            zone_changed = True

    # ``ttl`` here is deliberately allowed to be None — that is the stored form
    # of "inherits the zone TTL", and restoring it as anything else would leave
    # the record pinned forever.
    original_ttls: dict[str, int | None] = {
        str(entry.get("id")): entry.get("ttl")
        for entry in (snapshot.get("records") or [])
        if entry.get("id")
    }

    records = await _load_records(db, zone)
    restored = [
        r for r in records if str(r.id) in original_ttls and r.ttl != original_ttls[str(r.id)]
    ]
    for record in restored:
        record.ttl = original_ttls[str(record.id)]

    if restored or zone_changed:
        target_serial = bump_zone_serial(zone)
        if restored:
            ops = _ttl_ops(restored, zone)
            for op in ops:
                op["target_serial"] = target_serial
            await enqueue_record_ops_batch(db, zone, ops)
        collect_wake(dns_group_channel(zone.group_id))

    item.ttl_snapshot = None
    item.ttl_lowered_at = None
    if item.stage == "preflight_done":
        item.stage = "parity_checked"
    await db.flush()

    logger.info(
        "cutover.preflight.restored",
        zone=zone.name,
        item=str(item.id),
        records_restored=len(restored),
        zone_changed=zone_changed,
        user=current_user.username if current_user else None,
    )
    return len(restored)


__all__ = [
    "MAX_TARGET_TTL",
    "MIN_TARGET_TTL",
    "apply_ttl_preflight",
    "preview_ttl_preflight",
    "restore_ttl_preflight",
    "validate_target_ttl",
    "windows_ttl_powershell",
]

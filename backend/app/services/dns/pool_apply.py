"""DNS pool apply-state service.

Bridges ``DNSPoolMember`` state to actual ``DNSRecord`` rows. For every
healthy + enabled member there should be exactly one ``DNSRecord``
(name = pool.record_name, type = pool.record_type, value =
member.address, pool_member_id = member.id). For every unhealthy or
disabled member, that record should not exist.

This service is called from the pool health-check task after each
member-state evaluation; it diffs current records against what
``apply_pool_state`` says should exist and emits create/delete ops.

Driver-agnostic: emits regular ``enqueue_record_op`` calls so BIND9 +
Windows DNS render unchanged. The records themselves carry
``pool_member_id`` so the records UI can flag them as pool-managed and
record CRUD endpoints reject operator edits.
"""

from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSPool, DNSPoolMember, DNSRecord, DNSZone
from app.services.dns.record_ops import enqueue_record_op
from app.services.dns.serial import bump_zone_serial

logger = structlog.get_logger(__name__)


async def apply_pool_state(
    db: AsyncSession,
    pool: DNSPool,
) -> dict[str, int]:
    """Reconcile rendered records with the current member state.

    For each member: if healthy + enabled, ensure a record exists; if
    unhealthy or disabled, ensure none exists. Returns a summary dict
    with ``created`` / ``deleted`` counts.

    A disabled pool (``pool.enabled`` false) renders nothing, so the
    reconcile removes any records it previously rendered.

    The pool's TTL is honoured on every emitted record so changes to
    ``pool.ttl`` flow through on the next reconcile pass.
    """
    # #1966 — every read below runs without autoflush. A caller that took a
    # member out of ``pool.members`` (``delete_member`` / ``delete_pool``)
    # has queued the member row's DELETE as a delete-orphan; the first query
    # here would autoflush it, and the ``dns_record.pool_member_id`` FK
    # ``ON DELETE CASCADE`` would take the member's record row with it in
    # the same statement — before the orphan sweep could read it, so no
    # delete op was ever enqueued and the agent kept serving the address.
    with db.no_autoflush:
        zone, existing_by_member, orphan_records = await _read_pool_state(db, pool)
    if zone is None:
        return {"created": 0, "deleted": 0, "skipped": 0}

    created = 0
    deleted = 0
    skipped = 0
    ttl_changed: DNSPoolMember | None = None

    if orphan_records:
        # Every orphan's row goes in ONE targeted flush, before any op is
        # enqueued: ``enqueue_record_op`` autoflushes, which would write the
        # pending member DELETEs, and the FK cascade would then take the
        # orphans not yet deleted here (#1966).
        snapshots = [_delete_snapshot(o) for o in orphan_records]
        for orphan in orphan_records:
            await db.delete(orphan)
        await db.flush(orphan_records)
        for snapshot in snapshots:
            await enqueue_record_op(
                db, zone, "delete", snapshot, target_serial=bump_zone_serial(zone)
            )
            deleted += 1

    for member in pool.members:
        # Deliberately fail-open on an OLD verdict (#2312): ``last_check_at`` is not
        # consulted here, so a stopped health checker keeps the last-known set
        # rather than emptying the answer. Staleness is surfaced instead (see
        # ``pool_health_staleness`` and the ``dns_pool_health_stale`` alert).
        # A disabled pool renders nothing: every record it owns is removed
        # (#1974), and re-enabling restores the healthy + enabled members.
        should_render = (
            bool(pool.enabled)
            and bool(member.enabled)
            and ((member.last_check_state or "unknown") == "healthy")
        )
        rec = existing_by_member.get(str(member.id))

        if should_render and rec is None:
            await _create_pool_record(db, zone, pool, member)
            created += 1
        elif not should_render and rec is not None:
            await _delete_pool_record(db, zone, rec)
            deleted += 1
        elif should_render and rec is not None and rec.value != member.address:
            # Member address edited — the rendered record still
            # carries the old IP. Delete-then-recreate on the same
            # serial so the live daemon moves to the new value
            # atomically (same shape as the rename branch below).
            old_snapshot = {
                "name": rec.name,
                "type": rec.record_type,
                "value": rec.value,
                "ttl": rec.ttl,
                "rrset_action": "delete_value",
            }
            target_serial = bump_zone_serial(zone)
            await enqueue_record_op(db, zone, "delete", old_snapshot, target_serial=target_serial)
            rec.value = member.address
            rec.ttl = pool.ttl
            await enqueue_record_op(
                db,
                zone,
                "create",
                _record_payload(pool, member, pool.ttl),
                target_serial=target_serial,
            )
            created += 1
        elif (
            should_render
            and rec is not None
            and (rec.name != pool.record_name or rec.record_type != pool.record_type)
        ):
            # Pool rename / type-change — the existing record carries
            # the old (name, type) and BIND9 is still serving it under
            # those labels. Delete-then-recreate so the live daemon
            # actually moves to the new identity. Done as two ops on
            # the same serial so the replay is atomic from the
            # operator's perspective.
            old_snapshot = {
                "name": rec.name,
                "type": rec.record_type,
                "value": rec.value,
                "ttl": rec.ttl,
                "rrset_action": "delete_value",
            }
            target_serial = bump_zone_serial(zone)
            await enqueue_record_op(db, zone, "delete", old_snapshot, target_serial=target_serial)
            fqdn = zone.name if pool.record_name == "@" else f"{pool.record_name}.{zone.name}"
            rec.name = pool.record_name
            rec.record_type = pool.record_type
            rec.fqdn = fqdn
            rec.ttl = pool.ttl
            await enqueue_record_op(
                db,
                zone,
                "create",
                _record_payload(pool, member, pool.ttl),
                target_serial=target_serial,
            )
            created += 1  # counts as a re-creation under the new name
        elif should_render and rec is not None and rec.ttl != pool.ttl:
            # Pool TTL changed. Collected and shipped as ONE whole-RRset op
            # after the loop, not one per member (#1974): see below.
            rec.ttl = pool.ttl
            ttl_changed = member
        else:
            skipped += 1

    if ttl_changed is not None:
        # A TTL change is a property of the RRset, not of one member, so it
        # goes out as a single ``update`` WITHOUT ``rrset_action``:
        # ``enqueue_record_op`` then stamps it with the complete desired set
        # (every pool record, already at the new TTL and reflecting every
        # create / delete above, which have been flushed). The per-member
        # ``update`` this replaced carried ``rrset_action="add"`` and no set,
        # which the agentless drivers read as "replace the RRset with this
        # one value": on Windows DNS, Route 53 and Google Cloud DNS each
        # member's update cleared its siblings, so a TTL edit left a live pool
        # answering with only its last member while the database still listed
        # them all — and nothing reconciled it back, because the rows matched.
        # A whole-set write is also order-independent: it is emitted last in
        # the pass, so per-RR ops queued above it cannot be undone by it.
        await db.flush()
        target_serial = bump_zone_serial(zone)
        payload = _record_payload(pool, ttl_changed, pool.ttl)
        payload.pop("rrset_action")
        await enqueue_record_op(db, zone, "update", payload, target_serial=target_serial)

    if created or deleted:
        logger.info(
            "dns_pool_apply",
            pool=pool.name,
            zone=zone.name,
            created=created,
            deleted=deleted,
        )

    return {"created": created, "deleted": deleted, "skipped": skipped}


async def withdraw_member_records(
    db: AsyncSession, pool: DNSPool, members: list[DNSPoolMember]
) -> int:
    """Withdraw the rendered records of ``members`` BEFORE they are deleted.

    Call while the members are still in ``pool.members`` and nothing about
    them is pending. Each record is found by ``pool_member_id`` directly,
    deleted, flushed and its ``delete_value`` op enqueued — so by the time
    the member rows go, the ``dns_record.pool_member_id`` FK ``ON DELETE
    CASCADE`` has nothing left to take silently (#1966: it used to take the
    record row first, and no delete op was ever sent). Returns how many
    records were withdrawn.
    """
    ids = [m.id for m in members]
    if not ids:
        return 0
    zone = await db.get(DNSZone, pool.zone_id)
    if zone is None:
        return 0
    recs = (
        (await db.execute(select(DNSRecord).where(DNSRecord.pool_member_id.in_(ids))))
        .scalars()
        .all()
    )
    for rec in recs:
        await _delete_pool_record(db, zone, rec)
    if recs:
        logger.info("dns_pool_members_withdrawn", pool=pool.name, zone=zone.name, deleted=len(recs))
    return len(recs)


async def _read_pool_state(
    db: AsyncSession, pool: DNSPool
) -> tuple[DNSZone | None, dict[str, DNSRecord], list[DNSRecord]]:
    """The zone, the pool's rendered records keyed by member id, and the
    orphans (records of a member of this pool no longer in ``pool.members``).
    Call under ``db.no_autoflush`` (``apply_pool_state``)."""
    zone = await db.get(DNSZone, pool.zone_id)
    if zone is None:
        return None, {}, []

    # Existing records for this pool — keyed by member id so we can
    # diff against desired state below. No name/type filter on this
    # query because the rename branch downstream needs to find the
    # record under its OLD name to delete-then-recreate it.
    existing_res = await db.execute(
        select(DNSRecord).where(
            DNSRecord.zone_id == pool.zone_id,
            DNSRecord.pool_member_id.in_(_member_ids(pool)),
        )
    )
    existing_by_member: dict[str, DNSRecord] = {
        str(r.pool_member_id): r for r in existing_res.scalars().all()
    }

    # Orphan sweep — records whose ``pool_member_id`` belongs to a
    # member of THIS pool that's no longer in ``pool.members`` (eg.
    # the caller is ``delete_member`` which mutated the in-memory
    # list before calling here). Without this, the FK
    # ``ondelete=CASCADE`` on ``DNSRecord.pool_member_id`` strips the
    # record row at SQL commit but no ``enqueue_record_op('delete')``
    # ever fires, leaving BIND9 serving the stale answer until the
    # zone re-renders for some other reason.
    current_member_ids = {str(m.id) for m in pool.members}
    orphan_res = await db.execute(
        select(DNSRecord)
        .join(DNSPoolMember, DNSRecord.pool_member_id == DNSPoolMember.id)
        .where(DNSPoolMember.pool_id == pool.id)
    )
    orphan_records = [
        r for r in orphan_res.scalars().all() if str(r.pool_member_id) not in current_member_ids
    ]

    return zone, existing_by_member, orphan_records


def _member_ids(pool: DNSPool) -> list[str]:
    if not pool.members:
        return ["00000000-0000-0000-0000-000000000000"]  # safe non-match
    return [str(m.id) for m in pool.members]


async def _create_pool_record(
    db: AsyncSession,
    zone: DNSZone,
    pool: DNSPool,
    member: DNSPoolMember,
) -> None:
    fqdn = zone.name if pool.record_name == "@" else f"{pool.record_name}.{zone.name}"
    rec = DNSRecord(
        zone_id=zone.id,
        name=pool.record_name,
        fqdn=fqdn,
        record_type=pool.record_type,
        value=member.address,
        ttl=pool.ttl,
        pool_member_id=member.id,
    )
    db.add(rec)
    target_serial = bump_zone_serial(zone)
    await db.flush()
    await enqueue_record_op(
        db,
        zone,
        "create",
        _record_payload(pool, member, rec.ttl),
        target_serial=target_serial,
    )


def _delete_snapshot(rec: DNSRecord) -> dict[str, object]:
    # ``delete_value`` removes only this specific RR — sibling pool
    # members at the same (name, rtype) survive. Without this, removing
    # one unhealthy member would wipe every healthy member's record too.
    # #773 ships the complete desired RRset on ordinary record ops, but pool
    # ops opt out by carrying this flag: a pool re-points a member as a
    # delete-then-create pair on ONE serial, and a whole-RRset write would make
    # that pair order-dependent (the delete's set is computed before the row is
    # mutated, so applying it after the create would drop the new address).
    # Per-RR semantics are order-independent, which is what this path needs.
    return {
        "name": rec.name,
        "type": rec.record_type,
        "value": rec.value,
        "ttl": rec.ttl,
        "rrset_action": "delete_value",
    }


async def _delete_pool_record(db: AsyncSession, zone: DNSZone, rec: DNSRecord) -> None:
    snapshot = _delete_snapshot(rec)
    target_serial = bump_zone_serial(zone)
    await db.delete(rec)
    # Only this row. A bare ``flush()`` would also write a pending delete-orphan
    # member's DELETE in the same unit of work, in no defined order against
    # this one: the member first lets the FK cascade take this row, and the
    # ORM's own DELETE then matches nothing (#1966).
    await db.flush([rec])
    await enqueue_record_op(db, zone, "delete", snapshot, target_serial=target_serial)


def _record_payload(pool: DNSPool, member: DNSPoolMember, ttl: int | None) -> dict[str, object]:
    # ``add`` semantics — pool members are explicitly multi-RR (every
    # healthy member contributes its own A record at the same name).
    # The default RFC 2136 ``replace`` would clobber siblings on every
    # create, so the BIND9 driver only ever has one record live at the
    # pool's name regardless of how many members exist.
    # Setting it also opts these ops out of #773's whole-RRset stamping, which
    # is deliberate — see ``_delete_pool_record`` for why per-RR semantics are
    # the right shape for the delete-then-create pair this module emits.
    return {
        "name": pool.record_name,
        "type": pool.record_type,
        "value": member.address,
        "ttl": ttl,
        "rrset_action": "add",
    }

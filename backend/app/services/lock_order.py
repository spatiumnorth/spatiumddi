"""The row-lock order across DHCP leases, IPAM mirrors and DNS zones (#3617).

The lease path writes three kinds of shared row, and several transactions
write them at once: an agent's lease-events batch, the expiry sweep, the
agentless lease pull, a subnet / scope / server delete, and any IPAM edit that
publishes DNS. Two of them that take the same rows in different orders
deadlock (40P01), and Postgres answers one of them with a 500. So every one of
them takes its locks in ONE order:

1. ``dhcp_lease`` rows, ascending ``id``;
2. ``ip_address`` rows (the lease mirrors and any other address the work
   touches), ascending ``id``;
3. ``dns_zone`` rows, ascending ``id``, forward and reverse alike. A DNS
   write bumps its zone's serial, an UPDATE that holds the zone row until
   commit, so "locking a zone" and "writing a record into it" are the same
   event as far as other writers are concerned;
4. the audit-chain advisory lock, at commit (#3389, #3503 — see
   ``app.services.audit_chain.LOCKED_BEFORE_AUDIT_TABLES``).

A zone's **sync gate** (#3724, :func:`lock_zone_gate`) comes before all four:
a transaction-scoped advisory lock per zone, shared by a long writer that
commits in batches (the IPAM -> DNS auto-sync) and exclusive for a permanent
zone delete. A taker holds no row lock when it takes the gate, and takes
several gates in ascending key order, so it can never be waited on by a
transaction that holds a row and wants a gate. Its purpose is fairness, not
exclusion: Postgres queues a new shared request behind a waiting exclusive
one, so a delete waiting for one batch's rows is not overtaken by the next
batch at the commit boundary (which had it wait a second whole batch).
Any new taker must take the gate before its first row lock, or it creates a
cycle; so a writer that deletes several zones one after another in one
transaction (the trash sweep, a subnet purge's reverse zones) takes none.

Why this order: it is the one the hottest writer already had. A lease-events
batch upserts its lease rows first (one flush, which writes the rows of one
mapper in primary-key order), then locks the mirror rows ``FOR UPDATE`` by id
(#2580, #3601), then publishes DDNS, and takes the chain lock at commit. The
expiry sweep was brought to the same order in #3605. What was left (#3617):

* the agentless lease pull interleaved lease, mirror and DDNS work per lease,
  in wire order — it now locks the server's lease rows by id, then the mirror
  rows by id, then the zones, before any of them is written;
* a subnet soft-delete revoked and deleted the mirrors before it purged the
  scope's leases — it now locks the leases first;
* a DDNS revoke retracts the PTR before the forward record (#1800), so it
  took the reverse zone first, while a DDNS publish took the forward zone
  first: two DDNS writes on different addresses of one forward / reverse zone
  pair deadlocked. ``_sync_dns_record`` now locks every zone it may write, in
  id order, before it writes any (:func:`lock_zones_for_sync`), and a writer
  that syncs many addresses in one transaction locks the union of their zones
  up front (:func:`lock_zones_for_addresses`), since locking per address
  would still take them out of id order across addresses.

Each step is one ``SELECT ... ORDER BY id FOR [NO KEY] UPDATE`` (chunked for a
big set, the chunks ascending), so two transactions that lock overlapping rows
of one table cannot each hold a row the other wants, and a transaction never
waits for a table earlier in the list while it holds a later one. A row
already held is locked again for free. Zone rows are taken ``FOR NO KEY
UPDATE``, the lock the serial-bump UPDATE takes anyway: a concurrent record
insert's foreign-key check (``FOR KEY SHARE`` on its zone) is not blocked by
it.

A scope's **gate** (#3748, :func:`lock_scope_gates`) sits beside it at step 0,
ahead of the zone gate: shared for a lease-events batch, exclusive for every
delete that takes scope rows ``FOR UPDATE`` or deletes them — the scope delete,
and the subnet, block and space deletes, for every live scope their cascade
reaches (soft: before ``_lock_scope_batch_rows``; a permanent subnet delete:
before its lease rows). It exists because Postgres lets a new ``FOR KEY
SHARE`` join while another is held even when a ``FOR UPDATE`` is queued, so a
Kea HA pair's overlapping batches starved the delete past the command timeout;
a new shared advisory request does queue behind a waiting exclusive one. Taken
in ascending key order, as each transaction's first lock (the deletes compute
their scope ids with plain reads), by takers none of which takes a zone gate,
with no row lock held that the other side waits for (a batch has inserted its
ingest receipt, which no delete touches). A scope edit needs no gate: its
UPDATE changes no key column, so it takes the row ``FOR NO KEY UPDATE``, which
a ``FOR KEY SHARE`` does not block. A DHCP server-group delete needs none
either: it refuses a group that still has servers, so no agent can post a
batch for its scopes. Any new delete that takes scope rows ``FOR UPDATE`` must
take their gates exclusive before its first row lock.

A scope row (``dhcp_scope``) sits between steps 1 and 2 for the lease writers
that must not write into a scope in the Trash and the delete that puts it there
(#3733). A lease-events batch holds the scopes its events resolve to ``FOR KEY
SHARE`` after its lease rows, and reads them again there. A scope soft-delete
(and a subnet / block / space soft-delete, for every scope its cascade reaches,
ascending id, #3744) takes its scope row ``FOR UPDATE`` before anything it
writes, takes no lease row in that transaction, and tears the scope's leases
down after its commit, one batch per transaction, each batch in the order
above. So the stamp waits for a batch that already holds the scope, and a
later batch waits for the stamp and finds the scope in the Trash.
Each teardown batch also reads its scope row ``FOR SHARE`` after its lease
rows and holds it to its commit (#3777), so a Trash restore (an UPDATE of
``deleted_at``) waits for the batch in flight and the next batch finds the
scope live. After the lease rows, not before: a Trash purge locks the scope's
lease rows and then deletes the scope row, which a batch holding the scope
while it waited for those leases would deadlock with. The restore locks the
scope rows it un-stamps (``FOR NO KEY UPDATE``, ascending id) before the zones
it writes (#3627), since the batch goes on from the scope to its mirrors'
zones. ``FOR SHARE`` and ``FOR NO KEY UPDATE`` both leave a lease-events
batch's ``FOR KEY SHARE`` alone.

``tests/_row_lock_order_guard.py`` asserts the order for the whole test suite.
"""

from __future__ import annotations

import ipaddress
import uuid
import zlib
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

# Bind parameters per lock statement; asyncpg refuses more than 32,767.
_CHUNK = 1000


async def lock_lease_rows(db: AsyncSession, *conds: Any) -> list[uuid.UUID]:
    """Step 1: lock the matching ``dhcp_lease`` rows, ascending id."""
    from app.models.dhcp import DHCPLease  # noqa: PLC0415

    return list(
        (
            await db.execute(
                select(DHCPLease.id).where(*conds).order_by(DHCPLease.id).with_for_update()
            )
        )
        .scalars()
        .all()
    )


async def lock_mirror_rows(
    db: AsyncSession, keys: set[tuple[Any, str]], *, chunk: int = _CHUNK
) -> list[Any]:
    """Step 2 for lease mirrors: the ``auto_from_lease`` rows at ``keys``
    ((subnet id, normalised address)), row-locked in ascending id order, with
    their subnets loaded.

    The ids are read first and locked in ascending chunks, which keeps the
    whole lock order ascending however many chunks it takes (#3605). A row
    that stopped matching in between (taken over by a reservation, say) is
    dropped by the locked read; one created in between is not returned.
    """
    from sqlalchemy.orm import selectinload  # noqa: PLC0415

    from app.models.ipam import IPAddress  # noqa: PLC0415
    from app.services.dhcp.normalize import norm_ip  # noqa: PLC0415

    by_subnet: dict[Any, list[str]] = {}
    for subnet_id, address in keys:
        by_subnet.setdefault(subnet_id, []).append(address)
    ids: set[Any] = set()
    for subnet_id, addresses in by_subnet.items():
        addresses.sort()
        for i in range(0, len(addresses), chunk):
            id_res = await db.execute(
                select(IPAddress.id).where(
                    IPAddress.subnet_id == subnet_id,
                    IPAddress.address.in_(addresses[i : i + chunk]),
                    IPAddress.auto_from_lease.is_(True),
                )
            )
            ids.update(id_res.scalars().all())
    ordered = sorted(ids)
    rows: list[Any] = []
    for i in range(0, len(ordered), chunk):
        res = await db.execute(
            select(IPAddress)
            .where(
                IPAddress.id.in_(ordered[i : i + chunk]),
                IPAddress.auto_from_lease.is_(True),
            )
            .options(selectinload(IPAddress.subnet))
            .order_by(IPAddress.id)
            .with_for_update(of=IPAddress)
            .execution_options(populate_existing=True)
        )
        rows.extend(
            r for r in res.scalars().all() if (r.subnet_id, norm_ip(str(r.address))) in keys
        )
    return rows


#: Advisory-lock namespace of the per-zone sync gate (#3724), "ZSYN".
ZONE_SYNC_GATE_NS = 0x5A53594E


def _zone_gate_key(zone_id: Any) -> int:
    """Signed 32-bit crc32 of the zone id: the second int of the gate's key."""
    key = zlib.crc32(str(zone_id).encode("utf-8"))
    return key - 2**32 if key >= 2**31 else key


async def lock_zone_gate(db: AsyncSession, zone_ids: Iterable[Any], *, exclusive: bool) -> None:
    """Step 0 (#3724): take the sync gate of each zone in ``zone_ids``, shared
    (a batch writer) or ``exclusive`` (a permanent zone delete), in ascending
    key order, to the end of the transaction. Call it before any row lock.
    Two zones whose ids collide on the crc32 share a gate, which only costs a
    wait."""
    fn = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
    for key in sorted({_zone_gate_key(z) for z in zone_ids if z is not None}):
        await db.execute(text(f"SELECT {fn}(:ns, :key)"), {"ns": ZONE_SYNC_GATE_NS, "key": key})


#: Advisory-lock namespace of the per-scope gate (#3748), "DSCP".
SCOPE_GATE_NS = 0x44534350


def _scope_gate_key(scope_id: Any) -> int:
    """Signed 32-bit crc32 of the scope id: the second int of the gate's key."""
    key = zlib.crc32(str(scope_id).encode("utf-8"))
    return key - 2**32 if key >= 2**31 else key


async def lock_scope_gates(db: AsyncSession, scope_ids: Iterable[Any], *, exclusive: bool) -> None:
    """Step 0 (#3748): take the gate of each scope in ``scope_ids``, shared
    (a lease-events batch) or ``exclusive`` (a delete that takes the scope row
    ``FOR UPDATE``), in ascending key order, to the end of the transaction.
    Call it before any row lock, and before :func:`lock_zone_gate` when a
    transaction takes both (none does today).

    A batch holds its scope ``FOR KEY SHARE`` and Postgres lets a new KEY
    SHARE join while another is held, even with a ``FOR UPDATE`` queued, so
    two agents (a Kea HA pair) posting overlapping batches kept the delete
    waiting until the 30 s command timeout. Advisory locks queue a new shared
    request behind a waiting exclusive one, so the delete waits only for the
    batches already running. Two scopes whose ids collide on the crc32 share a
    gate, which only costs a wait."""
    fn = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
    for key in sorted({_scope_gate_key(s) for s in scope_ids if s is not None}):
        await db.execute(text(f"SELECT {fn}(:ns, :key)"), {"ns": SCOPE_GATE_NS, "key": key})


async def lock_zone_rows(db: AsyncSession, zone_ids: Iterable[Any]) -> None:
    """Step 3: lock the ``dns_zone`` rows in ``zone_ids``, ascending id.

    A soft-deleted zone is locked too: its restore un-stamps it, and a record
    retraction may still bump its serial."""
    from app.models.dns import DNSZone  # noqa: PLC0415

    ordered = sorted({z for z in zone_ids if z is not None})
    for i in range(0, len(ordered), _CHUNK):
        await db.execute(
            select(DNSZone.id)
            .where(DNSZone.id.in_(ordered[i : i + _CHUNK]))
            .order_by(DNSZone.id)
            .with_for_update(key_share=True)
            # ``lock_order`` lets the test-suite guard tell a pre-lock from
            # a lock taken for another reason (tests/_row_lock_order_guard.py).
            .execution_options(include_deleted=True, lock_order="zone_prelock")
        )


async def address_ids_of_zones(db: AsyncSession, zone_ids: Iterable[Any]) -> set[Any]:
    """The ``ip_address`` rows a delete of ``zone_ids`` rewrites, unlocked.

    ``ip_address.forward_zone_id`` / ``reverse_zone_id`` reference ``dns_zone``
    and ``ip_address.dns_record_id`` references ``dns_record``, all ``ON DELETE
    SET NULL``: deleting a zone (and with it, its records) locks every such
    row. Records in the trash and rows in the trash are included."""
    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.models.ipam import IPAddress  # noqa: PLC0415

    zones = sorted({z for z in zone_ids if z is not None})
    found: set[Any] = set()
    for i in range(0, len(zones), _CHUNK):
        chunk = zones[i : i + _CHUNK]
        record_ids = (
            select(DNSRecord.id)
            .where(DNSRecord.zone_id.in_(chunk))
            .execution_options(include_deleted=True)
            .scalar_subquery()
        )
        res = await db.execute(
            select(IPAddress.id)
            .where(
                IPAddress.dns_record_id.in_(record_ids)
                | IPAddress.forward_zone_id.in_(chunk)
                | IPAddress.reverse_zone_id.in_(chunk)
            )
            .execution_options(include_deleted=True)
        )
        found.update(res.scalars().all())
    return found


async def address_ids_of_records(db: AsyncSession, record_ids: Iterable[Any]) -> set[Any]:
    """The ``ip_address`` rows a delete of the ``dns_record`` rows
    ``record_ids`` rewrites (``dns_record_id`` is ``ON DELETE SET NULL``),
    unlocked."""
    from app.models.ipam import IPAddress  # noqa: PLC0415

    records = sorted({r for r in record_ids if r is not None})
    found: set[Any] = set()
    for i in range(0, len(records), _CHUNK):
        res = await db.execute(
            select(IPAddress.id)
            .where(IPAddress.dns_record_id.in_(records[i : i + _CHUNK]))
            .execution_options(include_deleted=True)
        )
        found.update(res.scalars().all())
    return found


async def _lock_address_ids(db: AsyncSession, ids: Iterable[Any], *, nowait: bool = False) -> None:
    """Lock ``ip_address`` rows by id, ascending, ``FOR NO KEY UPDATE`` (the
    lock the foreign key's ``SET NULL`` takes). A row deleted meanwhile is
    skipped. ``nowait`` raises ``lock_not_available`` (55P03) instead of
    waiting for a row another transaction holds."""
    from app.models.ipam import IPAddress  # noqa: PLC0415

    ordered = sorted(set(ids))
    for i in range(0, len(ordered), _CHUNK):
        await db.execute(
            select(IPAddress.id)
            .where(IPAddress.id.in_(ordered[i : i + _CHUNK]))
            .order_by(IPAddress.id)
            .with_for_update(key_share=True, nowait=nowait)
            .execution_options(include_deleted=True)
        )


async def lock_address_rows(db: AsyncSession, ids: Iterable[Any]) -> list[Any]:
    """Step 2 for a writer that knows its address rows up front (#3724): lock
    ``ids`` ``FOR NO KEY UPDATE``, ascending id, before it takes any zone.

    A zone delete locks the rows it detaches before the zone (#3691), so a
    writer that took a zone first and wrote an address later (the IPAM -> DNS
    auto-sync, one ``_sync_dns_record`` per row) deadlocked with it."""
    ordered = sorted(set(ids))
    await _lock_address_ids(db, ordered)
    return ordered


async def lock_addresses_of_zones(db: AsyncSession, zone_ids: Iterable[Any]) -> list[Any]:
    """Step 2 for a zone delete: lock the ``ip_address`` rows a delete of
    ``zone_ids`` would rewrite (:func:`address_ids_of_zones`), ascending id,
    BEFORE the zone rows (#3691). Taken after the zone row, by the foreign
    key, that is step 3 before step 2, and a lease batch holding a mirror and
    waiting for the zone deadlocks with it.

    It takes no sync gate (#3724): the trash sweep purges many zones in one
    transaction, each after the last one's rows, so a gate here would be
    taken after a row lock, and in the sweep's order rather than by key. A
    caller that deletes one zone and holds nothing yet takes the gate itself
    first (the Trash page's permanent delete)."""
    ids = await address_ids_of_zones(db, zone_ids)
    await _lock_address_ids(db, ids)
    return sorted(ids)


#: Tries :func:`lock_addresses_before` makes before it waits for a late row.
_LATE_ROW_ATTEMPTS = 5


def _lock_not_available(exc: DBAPIError) -> bool:
    return getattr(exc.orig, "sqlstate", None) == "55P03"


async def lock_addresses_before[T](
    db: AsyncSession,
    find_ids: Callable[[], Awaitable[set[Any]]],
    take: Callable[[], Awaitable[T]],
) -> T:
    """Lock the ``ip_address`` rows ``find_ids`` names, ascending id, then run
    ``take`` (which locks the zone row), and return what it returns (#3691).

    A delete of a zone or of records rewrites the address rows linked to it
    through ``ON DELETE SET NULL`` foreign keys, which locks them after the
    zone row unless they are locked first. A row linked between the first
    lock and ``take`` (by a writer that held the zone row, so the link was
    not visible yet) is still taken after the zone. It is locked ``NOWAIT``:
    if a lease batch has it and waits for the zone, the work is rolled back
    to a savepoint, which releases the zone row, and tried again with the row
    now in the first pass. The last try waits instead of retrying.

    No row can be linked to the zone while ``take``'s lock is held: every
    writer that links an address to a zone or to one of its records takes the
    zone row first (``lock_zones_for_sync``), or its foreign-key check on
    ``forward_zone_id`` / ``reverse_zone_id`` waits for a ``FOR UPDATE``.
    """
    for attempt in range(_LATE_ROW_ATTEMPTS):
        last = attempt == _LATE_ROW_ATTEMPTS - 1
        try:
            async with db.begin_nested():
                held = await find_ids()
                await _lock_address_ids(db, held)
                result = await take()
                await _lock_address_ids(db, await find_ids() - held, nowait=not last)
            return result
        except DBAPIError as exc:
            if last or not _lock_not_available(exc):
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _uuid_or_none(raw: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(raw))
    except (ValueError, TypeError):
        return None


async def _published_zone_ids(db: AsyncSession, ip_ids: list[Any]) -> set[Any]:
    """The zones holding an auto-generated record of any of ``ip_ids``, live or
    trashed.

    The trashed ones count (#3687): the writers that purge an address's
    trashed records (``purge_trashed_address_records``) delete them in
    whatever zone they sit, and a permanent zone delete takes the zone row
    before it deletes that zone's records, trashed ones included. A purge
    that ran before its zone was locked would hold the record and then wait
    for the zone, the reverse of the delete."""
    from app.models.dns import DNSRecord  # noqa: PLC0415

    found: set[Any] = set()
    ids = sorted({i for i in ip_ids if i is not None})
    for i in range(0, len(ids), _CHUNK):
        found.update(
            (
                await db.execute(
                    select(DNSRecord.zone_id)
                    .where(
                        DNSRecord.ip_address_id.in_(ids[i : i + _CHUNK]),
                        DNSRecord.auto_generated.is_(True),
                    )
                    .distinct()
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
    return found


async def _publish_zone_ids(
    db: AsyncSession,
    ip: Any,
    subnet: Any,
    zone_id: Any,
    subnet_cache: dict[Any, set[Any] | None],
    ddns: bool,
) -> set[Any]:
    """The zones a create / update sync of ``ip`` may write besides the ones
    already holding its records: the forward zone (``zone_id``, else the
    subnet's effective one, else the row's own), the extras, and the reverse
    zone covering the address.

    The reverse zone is resolved only for a row that has none yet: the one it
    has published into is the one it keeps. (A reverse-zone re-layout that
    moves an address's PTR is the case this leaves to the write itself.)

    With ``ddns`` (a lease batch, whose publish passes the subnet's DDNS
    override zone as ``zone_id``, #428): the override zone too, and nothing
    at all for a subnet with DDNS off, where the publish writes nothing."""
    from app.api.v1.ipam.router import (  # noqa: PLC0415
        _resolve_effective_zone,
        _resolve_reverse_zone,
    )
    from app.services.dns.ddns import (  # noqa: PLC0415
        _resolve_override_zone_id,
        resolve_effective_ddns,
    )

    if subnet is not None and subnet.id not in subnet_cache:
        eff = await resolve_effective_ddns(db, subnet) if ddns else None
        if eff is not None and not eff.enabled:
            subnet_cache[subnet.id] = None
        else:
            zones = {await _resolve_effective_zone(db, subnet)}
            if eff is not None:
                zones.add(await _resolve_override_zone_id(db, eff.domain_override))
            subnet_cache[subnet.id] = zones
    subnet_zones = subnet_cache.get(subnet.id) if subnet is not None else set()
    if subnet_zones is None:
        return set()
    found: set[Any] = {ip.reverse_zone_id}
    hostname = (ip.hostname or "").strip()
    if ddns or (hostname and hostname != "gateway"):
        # A blank name only retracts what is published (the zones above it),
        # and the gateway placeholder writes no forward record. Neither
        # writes a forward zone, so neither locks one: a subnet create syncs
        # its gateway after auditing the reverse zone it made, and a lock
        # taken after the audit-chain lock deadlocks against a record create
        # (#3503). A lease publish (``ddns``) names the row itself first.
        found |= {ip.forward_zone_id, zone_id}
        if zone_id is None:
            found |= subnet_zones
        found.update(_uuid_or_none(raw) for raw in ip.extra_zone_ids or [])
    if subnet is not None and ip.reverse_zone_id is None:
        try:
            addr = ipaddress.ip_address(str(ip.address))
        except ValueError:
            addr = None
        if addr is not None:
            rev = await _resolve_reverse_zone(db, subnet, addr)
            if rev is not None:
                found.add(rev.id)
    return found


async def lock_zones_for_sync(
    db: AsyncSession,
    ip: Any,
    subnet: Any,
    *,
    zone_id: Any = None,
    action: str = "create",
) -> None:
    """Lock every zone one ``_sync_dns_record`` of ``ip`` may write, in id order.

    A retraction writes only the zones holding the address's records; a
    publish may also write its forward, extra and reverse zones. Locking a
    zone that ends up unwritten costs only the wait a writer to it would have
    had anyway."""
    if action == "delete":
        await lock_zones_for_addresses(db, retracting=[ip])
    else:
        await lock_zones_for_addresses(db, publishing=[(subnet, ip)], zone_id=zone_id)


async def zone_ids_for_addresses(
    db: AsyncSession,
    *,
    publishing: Iterable[tuple[Any, Any]] = (),
    retracting: Iterable[Any] = (),
    zone_id: Any = None,
    ddns: bool = False,
    extra_zone_ids: Iterable[Any] = (),
) -> set[Any]:
    """Every zone the DNS syncs of a unit of work may write (read-only): a
    publish of each ``(subnet, ip_row)`` in ``publishing``, a retraction of
    each row in ``retracting``, and ``extra_zone_ids`` (the zones of records
    the work deletes outright, #3724). ``ddns`` adds each subnet's DDNS
    override zone, which a lease publish writes into instead of the subnet's
    own (#428)."""
    pub = [(subnet, ip) for subnet, ip in publishing if ip is not None]
    rows = [ip for ip in retracting if ip is not None] + [ip for _subnet, ip in pub]
    zones = {z for z in extra_zone_ids if z is not None}
    if not rows:
        return zones
    zones |= await _published_zone_ids(db, [ip.id for ip in rows])
    subnet_cache: dict[Any, set[Any] | None] = {}
    for subnet, ip in pub:
        zones |= await _publish_zone_ids(db, ip, subnet, zone_id, subnet_cache, ddns)
    return zones


async def lock_zones_for_addresses(
    db: AsyncSession,
    *,
    publishing: Iterable[tuple[Any, Any]] = (),
    retracting: Iterable[Any] = (),
    zone_id: Any = None,
    ddns: bool = False,
    extra_zone_ids: Iterable[Any] = (),
) -> None:
    """Lock, in one id-ordered pass, every zone the DNS syncs of a unit of
    work may write (:func:`zone_ids_for_addresses`).

    For a transaction that syncs several addresses (a lease batch, the
    sweep): each sync locks its own zones in order, but one address's zones
    after another's are not in id order between them, so a writer taking the
    same zones for its own addresses in another order could still wait in a
    cycle."""
    zones = await zone_ids_for_addresses(
        db,
        publishing=publishing,
        retracting=retracting,
        zone_id=zone_id,
        ddns=ddns,
        extra_zone_ids=extra_zone_ids,
    )
    if zones:
        await lock_zone_rows(db, zones)


async def _mirror_zone_and_address_ids(
    db: AsyncSession, lease_ids: list[Any]
) -> tuple[set[Any], set[Any]]:
    """(zone ids, ``ip_address`` ids) a teardown of the mirrors at
    ``lease_ids``' addresses writes: the zones holding an auto-generated
    record, live or trashed, of such a mirror, and the mirrors plus every
    address linked to one of those records (``dns_record_id``)."""
    from app.models.dhcp import DHCPLease  # noqa: PLC0415
    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.models.ipam import IPAddress  # noqa: PLC0415

    zones: set[Any] = set()
    addrs: set[Any] = set()
    records: set[Any] = set()
    for i in range(0, len(lease_ids), _CHUNK):
        chunk = lease_ids[i : i + _CHUNK]
        mirrors = (
            select(IPAddress.id)
            .join(DHCPLease, DHCPLease.ip_address == IPAddress.address)
            .where(DHCPLease.id.in_(chunk), IPAddress.auto_from_lease.is_(True))
            .execution_options(include_deleted=True)
        )
        addrs.update((await db.execute(mirrors)).scalars().all())
        for zone_id, record_id in (
            await db.execute(
                select(DNSRecord.zone_id, DNSRecord.id)
                .join(IPAddress, IPAddress.id == DNSRecord.ip_address_id)
                .join(DHCPLease, DHCPLease.ip_address == IPAddress.address)
                .where(
                    DHCPLease.id.in_(chunk),
                    IPAddress.auto_from_lease.is_(True),
                    DNSRecord.auto_generated.is_(True),
                )
                .execution_options(include_deleted=True)
            )
        ).all():
            zones.add(zone_id)
            records.add(record_id)
    addrs |= await address_ids_of_records(db, records)
    return zones, addrs


async def lock_zones_for_lease_mirrors(db: AsyncSession, lease_ids: Iterable[Any]) -> None:
    """Lock, in one id-ordered pass, every zone holding an auto-generated
    record, live or trashed, of the lease mirror at any of ``lease_ids``'
    addresses (#3687) — after the ``ip_address`` rows that teardown writes:
    the mirrors and the addresses linked to the records it deletes (``dns_record_id``
    is ``ON DELETE SET NULL``), ascending id (#3690). A permanent zone
    delete locks those address rows before its zone row (#3691), so a
    teardown holding the zone and then writing an address would deadlock
    with it.

    For a unit of work that tears the mirrors down lease by lease (a DHCP
    server delete) and so purges their trashed records in any zone before it
    reaches a later lease's live zones. Matched on address alone: a zone
    locked for an address the lease's own subnet does not hold costs only
    the wait a writer to it would have had anyway."""
    ids = sorted({i for i in lease_ids if i is not None})
    if not ids:
        return

    async def find() -> set[Any]:
        return (await _mirror_zone_and_address_ids(db, ids))[1]

    async def take() -> None:
        await lock_zone_rows(db, (await _mirror_zone_and_address_ids(db, ids))[0])

    await lock_addresses_before(db, find, take)


async def zone_ids_for_subnets(db: AsyncSession, subnet_ids: Iterable[Any]) -> set[Any]:
    """The zones a write over ``subnet_ids`` may touch: the zones holding a
    record of any of their addresses (the lease mirrors' DDNS, the subnet's own
    A / PTR) and the reverse zones the subnets are linked to."""
    from app.models.dns import DNSRecord, DNSZone  # noqa: PLC0415
    from app.models.ipam import IPAddress  # noqa: PLC0415

    ids = sorted({s for s in subnet_ids if s is not None})
    zones: set[Any] = set()
    for i in range(0, len(ids), _CHUNK):
        chunk = ids[i : i + _CHUNK]
        zones.update(
            (
                await db.execute(
                    select(DNSRecord.zone_id)
                    .where(
                        DNSRecord.ip_address_id.in_(
                            select(IPAddress.id).where(IPAddress.subnet_id.in_(chunk))
                        )
                    )
                    .distinct()
                )
            )
            .scalars()
            .all()
        )
        zones.update(
            (await db.execute(select(DNSZone.id).where(DNSZone.linked_subnet_id.in_(chunk))))
            .scalars()
            .all()
        )
    return zones


async def zone_ids_for_scope_statics(db: AsyncSession, scope_ids: Iterable[Any]) -> set[Any]:
    """The zones a restore of ``scope_ids`` publishes their reservations into.

    A soft-delete of a scope (or of its subnet) deletes each reservation's
    address row and its A / PTR records, and the restore re-creates them
    (``remirror_scope_statics``), so no record names the zones yet and
    :func:`zone_ids_for_subnets` cannot find them. They are resolved the way
    the re-mirror's own sync resolves them: ``_publish_zone_ids`` over a
    transient row at each reservation's address, so the forward zone, the
    extras and the reverse zone are the ones the publish will lock. Reads
    include the trashed reservations, which are un-stamped later.

    A row already at the address (a scope trashed on its own leaves its subnet
    live, and the address may have been allocated meanwhile) is taken over by
    the re-mirror, which publishes into that row's own forward zone and keeps
    its reverse zone: its zones are added too."""
    from app.models.dhcp import DHCPScope, DHCPStaticAssignment  # noqa: PLC0415
    from app.models.ipam import IPAddress, Subnet  # noqa: PLC0415
    from app.services.dhcp.normalize import norm_ip  # noqa: PLC0415

    ids = sorted({s for s in scope_ids if s is not None})
    zones: set[Any] = set()
    subnet_cache: dict[Any, set[Any] | None] = {}
    subnets: dict[Any, Any] = {}
    for i in range(0, len(ids), _CHUNK):
        chunk = ids[i : i + _CHUNK]
        scopes = (
            (
                await db.execute(
                    select(DHCPScope)
                    .where(DHCPScope.id.in_(chunk))
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
        by_id = {sc.id: sc for sc in scopes}
        incumbents = {
            (row.subnet_id, norm_ip(str(row.address))): row
            for row in (
                await db.execute(
                    select(IPAddress)
                    .where(IPAddress.subnet_id.in_({sc.subnet_id for sc in scopes}))
                    .where(
                        IPAddress.address.in_(
                            select(DHCPStaticAssignment.ip_address)
                            .where(DHCPStaticAssignment.scope_id.in_(chunk))
                            .execution_options(include_deleted=True)
                        )
                    )
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        }
        statics = (
            (
                await db.execute(
                    select(DHCPStaticAssignment)
                    .where(DHCPStaticAssignment.scope_id.in_(chunk))
                    .execution_options(include_deleted=True)
                )
            )
            .scalars()
            .all()
        )
        for st in statics:
            scope = by_id.get(st.scope_id)
            if scope is None:
                continue
            if scope.subnet_id not in subnets:
                subnets[scope.subnet_id] = (
                    await db.execute(
                        select(Subnet)
                        .where(Subnet.id == scope.subnet_id)
                        .execution_options(include_deleted=True)
                    )
                ).scalar_one_or_none()
            subnet = subnets[scope.subnet_id]
            if subnet is None:
                continue
            # Never added to the session: built only to be read.
            row = incumbents.get((subnet.id, norm_ip(str(st.ip_address))))
            ip = IPAddress(
                subnet_id=subnet.id,
                address=str(st.ip_address),
                hostname=(st.hostname or "").strip(),
                status="static_dhcp",
                forward_zone_id=row.forward_zone_id if row is not None else None,
                reverse_zone_id=row.reverse_zone_id if row is not None else None,
                extra_zone_ids=list(row.extra_zone_ids or []) if row is not None else [],
            )
            zones |= await _publish_zone_ids(db, ip, subnet, None, subnet_cache, False)
    zones.discard(None)
    return zones


async def lock_zones_for_subnets(db: AsyncSession, subnet_ids: Iterable[Any]) -> None:
    """Lock, in one id-ordered pass, every zone a delete of ``subnet_ids`` may
    write: the zones holding a record of any of their addresses (the lease
    mirrors' DDNS, the subnet's own A / PTR, which a soft-delete retracts),
    and the reverse zones the subnets are linked to (retired or re-linked).

    The subnets' address rows that carry a record or a mirror are locked
    first, ascending id (#3690): the retraction rewrites them, and a
    permanent zone delete locks them before the zone row (#3691)."""
    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.models.ipam import IPAddress  # noqa: PLC0415

    sids = sorted({s for s in subnet_ids if s is not None})

    async def find() -> set[Any]:
        found: set[Any] = set()
        for i in range(0, len(sids), _CHUNK):
            found.update(
                (
                    await db.execute(
                        select(IPAddress.id)
                        .where(
                            IPAddress.subnet_id.in_(sids[i : i + _CHUNK]),
                            IPAddress.auto_from_lease.is_(True)
                            | IPAddress.dns_record_id.is_not(None)
                            | IPAddress.id.in_(
                                select(DNSRecord.ip_address_id)
                                .where(DNSRecord.ip_address_id.is_not(None))
                                .execution_options(include_deleted=True)
                            ),
                        )
                        .execution_options(include_deleted=True)
                    )
                )
                .scalars()
                .all()
            )
        return found

    async def take() -> None:
        await lock_zone_rows(db, await zone_ids_for_subnets(db, sids))

    await lock_addresses_before(db, find, take)


__all__ = [
    "lock_lease_rows",
    "lock_mirror_rows",
    "lock_zones_for_subnets",
    "lock_zones_for_lease_mirrors",
    "zone_ids_for_subnets",
    "lock_zone_rows",
    "lock_zones_for_addresses",
    "lock_zones_for_sync",
]

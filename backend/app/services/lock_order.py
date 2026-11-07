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

``tests/_row_lock_order_guard.py`` asserts the order for the whole test suite.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
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


async def lock_addresses_of_zones(db: AsyncSession, zone_ids: Iterable[Any]) -> list[Any]:
    """Step 2 for a zone delete: lock the ``ip_address`` rows a delete of
    ``zone_ids`` would rewrite, ascending id, BEFORE the zone rows (#3691).

    ``ip_address.forward_zone_id`` / ``reverse_zone_id`` reference ``dns_zone``
    and ``ip_address.dns_record_id`` references ``dns_record``, all ``ON DELETE
    SET NULL``: deleting a zone (and with it, its records) locks every such
    row. Taken after the zone row, that is step 3 before step 2, and a lease
    batch holding a mirror and waiting for the zone deadlocks with it. Records
    in the trash and rows in the trash are included. The caller re-runs this
    once it holds the zone rows, to take any row linked in between (it is then
    out of order, but only a row nobody held when the first pass ran).
    """
    from app.models.dns import DNSRecord  # noqa: PLC0415
    from app.models.ipam import IPAddress  # noqa: PLC0415

    zones = sorted({z for z in zone_ids if z is not None})
    if not zones:
        return []
    locked: set[Any] = set()
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
            .order_by(IPAddress.id)
            .with_for_update(key_share=True, of=IPAddress)
            .execution_options(include_deleted=True)
        )
        locked.update(res.scalars().all())
    return sorted(locked)


def _uuid_or_none(raw: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(raw))
    except (ValueError, TypeError):
        return None


async def _published_zone_ids(db: AsyncSession, ip_ids: list[Any]) -> set[Any]:
    """The zones holding an auto-generated record of any of ``ip_ids``."""
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


async def lock_zones_for_addresses(
    db: AsyncSession,
    *,
    publishing: Iterable[tuple[Any, Any]] = (),
    retracting: Iterable[Any] = (),
    zone_id: Any = None,
    ddns: bool = False,
) -> None:
    """Lock, in one id-ordered pass, every zone the DNS syncs of a unit of
    work may write: a publish of each ``(subnet, ip_row)`` in ``publishing``
    and a retraction of each row in ``retracting``.

    For a transaction that syncs several addresses (a lease batch, the
    sweep): each sync locks its own zones in order, but one address's zones
    after another's are not in id order between them, so a writer taking the
    same zones for its own addresses in another order could still wait in a
    cycle. ``ddns`` adds each subnet's DDNS override zone, which a lease
    publish writes into instead of the subnet's own (#428)."""
    pub = [(subnet, ip) for subnet, ip in publishing if ip is not None]
    rows = [ip for ip in retracting if ip is not None] + [ip for _subnet, ip in pub]
    if not rows:
        return
    zones = await _published_zone_ids(db, [ip.id for ip in rows])
    subnet_cache: dict[Any, set[Any] | None] = {}
    for subnet, ip in pub:
        zones |= await _publish_zone_ids(db, ip, subnet, zone_id, subnet_cache, ddns)
    await lock_zone_rows(db, zones)


async def lock_zones_for_subnets(db: AsyncSession, subnet_ids: Iterable[Any]) -> None:
    """Lock, in one id-ordered pass, every zone a delete of ``subnet_ids`` may
    write: the zones holding a record of any of their addresses (the lease
    mirrors' DDNS, the subnet's own A / PTR, which a soft-delete retracts),
    and the reverse zones the subnets are linked to (retired or re-linked)."""
    from app.models.dns import DNSRecord, DNSZone  # noqa: PLC0415
    from app.models.ipam import IPAddress  # noqa: PLC0415

    ids = sorted({s for s in subnet_ids if s is not None})
    if not ids:
        return
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
    await lock_zone_rows(db, zones)


__all__ = [
    "lock_lease_rows",
    "lock_mirror_rows",
    "lock_zones_for_subnets",
    "lock_zone_rows",
    "lock_zones_for_addresses",
    "lock_zones_for_sync",
]

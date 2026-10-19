"""Whether a DNS record would duplicate one the zone already holds (#1230).

Two rows describing the same resource record are not harmless clutter. Every
record op carries the whole RRset the server should end up with, built from
the live rows, and a delete used to drop the deleted row's VALUE from it — so
deleting one of two identical rows retracted the record from the server while
the other row still listed it: a wrong DNS answer, with the UI showing a
record nothing serves. ``app.services.dns.rrset`` now drops the deleted ROW
instead, so twins that already exist no longer do that; this module stops new
ones being made by the paths an operator drives (REST create / update / bulk
create, and the Copilot).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSServer, DNSZone


async def find_identical_record(
    db: AsyncSession,
    zone_id: uuid.UUID,
    *,
    view_id: uuid.UUID | None,
    name: str,
    record_type: str,
    value: str,
    priority: int | None,
    weight: int | None,
    port: int | None,
    exclude_id: uuid.UUID | None = None,
) -> DNSRecord | None:
    """A live record identical to the one described, or None.

    Identical means the same view, owner name, type, value and structured
    fields (priority / weight / port). TTL is not part of it: it belongs to
    the RRset, not to a member, which is the line the RRset fold draws too.
    Owner names compare case-insensitively, as DNS does; the value compares
    exactly after trimming, as the fold does. Soft-deleted rows are excluded by
    the session-wide filter, so a record in the trash does not block
    re-creating it.
    """
    stmt = select(DNSRecord).where(
        DNSRecord.zone_id == zone_id,
        DNSRecord.view_id.is_not_distinct_from(view_id),
        func.lower(DNSRecord.name) == name.lower(),
        func.upper(DNSRecord.record_type) == record_type.upper(),
        func.btrim(DNSRecord.value) == value.strip(),
        DNSRecord.priority.is_not_distinct_from(priority),
        DNSRecord.weight.is_not_distinct_from(weight),
        DNSRecord.port.is_not_distinct_from(port),
    )
    if exclude_id is not None:
        stmt = stmt.where(DNSRecord.id != exclude_id)
    return (await db.execute(stmt.limit(1))).scalars().first()


async def zone_target_readings(
    db: AsyncSession, zone_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, tuple[str, bool]]:
    """Per zone, its name and whether a dot-less name target is read RELATIVE
    to it (#2045).

    A PTR target written without its trailing dot means two different things
    depending on the server: BIND9, both Technitium drivers and Windows Path A
    read it as a zone file does (``db1.example.com`` in a reverse zone is
    ``db1.example.com.<zone>.``), while the cloud providers and Windows Path B
    take it as given (see ``targets_are_relative``, #1794). PowerDNS refuses
    the dot-less spelling outright, so it is never served as the absolute
    name either. The reading is relative unless EVERY server in the zone's
    group takes the name as given: one server serving the relative name is a
    wrong answer on that server. A group with no server reads it as BIND9
    does, the default driver.
    """
    from app.services.dns.pull_from_server import targets_are_relative  # noqa: PLC0415

    ids = list(set(zone_ids))
    if not ids:
        return {}
    rows = (
        await db.execute(
            select(DNSZone.id, DNSZone.name, DNSServer.driver, DNSServer.credentials_encrypted)
            .select_from(DNSZone)
            .outerjoin(DNSServer, DNSServer.group_id == DNSZone.group_id)
            .where(DNSZone.id.in_(ids))
        )
    ).all()
    names: dict[uuid.UUID, str] = {}
    relative: dict[uuid.UUID, bool] = {}
    for zid, zname, driver, creds in rows:
        names[zid] = zname
        if driver is None:  # outer join: a group with no server
            relative.setdefault(zid, True)
            continue
        server = SimpleNamespace(driver=driver, credentials_encrypted=creds)
        relative[zid] = relative.get(zid, False) or targets_are_relative(server)
    return {zid: (names[zid], relative[zid]) for zid in names}


def ptr_target_key(value: str, zone_name: str, *, relative: bool) -> str:
    """A PTR target as the zone's servers serve it, for comparison (#2045):
    lower case (DNS names compare case-insensitively) and absolute, with a
    dot-less target expanded against the zone when ``relative``."""
    from app.services.dns.pull_from_server import _normalize_value  # noqa: PLC0415

    return _normalize_value("PTR", value, zone_name, relative_targets=relative)


def describe_identical(existing: DNSRecord) -> str:
    """The refusal message, shared so REST and the Copilot say the same thing."""
    return (
        f"An identical {existing.record_type} record {existing.fqdn} -> "
        f"{existing.value} already exists (id {existing.id}). Deleting either "
        "copy would retract the record from the server while the other still "
        "lists it."
    )

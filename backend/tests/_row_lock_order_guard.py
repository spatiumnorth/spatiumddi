"""Test-time guard: lease → mirror → zone row-lock order (#3617).

``app.services.lock_order`` documents one order for the rows the lease path
shares: ``dhcp_lease`` rows, then ``ip_address`` rows, then ``dns_zone`` rows
(each ascending id), then the audit chain. Two writers that take them in
different orders deadlock. This records, per transaction, every:

* ``dns_zone`` row newly locked while the transaction already holds a zone
  row with a HIGHER id: the forward / reverse zone cycle of #3617, and any
  multi-zone writer that takes its zones one at a time out of order;
* ``dhcp_lease`` row newly locked (written, deleted, or selected ``FOR
  UPDATE``) after the transaction locked an ``ip_address`` row: the
  subnet-delete and lease-pull cycles of #3617;
* zone pre-lock (``lock_zone_rows``) taken after the audit-chain lock, which
  the #3503 guard cannot see because it watches writes only.

``conftest`` fails the test that made one, so a new path cannot reintroduce
the order unseen. A row inserted by the transaction is held from then on but
was never waited for, so an insert neither counts as a lock nor trips a
check; a bulk ``UPDATE`` / ``DELETE`` names no ids, so it counts for the
lease-after-mirror check only.

**Zone ids are made monotonic in the suite.** ``DNSZone.id`` is a random
``uuid4``, so whether a writer that takes two zones in a fixed order takes
them in id order would be a coin toss per test run: a guard on it would be
flaky. ``install`` gives each new zone an id that sorts after every zone made
before it in this process, so the check is deterministic: a writer's order is
compared with the order the test created its zones in. Production ids stay
random; the writers lock in id order whatever the ids are.
"""

from __future__ import annotations

import itertools
import random
import uuid
from typing import Any

from sqlalchemy import Delete, Select, Update, event
from sqlalchemy.orm import Session, SessionTransaction

from app.models.dhcp import DHCPLease
from app.models.dns import DNSZone
from app.models.ipam import IPAddress
from tests._audit_lock_order_guard import _LOCKED as _AUDIT_LOCKED
from tests._audit_lock_order_guard import _OWN_DIRS, _app_stack, _caller_frames

_ZONES = "_row_lock_guard_zones"
_OWN_ZONES = "_row_lock_guard_own_zones"
_LEASES = "_row_lock_guard_leases"
_MIRROR = "_row_lock_guard_mirror"

_ZONE, _LEASE, _MIRROR_TABLE = "dns_zone", "dhcp_lease", "ip_address"
_TABLES = {DNSZone: _ZONE, DHCPLease: _LEASE, IPAddress: _MIRROR_TABLE}

#: Entry points known to take ``dns_zone`` rows out of id order, NOT fixed
#: here, each with why. A zone-order violation under one of these frames is
#: not recorded; a lease-after-mirror one still is. Keep it short: every entry
#: is a deadlock waiting for its interleaving.
KNOWN_UNFIXED: dict[str, str] = {}

#: One entry per offence, read and cleared by the conftest fixture.
violations: list[str] = []

# High 64 bits random per process, low 64 a counter: monotonic, and never
# colliding with a zone id a test or an importer spells out.
_ZONE_ID_HIGH = random.getrandbits(64) << 64
_zone_counter = itertools.count(1)


def _next_zone_id() -> uuid.UUID:
    return uuid.UUID(int=_ZONE_ID_HIGH | next(_zone_counter))


def _record(session: Session, what: str, *, zone_order: bool = False) -> None:
    frames = _caller_frames()
    if not any(f.filename.startswith(_OWN_DIRS[0]) for f in frames):
        return  # a test arranging its own data, not an app path
    if zone_order and any(f.name in KNOWN_UNFIXED for f in frames):
        return
    violations.append(f"{what}; at {_app_stack(frames)}")


def _lock_zones(session: Session, ids: set[Any], how: str) -> None:
    held: set[Any] = session.info.setdefault(_ZONES, set())
    # A zone this transaction inserted: no other transaction can wait for it,
    # so it is neither a new lock nor a held one to compare against.
    own: set[Any] = session.info.get(_OWN_ZONES, set())
    new = {z for z in ids if z is not None and z not in held and z not in own}
    if not new:
        return
    if held and min(new) < max(held):
        _record(
            session,
            f"dns_zone {sorted(map(str, new))} locked ({how}) while holding the "
            f"higher-id dns_zone {max(held)}: zone rows out of id order",
            zone_order=True,
        )
    held.update(new)


def _lock_leases(session: Session, ids: set[Any] | None, how: str) -> None:
    held: set[Any] = session.info.setdefault(_LEASES, set())
    new = None if ids is None else {i for i in ids if i not in held}
    if new is not None and not new:
        return
    mirror_by = session.info.get(_MIRROR)
    if mirror_by is not None:
        _record(
            session,
            f"dhcp_lease rows locked ({how}) after this transaction locked ip_address "
            f"rows ({mirror_by}): lease rows must come first",
        )
    if new:
        held.update(new)


def _lock_mirror(session: Session, how: str) -> None:
    session.info.setdefault(_MIRROR, how)


def _modified(session: Session, obj: Any) -> bool:
    return obj in session.deleted or session.is_modified(obj, include_collections=False)


def _before_flush(session: Session, _ctx: Any, _instances: Any) -> None:
    for obj in session.new:
        if isinstance(obj, DNSZone):
            if obj.id is None:
                obj.id = _next_zone_id()
            session.info.setdefault(_OWN_ZONES, set()).add(obj.id)
        elif isinstance(obj, DHCPLease) and obj.id is not None:
            session.info.setdefault(_LEASES, set()).add(obj.id)
    touched = [o for o in (*session.dirty, *session.deleted) if _modified(session, o)]
    zones = {o.id for o in touched if isinstance(o, DNSZone)}
    leases = {o.id for o in touched if isinstance(o, DHCPLease)}
    if zones:
        _lock_zones(session, zones, "flush")
    if leases:
        # Before this flush's own mirror writes count: the unit of work's
        # order between the two tables is not ours to rely on either way.
        _lock_leases(session, leases, "flush")
    if any(isinstance(o, IPAddress) for o in touched):
        _lock_mirror(session, "flush")


def _after_flush(session: Session, _ctx: Any) -> None:
    for obj in session.new:
        if isinstance(obj, DHCPLease):
            session.info.setdefault(_LEASES, set()).add(obj.id)


def _locked_table(stmt: Select[Any]) -> tuple[Any, str] | None:
    """The mapped class and table a ``SELECT ... FOR UPDATE`` locks, when it
    is one of ours and the only table locked."""
    arg = stmt._for_update_arg
    if arg is None:
        return None
    if arg.of:
        tables = {getattr(c, "table", c) for c in arg.of}
    else:
        tables = set(stmt.get_final_froms())
    names = {getattr(t, "name", None) for t in tables}
    for cls, name in _TABLES.items():
        if name in names:
            return cls, name
    return None


def _ids_from_rows(rows: list[Any], cls: Any) -> set[Any]:
    ids: set[Any] = set()
    for row in rows:
        for value in row:
            if isinstance(value, cls):
                ids.add(value.id)
            elif isinstance(value, uuid.UUID):
                ids.add(value)
            break
    return ids


def _do_orm_execute(state: Any) -> Any:
    stmt = state.statement
    session = state.session
    if isinstance(stmt, (Update, Delete)):
        name = getattr(stmt.table, "name", None)
        if name == _LEASE:
            _lock_leases(session, None, "bulk " + type(stmt).__name__.upper())
        elif name == _MIRROR_TABLE:
            _lock_mirror(session, "bulk " + type(stmt).__name__.upper())
        return None
    if not isinstance(stmt, Select):
        return None
    locked = _locked_table(stmt)
    if locked is None:
        return None
    cls, name = locked
    frozen = state.invoke_statement().freeze()
    ids = _ids_from_rows(list(frozen().all()), cls)
    if (
        name == _ZONE
        and state.execution_options.get("lock_order") == "zone_prelock"
        and session.info.get(_AUDIT_LOCKED)
        and ids - session.info.get(_ZONES, set()) - session.info.get(_OWN_ZONES, set())
    ):
        _record(session, "dns_zone pre-locked after the audit-chain lock")
    if name == _ZONE:
        _lock_zones(session, ids, "SELECT FOR UPDATE")
    elif name == _LEASE:
        if ids:
            _lock_leases(session, ids, "SELECT FOR UPDATE")
    elif ids:
        _lock_mirror(session, "SELECT FOR UPDATE")
    return frozen()


def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:
        session.info.pop(_ZONES, None)
        session.info.pop(_OWN_ZONES, None)
        session.info.pop(_LEASES, None)
        session.info.pop(_MIRROR, None)


def install() -> None:
    if event.contains(Session, "before_flush", _before_flush):
        return
    event.listen(Session, "before_flush", _before_flush, insert=True)
    event.listen(Session, "after_flush", _after_flush)
    event.listen(Session, "do_orm_execute", _do_orm_execute)
    event.listen(Session, "after_transaction_end", _after_transaction_end)

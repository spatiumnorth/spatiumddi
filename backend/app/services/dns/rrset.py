"""Resolve the complete desired RRset for a record op (#773).

A record op carries one record. Every agent-side driver has to turn that into a
whole-RRset write, because none of the three wire protocols can express "change
this one RR and leave its siblings alone" from a payload that only names the
NEW value:

* BIND9 (RFC 2136) used ``upd.replace(...)``, which swaps the entire RRset for
  the single value in the op.
* Technitium used ``overwrite=true``, which does the same thing.
* PowerDNS read the live RRset and spliced the new value in — so it did not
  lose siblings, but it could not remove the *old* value on an edit either, and
  its own comment says so.

The result was that a name with more than one value at the same type served
only whichever op landed last: round-robin A records, a backup MX, SPF beside a
verification TXT, multiple apex NS. The database held every value and the
agent's rendered zone file held every value; only the incremental update path
lost them. ``rrset_action="add"`` existed as a per-op escape hatch but exactly
two callers ever set it, so everything else — operator record CRUD, the DNS
importers, IPAM→DNS sync, DDNS, ACME, trash restore — was affected.

The fix is to stop asking the wire protocol a question it cannot answer. The
control plane already knows the complete desired RRset — it is the source of
truth — so it ships that with the op, and each driver applies it as one atomic
whole-RRset write. Ops become idempotent and self-healing (replaying one
converges the server to the database) instead of order-dependent.

Wire shape, added to the op's ``record`` payload::

    "rrset": {"ttl": 3600,
              "members": [{"value": "10.0.0.1"},
                          {"value": "10.0.0.2"}]}

``members`` carries the structured fields too (``priority`` / ``weight`` /
``port``) so a driver composes each member's wire form exactly as it composes
the op's own. An EMPTY member list means the RRset should not exist at all.

Backward compatibility runs both ways. An agent that predates this field
ignores it and behaves exactly as it does today (the bug is not fixed for it,
but nothing is made worse). A current agent handed an op from an older control
plane sees no ``rrset`` and falls back to the previous ``rrset_action``
semantics.

The two callers that set ``rrset_action`` themselves — DNS pools and the
Windows-cutover TTL pre-flight — are deliberately NOT stamped, and keep the
per-RR semantics they already had. See :func:`stamp_rrsets_for_ops` for why a
whole-RRset write is the wrong shape for the pool re-point pair specifically.

Known bound: an op carries the RRset as of the moment it was ENQUEUED. Ops
enqueued together carry the same set, so a batch converges whichever order the
agent drains it in and however many times an op is replayed. Ops enqueued
minutes apart do not: if an older op fails, is reset to ``pending`` by
``ack_op`` and re-ships after a newer one has already applied, it reinstalls
the older set. That is the same outcome the previous single-value ``replace``
produced in that situation — no worse — and the next write to the name, or a
structural re-render, converges it. Making it airtight would mean re-resolving
the set at dispatch time in ``agent_config``, which costs a query per op per
bundle for a failure-path edge.

This is the agent path only. The agentless drivers (Windows DNS, and the cloud
providers) never see the field: ``enqueue_record_op`` stamps after it has
branched, so their op rows do not claim an RRset write nobody performed.
Windows DNS has its own whole-RRset collapse in ``drivers/dns/windows.py``;
that is a separate fix.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord, DNSZone

# Ops that describe an RRset. Everything else on the record-op queue is
# zone-level (``dnssec_sign`` / ``dnssec_unsign`` / ``dnssec_rollover``) and
# carries a placeholder record payload with no value to reason about.
RRSET_OPS = frozenset({"create", "update", "delete"})

# Fields that make up a member's wire form beyond the value itself.
_STRUCT_FIELDS = ("priority", "weight", "port")

# Names per ``IN`` clause. asyncpg refuses a statement with more than 32 767
# bind parameters, and the bulk path can touch far more names than that.
_NAME_CHUNK = 5000


def rrset_key(record: dict[str, Any]) -> tuple[str, str] | None:
    """The ``(name, type)`` an op's payload addresses, normalised, or None when
    the payload is not RRset-shaped (a DNSSEC op's placeholder record)."""
    rtype = record.get("type")
    if not rtype or rtype == "DNSSEC_OP":
        return None
    return ((record.get("name") or "@").lower(), str(rtype).upper())


def rrset_target(op: str, record: dict[str, Any]) -> tuple[str, str] | None:
    """The ``(name, type)`` this op performs an RRset write against, or None
    when it does not perform one.

    A payload with no ``value`` is refused as well as a non-RRset op: the whole
    scheme is "here is the set the server should end up with", and a set
    computed without knowing which RR the op is about would be wrong in the
    dangerous direction — a delete would ship the untouched set and quietly do
    nothing. Falling back to the legacy single-value semantics is the safe
    answer for a payload we cannot reason about.
    """
    if op not in RRSET_OPS or record.get("value") is None:
        return None
    return rrset_key(record)


def _member(value: str, ttl: int | None, src: Any) -> dict[str, Any]:
    """One RRset member. ``src`` is either a ``DNSRecord`` or an op payload
    dict — both expose the structured fields under the same names.

    A member built from a row also carries that row's ``id`` (an op payload
    carries it as ``record_id``), so a delete can drop exactly the row it is
    about and not an identical twin (#1230). It never reaches the wire:
    ``_rrset_payload`` strips it."""
    getter = src.get if isinstance(src, dict) else lambda f: getattr(src, f, None)
    out: dict[str, Any] = {"value": value, "ttl": ttl}
    for field in _STRUCT_FIELDS:
        val = getter(field)
        if val is not None:
            out[field] = val
    row_id = src.get("record_id") if isinstance(src, dict) else getattr(src, "id", None)
    if row_id is not None:
        out["id"] = str(row_id)
    return out


def _same_rr(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether two members are the same resource record.

    Value plus the structured fields, because two MX members at one name differ
    only by priority and two SRV members only by weight/port. TTL is excluded —
    it is a property of the RRset, not of a member, so a TTL-only edit must
    match its own record rather than adding a second copy of it.
    """
    if str(a.get("value") or "").strip() != str(b.get("value") or "").strip():
        return False
    return all(a.get(f) == b.get(f) for f in _STRUCT_FIELDS)


async def resolve_rrsets(
    db: AsyncSession,
    zone: DNSZone,
    keys: set[tuple[str, str]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Load the live members of every requested ``(name, type)``.

    Names are matched case-insensitively because DNS is; the database stores
    whatever the operator typed. Soft-deleted rows are excluded by the
    session-wide ``deleted_at IS NULL`` criterion in ``app.db``, and the SELECT
    autoflushes, so a row created / edited / soft-deleted earlier in the same
    request is already reflected here.

    The name list is chunked. ``enqueue_record_ops_bulk`` is the seed / import
    fast path and can hand over tens of thousands of distinct names in one call;
    a single ``IN`` would blow asyncpg's 32 767-bind-parameter ceiling and fail
    the whole commit, which for an import means losing the entire zone rather
    than one record.

    View-scoped records (``view_id``) are not filtered: a server whose group has
    views never receives incremental ops at all — ``agent_config`` retires them
    and re-renders the whole zone per view instead — so an op that reaches a
    driver is always from a group where every record lands in one namespace.
    """
    if not keys:
        return {}
    out: dict[tuple[str, str], list[dict[str, Any]]] = {key: [] for key in keys}
    names = sorted({name for name, _ in keys})
    for start in range(0, len(names), _NAME_CHUNK):
        rows = (
            (
                await db.execute(
                    select(DNSRecord).where(
                        DNSRecord.zone_id == zone.id,
                        func.lower(DNSRecord.name).in_(names[start : start + _NAME_CHUNK]),
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            key = ((row.name or "@").lower(), (row.record_type or "").upper())
            if key in out:
                out[key].append(_member(row.value, row.ttl, row))
    return out


def _fold(
    op: str,
    record: dict[str, Any],
    members: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """The RRset that should exist after ``op`` is applied to ``members``.

    * ``create`` / ``update`` — the op's value is present exactly once. It is
      spliced over any identical member rather than appended, so replaying an
      op cannot duplicate an RR, and an op whose row has not been flushed yet
      still lands.
    * ``delete`` — the op's ROW is absent. When the payload names the row
      (``record_id``), exactly that member is dropped, so an identical row
      that stays live keeps the value on the wire (#1230): the database can
      hold the same RR twice, and deleting one copy used to ship an RRset
      without it, so the server stopped answering for a record the UI still
      listed. Dropping the row rather than letting the query miss it matters
      for the callers that enqueue the retraction *before* the row leaves the
      database (``bulk_delete_records`` gates its DB delete on the wire
      result, and the IPAM sync deletes after enqueueing), where the rows the
      query returns include the very row being retracted. A payload without
      ``record_id`` (a caller with no row at hand) falls back to removing the
      value outright.

    The result is de-duplicated: the database may hold twins, the wire must
    not carry the same RR twice.
    """
    own = _member(record.get("value") or "", record.get("ttl"), record)
    row_id = own.get("id")
    if op == "delete" and row_id is not None:
        desired = [m for m in members if m.get("id") != row_id]
    else:
        desired = [m for m in members if not _same_rr(m, own)]
        if op != "delete":
            desired.append(own)
    unique: list[dict[str, Any]] = []
    for member in desired:
        if not any(_same_rr(member, kept) for kept in unique):
            unique.append(member)
    return unique


def _rrset_payload(members: list[dict[str, Any]], zone_ttl: int | None) -> dict[str, Any]:
    """The wire form: one TTL plus the member list, TTLs stripped per member.

    A null TTL means "inherit the zone default", which is how the zone file
    renders it; resolving it here keeps the wire consistent with the file
    instead of letting each driver fall back to a hardcoded 3600. Per RFC 2181
    an RRset has ONE TTL, so members that disagree resolve to the lowest — the
    conservative direction, since it only shortens caching.
    """
    default_ttl = 3600 if zone_ttl is None else zone_ttl
    ttls = [default_ttl if m.get("ttl") is None else m["ttl"] for m in members]
    return {
        "ttl": min(ttls) if ttls else default_ttl,
        "members": [{k: v for k, v in m.items() if k not in ("ttl", "id")} for m in members],
    }


async def stamp_rrsets_for_ops(
    db: AsyncSession,
    zone: DNSZone,
    ops: list[dict[str, Any]],
) -> None:
    """Stamp every op in a batch with the RRset that should exist once the
    WHOLE batch has been applied. Payloads are mutated in place.

    Folding the batch matters, and computing each op against the raw database
    snapshot instead is actively wrong. ``bulk_delete_records`` builds its ops
    from live rows and only deletes them after the wire result comes back, so
    deleting two of three values at one name resolves to ``[A, B, C]`` for both
    ops; reconciling each against that snapshot in isolation ships ``[B, C]``
    for one and ``[A, C]`` for the other, and whichever lands last reinstates a
    value the operator deleted.

    Stamping every op with the FINAL set — rather than a running prefix — is
    what keeps them order-independent as well as correct. Each op says "this
    name should end up exactly like this", so the agent may drain them in any
    order, and replaying one after the others is a no-op instead of a
    regression to an earlier state.

    Ops that carry an explicit ``rrset_action`` are left alone. Those callers
    (DNS pools, the Windows-cutover TTL pre-flight) already express precise
    per-RR semantics, and theirs are order-independent in a way a whole-RRset
    write cannot be across SEPARATE enqueue calls: a pool re-points a member
    with a ``delete_value`` of the old address and an ``add`` of the new, two
    calls on one serial. Stamping those would make the pair order-dependent —
    the delete's set is computed before the row is mutated, so applying it
    after the create would drop the new address.
    """
    stampable = [o for o in ops if not (o["record"].get("rrset_action") or "")]
    keys = {k for o in stampable if (k := rrset_target(o["op"], o["record"])) is not None}
    if not keys:
        return
    final = {key: list(members) for key, members in (await resolve_rrsets(db, zone, keys)).items()}
    for o in stampable:
        key = rrset_target(o["op"], o["record"])
        if key is not None:
            final[key] = _fold(o["op"], o["record"], final.get(key, []))
    for o in stampable:
        key = rrset_target(o["op"], o["record"])
        if key is not None:
            o["record"]["rrset"] = _rrset_payload(final[key], zone.ttl)

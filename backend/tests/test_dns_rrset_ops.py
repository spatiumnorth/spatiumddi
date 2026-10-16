"""#773 — an agent-bound record op must carry the COMPLETE desired RRset.

A record op names one record. Every agent driver has to turn that into a
whole-RRset write, because none of the three wire protocols can express "change
this RR and leave its siblings alone": BIND9 used RFC 2136 ``replace``,
Technitium used ``overwrite=true``, PowerDNS spliced but could never retract.
So a name carrying more than one value at the same type served only whichever
op landed last — round-robin A records, a backup MX, an SPF beside a
verification TXT, multiple apex NS. The database held every value and the
agent's rendered zone file held every value; only the incremental update path
lost them, which is exactly the kind of divergence nobody notices until a
failover.

The fix stops asking the wire protocol a question it cannot answer: the control
plane already knows the whole RRset, so it stamps it onto the op and the driver
applies it as one atomic write. This file pins that stamp — the payload shape,
what it must and must not contain, and the two places it must stay absent.

What each test guards:

* the #773 repro itself — a second value at an existing name keeps the first
* delete leaves siblings alone, and an empty member list is how "drop the whole
  RRset" is expressed
* the set is scoped to (name, type), and matched case-insensitively as DNS is
* one TTL per RRset (RFC 2181), resolved from the zone default rather than a
  driver-side hardcoded 3600
* structured fields (priority / weight / port) ride along, or a two-member MX
  loses the distinction between primary and backup
* every op in a batch carries the same set, which is what makes a batch
  order-independent and an op replay-safe
* DNSSEC ops carry no RRset (they have no record to reason about) and must not
  blow up on the way past
* agentless drivers ARE stamped too (#783), and the change handed to the
  driver carries the set as a neutral ``RRsetData``
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.dns.record_ops import (
    enqueue_record_op,
    enqueue_record_ops_batch,
    enqueue_record_ops_bulk,
)

# ── fixtures / helpers ──────────────────────────────────────────────────────


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rr-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="RRset Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_and_zone(
    db: AsyncSession,
    *,
    driver: str = "bind9",
    zone_ttl: int = 3600,
) -> tuple[DNSServerGroup, DNSServer, DNSZone]:
    """One group, one primary server on ``driver``, one zone."""
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=zone_ttl,
    )
    db.add(zone)
    await db.flush()
    return grp, server, zone


async def _add_record(
    db: AsyncSession,
    zone: DNSZone,
    *,
    name: str,
    value: str,
    record_type: str = "A",
    ttl: int | None = None,
    **struct: int | None,
) -> DNSRecord:
    """Insert a record row directly, bypassing the API.

    Some cases need a row the API would normalise (a name stored with its
    original case) or need the zone pre-populated without the create ops that
    populating it through the API would also queue.
    """
    rec = DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type=record_type,
        value=value,
        ttl=ttl,
        **struct,
    )
    db.add(rec)
    await db.flush()
    return rec


async def _ops(db: AsyncSession, zone: DNSZone) -> list[DNSRecordOp]:
    return list(
        (await db.execute(select(DNSRecordOp).where(DNSRecordOp.zone_name == zone.name)))
        .scalars()
        .all()
    )


async def _op_for_value(db: AsyncSession, zone: DNSZone, value: str) -> DNSRecordOp:
    """The single op whose payload names ``value`` — ops in one transaction all
    share a ``now()`` created_at, so they cannot be told apart by order."""
    matches = [o for o in await _ops(db, zone) if o.record.get("value") == value]
    assert len(matches) == 1, f"expected exactly one op for {value}, got {len(matches)}"
    return matches[0]


def _values(op: DNSRecordOp) -> set[str]:
    return {m["value"] for m in op.record["rrset"]["members"]}


def _records_url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


class _RecordingDriver:
    """Stand-in for an agentless driver — swallows the push and records it, so
    the agentless branch runs end to end without a live WinRM host."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str, str]] = []
        self.full_changes: list[Any] = []

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        self.changes.append((change.op, change.record.name, change.record.record_type))
        self.full_changes.append(change)

    async def apply_record_changes(self, server: Any, changes: Any) -> list[Any]:
        from app.drivers.dns.base import RecordChangeResult  # noqa: PLC0415

        for change in changes:
            await self.apply_record_change(server, change)
        return [RecordChangeResult(ok=True, change=c) for c in changes]

    @property
    def last_change(self) -> Any:
        return self.full_changes[-1] if self.full_changes else None


# ── 1. the #773 regression ──────────────────────────────────────────────────


async def test_second_value_at_a_name_keeps_the_first(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """THE #773 regression. Adding a second round-robin A record must not retire
    the first one.

    Pre-fix the second op carried only ``10.0.0.2``, and the agent's whole-RRset
    ``replace`` swapped the name's entire RRset for it — so the operator added
    an address and silently lost one. The op now describes the state the server
    must be in afterwards, which is both values.
    """
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    await db_session.commit()

    for value in ("10.0.0.1", "10.0.0.2"):
        r = await client.post(
            _records_url(zone),
            headers=headers,
            json={"name": "www", "record_type": "A", "value": value},
        )
        assert r.status_code == 201, r.text

    second = await _op_for_value(db_session, zone, "10.0.0.2")
    assert _values(second) == {"10.0.0.1", "10.0.0.2"}

    # The first op is honest about the state at the time it was enqueued — the
    # name held one value then, and replaying it after the second op landed
    # would be the one known-lossy case (documented in rrset.py).
    first = await _op_for_value(db_session, zone, "10.0.0.1")
    assert _values(first) == {"10.0.0.1"}


# ── 2-3. delete semantics ───────────────────────────────────────────────────


async def test_delete_one_value_keeps_the_surviving_siblings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Removing one address from a round-robin set must leave the other two
    serving. The delete op is a whole-RRset write like any other, so if it
    carried only the removed value the agent would install *that* as the RRset —
    deleting an address by making it the only one left."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    victim: DNSRecord | None = None
    for value in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        rec = await _add_record(db_session, zone, name="pool", value=value)
        if value == "10.0.0.2":
            victim = rec
    assert victim is not None
    await db_session.commit()

    r = await client.delete(f"{_records_url(zone)}/{victim.id}", headers=headers)
    assert r.status_code == 204, r.text

    op = await _op_for_value(db_session, zone, "10.0.0.2")
    assert op.op == "delete"
    assert _values(op) == {"10.0.0.1", "10.0.0.3"}
    assert "10.0.0.2" not in _values(op)


async def test_delete_of_the_last_value_yields_an_empty_member_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An empty ``members`` is how the payload says "this RRset should not
    exist". It has to be distinguishable from a one-member set, or deleting the
    only A record at a name would either leave it serving or make the driver
    guess."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    only = await _add_record(db_session, zone, name="solo", value="10.0.0.9")
    await db_session.commit()

    r = await client.delete(f"{_records_url(zone)}/{only.id}", headers=headers)
    assert r.status_code == 204, r.text

    op = await _op_for_value(db_session, zone, "10.0.0.9")
    assert op.op == "delete"
    assert op.record["rrset"]["members"] == []


# ── 4-5. what belongs in the set ────────────────────────────────────────────


async def test_rrset_is_scoped_to_one_name_and_type(db_session: AsyncSession) -> None:
    """The set is keyed on (name, type). Pulling in a neighbouring name's values
    would publish them under the wrong label; pulling in another type's would
    hand the driver rdata it cannot encode for the type it is writing."""
    _grp, _server, zone = await _group_and_zone(db_session)
    await _add_record(db_session, zone, name="www", value="10.0.0.1")
    await _add_record(db_session, zone, name="www", value="2001:db8::1", record_type="AAAA")
    await _add_record(db_session, zone, name="www", value='"v=spf1 -all"', record_type="TXT")
    await _add_record(db_session, zone, name="other", value="10.0.0.9")
    await db_session.commit()

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "www", "type": "A", "value": "10.0.0.2"}
    )
    assert op is not None
    assert _values(op) == {"10.0.0.1", "10.0.0.2"}


async def test_sibling_stored_in_a_different_case_is_still_in_the_rrset(
    db_session: AsyncSession,
) -> None:
    """DNS names are case-insensitive and nothing normalises them on write, so
    the same name can be stored as ``WWW`` and ``www`` in two rows. Matching by
    exact string would treat those as different RRsets — and the op for ``www``
    would then quietly retire the ``WWW`` row's value on the wire."""
    _grp, _server, zone = await _group_and_zone(db_session)
    await _add_record(db_session, zone, name="WWW", value="10.0.0.1")
    await db_session.commit()

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "www", "type": "A", "value": "10.0.0.2"}
    )
    assert op is not None
    assert _values(op) == {"10.0.0.1", "10.0.0.2"}


# ── 6. one TTL per RRset ────────────────────────────────────────────────────


async def test_null_ttl_resolves_to_the_zone_default_not_a_hardcoded_3600(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A NULL record TTL means "inherit the zone default" — that is how the zone
    file renders it. The agents' record-op branch falls back to a hardcoded 3600
    instead, so leaving the null on the wire would write 3600 onto every
    inheriting record of a zone whose default is anything else. Resolving it
    centrally keeps the incremental path and the rendered file agreeing."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session, zone_ttl=7200)
    await db_session.commit()

    r = await client.post(
        _records_url(zone),
        headers=headers,
        json={"name": "app", "record_type": "A", "value": "10.0.0.5"},
    )
    assert r.status_code == 201, r.text

    op = await _op_for_value(db_session, zone, "10.0.0.5")
    assert op.record["ttl"] is None, "the row keeps its NULL — inheritance is stored, not resolved"
    assert op.record["rrset"]["ttl"] == 7200
    assert op.record["rrset"]["ttl"] != 3600, "must not be the driver-side fallback"


async def test_members_with_different_ttls_resolve_to_the_lowest(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """RFC 2181: an RRset has ONE TTL. Two rows at one name can disagree, and
    something has to pick — the lowest, because the only cost is shorter
    caching, where the highest would leave resolvers holding a stale answer
    past the TTL the operator asked for on the other member."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session, zone_ttl=7200)
    await db_session.commit()

    for value, ttl in (("10.0.0.1", 300), ("10.0.0.2", 60)):
        r = await client.post(
            _records_url(zone),
            headers=headers,
            json={"name": "www", "record_type": "A", "value": value, "ttl": ttl},
        )
        assert r.status_code == 201, r.text

    second = await _op_for_value(db_session, zone, "10.0.0.2")
    assert _values(second) == {"10.0.0.1", "10.0.0.2"}, "both members, or there is no TTL to pick"
    assert second.record["rrset"]["ttl"] == 60
    # The first op saw only its own member, so it resolves to that member's TTL —
    # the min is over whatever the set held when the op was enqueued.
    first = await _op_for_value(db_session, zone, "10.0.0.1")
    assert first.record["rrset"]["ttl"] == 300
    # Members carry no per-member TTL — it is a property of the set, and
    # emitting one per member would invite a driver to write them individually.
    assert all("ttl" not in m for m in second.record["rrset"]["members"])


# ── 7. structured fields ────────────────────────────────────────────────────


async def test_mx_members_keep_their_priorities(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A backup MX is distinguished from the primary by nothing but its
    priority. Ship the set without it and the driver has two indistinguishable
    exchangers — mail delivery order becomes a coin flip."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    await db_session.commit()

    for value, priority in (("mail1.example.", 10), ("mail2.example.", 20)):
        r = await client.post(
            _records_url(zone),
            headers=headers,
            json={"name": "@", "record_type": "MX", "value": value, "priority": priority},
        )
        assert r.status_code == 201, r.text

    op = await _op_for_value(db_session, zone, "mail2.example.")
    members = {m["value"]: m for m in op.record["rrset"]["members"]}
    assert set(members) == {"mail1.example.", "mail2.example."}
    assert members["mail1.example."]["priority"] == 10
    assert members["mail2.example."]["priority"] == 20


async def test_srv_members_keep_priority_weight_and_port(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """SRV rdata is ``priority weight port target``. Drivers substitute 0 for a
    missing field (#424), so a member shipped without them renders as a valid
    but meaningless ``0 0 0 target`` — a live-looking record pointing at the
    wrong port."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    await db_session.commit()

    for value, port in (("sip1.example.", 5060), ("sip2.example.", 5061)):
        r = await client.post(
            _records_url(zone),
            headers=headers,
            json={
                "name": "_sip._tcp",
                "record_type": "SRV",
                "value": value,
                "priority": 10,
                "weight": 20,
                "port": port,
            },
        )
        assert r.status_code == 201, r.text

    op = await _op_for_value(db_session, zone, "sip2.example.")
    members = {m["value"]: m for m in op.record["rrset"]["members"]}
    assert set(members) == {"sip1.example.", "sip2.example."}
    for value, port in (("sip1.example.", 5060), ("sip2.example.", 5061)):
        assert (members[value]["priority"], members[value]["weight"], members[value]["port"]) == (
            10,
            20,
            port,
        )


# ── 8. batches carry one shared set ─────────────────────────────────────────


async def test_every_op_in_a_batch_carries_the_same_complete_set(
    db_session: AsyncSession,
) -> None:
    """This is what makes a batch order-independent and each op replay-safe.

    Every op at a shared (name, type) describes the SAME end state, so no op
    depends on another having been applied first: the agent can drain them in
    any order, retry one, or apply the same one twice, and the name still ends
    up serving all three values. Stamping per-op instead — resolving as each
    row lands — would make the last-applied op the winner all over again.
    """
    _grp, _server, zone = await _group_and_zone(db_session)
    values = ("10.0.0.1", "10.0.0.2", "10.0.0.3")
    for value in values:
        await _add_record(db_session, zone, name="pool", value=value, ttl=300)
    await db_session.commit()

    rows = await enqueue_record_ops_batch(
        db_session,
        zone,
        # ``ttl`` is carried the way ``record_op_payload`` carries it. The op's
        # own payload — not the row it came from — is what the fold splices in,
        # so a payload that omitted it would be asserting "no explicit TTL" and
        # the RRset would correctly resolve to the zone default instead.
        [
            {"op": "create", "record": {"name": "pool", "type": "A", "value": v, "ttl": 300}}
            for v in values
        ],
    )
    assert all(r is not None for r in rows)

    ops = await _ops(db_session, zone)
    assert len(ops) == 3
    assert all(_values(o) == set(values) for o in ops)
    assert {o.record["rrset"]["ttl"] for o in ops} == {300}


async def test_bulk_create_endpoint_stamps_every_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The bulk-create fast-path exists so a seeder does not pay a commit per
    record — but a fast path that skipped the stamp would seed a round-robin
    name and leave it serving one address, which is the #773 bug wearing a
    different hat."""
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    await db_session.commit()

    values = ("10.0.0.1", "10.0.0.2", "10.0.0.3")
    r = await client.post(
        f"{_records_url(zone)}/bulk-create",
        headers=headers,
        json={"records": [{"name": "pool", "record_type": "A", "value": v} for v in values]},
    )
    assert r.status_code == 201, r.text
    assert r.json()["created"] == 3

    ops = await _ops(db_session, zone)
    assert len(ops) == 3
    assert all(_values(o) == set(values) for o in ops)


async def test_bulk_helper_stamps_the_rrset(db_session: AsyncSession) -> None:
    """``enqueue_record_ops_bulk`` is a separate implementation from the singular
    and batch paths — it resolves the server set once and inserts every op row in
    one add_all rather than looping the singular path. A stamp added to the other
    two and forgotten here would leave the importers and the seeder emitting
    pre-#773 ops."""
    _grp, _server, zone = await _group_and_zone(db_session)
    values = ("10.0.0.1", "10.0.0.2")
    for value in values:
        await _add_record(db_session, zone, name="pool", value=value)
    await db_session.commit()

    dispatched = await enqueue_record_ops_bulk(
        db_session,
        zone,
        [{"op": "create", "record": {"name": "pool", "type": "A", "value": v}} for v in values],
    )
    assert dispatched == 2

    ops = await _ops(db_session, zone)
    assert len(ops) == 2
    assert all(_values(o) == set(values) for o in ops)


async def test_a_payload_that_already_carries_an_rrset_is_not_restamped(
    db_session: AsyncSession,
) -> None:
    """The batch path folds and stamps its whole list in one query and then
    delegates to the singular path, which must leave the result alone.
    Re-resolving per op would undo the fold — the very thing that keeps a batch
    of deletes from contradicting itself — and cost a query per op."""
    _grp, _server, zone = await _group_and_zone(db_session)
    await _add_record(db_session, zone, name="www", value="10.0.0.1")
    await db_session.commit()

    preset = {"ttl": 42, "members": [{"value": "192.0.2.1"}]}
    op = await enqueue_record_op(
        db_session,
        zone,
        "create",
        {"name": "www", "type": "A", "value": "10.0.0.2", "rrset": preset},
    )
    assert op is not None
    assert op.record["rrset"] == preset


async def test_a_batch_of_deletes_at_one_name_agrees_with_itself(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Deleting two of three values at one name must leave exactly the third.

    This is the case that makes folding the batch mandatory rather than a
    nicety. ``bulk_delete_records`` builds its ops from LIVE rows and only
    removes them from the database once the wire result comes back, so at stamp
    time all three are still there. Reconciling each op against that snapshot in
    isolation gives one op ``[B, C]`` and the other ``[A, C]`` — two whole-RRset
    writes that contradict each other, and whichever the agent applies last
    reinstates a value the operator just deleted.
    """
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    keep = await _add_record(db_session, zone, name="pool", value="10.0.0.3")
    doomed = [
        await _add_record(db_session, zone, name="pool", value="10.0.0.1"),
        await _add_record(db_session, zone, name="pool", value="10.0.0.2"),
    ]
    await db_session.commit()

    resp = await client.post(
        f"{_records_url(zone)}/bulk-delete",
        headers=headers,
        json={"record_ids": [str(r.id) for r in doomed]},
    )
    assert resp.status_code == 200, resp.text

    ops = [o for o in await _ops(db_session, zone) if o.op == "delete"]
    assert len(ops) == 2
    # Both ops describe the same end state, and it is the survivor alone.
    for op in ops:
        assert _values(op) == {keep.value}


async def test_update_ships_the_new_value_and_not_the_old(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Changing one value of a multi-value RRset replaces exactly that value.

    The op payload carries only the NEW value, which is why every driver had to
    guess: BIND9 and Technitium wiped the RRset, and PowerDNS's own comment
    admitted it could not remove the old one and left it live beside the new.
    With the desired set on the op there is nothing to guess.
    """
    headers = await _admin_headers(db_session)
    _grp, _server, zone = await _group_and_zone(db_session)
    await _add_record(db_session, zone, name="www", value="10.0.0.1")
    target = await _add_record(db_session, zone, name="www", value="10.0.0.2")
    await db_session.commit()

    resp = await client.put(
        f"{_records_url(zone)}/{target.id}", headers=headers, json={"value": "10.0.0.9"}
    )
    assert resp.status_code == 200, resp.text

    op = await _op_for_value(db_session, zone, "10.0.0.9")
    assert op.op == "update"
    assert _values(op) == {"10.0.0.1", "10.0.0.9"}


async def test_an_op_carrying_rrset_action_opts_out_of_stamping(
    db_session: AsyncSession,
) -> None:
    """DNS pools and the cutover TTL pre-flight express precise per-RR
    semantics, and must keep them.

    A pool re-points a member as a ``delete_value`` of the old address plus an
    ``add`` of the new — two SEPARATE enqueue calls on one serial. Per-RR ops
    are order-independent; whole-RRset writes are not, because the delete's set
    is computed before the row is mutated, so applying it after the create
    would drop the new address. Stamping these would trade a real bug for a
    subtler one.
    """
    _grp, _server, zone = await _group_and_zone(db_session)
    await _add_record(db_session, zone, name="pool", value="10.0.0.1")
    await db_session.commit()

    op = await enqueue_record_op(
        db_session,
        zone,
        "create",
        {"name": "pool", "type": "A", "value": "10.0.0.2", "rrset_action": "add"},
    )
    assert op is not None
    assert "rrset" not in op.record


# ── 9-10. where the stamp must NOT appear ───────────────────────────────────


async def test_dnssec_ops_carry_no_rrset(db_session: AsyncSession) -> None:
    """A DNSSEC op is zone-level and carries a placeholder record with no value
    to reason about. It has to pass through the stamp untouched — attaching an
    RRset would be meaningless, and raising on the placeholder would take zone
    signing down as collateral damage from a record-path change."""
    _grp, _server, zone = await _group_and_zone(db_session)
    await db_session.commit()

    op = await enqueue_record_op(
        db_session, zone, "dnssec_sign", {"name": "@", "type": "DNSSEC_OP"}
    )
    assert op is not None
    assert "rrset" not in op.record
    assert op.op == "dnssec_sign"


async def test_agentless_ops_are_stamped_and_reach_the_driver(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#783 — the agentless path gets the same set, as a neutral ``RRsetData``.

    This test used to assert the opposite. The reasoning behind that was that
    an agentless row must not claim an RRset write nobody performed — sound in
    itself, and the wrong conclusion, because the agentless drivers were
    performing whole-RRset writes the whole time. Windows' PowerShell
    ``Get-DnsServerResourceRecord … | Remove-…`` takes out every RR at the
    ``(name, type)`` no matter which value the op named, and only the op's own
    value went back; Route 53 / Azure / Google replace the RRset on update.
    So the write was always whole-RRset — it just had one value in it, which
    is what silently retired the siblings. Now the row and the write agree.
    """
    _grp, _server, zone = await _group_and_zone(db_session, driver="windows_dns")
    await _add_record(db_session, zone, name="www", value="10.0.0.1")
    await db_session.commit()

    recorder = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: recorder)

    op = await enqueue_record_op(
        db_session, zone, "create", {"name": "www", "type": "A", "value": "10.0.0.2"}
    )
    await db_session.commit()  # #1539 — the provider is written by the commit
    assert op is not None
    assert op.state == "applied", "the agentless branch really ran"
    assert recorder.changes == [("create", "www", "A")]
    # The row records the desired end state...
    assert {m["value"] for m in op.record["rrset"]["members"]} == {"10.0.0.1", "10.0.0.2"}
    # ...and the driver was handed it, not just the one new value.
    assert recorder.last_change is not None
    assert recorder.last_change.rrset is not None
    assert {m.value for m in recorder.last_change.rrset.members} == {"10.0.0.1", "10.0.0.2"}


async def test_agentless_batch_folds_before_stamping(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bulk delete of two of three values must not have the ops contradict.

    Both ops resolve against the same pre-delete snapshot, so reconciling each
    in isolation would ship ``[B, C]`` for one and ``[A, C]`` for the other and
    whichever landed last would reinstate a value the operator deleted. The
    whole batch is folded first, so both carry the survivor.
    """
    _grp, _server, zone = await _group_and_zone(db_session, driver="windows_dns")
    for value in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        await _add_record(db_session, zone, name="www", value=value)
    await db_session.commit()

    recorder = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: recorder)

    await enqueue_record_ops_batch(
        db_session,
        zone,
        [
            {"op": "delete", "record": {"name": "www", "type": "A", "value": "10.0.0.1"}},
            {"op": "delete", "record": {"name": "www", "type": "A", "value": "10.0.0.2"}},
        ],
    )
    await db_session.commit()  # #1539 — the provider is written by the commit

    sets = [
        {m.value for m in c.rrset.members} for c in recorder.full_changes if c.rrset is not None
    ]
    assert sets == [{"10.0.0.3"}, {"10.0.0.3"}]

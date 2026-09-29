"""Identical DNS records: deleting one must not retract the other (#1230).

``POST …/records`` did no duplicate check and ``dns_record`` has no unique
constraint, so a client retry (Ansible, a flaky network, a double click) stored
the same RR twice. That was worse than clutter. Every record op carries the
whole RRset the server should end up with (#773), and a delete dropped the
deleted row's VALUE from it — taking the twin's copy with it. The server
stopped answering for a record the database, and the UI, still listed.

Two halves, both pinned here:

* the RRset fold drops the deleted ROW (named by ``record_id``), so twins that
  already exist keep their value on the wire whichever copy is deleted;
* create, update, bulk create and the Copilot refuse to make a new twin.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services.ai.operations import CreateDNSRecordArgs, get_operation
from app.services.dns.record_ops import enqueue_record_op, record_op_payload
from app.services.dns.rrset import _fold

# ── helpers ─────────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"tw-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Twin Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _row(
    db: AsyncSession, zone: DNSZone, *, name: str = "www", value: str = "10.0.0.5", **kw: object
) -> DNSRecord:
    """Insert directly, bypassing the API: the twins under test predate the
    create-side refusal, so the API would no longer make them."""
    rec = DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type=kw.pop("record_type", "A"),  # type: ignore[arg-type]
        value=value,
        **kw,
    )
    db.add(rec)
    await db.flush()
    return rec


def _url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


async def _delete_ops(db: AsyncSession, zone: DNSZone) -> list[DNSRecordOp]:
    rows = (
        await db.execute(
            select(DNSRecordOp).where(
                DNSRecordOp.zone_name == zone.name, DNSRecordOp.op == "delete"
            )
        )
    ).scalars()
    return list(rows)


def _members(op: DNSRecordOp) -> list[str]:
    return [m["value"] for m in op.record["rrset"]["members"]]


# ── The wrong answer: deleting one twin ──────────────────────────────────────


async def test_deleting_one_twin_keeps_the_value_on_the_wire(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    first = await _row(db_session, zone)
    await _row(db_session, zone)
    await db_session.commit()

    resp = await client.delete(f"{_url(zone)}/{first.id}", headers=headers)
    assert resp.status_code == 204, resp.text

    (op,) = await _delete_ops(db_session, zone)
    assert _members(op) == ["10.0.0.5"], "the twin still lists it, so the server must serve it"


async def test_bulk_deleting_one_twin_keeps_it_and_deleting_both_drops_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``bulk_delete_records`` enqueues while the rows are still live, which is
    exactly where a by-value fold took the twin with it."""
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    first = await _row(db_session, zone)
    second = await _row(db_session, zone)
    await db_session.commit()

    resp = await client.post(
        f"{_url(zone)}/bulk-delete", headers=headers, json={"record_ids": [str(first.id)]}
    )
    assert resp.status_code == 200, resp.text
    (op,) = await _delete_ops(db_session, zone)
    assert _members(op) == ["10.0.0.5"]

    resp = await client.post(
        f"{_url(zone)}/bulk-delete", headers=headers, json={"record_ids": [str(second.id)]}
    )
    assert resp.status_code == 200, resp.text
    last = [
        o for o in await _delete_ops(db_session, zone) if o.record["record_id"] == str(second.id)
    ]
    assert _members(last[0]) == []


async def test_a_delete_enqueued_before_its_row_leaves_keeps_the_twin(
    db_session: AsyncSession,
) -> None:
    """The IPAM sync enqueues the delete and only then deletes the row."""
    zone = await _zone(db_session)
    doomed = await _row(db_session, zone)
    await _row(db_session, zone)

    await enqueue_record_op(db_session, zone, "delete", record_op_payload(doomed))
    (op,) = await _delete_ops(db_session, zone)
    assert _members(op) == ["10.0.0.5"]


def test_the_fold_drops_the_row_not_the_value() -> None:
    twin_a = {"value": "10.0.0.5", "ttl": None, "id": "a"}
    twin_b = {"value": "10.0.0.5", "ttl": None, "id": "b"}
    other = {"value": "10.0.0.6", "ttl": None, "id": "c"}
    members = [twin_a, twin_b, other]

    kept = _fold("delete", {"value": "10.0.0.5", "record_id": "a"}, members)
    assert [m["value"] for m in kept] == ["10.0.0.5", "10.0.0.6"]

    # No row named (a caller with no row at hand): the value goes, as before.
    legacy = _fold("delete", {"value": "10.0.0.5"}, members)
    assert [m["value"] for m in legacy] == ["10.0.0.6"]


def test_the_wire_never_carries_the_same_rr_twice() -> None:
    members = [
        {"value": "10.0.0.5", "ttl": None, "id": "a"},
        {"value": "10.0.0.5", "ttl": None, "id": "b"},
    ]
    folded = _fold("create", {"value": "10.0.0.7"}, members)
    assert sorted(m["value"] for m in folded) == ["10.0.0.5", "10.0.0.7"]


async def test_the_row_id_never_reaches_the_wire(db_session: AsyncSession) -> None:
    zone = await _zone(db_session)
    rec = await _row(db_session, zone)
    await enqueue_record_op(db_session, zone, "create", record_op_payload(rec))
    op = (
        await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.zone_name == zone.name))
    ).scalar_one()
    assert all("id" not in m for m in op.record["rrset"]["members"])


# ── No new twins: create / update / bulk create / Copilot ────────────────────


@pytest.mark.parametrize(
    "variant",
    [
        {"name": "www", "value": "10.0.0.5"},
        {"name": "WWW", "value": "10.0.0.5"},  # DNS names are case-insensitive
        {"name": "www", "value": "10.0.0.5", "ttl": 60},  # TTL is the RRset's
    ],
)
async def test_creating_an_identical_record_is_a_409(
    client: AsyncClient, db_session: AsyncSession, variant: dict[str, object]
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()

    first = await client.post(
        _url(zone), headers=headers, json={"name": "www", "record_type": "A", "value": "10.0.0.5"}
    )
    assert first.status_code == 201, first.text
    again = await client.post(_url(zone), headers=headers, json={"record_type": "A", **variant})
    assert again.status_code == 409, again.text
    assert first.json()["id"] in again.json()["detail"]


async def test_a_different_value_or_priority_is_not_a_twin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    for body in (
        {"name": "www", "record_type": "A", "value": "10.0.0.5"},
        {"name": "www", "record_type": "A", "value": "10.0.0.6"},
        {"name": "@", "record_type": "MX", "value": "mx1.example.", "priority": 10},
        {"name": "@", "record_type": "MX", "value": "mx1.example.", "priority": 20},
    ):
        resp = await client.post(_url(zone), headers=headers, json=body)
        assert resp.status_code == 201, (body, resp.text)


async def test_a_record_in_the_trash_does_not_block_re_creating_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    body = {"name": "www", "record_type": "A", "value": "10.0.0.5"}
    created = await client.post(_url(zone), headers=headers, json=body)
    assert created.status_code == 201, created.text
    deleted = await client.delete(f"{_url(zone)}/{created.json()['id']}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    again = await client.post(_url(zone), headers=headers, json=body)
    assert again.status_code == 201, again.text


async def test_an_edit_that_makes_a_twin_is_a_409_but_a_ttl_edit_on_one_is_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, value="10.0.0.5")
    other = await _row(db_session, zone, value="10.0.0.6")
    twin = await _row(db_session, zone, value="10.0.0.5")  # predates the rule
    await db_session.commit()

    resp = await client.put(f"{_url(zone)}/{other.id}", headers=headers, json={"value": "10.0.0.5"})
    assert resp.status_code == 409, resp.text

    resp = await client.put(f"{_url(zone)}/{twin.id}", headers=headers, json={"ttl": 120})
    assert resp.status_code == 200, resp.text


async def test_bulk_create_skips_what_the_zone_or_the_batch_already_has(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, name="www", value="10.0.0.5")
    await db_session.commit()

    resp = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={
            "records": [
                {"name": "WWW", "record_type": "A", "value": "10.0.0.5"},
                {"name": "api", "record_type": "A", "value": "10.0.0.9"},
                {"name": "api", "record_type": "A", "value": "10.0.0.9"},
                # MX defaults its priority to 10, so these two are one record.
                {"name": "@", "record_type": "MX", "value": "mx1.example."},
                {"name": "@", "record_type": "MX", "value": "mx1.example.", "priority": 10},
            ]
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["created"] == 2
    assert sorted(s["reason"] for s in body["skipped"]) == [
        "duplicate within batch",
        "duplicate within batch",
        "identical record already exists",
    ]


async def test_the_copilot_refuses_an_identical_record(db_session: AsyncSession) -> None:
    user, _headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, name="www", value="10.0.0.5")
    await db_session.commit()

    op = get_operation("create_dns_record")
    assert op is not None
    args = CreateDNSRecordArgs(zone_id=str(zone.id), name="www", record_type="A", value="10.0.0.5")
    with pytest.raises(ValueError, match="identical"):
        await op.apply(db_session, user, args)

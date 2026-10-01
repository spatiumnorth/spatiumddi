"""Blocklist entries are collected as column rows, in a stable order (#1109).

``_collect_lists`` used to hydrate every entry as a tracked ORM object, one
query per list: the shape #948 removed for records, on the path the Family
filter profile (~596k entries, #878) makes the largest in a bundle. These pin
what the change must not move: the list order that decides which list wins a
duplicate owner name, and a within-list order that does not follow the heap,
so the bundle's ETag is the same on every build. Plus the effective endpoints,
which splatted ``EffectiveEntry.__dict__`` and broke when it became slotted.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServerGroup,
)
from app.services.dns_blocklist import _collect_lists, build_effective_for_group


async def _list(db: AsyncSession, mode: str, domains: list[str], **kw) -> DNSBlockList:
    bl = DNSBlockList(name=f"c-{uuid.uuid4().hex[:8]}", block_mode=mode, **kw)
    db.add(bl)
    await db.flush()
    for d in domains:
        db.add(DNSBlockListEntry(list_id=bl.id, domain=d, entry_type="block", source="manual"))
    await db.flush()
    return bl


@pytest.mark.asyncio
async def test_the_first_list_given_comes_first(db_session: AsyncSession) -> None:
    """The renderers keep the first writer of an owner name (#878), so the
    caller's list order is what decides a collision."""
    a = await _list(db_session, "nxdomain", ["dup.example", "only-a.example"])
    b = await _list(db_session, "sinkhole", ["DUP.example"], sinkhole_ip="192.0.2.1")
    db_session.add(DNSBlockListException(list_id=b.id, domain="Allowed.example"))
    await db_session.flush()

    entries, exceptions, ids = await _collect_lists(db_session, [b, a])
    assert ids == [b.id, a.id]
    dup = [e for e in entries if e.domain == "dup.example"]
    assert [e.block_mode for e in dup] == ["sinkhole", "nxdomain"]
    assert dup[0].sinkhole_ip == "192.0.2.1" and dup[0].list_name == b.name
    assert exceptions == {"allowed.example"}


@pytest.mark.asyncio
async def test_entries_are_read_as_columns_not_entities(db_session: AsyncSession) -> None:
    """The point of #1109: a ~596k-entry profile must not be hydrated into
    ORM objects on every bundle build. Every value assertion here would
    still pass if the query went back to ``select(DNSBlockListEntry)``, so
    pin the SQL: the four columns the bundle needs, and nothing an entity
    load would add (its ``id``, ``list_id``, ``source``, ...). The identity
    map cannot show this: it holds weak references, and the entities are
    gone again before the call returns."""
    a = await _list(db_session, "nxdomain", ["one.example", "two.example"])
    statements: list[str] = []

    def capture(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        flat = " ".join(statement.split())
        if flat.upper().startswith("SELECT") and "FROM dns_blocklist_entry" in flat:
            statements.append(flat)

    event.listen(Engine, "before_cursor_execute", capture)
    try:
        entries, _, _ = await _collect_lists(db_session, [a])
    finally:
        event.remove(Engine, "before_cursor_execute", capture)

    assert [e.domain for e in entries] == ["one.example", "two.example"]
    assert len(statements) == 1, statements
    selected = statements[0][len("SELECT ") : statements[0].index(" FROM ")]
    assert [c.strip() for c in selected.split(",")] == [
        "dns_blocklist_entry.domain",
        "dns_blocklist_entry.entry_type",
        "dns_blocklist_entry.target",
        "dns_blocklist_entry.is_wildcard",
    ], selected


@pytest.mark.asyncio
async def test_a_disabled_list_contributes_nothing(db_session: AsyncSession) -> None:
    a = await _list(db_session, "nxdomain", ["x.example"])
    a.enabled = False
    await db_session.flush()
    assert await _collect_lists(db_session, [a]) == ([], set(), [])


@pytest.mark.asyncio
async def test_entries_come_in_domain_order_not_insertion_order(
    db_session: AsyncSession,
) -> None:
    """Two reads in one session return the heap order twice, so comparing
    builds proves nothing; pin the order to one the heap cannot produce by
    accident (inserted in reverse)."""
    names = [f"h{i:02d}.example" for i in range(50)]
    a = await _list(db_session, "nxdomain", list(reversed(names)))
    entries, _, _ = await _collect_lists(db_session, [a])
    assert [e.domain for e in entries] == names


@pytest.mark.asyncio
async def test_group_lists_are_collected_in_a_stable_order(db_session: AsyncSession) -> None:
    """The ``blocklists`` relationship has no ``order_by``; the builder must
    not hand the collision winner (#878) to whatever order Postgres returns."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()
    lists = []
    for name in ("zz-last", "aa-first", "mm-middle"):
        bl = DNSBlockList(name=f"{name}-{uuid.uuid4().hex[:6]}", block_mode="nxdomain")
        bl.server_groups = [group]
        db_session.add(bl)
        lists.append(bl)
    await db_session.commit()

    eff = await build_effective_for_group(db_session, group.id)
    assert eff.lists == [bl.id for bl in sorted(lists, key=lambda b: b.name)]


@pytest.mark.asyncio
async def test_effective_endpoint_serialises_slotted_entries(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``EffectiveEntry`` is slotted, so it has no ``__dict__`` to splat."""
    user = User(
        username="eff1109",
        email="eff1109@example.com",
        display_name="eff1109",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    # Assigned while transient: on a persistent row the collection set would
    # lazy-load the old value, which the async session cannot do.
    bl = DNSBlockList(name=f"c-{uuid.uuid4().hex[:8]}", block_mode="nxdomain")
    bl.server_groups = [group]
    db_session.add_all([user, group, bl])
    await db_session.flush()
    db_session.add(
        DNSBlockListEntry(list_id=bl.id, domain="bad.example", entry_type="block", source="manual")
    )
    await db_session.commit()

    resp = await client.get(
        f"/api/v1/dns/blocklists/effective/group/{group.id}",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert resp.status_code == 200, resp.text
    [entry] = resp.json()["entries"]
    assert entry["domain"] == "bad.example" and entry["list_name"] == bl.name

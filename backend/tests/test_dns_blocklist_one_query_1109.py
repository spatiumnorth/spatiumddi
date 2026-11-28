"""Blocklist collection is one query per kind, not one per list (#1109).

``_collect_lists`` ran an entries query and an exceptions query for every
enabled list. These pin what the single-query form must not move (the list
order that decides which list wins a duplicate owner name, #878, and the
bytes the bundle's ETag is taken over) and that the number of statements no
longer follows the number of lists.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json

import pytest
from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSBlockList, DNSBlockListEntry, DNSBlockListException
from app.services.dns_blocklist import _collect_lists


async def _list(
    db: AsyncSession, name: str, mode: str, domains: list[str], **kw: object
) -> DNSBlockList:
    bl = DNSBlockList(name=name, block_mode=mode, **kw)
    db.add(bl)
    await db.flush()
    for d in domains:
        db.add(DNSBlockListEntry(list_id=bl.id, domain=d, entry_type="block", source="manual"))
    await db.flush()
    return bl


def _fingerprint(entries, exceptions, list_ids) -> str:  # noqa: ANN001
    # list ids are random per run; replace them by their position in list_ids.
    pos = {lid: i for i, lid in enumerate(list_ids)}
    rows = []
    for e in entries:
        d = dataclasses.asdict(e)
        d["list_id"] = pos[d["list_id"]]
        rows.append(d)
    blob = json.dumps(
        {"entries": rows, "exceptions": sorted(exceptions), "n": len(list_ids)},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


# Pinned against the per-list implementation, before the change.
PINNED = "b9d2352490dd547c44a6bba6d8a21fa7df885d052fb9dcbd8d0d33d757d10077"


@pytest.mark.asyncio
async def test_collision_winner_and_fingerprint_are_pinned(db_session: AsyncSession) -> None:
    b = await _list(
        db_session,
        "b-sink",
        "sinkhole",
        ["dup.example", "b-only.example", "y.example"],
        sinkhole_ip="192.0.2.1",
    )
    a = await _list(db_session, "a-nx", "nxdomain", ["dup.example", "a-only.example", "m.example"])
    c = await _list(db_session, "c-nx", "nxdomain", ["dup.example", "c-only.example"])
    db_session.add(DNSBlockListException(list_id=a.id, domain="Allowed.example"))
    db_session.add(DNSBlockListException(list_id=c.id, domain="other.example"))
    await db_session.flush()

    entries, exceptions, ids = await _collect_lists(db_session, [b, a, c])
    assert ids == [b.id, a.id, c.id]
    # Caller order, then domain order within a list; the first writer of
    # ``dup.example`` is the sinkhole list.
    assert [e.list_name for e in entries if e.domain == "dup.example"] == [
        "b-sink",
        "a-nx",
        "c-nx",
    ]
    assert [e.domain for e in entries] == [
        "b-only.example",
        "dup.example",
        "y.example",
        "a-only.example",
        "dup.example",
        "m.example",
        "c-only.example",
        "dup.example",
    ]
    assert exceptions == {"allowed.example", "other.example"}
    assert _fingerprint(entries, exceptions, ids) == PINNED


@pytest.mark.asyncio
async def test_statement_count_does_not_follow_list_count(db_session: AsyncSession) -> None:
    lists = [await _list(db_session, f"n-{i:02d}", "nxdomain", [f"d{i}.example"]) for i in range(8)]
    counts: list[int] = []

    def capture(conn, cursor, statement, parameters, context, executemany):  # noqa: ANN001
        if "dns_blocklist_" in statement:
            counts.append(1)

    async def run(subset: list[DNSBlockList]) -> int:
        counts.clear()
        event.listen(Engine, "before_cursor_execute", capture)
        try:
            await _collect_lists(db_session, subset)
        finally:
            event.remove(Engine, "before_cursor_execute", capture)
        return len(counts)

    one = await run(lists[:1])
    many = await run(lists)
    assert many == one, (one, many)
    assert many <= 2

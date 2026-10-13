"""#1724: the blocklist API must not load a list's entries into the api.

Deleting a ~580k-entry catalog list, opening its entries page and a bulk
add each hydrated every entry as an ORM instance (OOM-kill on the api).
Memory must not follow list length; ``DNSBlockListEntry`` instance
creation/loading is the proxy (as in #1466's refresh test).
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSBlockList, DNSBlockListEntry, DNSBlockListException


@contextlib.contextmanager
def _count_entry_instances() -> Iterator[dict[str, int]]:
    counts = {"init": 0, "load": 0}

    def _init(*_a: object, **_k: object) -> None:
        counts["init"] += 1

    def _load(*_a: object, **_k: object) -> None:
        counts["load"] += 1

    event.listen(DNSBlockListEntry, "init", _init)
    event.listen(DNSBlockListEntry, "load", _load)
    try:
        yield counts
    finally:
        event.remove(DNSBlockListEntry, "init", _init)
        event.remove(DNSBlockListEntry, "load", _load)


async def _headers(db: AsyncSession) -> dict[str, str]:
    u = User(
        username="bl1724",
        email="bl1724@example.com",
        display_name="bl1724",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _seed(db: AsyncSession, n: int) -> DNSBlockList:
    bl = DNSBlockList(name="big", entry_count=n)
    db.add(bl)
    await db.flush()
    await db.execute(
        DNSBlockListEntry.__table__.insert(),
        [
            {"list_id": bl.id, "domain": f"d{i}.example", "entry_type": "block", "source": "feed"}
            for i in range(n)
        ],
    )
    db.add(DNSBlockListException(list_id=bl.id, domain="ok.example"))
    await db.commit()
    db.expunge_all()
    return bl


@pytest.mark.asyncio
async def test_delete_never_loads_entries(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    bl = await _seed(db_session, 300)
    bl_id = bl.id
    with _count_entry_instances() as counts:
        resp = await client.delete(f"/api/v1/dns/blocklists/{bl_id}", headers=headers)
    assert resp.status_code == 204, resp.text
    assert counts == {"init": 0, "load": 0}
    db_session.expunge_all()
    # The DB cascade still removed the children.
    assert (
        await db_session.execute(
            select(func.count())
            .select_from(DNSBlockListEntry)
            .where(DNSBlockListEntry.list_id == bl_id)
        )
    ).scalar_one() == 0
    assert (
        await db_session.execute(
            select(func.count())
            .select_from(DNSBlockListException)
            .where(DNSBlockListException.list_id == bl_id)
        )
    ).scalar_one() == 0
    # One audit row for the list, not one per entry.
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "dns_blocklist")
            )
        )
        .scalars()
        .all()
    )
    assert [r.action for r in rows] == ["delete"]


@pytest.mark.asyncio
async def test_entries_page_counts_in_db(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    bl = await _seed(db_session, 300)
    with _count_entry_instances() as counts:
        resp = await client.get(f"/api/v1/dns/blocklists/{bl.id}/entries?limit=5", headers=headers)
        filt = await client.get(
            f"/api/v1/dns/blocklists/{bl.id}/entries?limit=5&q=d29", headers=headers
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 300 and len(body["items"]) == 5
    assert filt.json()["total"] == 11  # d29, d290-d299
    # Only the 5-row pages are materialised.
    assert counts["load"] == 5 + 5 and counts["init"] == 0


def _entry_domain_reads(statement: str) -> bool:
    """A SELECT of entry domains (the bulk diff), as opposed to an INSERT."""
    st = statement.lstrip().upper()
    return st.startswith("SELECT") and "DNS_BLOCKLIST_ENTRY.DOMAIN" in st


@contextlib.contextmanager
def _capture_entry_reads(db: AsyncSession) -> Iterator[list[str]]:
    reads: list[str] = []

    def _before(conn, cursor, statement, params, context, executemany):  # type: ignore[no-untyped-def]
        if _entry_domain_reads(statement):
            reads.append(statement)

    engine = db.get_bind()
    sync_engine = getattr(engine, "sync_engine", engine)
    event.listen(sync_engine, "before_cursor_execute", _before)
    try:
        yield reads
    finally:
        event.remove(sync_engine, "before_cursor_execute", _before)


@pytest.mark.asyncio
async def test_bulk_add_diffs_only_incoming(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    bl = await _seed(db_session, 300)
    with _capture_entry_reads(db_session) as reads:
        resp = await client.post(
            f"/api/v1/dns/blocklists/{bl.id}/entries/bulk",
            json={"domains": ["d1.example", "new1.example", "new2.example", "d2.example"]},
            headers=headers,
        )
    assert resp.status_code in (200, 201), resp.text
    assert resp.json()["added"] == 2
    assert reads, "the diff must query the entries table"
    # Every domain read is filtered to the incoming batch; none reads the list.
    for st in reads:
        assert " IN " in st.upper() or "ANY" in st.upper(), st
    refreshed = await db_session.get(DNSBlockList, bl.id)
    await db_session.refresh(refreshed)
    assert refreshed is not None and refreshed.entry_count == 302


@pytest.mark.asyncio
async def test_bulk_add_chunk_boundary_duplicates_and_case(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Existing domains past the first 5000-domain chunk are still found,
    in-payload duplicates and case/trailing-dot variants collapse, and
    ``entry_count`` moves by exactly the rows inserted."""
    headers = await _headers(db_session)
    bl = await _seed(db_session, 300)
    fresh = [f"n{i}.example" for i in range(5100)]
    # d5 / d250 sit after the 5000-domain chunk boundary in the payload.
    payload = fresh[:5000] + ["D5.EXAMPLE.", "d250.example"] + fresh[5000:]
    payload += ["N1.example", "n1.example.", "n5050.example"]  # dupes of fresh
    with _capture_entry_reads(db_session) as reads:
        resp = await client.post(
            f"/api/v1/dns/blocklists/{bl.id}/entries/bulk",
            json={"domains": payload},
            headers=headers,
        )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    assert body["added"] == 5100
    assert body["skipped"] == len(payload) - 5100
    assert len(reads) == 2  # ceil(5102 / 5000) chunked reads
    db_session.expunge_all()
    total = (
        await db_session.execute(
            select(func.count())
            .select_from(DNSBlockListEntry)
            .where(DNSBlockListEntry.list_id == bl.id)
        )
    ).scalar_one()
    assert total == 5400
    refreshed = await db_session.get(DNSBlockList, bl.id)
    assert refreshed is not None and refreshed.entry_count == 5400

"""An orphan's withdrawn aliases follow the address, not the Trash (#3189).

Mark as Orphan soft-deletes the address's aliases (#2604). The Trash listed
them as plain DNS Record rows: Restore served the alias while its host was
withdrawn, and Delete permanently lost it for good. While the address is an
orphan the Trash neither lists them nor acts on them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.tasks.trash_purge import _purge_dns_records
from tests.test_ipam_alias_cname_exclusive_2080 import _setup
from tests.test_ipam_orphan_aliases_2604 import (
    _alias_names,
    _aliased,
    _all_alias_rows,
    _live_zone,
)


async def _orphaned(client: AsyncClient, db: AsyncSession, addr: str):  # type: ignore[no-untyped-def]
    headers, sid, zone = await _setup(client, db)
    ip_id = await _aliased(client, headers, sid, addr)
    d = await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    assert d.status_code == 204, d.text
    rows = await _all_alias_rows(db, ip_id)
    assert rows and all(r.deleted_at is not None for r in rows)
    return headers, sid, zone, ip_id, rows


async def _trash_ids(client: AsyncClient, headers: dict[str, str]) -> set[str]:
    r = await client.get("/api/v1/admin/trash?type=dns_record&limit=200", headers=headers)
    assert r.status_code == 200, r.text
    return {i["id"] for i in r.json()["items"]}


@pytest.mark.asyncio
async def test_trash_does_not_list_withdrawn_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _sid, _zone, _ip, rows = await _orphaned(client, db_session, "10.98.5.21")
    assert not ({str(r.id) for r in rows} & await _trash_ids(client, headers))


@pytest.mark.asyncio
async def test_restore_of_a_withdrawn_alias_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _sid, zone, ip_id, rows = await _orphaned(client, db_session, "10.98.5.22")
    zone_id = zone.id
    r = await client.post(f"/api/v1/admin/trash/dns_record/{rows[0].id}/restore", headers=headers)
    assert r.status_code == 409, r.text
    assert "orphan" in r.text
    # The refusal names the address the alias follows.
    assert "10.98.5.22" in r.json()["detail"]
    await db_session.rollback()
    assert await _live_zone(db_session, zone_id) == []
    assert await _alias_names(client, headers, ip_id) == []


@pytest.mark.asyncio
async def test_permanent_delete_of_a_withdrawn_alias_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _sid, _zone, ip_id, rows = await _orphaned(client, db_session, "10.98.5.23")
    r = await client.delete(f"/api/v1/admin/trash/dns_record/{rows[0].id}", headers=headers)
    assert r.status_code == 409, r.text
    await db_session.rollback()
    assert len(await _all_alias_rows(db_session, ip_id)) == len(rows)
    # ...and un-orphaning still brings them all back.
    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"status": "allocated"}
    )
    assert p.status_code == 200, p.text
    assert await _alias_names(client, headers, ip_id) == ["ftp", "www"]


@pytest.mark.asyncio
async def test_after_un_orphaning_nothing_is_left_in_the_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _sid, _zone, ip_id, rows = await _orphaned(client, db_session, "10.98.5.24")
    p = await client.put(
        f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"status": "allocated"}
    )
    assert p.status_code == 200, p.text
    assert not ({str(r.id) for r in rows} & await _trash_ids(client, headers))


@pytest.mark.asyncio
async def test_permanent_delete_of_the_address_purges_its_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _sid, _zone, ip_id, rows = await _orphaned(client, db_session, "10.98.5.25")
    d = await client.delete(f"/api/v1/ipam/addresses/{ip_id}?permanent=true", headers=headers)
    assert d.status_code == 204, d.text
    assert await _all_alias_rows(db_session, ip_id) == []
    assert not ({str(r.id) for r in rows} & await _trash_ids(client, headers))


@pytest.mark.asyncio
async def test_a_hand_trashed_record_still_restores(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Control: a record trashed on its own is an ordinary Trash row."""
    headers, sid, _zone = await _setup(client, db_session)
    ip_id = await _aliased(client, headers, sid, "10.98.5.26")
    rows = await _all_alias_rows(db_session, ip_id)
    rec = rows[0]
    d = await client.delete(
        f"/api/v1/dns/groups/{_zone.group_id}/zones/{rec.zone_id}/records/{rec.id}", headers=headers
    )
    assert d.status_code in (200, 204), d.text
    assert str(rec.id) in await _trash_ids(client, headers)
    r = await client.post(f"/api/v1/admin/trash/dns_record/{rec.id}/restore", headers=headers)
    assert r.status_code == 200, r.text


async def _hand_trashed_then_orphaned(  # type: ignore[no-untyped-def]
    client: AsyncClient, db: AsyncSession, addr: str
):
    """An alias the operator trashed by hand while the address was live, after
    which the address was marked as orphan. It is not one the orphan withdrew:
    the address's Restore does not bring it back (#2604 restores the orphan
    batch only), so it must stay an ordinary Trash row."""
    headers, sid, zone = await _setup(client, db)
    ip_id = await _aliased(client, headers, sid, addr)
    rows = await _all_alias_rows(db, ip_id)
    hand = next(r for r in rows if r.name == "www")
    d = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{hand.zone_id}/records/{hand.id}",
        headers=headers,
    )
    assert d.status_code in (200, 204), d.text
    o = await client.delete(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    assert o.status_code == 204, o.text
    withdrawn = next(r for r in rows if r.name == "ftp")
    return headers, ip_id, hand.id, withdrawn.id


@pytest.mark.asyncio
async def test_an_alias_trashed_by_hand_before_the_orphan_stays_a_trash_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _ip, hand_id, withdrawn_id = await _hand_trashed_then_orphaned(
        client, db_session, "10.98.5.27"
    )
    listed = await _trash_ids(client, headers)
    assert str(hand_id) in listed
    assert str(withdrawn_id) not in listed
    r = await client.delete(f"/api/v1/admin/trash/dns_record/{hand_id}", headers=headers)
    assert r.status_code == 204, r.text


@pytest.mark.asyncio
async def test_retention_purge_holds_only_what_the_orphan_withdrew(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _headers, ip_id, hand_id, withdrawn_id = await _hand_trashed_then_orphaned(
        client, db_session, "10.98.5.28"
    )
    # A cutoff past every stamp: anything not held back would go.
    await _purge_dns_records(db_session, datetime.now(UTC) + timedelta(days=1), set())
    await db_session.commit()
    left = {r.id for r in await _all_alias_rows(db_session, ip_id)}
    assert withdrawn_id in left
    assert hand_id not in left

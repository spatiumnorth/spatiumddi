"""Sync DNS drift reads an address in every zone it publishes to (#2107).

An address with ``extra_zone_ids`` has its host A in its forward zone AND in
each extra zone IPAM authors. The drift check compared every forward record
against the forward zone alone, so a correct record in an extra zone read as
``mismatched``.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSZone
from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _setup
from tests.test_ipam_alias_marker_2084 import _extra_zone, _rows


async def _preview(client: AsyncClient, headers: dict[str, str], sid: str) -> dict[str, Any]:
    r = await client.get(f"/api/v1/ipam/subnets/{sid}/dns-sync/preview", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _fwd(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [i for i in items if i["record_type"] in ("A", "AAAA")]


async def _published(client: AsyncClient, db: AsyncSession, headers, sid, extra: DNSZone, zone):
    r = await _alloc(client, headers, sid, "10.98.5.20", "h1", extra_zone_ids=[str(extra.id)])
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    rows = await _rows(db, ip_id)
    assert {x.zone_id for x in rows if x.record_type == "A"} == {zone.id, extra.id}
    return ip_id, rows


@pytest.mark.asyncio
async def test_a_correct_record_in_an_extra_zone_is_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    await _published(client, db_session, headers, sid, extra, zone)
    rep = await _preview(client, headers, sid)
    assert _fwd(rep["mismatched"]) == []
    assert _fwd(rep["missing"]) == []
    assert _fwd(rep["stale"]) == []

    # Committing the default selection (every mismatched row) changes nothing.
    n_ops = len((await db_session.execute(select(DNSRecordOp))).scalars().all())
    ids = [m["record_id"] for m in rep["mismatched"]]
    c = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={"update_record_ids": ids},
    )
    assert c.status_code == 200, c.text
    assert len((await db_session.execute(select(DNSRecordOp))).scalars().all()) == n_ops


@pytest.mark.asyncio
async def test_a_missing_extra_zone_record_reads_missing_in_that_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    ip_id, rows = await _published(client, db_session, headers, sid, extra, zone)
    gone = next(r for r in rows if r.zone_id == extra.id and r.record_type == "A")
    await db_session.delete(gone)
    await db_session.commit()

    rep = await _preview(client, headers, sid)
    assert _fwd(rep["mismatched"]) == []
    miss = _fwd(rep["missing"])
    assert [(m["zone_id"], m["expected_name"]) for m in miss] == [(str(extra.id), "h1")]

    c = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={"create_for_ip_ids": [ip_id]},
    )
    assert c.status_code == 200, c.text
    after = await _rows(db_session, ip_id)
    assert {x.zone_id for x in after if x.record_type == "A"} == {zone.id, extra.id}
    assert _fwd((await _preview(client, headers, sid))["missing"]) == []


@pytest.mark.asyncio
async def test_a_wrong_extra_zone_record_reads_mismatched_in_that_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    ip_id, rows = await _published(client, db_session, headers, sid, extra, zone)
    bad = next(r for r in rows if r.zone_id == extra.id and r.record_type == "A")
    bad.value = "10.98.5.99"
    await db_session.commit()

    rep = await _preview(client, headers, sid)
    mm = _fwd(rep["mismatched"])
    assert [(m["record_id"], m["zone_id"], m["zone_name"]) for m in mm] == [
        (str(bad.id), str(extra.id), extra.name)
    ]
    assert mm[0]["expected_value"] == "10.98.5.20"
    assert _fwd(rep["missing"]) == []

    c = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={"update_record_ids": [str(bad.id)]},
    )
    assert c.status_code == 200, c.text
    after = await _rows(db_session, ip_id)
    assert sorted((str(x.zone_id), x.value) for x in after if x.record_type == "A") == sorted(
        [(str(zone.id), "10.98.5.20"), (str(extra.id), "10.98.5.20")]
    )
    assert _fwd((await _preview(client, headers, sid))["mismatched"]) == []


@pytest.mark.asyncio
async def test_a_zone_ipam_does_not_author_takes_no_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    extra.zone_type = "forward"
    await db_session.commit()
    r = await _alloc(client, headers, sid, "10.98.5.21", "h2", extra_zone_ids=[str(extra.id)])
    assert r.status_code == 201, r.text
    rep = await _preview(client, headers, sid)
    assert _fwd(rep["missing"]) == [] and _fwd(rep["mismatched"]) == []

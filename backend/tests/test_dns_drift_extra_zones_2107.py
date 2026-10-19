"""Sync DNS drift reads an address in every zone it publishes to (#2107).

An address with ``extra_zone_ids`` has its host A in its forward zone AND in
each extra zone IPAM authors. The drift check compared every forward record
against the forward zone alone, so a correct record in an extra zone read as
``mismatched``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSZone
from app.models.ipam import IPAddress
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


# ── Validation cases ─────────────────────────────────────────────────────────


async def _ip(db: AsyncSession, ip_id: str) -> IPAddress:
    return (
        await db.execute(
            select(IPAddress)
            .where(IPAddress.id == uuid.UUID(ip_id))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def _commit(client: AsyncClient, headers, sid: str, rep: dict[str, Any]) -> None:
    """Commit the dialog's default selection: every row of every section."""
    c = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={
            "create_for_ip_ids": sorted({m["ip_id"] for m in rep["missing"]}),
            "update_record_ids": [m["record_id"] for m in rep["mismatched"]],
            "delete_stale_record_ids": [s["record_id"] for s in rep["stale"]],
        },
    )
    assert c.status_code == 200, c.text
    assert c.json().get("errors", []) == [], c.text


@pytest.mark.asyncio
async def test_an_extra_zone_equal_to_the_primary_is_one_record_in_sync(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    r = await _alloc(client, headers, sid, "10.98.5.22", "h3", extra_zone_ids=[str(zone.id)])
    assert r.status_code == 201, r.text
    rows = await _rows(db_session, r.json()["id"])
    assert [x.zone_id for x in rows if x.record_type == "A"] == [zone.id]
    rep = await _preview(client, headers, sid)
    assert _fwd(rep["missing"]) == [] and _fwd(rep["mismatched"]) == []
    assert _fwd(rep["stale"]) == []


@pytest.mark.asyncio
async def test_extra_zone_ids_are_matched_as_uuids_not_strings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An upper-case or braced UUID string reads as the same zone in the drift
    check and in the sync, so neither reports nor retracts the record."""
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    ip_id, _ = await _published(client, db_session, headers, sid, extra, zone)
    ip = await _ip(db_session, ip_id)
    ip.extra_zone_ids = ["{" + str(extra.id).upper() + "}", "not-a-uuid"]
    await db_session.commit()

    rep = await _preview(client, headers, sid)
    assert _fwd(rep["missing"]) == [] and _fwd(rep["mismatched"]) == []
    assert _fwd(rep["stale"]) == []
    # A re-sync of the address keeps the extra-zone record.
    c = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={"create_for_ip_ids": [ip_id]},
    )
    assert c.status_code == 200, c.text
    after = await _rows(db_session, ip_id)
    assert {x.zone_id for x in after if x.record_type == "A"} == {zone.id, extra.id}


@pytest.mark.asyncio
async def test_missing_in_two_zones_is_two_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    ip_id, rows = await _published(client, db_session, headers, sid, extra, zone)
    for r in rows:
        if r.record_type == "A":
            await db_session.delete(r)
    await db_session.commit()

    rep = await _preview(client, headers, sid)
    assert sorted(m["zone_id"] for m in _fwd(rep["missing"])) == sorted(
        [str(zone.id), str(extra.id)]
    )
    await _commit(client, headers, sid, rep)
    after = await _rows(db_session, ip_id)
    assert {x.zone_id for x in after if x.record_type == "A"} == {zone.id, extra.id}
    rep2 = await _preview(client, headers, sid)
    assert _fwd(rep2["missing"]) == [] and _fwd(rep2["mismatched"]) == []


@pytest.mark.asyncio
async def test_a_record_left_in_a_former_extra_zone_is_listed_and_retracted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``extra_zone_ids`` lost a zone without a sync (an import, a restore):
    the record still there is drift, and committing it retracts it with an op,
    as ``_sync_dns_record`` Phase 1 does, and leaves the primary alone."""
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    ip_id, rows = await _published(client, db_session, headers, sid, extra, zone)
    left = next(r for r in rows if r.zone_id == extra.id and r.record_type == "A")
    keep = next(r for r in rows if r.zone_id == zone.id and r.record_type == "A")
    ip = await _ip(db_session, ip_id)
    ip.extra_zone_ids = []
    await db_session.commit()

    rep = await _preview(client, headers, sid)
    listed = [m["record_id"] for m in _fwd(rep["mismatched"])] + [
        s["record_id"] for s in _fwd(rep["stale"])
    ]
    assert listed == [str(left.id)]
    assert _fwd(rep["missing"]) == []

    await _commit(client, headers, sid, rep)
    after = await _rows(db_session, ip_id)
    assert [(x.id, x.zone_id) for x in after if x.record_type == "A"] == [(keep.id, zone.id)]
    ops = (
        (await db_session.execute(select(DNSRecordOp).where(DNSRecordOp.zone_id == extra.id)))
        .scalars()
        .all()
    )
    assert any(o.op == "delete" and o.record.get("name") == "h1" for o in ops)


@pytest.mark.asyncio
async def test_committing_an_extra_zone_row_leaves_the_aliases(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, zone = await _setup(client, db_session)
    extra = await _extra_zone(db_session, zone)
    r = await _alloc(
        client,
        headers,
        sid,
        "10.98.5.23",
        "h4",
        extra_zone_ids=[str(extra.id)],
        aliases=[{"name": "www4", "record_type": "A"}],
    )
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    rows = await _rows(db_session, ip_id)
    aliases = sorted((x.id, x.zone_id, x.name, x.value) for x in rows if x.ip_alias)
    assert aliases, "the alias was not written"
    rep = await _preview(client, headers, sid)
    assert _fwd(rep["missing"]) == [] and _fwd(rep["mismatched"]) == []

    gone = next(x for x in rows if x.zone_id == extra.id and not x.ip_alias)
    gone.value = "10.98.5.98"
    await db_session.commit()
    rep = await _preview(client, headers, sid)
    assert [m["record_id"] for m in _fwd(rep["mismatched"])] == [str(gone.id)]
    await _commit(client, headers, sid, rep)

    after = await _rows(db_session, ip_id)
    assert sorted((x.id, x.zone_id, x.name, x.value) for x in after if x.ip_alias) == aliases
    assert sorted(
        (str(x.zone_id), x.value) for x in after if not x.ip_alias and x.record_type == "A"
    ) == sorted([(str(zone.id), "10.98.5.23"), (str(extra.id), "10.98.5.23")])

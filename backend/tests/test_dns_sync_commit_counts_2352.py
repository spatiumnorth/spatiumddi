"""Sync DNS commit counts only what it wrote (#2352).

An address named in ``create_for_ip_ids`` whose forward A and PTR already
exist queues no DNS op, so the commit must not report it as ``created`` nor
write a ``dns-sync`` audit row claiming it was. All three scopes (subnet,
block, space) share the apply path.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dns import DNSRecord, DNSRecordOp
from app.models.ipam import Subnet
from tests.test_ipam_alias_cname_exclusive_2080 import _alloc, _setup
from tests.test_ipam_alias_marker_2084 import _rows


async def _n_ops(db: AsyncSession) -> int:
    return len((await db.execute(select(DNSRecordOp))).scalars().all())


async def _sync_audits(db: AsyncSession) -> list[AuditLog]:
    res = await db.execute(select(AuditLog).where(AuditLog.action == "dns-sync"))
    return list(res.scalars().all())


async def _scope_urls(db: AsyncSession, sid: str) -> dict[str, str]:
    import uuid

    sn = await db.get(Subnet, uuid.UUID(sid))
    assert sn is not None
    return {
        "subnet": f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        "block": f"/api/v1/ipam/blocks/{sn.block_id}/dns-sync/commit",
        "space": f"/api/v1/ipam/spaces/{sn.space_id}/dns-sync/commit",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["subnet", "block", "space"])
async def test_an_address_whose_records_exist_counts_as_unchanged(
    client: AsyncClient, db_session: AsyncSession, scope: str
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    r = await _alloc(client, headers, sid, "10.98.5.20", "h1")
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    assert [x for x in await _rows(db_session, ip_id) if x.record_type == "A"]
    n_ops = await _n_ops(db_session)
    n_audits = len(await _sync_audits(db_session))

    url = (await _scope_urls(db_session, sid))[scope]
    c = await client.post(url, headers=headers, json={"create_for_ip_ids": [ip_id]})
    assert c.status_code == 200, c.text
    body = c.json()
    assert (body["created"], body["updated"], body["deleted"], body["errors"]) == (0, 0, 0, [])
    assert await _n_ops(db_session) == n_ops
    assert len(await _sync_audits(db_session)) == n_audits


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["subnet", "block", "space"])
async def test_an_address_missing_its_record_still_counts_as_created(
    client: AsyncClient, db_session: AsyncSession, scope: str
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    r = await _alloc(client, headers, sid, "10.98.5.21", "h2")
    assert r.status_code == 201, r.text
    ip_id = r.json()["id"]
    for row in await _rows(db_session, ip_id):
        if isinstance(row, DNSRecord) and row.record_type == "A":
            await db_session.delete(row)
    await db_session.commit()
    n_ops = await _n_ops(db_session)

    url = (await _scope_urls(db_session, sid))[scope]
    c = await client.post(url, headers=headers, json={"create_for_ip_ids": [ip_id]})
    assert c.status_code == 200, c.text
    body = c.json()
    assert (body["created"], body["errors"]) == (1, [])
    assert await _n_ops(db_session) > n_ops
    audits = await _sync_audits(db_session)
    assert audits and audits[-1].new_value["created"] == 1


@pytest.mark.asyncio
async def test_only_the_missing_address_of_two_is_counted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, _zone = await _setup(client, db_session)
    ok = (await _alloc(client, headers, sid, "10.98.5.30", "ok")).json()["id"]
    gap = (await _alloc(client, headers, sid, "10.98.5.31", "gap")).json()["id"]
    for row in await _rows(db_session, gap):
        if row.record_type == "A":
            await db_session.delete(row)
    await db_session.commit()

    c = await client.post(
        f"/api/v1/ipam/subnets/{sid}/dns-sync/commit",
        headers=headers,
        json={"create_for_ip_ids": [ok, gap]},
    )
    assert c.status_code == 200, c.text
    assert (c.json()["created"], c.json()["updated"]) == (1, 0)

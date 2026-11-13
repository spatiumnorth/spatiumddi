"""#3920 — a record restored from the Trash into a zone that was pinned to
another view in the meantime is refused, as the record API and #3839's re-pin
check refuse the same state."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSView
from tests.test_dnssec_single_signer import _group, _headers, _zone


async def _setup(client, db, headers):
    g, _ = await _group(db, servers=1)
    va = DNSView(group_id=g.id, name="viewa")
    vb = DNSView(group_id=g.id, name="viewb")
    db.add_all([va, vb])
    z = _zone(g.id, name=f"t{uuid.uuid4().hex[:6]}.example.")
    db.add(z)
    await db.commit()
    base = f"/api/v1/dns/groups/{g.id}/zones/{z.id}"
    ids = []
    for view, ip in ((va, "192.0.2.41"), (vb, "192.0.2.42")):
        r = await client.post(
            f"{base}/records",
            headers=headers,
            json={
                "name": "www",
                "record_type": "A",
                "value": ip,
                "view_id": str(view.id),
            },
        )
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    return g, z, va, vb, base, ids


@pytest.mark.asyncio
async def test_restore_into_zone_pinned_to_another_view_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    g, z, va, vb, base, ids = await _setup(client, db_session, headers)
    assert (await client.delete(f"{base}/records/{ids[1]}", headers=headers)).status_code == 204
    r = await client.put(base, headers=headers, json={"view_id": str(va.id)})
    assert r.status_code == 200, r.text

    resp = await client.post(f"/api/v1/admin/trash/dns_record/{ids[1]}/restore", headers=headers)
    assert resp.status_code == 409, resp.text
    reason = resp.json()["detail"]["conflicts"][0]["reason"]
    assert "viewb" in reason and "viewa" in reason

    live = await client.get(f"{base}/records", headers=headers)
    assert ids[1] not in live.text


@pytest.mark.asyncio
async def test_restore_into_matching_or_unpinned_zone_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    g, z, va, vb, base, ids = await _setup(client, db_session, headers)
    for rid in ids:
        assert (await client.delete(f"{base}/records/{rid}", headers=headers)).status_code == 204
    # Pinned to view A: the view-A record restores, the view-B one is refused.
    assert (
        await client.put(base, headers=headers, json={"view_id": str(va.id)})
    ).status_code == 200
    ok = await client.post(f"/api/v1/admin/trash/dns_record/{ids[0]}/restore", headers=headers)
    assert ok.status_code == 200, ok.text
    # Unpinning the zone lets the other one back.
    assert (await client.put(base, headers=headers, json={"view_id": None})).status_code == 200
    ok = await client.post(f"/api/v1/admin/trash/dns_record/{ids[1]}/restore", headers=headers)
    assert ok.status_code == 200, ok.text

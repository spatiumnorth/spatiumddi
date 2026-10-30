"""Sync DNS leaves an unticked mismatched record as it is (#3081).

#2471 held back the unticked *Missing* rows. A hand-edited (Mismatched) record
whose address had another row ticked was still rewritten, because the commit
re-syncs an address whole. ``update_record_ids`` now names exactly the existing
records to change; every other record of a synced address keeps its value. Run
at subnet, block and space scope; these read the DNS rows back, not the request.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_dns_sync_address_zone_2104 import _new_zone, _rows, _setup

_HAND_A = "10.104.5.99"


async def _drifted(
    client: AsyncClient, db: AsyncSession, with_extra: bool = False
) -> tuple[Any, str, dict[str, Any], Any]:
    env = await _setup(client, db)
    extra = None
    body: dict[str, Any] = {"address": "10.104.5.40", "hostname": "h3081"}
    if with_extra:
        extra = await _new_zone(db, env.zone.group_id, "x")
        await db.commit()
        body["extra_zone_ids"] = [str(extra.id)]
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.sid}/addresses", headers=env.headers, json=body
    )
    assert r.status_code == 201, r.text
    ip_id = str(r.json()["id"])
    recs: dict[str, Any] = {}
    for rec in await _rows(db, ip_id):
        if rec.record_type == "PTR":
            rec.value = "h3081-hand.example."
            recs["PTR"] = rec
        elif rec.zone_id == env.zone.id:
            rec.value = _HAND_A
            recs["A"] = rec
        else:
            rec.value = "10.104.5.98"
            recs["XA"] = rec
    await db.commit()
    return env, ip_id, recs, extra


async def _values(db: AsyncSession, env: Any, ip_id: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for rec in await _rows(db, ip_id):
        key = "PTR" if rec.record_type == "PTR" else ("A" if rec.zone_id == env.zone.id else "XA")
        out[key] = rec.value
    return out


async def _commit(
    client: AsyncClient, env: Any, scope: str, ids: list[uuid.UUID]
) -> dict[str, Any]:
    path = {
        "subnet": f"/api/v1/ipam/subnets/{env.sid}",
        "block": f"/api/v1/ipam/blocks/{env.block_id}",
        "space": f"/api/v1/ipam/spaces/{env.space_id}",
    }[scope]
    c = await client.post(
        f"{path}/dns-sync/commit",
        headers=env.headers,
        json={"update_record_ids": [str(i) for i in ids]},
    )
    assert c.status_code == 200, c.text
    assert c.json()["errors"] == [], c.text
    return c.json()  # type: ignore[no-any-return]


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["subnet", "block", "space"])
async def test_ticked_a_leaves_an_unticked_ptr(
    client: AsyncClient, db_session: AsyncSession, scope: str
) -> None:
    env, ip_id, recs, _ = await _drifted(client, db_session)
    res = await _commit(client, env, scope, [recs["A"].id])
    vals = await _values(db_session, env, ip_id)
    assert vals["A"] == "10.104.5.40"  # ticked: corrected
    assert vals["PTR"] == "h3081-hand.example."  # unticked: the hand edit stays
    assert res["updated"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["subnet", "block", "space"])
async def test_both_ticked_corrects_both(
    client: AsyncClient, db_session: AsyncSession, scope: str
) -> None:
    env, ip_id, recs, _ = await _drifted(client, db_session)
    await _commit(client, env, scope, [recs["A"].id, recs["PTR"].id])
    vals = await _values(db_session, env, ip_id)
    assert vals["A"] == "10.104.5.40"
    assert vals["PTR"] == "h3081.example." or vals["PTR"].startswith("h3081.")


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["subnet", "block", "space"])
async def test_ticked_ptr_leaves_an_unticked_a(
    client: AsyncClient, db_session: AsyncSession, scope: str
) -> None:
    env, ip_id, recs, _ = await _drifted(client, db_session)
    await _commit(client, env, scope, [recs["PTR"].id])
    vals = await _values(db_session, env, ip_id)
    assert vals["A"] == _HAND_A
    assert vals["PTR"].startswith("h3081.")


@pytest.mark.asyncio
async def test_ticked_extra_zone_a_leaves_unticked_a_and_ptr(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env, ip_id, recs, _ = await _drifted(client, db_session, with_extra=True)
    await _commit(client, env, "subnet", [recs["XA"].id])
    vals = await _values(db_session, env, ip_id)
    assert vals["XA"] == "10.104.5.40"
    assert vals["A"] == _HAND_A
    assert vals["PTR"] == "h3081-hand.example."

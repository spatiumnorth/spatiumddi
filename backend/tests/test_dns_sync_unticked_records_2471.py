"""Sync DNS writes only the records the operator left ticked (#2471).

The dialog lists an address's A, its PTR and each extra-zone A as separate
rows, each with its own tick, but the commit sends addresses and the API
re-syncs an address whole. Unticking the PTR of an address whose A stayed
ticked wrote the PTR anyway. The commit now carries the unticked rows in
``skip_records``; these tests read the DNS rows back, not the request.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from tests.test_dns_sync_address_zone_2104 import _new_zone, _rows, _setup  # noqa: F401


async def _missing_address(
    client: AsyncClient, db: AsyncSession, with_extra: bool = False
) -> tuple[Any, str, Any]:
    env = await _setup(client, db)
    extra = None
    body: dict[str, Any] = {"address": "10.104.5.30", "hostname": "h2471"}
    if with_extra:
        extra = await _new_zone(db, env.zone.group_id, "x")
        await db.commit()
        body["extra_zone_ids"] = [str(extra.id)]
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.sid}/addresses", headers=env.headers, json=body
    )
    assert r.status_code == 201, r.text
    ip_id = str(r.json()["id"])
    # Records missing, as after update_subnet gave the subnet its DNS settings.
    await db.execute(delete(DNSRecord).where(DNSRecord.ip_address_id == uuid.UUID(ip_id)))
    await db.commit()
    return env, ip_id, extra


async def _types(db: AsyncSession, ip_id: str) -> list[tuple[str, uuid.UUID]]:
    return sorted((r.record_type, r.zone_id) for r in await _rows(db, ip_id) if not r.ip_alias)


async def _commit(client: AsyncClient, env: Any, ip_id: str, skip: list[dict[str, str]]) -> None:
    c = await client.post(
        f"/api/v1/ipam/subnets/{env.sid}/dns-sync/commit",
        headers=env.headers,
        json={"create_for_ip_ids": [ip_id], "skip_records": skip},
    )
    assert c.status_code == 200, c.text
    assert c.json()["errors"] == [], c.text


async def _preview_rows(client: AsyncClient, env: Any, ip_id: str) -> list[dict[str, Any]]:
    r = await client.get(f"/api/v1/ipam/subnets/{env.sid}/dns-sync/preview", headers=env.headers)
    assert r.status_code == 200, r.text
    return [m for m in r.json()["missing"] if m["ip_id"] == ip_id]


@pytest.mark.asyncio
async def test_an_unticked_ptr_is_not_written(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env, ip_id, _ = await _missing_address(client, db_session)
    rows = await _preview_rows(client, env, ip_id)
    assert sorted(m["record_type"] for m in rows) == ["A", "PTR"]
    ptr = next(m for m in rows if m["record_type"] == "PTR")

    await _commit(
        client,
        env,
        ip_id,
        [{"ip_id": ip_id, "record_type": "PTR", "zone_id": ptr["zone_id"]}],
    )
    assert [t for t, _ in await _types(db_session, ip_id)] == ["A"]

    # Ticked again, the PTR is written: the skip, not the endpoint, held it back.
    await _commit(client, env, ip_id, [])
    assert [t for t, _ in await _types(db_session, ip_id)] == ["A", "PTR"]


@pytest.mark.asyncio
async def test_an_unticked_extra_zone_a_is_not_written(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env, ip_id, extra = await _missing_address(client, db_session, with_extra=True)
    await _commit(
        client,
        env,
        ip_id,
        [{"ip_id": ip_id, "record_type": "A", "zone_id": str(extra.id)}],
    )
    assert sorted(z for t, z in await _types(db_session, ip_id) if t == "A") == [env.zone.id]
    assert "PTR" in [t for t, _ in await _types(db_session, ip_id)]


@pytest.mark.asyncio
async def test_a_skip_for_one_address_leaves_another_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env, ip_id, _ = await _missing_address(client, db_session)
    rows = await _preview_rows(client, env, ip_id)
    ptr = next(m for m in rows if m["record_type"] == "PTR")
    await _commit(
        client,
        env,
        ip_id,
        [{"ip_id": str(uuid.uuid4()), "record_type": "PTR", "zone_id": ptr["zone_id"]}],
    )
    assert [t for t, _ in await _types(db_session, ip_id)] == ["A", "PTR"]

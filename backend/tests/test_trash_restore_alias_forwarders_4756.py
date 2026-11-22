"""#4756 — an ALIAS restored from the Trash into a PowerDNS group whose Do53
forwarders were cleared meanwhile is refused, as the record API refuses it."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_powerdns_alias_resolver import _setup

_ALIAS = {"name": "@", "record_type": "ALIAS", "value": "lb.example.net."}


async def _trashed_alias(client, db, forwarders):
    headers, url = await _setup(db, forwarders)
    r = await client.post(url, headers=headers, json=_ALIAS)
    assert r.status_code in (200, 201), r.text
    rid = r.json()["id"]
    assert (await client.delete(f"{url}/{rid}", headers=headers)).status_code == 204
    # Cleared while the record sits in the Trash: the options guard counts none.
    options_url = url.split("/zones/")[0] + "/options"
    r = await client.put(options_url, headers=headers, json={"forwarders": []})
    assert r.status_code == 200, r.text
    return headers, url, rid


@pytest.mark.asyncio
async def test_restore_alias_without_forwarders_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, url, rid = await _trashed_alias(client, db_session, ["10.0.0.53"])
    resp = await client.post(f"/api/v1/admin/trash/dns_record/{rid}/restore", headers=headers)
    assert resp.status_code == 409, resp.text
    assert "forwarders" in resp.json()["detail"]["conflicts"][0]["reason"]
    live = await client.get(url, headers=headers)
    assert rid not in live.text


@pytest.mark.asyncio
async def test_restore_alias_with_forwarders_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, url, rid = await _trashed_alias(client, db_session, ["10.0.0.53"])
    options_url = url.split("/zones/")[0] + "/options"
    r = await client.put(options_url, headers=headers, json={"forwarders": ["10.0.0.54"]})
    assert r.status_code == 200, r.text
    resp = await client.post(f"/api/v1/admin/trash/dns_record/{rid}/restore", headers=headers)
    assert resp.status_code == 200, resp.text

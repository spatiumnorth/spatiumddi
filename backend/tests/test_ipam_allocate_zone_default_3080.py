"""An allocation that names no zone publishes into the subnet's primary (#3080).

The Allocate IP and Bulk allocate dialogs now leave ``dns_zone_id`` out when
the operator made no choice, and rely on the server to fall back to the
subnet's effective zone. Only ``""`` (Allocate IP's "None") means no DNS. These
pin that contract on every allocate path the dialogs call.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_ipam_dns_publish_names_2918 import _env, _records

ZONE = "alloc3080.example.test"


@pytest.mark.asyncio
@pytest.mark.parametrize("zone_field", ["absent", "null"])
async def test_bulk_commit_without_zone_publishes_to_primary(
    client: AsyncClient, db_session: AsyncSession, zone_field: str
) -> None:
    env = await _env(db_session, ZONE)
    assert env.zone is not None
    body: dict[str, Any] = {
        "range_start": "10.91.1.200",
        "range_end": "10.91.1.202",
        "hostname_template": "h-{n}",
        "create_dns_records": True,
    }
    if zone_field == "null":
        body["dns_zone_id"] = None
    base = f"/api/v1/ipam/subnets/{env.subnet.id}/bulk-allocate"
    preview = await client.post(f"{base}/preview", json=body, headers=env.headers)
    assert preview.status_code == 200, preview.text
    r = await client.post(base, json=body, headers=env.headers)
    assert r.status_code in (200, 201), r.text
    assert await _records(db_session, env.zone) == 3


@pytest.mark.asyncio
async def test_bulk_commit_without_dns_records_publishes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    env = await _env(db_session, ZONE)
    assert env.zone is not None
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.subnet.id}/bulk-allocate",
        json={
            "range_start": "10.91.1.200",
            "range_end": "10.91.1.201",
            "hostname_template": "h-{n}",
            "create_dns_records": False,
        },
        headers=env.headers,
    )
    assert r.status_code in (200, 201), r.text
    assert await _records(db_session, env.zone) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(("zone_field", "expected"), [("absent", 1), ("empty", 0)])
async def test_next_allocate_absent_vs_empty_zone(
    client: AsyncClient, db_session: AsyncSession, zone_field: str, expected: int
) -> None:
    env = await _env(db_session, ZONE)
    assert env.zone is not None
    body: dict[str, Any] = {"hostname": "h1"}
    if zone_field == "empty":
        body["dns_zone_id"] = ""
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.subnet.id}/next", json=body, headers=env.headers
    )
    assert r.status_code in (200, 201), r.text
    assert await _records(db_session, env.zone) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("zone_field", "expected"), [("absent", 1), ("empty", 0)])
async def test_create_address_absent_vs_empty_zone(
    client: AsyncClient, db_session: AsyncSession, zone_field: str, expected: int
) -> None:
    env = await _env(db_session, ZONE)
    assert env.zone is not None
    body: dict[str, Any] = {
        "subnet_id": str(env.subnet.id),
        "address": "10.91.1.50",
        "hostname": "h1",
    }
    if zone_field == "empty":
        body["dns_zone_id"] = ""
    r = await client.post(
        f"/api/v1/ipam/subnets/{env.subnet.id}/addresses", json=body, headers=env.headers
    )
    assert r.status_code in (200, 201), r.text
    assert await _records(db_session, env.zone) == expected

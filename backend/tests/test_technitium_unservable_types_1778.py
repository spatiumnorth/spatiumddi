"""Record types Technitium can never serve (#1778).

LOC was accepted (201) on a Technitium group and the op then failed for good;
URI was advertised and imported though SpatiumDDI does not model it.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.technitium import TechnitiumDriver
from app.drivers.dns.technitium_api import TechnitiumAPIDriver
from app.services.dns_import.technitium import _build_imported_zone
from tests.test_dns_modern_record_types import _admin_headers, _group_with_driver


@pytest.mark.parametrize("driver", ["technitium", "technitium_api", "windows_dns", "cloudflare"])
async def test_loc_refused_on_groups_that_cannot_serve_it(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = await _admin_headers(db_session)
    grp, zone = await _group_with_driver(db_session, driver)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
        headers=h,
        json={"name": "site", "record_type": "LOC", "value": "37 23 30.900 N 121 59 19.000 W 7m"},
    )
    assert r.status_code == 422, r.text
    assert "LOC" in r.json()["detail"] and driver in r.json()["detail"]


@pytest.mark.parametrize("driver", ["bind9", "powerdns"])
async def test_loc_still_accepted_where_it_is_served(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    h = await _admin_headers(db_session)
    grp, zone = await _group_with_driver(db_session, driver)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records",
        headers=h,
        json={
            "name": f"s{uuid.uuid4().hex[:4]}",
            "record_type": "LOC",
            "value": "37 23 30.900 N 121 59 19.000 W 7m",
        },
    )
    assert r.status_code == 201, r.text


def test_technitium_drivers_do_not_advertise_unmodelled_uri() -> None:
    for drv in (TechnitiumDriver(), TechnitiumAPIDriver()):
        types = drv.capabilities()["record_types"]
        assert "URI" not in types
        assert "LOC" not in types


def test_importer_reports_uri_as_skipped() -> None:
    zone = _build_imported_zone(
        "example.test",
        [
            {
                "name": "u.example.test",
                "type": "URI",
                "ttl": 300,
                "rData": {"priority": 1, "weight": 1, "uri": "https://example.test/"},
            },
            {"name": "a.example.test", "type": "A", "ttl": 300, "rData": {"ipAddress": "10.0.0.1"}},
        ],
    )
    assert [r.record_type for r in zone.records] == ["A"]
    assert any("URI×1" in w for w in zone.parse_warnings)

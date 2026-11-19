"""spatiumddi#3297 — a cleared hostname leaves no stale FQDN on any reader.

Clearing a hostname keeps ``ip_address.fqdn`` stored (the orphan restore needs
it), so every reader that presents the name as current has to key on the
hostname. Each test clears the name through the API and then reads through
its own path.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.auth import User
from app.models.ipam import IPAddress
from app.services.ai.tools import REGISTRY
from app.services.tls_cert.discovery import _host_for_ip
from tests.test_subnet_trash_retracts_dns_1906 import _address, _admin_headers, _setup

STALE = "gone-host.example.com"


async def _cleared(client: AsyncClient, db: AsyncSession, base: str, cidr: str, addr: str):  # type: ignore[no-untyped-def]
    """An address that published ``gone-host`` and then had its name cleared."""
    headers = await _admin_headers(db)
    _grp, _server, zone, sid, _ = await _setup(client, db, headers, cidr, None, base)
    ip_id = await _address(client, headers, sid, addr, "gone-host")
    r = await client.put(f"/api/v1/ipam/addresses/{ip_id}", headers=headers, json={"hostname": ""})
    assert r.status_code == 200, r.text
    row = (await db.execute(select(IPAddress).where(IPAddress.id == uuid.UUID(ip_id)))).scalar_one()
    await db.refresh(row)
    # Precondition: the stored name survives, which is what the restore needs.
    assert row.hostname in (None, "")
    assert row.fqdn == f"gone-host.{zone.name.rstrip('.')}"
    return headers, sid, ip_id, row, r


@pytest.mark.asyncio
async def test_address_read_and_update_response_carry_no_fqdn(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, ip_id, _row, put = await _cleared(
        client, db_session, "10.171.0.0/16", "10.171.1.0/24", "10.171.1.10"
    )
    assert put.json()["fqdn"] is None
    got = await client.get(f"/api/v1/ipam/addresses/{ip_id}", headers=headers)
    assert got.json()["fqdn"] is None
    lst = await client.get(f"/api/v1/ipam/subnets/{sid}/addresses", headers=headers)
    assert [a["fqdn"] for a in lst.json() if a["id"] == ip_id] == [None]


@pytest.mark.asyncio
async def test_address_search_does_not_match_the_stale_fqdn(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, _sid, ip_id, _row, _ = await _cleared(
        client, db_session, "10.172.0.0/16", "10.172.1.0/24", "10.172.1.10"
    )
    r = await client.get("/api/v1/ipam/addresses/search?q=gone-host", headers=headers)
    assert r.status_code == 200, r.text
    assert ip_id not in [i["id"] for i in r.json()["items"]]
    # Control: the row is there, by its address.
    r = await client.get("/api/v1/ipam/addresses/search?q=10.172.1.10", headers=headers)
    assert ip_id in [i["id"] for i in r.json()["items"]]


@pytest.mark.asyncio
async def test_export_ansible_and_tls_probe_do_not_use_the_stale_fqdn(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, sid, ip_id, row, _ = await _cleared(
        client, db_session, "10.173.0.0/16", "10.173.1.0/24", "10.173.1.10"
    )
    sp = (await client.get(f"/api/v1/ipam/subnets/{sid}", headers=headers)).json()["space_id"]
    exp = await client.get(
        f"/api/v1/ipam/export?space_id={sp}&format=json&include_addresses=true", headers=headers
    )
    assert exp.status_code == 200, exp.text
    # The address is exported (so the check below is not vacuous), nameless.
    assert "10.173.1.10" in exp.text and "gone-host" not in exp.text

    inv = await client.get("/api/v1/ansible/inventory", headers=headers)
    assert inv.status_code == 200, inv.text
    assert "gone-host" not in inv.text

    assert _host_for_ip(row) == "10.173.1.10"


@pytest.mark.asyncio
async def test_copilot_find_ip_addresses_reports_no_stale_fqdn(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _h, _sid, ip_id, _row, _ = await _cleared(
        client, db_session, "10.174.0.0/16", "10.174.1.0/24", "10.174.1.10"
    )
    user = User(
        username=f"u3297-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password=hash_password("x"),
        is_superadmin=True,
        is_active=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    # By address: the row is returned, and it carries no name.
    res: Any = await REGISTRY.call(
        "find_ip_addresses", {"q": "10.174.1.10"}, db=db_session, user=user
    )
    rows = [m for m in res["matches"] if m["id"] == ip_id]
    assert rows and rows[0]["fqdn"] is None
    # By the stale name: no match.
    res = await REGISTRY.call("find_ip_addresses", {"q": "gone-host"}, db=db_session, user=user)
    assert ip_id not in [m["id"] for m in res["matches"]]
    # The single-address lookup reports the same.
    res = await REGISTRY.call("find_ip", {"address": "10.174.1.10"}, db=db_session, user=user)
    rows = [m for m in res["matches"] if m["id"] == ip_id]
    assert rows and rows[0]["fqdn"] is None


@pytest.mark.asyncio
async def test_csv_export_and_vendor_devices_carry_no_stale_fqdn(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    headers, sid, _ip_id, row, _ = await _cleared(
        client, db_session, "10.175.0.0/16", "10.175.1.0/24", "10.175.1.10"
    )
    exp = await client.get(
        f"/api/v1/ipam/export?subnet_id={sid}&format=csv&include_addresses=true", headers=headers
    )
    assert exp.status_code == 200, exp.text
    assert "10.175.1.10" in exp.text and "gone-host" not in exp.text

    # Vendor device list: give the row a MAC and stub the OUI lookup.
    row.mac_address = "00:11:22:33:44:55"
    await db_session.commit()

    async def _vendors(_db: Any, macs: Any) -> dict[str, str]:
        from app.services.oui import normalize_mac_key

        return {k: "Acme Corp" for m in macs if m and (k := normalize_mac_key(m))}

    monkeypatch.setattr("app.services.ipam.vendor_rollup.bulk_lookup_vendors", _vendors)
    r = await client.get("/api/v1/ipam/reports/vendors/devices?vendor_search=acme", headers=headers)
    assert r.status_code == 200, r.text
    mine = [m for m in r.json()["matches"] if m["ip_address"] == "10.175.1.10"]
    assert mine and mine[0]["fqdn"] is None

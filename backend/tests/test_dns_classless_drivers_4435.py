"""#4435 — classless reverse zone names on drivers that cannot serve them.

Only the BIND9 agent encodes the ``/``; every other driver gets a 422.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup
from app.services.dns_import.canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)
from app.services.dns_import.commit import commit_import

CLASSLESS = "64/26.2.0.192.in-addr.arpa"


async def _setup(
    db: AsyncSession, driver: str = "bind9"
) -> tuple[User, dict[str, str], DNSServerGroup]:
    user = User(
        username=f"cl-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Classless",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([user, grp])
    await db.flush()
    await _server(db, grp, driver)
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, grp


async def _server(db: AsyncSession, grp: DNSServerGroup, driver: str) -> DNSServer:
    srv = DNSServer(
        group_id=grp.id,
        driver=driver,
        host=f"dns-{uuid.uuid4().hex[:6]}",
        name=f"dns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(srv)
    await db.flush()
    return srv


@pytest.mark.asyncio
@pytest.mark.parametrize(("rtype", "value"), [("NS", "ns1.example.net."), ("TXT", "hello")])
async def test_apex_record_in_classless_zone_is_accepted(
    client: AsyncClient, db_session: AsyncSession, rtype: str, value: str
) -> None:
    _, headers, grp = await _setup(db_session)
    z = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": CLASSLESS}, headers=headers
    )
    assert z.status_code == 201, z.text
    rec = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{z.json()['id']}/records",
        json={"name": "@", "record_type": rtype, "value": value},
        headers=headers,
    )
    assert rec.status_code == 201, rec.text


@pytest.mark.asyncio
async def test_importer_keeps_apex_ns_of_a_classless_zone(db_session: AsyncSession) -> None:
    user, _, grp = await _setup(db_session)
    zone = ImportedZone(
        name=CLASSLESS + ".",
        zone_type="primary",
        kind="reverse",
        soa=ImportedSOA("ns1.example.net.", "admin.example.net.", 1, 3600, 600, 86400, 300, 3600),
        records=[
            ImportedRecord("@", "NS", "ns1.example.net.", 300),
            ImportedRecord("@", "TXT", "hello", 300),
            ImportedRecord("5", "PTR", "host.example.test.", 300),
        ],
    )
    preview = ImportPreview(
        source="bind9",
        zones=[zone],
        conflicts=[],
        warnings=[],
        total_records=3,
        record_type_histogram={},
    )
    res = await commit_import(
        db_session,
        preview=preview,
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
        apex_ns_policy="keep",
    )
    assert res.zones[0].action_taken == "created", res
    assert res.zones[0].skipped_records == []
    stored = (await db_session.execute(select(DNSRecord))).scalars().all()
    assert sorted((r.name, r.record_type) for r in stored) == [
        ("5", "PTR"),
        ("@", "NS"),
        ("@", "TXT"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["powerdns", "technitium", "technitium_api", "windows_dns"])
async def test_classless_zone_refused_on_other_drivers(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    _, headers, grp = await _setup(db_session, driver)
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": CLASSLESS}, headers=headers
    )
    assert resp.status_code == 422, resp.text
    assert "classless" in resp.text and driver in resp.text
    ok = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": "2.0.192.in-addr.arpa"}, headers=headers
    )
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_classless_zone_refused_by_template_and_rename(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers, grp = await _setup(db_session, "powerdns")
    z = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": "2.0.192.in-addr.arpa"}, headers=headers
    )
    assert z.status_code == 201, z.text
    ren = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{z.json()['id']}",
        json={"name": CLASSLESS},
        headers=headers,
    )
    assert ren.status_code == 422, ren.text
    assert "classless" in ren.text


@pytest.mark.asyncio
async def test_server_cannot_join_a_group_holding_a_classless_zone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, headers, grp = await _setup(db_session, "bind9")
    z = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": CLASSLESS}, headers=headers
    )
    assert z.status_code == 201, z.text
    # Remove the bind9 server so single-driver does not answer first.
    for s in (
        (await db_session.execute(select(DNSServer).where(DNSServer.group_id == grp.id)))
        .scalars()
        .all()
    ):
        await db_session.delete(s)
    await db_session.flush()
    body: dict[str, Any] = {"name": "pdns1", "driver": "powerdns", "host": "pdns1.example.test"}
    resp = await client.post(f"/api/v1/dns/groups/{grp.id}/servers", json=body, headers=headers)
    assert resp.status_code == 422, resp.text
    assert "classless" in resp.text
    body["driver"] = "bind9"
    ok = await client.post(f"/api/v1/dns/groups/{grp.id}/servers", json=body, headers=headers)
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_importer_refuses_classless_zone_for_powerdns_group(
    db_session: AsyncSession,
) -> None:
    user, _, grp = await _setup(db_session, "powerdns")
    zone = ImportedZone(
        name=CLASSLESS + ".",
        zone_type="primary",
        kind="reverse",
        soa=ImportedSOA("ns1.example.net.", "admin.example.net.", 1, 3600, 600, 86400, 300, 3600),
        records=[ImportedRecord("5", "PTR", "host.example.test.", 300)],
    )
    preview = ImportPreview(
        source="bind9",
        zones=[zone],
        conflicts=[],
        warnings=[],
        total_records=1,
        record_type_histogram={},
    )
    res = await commit_import(
        db_session,
        preview=preview,
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert res.zones[0].action_taken != "created"
    assert "classless" in str(res.zones[0].error or res)

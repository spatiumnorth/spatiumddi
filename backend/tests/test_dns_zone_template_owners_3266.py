"""#3266 / #3267 — from-template stores owners in the record API's form, and
the Email template's DMARC stub exists with the mailbox left blank."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DNSServerGroup]:
    user = User(
        username=f"t-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, grp


async def _records(db: AsyncSession, zone_name: str) -> list[DNSRecord]:
    zone = (
        await db.execute(select(DNSZone).where(DNSZone.name.in_([zone_name, zone_name + "."])))
    ).scalar_one()
    rows = await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))
    return list(rows.scalars())


async def _create(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, zone: str, params: dict
) -> None:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/from-template",
        headers=headers,
        json={"template_id": "mail-basic", "zone_name": zone, "params": params},
    )
    assert resp.status_code == 201, resp.text


@pytest.mark.asyncio
async def test_dkim_owner_stored_lowercase_and_idna(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp = await _setup(db_session)
    await _create(
        client, headers, grp, "t1.test", {"mx_host": "mx.t1.test.", "dkim_selector": "Sel1"}
    )
    await _create(
        client, headers, grp, "t2.test", {"mx_host": "mx.t2.test.", "dkim_selector": "café"}
    )
    n1 = {r.name for r in await _records(db_session, "t1.test")}
    n2 = [r for r in await _records(db_session, "t2.test")]
    assert "sel1._domainkey" in n1 and "Sel1._domainkey" not in n1
    names2 = {r.name for r in n2}
    assert "xn--caf-dma._domainkey" in names2
    assert any(r.fqdn == "xn--caf-dma._domainkey.t2.test." for r in n2)


@pytest.mark.asyncio
async def test_ad_site_owner_lowercased(client: AsyncClient, db_session: AsyncSession) -> None:
    headers, grp = await _setup(db_session)
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/from-template",
        headers=headers,
        json={
            "template_id": "active-directory",
            "zone_name": "ad.test",
            "params": {"dc_hostname": "dc1.ad.test.", "site_name": "Default-First-Site-Name"},
        },
    )
    assert resp.status_code == 201, resp.text
    names = {r.name for r in await _records(db_session, "ad.test")}
    assert "_ldap._tcp.default-first-site-name._sites" in names
    assert not any(n != n.lower() for n in names)


@pytest.mark.asyncio
async def test_dmarc_stub_with_blank_mailbox(client: AsyncClient, db_session: AsyncSession) -> None:
    headers, grp = await _setup(db_session)
    await _create(client, headers, grp, "t3.test", {"mx_host": "mx.t3.test."})
    await _create(
        client, headers, grp, "t4.test", {"mx_host": "mx.t4.test.", "dmarc_email": "p@t4.test"}
    )
    blank = [r for r in await _records(db_session, "t3.test") if r.name == "_dmarc"]
    given = [r for r in await _records(db_session, "t4.test") if r.name == "_dmarc"]
    assert [r.value for r in blank] == ["v=DMARC1; p=none"]
    assert [r.value for r in given] == ["v=DMARC1; p=quarantine; rua=mailto:p@t4.test"]

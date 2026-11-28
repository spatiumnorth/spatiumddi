"""#4567 — a custom DNSSEC policy is refused on a PowerDNS group.

The PowerDNS agent signs with fixed settings and never reads the policy, so
storing one claimed an algorithm / NSEC3 the zone was not signed with.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSSECPolicy
from tests.test_dnssec_bind9 import _admin, _group_with_driver, _zone_row


async def _setup(db: AsyncSession, driver: str):
    token = await _admin(db)
    grp = await _group_with_driver(db, driver)
    zone = await _zone_row(db, grp)
    builtin = DNSSECPolicy(name=f"default-{uuid.uuid4().hex[:4]}", is_builtin=True)
    custom = DNSSECPolicy(name="nsec3-rsa", algorithm="rsasha256", nsec3=True)
    db.add_all([builtin, custom])
    await db.commit()
    return {"Authorization": f"Bearer {token}"}, grp, zone, builtin, custom


async def test_sign_with_custom_policy_refused_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp, zone, _b, custom = await _setup(db_session, "powerdns")
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/dnssec/sign"
    r = await client.post(url, headers=h, json={"policy_id": str(custom.id)})
    assert r.status_code == 422, r.text
    assert "PowerDNS" in r.json()["detail"]
    await db_session.refresh(zone)
    assert zone.dnssec_policy_id is None


async def test_sign_default_or_no_policy_allowed_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp, zone, builtin, _c = await _setup(db_session, "powerdns")
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/dnssec/sign"
    assert (await client.post(url, headers=h, json={})).status_code == 200
    r = await client.post(url, headers=h, json={"policy_id": str(builtin.id)})
    assert r.status_code == 200, r.text


async def test_patch_custom_policy_refused_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp, zone, _b, custom = await _setup(db_session, "powerdns")
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=h,
        json={"dnssec_policy_id": str(custom.id)},
    )
    assert r.status_code == 422, r.text
    assert "PowerDNS" in r.json()["detail"]


async def test_untouched_stored_policy_still_saves_on_powerdns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp, zone, _b, custom = await _setup(db_session, "powerdns")
    zone.dnssec_policy_id = custom.id
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=h,
        json={"dnssec_policy_id": str(custom.id)},
    )
    assert r.status_code == 200, r.text


async def test_custom_policy_still_allowed_on_bind9(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, grp, zone, _b, custom = await _setup(db_session, "bind9")
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/dnssec/sign"
    r = await client.post(url, headers=h, json={"policy_id": str(custom.id)})
    assert r.status_code == 200, r.text

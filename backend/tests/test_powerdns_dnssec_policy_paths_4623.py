"""#4623 — a custom DNSSEC policy is refused on every path into a PowerDNS group.

#4567 covered the zone update and Sign. The Copilot apply, a zone move and a
server joining the group reach the same state (a policy PowerDNS stores and
never applies); a stored one is reported on the zone's DNSSEC info.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dns import DNSSECPolicy, DNSServer
from app.services.ai.operations import get_operation
from app.services.ai.operations_writes import SignZoneDNSSECArgs
from tests.test_dnssec_bind9 import _admin, _group_with_driver, _zone_row


async def _setup(db: AsyncSession, src: str = "bind9", dst: str = "powerdns"):
    token = await _admin(db)
    src_grp = await _group_with_driver(db, src)
    dst_grp = await _group_with_driver(db, dst)
    zone = await _zone_row(db, src_grp)
    custom = DNSSECPolicy(name=f"nsec3-{uuid.uuid4().hex[:4]}", algorithm="rsasha256", nsec3=True)
    db.add(custom)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {token}"}, src_grp, dst_grp, zone, custom


async def test_copilot_sign_preview_and_apply_refuse(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _h, _s, grp, zone, custom = await _setup(db_session)
    zone.group_id = grp.id
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="x",
        hashed_password="x",
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.commit()
    op = get_operation("sign_zone_dnssec")
    assert op is not None
    args = SignZoneDNSSECArgs(group_id=grp.id, zone_id=zone.id, policy_id=custom.id)
    preview = await op.preview(db_session, user, args)
    assert preview.ok is False and "PowerDNS" in preview.detail
    try:
        await op.apply(db_session, user, args)
    except ValueError as exc:
        assert "PowerDNS" in str(exc)
    else:
        raise AssertionError("apply must refuse")
    await db_session.refresh(zone)
    assert zone.dnssec_policy_id is None
    assert not zone.dnssec_enabled


async def test_zone_move_into_powerdns_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, src, dst, zone, custom = await _setup(db_session)
    zone.dnssec_policy_id = custom.id
    await db_session.commit()
    base = f"/api/v1/dns/groups/{src.id}/zones/{zone.id}/move"
    p = await client.post(f"{base}/preview", headers=h, json={"target_group_id": str(dst.id)})
    assert p.status_code == 200, p.text
    assert "PowerDNS" in (p.json()["dnssec_policy_refusal"] or "")
    c = await client.post(
        f"{base}/commit",
        headers=h,
        json={"target_group_id": str(dst.id), "confirmation_zone_name": zone.name},
    )
    assert c.status_code == 422, c.text
    assert "PowerDNS" in c.json()["detail"]


async def test_zone_move_without_custom_policy_not_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, src, dst, zone, _c = await _setup(db_session)
    p = await client.post(
        f"/api/v1/dns/groups/{src.id}/zones/{zone.id}/move/preview",
        headers=h,
        json={"target_group_id": str(dst.id)},
    )
    assert p.status_code == 200, p.text
    assert p.json()["dnssec_policy_refusal"] is None


async def test_powerdns_server_cannot_join_group_holding_custom_policy(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, src, _dst, zone, custom = await _setup(db_session)
    zone.dnssec_policy_id = custom.id
    await db_session.commit()
    # Joining by create, driver change and move all hit the same check.
    for s in await _servers(db_session, src.id):
        await db_session.delete(s)
    await db_session.commit()
    body = {"name": "pdns1", "driver": "powerdns", "host": "pdns1.example.test"}
    r = await client.post(f"/api/v1/dns/groups/{src.id}/servers", headers=h, json=body)
    assert r.status_code == 422, r.text
    assert custom.name in r.json()["detail"]
    body["driver"] = "bind9"
    ok = await client.post(f"/api/v1/dns/groups/{src.id}/servers", headers=h, json=body)
    assert ok.status_code == 201, ok.text


async def test_server_move_into_group_holding_custom_policy_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, src, _dst, zone, custom = await _setup(db_session, src="bind9", dst="powerdns")
    zone.dnssec_policy_id = custom.id
    await db_session.commit()
    empty = await _group_with_driver(db_session, "powerdns")
    srv = (await _servers(db_session, empty.id))[0]
    await db_session.commit()
    # Make the target (src) group empty of servers so single-driver passes.
    for s in await _servers(db_session, src.id):
        await db_session.delete(s)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{empty.id}/servers/{srv.id}",
        headers=h,
        json={"group_id": str(src.id)},
    )
    assert r.status_code == 422, r.text
    assert "custom DNSSEC policy" in r.text


async def test_dnssec_info_reports_stored_unapplied_policy(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _s, dst, zone, custom = await _setup(db_session)
    zone.group_id = dst.id
    zone.dnssec_policy_id = custom.id
    await db_session.commit()
    url = f"/api/v1/dns/groups/{dst.id}/zones/{zone.id}/dnssec/info"
    r = await client.get(url, headers=h)
    assert r.status_code == 200, r.text
    assert "not applied" in r.json()["unapplied_warning"]
    zone.dnssec_policy_id = None
    await db_session.commit()
    assert (await client.get(url, headers=h)).json()["unapplied_warning"] is None


async def _servers(db: AsyncSession, group_id: uuid.UUID) -> list[DNSServer]:
    from sqlalchemy import select

    res = await db.execute(select(DNSServer).where(DNSServer.group_id == group_id))
    return list(res.scalars().all())

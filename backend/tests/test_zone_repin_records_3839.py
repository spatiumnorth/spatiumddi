"""spatiumddi#3839 — re-pinning a zone is held to the record API's view rule.

A pinned zone renders into its pin alone, so a record scoped to another view is
served in no view. The record API refuses writing that; Edit Zone must too.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone


async def _setup(db: AsyncSession):
    user = User(
        username=f"u3839-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"g3839-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    v1 = DNSView(group_id=grp.id, name="v1")
    v2 = DNSView(group_id=grp.id, name="v2")
    zone = DNSZone(group_id=grp.id, name="pin.example.test.", zone_type="primary", kind="forward")
    db.add_all([v1, v2, zone])
    await db.flush()
    for view, ip in ((v1, "192.0.2.41"), (v2, "192.0.2.42")):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                view_id=view.id,
                name="www",
                fqdn="www.pin.example.test.",
                record_type="A",
                value=ip,
            )
        )
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, grp, zone, v1, v2


async def test_repin_refused_while_a_record_is_scoped_to_another_view(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, v1, v2 = await _setup(db_session)
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=headers,
        json={"view_id": str(v1.id)},
    )
    assert resp.status_code == 422
    assert "192.0.2.42" in resp.text and "v2" in resp.text
    await db_session.refresh(zone)
    assert zone.view_id is None


async def test_repin_allowed_when_records_match_or_are_unscoped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, v1, v2 = await _setup(db_session)
    # Drop the v2 record: only a v1-scoped record remains, which the pin keeps.
    rec = (
        await db_session.execute(
            DNSRecord.__table__.select().where(DNSRecord.value == "192.0.2.42")
        )
    ).first()
    await db_session.execute(DNSRecord.__table__.delete().where(DNSRecord.id == rec.id))
    await db_session.commit()
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=headers,
        json={"view_id": str(v1.id)},
    )
    assert resp.status_code == 200, resp.text


async def test_clearing_the_pin_is_allowed_and_shared_records_never_block(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, zone, v1, v2 = await _setup(db_session)
    # A shared (view_id NULL) record plus a v1 record; the zone already pinned to v1.
    await db_session.execute(DNSRecord.__table__.delete().where(DNSRecord.value == "192.0.2.42"))
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            view_id=None,
            name="shared",
            fqdn="shared.pin.example.test.",
            record_type="A",
            value="192.0.2.43",
        )
    )
    zone.view_id = v1.id
    await db_session.commit()
    # Re-pinning to the same view and clearing the pin are not re-pins to another view.
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=headers,
        json={"view_id": str(v1.id)},
    )
    assert resp.status_code == 200, resp.text
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=headers,
        json={"view_id": None},
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(zone)
    assert zone.view_id is None


async def test_repin_of_a_pinned_zone_names_a_remedy_the_record_api_accepts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3943 — while the zone is pinned, moving a record to the new view is 422."""
    headers, grp, zone, v1, v2 = await _setup(db_session)
    zone.view_id = v1.id
    await db_session.commit()
    # The record API refuses the "move" the old words named first.
    rec = (
        await db_session.execute(select(DNSRecord).where(DNSRecord.view_id == v1.id))
    ).scalar_one()
    mv = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/records/{rec.id}",
        headers=headers,
        json={"view_id": str(v2.id)},
    )
    assert mv.status_code == 422
    resp = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}",
        headers=headers,
        json={"view_id": str(v2.id)},
    )
    assert resp.status_code == 422
    assert "Move those records" not in resp.text
    assert "Remove their view first" in resp.text

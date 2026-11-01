"""#3265 — a zone that holds records is not renamed through the API."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DNSServerGroup]:
    user = User(
        username=f"rn-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Rename Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, grp


async def _zone(db: AsyncSession, grp: DNSServerGroup, with_record: bool) -> DNSZone:
    z = DNSZone(
        group_id=grp.id, name=f"rn{uuid.uuid4().hex[:6]}.test.", zone_type="primary", kind="forward"
    )
    db.add(z)
    await db.flush()
    if with_record:
        db.add(
            DNSRecord(
                zone_id=z.id,
                name="h1",
                fqdn=f"h1.{z.name.rstrip('.')}",
                record_type="A",
                value="192.0.2.1",
            )
        )
        await db.flush()
    return z


async def test_rename_with_records_is_refused_and_changes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp = await _setup(db_session)
    z = await _zone(db_session, grp, True)
    old = z.name
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{z.id}",
        json={"name": "_rn.other.test"},
        headers=headers,
    )
    assert r.status_code == 409, r.text
    assert "holds 1 record" in r.text
    got = await client.get(f"/api/v1/dns/groups/{grp.id}/zones/{z.id}", headers=headers)
    assert got.json()["name"] == old


async def test_rename_of_empty_zone_and_same_name_save_still_work(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp = await _setup(db_session)
    full = await _zone(db_session, grp, True)
    # Re-sending the stored name (a GET-then-PUT client) is not a rename.
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{full.id}",
        json={"name": full.name, "ttl": 600},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    empty = await _zone(db_session, grp, False)
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{empty.id}",
        json={"name": "renamed.test"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "renamed.test."

"""A zone's own named.conf clauses are validated on create and update (#1316).

The zone half of #1244. ``allow_query`` / ``allow_transfer`` /
``also_notify`` / ``notify_enabled`` are rendered into the zone's
``zone { … }`` statement, so one bad element makes BIND refuse the file and
the whole group stops converging. The grammars themselves are pinned in
``test_dns_server_options_validation.py``; these tests pin the wiring.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSAcl, DNSServerGroup, DNSTSIGKey, DNSZone


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    u.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    return group


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "bad"),
    [
        ("allow_transfer", ["any", "10.0.0.300"], "10.0.0.300"),
        ("allow_query", ["undefined-acl"], "undefined-acl"),
        ("also_notify", ["192.0.2.0/24"], "192.0.2.0/24"),
        ("notify_enabled", "sometimes", "sometimes"),
    ],
)
async def test_create_refuses_a_bad_clause_naming_it(
    client: AsyncClient, db_session: AsyncSession, field: str, value: object, bad: str
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={"name": "example.com", field: value},
        headers=headers,
    )
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == field
    assert r.json()["detail"]["value"] == bad


@pytest.mark.asyncio
async def test_create_accepts_group_names_and_bind_forms(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    db_session.add(DNSAcl(group_id=group.id, name="secondaries"))
    db_session.add(
        DNSTSIGKey(group_id=group.id, name="xfer", algorithm="hmac-sha256", secret_encrypted=b"x")
    )
    await db_session.commit()

    r = await client.post(
        f"/api/v1/dns/groups/{group.id}/zones",
        json={
            "name": "example.com",
            "allow_query": ["any"],
            "allow_transfer": ["secondaries", "key xfer", "!192.0.2.9"],
            "also_notify": ["192.0.2.1 port 5353 key xfer"],
            "notify_enabled": "explicit",
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_update_checks_a_changed_value_but_not_a_stored_one(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _superadmin(db_session)
    group = await _group(db_session)
    # A value stored before the gate existed — the form sends it back on
    # every save and must not make the zone uneditable.
    zone = DNSZone(group_id=group.id, name="example.com.", allow_transfer=["legacy-acl"])
    db_session.add(zone)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/zones/{zone.id}"

    r = await client.put(url, json={"allow_transfer": ["legacy-acl"], "ttl": 600}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["ttl"] == 600

    r = await client.put(url, json={"allow_transfer": ["10.0.0.300"]}, headers=headers)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["field"] == "allow_transfer"

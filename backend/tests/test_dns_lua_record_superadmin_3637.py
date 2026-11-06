"""Writing a LUA record needs a superadmin (#3637).

PowerDNS runs a LUA record's snippet inside the DNS server at query time, and
the snippet menu offers TCP / HTTP(S) probes made from the server's address.
The DNS Editor role holds ``admin`` on ``dns_record``, so the ``dns_record``
gate alone let it store one. Every route that stores a record now asks for a
superadmin when the type is LUA; a refusal is audited, and deleting an existing
LUA record is unchanged.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns import router as dns_router
from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.services.dns_io.parser import ParsedRecord, ParsedZone

pytestmark = pytest.mark.asyncio

LUA_VALUE = "A \"'192.0.2.1'\""
EDITOR_PERMS = [
    {"action": "admin", "resource_type": "dns_record"},
    {"action": "admin", "resource_type": "dns_zone"},
    {"action": "admin", "resource_type": "dns_group"},
]


async def _user(db: AsyncSession, *, superadmin: bool) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="Test",
        hashed_password=hash_password("x" * 12),
        is_superadmin=superadmin,
    )
    if not superadmin:
        role = Role(name=f"r-{tag}", permissions=EDITOR_PERMS)
        group = Group(name=f"g-{tag}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    else:
        user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession) -> DNSZone:
    # A group with no servers passes the driver gate, so only the role is tested.
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    name = f"z{uuid.uuid4().hex[:6]}.example."
    zone = DNSZone(
        group_id=grp.id,
        name=name,
        zone_type="primary",
        kind="forward",
        primary_ns=f"ns1.{name}",
        admin_email=f"admin.{name}",
    )
    db.add(zone)
    await db.flush()
    zone.__dict__["base_url"] = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}"
    return zone


def _base(zone: DNSZone) -> str:
    return str(zone.__dict__["base_url"])  # set by _zone: the row expires on commit


async def _lua_row(db: AsyncSession, zone: DNSZone, value: str = LUA_VALUE) -> DNSRecord:
    rec = DNSRecord(
        zone_id=zone.id,
        name="p1",
        fqdn=f"p1.{zone.name}",
        record_type="LUA",
        value=value,
    )
    db.add(rec)
    await db.flush()
    return rec


async def _lua_count(db: AsyncSession, zone_id: uuid.UUID) -> int:
    db.expire_all()
    rows = await db.execute(
        select(DNSRecord).where(
            DNSRecord.zone_id == zone_id,
            DNSRecord.record_type == "LUA",
            DNSRecord.deleted_at.is_(None),
        )
    )
    return len(rows.scalars().all())


def _csv() -> dict[str, Any]:
    body = f'id,name,type,value,ttl\n,p2,LUA,"{LUA_VALUE.replace(chr(34), chr(34) * 2)}",300\n'
    return {"files": {"file": ("r.csv", body.encode(), "text/csv")}}


async def test_editor_cannot_create_a_lua_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=False)
    zone = await _zone(db_session)
    zone_id = zone.id
    await db_session.commit()

    r = await client.post(
        f"{_base(zone)}/records",
        headers=h,
        json={"name": "p1", "record_type": "LUA", "value": LUA_VALUE},
    )
    assert r.status_code == 403, r.text
    assert "superadmin" in r.json()["detail"]
    assert await _lua_count(db_session, zone_id) == 0
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.result == "denied")))
        .scalars()
        .all()
    )
    assert any("LUA" in (a.error_detail or "") for a in audit)

    # Other types are untouched.
    ok = await client.post(
        f"{_base(zone)}/records",
        headers=h,
        json={"name": "w", "record_type": "A", "value": "192.0.2.5"},
    )
    assert ok.status_code == 201, ok.text


async def test_superadmin_can_create_a_lua_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(
        f"{_base(zone)}/records",
        headers=h,
        json={"name": "p1", "record_type": "LUA", "value": LUA_VALUE},
    )
    assert r.status_code == 201, r.text


async def test_editor_cannot_change_a_lua_value_but_can_change_its_ttl_and_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=False)
    zone = await _zone(db_session)
    rec = await _lua_row(db_session, zone)
    zone_id, rec_id = zone.id, rec.id
    await db_session.commit()

    r = await client.put(
        f"{_base(zone)}/records/{rec_id}", headers=h, json={"value": "A \"'192.0.2.9'\""}
    )
    assert r.status_code == 403, r.text
    db_session.expire_all()
    assert (await db_session.get(DNSRecord, rec_id)).value == LUA_VALUE  # type: ignore[union-attr]

    ttl = await client.put(f"{_base(zone)}/records/{rec_id}", headers=h, json={"ttl": 120})
    assert ttl.status_code == 200, ttl.text

    gone = await client.delete(f"{_base(zone)}/records/{rec_id}", headers=h)
    assert gone.status_code == 204, gone.text
    assert await _lua_count(db_session, zone_id) == 0


async def test_superadmin_can_change_a_lua_value(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _user(db_session, superadmin=True)
    zone = await _zone(db_session)
    rec = await _lua_row(db_session, zone)
    rec_id = rec.id
    await db_session.commit()

    r = await client.put(
        f"{_base(zone)}/records/{rec_id}", headers=h, json={"value": "A \"'192.0.2.9'\""}
    )
    assert r.status_code == 200, r.text


async def test_bulk_create(client: AsyncClient, db_session: AsyncSession) -> None:
    ed = await _user(db_session, superadmin=False)
    sa = await _user(db_session, superadmin=True)
    zone = await _zone(db_session)
    zone_id = zone.id
    await db_session.commit()
    body = {
        "records": [
            {"name": "w", "record_type": "A", "value": "192.0.2.5"},
            {"name": "p1", "record_type": "LUA", "value": LUA_VALUE},
        ]
    }
    r = await client.post(f"{_base(zone)}/records/bulk-create", headers=ed, json=body)
    assert r.status_code == 403, r.text
    assert await _lua_count(db_session, zone_id) == 0
    r = await client.post(f"{_base(zone)}/records/bulk-create", headers=sa, json=body)
    assert r.status_code == 201, r.text


async def test_spreadsheet_import(client: AsyncClient, db_session: AsyncSession) -> None:
    ed = await _user(db_session, superadmin=False)
    sa = await _user(db_session, superadmin=True)
    zone = await _zone(db_session)
    zone_id = zone.id
    await db_session.commit()
    r = await client.post(
        f"{_base(zone)}/import/spreadsheet/commit", headers=ed, data={"mode": "merge"}, **_csv()
    )
    assert r.status_code == 403, r.text
    assert await _lua_count(db_session, zone_id) == 0
    r = await client.post(
        f"{_base(zone)}/import/spreadsheet/commit", headers=sa, data={"mode": "merge"}, **_csv()
    )
    assert r.status_code == 200, r.text
    assert await _lua_count(db_session, zone_id) == 1


async def test_zone_file_import(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # dnspython does not parse LUA, so a real file cannot carry one; the gate
    # still sits on the commit for any parser that learns to.
    monkeypatch.setattr(
        dns_router,
        "parse_zone_file",
        lambda text, zone_name: ParsedZone(
            soa=None,
            records=[ParsedRecord(name="p3", record_type="LUA", value=LUA_VALUE, ttl=300)],
        ),
    )
    ed = await _user(db_session, superadmin=False)
    sa = await _user(db_session, superadmin=True)
    zone = await _zone(db_session)
    zone_id = zone.id
    await db_session.commit()
    body = {"zone_file": "ignored", "conflict_strategy": "merge"}
    r = await client.post(f"{_base(zone)}/import/commit", headers=ed, json=body)
    assert r.status_code == 403, r.text
    assert await _lua_count(db_session, zone_id) == 0
    r = await client.post(f"{_base(zone)}/import/commit", headers=sa, json=body)
    assert r.status_code == 200, r.text
    assert await _lua_count(db_session, zone_id) == 1


async def test_zone_from_template(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        dns_router,
        "materialize",
        lambda template, zone_name, params: [
            {
                "name": "p1",
                "record_type": "LUA",
                "value": LUA_VALUE,
                "ttl": 300,
                "priority": None,
                "weight": None,
                "port": None,
            }
        ],
    )
    ed = await _user(db_session, superadmin=False)
    sa = await _user(db_session, superadmin=True)
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/from-template"
    body = {
        "template_id": "web-basic",
        "zone_name": "tpl.example.",
        "params": {"origin_ip": "192.0.2.10"},
    }
    r = await client.post(url, headers=ed, json=body)
    assert r.status_code == 403, r.text
    zones = (await db_session.execute(select(DNSZone).where(DNSZone.group_id == grp.id))).all()
    assert zones == []
    r = await client.post(url, headers=sa, json=body)
    assert r.status_code == 201, r.text


async def test_editor_resending_an_unchanged_lua_value_is_not_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # A GET-then-PUT client re-sends every field; only a changed value is a
    # LUA write, so a TTL edit that carries the stored snippet goes through.
    h = await _user(db_session, superadmin=False)
    zone = await _zone(db_session)
    rec = await _lua_row(db_session, zone)
    rec_id = rec.id
    await db_session.commit()

    r = await client.put(
        f"{_base(zone)}/records/{rec_id}",
        headers=h,
        json={"name": "p1", "value": LUA_VALUE, "ttl": 120},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ttl"] == 120


async def test_a_superadmin_role_without_the_flag_may_write_lua(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # An LDAP / OIDC user mapped into a group whose role holds */* is a
    # superadmin without the legacy column (#190).
    tag = uuid.uuid4().hex[:8]
    role = Role(name=f"r-{tag}", permissions=[{"action": "*", "resource_type": "*"}])
    group = Group(name=f"g-{tag}")
    group.roles = [role]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="Test",
        hashed_password=hash_password("x" * 12),
        is_superadmin=False,
    )
    user.groups = [group]
    db_session.add_all([role, group, user])
    await db_session.flush()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(
        f"{_base(zone)}/records",
        headers=h,
        json={"name": "p1", "record_type": "LUA", "value": LUA_VALUE},
    )
    assert r.status_code == 201, r.text


async def _superadmin_token(db: AsyncSession, grants: list[dict] | None) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    owner = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="Test",
        hashed_password=hash_password("x" * 12),
        is_superadmin=True,
    )
    owner.groups = []
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{tag}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=grants,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    return {"Authorization": f"Bearer {raw}"}


async def test_superadmin_api_tokens(client: AsyncClient, db_session: AsyncSession) -> None:
    # An unrestricted token of a superadmin is that superadmin. A token bound
    # to one zone is never a superadmin (#374): it may write that zone's
    # ordinary records, but not a LUA one.
    zone = await _zone(db_session)
    zone_id = zone.id
    open_token = await _superadmin_token(db_session, None)
    zone_token = await _superadmin_token(
        db_session,
        [
            {"action": "write", "resource_type": "dns_zone", "resource_id": str(zone_id)},
            {"action": "write", "resource_type": "dns_record", "resource_id": "*"},
        ],
    )
    await db_session.commit()
    url = f"{_base(zone)}/records"

    r = await client.post(
        url, headers=zone_token, json={"name": "p1", "record_type": "LUA", "value": LUA_VALUE}
    )
    assert r.status_code == 403, r.text
    assert await _lua_count(db_session, zone_id) == 0
    ok = await client.post(
        url, headers=zone_token, json={"name": "w", "record_type": "A", "value": "192.0.2.5"}
    )
    assert ok.status_code == 201, ok.text

    r = await client.post(
        url, headers=open_token, json={"name": "p1", "record_type": "LUA", "value": LUA_VALUE}
    )
    assert r.status_code == 201, r.text

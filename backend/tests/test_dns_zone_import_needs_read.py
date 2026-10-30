"""The zone import and sync routes answer with the zone's records, so they ask
for ``read`` as the zone export and the record list do.

These routes are POSTs, and the DNS router's gate takes the action from the
method: a POST asks for ``write`` on one of ``dns_group`` / ``dns_zone`` /
``dns_record``. Their answers carry the zone's existing records (a ``replace``
preview lists every record the file omits under ``to_delete``), so a role with
``write`` and no ``read`` must be refused here as it is refused by the export.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone

pytestmark = pytest.mark.asyncio

WRITE_RECORDS = [{"action": "write", "resource_type": "dns_record"}]
READ_WRITE_RECORDS = [
    {"action": "write", "resource_type": "dns_record"},
    {"action": "read", "resource_type": "dns_record"},
]
CSV_HEADER = "id,name,type,value,ttl\n"


async def _user(
    db: AsyncSession, perms: list[dict[str, Any]] | None, *, superadmin: bool = False
) -> User:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="Test",
        hashed_password=hash_password("x" * 12),
        is_superadmin=superadmin,
    )
    if perms is not None:
        role = Role(name=f"r-{tag}", permissions=perms)
        group = Group(name=f"g-{tag}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return user


async def _headers(db: AsyncSession, perms: list[dict[str, Any]]) -> dict[str, str]:
    user = await _user(db, perms)
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession, grp: DNSServerGroup | None = None) -> DNSZone:
    if grp is None:
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
    for i in (2, 3, 4):
        db.add(
            DNSRecord(
                zone_id=zone.id,
                name=f"r{i}",
                fqdn=f"r{i}.{name}",
                record_type="A",
                value=f"192.0.2.21{i}",
            )
        )
    await db.flush()
    return zone


def _base(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}"


def _zone_file(zone: DNSZone) -> dict[str, Any]:
    return {
        "zone_file": f"$ORIGIN {zone.name}\nnew 300 IN A 192.0.2.99\n",
        "conflict_strategy": "replace",
    }


def _sheet() -> dict[str, Any]:
    return {
        "files": {"file": ("r.csv", (CSV_HEADER + ",new,A,192.0.2.99,300\n").encode(), "text/csv")}
    }


async def _record_values(db: AsyncSession, zone_id: uuid.UUID) -> list[str]:
    rows = await db.execute(
        select(DNSRecord.value).where(DNSRecord.zone_id == zone_id, DNSRecord.deleted_at.is_(None))
    )
    return sorted(rows.scalars().all())


async def test_write_only_role_cannot_preview_a_zone_file(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, WRITE_RECORDS)
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(f"{_base(zone)}/import/preview", headers=h, json=_zone_file(zone))
    assert r.status_code == 403, r.text
    assert "192.0.2.212" not in r.text
    # The export refuses the same caller; the two now agree.
    exp = await client.get(f"{_base(zone)}/export", headers=h)
    assert exp.status_code == 403, exp.text


async def test_write_only_role_cannot_preview_a_spreadsheet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, WRITE_RECORDS)
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(
        f"{_base(zone)}/import/spreadsheet/preview",
        headers=h,
        data={"mode": "replace"},
        **_sheet(),
    )
    assert r.status_code == 403, r.text
    assert "192.0.2.212" not in r.text


async def test_write_only_role_cannot_commit_an_import(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, WRITE_RECORDS)
    zone = await _zone(db_session)
    await db_session.commit()
    zone_id = zone.id
    before = await _record_values(db_session, zone_id)
    assert len(before) == 3

    # ``merge`` so the write alone would be enough; a ``replace`` also needs
    # ``delete`` and would be refused for that instead.
    body = {**_zone_file(zone), "conflict_strategy": "merge"}
    r = await client.post(f"{_base(zone)}/import/commit", headers=h, json=body)
    assert r.status_code == 403, r.text
    r = await client.post(
        f"{_base(zone)}/import/spreadsheet/commit",
        headers=h,
        data={"mode": "merge"},
        **_sheet(),
    )
    assert r.status_code == 403, r.text

    db_session.expire_all()
    assert await _record_values(db_session, zone_id) == before


async def test_write_only_role_cannot_sync_with_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, WRITE_RECORDS)
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(f"{_base(zone)}/sync-with-server", headers=h, json={"apply": False})
    assert r.status_code == 403, r.text


async def test_read_and_write_previews_the_zone_file(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, READ_WRITE_RECORDS)
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(f"{_base(zone)}/import/preview", headers=h, json=_zone_file(zone))
    assert r.status_code == 200, r.text
    body = r.json()
    assert [c["name"] for c in body["to_create"]] == ["new"]
    assert sorted(c["value"] for c in body["to_delete"]) == [
        "192.0.2.212",
        "192.0.2.213",
        "192.0.2.214",
    ]


async def test_read_on_the_record_type_is_needed_not_any_dns_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # #3073: the preview answers with the zone's records, so it needs read on
    # ``dns_record`` (as the record list does); read on ``dns_zone`` no longer
    # stands in for it, and the export needs both.
    zone_reader = await _headers(
        db_session,
        [
            {"action": "write", "resource_type": "dns_record"},
            {"action": "read", "resource_type": "dns_zone"},
        ],
    )
    h = await _headers(
        db_session,
        [
            {"action": "write", "resource_type": "dns_record"},
            {"action": "read", "resource_type": "dns_record"},
            {"action": "read", "resource_type": "dns_zone"},
        ],
    )
    zone = await _zone(db_session)
    await db_session.commit()

    r = await client.post(
        f"{_base(zone)}/import/spreadsheet/preview",
        headers=zone_reader,
        data={"mode": "replace"},
        **_sheet(),
    )
    assert r.status_code == 403, r.text

    assert (await client.get(f"{_base(zone)}/export", headers=h)).status_code == 200
    r = await client.post(
        f"{_base(zone)}/import/spreadsheet/preview",
        headers=h,
        data={"mode": "replace"},
        **_sheet(),
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["to_delete"]) == 3


async def test_zone_scoped_token_previews_its_own_zone_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    owner = await _user(db_session, None, superadmin=True)
    zone_a = await _zone(db_session)
    zone_b = await _zone(db_session)
    raw, _prefix, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=[
                {"action": "write", "resource_type": "dns_zone", "resource_id": str(zone_a.id)}
            ],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db_session.commit()
    h = {"Authorization": f"Bearer {raw}"}

    ok = await client.post(f"{_base(zone_a)}/import/preview", headers=h, json=_zone_file(zone_a))
    assert ok.status_code == 200, ok.text
    assert len(ok.json()["to_delete"]) == 3
    other = await client.post(f"{_base(zone_b)}/import/preview", headers=h, json=_zone_file(zone_b))
    assert other.status_code == 403, other.text

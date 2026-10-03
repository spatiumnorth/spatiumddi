"""A CNAME stands alone at its name (#1381).

``www A`` then ``www CNAME`` both answered 201. A name that holds a CNAME holds
nothing else (RFC 1034 §3.6.2, RFC 2181 §10.1), so both engines refuse that
zone: PowerDNS answered the agent's patch with 422 "Conflicts with
pre-existing RRset", and BIND's zone check refuses "CNAME and other data",
which quarantines the server's whole config bundle (#1378).

Create, update, bulk create and the Copilot now refuse it: 409 for a clash
with a row the zone holds, 422 for a CNAME at the apex, which always holds the
SOA and NS. Views decide whether two rows meet: a row with no view renders in
every view, a scoped row only in its own.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSView, DNSZone
from app.services.ai.operations import CreateDNSRecordArgs, get_operation
from app.services.dns.cname_conflict import (
    CNAME_CONFLICT_REASON,
    is_apex,
    types_conflict,
    views_overlap,
)

# ── The rule ────────────────────────────────────────────────────────────────


def test_the_rule() -> None:
    v1, v2 = uuid.uuid4(), uuid.uuid4()
    assert views_overlap(None, None) and views_overlap(None, v1) and views_overlap(v1, None)
    assert views_overlap(v1, v1) and not views_overlap(v1, v2)
    assert types_conflict("CNAME", "A") and types_conflict("A", "CNAME")
    assert types_conflict("cname", "cname") and types_conflict("TXT", "CNAME")
    assert not types_conflict("A", "AAAA") and not types_conflict("MX", "TXT")
    assert is_apex("@") and is_apex("") and not is_apex("www")


# ── The API ─────────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"cn-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="CNAME Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _zone(db: AsyncSession) -> DNSZone:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(
        DNSServer(
            group_id=grp.id,
            driver="bind9",
            host="10.0.0.1",
            name=f"srv-{uuid.uuid4().hex[:6]}",
            is_primary=True,
            is_enabled=True,
        )
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
        ttl=3600,
    )
    db.add(zone)
    await db.flush()
    return zone


async def _row(
    db: AsyncSession, zone: DNSZone, name: str, rtype: str, value: str, **kw: object
) -> DNSRecord:
    """Insert directly, bypassing the API (a row that predates the rule, or
    one IPAM generated)."""
    rec = DNSRecord(
        zone_id=zone.id,
        name=name,
        fqdn=f"{name}.{zone.name}",
        record_type=rtype,
        value=value,
        **kw,
    )
    db.add(rec)
    await db.flush()
    return rec


def _url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


async def _at(db: AsyncSession, zone: DNSZone | uuid.UUID, name: str) -> list[str]:
    zone_id = zone if isinstance(zone, uuid.UUID) else zone.id
    rows = await db.execute(
        select(DNSRecord.record_type).where(DNSRecord.zone_id == zone_id, DNSRecord.name == name)
    )
    return sorted(rows.scalars().all())


async def _post(client: AsyncClient, zone: DNSZone, headers: dict[str, str], **body: object):
    return await client.post(_url(zone), headers=headers, json=body)


async def test_a_cname_beside_other_data_is_a_409_both_ways(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()

    a = await _post(client, zone, headers, name="www", record_type="A", value="10.0.0.1")
    assert a.status_code == 201, a.text
    resp = await _post(
        client, zone, headers, name="www", record_type="CNAME", value=f"t.{zone.name}"
    )
    assert resp.status_code == 409, resp.text
    assert "CNAME" in resp.json()["detail"] and a.json()["id"] in resp.json()["detail"]
    # Other data still coexists.
    resp = await _post(client, zone, headers, name="www", record_type="AAAA", value="2001:db8::1")
    assert resp.status_code == 201, resp.text
    assert await _at(db_session, zone, "www") == ["A", "AAAA"]

    cname = await _post(
        client, zone, headers, name="alias", record_type="CNAME", value=f"www.{zone.name}"
    )
    assert cname.status_code == 201, cname.text
    for body in (
        {"record_type": "A", "value": "10.0.0.2"},
        {"record_type": "TXT", "value": '"x"'},
        {"record_type": "MX", "value": f"www.{zone.name}", "priority": 10},
        {"record_type": "CNAME", "value": f"other.{zone.name}"},  # a second CNAME
    ):
        resp = await _post(client, zone, headers, name="alias", **body)
        assert resp.status_code == 409, (body, resp.text)
        assert cname.json()["id"] in resp.json()["detail"]
    assert await _at(db_session, zone, "alias") == ["CNAME"]


async def test_the_apex_never_takes_a_cname(client: AsyncClient, db_session: AsyncSession) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    for name in ("@", ""):
        resp = await _post(
            client, zone, headers, name=name, record_type="CNAME", value="target.example."
        )
        assert resp.status_code == 422, resp.text
        assert "apex" in resp.json()["detail"]
    # The apex still takes everything else.
    resp = await _post(client, zone, headers, name="@", record_type="TXT", value='"v=spf1 -all"')
    assert resp.status_code == 201, resp.text


async def test_an_ipam_record_counts_and_a_trashed_one_does_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, "host1", "A", "10.0.0.7", auto_generated=True)
    await db_session.commit()

    resp = await _post(
        client, zone, headers, name="host1", record_type="CNAME", value=f"t.{zone.name}"
    )
    assert resp.status_code == 409, resp.text

    gone = await _post(client, zone, headers, name="old", record_type="A", value="10.0.0.8")
    assert gone.status_code == 201, gone.text
    deleted = await client.delete(f"{_url(zone)}/{gone.json()['id']}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    resp = await _post(
        client, zone, headers, name="old", record_type="CNAME", value=f"t.{zone.name}"
    )
    assert resp.status_code == 201, resp.text


async def test_views_decide_whether_two_rows_meet(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    inside = DNSView(group_id=zone.group_id, name=f"in-{uuid.uuid4().hex[:4]}")
    outside = DNSView(group_id=zone.group_id, name=f"out-{uuid.uuid4().hex[:4]}")
    db_session.add_all([inside, outside])
    await db_session.commit()

    # Split horizon: a CNAME inside, an address outside, at one name.
    resp = await _post(
        client,
        zone,
        headers,
        name="www",
        record_type="CNAME",
        value=f"lb.{zone.name}",
        view_id=str(inside.id),
    )
    assert resp.status_code == 201, resp.text
    resp = await _post(
        client,
        zone,
        headers,
        name="www",
        record_type="A",
        value="203.0.113.5",
        view_id=str(outside.id),
    )
    assert resp.status_code == 201, resp.text
    # A shared row renders in every view, the inside one included.
    resp = await _post(client, zone, headers, name="www", record_type="TXT", value='"x"')
    assert resp.status_code == 409, resp.text

    resp = await _post(client, zone, headers, name="api", record_type="A", value="10.0.0.9")
    assert resp.status_code == 201, resp.text
    resp = await _post(
        client,
        zone,
        headers,
        name="api",
        record_type="CNAME",
        value=f"lb.{zone.name}",
        view_id=str(outside.id),
    )
    assert resp.status_code == 409, resp.text


async def test_an_edit_that_lands_on_a_cname_is_a_409_but_other_edits_are_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, "alias", "CNAME", f"www.{zone.name}")
    a = await _row(db_session, zone, "ren", "A", "10.0.0.3")
    c = await _row(db_session, zone, "c2", "CNAME", f"www.{zone.name}")
    await _row(db_session, zone, "data", "TXT", '"x"')
    # A pair stored before the rule: an edit that keeps its name goes through.
    legacy = await _row(db_session, zone, "both", "A", "10.0.0.4")
    await _row(db_session, zone, "both", "CNAME", f"www.{zone.name}")
    await db_session.commit()

    resp = await client.put(f"{_url(zone)}/{a.id}", headers=headers, json={"name": "alias"})
    assert resp.status_code == 409, resp.text
    resp = await client.put(f"{_url(zone)}/{c.id}", headers=headers, json={"name": "data"})
    assert resp.status_code == 409, resp.text
    # The app shares this session here; a request's own session is closed,
    # and so rolled back, when the 409 leaves the handler (app.db.get_db).
    zone_id, legacy_id, url = zone.id, legacy.id, _url(zone)
    await db_session.rollback()
    assert await _at(db_session, zone_id, "ren") == ["A"]
    assert await _at(db_session, zone_id, "c2") == ["CNAME"]

    resp = await client.put(f"{url}/{legacy_id}", headers=headers, json={"ttl": 120})
    assert resp.status_code == 200, resp.text
    resp = await client.put(
        f"{url}/{legacy_id}", headers=headers, json={"name": "both", "value": "10.0.0.5"}
    )
    assert resp.status_code == 200, resp.text


async def test_bulk_create_skips_a_clash_with_the_zone_or_the_batch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _user, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, "www", "A", "10.0.0.1")
    await _row(db_session, zone, "alias", "CNAME", f"www.{zone.name}")
    await db_session.commit()

    resp = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={
            "records": [
                {"name": "www", "record_type": "CNAME", "value": f"t.{zone.name}"},
                {"name": "alias", "record_type": "TXT", "value": '"x"'},
                # Identical to a row the zone holds: #1230's reason wins.
                {"name": "alias", "record_type": "CNAME", "value": f"www.{zone.name}"},
                {"name": "b", "record_type": "A", "value": "10.0.0.4"},
                {"name": "b", "record_type": "CNAME", "value": f"www.{zone.name}"},
                {"name": "b", "record_type": "AAAA", "value": "2001:db8::4"},
            ]
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["created"] == 2
    assert sorted((s["name"], s["reason"]) for s in body["skipped"]) == sorted(
        [
            ("alias", "identical record already exists"),
            ("alias", CNAME_CONFLICT_REASON),
            ("b", CNAME_CONFLICT_REASON),
            ("www", CNAME_CONFLICT_REASON),
        ]
    )
    assert await _at(db_session, zone, "b") == ["A", "AAAA"]

    resp = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={
            "records": [
                {"name": "ok", "record_type": "A", "value": "10.0.0.9"},
                {"name": "@", "record_type": "CNAME", "value": "target.example."},
            ]
        },
    )
    assert resp.status_code == 422, resp.text
    assert await _at(db_session, zone, "ok") == []


async def test_the_copilot_refuses_a_cname_beside_other_data(db_session: AsyncSession) -> None:
    user, _headers = await _admin(db_session)
    zone = await _zone(db_session)
    await _row(db_session, zone, "www", "A", "10.0.0.1")
    await db_session.commit()

    op = get_operation("create_dns_record")
    assert op is not None
    for name, match in (("www", "cannot take a CNAME"), ("@", "apex")):
        args = CreateDNSRecordArgs(
            zone_id=str(zone.id), name=name, record_type="CNAME", value="t.example."
        )
        preview = await op.preview(db_session, user, args)
        assert preview.ok is False and match in preview.detail
        with pytest.raises(ValueError, match=match):
            await op.apply(db_session, user, args)

"""#3672 — a zone too long to carry its apex defaults is refused, in words.

A zone name may be 253 characters, but with no Primary NS the agent serves
its SOA with the placeholder name server ``ns1.<zone>`` and with no Admin
Email the mailbox ``admin.<zone>``. Past 253 characters those are not DNS
names, BIND refuses the zone, and it is never served (and its hold-back once
stopped every other change to the group). Add Zone, Edit Zone, the template
create, the Copilot create and the importer now refuse such a zone with a 422
(or a failed zone) naming the field to set.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.services.dns.zone_apex import apex_name_length_error
from app.services.dns_import.canonical import (
    ImportedRecord,
    ImportedSOA,
    ImportedZone,
    ImportPreview,
)
from app.services.dns_import.commit import commit_import


def _long(n: int, tail: str = "example.test") -> str:
    """A valid zone name of exactly ``n`` characters (labels <= 63)."""
    labels: list[str] = []
    room = n - len(tail)
    while room > 0:
        size = min(60, room - 1)
        labels.append("a" * size)
        room -= size + 1
    name = ".".join([*labels, tail])
    assert len(name) == n, len(name)
    return name


# ── the rule ────────────────────────────────────────────────────────────────


def test_helper_250_with_neither_names_both_fields() -> None:
    err = apex_name_length_error(_long(250) + ".", "", "")
    assert err is not None
    assert "Primary NS (primary_ns)" in err and "Admin Email (admin_email)" in err
    assert "'ns1.<zone name>' (254 characters)" in err
    assert "'admin.<zone name>' (256 characters)" in err
    assert "at most 247 characters" in err


def test_helper_limits_are_exact() -> None:
    # ns1.<zone> fits at 249; admin.<zone> fits at 247.
    assert apex_name_length_error(_long(247), "", "") is None
    assert apex_name_length_error(_long(248), "", "") is not None
    assert apex_name_length_error(_long(249), "", "hostmaster.example.test.") is None
    err = apex_name_length_error(_long(250), "", "hostmaster.example.test.")
    assert err is not None and "Primary NS" in err and "Admin Email" not in err
    err = apex_name_length_error(_long(248), "ns1.example.test.", "")
    assert err is not None and "Admin Email" in err and "Primary NS" not in err


def test_helper_explicit_values_lift_the_limit() -> None:
    assert (
        apex_name_length_error(_long(253), "ns1.example.test.", "hostmaster.example.test.") is None
    )


def test_helper_an_apex_ns_record_replaces_the_placeholder_name_server() -> None:
    zone = _long(250) + "."
    records = [("@", "NS", "ns1.example.test.")]
    err = apex_name_length_error(zone, "", "hostmaster.example.test.", records)
    assert err is None


def test_helper_a_zone_of_non_host_labels_has_a_short_placeholder() -> None:
    # #3003 — such a zone's placeholder is outside it (``invalid.``).
    assert apex_name_length_error("_x." + _long(249), "", "") is None


# ── through the API ─────────────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u3672-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession) -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g3672-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    return grp


@pytest.mark.asyncio
async def test_add_zone_refuses_and_stores_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()
    name = _long(250)
    r = await client.post(f"/api/v1/dns/groups/{grp.id}/zones", json={"name": name}, headers=h)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "Primary NS (primary_ns)" in detail and "Admin Email (admin_email)" in detail
    assert "253-character limit" in detail
    stored = (await db_session.execute(select(DNSZone).where(DNSZone.group_id == grp.id))).all()
    assert stored == []


@pytest.mark.asyncio
async def test_add_zone_takes_the_same_name_with_both_fields_set(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={
            "name": _long(250),
            "primary_ns": "ns1.example.test.",
            "admin_email": "hostmaster.example.test.",
        },
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_add_zone_secondary_is_not_held_to_the_rule(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A secondary zone's SOA comes from its primary, not from our defaults."""
    h = await _headers(db_session)
    grp = await _group(db_session)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": _long(250), "zone_type": "secondary", "masters": ["192.0.2.1"]},
        headers=h,
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_edit_zone_refuses_clearing_a_field_the_name_needs(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session)
    zone = DNSZone(
        group_id=grp.id,
        name=_long(250) + ".",
        zone_type="primary",
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
    )
    db_session.add(zone)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}"

    r = await client.put(url, json={"admin_email": ""}, headers=h)
    assert r.status_code == 422, r.text
    assert "Admin Email (admin_email)" in r.json()["detail"]

    r = await client.put(url, json={"primary_ns": ""}, headers=h)
    assert r.status_code == 422, r.text
    assert "Primary NS (primary_ns)" in r.json()["detail"]

    # An unrelated edit that re-sends the stored values goes through.
    r = await client.put(
        url,
        json={
            "ttl": 600,
            "primary_ns": "ns1.example.test.",
            "admin_email": "hostmaster.example.test.",
        },
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_edit_zone_a_stored_long_zone_stays_editable(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A zone stored before the rule must take an edit that does not touch
    the inputs, or the operator cannot even rename it out of trouble."""
    h = await _headers(db_session)
    grp = await _group(db_session)
    zone = DNSZone(group_id=grp.id, name=_long(250) + ".", zone_type="primary")
    db_session.add(zone)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}"

    r = await client.put(url, json={"ttl": 600}, headers=h)
    assert r.status_code == 200, r.text
    r = await client.put(url, json={"admin_email": "hostmaster.example.test."}, headers=h)
    assert r.status_code == 422, r.text
    assert "Primary NS (primary_ns)" in r.json()["detail"]
    r = await client.put(
        url,
        json={"admin_email": "hostmaster.example.test.", "primary_ns": "ns1.example.test."},
        headers=h,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_importer_fails_the_zone_and_stores_nothing(db_session: AsyncSession) -> None:
    user = User(
        username=f"u3672-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    grp = await _group(db_session)
    name = _long(250) + "."
    zone = ImportedZone(
        name=name,
        zone_type="primary",
        kind="forward",
        soa=ImportedSOA("", "", 1, 3600, 600, 86400, 300, 3600),
        records=[ImportedRecord("www", "A", "192.0.2.1", 300)],
    )
    res = await commit_import(
        db_session,
        preview=ImportPreview(
            source="bind9",
            zones=[zone],
            conflicts=[],
            warnings=[],
            total_records=1,
            record_type_histogram={},
        ),
        target_group_id=grp.id,
        target_view_id=None,
        conflict_actions={},
        current_user=user,
    )
    assert res.zones[0].action_taken == "failed"
    assert "Primary NS (primary_ns)" in (res.zones[0].error or "")
    assert (await db_session.execute(select(DNSZone).where(DNSZone.group_id == grp.id))).all() == []
    assert (await db_session.execute(select(DNSRecord))).all() == []

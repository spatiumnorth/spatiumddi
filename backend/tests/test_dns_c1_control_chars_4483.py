"""A C1 control character (U+0080..U+009F) is refused in DNS data as C0 is (#4483).

``contains_control_chars`` was documented C0/C1 but matched C0 + DEL only, so a
TXT value holding U+0085 (NEL) or U+009B (CSI) was stored while U+0007 was
refused. IDN / UTF-8 text outside the C1 block must still pass.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dns_names import (
    contains_control_chars,
    contains_zonefile_unsafe,
    record_value_error,
    strip_control_chars,
)
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServerGroup, DNSZone

C1 = ["\x80", "\x85", "\x9b", "\x9f"]


@pytest.mark.parametrize("ch", C1 + ["\x7f", "\x07"])
def test_guard_and_strip_cover_c0_del_c1(ch: str) -> None:
    assert contains_control_chars(f"one{ch}two")
    assert contains_zonefile_unsafe(f"one{ch}two")
    assert strip_control_chars(f"one{ch}two") == "onetwo"


@pytest.mark.parametrize("text", ["café", " nbsp", "ÿ", "例え", "…"])
def test_utf8_text_outside_c1_is_untouched(text: str) -> None:
    assert not contains_control_chars(text)
    assert strip_control_chars(text) == text


@pytest.mark.parametrize(
    "rtype,value",
    [
        ("TXT", "one\x85two"),
        ("A", "10.0.0.1\x85"),
        ("CNAME", "t\x9barget.example."),
        ("MX", "mail\x80.example."),
        ("TXT", "\x9f"),
    ],
)
def test_record_value_refuses_c1(rtype: str, value: str) -> None:
    assert record_value_error(rtype, value) is not None


def test_record_value_accepts_idn_text() -> None:
    assert record_value_error("TXT", "v=spf1 café …") is None


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DNSZone]:
    user = User(
        username=f"c1-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    grp = DNSServerGroup(name=f"c1-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"c1{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, zone


def _url(zone: DNSZone) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rtype,good,bad",
    [
        ("TXT", "one two", "one\x85two"),
        ("A", "10.0.0.1", "10.0.0.1\x80"),
        ("CNAME", "target.example.", "tar\x9bget.example."),
        ("MX", "mail.example.", "mail\x9f.example."),
    ],
)
async def test_record_create_and_update_refuse_c1(
    db_session: AsyncSession, client: AsyncClient, rtype: str, good: str, bad: str
) -> None:
    headers, zone = await _setup(db_session)
    body = {"name": "t", "record_type": rtype, "value": good}
    if rtype == "MX":
        body["priority"] = 10
    ok = await client.post(_url(zone), json=body, headers=headers)
    assert ok.status_code == 201, ok.text
    rid = ok.json()["id"]

    refused = await client.post(
        _url(zone), json={**body, "name": "t2", "value": bad}, headers=headers
    )
    assert refused.status_code == 422, refused.text

    upd = await client.put(f"{_url(zone)}/{rid}", json={"value": bad}, headers=headers)
    assert upd.status_code == 422, upd.text

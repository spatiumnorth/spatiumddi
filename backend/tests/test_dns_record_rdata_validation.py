"""Structured rdata dnspython cannot read is a 422, not a stored row (#2502).

The BIND9 agent writes ``value`` into the zone file verbatim, so one bad CAA /
TLSA / SSHFP / NAPTR / LOC / MX / SRV row made ``named-checkzone`` refuse the
zone and the agent quarantine the server's whole bundle.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_dns_record_cname_alone import _admin, _post, _row, _url, _zone

BAD = [
    ("CAA", "garbage"),
    ("TLSA", "not a tlsa"),
    ("SSHFP", "1 2 zz"),
    ("NAPTR", "x"),
    ("LOC", "nonsense"),
    ("MX", "mail.example.com extra"),
]

GOOD = [
    ("CAA", '0 issue "letsencrypt.org"'),
    ("SSHFP", "1 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789"),
    ("MX", "mail.example.com."),
    ("TXT", "v=spf1 -all"),
]


@pytest.mark.parametrize("rtype,value", BAD)
async def test_bad_rdata_is_422_on_create(
    client: AsyncClient, db_session: AsyncSession, rtype: str, value: str
) -> None:
    _u, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    r = await _post(client, zone, headers, name="x", record_type=rtype, value=value)
    assert r.status_code == 422, r.text
    assert rtype in r.json()["detail"]


async def test_srv_with_extra_token_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    _u, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    r = await _post(
        client,
        zone,
        headers,
        name="_sip._tcp",
        record_type="SRV",
        value="a.example.com b",
        priority=1,
        weight=1,
        port=5060,
    )
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("rtype,value", GOOD)
async def test_good_rdata_still_201(
    client: AsyncClient, db_session: AsyncSession, rtype: str, value: str
) -> None:
    _u, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    r = await _post(client, zone, headers, name="x", record_type=rtype, value=value)
    assert r.status_code == 201, r.text


async def test_srv_with_separate_fields_is_201(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    r = await _post(
        client,
        zone,
        headers,
        name="_sip._tcp",
        record_type="SRV",
        value="sip.example.com.",
        priority=1,
        weight=2,
        port=5060,
    )
    assert r.status_code == 201, r.text


async def test_update_to_bad_value_is_422_but_unrelated_edit_of_legacy_row_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, headers = await _admin(db_session)
    zone = await _zone(db_session)
    legacy = await _row(db_session, zone, "old", "CAA", "garbage")
    ok = await _row(db_session, zone, "new", "CAA", '0 issue "a.example"')
    await db_session.commit()
    bad = await client.put(f"{_url(zone)}/{ok.id}", headers=headers, json={"value": "garbage"})
    assert bad.status_code == 422, bad.text
    ttl = await client.put(f"{_url(zone)}/{legacy.id}", headers=headers, json={"ttl": 600})
    assert ttl.status_code == 200, ttl.text


async def test_bulk_create_refuses_the_batch_on_bad_rdata(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _u, headers = await _admin(db_session)
    zone = await _zone(db_session)
    await db_session.commit()
    r = await client.post(
        f"{_url(zone)}/bulk-create",
        headers=headers,
        json={"records": [{"name": "x", "record_type": "TLSA", "value": "not a tlsa"}]},
    )
    assert r.status_code == 422, r.text


def test_helper_composes_priority_like_the_agent() -> None:
    from app.core.dns_names import structured_rdata_error

    assert structured_rdata_error("MX", "mail.example.com.", priority=10) is None
    assert structured_rdata_error("MX", "mail.example.com. extra", priority=10)
    assert structured_rdata_error("MX", "mail", priority=10, origin="example.com.") is None
    assert structured_rdata_error("FOO", "anything") is None
    assert structured_rdata_error("ALIAS", "anything") is None

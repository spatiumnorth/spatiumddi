"""#2073 — every TTL an operator stores that reaches a rendered zone is bounded
0..2^31-1, and a zone or record stored negative before the bound serves anyway.

A negative ``$TTL`` (or record TTL) makes BIND refuse the whole zone file, so
the zone is never served. The zone/record schemas are covered in
``test_dns_zone_soa_timers.py``; this file covers the IPAM DDNS TTL (it stamps
the TTL of every DDNS-generated record), the importers, and how the bundle and
the record-op path ship rows stored before the bound existed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import (
    DNS_TTL_MAX,
    DNSRecord,
    DNSServer,
    DNSServerGroup,
    DNSZone,
    servable_ttl,
)
from app.services.dns.agent_config import build_config_bundle
from app.services.dns.record_ops import record_op_payload
from app.services.dns.rrset import _rrset_payload
from app.services.dns_import.canonical import ImportedSOA, ImportedZone
from app.services.dns_import.commit import _zone_kwargs_from_parsed
from app.services.dns_io.parser import parse_zone_file


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ttl-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TTL Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group_with_server(db: AsyncSession) -> tuple[DNSServerGroup, DNSServer]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host=f"dns-{uuid.uuid4().hex[:6]}",
        name=f"dns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    await db.flush()
    return grp, server


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [-1, DNS_TTL_MAX + 1])
async def test_an_ipam_ddns_ttl_out_of_range_is_refused(
    client: AsyncClient, db_session: AsyncSession, value: int
) -> None:
    headers = await _headers(db_session)
    created = await client.post(
        "/api/v1/ipam/spaces",
        json={"name": f"s-{uuid.uuid4().hex[:6]}", "ddns_ttl": value},
        headers=headers,
    )
    assert created.status_code == 422, created.text
    assert "ddns_ttl" in created.text

    ok = await client.post(
        "/api/v1/ipam/spaces",
        json={"name": f"s-{uuid.uuid4().hex[:6]}", "ddns_ttl": 300},
        headers=headers,
    )
    assert ok.status_code == 201, ok.text
    updated = await client.put(
        f"/api/v1/ipam/spaces/{ok.json()['id']}", json={"ddns_ttl": value}, headers=headers
    )
    assert updated.status_code == 422, updated.text
    assert "ddns_ttl" in updated.text


@pytest.mark.asyncio
async def test_a_zone_ttl_written_as_text_is_refused_not_truncated(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2074's API half: ``"1h"`` is a 422, never 1."""
    headers = await _headers(db_session)
    grp, _server = await _group_with_server(db_session)
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": f"z{uuid.uuid4().hex[:6]}.example.test", "ttl": "1h"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "ttl" in resp.text


@pytest.mark.asyncio
async def test_a_zone_and_record_stored_negative_before_the_bound_still_serve(
    db_session: AsyncSession,
) -> None:
    """A row the API accepted before #2073 is shipped servable: the zone with
    the create default ``$TTL``, the record inheriting it. Shipping ``-1`` made
    BIND refuse the zone file, so the zone was never served."""
    grp, server = await _group_with_server(db_session)
    zone = DNSZone(
        group_id=grp.id, name="neg.example.test.", zone_type="primary", kind="forward", ttl=-1
    )
    db_session.add(zone)
    await db_session.flush()
    db_session.add(
        DNSRecord(zone_id=zone.id, name="www", record_type="A", value="192.0.2.1", ttl=-5)
    )
    db_session.add(
        DNSRecord(zone_id=zone.id, name="mail", record_type="A", value="192.0.2.2", ttl=120)
    )
    await db_session.commit()

    bundle = await build_config_bundle(db_session, server)

    (shipped,) = [z for z in bundle["zones"] if z["name"] == "neg.example.test."]
    assert shipped["ttl"] == 3600
    ttls = {r["name"]: r["ttl"] for r in shipped["records"]}
    assert ttls == {"www": None, "mail": 120}


def test_servable_ttl_keeps_the_rfc_2181_range_and_drops_the_rest() -> None:
    assert [servable_ttl(v) for v in (None, -1, 0, 300, DNS_TTL_MAX, DNS_TTL_MAX + 1)] == [
        None,
        None,
        0,
        300,
        DNS_TTL_MAX,
        None,
    ]


def test_a_record_op_and_its_rrset_never_carry_a_negative_ttl() -> None:
    """The RFC 2136 / agentless path ships a stored row the same way the
    bundle does: a negative TTL is null (inherit), and the RRset resolves
    a null against a servable zone TTL."""
    rec = DNSRecord(
        id=uuid.uuid4(),
        zone_id=uuid.uuid4(),
        name="www",
        record_type="A",
        value="192.0.2.1",
        ttl=-5,
    )
    assert record_op_payload(rec)["ttl"] is None

    members = [{"value": "192.0.2.1", "ttl": -5}, {"value": "192.0.2.2", "ttl": None}]
    assert _rrset_payload(members, -1)["ttl"] == 3600
    assert _rrset_payload(members, 600)["ttl"] == 600
    assert _rrset_payload([{"value": "192.0.2.1", "ttl": 60}], -1)["ttl"] == 60


def test_an_imported_zone_with_ttls_out_of_range_stores_servable_values() -> None:
    """An uploaded export can carry a TTL no server serves (-1), or one past
    int4 that would 500 the commit; the zone takes the defaults instead."""
    soa = ImportedSOA(
        primary_ns="ns1.example.test.",
        admin_email="hostmaster.example.test.",
        serial=1,
        refresh=-1,
        retry=600,
        expire=2**32 - 1,
        minimum=300,
        ttl=-1,
    )
    parsed = ImportedZone(
        name="imp.example.test.", zone_type="primary", kind="forward", soa=soa, records=[]
    )
    kw = _zone_kwargs_from_parsed(
        parsed,
        name="imp.example.test.",
        target_group_id=uuid.uuid4(),
        target_view_id=None,
        source="powerdns",
        now=datetime.now(UTC),
    )
    assert (kw["ttl"], kw["refresh"], kw["retry"], kw["expire"], kw["minimum"]) == (
        3600,
        86400,
        600,
        3600000,
        300,
    )


def test_a_zone_file_record_ttl_past_rfc_2181_inherits() -> None:
    """dnspython accepts a TTL up to 2^32-1; past 2^31-1 the column cannot hold
    it, so the parsed record inherits the zone's $TTL instead of 500ing."""
    text = (
        "$TTL 300\n"
        "@ IN SOA ns1.big.test. hostmaster.big.test. 1 3600 600 86400 300\n"
        "@ IN NS ns1.big.test.\n"
        "big 4294967295 IN A 192.0.2.1\n"
        "ok 60 IN A 192.0.2.2\n"
    )
    parsed = parse_zone_file(text, "big.test.")
    ttls = {r.name: r.ttl for r in parsed.records if r.record_type == "A"}
    assert ttls == {"big": None, "ok": 60}

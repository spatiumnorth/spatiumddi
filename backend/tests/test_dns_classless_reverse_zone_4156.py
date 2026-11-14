"""#4156 — an RFC 2317 classless reverse zone can be created over REST.

``0/26.2.0.192.in-addr.arpa`` was refused by the zone-name rule (a ``/`` is not
an LDH label character) while a DNS configuration import created it and BIND9
serves it. The slash is legal only as the first label of a name under
``in-addr.arpa``; every other ``/`` is still a 422.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns.agent_config import build_config_bundle


async def _setup(db: AsyncSession) -> tuple[dict[str, str], DNSServerGroup, DNSServer]:
    user = User(
        username=f"cl-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Classless Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
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
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}, grp, server


@pytest.mark.asyncio
async def test_classless_reverse_zone_create_ptr_and_bundle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, server = await _setup(db_session)
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones",
        json={"name": "0/26.2.0.192.in-addr.arpa"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    zone = resp.json()
    assert zone["name"] == "0/26.2.0.192.in-addr.arpa."
    assert zone["kind"] == "reverse"

    for rtype, name, value in (("PTR", "5", "host.example.test."), ("CNAME", "6", "x.example.")):
        rec = await client.post(
            f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}/records",
            json={"name": name, "record_type": rtype, "value": value},
            headers=headers,
        )
        assert rec.status_code == 201, rec.text

    bundle = await build_config_bundle(db_session, server)
    assert "0/26.2.0.192.in-addr.arpa." in [z["name"] for z in bundle["zones"]]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name", ["0/26.example.test", "0/24.2.0.192.in-addr.arpa", "a/26.2.0.192.in-addr.arpa"]
)
async def test_other_slash_zone_names_are_still_refused(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    headers, grp, _ = await _setup(db_session)
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": name}, headers=headers
    )
    assert resp.status_code == 422, resp.text


# ── #4166: the parent zone's RFC 2317 records ────────────────────────────


async def _zone(
    client: AsyncClient, headers: dict[str, str], grp: DNSServerGroup, name: str
) -> dict[str, Any]:
    resp = await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones", json={"name": name}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()  # type: ignore[no-any-return]


async def _record(
    client: AsyncClient,
    headers: dict[str, str],
    grp: DNSServerGroup,
    zone: dict[str, Any],
    name: str,
    rtype: str,
    value: str,
) -> Response:
    return await client.post(
        f"/api/v1/dns/groups/{grp.id}/zones/{zone['id']}/records",
        json={"name": name, "record_type": rtype, "value": value},
        headers=headers,
    )


@pytest.mark.asyncio
async def test_parent_zone_takes_the_classless_cname_and_delegation_ns(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, grp, _ = await _setup(db_session)
    parent = await _zone(client, headers, grp, "2.0.192.in-addr.arpa")
    child = await _zone(client, headers, grp, "64/26.2.0.192.in-addr.arpa")

    target = "65.64/26.2.0.192.in-addr.arpa."
    cname = await _record(client, headers, grp, parent, "65", "CNAME", target)
    assert cname.status_code == 201, cname.text
    ns = await _record(client, headers, grp, parent, "64/26", "NS", "ns1.example.net.")
    assert ns.status_code == 201, ns.text
    assert ns.json()["fqdn"].startswith("64/26.2.0.192")
    # The PTR the CNAME lands on lives in the child.
    ptr = await _record(client, headers, grp, child, "65", "PTR", "host.example.test.")
    assert ptr.status_code == 201, ptr.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("zone_name", "name", "rtype", "value"),
    [
        # a '/' in an owner anywhere but the delegation NS of a classless child
        ("example.test", "64/26", "NS", "ns1.example.net."),
        ("example.test", "64/26", "A", "192.0.2.1"),
        ("2.0.192.in-addr.arpa", "64/26", "A", "192.0.2.1"),
        ("2.0.192.in-addr.arpa", "64/26", "PTR", "host.example.test."),
        ("2.0.192.in-addr.arpa", "64/24", "NS", "ns1.example.net."),
        ("2.0.192.in-addr.arpa", "x.64/26", "NS", "ns1.example.net."),
        # a '/' in a CNAME target that is not a classless child
        ("2.0.192.in-addr.arpa", "65", "CNAME", "65.64/24.2.0.192.in-addr.arpa."),
        ("2.0.192.in-addr.arpa", "65", "CNAME", "65.64/26.example.com."),
        ("2.0.192.in-addr.arpa", "65", "CNAME", "x.64/26.2.0.192.in-addr.arpa."),
        ("example.test", "www", "CNAME", "65.64/26.example.com."),
    ],
)
async def test_other_slashes_in_records_are_still_refused(
    client: AsyncClient,
    db_session: AsyncSession,
    zone_name: str,
    name: str,
    rtype: str,
    value: str,
) -> None:
    headers, grp, _ = await _setup(db_session)
    zone = await _zone(client, headers, grp, zone_name)
    resp = await _record(client, headers, grp, zone, name, rtype, value)
    assert resp.status_code == 422, resp.text

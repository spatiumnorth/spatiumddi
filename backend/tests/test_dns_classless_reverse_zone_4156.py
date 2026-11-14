"""#4156 — an RFC 2317 classless reverse zone can be created over REST.

``0/26.2.0.192.in-addr.arpa`` was refused by the zone-name rule (a ``/`` is not
an LDH label character) while a DNS configuration import created it and BIND9
serves it. The slash is legal only as the first label of a name under
``in-addr.arpa``; every other ``/`` is still a 422.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
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

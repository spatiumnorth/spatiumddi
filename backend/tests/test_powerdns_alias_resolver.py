"""A PowerDNS group's ALIAS resolver is its own forwarders, never a public default (#1353).

PowerDNS expands an ALIAS through ``resolver=`` in pdns.conf. The control
plane never sent one, so the agent's hardcoded ``1.1.1.1,8.8.8.8`` reached
every PowerDNS server: ALIAS targets went to Cloudflare and Google, an
outbound connection nobody configured. Now the bundle carries the group's
plain-DNS forwarders, and a new ALIAS record on a group without them is
refused rather than stored to answer nothing.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions, DNSZone
from app.services.dns.powerdns_alias import alias_resolver


@pytest.mark.parametrize(
    ("forwarders", "transport", "expected"),
    [
        (["10.0.0.53"], "do53", "10.0.0.53"),
        (["10.0.0.53@5353", "2001:db8::53@53"], "do53", "10.0.0.53:5353,[2001:db8::53]:53"),
        (["10.0.0.53"], None, "10.0.0.53"),
        ([], "do53", ""),
        (None, "do53", ""),
        # resolver= speaks Do53 only; an encrypted choice is not downgraded.
        (["10.0.0.53"], "tls", ""),
        (["10.0.0.53"], "https", ""),
        # Rows stored before forwarders were validated never reach pdns.conf.
        (
            ["10.0.0.53\nlaunch=bind", "ns.example.com", "10.0.0.1@99999", "10.0.0.2"],
            "do53",
            "10.0.0.2",
        ),
    ],
)
def test_alias_resolver(forwarders: list[str] | None, transport: str | None, expected: str) -> None:
    assert alias_resolver(forwarders, transport) == expected


async def _setup(db: AsyncSession, forwarders: list[str]) -> tuple[dict[str, str], str]:
    user = User(
        username=f"al-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Alias Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    group = DNSServerGroup(name=f"al-{uuid.uuid4().hex[:6]}")
    db.add_all([user, group])
    await db.flush()
    db.add(
        DNSServer(
            group_id=group.id,
            name=f"pdns-{uuid.uuid4().hex[:6]}",
            driver="powerdns",
            host="10.0.0.10",
        )
    )
    db.add(DNSServerOptions(group_id=group.id, forwarders=forwarders))
    zone = DNSZone(
        group_id=group.id,
        name=f"z{uuid.uuid4().hex[:6]}.test.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.test.",
        admin_email="admin.example.test.",
    )
    db.add(zone)
    await db.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    return headers, f"/api/v1/dns/groups/{group.id}/zones/{zone.id}/records"


@pytest.mark.asyncio
async def test_an_alias_needs_the_groups_forwarders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, url = await _setup(db_session, [])
    resp = await client.post(
        url, headers=headers, json={"name": "@", "record_type": "ALIAS", "value": "lb.example.net."}
    )
    assert resp.status_code == 422, resp.text
    assert "forwarders" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_alias_is_accepted_with_forwarders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, url = await _setup(db_session, ["10.0.0.53"])
    resp = await client.post(
        url, headers=headers, json={"name": "@", "record_type": "ALIAS", "value": "lb.example.net."}
    )
    assert resp.status_code in (200, 201), resp.text


def test_a_scoped_ipv6_forwarder_is_dropped() -> None:
    # ``ipaddress`` accepts a zone index; ``resolver=`` cannot parse one, and
    # the agent refuses the whole list when it sees it.
    assert alias_resolver(["fe80::1%eth0", "10.0.0.2"], "do53") == "10.0.0.2"


@pytest.mark.asyncio
async def test_clearing_the_forwarders_under_live_alias_records_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, url = await _setup(db_session, ["10.0.0.53"])
    resp = await client.post(
        url, headers=headers, json={"name": "@", "record_type": "ALIAS", "value": "lb.example.net."}
    )
    assert resp.status_code in (200, 201), resp.text
    options_url = url.split("/zones/")[0] + "/options"

    resp = await client.put(options_url, headers=headers, json={"forwarders": []})
    assert resp.status_code == 422, resp.text
    assert "ALIAS" in resp.json()["detail"]

    # Changing the forwarders while keeping one still saves.
    resp = await client.put(options_url, headers=headers, json={"forwarders": ["10.0.0.54"]})
    assert resp.status_code == 200, resp.text

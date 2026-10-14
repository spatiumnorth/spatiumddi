"""#1858 — Technitium has no HMAC-SHA224, so a sha224 TSIG key is refused (422)
on a Technitium group instead of being installed and failing every signed
transfer with BADKEY.

Upstream: TechnitiumLibrary ``DnsDatagram.GetTsigMacSize`` handles hmac-md5,
-sha1, -sha256, -sha256-128, -sha384, -sha384-192, -sha512, -sha512-256 and
returns 0 for anything else.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSTSIGKey, DNSZoneUpdateAcl
from tests.test_dns_server_group_move import (
    _auth,
    _fleet_appliance,
    _group,
    _roles_url,
    _server,
    _superadmin,
)
from tests.test_dns_zone_group_move import _commit, _preview, _zone

TECHNITIUM = ["technitium", "technitium_api"]


def _keys_url(group_id: object) -> str:
    return f"/api/v1/dns/groups/{group_id}/tsig-keys"


async def _key(db: AsyncSession, group: object, name: str, algo: str) -> DNSTSIGKey:
    k = DNSTSIGKey(group_id=group.id, name=name, algorithm=algo, secret_encrypted=b"x")  # type: ignore[attr-defined]
    db.add(k)
    await db.flush()
    return k


def test_policy_table() -> None:
    from app.services.dns.tsig_algorithms import key_refusal, unsupported_drivers

    for driver in TECHNITIUM:
        assert unsupported_drivers("hmac-sha224", [driver]) == [driver]
        for ok in ("hmac-sha1", "hmac-sha256", "hmac-sha384", "hmac-sha512"):
            assert unsupported_drivers(ok, [driver]) == []
    # BIND9 and PowerDNS both implement sha224; Windows / cloud use no TSIG keys.
    for driver in ("bind9", "powerdns", "windows_dns", "route53"):
        assert unsupported_drivers("hmac-sha224", [driver]) == []
    msg = key_refusal("hmac-sha224", ["technitium"], key="k224")
    assert msg and "hmac-sha224" in msg and "Technitium" in msg and "k224" in msg


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", TECHNITIUM)
async def test_create_sha224_key_in_technitium_group_is_422(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    token = await _superadmin(db_session, f"r1858a{driver}")
    g = await _group(db_session, f"t-{driver}")
    await _server(db_session, g, "ns1", driver=driver)
    r = await client.post(
        _keys_url(g.id),
        json={"name": "k224", "algorithm": "hmac-sha224"},
        headers=_auth(token),
    )
    assert r.status_code == 422, r.text
    assert "hmac-sha224" in r.json()["detail"] and "Technitium" in r.json()["detail"]
    ok = await client.post(
        _keys_url(g.id),
        json={"name": "k256", "algorithm": "hmac-sha256"},
        headers=_auth(token),
    )
    assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
@pytest.mark.parametrize("driver", ["bind9", "powerdns"])
async def test_sha224_key_still_allowed_on_other_drivers(
    client: AsyncClient, db_session: AsyncSession, driver: str
) -> None:
    token = await _superadmin(db_session, f"r1858b{driver}")
    g = await _group(db_session, f"o-{driver}")
    await _server(db_session, g, "ns1", driver=driver)
    r = await client.post(
        _keys_url(g.id), json={"name": "k224", "algorithm": "hmac-sha224"}, headers=_auth(token)
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_update_to_sha224_is_422_but_resaving_is_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "r1858c")
    g = await _group(db_session, "tu")
    await _server(db_session, g, "ns1", driver="technitium")
    k = await _key(db_session, g, "k256", "hmac-sha256")
    r = await client.put(
        f"{_keys_url(g.id)}/{k.id}", json={"algorithm": "hmac-sha224"}, headers=_auth(token)
    )
    assert r.status_code == 422, r.text
    assert "hmac-sha224" in r.json()["detail"]
    # A key stored before the gate keeps saving: only a CHANGE is refused.
    legacy = await _key(db_session, g, "old224", "hmac-sha224")
    r = await client.put(
        f"{_keys_url(g.id)}/{legacy.id}",
        json={"algorithm": "hmac-sha224", "notes": "kept"},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_technitium_server_cannot_join_group_holding_sha224_key(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "r1858d")
    dst = await _group(db_session, "holds224")
    await _key(db_session, dst, "k224", "hmac-sha224")
    # create
    r = await client.post(
        f"/api/v1/dns/groups/{dst.id}/servers",
        json={"name": "t1", "driver": "technitium", "host": "t1", "port": 53},
        headers=_auth(token),
    )
    assert r.status_code == 422, r.text
    assert "hmac-sha224" in r.json()["detail"]
    # move
    src = await _group(db_session, "src")
    srv = await _server(db_session, src, "t2", driver="technitium")
    r = await client.put(
        f"/api/v1/dns/groups/{src.id}/servers/{srv.id}",
        json={"group_id": str(dst.id)},
        headers=_auth(token),
    )
    assert r.status_code == 422, r.text
    assert "k224" in r.json()["detail"]
    # a BIND9 server may still join: it signs with sha224 fine
    r = await client.post(
        f"/api/v1/dns/groups/{dst.id}/servers",
        json={"name": "b1", "driver": "bind9", "host": "b1", "port": 53},
        headers=_auth(token),
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_fleet_technitium_role_into_group_holding_sha224_key_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "r1858e")
    plain = await _group(db_session, "plain")
    dst = await _group(db_session, "holds224f")
    await _key(db_session, dst, "k224", "hmac-sha224")
    appliance = await _fleet_appliance(db_session, plain)
    appliance.assigned_roles = ["dns-technitium"]
    await db_session.flush()
    r = await client.put(
        _roles_url(appliance.id), json={"dns_group_id": str(dst.id)}, headers=_auth(token)
    )
    assert r.status_code == 422, r.text
    assert "hmac-sha224" in r.json()["detail"]


@pytest.mark.asyncio
async def test_zone_using_a_sha224_key_cannot_move_into_a_technitium_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "r1858f")
    src = await _group(db_session, "zsrc")
    dst = await _group(db_session, "zdst")
    await _server(db_session, dst, "t1", driver="technitium")
    src_key = await _key(db_session, src, "ddns", "hmac-sha256")
    await _key(db_session, dst, "ddns", "hmac-sha224")  # stored before the gate
    zone = await _zone(db_session, src)
    db_session.add(
        DNSZoneUpdateAcl(
            zone_id=zone.id, seq=0, action="grant", match_kind="tsig_key", tsig_key_id=src_key.id
        )
    )
    await db_session.flush()
    # The preview reports the refusal the commit raises, so the UI can block
    # the Move button instead of letting the operator find out on commit.
    p = await _preview(client, token, zone, dst)
    assert p.status_code == 200, p.text
    refusal = p.json()["tsig_algorithm_refusal"]
    assert refusal and "hmac-sha224" in refusal and "ddns" in refusal
    r = await _commit(client, token, zone, dst, acks=[])
    assert r.status_code == 422, r.text
    assert "hmac-sha224" in r.json()["detail"] and "ddns" in r.json()["detail"]


@pytest.mark.asyncio
async def test_copilot_technitium_role_into_group_holding_sha224_key_is_refused(
    db_session: AsyncSession,
) -> None:
    from sqlalchemy import select

    from app.models.auth import User
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
        _preview_assign_appliance_role,
    )

    await _superadmin(db_session, "r1858g")
    user = (await db_session.execute(select(User).where(User.username == "r1858g"))).scalar_one()
    plain = await _group(db_session, "plain-g")
    dst = await _group(db_session, "holds224g")
    await _key(db_session, dst, "k224", "hmac-sha224")
    appliance = await _fleet_appliance(db_session, plain)
    args = AssignApplianceRoleArgs(
        appliance_id=str(appliance.id), roles=["dns-technitium"], dns_group_id=str(dst.id)
    )
    preview = await _preview_assign_appliance_role(db_session, user, args)
    assert not preview.ok
    assert "hmac-sha224" in preview.detail
    with pytest.raises(ValueError, match="hmac-sha224"):
        await _apply_assign_appliance_role(db_session, user, args)
    assert appliance.assigned_dns_group_id == plain.id

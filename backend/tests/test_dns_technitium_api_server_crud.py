"""API-level lifecycle for the agentless Technitium driver (issue #810).

The driver's own behaviour is covered offline in
``test_dns_driver_technitium_api.py``. This file exercises the parts that
only exist at the router boundary: credential validation on save, the
merge-on-update contract the modal promises, and the test-connection probe.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup

_CREDS = {
    "api_url": "https://dns.example.test:53443",
    "api_token": "tok-original",
    "verify_tls": False,
}


async def _admin(db: AsyncSession) -> str:
    suffix = uuid.uuid4().hex[:8]
    user = User(
        username=f"tech-api-{suffix}",
        email=f"tech-api-{suffix}@example.test",
        display_name="Tech API Admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def _group(db: AsyncSession) -> DNSServerGroup:
    g = DNSServerGroup(name=f"tech-api-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    return g


async def _server(db: AsyncSession, group: DNSServerGroup, creds: dict[str, Any] | None) -> Any:
    s = DNSServer(
        group_id=group.id,
        name=f"tech-{uuid.uuid4().hex[:6]}",
        driver="technitium_api",
        host="10.0.0.53",
        port=53,
        credentials_encrypted=encrypt_dict(creds) if creds else None,
    )
    db.add(s)
    await db.flush()
    return s


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── create ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_requires_credentials(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers",
        headers=_h(token),
        json={"name": "t1", "driver": "technitium_api", "host": "10.0.0.53"},
    )
    assert resp.status_code == 400
    assert "cloud_credentials" in resp.text


@pytest.mark.asyncio
async def test_create_rejects_a_schemeless_api_url(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Refused at save rather than at the first sync.

    Guessing http:// would put the bearer token on the wire in cleartext.
    """
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers",
        headers=_h(token),
        json={
            "name": "t1",
            "driver": "technitium_api",
            "host": "10.0.0.53",
            "cloud_credentials": {"api_url": "dns.example.test", "api_token": "t"},
        },
    )
    assert resp.status_code == 422
    assert "http:// or https://" in resp.text


@pytest.mark.asyncio
async def test_create_rejects_a_missing_token(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers",
        headers=_h(token),
        json={
            "name": "t1",
            "driver": "technitium_api",
            "host": "10.0.0.53",
            "cloud_credentials": {"api_url": "https://dns.example.test"},
        },
    )
    assert resp.status_code == 422
    assert "Create Token" in resp.text


@pytest.mark.asyncio
async def test_create_stores_the_credentials_encrypted(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    group = await _group(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers",
        headers=_h(token),
        json={
            "name": "t1",
            "driver": "technitium_api",
            "host": "10.0.0.53",
            "cloud_credentials": _CREDS,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # Credentials are never echoed back.
    assert "cloud_credentials" not in body
    assert "tok-original" not in resp.text

    row = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == uuid.UUID(body["id"])))
    ).scalar_one()
    assert decrypt_dict(row.credentials_encrypted) == _CREDS


# ── update: the merge contract ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_merges_over_the_stored_credentials(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """An edit that leaves the URL alone must not wipe the token.

    The modal renders every credential field blank on edit — credentials are
    never returned — and tells the operator blank means "keep". A full
    replace turned a settings edit into "delete the token", and the server
    then 422s on save for the token it just discarded. A new URL is another
    destination, so it needs the token again (and then merges over the rest).
    """
    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, _CREDS)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{group.id}/servers/{server.id}"

    resp = await client.put(
        url,
        headers=_h(token),
        json={"cloud_credentials": {"api_url": "https://dns.example.test:5380"}},
    )
    assert resp.status_code == 422, resp.text

    resp = await client.put(
        url,
        headers=_h(token),
        json={
            "cloud_credentials": {
                "api_url": "https://dns.example.test:5380",
                "api_token": "tok-original",
            }
        },
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(server)
    stored = decrypt_dict(server.credentials_encrypted)
    assert stored["api_url"] == "https://dns.example.test:5380"
    assert stored["api_token"] == "tok-original"
    # An untouched checkbox keeps its stored value rather than reverting to
    # the default — the whole point of merging.
    assert stored["verify_tls"] is False


@pytest.mark.asyncio
async def test_update_can_toggle_verify_tls_alone(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, _CREDS)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}",
        headers=_h(token),
        json={"cloud_credentials": {"verify_tls": True}},
    )
    assert resp.status_code == 200, resp.text

    await db_session.refresh(server)
    stored = decrypt_dict(server.credentials_encrypted)
    assert stored["verify_tls"] is True
    assert stored["api_token"] == "tok-original"


@pytest.mark.asyncio
async def test_update_can_clear_credentials(db_session: AsyncSession, client: AsyncClient) -> None:
    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, _CREDS)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}",
        headers=_h(token),
        json={"cloud_credentials": {}},
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.credentials_encrypted is None


@pytest.mark.asyncio
async def test_credentials_are_refused_on_a_driver_that_takes_none(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Never clobber a bind9 row's credentials column with a meaningless blob."""
    token = await _admin(db_session)
    group = await _group(db_session)
    server = DNSServer(group_id=group.id, name="b1", driver="bind9", host="10.0.0.1", port=53)
    db_session.add(server)
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}",
        headers=_h(token),
        json={"cloud_credentials": {"api_url": "https://x.test", "api_token": "t"}},
    )
    assert resp.status_code == 400
    assert "bind9" in resp.text


# ── test-connection ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_test_connection_probes_with_stored_credentials(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.drivers.dns._cloud_base import CloudDNSProbe
    from app.drivers.dns.technitium_api import TechnitiumAPIDriver

    async def _fake_probe(self: Any, server: Any) -> CloudDNSProbe:
        return CloudDNSProbe(ok=True, message="Authenticated; 3 zone(s) visible.", zone_count=3)

    monkeypatch.setattr(TechnitiumAPIDriver, "probe", _fake_probe)

    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, _CREDS)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}/test-connection",
        headers=_h(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "message": "Authenticated; 3 zone(s) visible."}


@pytest.mark.asyncio
async def test_test_connection_reports_a_bad_token_as_ok_false_not_500(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The provider's own message is the useful thing to show."""
    from app.drivers.dns._cloud_base import CloudDNSProbe
    from app.drivers.dns.technitium_api import TechnitiumAPIDriver

    async def _fake_probe(self: Any, server: Any) -> CloudDNSProbe:
        return CloudDNSProbe(ok=False, message="Technitium rejected the API token")

    monkeypatch.setattr(TechnitiumAPIDriver, "probe", _fake_probe)

    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, _CREDS)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}/test-connection",
        headers=_h(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["ok"] is False


@pytest.mark.asyncio
async def test_test_connection_needs_stored_credentials(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, None)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}/test-connection",
        headers=_h(token),
    )
    assert resp.status_code == 400
    assert "no stored credentials" in resp.text


@pytest.mark.asyncio
async def test_test_connection_rejects_an_agent_managed_driver(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """bind9 has no control-plane channel to probe, and the error says so."""
    token = await _admin(db_session)
    group = await _group(db_session)
    server = DNSServer(group_id=group.id, name="b1", driver="bind9", host="10.0.0.1", port=53)
    db_session.add(server)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}/test-connection",
        headers=_h(token),
    )
    assert resp.status_code == 400
    assert "bind9" in resp.text


# ── topology pull ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pull_zones_is_allowed_for_the_new_driver(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate moved from two inline driver-name comparisons to a set.

    Regression guard for that refactor from the other side: the new driver
    has to actually be let through.
    """
    from app.drivers.dns.technitium_api import TechnitiumAPIDriver

    async def _fake_pull(self: Any, server: Any) -> list[dict[str, Any]]:
        return [{"name": "example.com.", "zone_type": "Primary", "manageable": True}]

    monkeypatch.setattr(TechnitiumAPIDriver, "pull_zones_from_server", _fake_pull)

    token = await _admin(db_session)
    group = await _group(db_session)
    server = await _server(db_session, group, _CREDS)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/servers/{server.id}/pull-zones-from-server",
        headers=_h(token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["zones"][0]["name"] == "example.com."

"""An edit that moves a destination must bring the stored credential with it.

A credential the API never returns cannot be re-read by the editor, so a
change to the URL / address / host of a row that keeps one is refused unless
the same request supplies (or clears) the credential. Read surfaces for APT
source URIs show an embedded ``user:pass@`` masked, and a save of the masked
form keeps the stored one.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPSpace
from app.models.network import NetworkDevice
from app.models.settings import PlatformSettings
from app.models.wol_schedule import WolCalendar

pytestmark = pytest.mark.asyncio


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _calendar(client: AsyncClient, h: dict[str, str]) -> str:
    r = await client.post(
        "/api/v1/wake-scheduler/calendars",
        headers=h,
        json={
            "name": f"cal-{uuid.uuid4().hex[:6]}",
            "kind": "caldav",
            "url": "https://dav.example/cal/",
            "username": "svc",
            "password": "stored-pw",
            "refresh_interval_minutes": 360,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_calendar_url_change_without_password_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    cid = await _calendar(client, h)
    r = await client.patch(
        f"/api/v1/wake-scheduler/calendars/{cid}",
        headers=h,
        json={"url": "https://other.example/cal/"},
    )
    assert r.status_code == 422, r.text
    assert "url" in r.json()["detail"] and "password" in r.json()["detail"]
    row = await db_session.get(WolCalendar, uuid.UUID(cid))
    assert row is not None and row.url == "https://dav.example/cal/"


async def test_calendar_url_change_with_password_or_unchanged_url_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    cid = await _calendar(client, h)
    # Same URL, other field: the stored password is not going anywhere new.
    r = await client.patch(
        f"/api/v1/wake-scheduler/calendars/{cid}",
        headers=h,
        json={"url": "https://dav.example/cal/", "refresh_interval_minutes": 60},
    )
    assert r.status_code == 200, r.text
    # New URL with the password sent again.
    r = await client.patch(
        f"/api/v1/wake-scheduler/calendars/{cid}",
        headers=h,
        json={"url": "https://other.example/cal/", "password": "new-pw"},
    )
    assert r.status_code == 200, r.text
    row = await db_session.get(WolCalendar, uuid.UUID(cid))
    await db_session.refresh(row)
    assert row is not None and row.password_encrypted is not None
    assert decrypt_str(row.password_encrypted) == "new-pw"


async def test_network_device_address_change_without_community_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    await db_session.commit()
    r = await client.post(
        "/api/v1/network-devices",
        headers=h,
        json={
            "name": f"sw-{uuid.uuid4().hex[:6]}",
            "hostname": "192.0.2.10",
            "ip_address": "192.0.2.10",
            "device_type": "switch",
            "snmp_version": "v2c",
            "community": "public-secret",
            "ip_space_id": str(space.id),
        },
    )
    assert r.status_code == 201, r.text
    dev_id = r.json()["id"]

    r = await client.patch(
        f"/api/v1/network-devices/{dev_id}", headers=h, json={"ip_address": "192.0.2.99"}
    )
    assert r.status_code == 422, r.text
    assert "ip_address" in r.json()["detail"]
    dev = await db_session.get(NetworkDevice, uuid.UUID(dev_id))
    await db_session.refresh(dev)
    assert str(dev.ip_address) == "192.0.2.10"

    r = await client.patch(
        f"/api/v1/network-devices/{dev_id}",
        headers=h,
        json={"ip_address": "192.0.2.99", "community": "other"},
    )
    assert r.status_code == 200, r.text
    r = await client.patch(f"/api/v1/network-devices/{dev_id}", headers=h, json={"snmp_port": 1161})
    assert r.status_code == 422, r.text


async def test_apt_source_uri_userinfo_is_masked_and_kept_on_resave(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    src: dict[str, Any] = {
        "name": "lan",
        "uri": "https://bob:hunter2@mirror.lan/debian",
        "suites": "trixie",
        "components": "main",
        "enabled": True,
    }
    r = await client.put("/api/v1/settings", headers=h, json={"apt_sources": [src]})
    assert r.status_code == 200, r.text
    assert "hunter2" not in r.text and "bob" not in r.text
    assert r.json()["apt_sources"][0]["uri"] == "https://***@mirror.lan/debian"

    r = await client.get("/api/v1/settings", headers=h)
    assert "hunter2" not in r.text
    masked = r.json()["apt_sources"][0]

    # The form sends the masked row back: the stored credential survives.
    r = await client.put("/api/v1/settings", headers=h, json={"apt_sources": [masked]})
    assert r.status_code == 200, r.text
    st = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(st)
    assert st is not None and st.apt_sources[0]["uri"] == "https://bob:hunter2@mirror.lan/debian"

    # A masked URI with nothing stored to keep is refused, not saved as '***'.
    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={"apt_sources": [{**masked, "name": "x", "uri": "https://***@elsewhere.lan/d"}]},
    )
    assert r.status_code == 422, r.text


async def test_apt_source_masked_uri_on_a_new_host_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    src: dict[str, Any] = {
        "name": "lan",
        "uri": "http://bob:hunter2@mirror.lan:8080/apt/",
        "suites": "trixie",
        "components": "main",
        "enabled": True,
    }
    r = await client.put("/api/v1/settings", headers=h, json={"apt_sources": [src]})
    assert r.status_code == 200, r.text
    stored = "http://bob:hunter2@mirror.lan:8080/apt/"

    async def _stored() -> str:
        st = await db_session.get(PlatformSettings, 1)
        assert st is not None
        await db_session.refresh(st)
        return str(st.apt_sources[0]["uri"])

    # Host, port or scheme moved with the mask left in: refused, unchanged.
    for moved in (
        "http://***@other.lan:8080/apt/",
        "http://***@mirror.lan:9090/apt/",
        "https://***@mirror.lan:8080/apt/",
    ):
        r = await client.put(
            "/api/v1/settings", headers=h, json={"apt_sources": [{**src, "uri": moved}]}
        )
        assert r.status_code == 422, r.text
        assert "re-enter" in r.text and "hunter2" not in r.text
        assert await _stored() == stored

    # Same host and port, new path: the credential is kept.
    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={"apt_sources": [{**src, "uri": "http://***@mirror.lan:8080/other/"}]},
    )
    assert r.status_code == 200, r.text
    assert await _stored() == "http://bob:hunter2@mirror.lan:8080/other/"

    # A new host with a real credential supplied is stored as sent.
    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={"apt_sources": [{**src, "uri": "http://amy:pw2@other.lan:8080/apt/"}]},
    )
    assert r.status_code == 200, r.text
    assert await _stored() == "http://amy:pw2@other.lan:8080/apt/"


async def test_guard_rule_cases() -> None:
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.core.stored_secret_guard import (
        require_secret_with_destination_change as rule,
    )
    from app.core.stored_secret_guard import (
        sent_server_credential,
    )

    row = SimpleNamespace(host="a.example", port=443)
    stored = {"token": b"ciphertext"}
    # Not moved: fine. Moved with the secret re-sent or cleared: fine.
    rule(row, {"host": "a.example", "port": "443"}, destination=("host", "port"), secrets=stored)
    rule(row, {"host": "b.example", "token": "x"}, destination=("host",), secrets=stored)
    rule(row, {"host": "b.example", "token": ""}, destination=("host",), secrets=stored)
    # Nothing stored, nothing to protect.
    rule(row, {"host": "b.example"}, destination=("host",), secrets={"token": None})
    # Moved with a stored secret kept: refused, naming the field.
    with pytest.raises(HTTPException) as exc:
        rule(row, {"port": 8443}, destination=("host", "port"), secrets=stored)
    assert exc.value.status_code == 422 and "port" in exc.value.detail
    # A destination held encrypted counts as moved when a new value arrives.
    with pytest.raises(HTTPException):
        rule(row, {"url": "https://x"}, destination=(), replaced=("url",), secrets=stored)

    assert sent_server_credential(None, None) is None
    assert sent_server_credential({}, None) == ""
    assert sent_server_credential({"password": "p"}, None) == "p"
    assert sent_server_credential(None, {"vdom": "root"}) is None

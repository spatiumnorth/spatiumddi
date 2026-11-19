"""Windows DNS / DHCP servers: the stored WinRM settings round-trip.

The server responses echo the non-secret WinRM settings (port, transport,
TLS, certificate validation) so the edit dialogs can show what is stored,
and an update that does not carry a setting keeps the stored value. The
username and password are never returned.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.security import create_access_token, hash_password
from app.drivers._winrm import effective_winrm_settings, winrm_settings_diff
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup

STORED: dict[str, Any] = {
    "username": "CORP\\svc-ddi",
    "password": "pw-never-echoed",
    "winrm_port": 5986,
    "transport": "credssp",
    "use_tls": True,
    "verify_tls": True,
}
SETTINGS = {"winrm_port": 5986, "transport": "credssp", "use_tls": True, "verify_tls": True}


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"wr-{uuid.uuid4().hex[:6]}",
        email=f"wr-{uuid.uuid4().hex[:6]}@example.test",
        display_name="wr",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _dns_server(db: AsyncSession) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    s = DNSServer(
        group_id=group.id,
        name="win-dns1",
        driver="windows_dns",
        host="dc1.corp.example",
        port=53,
        roles=["authoritative"],
        status="active",
        is_primary=True,
        credentials_encrypted=encrypt_dict(STORED),
    )
    db.add(s)
    await db.commit()
    return s


async def _dhcp_server(db: AsyncSession) -> DHCPServer:
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    s = DHCPServer(
        name="win-dhcp1",
        driver="windows_dhcp",
        host="dhcp1.corp.example",
        port=67,
        server_group_id=group.id,
        credentials_encrypted=encrypt_dict(STORED),
    )
    db.add(s)
    await db.commit()
    return s


def _assert_no_secret(body: dict[str, Any]) -> None:
    text = json.dumps(body)
    assert "pw-never-echoed" not in text
    assert "svc-ddi" not in text


# ── helpers ─────────────────────────────────────────────────────────────


def test_effective_settings_match_what_a_session_uses() -> None:
    assert effective_winrm_settings({}) == {
        "winrm_port": 5985,
        "transport": "ntlm",
        "use_tls": False,
        "verify_tls": False,
    }
    assert effective_winrm_settings({"use_tls": True})["winrm_port"] == 5986
    assert effective_winrm_settings(STORED) == SETTINGS


def test_settings_diff_names_old_and_new_values() -> None:
    after = {**STORED, "verify_tls": False}
    assert winrm_settings_diff(STORED, after) == {"verify_tls": {"old": True, "new": False}}
    assert winrm_settings_diff(STORED, dict(STORED)) == {}


# ── Windows DNS ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dns_response_echoes_stored_winrm_settings_without_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    s = await _dns_server(db_session)
    r = await client.get(f"/api/v1/dns/groups/{s.group_id}/servers", headers=h)
    assert r.status_code == 200, r.text
    row = next(x for x in r.json() if x["id"] == str(s.id))
    assert row["winrm_settings"] == SETTINGS
    _assert_no_secret(row)


@pytest.mark.asyncio
async def test_dns_untouched_put_keeps_https_and_cert_validation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    s = await _dns_server(db_session)
    # What an untouched edit dialog sends: the visible fields, no
    # windows_credentials block.
    r = await client.put(
        f"/api/v1/dns/groups/{s.group_id}/servers/{s.id}",
        headers=h,
        json={"name": "win-dns1", "host": "dc1.corp.example", "port": 53, "notes": ""},
    )
    assert r.status_code == 200, r.text
    assert r.json()["winrm_settings"] == SETTINGS
    await db_session.refresh(s)
    assert decrypt_dict(s.credentials_encrypted) == STORED


@pytest.mark.asyncio
async def test_dns_partial_credentials_keep_unsent_settings_and_audit_the_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    s = await _dns_server(db_session)
    r = await client.put(
        f"/api/v1/dns/groups/{s.group_id}/servers/{s.id}",
        headers=h,
        json={"windows_credentials": {"password": "new-pw", "transport": "ntlm"}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["winrm_settings"] == {**SETTINGS, "transport": "ntlm"}
    await db_session.refresh(s)
    stored = decrypt_dict(s.credentials_encrypted)
    assert stored == {**STORED, "password": "new-pw", "transport": "ntlm"}
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dns_server",
                AuditLog.resource_id == str(s.id),
                AuditLog.action == "update",
            )
        )
    ).scalar_one()
    assert row.new_value["winrm_settings_changed"] == {
        "transport": {"old": "credssp", "new": "ntlm"}
    }
    assert "new-pw" not in json.dumps(row.new_value)


# ── Windows DHCP ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dhcp_response_echoes_stored_winrm_settings_without_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    s = await _dhcp_server(db_session)
    r = await client.get(f"/api/v1/dhcp/servers/{s.id}", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["winrm_settings"] == SETTINGS
    _assert_no_secret(r.json())


@pytest.mark.asyncio
async def test_dhcp_untouched_put_keeps_https_and_cert_validation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    s = await _dhcp_server(db_session)
    r = await client.put(
        f"/api/v1/dhcp/servers/{s.id}",
        headers=h,
        json={"name": "win-dhcp1", "host": "dhcp1.corp.example", "description": ""},
    )
    assert r.status_code == 200, r.text
    assert r.json()["winrm_settings"] == SETTINGS
    await db_session.refresh(s)
    assert decrypt_dict(s.credentials_encrypted) == STORED


@pytest.mark.asyncio
async def test_dhcp_partial_credentials_keep_unsent_settings_and_audit_the_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    s = await _dhcp_server(db_session)
    r = await client.put(
        f"/api/v1/dhcp/servers/{s.id}",
        headers=h,
        json={"windows_credentials": {"username": "CORP\\other"}},
    )
    assert r.status_code == 200, r.text
    assert r.json()["winrm_settings"] == SETTINGS
    await db_session.refresh(s)
    assert decrypt_dict(s.credentials_encrypted) == {**STORED, "username": "CORP\\other"}
    row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dhcp_server",
                AuditLog.resource_id == str(s.id),
                AuditLog.action == "update",
            )
        )
    ).scalar_one()
    assert row.new_value["windows_credentials_updated"] == ["username"]
    assert "winrm_settings_changed" not in row.new_value


@pytest.mark.asyncio
async def test_non_windows_server_has_no_winrm_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(group)
    await db_session.flush()
    s = DHCPServer(name="kea1", driver="kea", host="kea1", port=67, server_group_id=group.id)
    db_session.add(s)
    await db_session.commit()
    r = await client.get(f"/api/v1/dhcp/servers/{s.id}", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["winrm_settings"] is None

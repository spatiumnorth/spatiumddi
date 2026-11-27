"""A stored credential is only kept when its destination is unchanged.

Covers the cases the first destination rule missed: a blank credential field
that the handler reads as "keep the stored one", a destination held inside a
credential blob, block-sync write credentials that ride on the same host, and
a connection test that names a stored row but a different host.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_dict, decrypt_str, encrypt_dict, encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSServerOptions
from app.models.feature_module import FeatureModule
from app.models.ipam import IPSpace
from app.services import feature_modules

pytestmark = pytest.mark.asyncio

NEW_HOST = "203.0.113.77"

# module, base path, create body (minus ipam_space_id), secret field, moved
# destination field + value, id field a test request uses, test path, and the
# row attribute holding the encrypted secret.
CASES: dict[str, dict[str, Any]] = {
    "fortinet": dict(
        module="integrations.fortinet",
        path="/api/v1/fortinet/firewalls",
        body={"host": "198.51.100.5", "api_token": "tok-old"},
        secret="api_token",
        move=("host", NEW_HOST),
        test_path="/api/v1/fortinet/firewalls/test",
        test_id="firewall_id",
    ),
    "proxmox": dict(
        module="integrations.proxmox",
        path="/api/v1/proxmox/nodes",
        body={"host": "198.51.100.5", "token_id": "u@pam!t", "token_secret": "sec-old"},
        secret="token_secret",
        move=("host", NEW_HOST),
        test_path="/api/v1/proxmox/nodes/test",
        test_id="node_id",
    ),
    "vsphere": dict(
        module="integrations.vsphere",
        path="/api/v1/vsphere/targets",
        body={"host": "198.51.100.5", "username": "svc@vsphere.local", "password": "pw-old"},
        secret="password",
        move=("host", NEW_HOST),
        test_path="/api/v1/vsphere/targets/test",
        test_id="target_id",
    ),
    "kubernetes": dict(
        module="integrations.kubernetes",
        path="/api/v1/kubernetes/clusters",
        body={"api_server_url": "https://198.51.100.5:6443", "token": "tok-old"},
        secret="token",
        move=("api_server_url", "https://203.0.113.77:6443"),
        test_path="/api/v1/kubernetes/clusters/test",
        test_id="cluster_id",
    ),
    "docker": dict(
        module="integrations.docker",
        path="/api/v1/docker/hosts",
        body={
            "connection_type": "tcp",
            "endpoint": "tcp://198.51.100.5:2376",
            "client_cert_pem": "cert",
            "client_key_pem": "key-old",
        },
        secret="client_key_pem",
        move=("endpoint", "tcp://203.0.113.77:2376"),
        test_path="/api/v1/docker/hosts/test",
        test_id="host_id",
    ),
    "netbird": dict(
        module="integrations.netbird",
        path="/api/v1/netbird/instances",
        body={"api_url": "https://nb.example.test", "api_key": "key-old"},
        secret="api_key",
        move=("api_url", "https://nb2.example.test"),
        test_path="/api/v1/netbird/instances/test",
        test_id="instance_id",
    ),
    "opnsense": dict(
        module="integrations.opnsense",
        path="/api/v1/opnsense/routers",
        body={"host": "198.51.100.5", "api_key": "k", "api_secret": "sec-old"},
        secret="api_secret",
        move=("host", NEW_HOST),
        test_path="/api/v1/opnsense/routers/test",
        test_id="router_id",
    ),
    "panos": dict(
        module="integrations.paloalto",
        path="/api/v1/paloalto/firewalls",
        body={"host": "198.51.100.5", "api_key": "key-old"},
        secret="api_key",
        move=("host", NEW_HOST),
        test_path="/api/v1/paloalto/firewalls/test",
        test_id="firewall_id",
    ),
    "meraki": dict(
        module="integrations.meraki",
        path="/api/v1/meraki/orgs",
        body={"org_id": "123", "api_key": "key-old"},
        secret="api_key",
        move=("base_url", "https://n1.example.test/api/v1"),
        test_path="/api/v1/meraki/orgs/test",
        test_id="org_id_pk",
    ),
    "unifi": dict(
        module="integrations.unifi",
        path="/api/v1/unifi/controllers",
        body={"mode": "local", "host": "198.51.100.5", "api_key": "key-old"},
        secret="api_key",
        move=("host", NEW_HOST),
        test_path="/api/v1/unifi/controllers/test",
        test_id="controller_id",
    ),
}


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


async def _create(
    client: AsyncClient, db: AsyncSession, name: str
) -> tuple[dict[str, str], str, dict[str, Any]]:
    case = CASES[name]
    db.add(FeatureModule(id=case["module"], enabled=True))
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    h = await _admin(db)
    await db.commit()
    feature_modules.invalidate_cache()
    r = await client.post(
        case["path"],
        headers=h,
        json={"name": f"t-{uuid.uuid4().hex[:6]}", "ipam_space_id": str(space.id), **case["body"]},
    )
    assert r.status_code == 201, r.text
    return h, r.json()["id"], case


async def _read(client: AsyncClient, h: dict[str, str], path: str, rid: str) -> dict[str, Any]:
    rows = (await client.get(path, headers=h)).json()
    return next(r for r in rows if r["id"] == rid)


@pytest.mark.parametrize("name", sorted(CASES))
async def test_blank_credential_does_not_carry_the_stored_one_to_a_new_destination(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    h, rid, case = await _create(client, db_session, name)
    field, value = case["move"]
    url = f"{case['path']}/{rid}"
    before = await _read(client, h, case["path"], rid)
    # A blank credential keeps the stored one, so it is not a re-entry.
    for body in (
        {field: value, case["secret"]: ""},
        {field: value},
    ):
        r = await client.put(url, headers=h, json=body)
        assert r.status_code == 422, (body, r.text)
        assert case["secret"] in r.json()["detail"]
    assert (await _read(client, h, case["path"], rid))[field] == before[field]
    # The destination unchanged: a blank credential still means "keep".
    r = await client.put(url, headers=h, json={field: before[field], case["secret"]: ""})
    assert r.status_code == 200, r.text
    # The credential sent again with the new destination goes through.
    r = await client.put(url, headers=h, json={field: value, case["secret"]: "fresh"})
    assert r.status_code == 200, r.text
    assert r.json()[field] == value


@pytest.mark.parametrize("name", sorted(CASES))
async def test_connection_test_of_a_stored_row_needs_its_own_credential_for_a_new_host(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    h, rid, case = await _create(client, db_session, name)
    field, value = case["move"]
    for extra in ({}, {case["secret"]: ""}):
        r = await client.post(
            case["test_path"], headers=h, json={case["test_id"]: rid, field: value, **extra}
        )
        assert r.status_code == 422, (extra, r.text)
        assert "re-enter" in r.json()["detail"] and case["secret"] in r.json()["detail"]


# ── block-sync write credentials follow the host ────────────────────────


def _model(name: str) -> Any:
    from app.models.meraki import MerakiOrg
    from app.models.opnsense import OPNsenseRouter
    from app.models.panos import PANOSFirewall
    from app.models.unifi import UnifiController

    return {
        "opnsense": OPNsenseRouter,
        "panos": PANOSFirewall,
        "meraki": MerakiOrg,
        "unifi": UnifiController,
    }[name]


WRITE = {
    "opnsense": {"block_sync_api_key": "wk", "block_sync_api_secret_encrypted": encrypt_str("ws")},
    "panos": {"block_sync_api_key_encrypted": encrypt_str("wk")},
    "meraki": {"block_sync_api_key_encrypted": encrypt_str("wk")},
    "unifi": {"block_sync_api_key_encrypted": encrypt_str("wk")},
}


@pytest.mark.parametrize("name", sorted(WRITE))
@pytest.mark.parametrize("armed", [False, True])
async def test_block_sync_write_credentials_do_not_follow_a_moved_host(
    client: AsyncClient, db_session: AsyncSession, name: str, armed: bool
) -> None:
    h, rid, case = await _create(client, db_session, name)
    row = await db_session.get(_model(name), uuid.UUID(rid))
    assert row is not None
    for col, val in WRITE[name].items():
        setattr(row, col, val)
    row.block_sync_enabled = armed
    await db_session.commit()
    field, value = case["move"]
    r = await client.put(
        f"{case['path']}/{rid}", headers=h, json={field: value, case["secret"]: "fresh"}
    )
    await db_session.refresh(row)
    if armed:
        assert r.status_code == 422 and "armed" in r.json()["detail"], r.text
        assert all(getattr(row, c) == v for c, v in WRITE[name].items())
        return
    assert r.status_code == 200, r.text
    for col, val in WRITE[name].items():
        assert not getattr(row, col), col
    # A host edit that does not move it leaves them alone.
    for col, val in WRITE[name].items():
        setattr(row, col, val)
    await db_session.commit()
    r = await client.put(f"{case['path']}/{rid}", headers=h, json={"description": "x"})
    assert r.status_code == 200, r.text
    await db_session.refresh(row)
    assert all(getattr(row, c) == v for c, v in WRITE[name].items())


# ── InfluxDB: a blank never clears, so it is not a re-entry ─────────────


async def test_influxdb_blank_secret_does_not_satisfy_a_url_change(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/settings/influxdb-targets",
        headers=h,
        json={
            "name": f"i-{uuid.uuid4().hex[:6]}",
            "version": "v2",
            "url": "https://influx.example.test:8086",
            "org": "o",
            "bucket": "b",
            "token": "tok-old",
        },
    )
    assert r.status_code in (200, 201), r.text
    tid = r.json()["id"]
    url = f"/api/v1/settings/influxdb-targets/{tid}"
    for body in ({"token": ""}, {}):
        r = await client.put(
            url, headers=h, json={"url": "https://influx2.example.test:8086", **body}
        )
        assert r.status_code == 422, (body, r.text)
    # The clear flag is the explicit way to drop it; that satisfies the rule.
    r = await client.put(
        url,
        headers=h,
        json={"url": "https://influx2.example.test:8086", "clear_token": True},
    )
    assert r.status_code in (200, 422), r.text
    assert "re-enter" not in r.text


# ── Technitium: the API URL lives in the credential blob ────────────────


async def _technitium(db: AsyncSession) -> tuple[dict[str, str], DNSServer]:
    h = await _admin(db)
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(g)
    await db.flush()
    db.add(DNSServerOptions(group_id=g.id))
    s = DNSServer(
        group_id=g.id,
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="technitium_api",
        host="10.0.0.53",
        port=53,
        credentials_encrypted=encrypt_dict(
            {"api_url": "https://dns.example.test:53443", "api_token": "tok-old"}
        ),
    )
    db.add(s)
    await db.commit()
    return h, s


async def test_technitium_api_url_change_needs_the_token_again(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, s = await _technitium(db_session)
    url = f"/api/v1/dns/groups/{s.group_id}/servers/{s.id}"
    for creds in (
        {"api_url": "https://dns2.example.test:53443"},
        {"api_url": "https://dns2.example.test:53443", "api_token": ""},
    ):
        r = await client.put(url, headers=h, json={"cloud_credentials": creds})
        assert r.status_code == 422, (creds, r.text)
        assert "api_token" in r.json()["detail"]
    await db_session.refresh(s)
    assert decrypt_dict(s.credentials_encrypted)["api_url"] == "https://dns.example.test:53443"
    # Same URL (case / trailing slash aside), other settings: token kept.
    r = await client.put(
        url,
        headers=h,
        json={
            "cloud_credentials": {"api_url": "https://DNS.example.test:53443/", "verify_tls": False}
        },
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(s)
    assert decrypt_dict(s.credentials_encrypted)["api_token"] == "tok-old"
    # New URL with the token sent again.
    r = await client.put(
        url,
        headers=h,
        json={
            "cloud_credentials": {"api_url": "https://dns2.example.test:53443", "api_token": "n"}
        },
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(s)
    assert decrypt_dict(s.credentials_encrypted)["api_token"] == "n"


async def test_guard_blank_keeps_rule() -> None:
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.core.stored_secret_guard import require_secret_with_destination_change as guard

    row = SimpleNamespace(host="a")
    kw = dict(destination=("host",), secrets={"tok": b"x"})
    guard(row, {"host": "b", "tok": ""}, **kw)  # "" clears here
    with pytest.raises(HTTPException):
        guard(row, {"host": "b", "tok": ""}, blank_keeps=("tok",), **kw)
    guard(row, {"host": "b", "tok": "new"}, blank_keeps=("tok",), **kw)
    assert decrypt_str(encrypt_str("x")) == "x"

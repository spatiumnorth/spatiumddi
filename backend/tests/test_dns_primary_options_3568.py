"""Per-primary TSIG key + TLS on a secondary zone, and XFR over TLS (#3568).

The zone's ``master_options`` (keyed by the ``masters`` entry) and the group's
``allow_transfer_tls_only``: the API validation, the bundle each agent polls
(and that its ETag moves with them), the control-plane preview renderer, and
the role matrix. The agent's rendering is covered in
``agent/dns/tests/test_secondary_primary_options_render_3568.py``.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import ServerOptions, ZoneData
from app.drivers.dns.bind9 import BIND9Driver
from app.main import _BUILTIN_ROLES
from app.models.appliance import ApplianceCertificate
from app.models.auth import Group, Role, User
from app.models.dns import DNSServer, DNSServerGroup, DNSTSIGKey, DNSZone
from app.services.dns.agent_config import render_bundle_body

pytestmark = pytest.mark.asyncio

SECRET = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"


async def _headers(
    db: AsyncSession, *, role: str | None = None, superadmin: bool = False
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    if role is not None:
        r = Role(name=f"r-{tag}", description="", permissions=list(_BUILTIN_ROLES[role][1]))
        g = Group(name=f"g-{tag}", description="")
        g.roles = [r]
        g.users = [user]
        db.add_all([r, g])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, driver: str = "bind9") -> DNSServerGroup:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    db.add(DNSServer(group_id=grp.id, name="ns1", driver=driver, host="10.0.0.53", port=53))
    db.add(
        DNSTSIGKey(
            group_id=grp.id,
            name="xfer.example.",
            algorithm="hmac-sha256",
            secret_encrypted=encrypt_str(SECRET),
        )
    )
    await db.flush()
    return grp


async def _server(db: AsyncSession, group_id: uuid.UUID) -> DNSServer:
    return (await db.execute(select(DNSServer).where(DNSServer.group_id == group_id))).scalar_one()


def _body(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "sec.example.com.",
        "zone_type": "secondary",
        "masters": ["192.0.2.10", "192.0.2.11@853"],
        "master_options": {
            "192.0.2.10": {"tsig_key": "xfer.example."},
            "192.0.2.11@853": {"tls_hostname": "ns1.example.com", "tsig_key": "XFER.example"},
        },
    }
    body.update(over)
    return body


async def _create(client: AsyncClient, grp: DNSServerGroup, h: dict[str, str], **over: Any) -> Any:
    return await client.post(f"/api/v1/dns/groups/{grp.id}/zones", headers=h, json=_body(**over))


# ── API ─────────────────────────────────────────────────────────────────────


async def test_create_stores_and_returns_options_and_never_a_secret(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    await db_session.commit()
    r = await _create(client, grp, h)
    assert r.status_code == 201, r.text
    assert r.json()["master_options"] == {
        "192.0.2.10": {"tsig_key": "xfer.example.", "tls_hostname": None},
        "192.0.2.11@853": {"tsig_key": "XFER.example", "tls_hostname": "ns1.example.com"},
    }
    assert SECRET not in r.text


async def test_zone_without_options_reads_empty(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    await db_session.commit()
    r = await _create(client, grp, h, master_options={})
    assert r.status_code == 201, r.text
    assert r.json()["master_options"] == {}


@pytest.mark.parametrize(
    "over, needle",
    [
        ({"master_options": {"203.0.113.9": {"tsig_key": "xfer.example."}}}, "not one of"),
        ({"master_options": {"192.0.2.10": {"tsig_key": "nope."}}}, "not a key of this"),
        # The group's generated key is the control plane's own write identity.
        ({"master_options": {"192.0.2.10": {"tsig_key": "spatium-default"}}}, "not a key of this"),
        ({"zone_type": "primary", "masters": []}, "secondary and stub"),
    ],
)
async def test_create_refuses_options_the_zone_cannot_honour(
    client: AsyncClient, db_session: AsyncSession, over: dict[str, Any], needle: str
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    await db_session.commit()
    if over.get("zone_type") == "primary":
        over = {**over, "master_options": {"192.0.2.10": {"tsig_key": "xfer.example."}}}
    r = await _create(client, grp, h, **over)
    assert r.status_code == 422, r.text
    assert needle in r.text


@pytest.mark.parametrize(
    "opts",
    [
        {"192.0.2.10": {"tls_hostname": 'x"; }; evil {'}},
        {"192.0.2.10": {"tsig_key": 'k"; }; evil {'}},
        {"192.0.2.10": {"unknown": "x"}},
    ],
)
async def test_create_refuses_injection_in_options(
    client: AsyncClient, db_session: AsyncSession, opts: dict[str, Any]
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    await db_session.commit()
    r = await _create(client, grp, h, master_options=opts)
    assert r.status_code == 422, r.text


async def test_options_are_refused_on_a_powerdns_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session, driver="powerdns")
    await db_session.commit()
    r = await _create(client, grp, h)
    assert r.status_code == 422, r.text
    assert "BIND9 only" in r.text
    # A plain secondary there is untouched.
    r = await _create(client, grp, h, master_options={})
    assert r.status_code == 201, r.text


async def test_update_sets_clears_and_prunes(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    await db_session.commit()
    zid = (await _create(client, grp, h)).json()["id"]
    url = f"/api/v1/dns/groups/{grp.id}/zones/{zid}"

    # Dropping a master prunes the options it carried.
    r = await client.put(url, headers=h, json={"masters": ["192.0.2.10"]})
    assert r.status_code == 200, r.text
    assert list(r.json()["master_options"]) == ["192.0.2.10"]

    # An explicit value is validated against the effective masters.
    r = await client.put(
        url, headers=h, json={"master_options": {"192.0.2.11@853": {"tsig_key": "xfer.example."}}}
    )
    assert r.status_code == 422, r.text

    r = await client.put(url, headers=h, json={"master_options": {}})
    assert r.status_code == 200, r.text
    assert r.json()["master_options"] == {}


# ── Bundle ──────────────────────────────────────────────────────────────────


async def test_bundle_ships_options_and_the_etag_moves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    gid = grp.id
    await db_session.commit()
    srv = await _server(db_session, gid)

    zid = (await _create(client, grp, h, master_options={})).json()["id"]
    plain = await render_bundle_body(db_session, srv)
    (z,) = [z for z in plain.body["zones"] if z["name"] == "sec.example.com."]
    # Nothing set: the key is absent, so the bundle an old agent reads is the same.
    assert "master_options" not in z

    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/zones/{zid}",
        headers=h,
        json={"master_options": {"192.0.2.10": {"tsig_key": "xfer.example."}}},
    )
    assert r.status_code == 200, r.text
    db_session.expire_all()
    srv = await _server(db_session, gid)
    keyed = await render_bundle_body(db_session, srv)
    (z,) = [z for z in keyed.body["zones"] if z["name"] == "sec.example.com."]
    assert z["master_options"] == {"192.0.2.10": {"tsig_key": "xfer.example."}}
    assert z["masters"] == ["192.0.2.10", "192.0.2.11@853"]
    assert keyed.etag != plain.etag
    assert keyed.structural_etag != plain.structural_etag
    # The key it names ships with the rest of the group's keys.
    assert "xfer.example." in [k["name"] for k in keyed.body["tsig_keys"]]


# ── Preview renderer (control-plane copy of the agent's render) ────────────


def _zone(**over: Any) -> ZoneData:
    base: dict[str, Any] = dict(
        name="sec.example.com.",
        zone_type="secondary",
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="",
        admin_email="",
        serial=0,
        masters=("192.0.2.10", "192.0.2.11@853"),
        master_options=(
            ("192.0.2.10", "xfer.example.", None),
            ("192.0.2.11@853", None, "ns1.example.com"),
        ),
    )
    base.update(over)
    return ZoneData(**base)


async def test_preview_renders_key_and_tls() -> None:
    from types import SimpleNamespace

    out = BIND9Driver().render_zone_config(
        _zone(), (SimpleNamespace(name="xfer.example.", secret="x", algorithm="hmac-sha256"),)
    )
    assert 'masters { 192.0.2.10 key "xfer.example."; 192.0.2.11 port 853 tls ' in out
    # A key the bundle does not hold is left off, never rendered undefined.
    out = BIND9Driver().render_zone_config(_zone(), ())
    assert "key" not in out


async def test_preview_allow_transfer_transport() -> None:
    drv = BIND9Driver()
    on = drv.render_server_config(
        object(), ServerOptions(dot_enabled=True, allow_transfer_tls_only=True)
    )
    assert "allow-transfer transport tls {" in on
    off = drv.render_server_config(object(), ServerOptions(dot_enabled=True))
    assert "transport tls" not in off
    # No DoT listener to ride on: plain, as the agent does.
    nodot = drv.render_server_config(object(), ServerOptions(allow_transfer_tls_only=True))
    assert "transport tls" not in nodot


# ── Group option: XFR over TLS ──────────────────────────────────────────────


async def _cert(db: AsyncSession) -> ApplianceCertificate:
    row = ApplianceCertificate(
        name=f"c-{uuid.uuid4().hex[:6]}",
        source="upload",
        cert_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        key_encrypted=encrypt_str("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n"),
        subject_cn="dns.example.test",
        sans_json=["dns.example.test"],
    )
    db.add(row)
    await db.flush()
    return row


async def test_tls_only_needs_dot(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/options"
    r = await client.put(url, headers=h, json={"allow_transfer_tls_only": True})
    assert r.status_code == 422, r.text
    assert "DoT" in r.text


async def test_tls_only_round_trips_and_reaches_the_bundle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session)
    cert = await _cert(db_session)
    gid = grp.id
    await db_session.commit()
    url = f"/api/v1/dns/groups/{grp.id}/options"
    assert (await client.get(url, headers=h)).json()["allow_transfer_tls_only"] is False
    r = await client.put(
        url,
        headers=h,
        json={
            "dot_enabled": True,
            "tls_certificate_id": str(cert.id),
            "allow_transfer_tls_only": True,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["allow_transfer_tls_only"] is True

    body = (await render_bundle_body(db_session, await _server(db_session, gid))).body
    assert body["options"]["allow_transfer_tls_only"] is True

    # Turning DoT off while it is set is refused: the merged state is checked.
    r = await client.put(url, headers=h, json={"dot_enabled": False})
    assert r.status_code == 422, r.text


async def test_tls_only_is_refused_on_a_powerdns_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session, superadmin=True)
    grp = await _group(db_session, driver="powerdns")
    cert = await _cert(db_session)
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/groups/{grp.id}/options",
        headers=h,
        json={
            "dot_enabled": True,
            "tls_certificate_id": str(cert.id),
            "allow_transfer_tls_only": True,
        },
    )
    assert r.status_code == 422, r.text
    assert "BIND9 only" in r.text


# ── Role matrix ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "role, superadmin, expected",
    [("Viewer", False, 403), ("DNS Editor", False, 201), (None, True, 201)],
)
async def test_create_with_options_by_role(
    client: AsyncClient,
    db_session: AsyncSession,
    role: str | None,
    superadmin: bool,
    expected: int,
) -> None:
    h = await _headers(db_session, role=role, superadmin=superadmin)
    grp = await _group(db_session)
    await db_session.commit()
    r = await _create(client, grp, h)
    assert r.status_code == expected, r.text


async def test_group_option_is_superadmin_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    grp = await _group(db_session)
    await db_session.commit()
    for role in ("Viewer", "DNS Editor"):
        h = await _headers(db_session, role=role)
        await db_session.commit()
        r = await client.put(
            f"/api/v1/dns/groups/{grp.id}/options",
            headers=h,
            json={"allow_transfer_tls_only": False},
        )
        assert r.status_code == 403, (role, r.text)


async def test_models_default_off(db_session: AsyncSession) -> None:
    grp = await _group(db_session)
    zone = DNSZone(group_id=grp.id, name="x.example.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.flush()
    await db_session.refresh(zone)
    assert zone.master_options == {}

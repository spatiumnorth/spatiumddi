"""DHCP option 43 vendor presets (#4490): byte-for-byte encodings from each
vendor's published example, the API, and the rendered Kea config."""

from __future__ import annotations

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dhcp.kea import KeaDriver
from app.models.auth import User
from app.models.dhcp import DHCPPhoneProfile, DHCPPhoneProfileScope
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.option_validation import validate_phone_options
from app.services.dhcp.vendor_presets import encode_preset, get_preset, list_presets
from tests.test_dhcp_phone_profiles import _make_group_server_scope


def _enc(preset_id: str, *ips: str) -> str:
    p = get_preset(preset_id)
    assert p is not None
    return encode_preset(p, list(ips)).value_hex


# Each expected value is the worked example printed in the vendor's document.
def test_unifi_matches_ubiquiti_example() -> None:
    assert _enc("unifi", "172.16.30.3") == "0104ac101e03"


def test_cisco_wlc_matches_cisco_examples() -> None:
    assert _enc("cisco-wlc", "192.168.10.5", "192.168.10.20") == "f108c0a80a05c0a80a14"
    assert _enc("cisco-wlc", "192.168.1.10") == "f104c0a8010a"


def test_ruckus_matches_ruckus_example() -> None:
    assert _enc("ruckus-smartzone", "192.168.1.120") == "060d3139322e3136382e312e313230"
    assert _enc("ruckus-zonedirector", "10.0.0.1") == "0308" + b"10.0.0.1".hex()


@pytest.mark.parametrize(
    "preset_id,ips",
    [
        ("unifi", []),
        ("unifi", ["10.0.0.1", "10.0.0.2"]),
        ("unifi", ["not-an-ip"]),
        ("cisco-wlc", ["2001:db8::1"]),
        ("ruckus-smartzone", ["10.0.0.1", "10.0.0.2"]),
    ],
)
def test_bad_input_refused(preset_id: str, ips: list[str]) -> None:
    p = get_preset(preset_id)
    assert p is not None
    with pytest.raises(ValueError):
        encode_preset(p, ips)


def test_every_encoding_is_a_loadable_option_43() -> None:
    for p in list_presets():
        value = encode_preset(p, ["10.1.2.3"]).value_hex
        validate_phone_options(
            [{"code": 43, "value": value}], previous=None, going_live=True, enabled=True
        )


async def test_api_lists_and_encodes(client: AsyncClient, db_session: AsyncSession) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    token = create_access_token(str(user.id))
    await db_session.commit()
    auth_headers = {"Authorization": f"Bearer {token}"}
    r = await client.get("/api/v1/dhcp/vendor-presets", headers=auth_headers)
    assert r.status_code == 200
    ids = {p["id"] for p in r.json()}
    assert {"unifi", "cisco-wlc", "ruckus-smartzone"} <= ids
    r = await client.get(
        "/api/v1/dhcp/vendor-presets/unifi/encode?controller=172.16.30.3", headers=auth_headers
    )
    assert r.status_code == 200
    assert r.json()["value"] == "0104ac101e03"
    assert r.json()["vendor_class_match"] == "ubnt"
    r = await client.get(
        "/api/v1/dhcp/vendor-presets/unifi/encode?controller=nope", headers=auth_headers
    )
    assert r.status_code == 422
    r = await client.get("/api/v1/dhcp/vendor-presets/zzz/encode", headers=auth_headers)
    assert r.status_code == 404


async def test_preset_value_renders_in_kea_class(db_session: AsyncSession) -> None:
    db = db_session
    grp, srv, scope = await _make_group_server_scope(db)
    p = get_preset("unifi")
    assert p is not None
    enc = encode_preset(p, ["172.16.30.3"])
    prof = DHCPPhoneProfile(
        group_id=grp.id,
        name=f"unifi-{uuid.uuid4().hex[:6]}",
        description="",
        enabled=True,
        vendor="Ubiquiti",
        vendor_class_match=p.vendor_class_match,
        option_set=[{"code": 43, "name": "vendor-encapsulated-options", "value": enc.value_hex}],
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=scope.id))
    await db.flush()

    bundle = await build_config_bundle(db, srv)
    cfg = json.loads(KeaDriver().render_config(bundle))
    cls = next(c for c in cfg["Dhcp4"]["client-classes"] if c["name"].startswith("voip-"))
    assert "'ubnt'" in cls["test"]
    opt = next(o for o in cls["option-data"] if o.get("code") == 43)
    assert opt["data"] == "0104ac101e03"
    defs = {d["code"]: d for d in cfg["Dhcp4"]["option-def"]}
    assert defs[43]["type"] == "binary"


async def _plain_user(db: AsyncSession, permissions: list[dict[str, str]] | None = None) -> str:
    from app.models.auth import Group, Role

    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=False,
        is_active=True,
    )
    u.groups = []
    if permissions:
        role = Role(name=f"r-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"g-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        u.groups = [group]
        db.add_all([role, group])
    db.add(u)
    await db.flush()
    token = create_access_token(str(u.id))
    await db.commit()
    return token


async def test_api_permission_and_input_errors(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """No dhcp_scope read -> 403 (never 500, never the catalogue); anonymous ->
    401; a reader gets 422 for empty / excess / malformed controllers."""
    nobody = {"Authorization": f"Bearer {await _plain_user(db_session)}"}
    for url in (
        "/api/v1/dhcp/vendor-presets",
        "/api/v1/dhcp/vendor-presets/unifi/encode?controller=172.16.30.3",
    ):
        assert (await client.get(url)).status_code == 401
        assert (await client.get(url, headers=nobody)).status_code == 403

    reader = {
        "Authorization": "Bearer "
        + await _plain_user(db_session, [{"action": "read", "resource_type": "dhcp_scope"}])
    }
    base = "/api/v1/dhcp/vendor-presets"
    assert (await client.get(base, headers=reader)).status_code == 200
    # Unknown preset is 404 before the address is even looked at.
    assert (await client.get(f"{base}/zzz/encode?controller=x", headers=reader)).status_code == 404
    for qs in (
        "",  # none
        "?controller=",  # blank
        "?controller=172.16.30.3&controller=172.16.30.4",  # UniFi takes one
        "?controller=2001:db8::1",  # IPv6
        "?controller=172.16.30.3/24",
    ):
        r = await client.get(f"{base}/unifi/encode{qs}", headers=reader)
        assert r.status_code == 422, (qs, r.status_code)
        assert r.json()["detail"]
    many = "&".join(f"controller=10.0.0.{i}" for i in range(1, 65))
    r = await client.get(f"{base}/cisco-wlc/encode?{many}", headers=reader)
    assert r.status_code == 422
    ok = "&".join(f"controller=10.0.0.{i}" for i in range(1, 64))
    r = await client.get(f"{base}/cisco-wlc/encode?{ok}", headers=reader)
    assert r.status_code == 200 and r.json()["byte_length"] == 254


async def test_mcp_tool_matches_rest_and_needs_dhcp_scope_read(
    db_session: AsyncSession,
) -> None:
    from app.services.ai.tools import REGISTRY
    from app.services.ai.tools.base import ToolPermissionDenied

    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(u)
    await db_session.flush()
    name = "find_dhcp_vendor_presets"
    out = await REGISTRY.call(
        name,
        {"preset_id": "unifi", "controllers": ["172.16.30.3"]},
        db=db_session,
        user=u,
        effective={name},
    )
    assert out["encoded"]["value"] == "0104ac101e03"
    out = await REGISTRY.call(
        name,
        {"preset_id": "unifi", "controllers": ["nope"]},
        db=db_session,
        user=u,
        effective={name},
    )
    assert "not an IPv4" in out["error"] and "encoded" not in out
    out = await REGISTRY.call(name, {"preset_id": "zzz"}, db=db_session, user=u, effective={name})
    assert out["error"] == "Unknown vendor preset"

    nobody = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    nobody.groups = []
    db_session.add(nobody)
    await db_session.flush()
    with pytest.raises(ToolPermissionDenied):
        await REGISTRY.call(name, {}, db=db_session, user=nobody, effective={name})

"""Phone-profile options are delivered by code and checked on write (#1294).

A phone profile keyed each option by its catalogue name (``polycom-config-url``),
which the agent does not know and dropped, so option 160 never reached a
phone. And nothing checked a value: rendered by code, the starter pack's
``CHANGE-ME`` in binary option 43 would make Kea reject the group's whole
config.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPPhoneProfile, DHCPPhoneProfileScope, DHCPServerGroup
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.option_validation import (
    phone_options_loadable,
    phone_options_map,
    validate_phone_options,
)
from tests.test_dhcp_phone_profiles import _make_group_server_scope

URL = "https://prov.example.com/{mac}"


def test_the_code_decides_the_key() -> None:
    assert phone_options_map(
        [
            {"code": 160, "name": "polycom-config-url", "value": URL},
            {"code": 66, "name": "tftp-server-name", "value": "tftp.example"},
            {"code": 150, "name": "", "value": "10.0.0.9"},
            {"code": 161, "name": "yealink-prov-server", "value": ""},  # unset
        ]
    ) == {"code:160": URL, "tftp-server-name": "tftp.example", "tftp-server-address": "10.0.0.9"}


@pytest.mark.parametrize(
    ("rows", "fragment"),
    [
        ([{"code": 43, "name": "vendor-encapsulated-options", "value": "0x0104"}], "hex digits"),
        ([{"code": 150, "value": "tftp.example"}], "not an IPv4 address"),
        ([{"code": 44, "name": "netbios-name-servers", "value": "10.0.0.1"}], "cannot deliver"),
        (
            [{"code": 160, "value": URL}, {"code": 160, "value": "https://other"}],
            "listed twice",
        ),
        ([{"code": 150, "name": "tftp-server-name", "value": "10.0.0.9"}], "which is option 66"),
    ],
)
def test_options_kea_cannot_load_are_refused(rows: list[dict], fragment: str) -> None:
    with pytest.raises(ValueError, match=fragment):
        validate_phone_options(rows)


def test_a_placeholder_is_refused_only_when_the_profile_goes_live() -> None:
    rows = [{"code": 160, "name": "polycom-config-url", "value": "CHANGE-ME"}]
    validate_phone_options(rows)  # a string option: loadable, just not useful
    with pytest.raises(ValueError, match="placeholder"):
        validate_phone_options(rows, going_live=True)


def test_an_unchanged_stored_option_does_not_block_an_edit() -> None:
    stored = [{"code": 43, "name": "vendor-encapsulated-options", "value": "CHANGE-ME"}]
    validate_phone_options(stored + [{"code": 160, "value": URL}], previous=stored)
    # Going live re-checks every option, the unchanged ones included.
    with pytest.raises(ValueError, match="placeholder"):
        validate_phone_options(stored, previous=stored, going_live=True)
    broken = [{"code": 43, "value": "0x01"}]
    with pytest.raises(ValueError, match="'code:43'"):
        validate_phone_options(broken, previous=broken, going_live=True)


def test_a_catalogue_label_that_contradicts_its_code_is_refused() -> None:
    # The editor's "Add option" row defaults to code 66; a label typed over it
    # without changing the code would otherwise deliver the URL as option 66.
    with pytest.raises(ValueError, match="which is option 160"):
        validate_phone_options([{"code": 66, "name": "polycom-config-url", "value": URL}])
    with pytest.raises(ValueError, match="which is option 43"):
        validate_phone_options([{"code": 160, "name": "code:43", "value": "0104"}])


def test_a_stored_contradiction_keeps_its_pre_1294_delivery() -> None:
    # Before #1294 a label the agent knew decided, and any other was dropped.
    stored = [
        {"code": 66, "name": "tftp-server-address", "value": "10.0.0.9"},
        {"code": 66, "name": "polycom-config-url", "value": URL},
    ]
    assert phone_options_map(stored) == {"tftp-server-address": "10.0.0.9"}
    # And the profile stays editable while those rows are left alone.
    validate_phone_options(
        stored + [{"code": 161, "name": "yealink-prov-server", "value": URL}],
        previous=stored,
    )
    # Going live re-checks every row, so the contradiction has to be fixed.
    with pytest.raises(ValueError, match="which is option 150"):
        validate_phone_options(stored, previous=stored, going_live=True)


def test_an_enabled_profile_cannot_gain_a_placeholder() -> None:
    rows = [{"code": 160, "name": "polycom-config-url", "value": "CHANGE-ME"}]
    with pytest.raises(ValueError, match="placeholder"):
        validate_phone_options(rows, previous=[], enabled=True)
    # One already stored is left alone.
    validate_phone_options(rows, previous=rows, enabled=True)


def test_the_render_drops_what_kea_cannot_load() -> None:
    kept, dropped = phone_options_loadable(
        [
            {"code": 43, "name": "vendor-encapsulated-options", "value": "CHANGE-ME"},
            {"code": 160, "name": "polycom-config-url", "value": URL},
        ]
    )
    assert kept == {"code:160": URL}
    assert dropped == ["code:43"]


# ── Bundle ───────────────────────────────────────────────────────────────────


async def test_a_stored_profile_renders_by_code_and_skips_a_bad_match(
    db_session: AsyncSession,
) -> None:
    grp, srv, scope = await _make_group_server_scope(db_session)
    good = DHCPPhoneProfile(
        group_id=grp.id,
        name="Polycom",
        description="",
        enabled=True,
        vendor="Polycom",
        vendor_class_match="Polycôm",
        option_set=[
            {"code": 160, "name": "polycom-config-url", "value": URL},
            {"code": 43, "name": "vendor-encapsulated-options", "value": "CHANGE-ME"},
        ],
    )
    # Stored before the write check existed: the quote would end Kea's
    # string literal and reject the whole config.
    bad = DHCPPhoneProfile(
        group_id=grp.id,
        name="Broken",
        description="",
        enabled=True,
        vendor_class_match="it's",
        option_set=[{"code": 66, "value": "tftp.example"}],
    )
    newline = DHCPPhoneProfile(
        group_id=grp.id,
        name="Newline",
        description="",
        enabled=True,
        vendor_class_match="Poly\ncom",
        option_set=[{"code": 66, "value": "tftp.example"}],
    )
    db_session.add_all([good, bad, newline])
    await db_session.flush()
    db_session.add_all(
        [
            DHCPPhoneProfileScope(profile_id=good.id, scope_id=scope.id),
            DHCPPhoneProfileScope(profile_id=bad.id, scope_id=scope.id),
            DHCPPhoneProfileScope(profile_id=newline.id, scope_id=scope.id),
        ]
    )
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)
    (pc,) = bundle.phone_classes
    assert pc.options == {"code:160": URL}
    # Bytes, not characters: "ô" is two bytes of option 60.
    assert "substring(option[60].hex,0,8)" in pc.match_expression


# ── API ──────────────────────────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_the_api_checks_options_and_the_vendor_match(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(grp)
    await db_session.commit()
    url = f"/api/v1/dhcp/server-groups/{grp.id}/phone-profiles"

    resp = await client.post(
        url,
        headers=h,
        json={"name": "p1", "option_set": [{"code": 43, "value": "hello"}]},
    )
    assert resp.status_code == 422, resp.text
    assert "code:43" in resp.json()["detail"]

    resp = await client.post(url, headers=h, json={"name": "p2", "vendor_class_match": "a'b"})
    assert resp.status_code == 422, resp.text

    resp = await client.post(
        url,
        headers=h,
        json={"name": "p3", "option_set": [{"code": 160, "value": "CHANGE-ME"}]},
    )
    assert resp.status_code == 422, resp.text
    assert "placeholder" in resp.json()["detail"]


async def test_a_starter_pack_profile_cannot_be_enabled_with_its_placeholders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(grp)
    await db_session.commit()

    seeded = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/phone-profiles/seed-starter-pack", headers=h
    )
    assert seeded.status_code in (200, 201), seeded.text
    polycom = next(p for p in seeded.json() if p["name"] == "Polycom")
    assert polycom["enabled"] is False

    # An edit that leaves it disabled is fine: the placeholders are untouched.
    resp = await client.put(
        f"/api/v1/dhcp/phone-profiles/{polycom['id']}", headers=h, json={"description": "x"}
    )
    assert resp.status_code == 200, resp.text

    resp = await client.put(
        f"/api/v1/dhcp/phone-profiles/{polycom['id']}", headers=h, json={"enabled": True}
    )
    assert resp.status_code == 422, resp.text
    assert "placeholder" in resp.json()["detail"]

    resp = await client.put(
        f"/api/v1/dhcp/phone-profiles/{polycom['id']}",
        headers=h,
        json={
            "enabled": True,
            "option_set": [
                {"code": 66, "name": "tftp-server-name", "value": "tftp.example"},
                {"code": 160, "name": "polycom-config-url", "value": URL},
            ],
        },
    )
    assert resp.status_code == 200, resp.text

"""A PXE arch-match's vendor-class match is checked on write and at render (#1357).

``vendor_class_match`` renders inside Kea's ``=='<match>'`` string literal,
exactly like a phone profile's (#1294): a ``'`` ends the literal early and a
control character is refused inside one, so either rejects the server
group's WHOLE config. The phone-profile twin was fixed in #1294; PXE was
not, and its substring length was measured in characters, not bytes.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPPXEArchMatch, DHCPPXEProfile, DHCPServerGroup
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.option_validation import (
    check_vendor_class_match,
    vendor_class_match_test,
)
from tests.test_dhcp_phone_profiles import _make_group_server_scope


@pytest.mark.parametrize("value", ["it's", "PXE\nClient", "PXE\x00"])
def test_the_shared_check_refuses_what_breaks_the_literal(value: str) -> None:
    with pytest.raises(ValueError, match="vendor_class_match"):
        check_vendor_class_match(value)


@pytest.mark.parametrize("value", [None, "PXEClient", "HTTPClient:Arch:00016", "Polycôm"])
def test_the_shared_check_accepts_real_vendor_classes(value: str | None) -> None:
    assert check_vendor_class_match(value) == value


def test_ascii_keeps_the_quoted_form_and_non_ascii_renders_hex() -> None:
    # ASCII is byte-identical to the pre-#1357 render, so no ETag moves.
    assert vendor_class_match_test("PXEClient") == "substring(option[60].hex,0,9)=='PXEClient'"
    # Above U+00FF a quoted literal is JSON-escaped to ``\u20ac``, which Kea's
    # lexer refuses ("Unsupported unicode escape") — the whole config.
    expr = vendor_class_match_test("V€")
    assert expr == "substring(option[60].hex,0,4)==0x56E282AC"
    assert "'" not in expr


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


def _match(vendor: str | None) -> dict:
    return {"vendor_class_match": vendor, "arch_codes": [7], "boot_filename": "ipxe.efi"}


@pytest.mark.parametrize("bad", ["PXE'Client", "PXE\nClient"])
async def test_create_and_update_refuse_a_bad_vendor_match(
    client: AsyncClient, db_session: AsyncSession, bad: str
) -> None:
    h = await _headers(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(grp)
    await db_session.commit()
    url = f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles"

    resp = await client.post(
        url, headers=h, json={"name": "bad", "next_server": "10.0.0.5", "matches": [_match(bad)]}
    )
    assert resp.status_code == 422, resp.text
    assert "vendor_class_match" in resp.text

    resp = await client.post(
        url,
        headers=h,
        json={"name": "good", "next_server": "10.0.0.5", "matches": [_match("PXEClient")]},
    )
    assert resp.status_code == 201, resp.text
    profile_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{profile_id}", headers=h, json={"matches": [_match(bad)]}
    )
    assert resp.status_code == 422, resp.text
    assert "vendor_class_match" in resp.text

    # A non-ASCII vendor string is legitimate and still accepted.
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{profile_id}",
        headers=h,
        json={"matches": [_match("Vendör")]},
    )
    assert resp.status_code == 200, resp.text


async def test_a_stored_bad_match_is_left_out_and_the_rest_renders(
    db_session: AsyncSession,
) -> None:
    grp, srv, scope = await _make_group_server_scope(db_session)
    prof = DHCPPXEProfile(group_id=grp.id, name="boot", next_server="10.0.0.5", enabled=True)
    db_session.add(prof)
    await db_session.flush()
    good = DHCPPXEArchMatch(
        profile_id=prof.id,
        priority=10,
        vendor_class_match="Vendör",
        arch_codes=[7],
        boot_filename="ipxe.efi",
    )
    # Stored before the write check existed: the quote would end Kea's
    # string literal and reject the whole config.
    bad = DHCPPXEArchMatch(
        profile_id=prof.id,
        priority=20,
        vendor_class_match="it's",
        arch_codes=[0],
        boot_filename="undionly.kpxe",
    )
    db_session.add_all([good, bad])
    scope.pxe_profile_id = prof.id
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)
    (pc,) = bundle.pxe_classes
    assert pc.boot_file_name == "ipxe.efi"
    # Bytes, not characters: "ö" is two bytes of option 60, so "Vendör" is 7.
    # And a hex literal, not a quoted one: JSON-escaped to ``\u00f6``, Kea
    # would read the quoted form as ONE byte and never match.
    assert "substring(option[60].hex,0,7)==0x56656E64C3B672" in pc.match_expression
    assert "option[93].hex == 0x0007" in pc.match_expression
    # The rest of the bundle is intact.
    assert bundle.scopes

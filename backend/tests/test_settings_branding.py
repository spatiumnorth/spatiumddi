"""Settings-router tests for branding (issues #885 / #886 / #887 / #888).

Covers:

* ``GET /settings/public`` answers UNAUTHENTICATED and returns only the
  whitelisted branding fields — the login page depends on both halves.
* Banner fields round-trip through PUT /settings and are audited.
* Branding writes are superadmin-only: a delegated ``write:settings``
  editor is refused, because these fields render to anonymous visitors.
* Colour + length validation rejects anything that is not a hex triple.
* Logo upload accepts a PNG, rejects a non-PNG (an SVG in particular) and
  rejects an oversized file; the bytes come back from the public route
  with a matching ETag, and DELETE restores the bundled-asset fallback.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
import zlib

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.settings import BRANDING_ASSET_MAX_BYTES


async def _make_superadmin(db: AsyncSession, username: str = "brsuper") -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_settings_editor(db: AsyncSession, username: str = "brsettings") -> tuple[User, str]:
    """Holds ``write`` on ``settings`` but is not a superadmin — passes the
    generic settings gate, must still fail the branding gate."""
    role = Role(
        name=f"settings-editor-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": "write", "resource_type": "settings"}],
    )
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return user, create_access_token(str(user.id))


def _tiny_png() -> bytes:
    """A real 1x1 PNG, built here so the test needs no fixture file."""

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\xff\xff")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


@pytest.mark.asyncio
async def test_public_settings_needs_no_auth(client: AsyncClient) -> None:
    # No Authorization header at all — this is the whole point of the route.
    resp = await client.get("/api/v1/settings/public")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert set(body) == {"app_title", "login_banner", "env_banner", "logo_sha256"}
    assert body["login_banner"]["enabled"] is False
    assert body["env_banner"]["enabled"] is False
    assert body["logo_sha256"] is None


@pytest.mark.asyncio
async def test_banner_round_trip_and_audit(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={
            "app_title": "Acme DDI",
            "login_banner_enabled": True,
            "login_banner_title": "NOTICE",
            "login_banner_text": "Authorised users only.",
            "login_banner_require_ack": True,
            "env_banner_enabled": True,
            "env_banner_text": "DEVELOPMENT",
            "env_banner_bg": "#B91C1C",
            "env_banner_fg": "#FFFFFF",
            "env_banner_position": "both",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["login_banner_require_ack"] is True
    # Colours are normalised to lowercase on the way in.
    assert body["env_banner_bg"] == "#b91c1c"
    assert body["env_banner_position"] == "both"

    # The same values must now reach an anonymous visitor.
    pub = (await client.get("/api/v1/settings/public")).json()
    assert pub["app_title"] == "Acme DDI"
    assert pub["login_banner"] == {
        "enabled": True,
        "title": "NOTICE",
        "text": "Authorised users only.",
        "require_ack": True,
    }
    assert pub["env_banner"]["text"] == "DEVELOPMENT"

    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.resource_id == "branding")))
        .scalars()
        .all()
    )
    assert len(audit) == 1
    assert audit[0].resource_type == "platform_settings"
    assert audit[0].new_value["login_banner_text"] == "Authorised users only."


@pytest.mark.asyncio
async def test_branding_write_requires_superadmin(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_settings_editor(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"login_banner_text": "hello"},
    )
    assert resp.status_code == 403, resp.text

    # A non-branding field still goes through for the same user, proving
    # the refusal is the branding gate and not the generic settings gate.
    ok = await client.put(
        "/api/v1/settings",
        headers=headers,
        json={"dns_default_ttl": 7200},
    )
    assert ok.status_code == 200, ok.text


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["red", "#fff", "b91c1c", "#gggggg", "rgb(1,2,3)"])
async def test_rejects_non_hex_colour(
    db_session: AsyncSession, client: AsyncClient, bad: str
) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"env_banner_bg": bad},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_rejects_overlong_banner_text(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={"env_banner_text": "x" * 201},
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "limit"),
    [("app_title", 255), ("app_base_url", 500)],
)
async def test_rejects_overlong_title_and_base_url_naming_the_field(
    db_session: AsyncSession, client: AsyncClient, field: str, limit: int
) -> None:
    # #2205 — the column limit is enforced at the API with a reason that
    # names the field, not the catch-all "cannot be stored as sent".
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={field: "a" * (limit + 1)},
    )
    assert resp.status_code == 422, resp.text
    assert f"{field} must be {limit} characters or fewer" in resp.text
    ok = await client.put(
        "/api/v1/settings",
        headers={"Authorization": f"Bearer {token}"},
        json={field: "a" * limit},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()[field] == "a" * limit


@pytest.mark.asyncio
async def test_logo_upload_serve_and_delete(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}
    png = _tiny_png()

    resp = await client.put(
        "/api/v1/settings/branding/logo",
        headers=headers,
        files={"file": ("logo.png", png, "image/png")},
    )
    assert resp.status_code == 200, resp.text
    digest = hashlib.sha256(png).hexdigest()
    assert resp.json()["sha256"] == digest

    # Advertised on the public payload so the frontend knows to use it.
    pub = (await client.get("/api/v1/settings/public")).json()
    assert pub["logo_sha256"] == digest

    # Bytes come back unauthenticated, with a matching ETag.
    got = await client.get("/api/v1/settings/public/logo")
    assert got.status_code == 200
    assert got.content == png
    assert got.headers["content-type"] == "image/png"
    etag = got.headers["etag"]
    assert digest in etag

    # A conditional re-fetch is a 304, so browsers don't re-pull the blob.
    again = await client.get("/api/v1/settings/public/logo", headers={"If-None-Match": etag})
    assert again.status_code == 304

    # Uploading a second time replaces rather than accumulating.
    resp2 = await client.put(
        "/api/v1/settings/branding/logo",
        headers=headers,
        files={"file": ("logo.png", png, "image/png")},
    )
    assert resp2.status_code == 200

    delete = await client.delete("/api/v1/settings/branding/logo", headers=headers)
    assert delete.status_code == 204
    assert (await client.get("/api/v1/settings/public/logo")).status_code == 404
    assert (await client.get("/api/v1/settings/public")).json()["logo_sha256"] is None


@pytest.mark.asyncio
async def test_logo_rejects_svg_and_other_non_png(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """SVG is the one that matters: it is served same-origin and can carry
    script, so accepting it would be stored XSS against anonymous visitors."""
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    resp = await client.put(
        "/api/v1/settings/branding/logo",
        # Even with an image content-type claimed by the client.
        headers=headers,
        files={"file": ("logo.svg", svg, "image/png")},
    )
    assert resp.status_code == 422, resp.text
    assert (await client.get("/api/v1/settings/public/logo")).status_code == 404


@pytest.mark.asyncio
async def test_logo_rejects_oversized_upload(db_session: AsyncSession, client: AsyncClient) -> None:
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    # Valid PNG magic, but past the cap — the size check must fire even
    # for a well-formed image.
    payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * (BRANDING_ASSET_MAX_BYTES + 1)
    resp = await client.put(
        "/api/v1/settings/branding/logo",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("big.png", payload, "image/png")},
    )
    assert resp.status_code == 413, resp.text


@pytest.mark.asyncio
async def test_logo_write_requires_superadmin(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_settings_editor(db_session, "brlogoeditor")
    await db_session.commit()
    resp = await client.put(
        "/api/v1/settings/branding/logo",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("logo.png", _tiny_png(), "image/png")},
    )
    assert resp.status_code == 403, resp.text

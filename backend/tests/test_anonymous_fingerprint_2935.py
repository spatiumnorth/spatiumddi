"""Anonymous callers learn nothing about the version or the stack (#2935).

Version and stack details are for signed-in users only: the exact release
tells a scanner which advisories apply, and the worker list names every
container. Each surface keeps answering an anonymous caller, because
something legitimately asks it without a credential (the installer's
control-plane probe, an uptime monitor, the docs page shell), but with the
coarse answer only. A signed-in caller keeps the full one.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import hash_password
from app.drivers.dns.base import ServerOptions
from app.drivers.dns.bind9 import BIND9Driver
from app.drivers.dns.powerdns import render_pdns_conf
from app.models.auth import User, UserSession
from app.models.settings import PlatformSettings

from ._signed_in import signed_in_headers

RUNNING = "2026.10.02-1"
# Not a real release; just something no anonymous body may contain.
LATEST = "2026.10.09-7"


@pytest.fixture
def running(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "version", RUNNING)
    monkeypatch.setattr(settings, "app_version", "")


async def _release_check(db: AsyncSession) -> None:
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.latest_version = LATEST
    ps.update_available = True
    ps.latest_release_url = f"https://example.invalid/{LATEST}"
    await db.commit()


# ── /api/v1/version ──────────────────────────────────────────────────────


async def test_version_anonymous_gets_the_coarse_handshake(
    client: AsyncClient, db_session: AsyncSession, running: None
) -> None:
    await _release_check(db_session)
    r = await client.get("/api/v1/version")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["product"] == "SpatiumDDI"
    assert body["api_level"] == 1
    assert body["restricted"] is True
    assert body["version"] == "restricted"
    assert body["latest_version"] is None
    assert body["latest_release_url"] is None
    assert body["update_available"] is False
    assert body["release_check_enabled"] is False
    assert RUNNING not in r.text and LATEST not in r.text


async def test_version_anonymous_still_satisfies_an_older_installer(
    client: AsyncClient, running: None
) -> None:
    """An installer ISO built before #2935 decides "this is a SpatiumDDI
    control plane" with ``sed 's/.*"version"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\1/p'``
    and calls anything without a match "NOT reachable … Is this the right
    host?". The placeholder keeps that match non-empty without being a
    version, and neither version parser mistakes it for a release."""
    from app.core.versions import parse_release

    r = await client.get("/api/v1/version")
    m = re.search(r'.*"version"\s*:\s*"([^"]*)"', r.text)
    assert m and m.group(1) == "restricted", r.text
    assert parse_release(m.group(1)) is None


async def test_version_signed_in_gets_the_full_answer(
    client: AsyncClient, db_session: AsyncSession, running: None
) -> None:
    await _release_check(db_session)
    r = await client.get("/api/v1/version", headers=await signed_in_headers(db_session))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["product"] == "SpatiumDDI"
    assert body["restricted"] is False
    assert body["version"] == RUNNING
    assert body["latest_version"] == LATEST
    assert body["update_available"] is True


async def test_version_with_a_bad_token_is_anonymous_not_401(
    client: AsyncClient, running: None
) -> None:
    r = await client.get("/api/v1/version", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 200, r.text
    assert r.json()["restricted"] is True
    assert RUNNING not in r.text


# ── /api/openapi.json, /api/docs, /api/redoc ────────────────────────────


async def test_openapi_document_needs_a_session(client: AsyncClient, running: None) -> None:
    r = await client.get("/api/openapi.json")
    assert r.status_code == 401, r.text
    assert RUNNING not in r.text


async def test_openapi_document_signed_in(
    client: AsyncClient, db_session: AsyncSession, running: None
) -> None:
    r = await client.get("/api/openapi.json", headers=await signed_in_headers(db_session))
    assert r.status_code == 200, r.text
    spec = r.json()
    assert spec["openapi"].startswith("3.")
    assert "/api/v1/version" in spec["paths"]
    # It is the document app.openapi() builds — the release asset's source.
    from app.main import app

    assert spec == app.openapi()


@pytest.mark.parametrize("path", ["/api/docs", "/api/redoc"])
async def test_docs_pages_are_shells_without_the_spec(
    client: AsyncClient, path: str, running: None
) -> None:
    """The pages still load for anyone, but carry no route and no version:
    the spec is fetched by the page, signed in."""
    r = await client.get(path)
    assert r.status_code == 200, r.text
    assert RUNNING not in r.text
    assert "/api/v1/" not in r.text.replace("/api/v1/auth/openapi.json", "")
    assert '"paths"' not in r.text
    # The page never asks /auth/refresh: a refresh rotates the session the
    # console tab's access token belongs to.
    assert "/auth/refresh" not in r.text


# ── /api/v1/auth/openapi.json — the docs pages' spec, by cookie ─────────

_PASSWORD = "Sup3r-secret!"


async def _logged_in(client: AsyncClient, db: AsyncSession, **user_kw: Any) -> User:
    user = User(
        username=f"docs-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="Docs reader",
        hashed_password=hash_password(_PASSWORD),
        auth_source="local",
        is_active=True,
        is_superadmin=False,
    )
    db.add(user)
    await db.commit()
    r = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": _PASSWORD}
    )
    assert r.status_code == 200, r.text
    assert client.cookies.get("spatium_refresh")
    for k, v in user_kw.items():
        setattr(user, k, v)
    await db.commit()
    return user


async def _live_sessions(db: AsyncSession, user_id: Any) -> list[tuple[Any, str]]:
    """``(id, refresh_token_hash)`` of the user's unrevoked sessions."""
    from sqlalchemy import select

    rows = await db.execute(
        select(UserSession.id, UserSession.refresh_token_hash)
        .where(UserSession.user_id == user_id)
        .where(UserSession.revoked.is_(False))
        .execution_options(populate_existing=True)
    )
    return [tuple(r) for r in rows.all()]


async def test_docs_spec_by_cookie_does_not_rotate_the_session(
    client: AsyncClient, db_session: AsyncSession, running: None
) -> None:
    """The docs tab reads the refresh cookie and rotates nothing, so the
    console tab's access token (bound to that session) keeps working and the
    console's own next refresh, with the same cookie, still succeeds."""
    user = await _logged_in(client, db_session)
    user_id = user.id
    cookie = client.cookies.get("spatium_refresh")
    before = await _live_sessions(db_session, user_id)
    assert len(before) == 1

    from app.main import app

    r = await client.get("/api/v1/auth/openapi.json")
    assert r.status_code == 200, r.text
    assert r.json() == app.openapi()
    assert r.headers["cache-control"] == "no-store"
    assert not [c for c in r.headers.get_list("set-cookie") if c.startswith("spatium_refresh=")]

    after = await _live_sessions(db_session, user_id)
    assert after == before
    assert client.cookies.get("spatium_refresh") == cookie

    # The console refreshing afterwards, with the cookie it already had.
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200


async def test_docs_spec_by_cookie_without_a_session_is_401(
    client: AsyncClient, running: None
) -> None:
    r = await client.get("/api/v1/auth/openapi.json")
    assert r.status_code == 401, r.text
    assert RUNNING not in r.text
    client.cookies.set("spatium_refresh", "not-a-token", path="/api/v1/auth")
    assert (await client.get("/api/v1/auth/openapi.json")).status_code == 401


async def test_docs_spec_by_cookie_refuses_a_rotated_cookie(
    client: AsyncClient, db_session: AsyncSession, running: None
) -> None:
    await _logged_in(client, db_session)
    stale = client.cookies.get("spatium_refresh")
    assert (await client.post("/api/v1/auth/refresh")).status_code == 200
    client.cookies.clear()
    client.cookies.set("spatium_refresh", stale, path="/api/v1/auth")
    assert (await client.get("/api/v1/auth/openapi.json")).status_code == 401


@pytest.mark.parametrize(
    "user_kw",
    [{"is_active": False}, {"force_password_change": True}],
    ids=["disabled", "must-change"],
)
async def test_docs_spec_by_cookie_refuses_a_gated_account(
    client: AsyncClient, db_session: AsyncSession, running: None, user_kw: dict[str, Any]
) -> None:
    await _logged_in(client, db_session, **user_kw)
    assert (await client.get("/api/v1/auth/openapi.json")).status_code == 401


# ── /health/platform ─────────────────────────────────────────────────────


class _Redis:
    async def get(self, _key: str) -> bytes | None:
        return None

    async def ping(self) -> bool:
        return True

    async def aclose(self) -> None:
        return None


class _Control:
    def inspect(self, timeout: float = 1.0) -> _Control:
        return self

    def ping(self) -> dict[str, Any]:
        # The worker's hostname, which on Compose is the container id.
        return {"celery@3f2a9c1d0b7e": {"ok": "pong"}}


@pytest.fixture
def workers(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.celery_app import celery_app

    monkeypatch.setattr(celery_app, "control", _Control())
    monkeypatch.setattr("app.core.redis_client.make_async_redis", lambda *a, **k: _Redis())


async def test_platform_health_anonymous_is_status_only(client: AsyncClient, workers: None) -> None:
    r = await client.get("/health/platform")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"status"}
    assert body["status"] in ("ok", "degraded")
    assert "3f2a9c1d0b7e" not in r.text


async def test_platform_health_signed_in_keeps_the_details(
    client: AsyncClient, db_session: AsyncSession, workers: None
) -> None:
    r = await client.get("/health/platform", headers=await signed_in_headers(db_session))
    assert r.status_code == 200, r.text
    body = r.json()
    names = {c["name"] for c in body["components"]}
    assert {"api", "postgres", "redis", "celery-workers", "celery-beat"} <= names
    w = next(c for c in body["components"] if c["name"] == "celery-workers")
    assert w["workers"] == ["celery@3f2a9c1d0b7e"]
    for key in ("demo_mode", "maintenance_mode", "maintenance_message"):
        assert key in body


async def test_platform_health_rollup_matches_for_both(
    client: AsyncClient, db_session: AsyncSession, workers: None
) -> None:
    """The anonymous rollup is the same verdict, not a constant."""
    anon = (await client.get("/health/platform")).json()["status"]
    full = (
        await client.get("/health/platform", headers=await signed_in_headers(db_session))
    ).json()["status"]
    assert anon == full


# ── DNS daemons describe themselves as "none" ───────────────────────────


def test_control_plane_bind9_template_hides_the_version() -> None:
    out = BIND9Driver().render_server_config(None, ServerOptions())
    options = out[out.index("options {") :]
    assert '    version "none";' in options
    assert "    hostname none;" in options


def test_control_plane_pdns_conf_hides_the_version() -> None:
    lines = render_pdns_conf(api_key="k").splitlines()
    assert "version-string=none" in lines
    assert "server-id=none" in lines

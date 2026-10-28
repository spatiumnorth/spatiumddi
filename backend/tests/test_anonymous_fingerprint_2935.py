"""Anonymous callers learn nothing about the version or the stack (#2935).

Version and stack details are for signed-in users only: the exact release
tells a scanner which advisories apply, and the worker list names every
container. Each surface keeps answering an anonymous caller, because
something legitimately asks it without a credential (the installer's
control-plane probe, an uptime monitor, the docs page shell), but with the
coarse answer only. A signed-in caller keeps the full one.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.drivers.dns.base import ServerOptions
from app.drivers.dns.bind9 import BIND9Driver
from app.drivers.dns.powerdns import render_pdns_conf
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
    assert body["version"] is None
    assert body["latest_version"] is None
    assert body["latest_release_url"] is None
    assert body["update_available"] is False
    assert body["release_check_enabled"] is False
    assert RUNNING not in r.text and LATEST not in r.text


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
    assert "/api/v1/" not in r.text.replace("/api/v1/auth/refresh", "")
    assert '"paths"' not in r.text


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

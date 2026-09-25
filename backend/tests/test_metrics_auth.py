"""/metrics needs a bearer token (#1159).

The endpoint was anonymous, and it is reachable from outside: the web port
proxies it, and Docker Compose publishes the api port. So anyone who could
load the login page could read per-route request counts and the login
counters. It now answers only a request carrying the scrape token
(``PROMETHEUS_METRICS_TOKEN``) or a valid API token, unless
``PROMETHEUS_METRICS_REQUIRE_AUTH`` turns the check off.

The scrape-token cases use a throwaway app and need no database. The
API-token cases go through the real token resolver, so they create a user and
a token in the test database.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.security import generate_api_token, hash_password
from app.metrics import metrics_endpoint
from app.models.auth import APIToken, User

SCRAPE_TOKEN = "scrape-token-for-the-1159-tests"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_route("/metrics", metrics_endpoint)
    return app


@pytest.fixture
def require_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", SCRAPE_TOKEN)


def _get(headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    response = TestClient(_app()).get("/metrics", headers=headers or {})
    return response.status_code, dict(response.headers), response.content


def test_an_anonymous_scrape_is_refused(require_token: None) -> None:
    status, headers, body = _get()
    assert status == 401
    assert headers["www-authenticate"].startswith("Bearer")
    assert b"spatiumddi_" not in body, "a refused scrape must not leak the metrics"


def test_the_scrape_token_is_accepted(require_token: None) -> None:
    status, headers, body = _get({"Authorization": f"Bearer {SCRAPE_TOKEN}"})
    assert status == 200
    assert headers["content-type"].startswith("text/plain")
    assert b"spatiumddi_api_requests_total" in body


@pytest.mark.parametrize(
    "authorization",
    [
        f"Bearer {SCRAPE_TOKEN}x",
        f"Bearer {SCRAPE_TOKEN[:-1]}",
        f"Basic {SCRAPE_TOKEN}",
        f"Token {SCRAPE_TOKEN}",
        SCRAPE_TOKEN,
        "Bearer",
        "Bearer   ",
    ],
)
def test_anything_but_the_exact_bearer_token_is_refused(
    require_token: None, authorization: str
) -> None:
    status, _, _ = _get({"Authorization": authorization})
    assert status == 401


def test_an_unset_scrape_token_matches_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no scrape token configured, only API tokens get in. An empty
    bearer must not compare equal to the empty setting."""
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", "")
    for authorization in ("Bearer ", "Bearer  ", "Bearer x"):
        status, _, _ = _get({"Authorization": authorization})
        assert status == 401, authorization


def test_anonymous_scraping_can_be_turned_back_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", False)
    monkeypatch.setattr(settings, "prometheus_metrics_token", "")
    status, _, body = _get()
    assert status == 200
    assert b"spatiumddi_api_requests_total" in body


async def _api_token(db: AsyncSession, *, active: bool = True, user_active: bool = True) -> str:
    owner = User(
        username=f"mx-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Metrics scraper",
        hashed_password=hash_password("x"),
        is_superadmin=False,
        is_active=user_active,
    )
    db.add(owner)
    await db.flush()
    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"mx-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=active,
        )
    )
    await db.commit()
    return raw


async def _async_get(authorization: str) -> int:
    transport = ASGITransport(app=_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/metrics", headers={"Authorization": authorization})
    return response.status_code


@pytest.mark.asyncio
async def test_an_api_token_is_accepted(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any valid API token can scrape: no scrape token is configured here, so
    this goes through the real token resolver."""
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", "")
    raw = await _api_token(db_session)
    assert await _async_get(f"Bearer {raw}") == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("active", "user_active"),
    [(False, True), (True, False)],
    ids=["revoked token", "disabled owner"],
)
async def test_an_api_token_the_resolver_refuses_is_refused(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, active: bool, user_active: bool
) -> None:
    monkeypatch.setattr(settings, "prometheus_metrics_require_auth", True)
    monkeypatch.setattr(settings, "prometheus_metrics_token", "")
    raw = await _api_token(db_session, active=active, user_active=user_active)
    assert await _async_get(f"Bearer {raw}") == 401

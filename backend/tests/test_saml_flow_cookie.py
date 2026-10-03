"""SAML flow-cookie SameSite semantics (issue #873).

The IdP returns the assertion as a cross-site POST to our ACS. A
``SameSite=Lax`` cookie is never sent on a cross-site POST, so the flow
cookie has to be ``SameSite=None`` — which browsers only honour when the
cookie is also ``Secure``. These tests pin both halves: the attributes on
the cookie, and the HTTPS pre-flight that refuses the flow when the
deployment could not set such a cookie in the first place.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import router as auth_router
from app.models.auth_provider import AuthProvider
from app.models.settings import PlatformSettings

pytestmark = pytest.mark.asyncio


async def _saml_provider(db_session: AsyncSession) -> AuthProvider:
    provider = AuthProvider(
        name="test-idp",
        type="saml",
        is_enabled=True,
        config={
            "idp_entity_id": "https://idp.example.com/entity",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_x509_cert": "MIIBogus",
        },
    )
    db_session.add(provider)
    await db_session.commit()
    return provider


async def _set_base_url(db_session: AsyncSession, url: str) -> None:
    row = await db_session.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db_session.add(row)
    row.app_base_url = url
    await db_session.commit()


async def test_saml_flow_cookie_is_samesite_none_and_secure(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cookie must survive the IdP's cross-site POST back to the ACS."""
    provider = await _saml_provider(db_session)
    await _set_base_url(db_session, "https://ddi.example.com")
    monkeypatch.setattr(
        auth_router,
        "saml_authorize_url",
        lambda cfg, base, relay: ("https://idp.example.com/sso?x=1", "ONELOGIN_stub"),
    )

    resp = await client.get(f"/api/v1/auth/{provider.id}/authorize")

    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://idp.example.com/sso")
    set_cookie = next(
        v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie" and "saml_flow=" in v
    )
    lowered = set_cookie.lower()
    assert "samesite=none" in lowered
    assert "secure" in lowered
    assert "httponly" in lowered
    assert "path=/api/v1/auth/" in lowered


async def test_saml_flow_cookie_stays_lax_over_plain_http(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SameSite=None is only honoured with Secure, which we cannot set over
    HTTP — so an HTTP deployment keeps the Lax cookie, which is exactly what
    the one IdP topology that can work there (same-site) needs. The flow is
    not refused up front: that would break those installs."""
    provider = await _saml_provider(db_session)
    await _set_base_url(db_session, "http://ddi.example.com")
    monkeypatch.setattr(
        auth_router,
        "saml_authorize_url",
        lambda cfg, base, relay: ("https://idp.example.com/sso?x=1", "ONELOGIN_stub"),
    )

    resp = await client.get(f"/api/v1/auth/{provider.id}/authorize")

    assert resp.status_code == 302
    assert resp.headers["location"].startswith("https://idp.example.com/sso")
    set_cookie = next(
        v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie" and "saml_flow=" in v
    )
    lowered = set_cookie.lower()
    assert "samesite=lax" in lowered
    assert "secure" not in lowered


async def test_acs_without_cookie_over_http_reports_requires_https(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """On an HTTP deployment a missing flow cookie means the IdP's POST was
    cross-site and the Lax cookie was withheld — an actionable TLS problem,
    not a "try again" state error."""
    provider = await _saml_provider(db_session)
    await _set_base_url(db_session, "http://ddi.example.com")

    resp = await client.post(
        f"/api/v1/auth/{provider.id}/callback",
        data={"SAMLResponse": "bogus", "RelayState": "whatever"},
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?error=saml_requires_https"


async def test_acs_without_cookie_over_https_is_a_state_error(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Over HTTPS the cookie is SameSite=None and should have ridden the POST,
    so absence is a genuinely expired / dropped flow."""
    provider = await _saml_provider(db_session)
    await _set_base_url(db_session, "https://ddi.example.com")

    resp = await client.post(
        f"/api/v1/auth/{provider.id}/callback",
        data={"SAMLResponse": "bogus", "RelayState": "whatever"},
    )

    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?error=saml_state_missing"

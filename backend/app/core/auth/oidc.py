"""OpenID Connect authorization-code flow helpers.

The orchestration (redirect to IdP, cookie-bound state + nonce, callback
handling) lives in ``backend/app/api/v1/auth/router.py``. This module
provides the pure IdP interactions: discovery, authorize URL building,
token exchange with ID-token verification, and an admin probe.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlencode

import httpx
import structlog
from joserfc import jwt
from joserfc._keys import KeySetSerialization
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from app.core.auth.user_sync import ExternalAuthResult
from app.core.crypto import decrypt_dict
from app.models.auth_provider import AuthProvider

logger = structlog.get_logger(__name__)


class OIDCServiceError(Exception):
    """Raised on discovery / token / verification failures."""


#: How far before a step-up flow started an ``auth_time`` may fall, for clock
#: skew between this server and the IdP. A compliant IdP re-authenticates
#: AFTER the flow starts, so this only has to cover skew.
AUTH_TIME_LEEWAY_SECONDS = 30


def _require_fresh_auth_time(raw: Any, fresh_since: int, *, now: float | None = None) -> None:
    # bool is an int subclass; ``true`` is not a time.
    # ``math.isfinite``: Python's JSON decoder accepts ``NaN`` / ``Infinity``,
    # and NaN compares False both ways, so it would pass both bounds below.
    if isinstance(raw, bool) or not isinstance(raw, int | float) or not math.isfinite(raw):
        raise OIDCServiceError("ID token has no usable auth_time, so it proves no fresh sign-in")
    current = time.time() if now is None else now
    if raw < fresh_since - AUTH_TIME_LEEWAY_SECONDS:
        raise OIDCServiceError("ID token auth_time predates this re-authentication")
    if raw > current + AUTH_TIME_LEEWAY_SECONDS:
        raise OIDCServiceError("ID token auth_time is in the future")


@dataclass
class OIDCConfig:
    discovery_url: str
    client_id: str
    client_secret: str
    scopes: list[str]
    claim_username: str
    claim_email: str
    claim_display_name: str
    claim_groups: str

    @classmethod
    def from_provider(cls, provider: AuthProvider) -> OIDCConfig:
        cfg = provider.config or {}
        secrets_data = (
            decrypt_dict(provider.secrets_encrypted) if provider.secrets_encrypted else {}
        )

        discovery_url = str(cfg.get("discovery_url") or "").strip()
        if not discovery_url:
            raise OIDCServiceError("config.discovery_url is required")
        client_id = str(cfg.get("client_id") or "").strip()
        client_secret = str(secrets_data.get("client_secret") or "")
        if not client_id:
            raise OIDCServiceError("config.client_id is required")
        if not client_secret:
            raise OIDCServiceError("secrets.client_secret is required")

        scopes_raw = cfg.get("scopes") or ["openid", "profile", "email"]
        if isinstance(scopes_raw, str):
            scopes = [s.strip() for s in scopes_raw.split() if s.strip()]
        else:
            scopes = [str(s).strip() for s in scopes_raw if str(s).strip()]
        if "openid" not in scopes:
            scopes = ["openid", *scopes]

        return cls(
            discovery_url=discovery_url,
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            claim_username=str(cfg.get("claim_username") or "preferred_username"),
            claim_email=str(cfg.get("claim_email") or "email"),
            claim_display_name=str(cfg.get("claim_display_name") or "name"),
            claim_groups=str(cfg.get("claim_groups") or "groups"),
        )


# Module-level caches — keyed by provider id so invalidation can target a
# single provider after an admin saves new config.
_DISCOVERY_CACHE: dict[str, tuple[dict[str, Any], float]] = {}
_JWKS_CACHE: dict[str, tuple[dict[str, Any], float]] = {}


def invalidate_caches(provider_id: str) -> None:
    _DISCOVERY_CACHE.pop(provider_id, None)
    _JWKS_CACHE.pop(provider_id, None)


async def _fetch_discovery(cfg: OIDCConfig, provider_id: str) -> dict[str, Any]:
    cached = _DISCOVERY_CACHE.get(provider_id) if provider_id else None
    if cached and cached[1] > time.time():
        return cached[0]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(cfg.discovery_url)
            r.raise_for_status()
            doc = r.json()
    except httpx.HTTPError as exc:
        raise OIDCServiceError(f"discovery fetch failed: {exc}") from exc
    except ValueError as exc:
        raise OIDCServiceError(f"discovery response was not JSON: {exc}") from exc
    if provider_id:
        _DISCOVERY_CACHE[provider_id] = (doc, time.time() + 3600)
    return doc


async def _fetch_jwks(jwks_uri: str, provider_id: str) -> KeySetSerialization:
    cached = _JWKS_CACHE.get(provider_id) if provider_id else None
    if cached and cached[1] > time.time():
        return cast(KeySetSerialization, cached[0])
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(jwks_uri)
            r.raise_for_status()
            jwks = cast(KeySetSerialization, r.json())
    except httpx.HTTPError as exc:
        raise OIDCServiceError(f"JWKS fetch failed: {exc}") from exc
    if provider_id:
        _JWKS_CACHE[provider_id] = (jwks, time.time() + 3600)
    return jwks


async def build_authorize_url(
    cfg: OIDCConfig,
    provider_id: str,
    state: str,
    nonce: str,
    redirect_uri: str,
    *,
    reauth: bool = False,
) -> str:
    """The IdP's authorize URL. ``reauth`` is the MFA-enrolment step-up
    (#1354): ``prompt=login`` + ``max_age=0`` ask the IdP to authenticate the
    user again rather than reuse its session, and make ``auth_time`` a claim
    the ID token must carry (OIDC core 3.1.2.1)."""
    doc = await _fetch_discovery(cfg, provider_id)
    endpoint = doc.get("authorization_endpoint")
    if not endpoint:
        raise OIDCServiceError("discovery doc has no authorization_endpoint")
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(cfg.scopes),
        "state": state,
        "nonce": nonce,
    }
    if reauth:
        params["prompt"] = "login"
        params["max_age"] = "0"
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{urlencode(params)}"


async def exchange_code(
    cfg: OIDCConfig,
    provider_id: str,
    code: str,
    redirect_uri: str,
    expected_nonce: str,
    *,
    fresh_since: int | None = None,
) -> ExternalAuthResult:
    """Exchange an authorization code for tokens, validate the ID token, and
    return a normalised ``ExternalAuthResult``.

    ``fresh_since`` (epoch seconds) makes this the verification half of a
    step-up (#1354): the ID token must carry an ``auth_time`` no earlier than
    that instant (less :data:`AUTH_TIME_LEEWAY_SECONDS`) and not in the
    future. A token with no ``auth_time``, or a non-numeric one, is refused: an
    IdP that ignored ``prompt=login`` and replayed its old session proves
    nothing, and so does one that does not say when the user signed in."""
    doc = await _fetch_discovery(cfg, provider_id)
    token_endpoint = doc.get("token_endpoint")
    issuer = doc.get("issuer")
    jwks_uri = doc.get("jwks_uri")
    if not token_endpoint or not issuer or not jwks_uri:
        raise OIDCServiceError("discovery doc missing token/issuer/jwks fields")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": cfg.client_id,
                    "client_secret": cfg.client_secret,
                },
                headers={"Accept": "application/json"},
            )
            r.raise_for_status()
            tokens = r.json()
    except httpx.HTTPError as exc:
        raise OIDCServiceError(f"token exchange failed: {exc}") from exc
    except ValueError as exc:
        raise OIDCServiceError(f"token response was not JSON: {exc}") from exc

    id_token = tokens.get("id_token")
    if not id_token:
        raise OIDCServiceError("no id_token in token response")

    jwks = await _fetch_jwks(jwks_uri, provider_id)
    key_set = KeySet.import_key_set(jwks)
    try:
        token = jwt.decode(id_token, key_set)
        registry = JWTClaimsRegistry(
            iss={"essential": True, "value": issuer},
            aud={"essential": True, "value": cfg.client_id},
        )
        registry.validate(token.claims)
    except JoseError as exc:
        raise OIDCServiceError(f"ID token invalid: {exc}") from exc

    claims = token.claims

    if claims.get("nonce") != expected_nonce:
        raise OIDCServiceError("nonce mismatch")

    if fresh_since is not None:
        _require_fresh_auth_time(claims.get("auth_time"), fresh_since)

    # Merge in userinfo claims where missing (access_token is required).
    merged: dict[str, Any] = dict(claims)
    userinfo_endpoint = doc.get("userinfo_endpoint")
    access_token = tokens.get("access_token")
    if userinfo_endpoint and access_token:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if r.status_code == 200:
                    for k, v in r.json().items():
                        merged.setdefault(k, v)
        except (httpx.HTTPError, ValueError):
            pass  # userinfo is optional

    sub = merged.get("sub")
    if not sub:
        raise OIDCServiceError("ID token missing 'sub' claim")

    username_raw = merged.get(cfg.claim_username) or sub
    email = merged.get(cfg.claim_email)
    display_name = merged.get(cfg.claim_display_name)
    groups_raw = merged.get(cfg.claim_groups) or []
    if isinstance(groups_raw, str):
        groups = [groups_raw]
    else:
        groups = [str(g) for g in groups_raw]

    return ExternalAuthResult(
        external_id=str(sub),
        username=str(username_raw).strip(),
        email=str(email) if email else None,
        display_name=str(display_name) if display_name else None,
        groups=groups,
    )


async def probe_discovery(
    provider: AuthProvider,
) -> dict[str, Any]:
    """Admin "test connection" probe — returns a structured report."""
    try:
        cfg = OIDCConfig.from_provider(provider)
    except OIDCServiceError as exc:
        return {"ok": False, "message": str(exc), "details": {}}

    try:
        doc = await _fetch_discovery(cfg, str(provider.id))
    except OIDCServiceError as exc:
        return {"ok": False, "message": str(exc), "details": {}}

    return {
        "ok": True,
        "message": "discovery OK",
        "details": {
            "issuer": doc.get("issuer"),
            "authorization_endpoint": doc.get("authorization_endpoint"),
            "token_endpoint": doc.get("token_endpoint"),
            "userinfo_endpoint": doc.get("userinfo_endpoint"),
            "jwks_uri": doc.get("jwks_uri"),
            "scopes_supported": doc.get("scopes_supported") or [],
            "claims_supported": doc.get("claims_supported") or [],
            "response_types_supported": doc.get("response_types_supported") or [],
        },
    }

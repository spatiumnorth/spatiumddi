"""SAML 2.0 Service Provider helpers.

Uses ``python3-saml`` (OneLogin's toolkit) for XML signing + assertion
validation. Only the SP-side of the flow is implemented: AuthnRequest
generation (HTTP-Redirect binding) and ACS assertion consumption
(HTTP-POST binding).
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

import httpx
import structlog
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from app.core.auth.user_sync import ExternalAuthResult
from app.core.crypto import decrypt_dict
from app.models.auth_provider import AuthProvider

logger = structlog.get_logger(__name__)


class SAMLServiceError(Exception):
    """Raised on SAML configuration / network / validation failures."""


@dataclass
class SAMLConfig:
    # IdP
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: str | None
    idp_x509_cert: str
    # SP
    sp_entity_id: str
    sp_acs_url: str
    sp_slo_url: str
    sp_x509_cert: str | None  # optional — only needed for signed requests
    sp_private_key: str | None
    # Claim mapping (attribute names as sent by IdP)
    attr_username: str
    attr_email: str
    attr_display_name: str
    attr_groups: str
    # Optional metadata URL for auto-refreshing IdP config (not yet used)
    idp_metadata_url: str | None

    @classmethod
    def from_provider(cls, provider: AuthProvider, base_url: str) -> SAMLConfig:
        cfg = provider.config or {}
        secrets_data = (
            decrypt_dict(provider.secrets_encrypted) if provider.secrets_encrypted else {}
        )

        sp_entity_id = (
            str(cfg.get("sp_entity_id") or "").strip()
            or f"{base_url.rstrip('/')}/saml/{provider.id}"
        )
        sp_acs_url = f"{base_url.rstrip('/')}/api/v1/auth/{provider.id}/callback"
        sp_slo_url = f"{base_url.rstrip('/')}/api/v1/auth/{provider.id}/slo"

        idp_entity_id = str(cfg.get("idp_entity_id") or "").strip()
        idp_sso_url = str(cfg.get("idp_sso_url") or "").strip()
        idp_x509_cert = str(cfg.get("idp_x509_cert") or "").strip()
        if not idp_entity_id or not idp_sso_url or not idp_x509_cert:
            raise SAMLServiceError(
                "config.idp_entity_id, config.idp_sso_url, and config.idp_x509_cert are required"
            )

        return cls(
            idp_entity_id=idp_entity_id,
            idp_sso_url=idp_sso_url,
            idp_slo_url=str(cfg.get("idp_slo_url") or "").strip() or None,
            idp_x509_cert=idp_x509_cert,
            sp_entity_id=sp_entity_id,
            sp_acs_url=sp_acs_url,
            sp_slo_url=sp_slo_url,
            sp_x509_cert=str(cfg.get("sp_x509_cert") or "").strip() or None,
            sp_private_key=str(secrets_data.get("sp_private_key") or "").strip() or None,
            attr_username=str(cfg.get("attr_username") or "NameID"),
            attr_email=str(cfg.get("attr_email") or "email"),
            attr_display_name=str(cfg.get("attr_display_name") or "displayName"),
            attr_groups=str(cfg.get("attr_groups") or "groups"),
            idp_metadata_url=str(cfg.get("idp_metadata_url") or "").strip() or None,
        )


def _settings_dict(cfg: SAMLConfig) -> dict[str, Any]:
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": cfg.sp_entity_id,
            "assertionConsumerService": {
                "url": cfg.sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": cfg.sp_slo_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": cfg.sp_x509_cert or "",
            "privateKey": cfg.sp_private_key or "",
        },
        "idp": {
            "entityId": cfg.idp_entity_id,
            "singleSignOnService": {
                "url": cfg.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": cfg.idp_slo_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg.idp_x509_cert,
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
            "wantAttributeStatement": False,
        },
    }


def _request_data(host: str, path: str, query: str = "", post: dict | None = None) -> dict:
    """Shape the dict python3-saml expects from the request.

    ``host`` should include the scheme prefix (we pass this in explicitly so
    reverse-proxy headers don't break signature validation)."""
    is_https = host.startswith("https://")
    server_name = host.removeprefix("http://").removeprefix("https://").rstrip("/")
    # Strip a trailing port from the "server name" since python3-saml expects
    # it separately; but for our purposes passing it all in server_name is
    # safer because proxy / dev environments vary.
    return {
        "https": "on" if is_https else "off",
        "http_host": server_name,
        "server_port": "443" if is_https else "80",
        "script_name": path,
        "get_data": {},
        "post_data": post or {},
        "query_string": query,
    }


def build_authorize_url(cfg: SAMLConfig, base_url: str, relay_state: str) -> str:
    """Returns the IdP's SSO URL (HTTP-Redirect binding) with a SAMLRequest
    parameter. ``relay_state`` is the CSRF-like token we round-trip."""
    settings = OneLogin_Saml2_Settings(_settings_dict(cfg), sp_validation_only=False)
    saml_auth = OneLogin_Saml2_Auth(
        _request_data(base_url, "/api/v1/auth/authorize"), old_settings=settings
    )
    return saml_auth.login(return_to=relay_state)


@dataclass
class SAMLConsumeResult:
    result: ExternalAuthResult
    relay_state: str | None
    attributes: dict[str, Any]


def consume_assertion(cfg: SAMLConfig, base_url: str, post_data: dict) -> SAMLConsumeResult:
    """Validate a signed SAML Response and extract claims.

    ``post_data`` is the form body from the ACS POST (``SAMLResponse`` +
    optional ``RelayState``).
    """
    settings = OneLogin_Saml2_Settings(_settings_dict(cfg), sp_validation_only=False)
    saml_auth = OneLogin_Saml2_Auth(
        _request_data(base_url, "/api/v1/auth/acs", post=post_data),
        old_settings=settings,
    )
    saml_auth.process_response()

    errors = saml_auth.get_errors()
    if errors:
        reason = saml_auth.get_last_error_reason() or ", ".join(errors)
        raise SAMLServiceError(f"SAML response rejected: {reason}")
    if not saml_auth.is_authenticated():
        raise SAMLServiceError("SAML response did not authenticate the user")

    attrs = saml_auth.get_attributes() or {}
    name_id = saml_auth.get_nameid() or ""
    # The NameID is the account's key at this provider (#1235), and a
    # transient one is new on every sign-in: the first would create an
    # account that every later sign-in is refused, as its username is taken
    # and an account is never adopted by username. Refuse it up front, with
    # the setting that fixes it.
    if saml_auth.get_nameid_format() == OneLogin_Saml2_Constants.NAMEID_TRANSIENT:
        raise SAMLServiceError(
            "the IdP sent a transient NameID, which changes on every sign-in and "
            "cannot identify an account; configure it to release a persistent or "
            "emailAddress NameID"
        )
    session_index = saml_auth.get_session_index() or ""

    def _first(name: str) -> str | None:
        val = attrs.get(name)
        if val is None:
            return None
        if isinstance(val, list):
            return str(val[0]) if val else None
        return str(val)

    def _all(name: str) -> list[str]:
        val = attrs.get(name)
        if val is None:
            return []
        if isinstance(val, list):
            return [str(v) for v in val]
        return [str(val)]

    # NameID usually acts as username + external_id simultaneously; when the
    # IdP ships an explicit attribute we prefer it for username.
    username = _first(cfg.attr_username) or name_id
    email = _first(cfg.attr_email)
    display_name = _first(cfg.attr_display_name)
    groups = _all(cfg.attr_groups)

    external_id = name_id or username
    return SAMLConsumeResult(
        result=ExternalAuthResult(
            external_id=str(external_id),
            username=str(username).strip(),
            email=email,
            display_name=display_name,
            groups=groups,
        ),
        relay_state=post_data.get("RelayState"),
        attributes={
            "name_id": name_id,
            "session_index": session_index,
            "raw": attrs,
        },
    )


def sp_metadata_xml(cfg: SAMLConfig) -> str:
    settings = OneLogin_Saml2_Settings(_settings_dict(cfg), sp_validation_only=True)
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if errors:
        raise SAMLServiceError(f"SP metadata invalid: {errors}")
    return metadata.decode() if isinstance(metadata, bytes) else metadata


async def probe_metadata(provider: AuthProvider, base_url: str) -> dict[str, Any]:
    """Admin "test" probe: fetch and parse the IdP metadata URL (if given)
    and report what we discovered."""
    cfg_src = provider.config or {}
    metadata_url = str(cfg_src.get("idp_metadata_url") or "").strip()

    if metadata_url:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(metadata_url)
                r.raise_for_status()
                xml = r.text
        except httpx.HTTPError as exc:
            return {"ok": False, "message": f"metadata fetch failed: {exc}", "details": {}}

        try:
            parsed = OneLogin_Saml2_IdPMetadataParser.parse(xml)
        except Exception as exc:  # noqa: BLE001 — python3-saml raises plain Exception
            return {
                "ok": False,
                "message": f"metadata parse failed: {exc}",
                "details": {},
            }

        idp = (parsed or {}).get("idp") or {}
        sso = idp.get("singleSignOnService") or {}
        slo = idp.get("singleLogoutService") or {}
        return {
            "ok": True,
            "message": "metadata OK",
            "details": {
                "idp_entity_id": idp.get("entityId"),
                "idp_sso_url": sso.get("url") if isinstance(sso, dict) else None,
                "idp_slo_url": slo.get("url") if isinstance(slo, dict) else None,
                "idp_cert_fingerprint_prefix": (idp.get("x509cert") or "")[:60],
            },
        }

    # No metadata URL — validate the manually-entered IdP fields.
    try:
        cfg = SAMLConfig.from_provider(provider, base_url)
    except SAMLServiceError as exc:
        return {"ok": False, "message": str(exc), "details": {}}
    # Try to instantiate settings — catches malformed certs etc.
    try:
        OneLogin_Saml2_Settings(_settings_dict(cfg), sp_validation_only=False)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": f"settings invalid: {exc}", "details": {}}
    return {
        "ok": True,
        "message": "manual config parses",
        "details": {
            "idp_entity_id": cfg.idp_entity_id,
            "idp_sso_url": cfg.idp_sso_url,
            "sp_acs_url": cfg.sp_acs_url,
            "sp_entity_id": cfg.sp_entity_id,
        },
    }


def decode_saml_response_for_debug(raw: str) -> str:
    """Helper for test scaffolding: decode base64 SAMLResponse form value."""
    return base64.b64decode(raw).decode("utf-8", errors="replace")


def now_ts() -> int:
    return int(time.time())

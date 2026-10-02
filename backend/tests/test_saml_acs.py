"""SAML sign-in through the ACS the service provider advertises (#1335).

The SP names one Assertion Consumer Service per provider,
``POST /api/v1/auth/{provider_id}/callback``, in its metadata and in every
AuthnRequest's ``AssertionConsumerServiceURL``. A conforming IdP addresses its
Response there: the Response's ``Destination`` and the bearer
``SubjectConfirmationData`` ``Recipient`` both carry that URL, and the SP must
check both against the ACS the Response was delivered to (SAML bindings
3.5.5.2, profiles 4.1.4.3 and 4.1.4.5). python3-saml does that in strict mode,
against the URL it is told the Response arrived at.

These tests drive the whole flow: the metadata, the authorize redirect, and the
IdP's POST of a Response signed with a throwaway IdP key, so the strict checks
run for real. #873's tests only ever post a bogus ``SAMLResponse``.
"""

from __future__ import annotations

import base64
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import AsyncClient, Response
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import Group, User
from app.models.auth_provider import AuthGroupMapping, AuthProvider
from app.models.settings import PlatformSettings

pytestmark = pytest.mark.asyncio

BASE_URL = "https://ddi.example.com"
IDP_ENTITY_ID = "https://idp.example.com/entity"
NAME_ID = "alice@example.com"


def _idp_signing_pair() -> tuple[str, str]:
    """A throwaway RSA key, and the self-signed certificate the IdP signs with."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example.com")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode()


IDP_KEY, IDP_CERT = _idp_signing_pair()

_ASSERTION = (
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    ' ID="{assertion_id}" Version="2.0" IssueInstant="{now}">'
    "<saml:Issuer>{issuer}</saml:Issuer>"
    "<saml:Subject>"
    '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
    "{name_id}</saml:NameID>"
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    '<saml:SubjectConfirmationData InResponseTo="{in_response_to}"'
    ' NotOnOrAfter="{later}" Recipient="{destination}"/>'
    "</saml:SubjectConfirmation>"
    "</saml:Subject>"
    '<saml:Conditions NotBefore="{earlier}" NotOnOrAfter="{later}">'
    "<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>"
    "</saml:AudienceRestriction>"
    "</saml:Conditions>"
    '<saml:AuthnStatement AuthnInstant="{now}" SessionIndex="{session_index}">'
    "<saml:AuthnContext><saml:AuthnContextClassRef>"
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    "</saml:AuthnContextClassRef></saml:AuthnContext>"
    "</saml:AuthnStatement>"
    "<saml:AttributeStatement>"
    '<saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue>'
    "</saml:Attribute>"
    "</saml:AttributeStatement>"
    "</saml:Assertion>"
)

_RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    ' ID="{response_id}" Version="2.0" IssueInstant="{now}"'
    ' Destination="{destination}" InResponseTo="{in_response_to}">'
    "<saml:Issuer>{issuer}</saml:Issuer>"
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
    "</samlp:Status>"
    "{assertion}"
    "</samlp:Response>"
)


def _signed_response(*, destination: str, in_response_to: str, audience: str) -> str:
    """The form value an IdP posts: a Response whose Assertion is signed
    RSA-SHA256 with the IdP's key, its ``Destination`` and ``Recipient`` both
    ``destination``."""
    now = datetime.now(UTC)
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    fields = {
        "issuer": IDP_ENTITY_ID,
        "name_id": NAME_ID,
        "destination": destination,
        "in_response_to": in_response_to,
        "audience": audience,
        "now": now.strftime(stamp),
        "earlier": (now - timedelta(minutes=1)).strftime(stamp),
        "later": (now + timedelta(minutes=5)).strftime(stamp),
    }
    assertion = OneLogin_Saml2_Utils.add_sign(
        _ASSERTION.format(
            assertion_id=OneLogin_Saml2_Utils.generate_unique_id(),
            session_index=OneLogin_Saml2_Utils.generate_unique_id(),
            **fields,
        ),
        IDP_KEY,
        IDP_CERT,
    )
    response = _RESPONSE.format(
        response_id=OneLogin_Saml2_Utils.generate_unique_id(),
        assertion=assertion.decode(),
        **fields,
    )
    return base64.b64encode(response.encode()).decode()


async def _saml_provider(db: AsyncSession, base_url: str = BASE_URL) -> tuple[AuthProvider, Group]:
    """An enabled SAML provider that trusts ``IDP_CERT``, maps the IdP's
    ``staff`` group to the returned group, and creates accounts, on a
    deployment whose external URL is ``base_url``."""
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    provider = AuthProvider(
        name=f"saml-{uuid.uuid4().hex[:6]}",
        type="saml",
        is_enabled=True,
        config={
            "idp_entity_id": IDP_ENTITY_ID,
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_x509_cert": IDP_CERT,
        },
        auto_create_users=True,
    )
    db.add_all([group, provider])
    await db.flush()
    db.add(
        AuthGroupMapping(
            provider_id=provider.id, external_group="staff", internal_group_id=group.id
        )
    )
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.app_base_url = base_url
    await db.commit()
    return provider, group


async def _start_sign_in(client: AsyncClient, provider: AuthProvider) -> dict[str, str]:
    """What the SP tells the IdP (its metadata, the AuthnRequest), and what the
    browser carries back to the ACS (``RelayState`` and the flow cookie)."""
    metadata = await client.get(f"/api/v1/auth/{provider.id}/metadata")
    assert metadata.status_code == 200, metadata.text
    descriptor = OneLogin_Saml2_XML.to_etree(metadata.content)

    resp = await client.get(f"/api/v1/auth/{provider.id}/authorize")
    assert resp.status_code == 302, resp.text
    query = parse_qs(urlsplit(resp.headers["location"]).query)
    request = OneLogin_Saml2_XML.to_etree(
        OneLogin_Saml2_Utils.decode_base64_and_inflate(query["SAMLRequest"][0])
    )
    cookie = next(
        v.split(";", 1)[0]
        for k, v in resp.headers.multi_items()
        if k.lower() == "set-cookie" and v.startswith("saml_flow=")
    )
    return {
        "metadata_acs": OneLogin_Saml2_XML.query(
            descriptor, "//md:AssertionConsumerService/@Location"
        )[0],
        "sp_entity_id": descriptor.get("entityID"),
        "request_acs": request.get("AssertionConsumerServiceURL"),
        "request_id": request.get("ID"),
        "relay_state": query["RelayState"][0],
        "cookie": cookie,
    }


async def _idp_posts(
    client: AsyncClient, provider: AuthProvider, flow: dict[str, str], *, destination: str
) -> Response:
    """The browser delivering the IdP's Response to the provider's ACS."""
    return await client.post(
        f"/api/v1/auth/{provider.id}/callback",
        data={
            "SAMLResponse": _signed_response(
                destination=destination,
                in_response_to=flow["request_id"],
                audience=flow["sp_entity_id"],
            ),
            "RelayState": flow["relay_state"],
        },
        # The flow cookie is ``Secure`` behind an HTTPS base URL, so this
        # client's plain-HTTP cookie jar would hold it back; a browser sends it.
        headers={"Cookie": flow["cookie"]},
    )


async def _rejection(db: AsyncSession, provider: AuthProvider) -> object:
    """Why the SP refused the Response, as its audit row records it."""
    row = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.resource_id == str(provider.id), AuditLog.result == "error")
                .order_by(AuditLog.seq.desc())
            )
        )
        .scalars()
        .first()
    )
    return row.new_value if row is not None else None


@pytest.mark.parametrize(
    "base_url",
    [
        pytest.param(BASE_URL, id="https"),
        pytest.param("https://ddi.example.com:8443", id="https-port"),
        pytest.param("https://example.com/ddi", id="path-prefix"),
        pytest.param("http://10.0.0.5:8080", id="http-port"),
        pytest.param("http://[fd00::5]:8080", id="ipv6"),
    ],
)
async def test_a_response_addressed_to_the_advertised_acs_signs_the_user_in(
    client: AsyncClient, db_session: AsyncSession, base_url: str
) -> None:
    provider, group = await _saml_provider(db_session, base_url)
    flow = await _start_sign_in(client, provider)
    acs = f"{base_url}/api/v1/auth/{provider.id}/callback"
    # The one ACS the SP advertises, in both places an IdP reads it from.
    assert flow["metadata_acs"] == acs
    assert flow["request_acs"] == acs

    resp = await _idp_posts(client, provider, flow, destination=acs)

    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith("/login/callback#access_token="), (
        location,
        await _rejection(db_session, provider),
    )
    user = (
        await db_session.execute(
            select(User).where(User.auth_source == "saml", User.external_id == NAME_ID)
        )
    ).scalar_one()
    assert user.username == NAME_ID
    assert [g.id for g in await user.awaitable_attrs.groups] == [group.id]


@pytest.mark.parametrize(
    "path",
    [
        # Where the SP used to tell python3-saml every Response arrived: a
        # URL it neither advertises nor routes (a POST there is a 404).
        pytest.param("/api/v1/auth/acs", id="unadvertised-acs"),
        pytest.param(
            "/api/v1/auth/00000000-0000-4000-8000-000000000001/callback",
            id="another-providers-acs",
        ),
    ],
)
async def test_a_response_addressed_to_any_other_url_is_refused(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    """Strict validation stays on: the ``Destination`` and ``Recipient`` must
    name the ACS the Response was delivered to."""
    provider, _ = await _saml_provider(db_session)
    flow = await _start_sign_in(client, provider)
    acs = f"{BASE_URL}/api/v1/auth/{provider.id}/callback"

    resp = await _idp_posts(client, provider, flow, destination=f"{BASE_URL}{path}")

    assert resp.status_code == 302, resp.text
    assert resp.headers["location"] == "/login?error=saml_assertion_rejected"
    rejection = await _rejection(db_session, provider)
    assert isinstance(rejection, dict), rejection
    assert rejection["reason"] == "saml_rejected"
    assert f"The response was received at {acs} instead of {BASE_URL}{path}" in (
        rejection["detail"]
    )
    users = await db_session.execute(select(User).where(User.auth_source == "saml"))
    assert users.scalars().all() == []

"""Every endpoint the SAML service provider's metadata advertises is served (#1420).

``GET /api/v1/auth/{provider_id}/metadata`` is what an administrator registers
at the IdP, and the IdP sends each message to the endpoint the metadata names,
on the binding it names. The metadata advertised a ``SingleLogoutService`` at
``/api/v1/auth/{provider_id}/slo`` (HTTP-Redirect) that no route serves: an IdP
configured from it sent its LogoutRequests to a 404, reported a partial logout,
and the SpatiumDDI session outlived the user's IdP logout. SpatiumDDI does not
take part in SAML single logout, so its metadata must not offer it, and the
Assertion Consumer Service it does serve stays advertised.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from httpx import AsyncClient
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_saml_acs import BASE_URL, _saml_provider

pytestmark = pytest.mark.asyncio

_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


async def _advertised_endpoints(
    client: AsyncClient, provider_id: object
) -> list[tuple[str, str, str]]:
    """``(element, binding, location)`` for every endpoint in the SP metadata."""
    metadata = await client.get(f"/api/v1/auth/{provider_id}/metadata")
    assert metadata.status_code == 200, metadata.text
    descriptor = OneLogin_Saml2_XML.to_etree(metadata.content)
    return [
        (el.tag.rsplit("}", 1)[-1], el.get("Binding") or "", el.get("Location") or "")
        for el in OneLogin_Saml2_XML.query(descriptor, "//md:SPSSODescriptor/*[@Location]")
    ]


async def test_every_endpoint_the_sp_metadata_advertises_answers_on_its_binding(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    provider, _ = await _saml_provider(db_session)
    endpoints = await _advertised_endpoints(client, provider.id)

    # Positive control: the metadata advertises the ACS the SP serves, so a
    # metadata with no endpoints at all cannot pass.
    assert (
        "AssertionConsumerService",
        _HTTP_POST,
        f"{BASE_URL}/api/v1/auth/{provider.id}/callback",
    ) in endpoints, endpoints

    unserved = []
    for element, binding, location in endpoints:
        assert location.startswith(f"{BASE_URL}/"), (element, location)
        path = urlsplit(location).path
        if binding == _HTTP_POST:
            resp = await client.post(path, data={})
        elif binding == _HTTP_REDIRECT:
            resp = await client.get(path)
        else:
            unserved.append(f"{element} {location}: binding {binding!r} is not one the SP serves")
            continue
        # Any answer but "no such route" is served: the empty message is
        # refused, but by the endpoint the metadata names.
        if resp.status_code in (404, 405):
            unserved.append(f"{element} {binding.rsplit(':', 1)[-1]} {path} -> {resp.status_code}")
    assert not unserved, (
        "The SP metadata advertises endpoints no route serves, so an IdP configured "
        "from it sends those messages to nothing: " + "; ".join(unserved)
    )

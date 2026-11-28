"""A DHCP reservation request's preview names the scope's subnet network only
to a user who can read that subnet.

The scope is the resource the requester names and reads; its subnet is a
parent they may not read, so the refusal and the stored preview text word
themselves without the network for them and keep it for a subnet reader.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_portal_submit_refusals_2903 import _submit
from tests.test_self_service_requests import (
    BARE_REQUESTER_PERMS,
    MODULE,
    REQUESTER_PERMS,
    _enable_module,
    _user,
)

SCOPE_ONLY_PERMS = [*BARE_REQUESTER_PERMS, {"action": "read", "resource_type": "dhcp_scope"}]
NETWORK = "10.60.0.0/24"


async def _token(db: AsyncSession, perms: list[dict]) -> str:
    await _enable_module(db, MODULE)
    _, token = await _user(db, name="req", permissions=perms)
    return token


def _args(scope: DHCPScope, ip: str) -> dict:
    return {"scope_id": str(scope.id), "ip_address": ip, "mac_address": "aa:bb:cc:dd:ee:01"}


@pytest.mark.asyncio
async def test_out_of_subnet_refusal_omits_network_without_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _token(db_session, SCOPE_ONLY_PERMS)
    scope, _, _ = await _estate(db_session)
    resp = await _submit(client, tok, "dhcp_reservation", _args(scope, "192.0.2.250"))
    assert resp.status_code == 400, resp.text
    assert NETWORK not in resp.text
    assert "outside the scope's subnet" in resp.text


@pytest.mark.asyncio
async def test_out_of_subnet_refusal_names_network_with_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _token(db_session, REQUESTER_PERMS)
    scope, _, _ = await _estate(db_session)
    resp = await _submit(client, tok, "dhcp_reservation", _args(scope, "192.0.2.250"))
    assert resp.status_code == 400, resp.text
    assert NETWORK in resp.text


@pytest.mark.asyncio
async def test_unnamed_scope_summary_omits_network_without_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _token(db_session, SCOPE_ONLY_PERMS)
    scope, _, _ = await _estate(db_session)
    scope.name = ""
    await db_session.flush()
    resp = await _submit(client, tok, "dhcp_reservation", _args(scope, "10.60.0.50"))
    assert resp.status_code == 201, resp.text
    assert NETWORK not in resp.text
    assert str(scope.id) in resp.json()["preview_text"]


@pytest.mark.asyncio
async def test_unnamed_scope_summary_names_network_with_subnet_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _token(db_session, REQUESTER_PERMS)
    scope, _, _ = await _estate(db_session)
    scope.name = ""
    await db_session.flush()
    resp = await _submit(client, tok, "dhcp_reservation", _args(scope, "10.60.0.50"))
    assert resp.status_code == 201, resp.text
    assert NETWORK in resp.json()["preview_text"]

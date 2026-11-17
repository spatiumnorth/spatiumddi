"""#3614 — a list payload naming one option twice is a 422, not a silent last-wins."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServerGroup
from app.services.dhcp.option_validation import normalize_options
from tests.test_dhcp_scope_options_roundtrip import _create, _make_token, _subnet_and_group

DUP_CODE = [
    {"code": 6, "value": ["10.0.0.1"]},
    {"code": 6, "value": ["10.0.0.2"]},
]
DUP_NAME_CODE = [
    {"name": "dns-servers", "code": 6, "value": ["10.0.0.1"]},
    {"code": 6, "name": "custom", "value": ["10.0.0.2"]},
]
DISTINCT = [
    {"code": 6, "name": "dns-servers", "value": ["10.0.0.1"]},
    {"code": 15, "name": "domain-name", "value": "example.com"},
]


def test_duplicate_by_code_raises() -> None:
    with pytest.raises(ValueError, match="dns-servers.*more than once"):
        normalize_options(DUP_CODE)


def test_duplicate_by_name_and_code_raises() -> None:
    with pytest.raises(ValueError) as e:
        normalize_options(DUP_NAME_CODE)
    msg = str(e.value)
    assert "dns-servers" in msg and "10.0.0.1" in msg and "10.0.0.2" in msg


def test_distinct_keys_and_dicts_accepted() -> None:
    assert set(normalize_options(DISTINCT)) == {"dns-servers", "domain-name"}
    assert normalize_options({"dns-servers": ["10.0.0.1"], "domain-name-servers": ["10.0.0.2"]})


@pytest.mark.asyncio
async def test_scope_create_and_update_422(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _make_token(db_session)
    subnet, grp = await _subnet_and_group(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=h,
        json={"group_id": str(grp.id), "name": "s", "options": DUP_NAME_CODE},
    )
    assert r.status_code == 422, r.text
    assert "dns-servers" in r.text

    body = await _create(client, h, subnet, grp, options=DISTINCT)
    r = await client.put(f"/api/v1/dhcp/scopes/{body['id']}", headers=h, json={"options": DUP_CODE})
    assert r.status_code == 422, r.text


@pytest.mark.asyncio
async def test_option_template_422(client: AsyncClient, db_session: AsyncSession) -> None:
    token = await _make_token(db_session)
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}
    url = f"/api/v1/dhcp/server-groups/{grp.id}/option-templates"

    r = await client.post(url, headers=h, json={"name": "t", "options": DUP_CODE})
    assert r.status_code == 422, r.text

    r = await client.post(url, headers=h, json={"name": "t", "options": DISTINCT})
    assert r.status_code == 201, r.text
    r = await client.put(
        f"/api/v1/dhcp/option-templates/{r.json()['id']}", headers=h, json={"options": DUP_CODE}
    )
    assert r.status_code == 422, r.text

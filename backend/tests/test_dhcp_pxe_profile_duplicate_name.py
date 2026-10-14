"""A duplicate PXE profile name answers 409, not 500 (#1911).

The name-clash check selected the whole ``DHCPPXEProfile``, whose ``matches``
collection is ``lazy="joined"``; ``scalar_one_or_none()`` on a joined-collection
result raises ``InvalidRequestError`` the moment a row exists, so the route's
own 409 was unreachable.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServerGroup
from tests.test_dhcp_pxe_vendor_match_validation import _headers, _match


async def _group(db: AsyncSession) -> DHCPServerGroup:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.commit()
    return grp


def _body(name: str, with_match: bool) -> dict:
    body: dict = {"name": name, "next_server": "10.0.0.5"}
    if with_match:
        body["matches"] = [_match("PXEClient")]
    return body


async def test_create_with_a_taken_name_is_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session)
    url = f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles"
    for with_match in (False, True):
        name = f"boot-{with_match}"
        assert (await client.post(url, headers=h, json=_body(name, with_match))).status_code == 201
        resp = await client.post(url, headers=h, json=_body(name, with_match))
        assert resp.status_code == 409, resp.text
        assert "exists" in resp.json()["detail"]


async def test_rename_onto_a_taken_name_is_409(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session)
    url = f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles"
    await client.post(url, headers=h, json=_body("a", True))
    resp = await client.post(url, headers=h, json=_body("b", False))
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{resp.json()['id']}", headers=h, json={"name": "a"}
    )
    assert resp.status_code == 409, resp.text


async def test_same_name_in_another_group_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    g1, g2 = await _group(db_session), await _group(db_session)
    for g in (g1, g2):
        resp = await client.post(
            f"/api/v1/dhcp/server-groups/{g.id}/pxe-profiles", headers=h, json=_body("x", True)
        )
        assert resp.status_code == 201, resp.text


async def test_sibling_dhcp_families_answer_409_on_a_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Client classes and server groups share the check shape; keep them 409."""
    h = await _headers(db_session)
    grp = await _group(db_session)
    url = f"/api/v1/dhcp/server-groups/{grp.id}/client-classes"
    body = {"name": "cc1", "match_expression": "option[60].text == 'x'"}
    assert (await client.post(url, headers=h, json=body)).status_code == 201
    assert (await client.post(url, headers=h, json=body)).status_code == 409
    resp = await client.post("/api/v1/dhcp/server-groups", headers=h, json={"name": grp.name})
    assert resp.status_code == 409, resp.text

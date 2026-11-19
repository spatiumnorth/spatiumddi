"""The DHCP importer never creates a client class under a reserved name.

``reserved_name_reason`` already guards the client-class API: an operator
class called ``DROP`` would replace the MAC blocklist class, and a Kea-owned
name makes Kea reject the whole config. The importer is a second way in, and
its commit takes the preview from the request body, so the check sits at
commit as well as in the parsers.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPClientClass
from app.services.dhcp_import import parse_isc_config, parse_kea_config
from tests.test_dhcp_import import _kea_preview, _make_admin, _make_block, _make_group, _make_space

_KEA_RESERVED = b"""
{ "Dhcp4": {
    "subnet4": [ { "subnet": "192.0.2.0/24" } ],
    "client-classes": [
      { "name": "drop", "test": "option[60].exists" },
      { "name": "HA_server1" },
      { "name": "voip", "test": "option[60].exists" }
    ]
} }
"""


def test_kea_parser_marks_reserved_names_unsupported() -> None:
    p = parse_kea_config(_KEA_RESERVED)
    by_name = {c.name: c for c in p.client_classes}
    assert by_name["voip"].supported is True
    for name in ("drop", "HA_server1"):
        assert by_name[name].supported is False
        assert by_name[name].warning and "Not imported" in by_name[name].warning


def test_isc_parser_says_why_a_reserved_class_is_not_imported() -> None:
    p = parse_isc_config(
        b"subnet 10.5.5.0 netmask 255.255.255.0 { range 10.5.5.10 10.5.5.20; }\n"
        b'class "DROP" { match if substring(option vendor-class-identifier,0,3) = "bad"; }\n'
    )
    (cc,) = p.client_classes
    assert cc.supported is False
    assert cc.warning and "built-in" in cc.warning


@pytest.mark.asyncio
async def test_commit_refuses_reserved_names_from_the_request_body(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _make_admin(db_session)
    group = await _make_group(db_session)
    space = await _make_space(db_session)
    block = await _make_block(db_session, space, "192.0.2.0/24")
    await db_session.commit()

    preview = (await _kea_preview(client, token, str(group.id), str(space.id))).json()
    template = preview["client_classes"][0]
    # A plan edited on the way back: reserved names, flagged supported.
    preview["client_classes"] = [
        {**template, "name": name, "supported": True, "warning": None}
        for name in ("DROP", "drop", "HA_x", "spatium-device-x", "voip")
    ]
    resp = await client.post(
        "/api/v1/dhcp/import/kea/commit",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target_group_id": str(group.id),
            "ipam_space_id": str(space.id),
            "ipam_block_id": str(block.id),
            "plan": preview,
            "conflict_actions": {},
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["client_classes_created"] == 1
    names = (
        (
            await db_session.execute(
                select(DHCPClientClass.name).where(DHCPClientClass.group_id == group.id)
            )
        )
        .scalars()
        .all()
    )
    assert list(names) == ["voip"]
    for name in ("DROP", "drop", "HA_x", "spatium-device-x"):
        assert any(f"'{name}' was not imported" in w for w in body["warnings"]), body["warnings"]

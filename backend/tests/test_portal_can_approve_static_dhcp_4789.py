"""An IP request for a ``static_dhcp`` address needs reservation write to approve (#4789).

Its apply makes a DHCP reservation and refuses an approver without write on
``dhcp_static`` with #3646's 403, so the row's ``can_approve`` must ask it too.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.test_portal_can_approve_target_4382 import _row
from tests.test_portal_dhcp_static_ipam_mirror_2901 import _estate
from tests.test_portal_submit_refusals_2903 import _requester, _submit
from tests.test_self_service_requests import _auth, _user

BASE = [
    {"action": "approve", "resource_type": "change_request"},
    {"action": "read", "resource_type": "change_request"},
    {"action": "write", "resource_type": "subnet"},
    {"action": "read", "resource_type": "subnet"},
    {"action": "write", "resource_type": "ip_address"},
    {"action": "read", "resource_type": "ip_address"},
]


@pytest.mark.asyncio
async def test_static_dhcp_row_needs_reservation_write(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    tok = await _requester(db_session)
    _, subnet, _ = await _estate(db_session)
    subnet_id = subnet.id
    _, plain = await _user(db_session, name="plain", permissions=BASE)
    _, resv = await _user(
        db_session,
        name="resv",
        permissions=BASE
        + [
            {"action": "write", "resource_type": "dhcp_static"},
            {"action": "read", "resource_type": "dhcp_static"},
        ],
    )
    ids = {}
    for name, extra in (
        ("static", {"status": "static_dhcp", "mac_address": "02:00:5e:20:11:41"}),
        ("alloc", {}),
    ):
        last = "41" if name == "static" else "42"
        sub = await _submit(
            client,
            tok,
            "ip_address",
            {"subnet_id": str(subnet_id), "address": f"10.60.0.{last}", **extra},
        )
        assert sub.status_code == 201, sub.text
        ids[name] = sub.json()["id"]

    row = await _row(client, plain, ids["static"])
    assert row["can_approve"] is False
    assert "dhcp_static" in row["approve_blocked_reason"]
    r = await client.post(
        f"/api/v1/requests/{ids['static']}/approve", headers=_auth(plain), json={}
    )
    assert r.status_code == 403
    assert r.json()["detail"] == row["approve_blocked_reason"]
    assert (await _row(client, plain, ids["alloc"]))["can_approve"] is True

    assert (await _row(client, resv, ids["static"]))["can_approve"] is True

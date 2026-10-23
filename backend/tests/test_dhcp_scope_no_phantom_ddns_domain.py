"""#784 — the scope surface must not advertise a DDNS domain it cannot keep.

``ScopeResponse`` declared ``ddns_domain_override`` and ``_scope_to_response``
hardcoded it to ``None``. No column backed it, neither ``ScopeCreate`` nor
``ScopeUpdate`` declared it (so ``extra="ignore"`` dropped it from the body
without a word), and the scope form sent it on every save. An operator typed a
domain, got a 200, re-opened the scope, and found the field empty — with no
error anywhere in between.

It was removed rather than implemented. The DDNS domain is real one level up:
``services/dns/ddns.resolve_effective_ddns`` walks subnet → block → space and
reads ``ddns_domain_override`` there. A DHCP scope maps 1:1 to a subnet, so a
scope-level copy would be a second source of truth for one setting rather than
new capability.

These tests pin both halves of "removed": the response does not offer the
field, and a client still sending it (the old form, a saved script) is not
broken by it — the write succeeds and the value is simply not persisted
anywhere, which is what it always did.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet

pytestmark = pytest.mark.asyncio

CIDR = "198.51.100.0/24"


async def _setup(client: AsyncClient, db: AsyncSession) -> tuple[dict[str, str], dict]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=CIDR, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="s")
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, grp])
    await db.flush()
    await db.commit()

    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    resp = await client.post(
        f"/api/v1/dhcp/subnets/{subnet.id}/dhcp-scopes",
        headers=headers,
        json={"group_id": str(grp.id), "name": "s"},
    )
    assert resp.status_code in (200, 201), resp.text
    return headers, resp.json()


async def test_scope_response_does_not_advertise_a_ddns_domain(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers, scope = await _setup(client, db_session)

    assert "ddns_domain_override" not in scope

    fetched = (await client.get(f"/api/v1/dhcp/scopes/{scope['id']}", headers=headers)).json()
    assert "ddns_domain_override" not in fetched


async def test_a_client_still_sending_the_old_field_is_not_broken(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The old scope form, or any saved script, keeps working.

    The field was never accepted on write, so ignoring it is not a behaviour
    change — this only pins that removing it from the RESPONSE did not turn a
    previously-tolerated body into a 422.
    """
    headers, scope = await _setup(client, db_session)

    resp = await client.put(
        f"/api/v1/dhcp/scopes/{scope['id']}",
        headers=headers,
        json={"name": "renamed", "ddns_domain_override": "example.com"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "renamed"
    assert "ddns_domain_override" not in resp.json()


async def test_read_modify_write_of_a_fetched_scope_still_round_trips(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # GET → edit → PUT is the shape that exposed the original bug, and it is
    # also the shape most likely to break when a response field is removed.
    headers, scope = await _setup(client, db_session)

    current = (await client.get(f"/api/v1/dhcp/scopes/{scope['id']}", headers=headers)).json()
    current["name"] = "round-tripped"
    current.pop("is_active", None)

    resp = await client.put(f"/api/v1/dhcp/scopes/{scope['id']}", headers=headers, json=current)

    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "round-tripped"

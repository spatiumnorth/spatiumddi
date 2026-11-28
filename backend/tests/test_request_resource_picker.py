"""#759 — portal resource-reference fields become permission-filtered pickers.

The submit path deliberately does not require the underlying operation's
permission, so the picker endpoint is the one surface that could hand a
low-privilege Requester the whole estate inventory. These tests pin the
acceptance criterion: the options list contains ONLY rows the caller holds a
``read`` grant for — plus the schema annotation contract the form renders
from.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.dns import DNSServerGroup, DNSZone
from app.models.feature_module import FeatureModule
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services import feature_modules

MODULE = "governance.requests"

REQUESTER_PERMS = [
    {"action": "write", "resource_type": "provisioning_request"},
    {"action": "read", "resource_type": "provisioning_request"},
]


async def _user(
    db: AsyncSession, *, permissions: list[dict] | None = None, superadmin: bool = False
) -> tuple[User, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"u-{uuid.uuid4().hex[:8]}@t.io",
        display_name="u",
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    user.groups = []
    if permissions:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=permissions)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _enable_module(db: AsyncSession) -> None:
    existing = await db.get(FeatureModule, MODULE)
    if existing is None:
        db.add(FeatureModule(id=MODULE, enabled=True))
    else:
        existing.enabled = True
    await db.flush()
    feature_modules.invalidate_cache()


async def _subnets(db: AsyncSession, cidrs: list[str]) -> list[Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db.add(block)
    await db.flush()
    subs = []
    for i, cidr in enumerate(cidrs):
        sub = Subnet(space_id=space.id, block_id=block.id, network=cidr, name=f"net-{i}")
        db.add(sub)
        subs.append(sub)
    await db.flush()
    return subs


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── Schema annotation contract ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_catalog_carries_x_resource_annotations(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The form renders pickers off x-resource; each reference field must
    carry it, valued as the RBAC resource_type."""
    await _enable_module(db_session)
    _, token = await _user(db_session, permissions=REQUESTER_PERMS)
    await db_session.commit()

    resp = await client.get("/api/v1/requests/catalog", headers=_auth(token))
    assert resp.status_code == 200, resp.text
    by_kind = {k["kind"]: k for k in resp.json()}
    expected = {
        "subnet": ("block_id", "ip_block"),
        "ip_address": ("subnet_id", "subnet"),
        "dns_record": ("zone_id", "dns_zone"),
        "dhcp_reservation": ("scope_id", "dhcp_scope"),
    }
    for kind, (field, rtype) in expected.items():
        props = by_kind[kind]["args_schema"]["properties"]
        assert props[field].get("x-resource") == rtype, (kind, field, props[field])


# ── Permission filtering (the acceptance criterion) ─────────────────────────


@pytest.mark.asyncio
async def test_picker_returns_only_rows_the_caller_can_read(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    subs = await _subnets(db_session, ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"])
    visible = subs[1]
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [
            {
                "action": "read",
                "resource_type": "subnet",
                "resource_id": str(visible.id),
            }
        ],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "subnet"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert [o["id"] for o in body["options"]] == [str(visible.id)]
    assert body["options"][0]["label"] == "10.2.0.0/24"
    assert body["truncated"] is False


@pytest.mark.asyncio
async def test_picker_type_level_read_sees_all(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    subs = await _subnets(db_session, ["10.1.0.0/24", "10.2.0.0/24"])
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "subnet"}],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "subnet"},
    )
    assert resp.status_code == 200
    got = {o["id"] for o in resp.json()["options"]}
    assert {str(s.id) for s in subs} <= got


@pytest.mark.asyncio
async def test_picker_requires_submit_permission(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """No write,provisioning_request → 403, even with resource read grants —
    the endpoint exists for the portal form only."""
    await _enable_module(db_session)
    await _subnets(db_session, ["10.1.0.0/24"])
    _, token = await _user(db_session, permissions=[{"action": "read", "resource_type": "subnet"}])
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "subnet"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_picker_unknown_resource_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    _, token = await _user(db_session, permissions=REQUESTER_PERMS)
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "user"},  # never expose principals through this door
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_picker_search_narrows(client: AsyncClient, db_session: AsyncSession) -> None:
    await _enable_module(db_session)
    await _subnets(db_session, ["10.1.0.0/24", "192.168.7.0/24"])
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "subnet"}],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "subnet", "q": "192.168.7"},
    )
    assert resp.status_code == 200
    labels = [o["label"] for o in resp.json()["options"]]
    assert labels == ["192.168.7.0/24"]


# ── Per-resource query shapes ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zone_picker_offers_primary_zones_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A record request against a secondary zone can only fail at approval."""
    await _enable_module(db_session)
    g = DNSServerGroup(name=f"dg-{uuid.uuid4().hex[:6]}")
    db_session.add(g)
    await db_session.flush()
    primary = DNSZone(group_id=g.id, name="corp.example.test.", zone_type="primary")
    secondary = DNSZone(group_id=g.id, name="mirror.example.test.", zone_type="secondary")
    db_session.add_all([primary, secondary])
    await db_session.flush()
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "dns_zone"}],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "dns_zone", "q": "example.test"},
    )
    assert resp.status_code == 200
    assert [o["id"] for o in resp.json()["options"]] == [str(primary.id)]


@pytest.mark.asyncio
async def test_scope_picker_active_only_and_labeled_with_range(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable_module(db_session)
    subs = await _subnets(db_session, ["10.5.0.0/24", "10.6.0.0/24"])
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(grp)
    await db_session.flush()
    active = DHCPScope(subnet_id=subs[0].id, group_id=grp.id, name="office", is_active=True)
    inactive = DHCPScope(subnet_id=subs[1].id, group_id=grp.id, name="old", is_active=False)
    db_session.add_all([active, inactive])
    await db_session.flush()
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [
            {"action": "read", "resource_type": "dhcp_scope"},
            {"action": "read", "resource_type": "subnet"},
        ],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "dhcp_scope"},
    )
    assert resp.status_code == 200
    opts = {o["id"]: o for o in resp.json()["options"]}
    assert str(active.id) in opts and str(inactive.id) not in opts
    got = opts[str(active.id)]
    assert got["label"] == "office" and got["sublabel"] == "10.5.0.0/24"


@pytest.mark.asyncio
async def test_picker_grants_on_other_types_reveal_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The acceptance criterion's other face: read on dns_zone does not open
    the subnet picker."""
    await _enable_module(db_session)
    await _subnets(db_session, ["10.1.0.0/24"])
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS + [{"action": "read", "resource_type": "dns_zone"}],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "subnet"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"options": [], "truncated": False}


@pytest.mark.asyncio
async def test_picker_scan_reaches_past_the_first_page(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A scoped grant whose row sorts beyond page one (200 rows) must still be
    found — this exercises the multi-page loop and the id tiebreaker."""
    await _enable_module(db_session)
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/8", name="b")
    db_session.add(block)
    await db_session.flush()
    subs = []
    # 205 /24s — 10.0.0.0/24 … 10.0.204.0/24, sorted by network.
    for i in range(205):
        sub = Subnet(space_id=space.id, block_id=block.id, network=f"10.0.{i}.0/24", name=f"n{i}")
        db_session.add(sub)
        subs.append(sub)
    await db_session.flush()
    target = subs[204]  # sorts last → beyond the first 200-row page
    _, token = await _user(
        db_session,
        permissions=REQUESTER_PERMS
        + [{"action": "read", "resource_type": "subnet", "resource_id": str(target.id)}],
    )
    await db_session.commit()

    resp = await client.get(
        "/api/v1/requests/resource-options",
        headers=_auth(token),
        params={"resource": "subnet"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert [o["id"] for o in body["options"]] == [str(target.id)]
    assert body["truncated"] is False

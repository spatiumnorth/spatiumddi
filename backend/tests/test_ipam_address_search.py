"""HTTP-level tests for the IPAM address search / pagination surfaces.

Covers issues #517 (per-subnet address pagination + search + X-Total-Count)
and #520 (cross-subnet ``/addresses/search`` + ``/addresses/search/ids``,
including read-permission scoping).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet


async def _user(
    db: AsyncSession,
    *,
    name: str = "u",
    permissions: list[dict] | None = None,
    superadmin: bool = False,
) -> tuple[User, str]:
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@t.io",
        display_name=name,
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


async def _subnet(
    db: AsyncSession,
    *,
    network: str = "10.0.5.0/24",
    block_net: str = "10.0.0.0/16",
    name: str = "s",
) -> Subnet:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=block_net, name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=network, name=name)
    db.add(subnet)
    await db.flush()
    return subnet


async def _ip(
    db: AsyncSession,
    subnet: Subnet,
    address: str,
    *,
    hostname: str | None = None,
    status: str = "allocated",
) -> IPAddress:
    row = IPAddress(subnet_id=subnet.id, address=address, hostname=hostname, status=status)
    db.add(row)
    await db.flush()
    return row


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── 517: per-subnet list pagination + header ──────────────────────────


@pytest.mark.asyncio
async def test_list_addresses_pagination_and_total_header(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    for i in range(1, 6):
        await _ip(db_session, subnet, f"10.0.5.{i}", hostname=f"host-{i}")

    res = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?limit=2&offset=0",
        headers=_auth(token),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert len(body) == 2
    assert res.headers["X-Total-Count"] == "5"
    # Default order = ascending inet.
    assert body[0]["address"] == "10.0.5.1"
    assert body[1]["address"] == "10.0.5.2"

    # Second page.
    res2 = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?limit=2&offset=2",
        headers=_auth(token),
    )
    assert [r["address"] for r in res2.json()] == ["10.0.5.3", "10.0.5.4"]
    assert res2.headers["X-Total-Count"] == "5"


@pytest.mark.asyncio
async def test_list_addresses_backward_compatible_no_params(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    for i in range(1, 4):
        await _ip(db_session, subnet, f"10.0.5.{i}")

    res = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/addresses", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert isinstance(body, list)
    assert len(body) == 3  # full unsliced list
    assert res.headers["X-Total-Count"] == "3"


@pytest.mark.asyncio
async def test_list_addresses_no_limit_is_capped_and_says_so(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1256: a call with no limit gets at most the cap, and is told it was cut."""
    from app.api.v1.ipam import router as ipam_router

    monkeypatch.setattr(ipam_router, "_ADDRESS_LIST_CAP", 3)
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    for i in range(1, 6):
        await _ip(db_session, subnet, f"10.0.5.{i}")

    res = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/addresses", headers=_auth(token))
    assert res.status_code == 200
    assert [r["address"] for r in res.json()] == ["10.0.5.1", "10.0.5.2", "10.0.5.3"]
    assert res.headers["X-Total-Count"] == "5"
    assert res.headers["X-Result-Truncated"] == "true"
    assert "5 rows" in res.headers["Warning"]

    # An explicit window is the caller's own choice: not flagged truncated.
    res2 = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?limit=2&offset=3", headers=_auth(token)
    )
    assert [r["address"] for r in res2.json()] == ["10.0.5.4", "10.0.5.5"]
    assert "X-Result-Truncated" not in res2.headers


@pytest.mark.asyncio
async def test_list_addresses_under_cap_is_not_flagged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    await _ip(db_session, subnet, "10.0.5.1")
    res = await client.get(f"/api/v1/ipam/subnets/{subnet.id}/addresses", headers=_auth(token))
    assert "X-Result-Truncated" not in res.headers
    assert res.headers["X-Total-Count"] == "1"


@pytest.mark.asyncio
async def test_list_addresses_limit_above_cap_is_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    res = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?limit=10001", headers=_auth(token)
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_list_addresses_q_filter(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    await _ip(db_session, subnet, "10.0.5.1", hostname="web-prod")
    await _ip(db_session, subnet, "10.0.5.2", hostname="db-prod")
    await _ip(db_session, subnet, "10.0.5.3", hostname="web-stage")

    res = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?q=web", headers=_auth(token)
    )
    assert res.status_code == 200
    hosts = sorted(r["hostname"] for r in res.json())
    assert hosts == ["web-prod", "web-stage"]
    assert res.headers["X-Total-Count"] == "2"


@pytest.mark.asyncio
async def test_list_addresses_sort_desc(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    await _ip(db_session, subnet, "10.0.5.1", hostname="alpha")
    await _ip(db_session, subnet, "10.0.5.2", hostname="charlie")
    await _ip(db_session, subnet, "10.0.5.3", hostname="bravo")

    res = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?sort=hostname&order=desc",
        headers=_auth(token),
    )
    assert res.status_code == 200
    assert [r["hostname"] for r in res.json()] == ["charlie", "bravo", "alpha"]


@pytest.mark.asyncio
async def test_list_addresses_bad_sort_422(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session)
    res = await client.get(
        f"/api/v1/ipam/subnets/{subnet.id}/addresses?sort=bogus", headers=_auth(token)
    )
    assert res.status_code == 422


# ── 520: cross-subnet search envelope ─────────────────────────────────


@pytest.mark.asyncio
async def test_search_envelope_and_joined_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session, network="10.9.0.0/24", name="mynet")
    await _ip(db_session, subnet, "10.9.0.5", hostname="needle-1")

    res = await client.get("/api/v1/ipam/addresses/search?q=needle", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body.keys()) == {"items", "total", "limit", "offset"}
    assert body["total"] == 1
    assert body["limit"] == 100
    assert body["offset"] == 0
    item = body["items"][0]
    assert item["hostname"] == "needle-1"
    assert item["subnet_cidr"] == "10.9.0.0/24"
    assert item["subnet_name"] == "mynet"
    assert item["space_id"] == str(subnet.space_id)
    assert item["space_name"] is not None


@pytest.mark.asyncio
async def test_search_spans_multiple_subnets(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    s1 = await _subnet(db_session, network="10.1.0.0/24", block_net="10.1.0.0/16")
    s2 = await _subnet(db_session, network="10.2.0.0/24", block_net="10.2.0.0/16")
    await _ip(db_session, s1, "10.1.0.5", hostname="shared-a")
    await _ip(db_session, s2, "10.2.0.5", hostname="shared-b")

    res = await client.get("/api/v1/ipam/addresses/search?q=shared", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 2
    subnet_ids = {i["subnet_id"] for i in body["items"]}
    assert subnet_ids == {str(s1.id), str(s2.id)}


@pytest.mark.asyncio
async def test_search_space_filter(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    s1 = await _subnet(db_session, network="10.3.0.0/24", block_net="10.3.0.0/16")
    s2 = await _subnet(db_session, network="10.4.0.0/24", block_net="10.4.0.0/16")
    await _ip(db_session, s1, "10.3.0.5", hostname="x")
    await _ip(db_session, s2, "10.4.0.5", hostname="x")

    res = await client.get(
        f"/api/v1/ipam/addresses/search?space_id={s1.space_id}", headers=_auth(token)
    )
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["items"][0]["subnet_id"] == str(s1.id)


# ── 520: permission scoping ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_read_permission_scoping(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A user readable on only subnet1 must not see subnet2's IPs."""
    s1 = await _subnet(db_session, network="10.5.0.0/24", block_net="10.5.0.0/16")
    s2 = await _subnet(db_session, network="10.6.0.0/24", block_net="10.6.0.0/16")
    await _ip(db_session, s1, "10.5.0.5", hostname="visible")
    await _ip(db_session, s2, "10.6.0.5", hostname="hidden")

    # read:ip_address (type-level) clears the coarse router gate; read:subnet is
    # scoped to s1 only, so _readable_subnet_ids should exclude s2.
    _, token = await _user(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "ip_address"},
            {"action": "read", "resource_type": "subnet", "resource_id": str(s1.id)},
        ],
    )

    res = await client.get("/api/v1/ipam/addresses/search", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    hosts = {i["hostname"] for i in body["items"]}
    assert hosts == {"visible"}
    assert body["total"] == 1


# ── 520: id-only endpoint + cap ───────────────────────────────────────


@pytest.mark.asyncio
async def test_search_ids_envelope(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session, network="10.7.0.0/24", block_net="10.7.0.0/16")
    ip_a = await _ip(db_session, subnet, "10.7.0.1", hostname="pick")
    ip_b = await _ip(db_session, subnet, "10.7.0.2", hostname="pick")
    await _ip(db_session, subnet, "10.7.0.3", hostname="skip")

    res = await client.get("/api/v1/ipam/addresses/search/ids?q=pick", headers=_auth(token))
    assert res.status_code == 200, res.text
    body = res.json()
    assert set(body.keys()) == {"ids", "total", "capped"}
    assert body["total"] == 2
    assert body["capped"] is False
    assert set(body["ids"]) == {str(ip_a.id), str(ip_b.id)}


@pytest.mark.asyncio
async def test_search_ids_cap(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.ipam import router as ipam_router

    monkeypatch.setattr(ipam_router, "_SEARCH_IDS_CAP", 2)
    _, token = await _user(db_session, superadmin=True)
    subnet = await _subnet(db_session, network="10.8.0.0/24", block_net="10.8.0.0/16")
    for i in range(1, 4):  # 3 matching rows, cap 2
        await _ip(db_session, subnet, f"10.8.0.{i}", hostname="capme")

    res = await client.get("/api/v1/ipam/addresses/search/ids?q=capme", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 3
    assert body["capped"] is True
    assert len(body["ids"]) == 2


@pytest.mark.asyncio
async def test_search_ids_permission_scoping(client: AsyncClient, db_session: AsyncSession) -> None:
    s1 = await _subnet(db_session, network="10.10.0.0/24", block_net="10.10.0.0/16")
    s2 = await _subnet(db_session, network="10.11.0.0/24", block_net="10.11.0.0/16")
    keep = await _ip(db_session, s1, "10.10.0.5", hostname="both")
    await _ip(db_session, s2, "10.11.0.5", hostname="both")

    _, token = await _user(
        db_session,
        permissions=[
            {"action": "read", "resource_type": "ip_address"},
            {"action": "read", "resource_type": "subnet", "resource_id": str(s1.id)},
        ],
    )
    res = await client.get("/api/v1/ipam/addresses/search/ids?q=both", headers=_auth(token))
    assert res.status_code == 200
    body = res.json()
    assert body["ids"] == [str(keep.id)]
    assert body["total"] == 1

"""#2147: ``POST /api/v1/presence`` and the ``find_device_presence`` MCP tool."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.auth import Group, Role, User
from app.models.dhcp import DHCPLease, DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IpMacHistory, IPSpace, Subnet
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import REGISTRY
from app.services.ipam.presence import MAX_MACS, PresenceResponse

pytestmark = pytest.mark.asyncio

NOW = lambda: datetime.now(UTC)  # noqa: E731
MAC_A = "a4:bb:cc:dd:ee:01"
MAC_B = "a4:bb:cc:dd:ee:02"
MAC_C = "a4:bb:cc:dd:ee:03"


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _user(
    db: AsyncSession, *, superadmin: bool = False, perms: list[dict] | None = None
) -> tuple[User, str]:
    u = User(
        username=f"p-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="p",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    if perms is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=perms)
        db.add(role)
        await db.flush()
        grp = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        grp.roles = [role]
        grp.users = [u]
        db.add(grp)
        await db.flush()
    await db.refresh(u, ["groups"])
    return u, create_access_token(str(u.id))


class Estate:
    """space -> block -> subnet -> scope on one Kea server."""

    def __init__(self, space: IPSpace, subnet: Subnet, scope: DHCPScope, server: DHCPServer):
        self.space, self.subnet, self.scope, self.server = space, subnet, scope, server


async def _estate(db: AsyncSession, net: str, *, driver: str = "kea") -> Estate:
    tag = uuid.uuid4().hex[:6]
    space = IPSpace(name=f"sp-{tag}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network="10.0.0.0/8")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, name="s", network=net)
    grp = DHCPServerGroup(name=f"g-{tag}", description="")
    db.add_all([subnet, grp])
    await db.flush()
    server = DHCPServer(
        name=f"k-{tag}", driver=driver, host="127.0.0.1", port=67, server_group_id=grp.id
    )
    scope = DHCPScope(group_id=grp.id, subnet_id=subnet.id, is_active=True)
    db.add_all([server, scope])
    await db.flush()
    return Estate(space, subnet, scope, server)


async def _lease(
    db: AsyncSession,
    e: Estate,
    ip: str,
    mac: str,
    *,
    seen_ago: int = 5,
    ends_in: int | None = 3600,
    state: str = "active",
    hostname: str | None = None,
) -> DHCPLease:
    lease = DHCPLease(
        server_id=e.server.id,
        scope_id=e.scope.id,
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        state=state,
        ends_at=NOW() + timedelta(seconds=ends_in) if ends_in is not None else None,
        last_seen_at=NOW() - timedelta(seconds=seen_ago),
    )
    db.add(lease)
    await db.flush()
    return lease


async def _post(client: AsyncClient, token: str, body: dict[str, Any]):
    return await client.post("/api/v1/presence", headers=_hdr(token), json=body)


async def _by_mac(client: AsyncClient, token: str, macs: list[str], **kw: Any) -> dict[str, dict]:
    resp = await _post(client, token, {"macs": macs, **kw})
    assert resp.status_code == 200, resp.text
    return {i["mac"]: i for i in resp.json()["items"]}


# ── presence rules ──────────────────────────────────────────────────────────


async def test_active_lease_with_recent_activity_is_present(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A, hostname="phone")
    await db_session.commit()
    row = (await _by_mac(client, token, [MAC_A]))[MAC_A]
    assert row["present"] is True
    assert row["ip"] == "10.1.0.5"
    assert row["hostname"] == "phone"
    assert row["source"] == "dhcp"
    assert row["randomized"] is False
    assert row["lease_expires_at"] is not None
    assert row["leases"][0]["scope_id"] == str(e.scope.id)
    assert row["leases"][0]["subnet_id"] == str(e.subnet.id)
    assert row["freshness_s"] is None


async def test_lease_alone_is_not_presence(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A, seen_ago=3600)  # lingering lease
    await db_session.commit()
    row = (await _by_mac(client, token, [MAC_A]))[MAC_A]
    assert row["present"] is False
    assert row["ip"] == "10.1.0.5"
    # A wider window makes the same data count: the window is honoured.
    assert (await _by_mac(client, token, [MAC_A], window_seconds=7200))[MAC_A]["present"] is True


async def test_expired_or_inactive_lease_is_not_active(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A, ends_in=-60)
    await _lease(db_session, e, "10.1.0.6", MAC_B, state="expired")
    await db_session.commit()
    rows = await _by_mac(client, token, [MAC_A, MAC_B])
    for mac in (MAC_A, MAC_B):
        assert rows[mac]["present"] is False and rows[mac]["leases"] == []


async def test_activity_without_lease_is_not_present(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    db_session.add(
        IPAddress(
            subnet_id=e.subnet.id,
            address="10.1.0.9",
            status="allocated",
            mac_address=MAC_A,
            last_seen_at=NOW(),
            last_seen_method="arp",
        )
    )
    await db_session.commit()
    row = (await _by_mac(client, token, [MAC_A]))[MAC_A]
    assert row["present"] is False
    assert row["source"] == "arp"  # the signal is reported, it just is not presence


async def test_freshest_signal_wins(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A, seen_ago=3600)
    db_session.add(
        IPAddress(
            subnet_id=e.subnet.id,
            address="10.1.0.5",
            status="dhcp",
            mac_address=MAC_A,
            last_seen_at=NOW() - timedelta(seconds=20),
            last_seen_method="ping",
        )
    )
    await db_session.commit()
    row = (await _by_mac(client, token, [MAC_A]))[MAC_A]
    assert row["present"] is True and row["source"] == "ping"


async def test_history_signal_and_manual_stamp(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A, seen_ago=3600)
    await _lease(db_session, e, "10.1.0.6", MAC_B, seen_ago=3600)
    ip_a = IPAddress(subnet_id=e.subnet.id, address="10.1.0.5", status="dhcp", mac_address=MAC_A)
    ip_b = IPAddress(
        subnet_id=e.subnet.id,
        address="10.1.0.6",
        status="dhcp",
        mac_address=MAC_B,
        last_seen_at=NOW(),
        last_seen_method="manual",  # an operator edit is not activity
    )
    db_session.add_all([ip_a, ip_b])
    await db_session.flush()
    db_session.add(
        IpMacHistory(ip_address_id=ip_a.id, mac_address=MAC_A, last_seen=NOW(), source="l2_sniff")
    )
    await db_session.commit()
    rows = await _by_mac(client, token, [MAC_A, MAC_B])
    assert rows[MAC_A]["present"] is True and rows[MAC_A]["source"] == "arp"
    assert rows[MAC_B]["present"] is False


async def test_randomized_flag_and_polled_freshness(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    ps = await db_session.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db_session.add(ps)
    ps.dhcp_pull_leases_interval_seconds = 45
    e = await _estate(db_session, "10.1.0.0/24", driver="windows_dhcp")
    rand = "02:bb:cc:dd:ee:01"  # locally-administered bit set
    await _lease(db_session, e, "10.1.0.5", rand)
    await db_session.commit()
    row = (await _by_mac(client, token, [rand]))[rand]
    assert row["randomized"] is True
    assert row["present"] is True
    assert row["freshness_s"] == 45


# ── request handling ────────────────────────────────────────────────────────


async def test_formats_normalised_and_duplicates_collapsed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A)
    await db_session.commit()
    resp = await _post(
        client,
        token,
        {"macs": ["A4-BB-CC-DD-EE-01", "a4bb.ccdd.ee01", "a4bbccddee01", MAC_B, MAC_A]},
    )
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert [i["mac"] for i in items] == [MAC_A, MAC_B]  # one each, first-seen order
    assert items[0]["present"] is True and items[1]["present"] is False


async def test_empty_list_is_an_empty_answer(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    await db_session.commit()
    resp = await _post(client, token, {"macs": []})
    assert resp.status_code == 200, resp.text
    assert resp.json()["items"] == []


async def test_malformed_macs_422_names_each_bad_entry(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    await db_session.commit()
    resp = await _post(client, token, {"macs": [MAC_A, "not-a-mac", "a4:bb:cc"]})
    assert resp.status_code == 422, resp.text
    detail = str(resp.json()["detail"])
    assert "not-a-mac" in detail and "a4:bb:cc" in detail and MAC_A not in detail


async def test_over_cap_and_bad_window_are_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, superadmin=True)
    await db_session.commit()
    many = [f"a4:bb:cc:{i >> 8:02x}:{i & 255:02x}:01" for i in range(MAX_MACS + 1)]
    assert (await _post(client, token, {"macs": many})).status_code == 422
    assert (await _post(client, token, {"macs": many[:MAX_MACS]})).status_code == 200
    assert (await _post(client, token, {"macs": [MAC_A], "window_seconds": 1})).status_code == 422
    assert (await _post(client, token, {"macs": "x"})).status_code == 422
    assert (await _post(client, token, {})).status_code == 422


# ── permissions ─────────────────────────────────────────────────────────────


async def test_no_grant_is_403_and_anonymous_is_401(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _user(db_session, perms=[{"action": "read", "resource_type": "dns_zone"}])
    await db_session.commit()
    assert (await _post(client, token, {"macs": [MAC_A]})).status_code == 403
    anon = await client.post("/api/v1/presence", json={"macs": [MAC_A]})
    assert anon.status_code == 401


async def test_scoped_user_never_sees_a_lease_outside_their_grants(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    mine = await _estate(db_session, "10.1.0.0/24")
    theirs = await _estate(db_session, "10.2.0.0/24")
    await _lease(db_session, mine, "10.1.0.5", MAC_A, hostname="mine")
    await _lease(db_session, theirs, "10.2.0.5", MAC_B, hostname="secret")
    # The foreign subnet also carries fresh activity for MAC_A: it must not
    # leak into MAC_A's last_seen_at / source either.
    db_session.add(
        IPAddress(
            subnet_id=theirs.subnet.id,
            address="10.2.0.6",
            status="dhcp",
            mac_address=MAC_A,
            last_seen_at=NOW() + timedelta(seconds=1),
            last_seen_method="snmp",
        )
    )
    _, token = await _user(
        db_session,
        perms=[{"action": "read", "resource_type": "subnet", "resource_id": str(mine.subnet.id)}],
    )
    await db_session.commit()
    rows = await _by_mac(client, token, [MAC_A, MAC_B, MAC_C])
    assert rows[MAC_A]["present"] is True and rows[MAC_A]["source"] == "dhcp"
    assert rows[MAC_A]["ip"] == "10.1.0.5"
    # MAC_B exists only outside the grant: byte-for-byte what an unknown MAC gets.
    leaked = {**rows[MAC_B], "mac": "x"}
    unknown = {**rows[MAC_C], "mac": "x"}
    assert leaked == unknown
    assert rows[MAC_B]["present"] is False and rows[MAC_B]["leases"] == []
    assert "secret" not in str(rows)
    # ...while an unscoped superadmin does see it.
    _, admin = await _user(db_session, superadmin=True)
    await db_session.commit()
    assert (await _by_mac(client, admin, [MAC_B]))[MAC_B]["present"] is True


# ── trash ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("what", ["scope", "subnet", "space"])
async def test_trashed_parent_hides_the_lease_and_restore_brings_it_back(
    client: AsyncClient, db_session: AsyncSession, what: str
) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A)
    db_session.add(
        IPAddress(
            subnet_id=e.subnet.id,
            address="10.1.0.5",
            status="dhcp",
            mac_address=MAC_A,
            last_seen_at=NOW(),
            last_seen_method="arp",
        )
    )
    await db_session.commit()
    model, row = {"scope": (DHCPScope, e.scope), "subnet": (Subnet, e.subnet)}.get(
        what, (IPSpace, e.space)
    )
    assert (await _by_mac(client, token, [MAC_A]))[MAC_A]["present"] is True

    await db_session.execute(
        update(model)
        .where(model.id == row.id)
        .values(deleted_at=NOW())
        .execution_options(include_deleted=True)
    )
    await db_session.commit()
    gone = (await _by_mac(client, token, [MAC_A]))[MAC_A]
    assert gone["present"] is False and gone["leases"] == []
    if what != "scope":  # a trashed scope leaves the (live) subnet's own activity signal
        assert gone["last_seen_at"] is None

    await db_session.execute(
        update(model)
        .where(model.id == row.id)
        .values(deleted_at=None)
        .execution_options(include_deleted=True)
    )
    await db_session.commit()
    assert (await _by_mac(client, token, [MAC_A]))[MAC_A]["present"] is True


async def test_subnet_trash_via_api_is_not_reported(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The real delete path. (It also tears the leases down, so restore is
    covered by the stamp-based test above, which keeps the lease rows.)"""
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A)
    await db_session.commit()
    assert (await _by_mac(client, token, [MAC_A]))[MAC_A]["present"] is True
    resp = await client.delete(f"/api/v1/ipam/subnets/{e.subnet.id}", headers=_hdr(token))
    assert resp.status_code == 204, resp.text
    assert (await _by_mac(client, token, [MAC_A]))[MAC_A]["present"] is False


# ── contract ────────────────────────────────────────────────────────────────


async def test_response_matches_openapi(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A)
    await db_session.commit()
    body = (await _post(client, token, {"macs": [MAC_A, MAC_B]})).json()
    PresenceResponse.model_validate(body)  # no stray / missing field

    spec = app.openapi()
    op = spec["paths"]["/api/v1/presence"]["post"]
    ref = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    schemas = spec["components"]["schemas"]
    resp_schema = schemas[ref.rsplit("/", 1)[1]]
    assert set(resp_schema["properties"]) == set(body)
    item_ref = resp_schema["properties"]["items"]["items"]["$ref"]
    assert set(schemas[item_ref.rsplit("/", 1)[1]]["properties"]) == set(body["items"][0])


async def test_mcp_tool_matches_rest(client: AsyncClient, db_session: AsyncSession) -> None:
    user, token = await _user(db_session, superadmin=True)
    e = await _estate(db_session, "10.1.0.0/24")
    await _lease(db_session, e, "10.1.0.5", MAC_A)
    await db_session.commit()
    tool = REGISTRY.get("find_device_presence")
    assert tool is not None
    assert tool.permission == ("read", "subnet") and tool.default_enabled is True
    args = {"macs": ["A4-BB-CC-DD-EE-01", MAC_B], "window_seconds": 600}
    rest = (await _post(client, token, args)).json()
    mcp = await tool.executor(db_session, user, tool.args_model(**args))
    assert mcp == rest


async def test_mcp_tool_is_scoped_like_rest(db_session: AsyncSession) -> None:
    mine = await _estate(db_session, "10.1.0.0/24")
    theirs = await _estate(db_session, "10.2.0.0/24")
    await _lease(db_session, mine, "10.1.0.5", MAC_A)
    await _lease(db_session, theirs, "10.2.0.5", MAC_B)
    user, _ = await _user(
        db_session,
        perms=[{"action": "read", "resource_type": "subnet", "resource_id": str(mine.subnet.id)}],
    )
    tool = REGISTRY.get("find_device_presence")
    assert tool is not None
    out = await tool.executor(db_session, user, tool.args_model(macs=[MAC_A, MAC_B]))
    present = {i["mac"]: i["present"] for i in out["items"]}
    assert present == {MAC_A: True, MAC_B: False}

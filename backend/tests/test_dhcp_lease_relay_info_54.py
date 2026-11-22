"""The relay agent information (option 82) of each lease is recorded (#54).

With ``store-extended-info`` on, Kea keeps the option-82 body a relay sent in
the lease's user context; the agent ships it as ``relay_agent_info``. Before
#54 the agent never read it and the control plane had nowhere to put it, so
"which switch port is this client on?" had no answer anywhere.

The bodies below are the ones kea-dhcp4 3.0.3 stored for the rig's relayed
DORAs (``agent/dhcp/tests/fixtures/kea303_relay_*``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import LeaseEvent, LeaseEventBatch, _auth_agent
from app.core.security import create_access_token, hash_password
from app.main import app
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPLeaseHistory, DHCPServer, DHCPServerGroup
from app.services.ai.tools.dhcp import (
    FindDHCPLeaseHistoryArgs,
    FindDHCPLeasesArgs,
    find_dhcp_lease_history,
    find_dhcp_leases,
)
from app.services.dhcp.lease_history import record_lease_history
from app.services.dhcp.relay_agent_info import (
    circuit_and_remote,
    decode_sub_options,
    parse_sub_options,
    printable_text,
    relay_hex_filter,
)

# circuit-id "eth0/1:100", remote-id AA BB CC 01 02 03
PORT_A = "010A657468302F313A3130300206AABBCC010203"
# circuit-id "eth0/2:100", same remote-id, sub-option 6 "sub-42"
PORT_B = "010A657468302F323A3130300206AABBCC01020306067375622D3432"
# binary circuit-id (00 04 00 64 01 07), remote-id "it's,\"x\"\n"
BINARY = "01060004006401070209697427732C2278220A"
CIRCUIT_A = "657468302F313A313030"
CIRCUIT_B = "657468302F323A313030"
REMOTE = "AABBCC010203"


# ── decoding ────────────────────────────────────────────────────────────────


def test_sub_options_parse_in_wire_order() -> None:
    assert parse_sub_options(PORT_B) == [
        (1, CIRCUIT_B),
        (2, REMOTE),
        (6, "7375622D3432"),
    ]
    assert circuit_and_remote(PORT_A) == (CIRCUIT_A, REMOTE)
    assert circuit_and_remote(BINARY) == ("000400640107", "697427732C2278220A")


def test_malformed_bodies() -> None:
    # A length running past the end, and a lone trailing byte.
    assert parse_sub_options("0105AABB") is None
    assert parse_sub_options("0102AABB02") is None
    assert circuit_and_remote("0102AABB0205CC") == (None, None)
    assert decode_sub_options("0105AABB") == []
    assert parse_sub_options(None) is None and parse_sub_options("") is None


def test_zero_length_and_repeated_sub_options() -> None:
    assert parse_sub_options("01000203AABBCC") == [(1, ""), (2, "AABBCC")]
    # An empty circuit-id is nothing to search for.
    assert circuit_and_remote("01000203AABBCC") == (None, "AABBCC")
    # A repeated code: the first one counts.
    assert circuit_and_remote("0101AA0101BB") == ("AA", None)


def test_printable_rendering_is_never_lossy() -> None:
    assert printable_text(CIRCUIT_A) == "eth0/1:100"
    assert printable_text("000400640107") is None
    assert printable_text("697427732C2278220A") is None  # newline at the end
    assert printable_text("C3A9") is None  # UTF-8, but not ASCII
    assert decode_sub_options(PORT_B)[2] == {"code": 6, "hex": "7375622D3432", "text": "sub-42"}


def test_filter_values() -> None:
    assert relay_hex_filter("65:74:68") == ("657468", False)
    assert relay_hex_filter("0x6574*") == ("6574", True)
    assert relay_hex_filter("657*") == ("657", True)  # a prefix may end mid-byte
    assert relay_hex_filter("657") is None
    assert relay_hex_filter("eth0") is None
    assert relay_hex_filter("*") is None


# ── the wire ────────────────────────────────────────────────────────────────


def _event(**over: Any) -> dict[str, Any]:
    end = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    ev: dict[str, Any] = {
        "ip_address": "10.54.1.100",
        "mac_address": "02:00:00:00:00:01",
        "state": "active",
        "starts_at": datetime.now(UTC).isoformat(),
        "ends_at": end,
        "expires_at": end,
    }
    ev.update(over)
    return ev


def test_lease_event_normalises_or_drops_the_body() -> None:
    assert LeaseEvent(**_event(relay_agent_info="0x" + PORT_A.lower())).relay_agent_info == PORT_A
    for bad in ("", "0x", "ABC", "GG", 12, "AB" * 256):
        # Never a 422: the lease itself must land.
        assert LeaseEvent(**_event(relay_agent_info=bad)).relay_agent_info is None
    assert LeaseEvent(**_event()).relay_agent_info is None


def test_an_unknown_event_key_is_accepted() -> None:
    """The contract the new field leans on in the other direction: a control
    plane older than an agent's newest field ignores it rather than 422ing the
    batch (only the envelope forbids extra keys)."""
    batch = LeaseEventBatch(leases=[_event(some_future_field="x")])  # type: ignore[list-item]
    assert len(batch.leases) == 1


# ── ingest ──────────────────────────────────────────────────────────────────


async def _seed(db: AsyncSession) -> tuple[DHCPServerGroup, DHCPServer]:
    group = DHCPServerGroup(name=f"rai-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    server = DHCPServer(
        name=f"rai-kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        status="active",
        server_group_id=group.id,
    )
    db.add(server)
    await db.commit()
    return group, server


async def _post(client: AsyncClient, server: DHCPServer, *events: dict[str, Any]) -> None:
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json={"leases": list(events)})
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


async def _lease(db: AsyncSession, ip: str) -> DHCPLease:
    stmt = select(DHCPLease).where(DHCPLease.ip_address == ip)
    return (await db.execute(stmt.execution_options(populate_existing=True))).scalar_one()


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    admin = User(
        username=f"sa-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@t.io",
        display_name="sa",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(admin)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(admin.id))}"}


@pytest.mark.asyncio
async def test_a_relayed_lease_records_its_circuit_and_remote_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, server = await _seed(db_session)
    await _post(client, server, _event(relay_agent_info=PORT_A))
    lease = await _lease(db_session, "10.54.1.100")
    assert lease.relay_agent_info == PORT_A
    assert lease.relay_circuit_id == CIRCUIT_A
    assert lease.relay_remote_id == REMOTE


@pytest.mark.asyncio
async def test_a_renewal_without_option_82_keeps_it_and_a_new_body_replaces_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, server = await _seed(db_session)
    await _post(client, server, _event(relay_agent_info=PORT_A))
    # The unicast renewal: no relay in the path, so no option 82.
    await _post(client, server, _event(hostname="renewed"))
    lease = await _lease(db_session, "10.54.1.100")
    assert lease.hostname == "renewed"
    assert (lease.relay_circuit_id, lease.relay_remote_id) == (CIRCUIT_A, REMOTE)
    # The client moved to another port and came in relayed again.
    await _post(client, server, _event(relay_agent_info=PORT_B))
    lease = await _lease(db_session, "10.54.1.100")
    assert (lease.relay_agent_info, lease.relay_circuit_id) == (PORT_B, CIRCUIT_B)


@pytest.mark.asyncio
async def test_a_malformed_body_is_kept_raw_and_bad_hex_is_dropped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, server = await _seed(db_session)
    await _post(
        client,
        server,
        _event(relay_agent_info="0102AABB0205CC"),  # truncated tail
        _event(ip_address="10.54.1.101", mac_address="02:00:00:00:00:02", relay_agent_info="XYZ"),
    )
    truncated = await _lease(db_session, "10.54.1.100")
    assert truncated.relay_agent_info == "0102AABB0205CC"
    assert truncated.relay_circuit_id is None and truncated.relay_remote_id is None
    garbage = await _lease(db_session, "10.54.1.101")
    assert garbage.relay_agent_info is None  # dropped, and the lease still landed


@pytest.mark.asyncio
async def test_history_keeps_the_circuit_and_remote_id(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, server = await _seed(db_session)
    await _post(client, server, _event(relay_agent_info=PORT_A))
    record_lease_history(db_session, await _lease(db_session, "10.54.1.100"), lease_state="expired")
    await db_session.commit()
    hist = (
        await db_session.execute(
            select(DHCPLeaseHistory).where(DHCPLeaseHistory.server_id == server.id)
        )
    ).scalar_one()
    assert (hist.relay_circuit_id, hist.relay_remote_id) == (CIRCUIT_A, REMOTE)


# ── REST ────────────────────────────────────────────────────────────────────


async def _three_leases(client: AsyncClient, db: AsyncSession) -> tuple[Any, DHCPServer]:
    group, server = await _seed(db)
    await _post(
        client,
        server,
        _event(relay_agent_info=PORT_A),
        _event(ip_address="10.54.1.120", mac_address="02:00:00:00:00:02", relay_agent_info=PORT_B),
        _event(ip_address="10.54.1.200", mac_address="02:00:00:00:00:04"),
    )
    return group, server


@pytest.mark.asyncio
async def test_lease_list_returns_and_filters_the_relay_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, server = await _three_leases(client, db_session)
    headers = await _admin_headers(db_session)

    resp = await client.get(f"/api/v1/dhcp/servers/{server.id}/leases", headers=headers)
    assert resp.status_code == 200, resp.text
    rows = {i["ip_address"]: i for i in resp.json()["items"]}
    a = rows["10.54.1.100"]
    assert a["relay_circuit_id"] == CIRCUIT_A and a["relay_circuit_id_text"] == "eth0/1:100"
    assert a["relay_remote_id"] == REMOTE and a["relay_remote_id_text"] is None
    assert a["relay_agent_info"] == PORT_A
    assert a["relay_sub_options"] == [
        {"code": 1, "hex": CIRCUIT_A, "text": "eth0/1:100"},
        {"code": 2, "hex": REMOTE, "text": None},
    ]
    none = rows["10.54.1.200"]
    assert none["relay_circuit_id"] is None and none["relay_sub_options"] == []

    async def ips(url: str, **params: str) -> set[str]:
        r = await client.get(url, headers=headers, params=params)
        assert r.status_code == 200, r.text
        return {i["ip_address"] for i in r.json()["items"]}

    for url in (f"/api/v1/dhcp/servers/{server.id}/leases", "/api/v1/dhcp/leases"):
        assert await ips(url, relay_circuit_id=CIRCUIT_A) == {"10.54.1.100"}
        assert await ips(url, relay_circuit_id="65:74:68:30:2F*") == {
            "10.54.1.100",
            "10.54.1.120",
        }
        assert await ips(url, relay_remote_id=REMOTE.lower()) == {"10.54.1.100", "10.54.1.120"}
        bad = await client.get(url, headers=headers, params={"relay_circuit_id": "eth0"})
        assert bad.status_code == 422, bad.text


@pytest.mark.asyncio
async def test_lease_history_returns_and_filters_the_relay_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, server = await _three_leases(client, db_session)
    for ip in ("10.54.1.100", "10.54.1.200"):
        record_lease_history(db_session, await _lease(db_session, ip), lease_state="expired")
    await db_session.commit()
    headers = await _admin_headers(db_session)
    for url in (f"/api/v1/dhcp/servers/{server.id}/lease-history", "/api/v1/dhcp/lease-history"):
        resp = await client.get(url, headers=headers, params={"relay_circuit_id": "657468*"})
        assert resp.status_code == 200, resp.text
        (row,) = resp.json()["items"]
        assert row["ip_address"] == "10.54.1.100"
        assert row["relay_circuit_id_text"] == "eth0/1:100"
        assert row["relay_remote_id"] == REMOTE


@pytest.mark.asyncio
async def test_relay_agent_observations(client: AsyncClient, db_session: AsyncSession) -> None:
    group, _server = await _three_leases(client, db_session)
    headers = await _admin_headers(db_session)
    url = f"/api/v1/dhcp/server-groups/{group.id}/relay-agent-observations"

    resp = await client.get(url, headers=headers, params={"sub_option": 2})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "sub_option": 2,
        "items": [{"hex": REMOTE, "text": None, "lease_count": 2}],
        "truncated": False,
    }

    resp = await client.get(url, headers=headers, params={"q": "eth0/2"})
    assert [i["text"] for i in resp.json()["items"]] == ["eth0/2:100"]
    resp = await client.get(url, headers=headers, params={"q": "/1"})
    assert [i["text"] for i in resp.json()["items"]] == ["eth0/1:100"]
    # Hex is matched on byte boundaries: both circuit-ids contain "02F3" as
    # text of their hex ("30 2F 3…"), straddling bytes, and neither holds it.
    resp = await client.get(url, headers=headers, params={"q": "02F3"})
    assert resp.json()["items"] == []
    resp = await client.get(url, headers=headers, params={"q": "2F32"})
    assert [i["text"] for i in resp.json()["items"]] == ["eth0/2:100"]

    other = await client.get(
        f"/api/v1/dhcp/server-groups/{uuid.uuid4()}/relay-agent-observations", headers=headers
    )
    assert other.status_code == 404


# ── MCP ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_copilot_lease_tools_return_and_filter_the_relay_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _group, _server = await _three_leases(client, db_session)
    hits = await find_dhcp_leases(
        db_session, None, FindDHCPLeasesArgs(relay_circuit_id=CIRCUIT_B)  # type: ignore[arg-type]
    )
    assert [(h["ip_address"], h["relay_circuit_id_text"], h["relay_remote_id"]) for h in hits] == [
        ("10.54.1.120", "eth0/2:100", REMOTE)
    ]
    bad = await find_dhcp_leases(
        db_session, None, FindDHCPLeasesArgs(relay_circuit_id="eth0/2")  # type: ignore[arg-type]
    )
    assert len(bad) == 1 and "not hex" in bad[0]["result"]

    record_lease_history(
        db_session, await _lease(db_session, "10.54.1.120"), lease_state="released"
    )
    await db_session.commit()
    hist = await find_dhcp_lease_history(
        db_session, None, FindDHCPLeaseHistoryArgs(relay_remote_id="AABB*")  # type: ignore[arg-type]
    )
    assert [(h["ip_address"], h["relay_circuit_id"]) for h in hist] == [("10.54.1.120", CIRCUIT_B)]

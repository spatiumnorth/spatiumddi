"""#2269 — ``DHCPScope.hostname_to_ipam_sync`` takes effect.

The setting was stored and never read: every lease's hostname reached IPAM.
Only ``on_lease`` writes a lease's hostname onto its IPAM mirror row; the
mirror row itself (status, MAC, last-seen) is written in every mode, and
nothing already in IPAM is deleted or blanked by turning the setting off.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _auth_agent
from app.main import app
from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

IP = "10.80.1.50"
MAC = "aa:bb:cc:dd:ee:50"


async def _seed(db: AsyncSession, mode: str | None) -> tuple[DHCPServer, Subnet]:
    space = IPSpace(name=f"hs-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.80.0.0/16", name="hs-blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.80.1.0/24", name="hs-sn")
    db.add(subnet)
    grp = DHCPServerGroup(name=f"hs-g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    server = DHCPServer(
        name=f"hs-srv-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        status="active",
        server_group_id=grp.id,
    )
    db.add(server)
    if mode is not None:
        db.add(
            DHCPScope(
                group_id=grp.id, subnet_id=subnet.id, is_active=True, hostname_to_ipam_sync=mode
            )
        )
    await db.flush()
    return server, subnet


def _payload(hostname: str = "client-a") -> dict:
    end = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "leases": [
            {
                "ip_address": IP,
                "mac_address": MAC,
                "hostname": hostname,
                "state": "active",
                "starts_at": datetime.now(UTC).isoformat(),
                "ends_at": end,
                "expires_at": end,
            }
        ]
    }


async def _post(client: AsyncClient, server: DHCPServer, payload: dict) -> None:
    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        resp = await client.post("/api/v1/dhcp/agents/lease-events", json=payload)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)
    assert resp.status_code == 200, resp.text


async def _row(db: AsyncSession) -> IPAddress:
    db.expire_all()
    return (await db.execute(select(IPAddress).where(IPAddress.address == IP))).scalar_one()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "hostname_lands"),
    [("on_lease", True), ("on_static_only", False), ("disabled", False), (None, True)],
)
async def test_agent_lease_event_honours_mode(
    client: AsyncClient, db_session: AsyncSession, mode: str | None, hostname_lands: bool
) -> None:
    server, subnet = await _seed(db_session, mode)
    subnet_id = subnet.id
    await db_session.commit()

    await _post(client, server, _payload("client-a"))

    row = await _row(db_session)
    # The mirror row exists in every mode ...
    assert row.subnet_id == subnet_id
    assert row.auto_from_lease is True
    assert row.status == "dhcp"
    assert str(row.mac_address) == MAC
    # ... only the hostname depends on the scope setting.
    assert (row.hostname or "") == ("client-a" if hostname_lands else "")


@pytest.mark.asyncio
async def test_agent_refresh_leaves_existing_hostname_when_disabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Turning the setting off keeps what IPAM already holds: a later lease
    event neither deletes the mirror nor overwrites / blanks its hostname."""
    server, subnet = await _seed(db_session, "on_lease")
    server_id = server.id
    await db_session.commit()
    await _post(client, server, _payload("old-name"))
    assert (await _row(db_session)).hostname == "old-name"

    scope = (await db_session.execute(select(DHCPScope))).scalars().first()
    scope.hostname_to_ipam_sync = "disabled"
    await db_session.commit()
    server = await db_session.get(DHCPServer, server_id)

    await _post(client, server, _payload("new-name"))
    row = await _row(db_session)
    assert row.auto_from_lease is True
    assert row.hostname == "old-name"


class _StubDriver:
    def __init__(self, leases: list[dict]) -> None:
        self._leases = leases

    async def get_leases(self, _server: DHCPServer) -> list[dict]:
        return self._leases


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "hostname_lands"),
    [("on_lease", True), ("on_static_only", False), ("disabled", False)],
)
async def test_pull_leases_honours_mode(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    hostname_lands: bool,
) -> None:
    from app.services.dhcp import pull_leases as pl

    server, subnet = await _seed(db_session, mode)
    server.driver = "windows_dhcp"
    subnet_id = subnet.id
    await db_session.commit()

    wire = [{"ip_address": IP, "mac_address": MAC, "hostname": "winbox"}]
    monkeypatch.setattr(pl, "get_driver", lambda _d: _StubDriver(wire))
    monkeypatch.setattr(pl, "is_agentless", lambda _d: True)

    import app.services.dns.ddns as ddns

    async def _noop(*a, **k):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(ddns, "apply_ddns_for_lease", _noop)
    monkeypatch.setattr(ddns, "revoke_ddns_for_lease", _noop)

    # Two passes: the first creates the mirror, the second takes the refresh
    # branch — both must respect the mode.
    for _ in range(2):
        await pl.pull_leases_from_server(db_session, server, apply=True)
        await db_session.commit()

    row = await _row(db_session)
    assert row.auto_from_lease is True
    assert row.subnet_id == subnet_id
    assert (row.hostname or "") == ("winbox" if hostname_lands else "")


@pytest.mark.asyncio
async def test_new_scope_defaults_to_on_lease(db_session: AsyncSession) -> None:
    """The default keeps what every scope has always done."""
    server, subnet = await _seed(db_session, None)
    scope = DHCPScope(group_id=server.server_group_id, subnet_id=subnet.id)
    db_session.add(scope)
    await db_session.flush()
    assert scope.hostname_to_ipam_sync == "on_lease"

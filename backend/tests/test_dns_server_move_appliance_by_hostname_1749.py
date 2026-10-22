"""Moving an appliance's own DNS server repoints the appliance (#1749).

The #934 move repointed ``Appliance.assigned_dns_group_id`` only when the
server row carried ``appliance_id`` — which agents never set (they register
by hostname). So the supervisor kept rendering ``AGENT_GROUP`` and the #50
DoT/DoH/DoQ firewall ports for the group the agent had left. The rows here
are created by POSTing what the agent sends to the real register endpoint.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import appliance_channel
from app.models.appliance import Appliance
from app.models.dns import DNSServer
from tests.test_dns_server_group_move import _auth, _group, _superadmin, _url

HOST = "ddi1749"


async def _appliance(
    db: AsyncSession, group, hostname: str = HOST, roles: list[str] | None = None
) -> Appliance:  # noqa: ANN001
    a = Appliance(
        hostname=hostname,
        public_key_der=b"\x00" * 32,
        public_key_fingerprint=f"fp-{uuid.uuid4().hex}",
        state="approved",
        assigned_roles=roles if roles is not None else ["dns-bind9"],
        assigned_dns_group_id=group.id,
    )
    db.add(a)
    await db.flush()
    return a


async def _register(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, group: str, driver: str = "bind9"
) -> uuid.UUID:
    monkeypatch.setenv("DNS_AGENT_KEY", "psk-1749")
    reg = await client.post(
        "/api/v1/dns/agents/register",
        headers={"X-DNS-Agent-Key": "psk-1749"},
        json={
            "hostname": HOST,
            "fingerprint": f"fp-{uuid.uuid4().hex[:8]}",
            "driver": driver,
            "roles": ["authoritative"],
            "agent_id": str(uuid.uuid4()),
            "group_name": group,
        },
    )
    assert reg.status_code == 200, reg.text
    return uuid.UUID(reg.json()["server_id"])


async def _move(client, token, db, src, srv_id, dst):  # noqa: ANN001, ANN202
    await db.commit()
    resp = await client.put(
        _url(src.id, srv_id), json={"group_id": str(dst.id)}, headers=_auth(token)
    )
    assert resp.status_code == 200, resp.text
    db.expire_all()


class _G:
    """Just an id, for ``_move`` after the session was expired."""

    def __init__(self, id_: uuid.UUID) -> None:
        self.id = id_


async def _control(
    client, token, db, appliance_id, srv_id, src_id, dst_id, **changes
):  # noqa: ANN001, ANN202
    """Positive control: flip the one fact that made the case negative, move
    the server back, and require the repoint. Without it each negative test
    would also pass on code that never repoints anything."""
    row = await db.get(Appliance, appliance_id)
    assert row is not None
    row.assigned_dns_group_id = dst_id
    for k, v in changes.items():
        setattr(row, k, v)
    await db.commit()
    await _move(client, token, db, _G(dst_id), srv_id, _G(src_id))
    row = await db.get(Appliance, appliance_id)
    assert row is not None and row.assigned_dns_group_id == src_id, "control: must repoint"


@pytest.mark.asyncio
async def test_move_repoints_the_appliance_found_by_hostname_and_wakes_it(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    wake = AsyncMock()
    monkeypatch.setattr("app.core.agent_wake.publish_wake", wake)
    token = await _superadmin(db_session, "root1749a")
    src = await _group(db_session, "default")
    dst = await _group(db_session, "internal")
    appliance = await _appliance(db_session, src)
    await db_session.commit()
    srv_id = await _register(client, monkeypatch, "default")
    srv = await db_session.get(DNSServer, srv_id)
    assert srv is not None and srv.appliance_id is None
    aid, dst_id = appliance.id, dst.id

    await _move(client, token, db_session, src, srv_id, dst)

    appliance = await db_session.get(Appliance, aid)
    assert appliance is not None and appliance.assigned_dns_group_id == dst_id
    woken = {c for call in wake.await_args_list for c in call.args}
    assert appliance_channel(aid) in woken


@pytest.mark.asyncio
async def test_move_leaves_an_appliance_assigned_elsewhere_alone_by_hostname(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _superadmin(db_session, "root1749b")
    src = await _group(db_session, "default")
    dst = await _group(db_session, "internal")
    elsewhere = await _group(db_session, "elsewhere")
    await db_session.commit()
    # Registered before the appliance points elsewhere: an appliance's agent
    # with no row registers into the appliance's group, not AGENT_GROUP (#2190).
    srv_id = await _register(client, monkeypatch, "default")
    appliance = await _appliance(db_session, elsewhere)
    await db_session.commit()
    aid, elsewhere_id = appliance.id, elsewhere.id
    src_id, dst_id = src.id, dst.id

    await _move(client, token, db_session, src, srv_id, dst)

    appliance = await db_session.get(Appliance, aid)
    assert appliance is not None and appliance.assigned_dns_group_id == elsewhere_id
    await _control(client, token, db_session, aid, srv_id, src_id, dst_id)


@pytest.mark.asyncio
async def test_move_of_a_stale_old_engine_row_does_not_repoint(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The appliance now runs technitium; the leftover bind9 row in its group
    is not what AGENT_GROUP drives, so moving it must not drag the pointer."""
    token = await _superadmin(db_session, "root1749c")
    src = await _group(db_session, "default")
    dst = await _group(db_session, "internal")
    appliance = await _appliance(db_session, src, roles=["dns-technitium"])
    await db_session.commit()
    srv_id = await _register(client, monkeypatch, "default", driver="bind9")
    aid, src_id, dst_id = appliance.id, src.id, dst.id

    await _move(client, token, db_session, src, srv_id, dst)

    appliance = await db_session.get(Appliance, aid)
    assert appliance is not None and appliance.assigned_dns_group_id == src_id
    await _control(
        client, token, db_session, aid, srv_id, src_id, dst_id, assigned_roles=["dns-bind9"]
    )


@pytest.mark.asyncio
async def test_move_does_not_repoint_when_two_appliances_share_the_hostname(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _superadmin(db_session, "root1749d")
    src = await _group(db_session, "default")
    dst = await _group(db_session, "internal")
    a1 = await _appliance(db_session, src)
    a2 = await _appliance(db_session, src, hostname=HOST.upper())
    await db_session.commit()
    srv_id = await _register(client, monkeypatch, "default")
    ids, src_id, dst_id = (a1.id, a2.id), src.id, dst.id

    await _move(client, token, db_session, src, srv_id, dst)

    for i in ids:
        row = await db_session.get(Appliance, i)
        assert row is not None and row.assigned_dns_group_id == src_id
    other = await db_session.get(Appliance, ids[1])
    assert other is not None
    other.hostname = "renamed-1749"  # no longer ambiguous
    await _control(client, token, db_session, ids[0], srv_id, src_id, dst_id)


# ── Follow-through to the supervisor's render ───────────────────────────────


@pytest.mark.asyncio
async def test_move_reaches_the_role_assignment_render(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What the supervisor is actually handed after the move: AGENT_GROUP (the
    group name) and the #50 DoT port come from the NEW group, not the old."""
    from app.api.v1.appliance.supervisor import _build_role_assignment
    from app.core.crypto import encrypt_str
    from app.models.appliance import ApplianceCertificate
    from app.models.dns import DNSServerOptions

    token = await _superadmin(db_session, "root1749e")
    src = await _group(db_session, "default")
    dst = await _group(db_session, "internal")
    cert = ApplianceCertificate(
        name=f"c-{uuid.uuid4().hex[:6]}",
        source="upload",
        cert_pem="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        key_encrypted=encrypt_str("k"),
        subject_cn="dns.example.test",
        sans_json=["dns.example.test"],
    )
    db_session.add(cert)
    await db_session.flush()
    db_session.add(
        DNSServerOptions(
            group_id=dst.id, dot_enabled=True, dot_port=8853, tls_certificate_id=cert.id
        )
    )
    appliance = await _appliance(db_session, src)
    await db_session.commit()
    srv_id = await _register(client, monkeypatch, "default")
    aid, dst_id = appliance.id, dst.id

    before = await _build_role_assignment(db_session, appliance)
    assert before.dns_group_name == "default" and before.dns_encrypted_tcp_ports == []

    await _move(client, token, db_session, src, srv_id, dst)

    appliance = await db_session.get(Appliance, aid)
    assert appliance is not None
    after = await _build_role_assignment(db_session, appliance)
    assert after.dns_group_id == dst_id
    assert after.dns_group_name == "internal"
    assert after.dns_encrypted_tcp_ports == [8853]


# ── DHCP: the same reverse-direction gap on the DHCP server PUT ─────────────


async def _dhcp_setup(db: AsyncSession, roles: list[str]):  # noqa: ANN202
    from app.models.dhcp import DHCPServerGroup

    src = DHCPServerGroup(name=f"dsrc-{uuid.uuid4().hex[:6]}")
    dst = DHCPServerGroup(name=f"ddst-{uuid.uuid4().hex[:6]}")
    db.add_all([src, dst])
    await db.flush()
    a = Appliance(
        hostname=HOST,
        public_key_der=b"\x00" * 32,
        public_key_fingerprint=f"fp-{uuid.uuid4().hex}",
        state="approved",
        assigned_roles=roles,
        assigned_dhcp_group_id=src.id,
    )
    db.add(a)
    await db.flush()
    return src, dst, a


async def _dhcp_register(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, group: str
) -> uuid.UUID:
    monkeypatch.setenv("DHCP_AGENT_KEY", "psk-1749d")
    reg = await client.post(
        "/api/v1/dhcp/agents/register",
        headers={"X-DHCP-Agent-Key": "psk-1749d"},
        json={
            "hostname": HOST,
            "fingerprint": f"fp-{uuid.uuid4().hex[:8]}",
            "driver": "kea",
            "agent_id": str(uuid.uuid4()),
            "group_name": group,
        },
    )
    assert reg.status_code == 200, reg.text
    return uuid.UUID(reg.json()["server_id"])


async def _dhcp_move(client, token, db, srv_id, group_id) -> None:  # noqa: ANN001
    await db.commit()
    resp = await client.put(
        f"/api/v1/dhcp/servers/{srv_id}",
        json={"server_group_id": str(group_id) if group_id else None},
        headers=_auth(token),
    )
    assert resp.status_code == 200, resp.text
    db.expire_all()


@pytest.mark.asyncio
async def test_dhcp_move_repoints_the_appliance_and_publishes_its_wake(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.appliance.supervisor import _build_role_assignment
    from app.models.dhcp import DHCPServer

    wake = AsyncMock()
    monkeypatch.setattr("app.core.agent_wake.publish_wake", wake)
    token = await _superadmin(db_session, "root1749f")
    src, dst, appliance = await _dhcp_setup(db_session, ["dhcp"])
    src_name, dst_id, aid = src.name, dst.id, appliance.id
    await db_session.commit()
    srv_id = await _dhcp_register(client, monkeypatch, src_name)
    srv = await db_session.get(DHCPServer, srv_id)
    assert srv is not None and srv.appliance_id is None

    await _dhcp_move(client, token, db_session, srv_id, dst_id)

    appliance = await db_session.get(Appliance, aid)
    assert appliance is not None and appliance.assigned_dhcp_group_id == dst_id
    woken = {c for call in wake.await_args_list for c in call.args}
    assert appliance_channel(aid) in woken
    ra = await _build_role_assignment(db_session, appliance)
    assert ra.dhcp_group_id == dst_id


@pytest.mark.asyncio
async def test_dhcp_move_leaves_an_appliance_without_the_dhcp_role_alone(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = await _superadmin(db_session, "root1749g")
    src, dst, appliance = await _dhcp_setup(db_session, ["dns-bind9"])
    src_name, src_id, dst_id, aid = src.name, src.id, dst.id, appliance.id
    await db_session.commit()
    srv_id = await _dhcp_register(client, monkeypatch, src_name)

    await _dhcp_move(client, token, db_session, srv_id, dst_id)
    row = await db_session.get(Appliance, aid)
    assert row is not None and row.assigned_dhcp_group_id == src_id

    # Control: give it the role, point it at dst, move back -> repointed.
    row.assigned_roles = ["dhcp"]
    row.assigned_dhcp_group_id = dst_id
    await _dhcp_move(client, token, db_session, srv_id, src_id)
    row = await db_session.get(Appliance, aid)
    assert row is not None and row.assigned_dhcp_group_id == src_id, "control: must repoint"


@pytest.mark.asyncio
async def test_dhcp_clearing_the_group_does_not_clear_the_appliance(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A NULL group would idle the supervisor's DHCP role; a clear is not a move."""
    token = await _superadmin(db_session, "root1749h")
    src, _dst, appliance = await _dhcp_setup(db_session, ["dhcp"])
    src_name, src_id, aid = src.name, src.id, appliance.id
    await db_session.commit()
    srv_id = await _dhcp_register(client, monkeypatch, src_name)

    await _dhcp_move(client, token, db_session, srv_id, None)
    row = await db_session.get(Appliance, aid)
    assert row is not None and row.assigned_dhcp_group_id == src_id

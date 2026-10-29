"""An appliance-hosted Kea HA pair no longer needs ha_peer_url by hand (#2963)."""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.appliance.dhcp_group_move import move_appliance_dhcp_servers
from app.services.dhcp.ha_peer_autofill import (
    appliance_ha_address,
    autofill_group_ha_peer_urls,
)


def _appliance(db: AsyncSession, ips: list[str], node_ip: str | None = None) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        assigned_roles=["dhcp"],
        node_ips=ips,
        node_ip=node_ip,
    )
    db.add(a)
    return a


def _kea(
    db: AsyncSession, group: DHCPServerGroup, ap: Appliance | None, url: str = ""
) -> DHCPServer:
    s = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host=ap.hostname if ap else "10.9.9.9",
        port=67,
        server_group_id=group.id,
        agent_id=uuid.uuid4(),
        appliance_id=ap.id if ap else None,
        ha_peer_url=url,
    )
    db.add(s)
    return s


async def _group(db: AsyncSession, mode: str = "host") -> DHCPServerGroup:
    g = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="", network_mode=mode)
    db.add(g)
    await db.flush()
    return g


def test_address_prefers_ipv4_then_v6_then_node_ip() -> None:
    a = Appliance(node_ips=["fd00::5", "10.0.0.5"], node_ip=None)
    assert appliance_ha_address(a) == "10.0.0.5"
    assert appliance_ha_address(Appliance(node_ips=["fd00::5"], node_ip=None)) == "[fd00::5]"
    assert appliance_ha_address(Appliance(node_ips=[], node_ip="10.1.1.1")) == "10.1.1.1"
    assert appliance_ha_address(Appliance(node_ips=["junk"], node_ip=None)) is None


@pytest.mark.asyncio
async def test_pair_gets_urls_from_node_addresses(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    res = await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert len(res.filled) == 2
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"


@pytest.mark.asyncio
async def test_operator_set_url_is_never_overwritten(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1 = _kea(db_session, g, a1, url="http://203.0.113.7:9000/")
    s2 = _kea(db_session, g, a2)
    await db_session.flush()
    await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert s1.ha_peer_url == "http://203.0.113.7:9000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"


@pytest.mark.asyncio
async def test_bridged_group_is_left_manual(db_session: AsyncSession) -> None:
    g = await _group(db_session, "bridged")
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    res = await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert res.filled == [] and s1.ha_peer_url == "" and s2.ha_peer_url == ""


@pytest.mark.asyncio
async def test_lone_member_and_non_appliance_member_untouched(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1 = _appliance(db_session, ["10.0.0.5"])
    await db_session.flush()
    s1 = _kea(db_session, g, a1)
    await db_session.flush()
    assert (await autofill_group_ha_peer_urls(db_session, g.id, via="t")).filled == []
    assert s1.ha_peer_url == ""
    s2 = _kea(db_session, g, None)  # compose agent: no appliance
    await db_session.flush()
    await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == ""


@pytest.mark.asyncio
async def test_role_assignment_move_fills_urls(db_session: AsyncSession) -> None:
    from app.models.auth import User

    g = await _group(db_session)
    old = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1 = _kea(db_session, g, a1)
    s2 = _kea(db_session, old, a2)
    await db_session.flush()
    user = User(username="u2963", email="u@x.com", display_name="T", is_superadmin=True)
    await move_appliance_dhcp_servers(db_session, a2, g, user)
    assert s2.server_group_id == g.id
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"


@pytest.mark.asyncio
async def test_group_reports_members_missing_a_peer_url(db_session: AsyncSession) -> None:
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.api.v1.dhcp.server_groups import _group_to_response

    g = await _group(db_session)
    s1 = _kea(db_session, g, None, url="http://10.9.9.1:8000/")
    s2 = _kea(db_session, g, None)
    await db_session.commit()
    g2 = (
        await db_session.execute(
            select(DHCPServerGroup)
            .where(DHCPServerGroup.id == g.id)
            .options(selectinload(DHCPServerGroup.servers))
        )
    ).scalar_one()
    assert _group_to_response(g2).ha_peer_urls_missing == [s2.name]
    assert s1.name not in _group_to_response(g2).ha_peer_urls_missing


@pytest.mark.asyncio
async def test_standalone_group_is_never_filled(db_session: AsyncSession) -> None:
    """``standalone`` is the operator saying "no HA" (and the UI's default for
    a new group). The bundle renders the hook from the URLs alone, so a fill
    here would hand Kea ``mode: standalone`` — an invalid HA config."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.api.v1.dhcp.server_groups import _group_to_response

    g = await _group(db_session)
    g.mode = "standalone"
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    assert (await autofill_group_ha_peer_urls(db_session, g.id, via="t")).filled == []
    assert s1.ha_peer_url == "" and s2.ha_peer_url == ""
    await db_session.commit()
    g2 = (
        await db_session.execute(
            select(DHCPServerGroup)
            .where(DHCPServerGroup.id == g.id)
            .options(selectinload(DHCPServerGroup.servers))
        )
    ).scalar_one()
    assert _group_to_response(g2).ha_peer_urls_missing == []


@pytest.mark.asyncio
async def test_unapproved_appliance_is_not_used(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    a2.state = "pending_approval"
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    await autofill_group_ha_peer_urls(db_session, g.id, via="t")
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == ""


@pytest.mark.asyncio
async def test_resaving_roles_without_a_move_does_not_refill(db_session: AsyncSession) -> None:
    """Fleet PUT with the same group: nothing moves, so a URL the operator
    cleared to keep the pair from forming stays cleared."""
    from app.models.auth import User

    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    s1, s2 = _kea(db_session, g, a1), _kea(db_session, g, a2)
    await db_session.flush()
    user = User(username="u2963b", email="u2@x.com", display_name="T", is_superadmin=True)
    res = await move_appliance_dhcp_servers(db_session, a2, g, user)
    assert res.moved == []
    assert s1.ha_peer_url == "" and s2.ha_peer_url == ""


async def _register(client, hostname: str, group: str, agent_id: str):  # type: ignore[no-untyped-def]
    return await client.post(
        "/api/v1/dhcp/agents/register",
        headers={"X-DHCP-Agent-Key": "k2963"},
        json={
            "hostname": hostname,
            "fingerprint": "f",
            "driver": "kea",
            "group_name": group,
            "agent_id": agent_id,
        },
    )


@pytest.mark.asyncio
async def test_registration_fills_on_join_but_not_on_restart(
    client, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second appliance's agent registering is the membership change that
    makes a pair: both members are filled. An agent restart re-registers the
    same row and must not refill a URL the operator cleared since."""
    from sqlalchemy import select

    monkeypatch.setenv("DHCP_AGENT_KEY", "k2963")
    g = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.commit()
    h1, h2, gname, gid = a1.hostname, a2.hostname, g.name, g.id
    id1, id2 = str(uuid.uuid4()), str(uuid.uuid4())

    assert (await _register(client, h1, gname, id1)).status_code == 200
    assert (await _register(client, h2, gname, id2)).status_code == 200

    async def urls() -> dict[str, str]:
        db_session.expire_all()
        rows = (
            await db_session.execute(select(DHCPServer).where(DHCPServer.server_group_id == gid))
        ).scalars()
        return {r.name: r.ha_peer_url for r in rows}

    assert await urls() == {h1: "http://10.0.0.5:8000/", h2: "http://10.0.0.6:8000/"}

    # Operator clears one URL to break the pair; the agent then restarts.
    row = (await db_session.execute(select(DHCPServer).where(DHCPServer.name == h1))).scalar_one()
    row.ha_peer_url = ""
    await db_session.commit()
    assert (await _register(client, h1, gname, id1)).status_code == 200
    assert (await urls())[h1] == ""


async def _response(db_session: AsyncSession, gid: uuid.UUID):  # type: ignore[no-untyped-def]
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.api.v1.dhcp.server_groups import _group_to_response

    db_session.expire_all()
    g = (
        await db_session.execute(
            select(DHCPServerGroup)
            .where(DHCPServerGroup.id == gid)
            .options(selectinload(DHCPServerGroup.servers))
        )
    ).scalar_one()
    return _group_to_response(g)


@pytest.mark.asyncio
async def test_three_members_are_never_filled(db_session: AsyncSession) -> None:
    """A 3rd+ Kea member renders as a backup peer and roles follow id order,
    so filling could hand a live pair's primary role to a new server. Left to
    the operator, and reported with the reason."""
    g = await _group(db_session)
    aps = [_appliance(db_session, [f"10.0.0.{n}"]) for n in (5, 6, 7)]
    await db_session.flush()
    rows = [_kea(db_session, g, ap) for ap in aps]
    await db_session.flush()
    assert (await autofill_group_ha_peer_urls(db_session, g.id, via="t")).filled == []
    assert all(r.ha_peer_url == "" for r in rows)
    gid = g.id
    await db_session.commit()
    resp = await _response(db_session, gid)
    assert len(resp.ha_peer_urls_missing) == 3
    assert resp.ha_autofill_skipped_reason == "more_than_two_kea_members"


@pytest.mark.asyncio
async def test_member_joining_an_existing_pair_is_reported_not_filled(
    db_session: AsyncSession,
) -> None:
    from app.models.auth import User

    g = await _group(db_session)
    other = await _group(db_session)
    a1, a2, a3 = (_appliance(db_session, [f"10.0.0.{n}"]) for n in (5, 6, 7))
    await db_session.flush()
    s1 = _kea(db_session, g, a1, url="http://10.0.0.5:8000/")
    s2 = _kea(db_session, g, a2, url="http://10.0.0.6:8000/")
    s3 = _kea(db_session, other, a3)
    await db_session.flush()
    user = User(username="u2963c", email="u3@x.com", display_name="T", is_superadmin=True)
    res = await move_appliance_dhcp_servers(db_session, a3, g, user)
    assert len(res.moved) == 1
    assert s3.ha_peer_url == ""
    assert s1.ha_peer_url == "http://10.0.0.5:8000/"
    assert s2.ha_peer_url == "http://10.0.0.6:8000/"
    gid, s3name = g.id, s3.name
    await db_session.commit()
    resp = await _response(db_session, gid)
    assert resp.ha_peer_urls_missing == [s3name]
    assert resp.ha_autofill_skipped_reason == "more_than_two_kea_members"


@pytest.mark.asyncio
async def test_derivable_pair_reports_no_skip_reason(db_session: AsyncSession) -> None:
    g = await _group(db_session)
    s1 = _kea(db_session, g, None, url="http://10.9.9.1:8000/")
    _kea(db_session, g, None)
    gid = g.id
    await db_session.commit()
    resp = await _response(db_session, gid)
    assert len(resp.ha_peer_urls_missing) == 1 and s1.name not in resp.ha_peer_urls_missing
    assert resp.ha_autofill_skipped_reason is None


@pytest.mark.asyncio
async def test_preflight_counts_an_autofilled_pair_and_not_a_three_member_group(
    db_session: AsyncSession,
) -> None:
    """``kea_ha_version_skew`` (#637 / #2195) mirrors the renderer: an
    autofilled appliance pair IS an HA pair; a group whose 3rd member was left
    URL-less is not, exactly as the bundle renders it."""
    from app.services.upgrades.preflight import check_kea_ha_version_skew

    pair = await _group(db_session)
    a1, a2 = _appliance(db_session, ["10.0.0.5"]), _appliance(db_session, ["10.0.0.6"])
    await db_session.flush()
    _kea(db_session, pair, a1).kea_version = "2.6.5"
    _kea(db_session, pair, a2).kea_version = "2.6.5"
    await db_session.flush()
    assert len((await autofill_group_ha_peer_urls(db_session, pair.id, via="t")).filled) == 2
    pair_name = pair.name
    await db_session.commit()
    r = await check_kea_ha_version_skew()
    assert r.level == "warn"
    assert pair_name in r.detail["pre_3_0"]

    trio = await _group(db_session)
    b = [_appliance(db_session, [f"10.1.0.{n}"]) for n in (5, 6, 7)]
    await db_session.flush()
    for ap in b:
        _kea(db_session, trio, ap).kea_version = "2.6.5"
    await db_session.flush()
    assert (await autofill_group_ha_peer_urls(db_session, trio.id, via="t")).filled == []
    trio_name = trio.name
    await db_session.commit()
    r = await check_kea_ha_version_skew()
    assert trio_name not in r.detail.get("pre_3_0", [])

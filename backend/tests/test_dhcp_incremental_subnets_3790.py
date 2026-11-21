"""Incremental subnet apply on a Kea HA pair (#3790): the bundle's permission
block, the ordering input and the heartbeat report."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.agents import _record_applied_subnet_ids
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.services.dhcp.config_bundle import INCREMENTAL_CAPABILITY, build_config_bundle

CAP = [INCREMENTAL_CAPABILITY]


async def _group(db: AsyncSession, mode: str, n: int = 2):
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="", mode=mode)
    db.add(grp)
    await db.flush()
    srvs = []
    for i in range(n):
        s = DHCPServer(
            name=f"s{i}-{uuid.uuid4().hex[:5]}",
            driver="kea",
            host=f"10.0.0.{i + 1}",
            port=67,
            server_group_id=grp.id,
            ha_peer_url=f"http://s{i}:8000/",
            agent_capabilities=list(CAP),
            applied_subnet_ids=[1, 2],
            last_health_check_at=datetime.now(UTC),
        )
        db.add(s)
        srvs.append(s)
    await db.flush()
    await db.refresh(grp, ["servers"])
    srvs.sort(key=lambda s: str(s.id))  # primary = first by id
    return grp, srvs


@pytest.mark.asyncio
async def test_hot_standby_members_get_role_and_partner_set(db_session: AsyncSession) -> None:
    _g, (primary, standby) = await _group(db_session, "hot-standby")
    primary.applied_subnet_ids = [1, 2, 3]
    standby.applied_subnet_ids = [1, 2]
    pb = await build_config_bundle(db_session, primary)
    sb = await build_config_bundle(db_session, standby)
    assert pb.incremental == {
        "ok": True,
        "role": "primary",
        "partner_applied_subnet_ids": [1, 2],
    }
    assert sb.incremental == {
        "ok": True,
        "role": "standby",
        "partner_applied_subnet_ids": [1, 2, 3],
    }


@pytest.mark.asyncio
async def test_partner_report_changes_the_etag(db_session: AsyncSession) -> None:
    _g, (primary, standby) = await _group(db_session, "hot-standby")
    before = (await build_config_bundle(db_session, primary)).etag
    standby.applied_subnet_ids = [1, 2, 9]
    assert (await build_config_bundle(db_session, primary)).etag != before


@pytest.mark.asyncio
async def test_load_balancing_keeps_full_reload(db_session: AsyncSession) -> None:
    _g, (a, _b) = await _group(db_session, "load-balancing")
    assert (await build_config_bundle(db_session, a)).incremental is None


@pytest.mark.asyncio
async def test_three_member_group_keeps_full_reload(db_session: AsyncSession) -> None:
    _g, members = await _group(db_session, "hot-standby", n=3)
    assert (await build_config_bundle(db_session, members[0])).incremental is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "what", ["no_capability", "partner_no_capability", "partner_unreported", "partner_stale"]
)
async def test_no_permission_when_the_pair_cannot_be_ordered(
    db_session: AsyncSession, what: str
) -> None:
    _g, (primary, standby) = await _group(db_session, "hot-standby")
    if what == "no_capability":
        primary.agent_capabilities = []
    elif what == "partner_no_capability":
        standby.agent_capabilities = []
    elif what == "partner_unreported":
        standby.applied_subnet_ids = None
    else:
        standby.last_health_check_at = datetime.now(UTC) - timedelta(minutes=10)
    assert (await build_config_bundle(db_session, primary)).incremental is None


@pytest.mark.asyncio
async def test_standalone_group_member_is_allowed_alone(db_session: AsyncSession) -> None:
    _g, (a, _b) = await _group(db_session, "standalone")
    assert (await build_config_bundle(db_session, a)).incremental == {
        "ok": True,
        "role": "standalone",
        "partner_applied_subnet_ids": None,
    }


@pytest.mark.asyncio
async def test_bundle_etag_unchanged_for_servers_that_do_not_use_it(
    db_session: AsyncSession,
) -> None:
    _g, (a, _b) = await _group(db_session, "standalone")
    a.agent_capabilities = []
    bundle = await build_config_bundle(db_session, a)
    assert bundle.incremental is None
    assert bundle.etag == bundle.compute_etag()


def test_record_applied_subnet_ids() -> None:
    s = DHCPServer(name="x", driver="kea", host="h", port=67)
    _record_applied_subnet_ids(s, None)
    assert s.applied_subnet_ids is None  # never reported stays UNKNOWN
    _record_applied_subnet_ids(s, [3, 1, 1])
    assert s.applied_subnet_ids == [1, 3]
    _record_applied_subnet_ids(s, [])
    assert s.applied_subnet_ids == []

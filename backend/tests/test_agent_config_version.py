"""The agent long-polls skip the bundle rebuild while nothing moved (#1109).

Two halves, and the second is the one that matters:

* an idle tick (the agent's etag is current, nothing was written) builds no
  bundle at all -- before, every tick of every parked agent assembled the whole
  bundle from the database to produce a 304;
* the version key MOVES for every table the bundle reads. A key that missed a
  contributor would freeze an agent's config while every surface reports
  converged, so this is parametrised over each contributor, backed by a guard
  that every table a real build touches is a probe, and by the safety interval
  that re-trusts nothing for long.
"""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp import agents as dhcp_agents
from app.api.v1.looking_glass import agents as lg_agents
from app.core.agent_wake import WakeResult
from app.main import app
from app.models.bgp_looking_glass import BGPLGPeer, LookingGlassCollector
from app.models.dhcp import (
    DHCPClientClass,
    DHCPMACBlock,
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPPool,
    DHCPPXEArchMatch,
    DHCPPXEProfile,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.feature_module import FeatureModule
from app.models.ipam import Subnet
from app.models.settings import PlatformSettings
from app.models.vlans import VLAN, Router
from app.services.agents.config_version import VersionCache
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.config_version import DHCP_CONFIG_PROBES, dhcp_config_version
from app.services.looking_glass.config_version import (
    LG_COLLECTOR_VOLATILE,
    LG_CONFIG_PROBES,
    LG_PEER_VOLATILE,
    lg_config_version,
)
from tests.conftest import _TestSessionLocal
from tests.test_dhcp_longpoll_wake_2040 import _estate as _dhcp_estate
from tests.test_dhcp_longpoll_wake_2040 import fresh_session_per_request  # noqa: F401
from tests.test_lg_longpoll_wake_2040 import _estate as _lg_estate


async def _rich_dhcp_estate(db: AsyncSession) -> dict[str, Any]:
    """The 2040 estate plus a row in every table the bundle reads."""
    ids = await _dhcp_estate(db)
    group, scope, subnet = ids["group"], ids["scope"], ids["subnet"]
    pool = DHCPPool(scope_id=scope, start_ip="10.9.1.10", end_ip="10.9.1.50", pool_type="dynamic")
    static = DHCPStaticAssignment(
        scope_id=scope, ip_address="10.9.1.5", mac_address="aa:bb:cc:00:00:01", hostname="h"
    )
    block = DHCPMACBlock(group_id=group, mac_address="aa:bb:cc:00:00:02", reason="other")
    pxe = DHCPPXEProfile(group_id=group, name="pxe", next_server="10.9.0.9")
    phone = DHCPPhoneProfile(group_id=group, name="phone")
    policy = DHCPDevicePolicy(
        group_id=group, name="pol", class_name="pol-class", device_classes=[], options={}
    )
    erl = EmergencyResponseLocation(name=f"erl-{uuid.uuid4().hex[:6]}")
    db.add_all([pool, static, block, pxe, phone, policy, erl])
    await db.flush()
    arch = DHCPPXEArchMatch(profile_id=pxe.id, boot_filename="a.efi")
    phone_scope = DHCPPhoneProfileScope(profile_id=phone.id, scope_id=scope)
    binding = ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=subnet)
    module = FeatureModule(id="network.e911", enabled=True)
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    router = Router(name=f"r-{uuid.uuid4().hex[:6]}")
    db.add(router)
    await db.flush()
    vlan = VLAN(router_id=router.id, vlan_id=10, name="v10")
    fingerprint = DHCPFingerprint(mac_address="aa:bb:cc:00:00:09", option_60="MSFT 5.0")
    db.add_all([arch, phone_scope, binding, module, vlan, fingerprint])
    await db.commit()
    return {
        **ids,
        "pool": pool.id,
        "static": static.id,
        "block": block.id,
        "pxe": pxe.id,
        "arch": arch.id,
        "phone": phone.id,
        "policy": policy.id,
        "erl": erl.id,
        "binding": binding.id,
        "router": router.id,
        "vlan": vlan.id,
    }


async def _key(db: AsyncSession, ids: dict[str, Any]) -> str:
    db.expire_all()
    server = await db.get(DHCPServer, ids["a"])
    assert server is not None
    key = await dhcp_config_version(db, server)
    await db.commit()
    return key


# ── every contributor moves the key ───────────────────────────────────────────


def _set(model: Any, id_key: str, **values: Any) -> Callable[[AsyncSession, dict[str, Any]], Any]:
    async def _do(db: AsyncSession, ids: dict[str, Any]) -> None:
        await db.execute(update(model).where(model.id == ids[id_key]).values(**values))

    return _do


async def _phone_scope_row(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.execute(
        update(DHCPPhoneProfileScope)
        .where(DHCPPhoneProfileScope.profile_id == ids["phone"])
        .values(scope_id=ids["scope"])
    )


async def _delete_pool(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.delete(await db.get(DHCPPool, ids["pool"]))


async def _expire_block(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.execute(
        update(DHCPMACBlock)
        .where(DHCPMACBlock.id == ids["block"])
        .values(expires_at=datetime.now(UTC) + timedelta(seconds=1))
    )


async def _fingerprint(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.execute(
        update(DHCPFingerprint)
        .where(DHCPFingerprint.mac_address == "aa:bb:cc:00:00:09")
        .values(option_55="1,3,6")
    )


async def _module(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.execute(update(FeatureModule).values(enabled=False))


async def _platform(db: AsyncSession, ids: dict[str, Any]) -> None:
    await db.execute(update(PlatformSettings).values(snmp_enabled=True))


async def _insert_scope_pool(db: AsyncSession, ids: dict[str, Any]) -> None:
    db.add(DHCPPool(scope_id=ids["scope"], start_ip="10.9.1.60", end_ip="10.9.1.70"))


Mutation = Callable[[AsyncSession, dict[str, Any]], Awaitable[None]]

#: table -> a write to it that changes (or could change) the rendered bundle.
CONTRIBUTORS: dict[str, Mutation] = {
    "dhcp_server_group": _set(DHCPServerGroup, "group", kea_thread_pool_size=9),
    "dhcp_server (peer url)": _set(DHCPServer, "b", ha_peer_url="http://10.9.0.77:8000/"),
    "dhcp_server (fleet column)": _set(DHCPServer, "a", desired_appliance_version="9.9.9"),
    "dhcp_server (maintenance)": _set(DHCPServer, "a", maintenance_mode=True),
    "dhcp_scope": _set(DHCPScope, "scope", lease_time=4242),
    "dhcp_pool (update)": _set(DHCPPool, "pool", end_ip="10.9.1.99"),
    "dhcp_pool (insert)": _insert_scope_pool,
    "dhcp_pool (delete)": _delete_pool,
    "dhcp_static_assignment": _set(DHCPStaticAssignment, "static", hostname="renamed"),
    "dhcp_client_class": _set(DHCPClientClass, "class", match_expression="option[60].hex == 0x09"),
    "dhcp_mac_block": _set(DHCPMACBlock, "block", enabled=False),
    "dhcp_mac_block (expiry set)": _expire_block,
    "dhcp_pxe_profile": _set(DHCPPXEProfile, "pxe", next_server="10.9.0.10"),
    "dhcp_pxe_arch_match": _set(DHCPPXEArchMatch, "arch", boot_filename="b.efi"),
    "dhcp_phone_profile": _set(DHCPPhoneProfile, "phone", name="phone2"),
    "dhcp_phone_profile_scope": _phone_scope_row,
    "dhcp_device_policy": _set(DHCPDevicePolicy, "policy", class_name="pol-class-2"),
    "subnet": _set(Subnet, "subnet", name="renamed-subnet"),
    "emergency_response_location": _set(EmergencyResponseLocation, "erl", name="erl-renamed"),
    "erl_binding": _set(ERLBinding, "binding", is_active=False),
    "dhcp_fingerprint": _fingerprint,
    "vlan": _set(VLAN, "vlan", name="v10-renamed"),
    "router": _set(Router, "router", name="router-renamed"),
    "feature_module": _module,
    "platform_settings": _platform,
}


@pytest.mark.parametrize("name", list(CONTRIBUTORS))
async def test_a_write_to_each_contributor_moves_the_dhcp_key(
    db_session: AsyncSession, name: str
) -> None:
    ids = await _rich_dhcp_estate(db_session)
    before = await _key(db_session, ids)
    assert await _key(db_session, ids) == before, "the key must be stable with no write"
    await CONTRIBUTORS[name](db_session, ids)
    await db_session.commit()
    assert await _key(db_session, ids) != before, f"a write to {name} left the key unmoved"


async def test_the_contributor_list_covers_every_probe_table() -> None:
    tested = {n.split(" ")[0] for n in CONTRIBUTORS}
    assert tested >= {p.name for p in DHCP_CONFIG_PROBES if not p.name.endswith("_live")}


async def test_an_expiring_mac_block_moves_the_key_with_no_write(db_session: AsyncSession) -> None:
    ids = await _rich_dhcp_estate(db_session)
    await db_session.execute(
        update(DHCPMACBlock)
        .where(DHCPMACBlock.id == ids["block"])
        .values(expires_at=datetime.now(UTC) + timedelta(seconds=2))
    )
    await db_session.commit()
    live = await _key(db_session, ids)
    await asyncio.sleep(2.5)
    assert (
        await _key(db_session, ids) != live
    ), "the bundle drops an expired block; the key must too"


async def test_agent_reports_do_not_move_the_dhcp_key(db_session: AsyncSession) -> None:
    ids = await _rich_dhcp_estate(db_session)
    before = await _key(db_session, ids)
    await db_session.execute(
        update(DHCPFingerprint).values(last_seen_at=datetime.now(UTC) + timedelta(hours=1))
    )
    await db_session.execute(
        update(DHCPServer)
        .where(DHCPServer.id == ids["a"])
        .values(
            agent_last_seen=datetime.now(UTC),
            last_seen_ip="10.9.0.1",
            status="active",
            ha_state="normal",
            config_apply_status="applied",
            spool_status={"x": 1},
            daemon_status="running",
        )
    )
    await db_session.commit()
    assert await _key(db_session, ids) == before


# ── the guard: every table a real build reads is a probe ─────────────────────


def _tables_in(sql: str) -> set[str]:
    return {
        m.group(1)
        for m in re.finditer(r'(?:FROM|JOIN)\s+"?([a-z_][a-z0-9_]*)"?', sql, flags=re.IGNORECASE)
    }


#: Read by the build but not a contributor: no row of these changes what ships.
NOT_CONFIG: set[str] = set()


async def test_every_table_a_dhcp_build_reads_is_probed(db_session: AsyncSession) -> None:
    ids = await _rich_dhcp_estate(db_session)
    seen: set[str] = set()
    engine = db_session.bind.sync_engine  # type: ignore[union-attr]

    def _capture(conn: Any, cursor: Any, statement: str, *a: Any) -> None:
        seen.update(_tables_in(statement))

    event.listen(engine, "before_cursor_execute", _capture)
    try:
        db_session.expire_all()
        server = await db_session.get(DHCPServer, ids["a"])
        assert server is not None
        await build_config_bundle(db_session, server)
    finally:
        event.remove(engine, "before_cursor_execute", _capture)
    probed = {p.name for p in DHCP_CONFIG_PROBES}
    missing = seen - probed - NOT_CONFIG - {"pg_catalog"}
    assert not missing, f"the bundle reads {sorted(missing)} but the version key does not"


# ── an idle tick builds nothing ───────────────────────────────────────────────


class _IdleWake:
    """``idle`` no-change wakes, then the test fires one after its edit."""

    def __init__(self, idle: int) -> None:
        self.idle = idle
        self.parked = asyncio.Event()
        self.fire = asyncio.Event()
        self.waits = 0

    async def wait(self, timeout: float) -> WakeResult:
        self.waits += 1
        if self.waits <= self.idle:
            return WakeResult.WAKE
        if self.waits == self.idle + 1:
            self.parked.set()
            await asyncio.wait_for(self.fire.wait(), timeout=timeout)
            return WakeResult.WAKE
        await asyncio.sleep(timeout)
        return WakeResult.TIMEOUT


async def _idle_then_edit(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    build_name: str,
    url: str,
    headers: dict[str, str],
    edit: Callable[[AsyncSession], Awaitable[None]],
    idle: int = 4,
) -> tuple[int, int, int]:
    """(builds in the idle ticks, builds in total, status of the poll after the edit)."""
    fake = _IdleWake(idle)

    @asynccontextmanager
    async def _subscription(_channels: Any) -> AsyncIterator[_IdleWake]:
        yield fake

    real = getattr(module, build_name)
    builds = {"n": 0}

    async def _counting(*args: Any, **kwargs: Any) -> Any:
        builds["n"] += 1
        return await real(*args, **kwargs)

    monkeypatch.setattr(module, "wake_subscription", _subscription)
    monkeypatch.setattr(module, "LONGPOLL_TIMEOUT_SECONDS", 6)
    monkeypatch.setattr(module, build_name, _counting)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        first = await ac.get(url, headers=headers)
        assert first.status_code == 200, first.text
        etag = first.json()["etag"]
        builds["n"] = 0
        poll = asyncio.create_task(ac.get(url, headers={**headers, "If-None-Match": f'"{etag}"'}))
        await asyncio.wait_for(fake.parked.wait(), timeout=10)
        idle_builds = builds["n"]
        async with _TestSessionLocal() as other:
            await edit(other)
            await other.commit()
        fake.fire.set()
        resp = await asyncio.wait_for(poll, timeout=20)
    return idle_builds, builds["n"], resp.status_code


async def test_an_idle_dhcp_poll_builds_no_bundle_and_still_sees_an_edit(
    db_session: AsyncSession,
    fresh_session_per_request: None,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _rich_dhcp_estate(db_session)
    dhcp_agents._BUNDLE_VERSIONS.clear()

    async def edit(other: AsyncSession) -> None:
        await other.execute(
            update(DHCPScope).where(DHCPScope.id == ids["scope"]).values(lease_time=1234)
        )

    idle_builds, total, status = await _idle_then_edit(
        monkeypatch,
        dhcp_agents,
        "build_config_bundle",
        "/api/v1/dhcp/agents/config",
        {"Authorization": f"Bearer {ids['token']}"},
        edit,
    )
    assert idle_builds == 0, f"{idle_builds} bundle build(s) across idle ticks that changed nothing"
    assert status == 200, "the poll must still answer the edit that landed after the idle ticks"
    assert total == 1


async def test_an_idle_lg_poll_builds_no_bundle_and_still_sees_an_edit(
    db_session: AsyncSession,
    fresh_session_per_request: None,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _lg_estate(db_session)
    lg_agents._BUNDLE_VERSIONS.clear()

    async def edit(other: AsyncSession) -> None:
        await other.execute(
            update(BGPLGPeer).where(BGPLGPeer.id == ids["peer"]).values(peer_asn=65099)
        )

    idle_builds, total, status = await _idle_then_edit(
        monkeypatch,
        lg_agents,
        "build_lg_config_bundle",
        "/api/v1/looking-glass/agents/config",
        {"Authorization": f"Bearer {ids['token']}"},
        edit,
    )
    assert idle_builds == 0, f"{idle_builds} bundle build(s) across idle ticks that changed nothing"
    assert status == 200
    assert total == 1


async def test_a_dhcp_poll_with_a_pending_op_is_still_answered_when_idle(
    db_session: AsyncSession,
    fresh_session_per_request: None,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The skip never swallows the ops queue."""
    from app.models.dhcp import DHCPConfigOp

    ids = await _rich_dhcp_estate(db_session)
    dhcp_agents._BUNDLE_VERSIONS.clear()

    async def edit(other: AsyncSession) -> None:
        other.add(
            DHCPConfigOp(
                server_id=ids["a"], op_type="apply_config", payload={"x": 1}, status="pending"
            )
        )

    _idle, _total, status = await _idle_then_edit(
        monkeypatch,
        dhcp_agents,
        "build_config_bundle",
        "/api/v1/dhcp/agents/config",
        {"Authorization": f"Bearer {ids['token']}"},
        edit,
        idle=2,
    )
    assert status == 200


# ── looking glass key ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda ids: update(BGPLGPeer).where(BGPLGPeer.id == ids["peer"]).values(peer_asn=1),
            id="peer-asn",
        ),
        pytest.param(
            lambda ids: update(BGPLGPeer).where(BGPLGPeer.id == ids["peer"]).values(enabled=False),
            id="peer-enabled",
        ),
        pytest.param(
            lambda ids: update(BGPLGPeer)
            .where(BGPLGPeer.id == ids["peer"])
            .values(md5_password_encrypted=b"x"),
            id="peer-md5",
        ),
        pytest.param(
            lambda ids: update(BGPLGPeer)
            .where(BGPLGPeer.id == ids["peer"])
            .values(import_filter={"mode": "scope"}),
            id="peer-filter",
        ),
        pytest.param(
            lambda ids: update(LookingGlassCollector)
            .where(LookingGlassCollector.id == ids["collector"])
            .values(enabled=False),
            id="collector-enabled",
        ),
        pytest.param(
            lambda ids: update(LookingGlassCollector)
            .where(LookingGlassCollector.id == ids["collector"])
            .values(name="renamed"),
            id="collector-name",
        ),
    ],
)
async def test_a_write_to_each_lg_contributor_moves_the_key(
    db_session: AsyncSession, mutate: Callable[[dict[str, Any]], Any]
) -> None:
    ids = await _lg_estate(db_session)

    async def key() -> str:
        db_session.expire_all()
        col = await db_session.get(LookingGlassCollector, ids["collector"])
        assert col is not None
        k = await lg_config_version(db_session, col)
        await db_session.commit()
        return k

    before = await key()
    assert await key() == before
    await db_session.execute(mutate(ids))
    await db_session.commit()
    assert await key() != before


async def test_an_lg_heartbeat_report_does_not_move_the_key(db_session: AsyncSession) -> None:
    ids = await _lg_estate(db_session)

    async def key() -> str:
        db_session.expire_all()
        col = await db_session.get(LookingGlassCollector, ids["collector"])
        assert col is not None
        k = await lg_config_version(db_session, col)
        await db_session.commit()
        return k

    before = await key()
    await db_session.execute(
        update(BGPLGPeer)
        .where(BGPLGPeer.id == ids["peer"])
        .values(session_state="established", prefixes_received=5, prefixes_accepted=5)
    )
    await db_session.execute(
        update(LookingGlassCollector)
        .where(LookingGlassCollector.id == ids["collector"])
        .values(last_seen_at=datetime.now(UTC), status="active")
    )
    await db_session.commit()
    assert await key() == before


def test_the_volatile_column_lists_name_real_columns() -> None:
    from app.services.dhcp.config_version import DHCP_SERVER_VOLATILE

    for model, names in (
        (DHCPServer, DHCP_SERVER_VOLATILE),
        (BGPLGPeer, LG_PEER_VOLATILE),
        (LookingGlassCollector, LG_COLLECTOR_VOLATILE),
    ):
        cols = set(model.__table__.columns.keys())
        assert set(names) <= cols, f"{model.__name__}: {sorted(set(names) - cols)}"
    assert {p.name for p in LG_CONFIG_PROBES} == {"looking_glass_collector", "bgp_lg_peer"}


# ── the safety interval ───────────────────────────────────────────────────────


def test_a_cached_etag_is_not_trusted_past_the_safety_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache = VersionCache(max_age=300.0)
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    cache.store("srv", "k1", "sha256:abc")
    assert cache.hit("srv", "k1", '"sha256:abc"') is not None
    assert cache.hit("srv", "k2", '"sha256:abc"') is None, "a moved key rebuilds"
    assert cache.hit("srv", "k1", '"sha256:other"') is None, "an agent on another etag gets a build"
    now[0] += 301.0
    assert cache.hit("srv", "k1", '"sha256:abc"') is None, "past the interval it rebuilds anyway"


def test_every_model_the_dhcp_bundle_module_imports_is_probed() -> None:
    """The runtime capture only sees queries an estate happens to trigger; this
    covers the models ``config_bundle`` names, whether or not a build used them."""
    from app.models.base import Base
    from app.services.dhcp import config_bundle

    tables = {
        v.__tablename__
        for v in vars(config_bundle).values()
        if isinstance(v, type) and issubclass(v, Base) and hasattr(v, "__tablename__")
    }
    assert tables, "the module's models were not found"
    missing = tables - {p.name for p in DHCP_CONFIG_PROBES}
    assert not missing, f"config_bundle names {sorted(missing)} but the version key does not"

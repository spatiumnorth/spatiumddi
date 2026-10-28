"""A crash-looping DNS / DHCP container raises an alert whatever the kubelet
calls the cause, and a silent agent no longer reads ``ok`` (#2961, #2962).

Found drilling #2188: dhcp-kea was memcg-killed six times in four minutes and
the kubelet recorded ``reason: Error`` / exit 137, not ``OOMKilled``. The row
read ``unreachable`` beside a stale ``daemon_status=ok``, the supervisor's
``role_health`` read ``unhealthy`` with six restarts, and no alert fired.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPServer
from app.services.agents.container_oom import (
    agent_silent_report,
    container_crash_loop_report,
    reason_source,
)
from app.services.agents.daemon_state import (
    STATUS_DEGRADED,
    STATUS_OK,
    forget_stale_ok,
    is_not_serving,
)
from app.services.alerts import _matching_agent_daemon_degraded_subjects
from tests.test_dhcp_container_oom_2023 import (
    _agent_hb,
    _appliance,
    _iso,
    _kea_server,
    _reload,
    _role_health,
    _supervisor_hb,
)

_RULE = SimpleNamespace(severity="critical")


def _loop(
    now: datetime,
    *,
    restarts: int = 6,
    ended_ago: timedelta = timedelta(minutes=1),
    status: str = "unhealthy",
    running_since: datetime | None = None,
    reason: str = "Error",
) -> dict[str, Any]:
    rh = _role_health(
        killed_at=now - ended_ago,
        running_since=running_since,
        reason=reason,
        restarts=restarts,
    )
    rh["dhcp-kea"]["status"] = status
    rh["dhcp-kea"]["since"] = _iso(now - timedelta(minutes=6))
    return rh


def test_a_crash_loop_names_its_evidence() -> None:
    now = datetime.now(UTC)
    got = container_crash_loop_report(_loop(now), "kea", now)
    assert got is not None
    report, since = got
    assert report["status"] == STATUS_DEGRADED
    reason = report["reason"]
    assert reason.startswith("crash_loop:")
    assert "restarted 6 times" in reason
    assert "reason Error" in reason and "exit code 137" in reason
    assert since == (now - timedelta(minutes=6)).replace(microsecond=0)
    assert reason_source(reason) == "supervisor"


@pytest.mark.parametrize(
    "kw",
    [
        {"restarts": 1},  # one restart is not a loop
        {"restarts": 2},
        {"ended_ago": timedelta(hours=2)},  # old history
        {"status": "healthy"},  # settled pod
        {"reason": "OOMKilled"},  # the OOM verdict's, not this one's
    ],
)
def test_it_is_not_a_crash_loop(kw: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    assert container_crash_loop_report(_loop(now, **kw), "kea", now) is None


def test_a_container_that_has_stayed_up_is_not_a_crash_loop() -> None:
    now = datetime.now(UTC)
    rh = _loop(now, status="starting", running_since=now - timedelta(minutes=11))
    assert container_crash_loop_report(rh, "kea", now) is None
    assert container_crash_loop_report(_loop(now), "windows_dhcp", now) is None


def test_a_silent_agent_needs_the_threshold_and_a_manager() -> None:
    now = datetime.now(UTC)
    rh = _loop(now, status="healthy", restarts=1)
    assert agent_silent_report(rh, "kea", now - timedelta(seconds=60), now) is None
    assert agent_silent_report(rh, "kea", None, now) is None  # never reported: unknown
    assert agent_silent_report({}, "kea", now - timedelta(hours=1), now) is None
    got = agent_silent_report(rh, "kea", now - timedelta(minutes=4), now)
    assert got is not None
    assert got[0]["reason"].startswith("agent_unreachable:")
    assert "restarted 1 time," in got[0]["reason"]


async def test_a_crash_loop_fires_after_the_grace_and_recovery_resolves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-loop-1")
    server, headers = await _kea_server(db_session, host="ddi-loop-1", appliance_id=appliance.id)
    await db_session.commit()
    now = datetime.now(UTC).replace(microsecond=0)

    await _supervisor_hb(client, appliance, token, _loop(now))
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("crash_loop:")
    assert is_not_serving(row.daemon_status, row.daemon_reason) is True
    assert row.daemon_status_since == now - timedelta(minutes=6)

    # The restarted agent saying ``ok`` between crashes does not hide it.
    await _agent_hb(client, headers, {"status": "ok"})
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_DEGRADED

    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    hit = [m for m in matches if m[0] == f"dhcp_server:{server.id}"]
    assert len(hit) == 1
    msg = hit[0][2]
    assert "Supervisor reported: crash_loop:" in msg
    assert "The agent is heartbeating" not in msg and "Agent reported" not in msg

    # Not before the grace: a loop first seen 2 minutes ago is not yet an alert.
    early = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, now - timedelta(minutes=4)
    )
    assert f"dhcp_server:{server.id}" not in {m[0] for m in early}

    # Recovery: up for ten minutes, the agent's ``ok`` clears the row.
    appl = await db_session.get(type(appliance), appliance.id)
    assert appl is not None
    appl.role_health = _loop(
        now,
        status="healthy",
        running_since=now - timedelta(minutes=11),
        ended_ago=timedelta(minutes=30),
    )
    await db_session.commit()
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK and row.daemon_reason is None
    after = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    assert f"dhcp_server:{server.id}" not in {m[0] for m in after}


async def test_a_single_restart_raises_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-loop-2")
    server, headers = await _kea_server(db_session, host="ddi-loop-2", appliance_id=appliance.id)
    await db_session.commit()
    now = datetime.now(UTC)

    await _supervisor_hb(client, appliance, token, _loop(now, restarts=1))
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK
    matches = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, now + timedelta(minutes=30)
    )
    assert f"dhcp_server:{server.id}" not in {m[0] for m in matches}


async def test_unreachable_under_a_live_supervisor_fires_after_the_threshold(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-loop-3")
    now = datetime.now(UTC).replace(microsecond=0)
    server, headers = await _kea_server(
        db_session,
        host="ddi-loop-3",
        appliance_id=appliance.id,
        last_seen_at=now - timedelta(seconds=60),
    )
    await db_session.commit()
    rh = _loop(now, status="healthy", restarts=0)

    # 60 s of silence is a blip: nothing is written.
    await _supervisor_hb(client, appliance, token, rh)
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK

    # Past the threshold the supervisor's word replaces the stale ``ok``.
    silent_since = now - timedelta(minutes=6)
    srv = await db_session.get(DHCPServer, server.id)
    assert srv is not None
    srv.agent_last_seen = silent_since
    srv.status = "unreachable"
    await db_session.commit()
    await _supervisor_hb(client, appliance, token, rh)
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("agent_unreachable:")
    assert row.daemon_status_since == silent_since

    # The alert's grace runs from the start of the silence, and its wording
    # says the agent is NOT heartbeating.
    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    hit = [m for m in matches if m[0] == f"dhcp_server:{server.id}"]
    assert len(hit) == 1 and "The agent is not heartbeating" in hit[0][2]
    young = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, silent_since + timedelta(minutes=4)
    )
    assert f"dhcp_server:{server.id}" not in {m[0] for m in young}

    # The agent coming back says ``ok`` and the alert resolves.
    await _agent_hb(client, headers, {"status": "ok"})
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK
    after = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    assert f"dhcp_server:{server.id}" not in {m[0] for m in after}


async def test_a_paused_server_is_never_called_silent(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-loop-4")
    server, _h = await _kea_server(
        db_session,
        host="ddi-loop-4",
        appliance_id=appliance.id,
        last_seen_at=datetime.now(UTC) - timedelta(hours=1),
    )
    server.maintenance_mode = True
    await db_session.commit()
    await _supervisor_hb(
        client, appliance, token, _loop(datetime.now(UTC), status="healthy", restarts=0)
    )
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK


async def test_the_wording_follows_the_source(db_session: AsyncSession) -> None:
    """The agent's own report keeps its wording; a kubelet-sourced OOM says the
    supervisor reported it (#2962)."""
    from app.services.agents.container_oom import container_oom_report

    now = datetime.now(UTC).replace(microsecond=0)
    appliance, _t = await _appliance(db_session, "ddi-loop-5")
    own, _h = await _kea_server(db_session, host="ddi-loop-5")
    own.daemon_status = STATUS_DEGRADED
    own.daemon_reason = "oom_killed: Kea was killed for exceeding its memory limit"
    own.daemon_status_since = now - timedelta(minutes=9)
    kubelet, _h2 = await _kea_server(db_session, host="ddi-loop-6")
    rep = container_oom_report(
        _role_health(killed_at=now - timedelta(minutes=9), running_since=None), "kea", now
    )
    assert rep is not None
    kubelet.daemon_status = STATUS_DEGRADED
    kubelet.daemon_reason = rep[0]["reason"]
    kubelet.daemon_status_since = now - timedelta(minutes=9)
    await db_session.commit()

    assert reason_source(own.daemon_reason) == "agent"
    assert reason_source(kubelet.daemon_reason) == "supervisor"
    matches = {
        m[0]: m[2] for m in await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    }
    assert "Agent reported: oom_killed:" in matches[f"dhcp_server:{own.id}"]
    assert "The agent is heartbeating" in matches[f"dhcp_server:{own.id}"]
    km = matches[f"dhcp_server:{kubelet.id}"]
    assert "Supervisor reported: oom_killed:" in km
    assert "The agent is heartbeating" not in km and "Agent reported" not in km


def test_forget_stale_ok_keeps_everything_but_ok() -> None:
    srv = SimpleNamespace(
        daemon_status=STATUS_OK, daemon_reason=None, daemon_status_since=datetime.now(UTC)
    )
    assert forget_stale_ok(srv) is True
    assert srv.daemon_status is None and srv.daemon_status_since is None
    assert is_not_serving(srv.daemon_status, srv.daemon_reason) is None
    bad = SimpleNamespace(daemon_status="degraded", daemon_reason="x", daemon_status_since=None)
    assert forget_stale_ok(bad) is False and bad.daemon_status == "degraded"


async def test_the_health_sweeps_no_longer_leave_a_stale_ok(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    import contextlib

    from app.models.dns import DNSServer, DNSServerGroup
    from app.tasks import dhcp_health
    from app.tasks import dns as dns_tasks

    class _Eng:
        async def dispose(self) -> None:
            return None

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    now = datetime.now(UTC)
    # DHCP, agent-based.
    kea, _h = await _kea_server(
        db_session, host="ddi-loop-7", last_seen_at=now - timedelta(minutes=10)
    )
    kea.status = "active"
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    db_session.add(group)
    await db_session.flush()
    dns = DNSServer(
        group_id=group.id,
        name="s1",
        driver="bind9",
        host="192.0.2.53",
        port=53,
        status="active",
        last_seen_at=now - timedelta(minutes=10),
        daemon_status=STATUS_OK,
        daemon_status_since=now - timedelta(hours=1),
    )
    db_session.add(dns)
    await db_session.commit()

    monkeypatch.setattr(dhcp_health, "create_async_engine", lambda *a, **kw: _Eng())
    monkeypatch.setattr(dhcp_health, "async_sessionmaker", lambda *a, **kw: _cm)
    await dhcp_health._check_health(kea.id)
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _Eng())
    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    await dns_tasks._dns_agent_stale_sweep_async()

    db_session.expunge_all()
    kea2 = await db_session.get(DHCPServer, kea.id)
    dns2 = await db_session.get(DNSServer, dns.id)
    assert kea2 is not None and dns2 is not None
    assert kea2.status == "unreachable" and kea2.daemon_status is None
    assert dns2.status == "unreachable" and dns2.daemon_status is None

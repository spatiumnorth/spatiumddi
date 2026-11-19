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
    HEARD_SINCE_KEY,
    RESTART_HISTORY_KEY,
    agent_silent_report,
    carry_restart_history,
    container_crash_loop_report,
    container_verdict,
    daemon_reported_by,
    reason_source,
    restarts_in_window,
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


def _history(*points: tuple[datetime, int]) -> list[dict[str, Any]]:
    return [{"at": _iso(at), "n": n} for at, n in points]


def _loop(
    now: datetime,
    *,
    restarts: int = 7,
    ended_ago: timedelta = timedelta(minutes=1),
    status: str = "unhealthy",
    running_since: datetime | None = None,
    reason: str = "Error",
    history: list[tuple[datetime, int]] | None = None,
) -> dict[str, Any]:
    """A role_health entry as stored after the backend has watched it.
    ``history`` defaults to the #2188 drill: count 1 before the window, then
    six restarts in four minutes."""
    rh = _role_health(killed_at=now - ended_ago, running_since=running_since, reason=reason)
    entry = rh["dhcp-kea"]
    entry["status"] = status
    entry["since"] = _iso(now - timedelta(minutes=6))
    entry["container"]["restart_count"] = restarts
    if history is None:
        history = [
            (now - timedelta(minutes=20), 1),
            (now - timedelta(minutes=5), 3),
            (now - timedelta(minutes=4), 4),
            (now - timedelta(minutes=2), restarts),
        ]
    entry[RESTART_HISTORY_KEY] = _history(*history)
    return rh


async def _seed(db: AsyncSession, appliance: Any, rh: dict[str, Any]) -> None:
    """Store ``rh`` (with its history) as the appliance's last role_health,
    as earlier supervisor heartbeats would have left it."""
    appl = await db.get(type(appliance), appliance.id)
    assert appl is not None
    appl.role_health = rh
    await db.commit()


def test_a_crash_loop_names_its_evidence() -> None:
    now = datetime.now(UTC).replace(microsecond=0)
    got = container_crash_loop_report(_loop(now), "kea", now)
    assert got is not None
    report, since = got
    assert report["status"] == STATUS_DEGRADED
    reason = report["reason"]
    assert reason.startswith("crash_loop:")
    assert "6 restarts in the last 15 min" in reason
    assert "lifetime restart count 7" in reason
    assert "reason Error" in reason and "exit code 137" in reason
    # The grace runs from when it became a loop (the third restart seen).
    assert since == now - timedelta(minutes=4)
    assert reason_source(reason) == "supervisor"


@pytest.mark.parametrize(
    "kw",
    [
        # One restart in the window, whatever the lifetime count: a node
        # reboot / slot upgrade restarts every container on the node once.
        {"history": "reboot"},
        {"history": "two"},  # two restarts in the window
        {"history": "old"},  # three restarts, but before the window
        {"history": "first_sight"},  # never watched before: no baseline
        {"status": "healthy"},  # settled pod
        {"reason": "OOMKilled"},  # the OOM verdict's, not this one's
    ],
)
def test_it_is_not_a_crash_loop(kw: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    shapes = {
        "reboot": [(now - timedelta(minutes=40), 6), (now - timedelta(minutes=1), 7)],
        "two": [(now - timedelta(minutes=20), 5), (now - timedelta(minutes=3), 7)],
        "old": [(now - timedelta(minutes=40), 4), (now - timedelta(minutes=20), 7)],
        "first_sight": [(now - timedelta(minutes=1), 7)],
    }
    if "history" in kw:
        kw = {"history": shapes[kw["history"]]}
    assert container_crash_loop_report(_loop(now, **kw), "kea", now) is None


def test_a_reboot_of_a_container_with_a_high_lifetime_count_is_not_a_loop() -> None:
    """#2928 / #2945: lifetime restartCount grows with every reboot. Just after
    one, the container is restarted, recently ended and not yet ready (a big
    RPZ zone set may hold it in its startup probe for many minutes), with a
    lifetime count well above 3. That is one restart, not a loop."""
    now = datetime.now(UTC)
    rh = _loop(
        now,
        restarts=12,
        status="starting",
        running_since=now - timedelta(seconds=40),
        ended_ago=timedelta(minutes=1),
        history=[(now - timedelta(hours=3), 11), (now - timedelta(seconds=30), 12)],
    )
    for minutes in (0, 3, 6, 9):
        assert container_crash_loop_report(rh, "kea", now + timedelta(minutes=minutes)) is None
    # Nor is the agent "silent": its container started 40 s ago.
    assert container_verdict(rh, "kea", now - timedelta(minutes=5), now) is None


def test_an_oom_with_many_restarts_stays_an_oom() -> None:
    """A loop whose last termination the kubelet calls OOMKilled is the OOM
    verdict's, with its own advice, never a generic crash loop."""
    now = datetime.now(UTC)
    rh = _loop(now, reason="OOMKilled")
    got = container_verdict(rh, "kea", now - timedelta(minutes=10), now)
    assert got is not None
    assert got[0]["reason"].startswith("oom_killed:")
    assert container_crash_loop_report(rh, "kea", now) is None


def test_a_container_that_has_stayed_up_is_not_a_crash_loop() -> None:
    now = datetime.now(UTC)
    rh = _loop(now, status="starting", running_since=now - timedelta(minutes=11))
    assert container_crash_loop_report(rh, "kea", now) is None
    assert container_crash_loop_report(_loop(now), "windows_dhcp", now) is None


def test_restart_history_is_measured_across_heartbeats() -> None:
    t0 = datetime.now(UTC).replace(microsecond=0)

    def hb(count: int, *, pod: str = "dhcp-kea-abcde") -> dict[str, Any]:
        rh = _role_health(killed_at=t0, running_since=None, reason="Error")
        rh["dhcp-kea"]["container"]["restart_count"] = count
        rh["dhcp-kea"]["container_id"] = pod
        # Whatever the supervisor sends under the backend's key is dropped.
        rh["dhcp-kea"][RESTART_HISTORY_KEY] = _history((t0 - timedelta(hours=1), 0))
        return rh

    stored = carry_restart_history(None, hb(1), t0)
    assert stored["dhcp-kea"][RESTART_HISTORY_KEY] == _history((t0, 1))
    # An unchanged count (the watchdog snapshot is cached) adds nothing.
    stored = carry_restart_history(stored, hb(1), t0 + timedelta(seconds=30))
    assert len(stored["dhcp-kea"][RESTART_HISTORY_KEY]) == 1
    # The drill: six restarts in four minutes.
    for i, n in enumerate((3, 4, 7), start=1):
        stored = carry_restart_history(stored, hb(n), t0 + timedelta(minutes=i))
    stored["dhcp-kea"]["status"] = "unhealthy"
    assert restarts_in_window(stored, "kea", t0 + timedelta(minutes=3)) == (
        6,
        t0 + timedelta(minutes=2),
    )
    # Twenty minutes later the old points fall out of the window, the last
    # one before it kept as the baseline.
    later = t0 + timedelta(minutes=25)
    stored = carry_restart_history(stored, hb(7), later)
    assert restarts_in_window(stored, "kea", later) == (0, None)
    assert len(stored["dhcp-kea"][RESTART_HISTORY_KEY]) == 1
    # A new pod starts its own history (its count starts again at 0).
    stored = carry_restart_history(stored, hb(0, pod="dhcp-kea-fghij"), later)
    assert stored["dhcp-kea"][RESTART_HISTORY_KEY] == _history((later, 0))


def test_a_silent_agent_needs_the_threshold_and_a_manager() -> None:
    now = datetime.now(UTC)
    rh = _loop(now, status="healthy", restarts=1, history=[])
    assert agent_silent_report(rh, "kea", now - timedelta(seconds=60), now) is None
    assert agent_silent_report(rh, "kea", None, now) is None  # never reported: unknown
    assert agent_silent_report({}, "kea", now - timedelta(hours=1), now) is None
    got = agent_silent_report(rh, "kea", now - timedelta(minutes=4), now)
    assert got is not None
    assert got[0]["reason"].startswith("agent_unreachable:")
    assert "lifetime restart count 1," in got[0]["reason"]
    # The grace runs from the start of the silence the supervisor could see.
    assert got[1] == now - timedelta(minutes=4)
    # A supervisor whose heartbeats resumed two minutes ago has not watched
    # long enough to call the agent silent, however old its last heartbeat.
    rh["dhcp-kea"][HEARD_SINCE_KEY] = _iso(now - timedelta(minutes=2))
    assert agent_silent_report(rh, "kea", now - timedelta(minutes=30), now) is None
    rh["dhcp-kea"][HEARD_SINCE_KEY] = _iso(now - timedelta(minutes=3, seconds=30))
    got = agent_silent_report(rh, "kea", now - timedelta(minutes=30), now)
    assert got is not None and got[1] == (now - timedelta(minutes=3, seconds=30)).replace(
        microsecond=0
    )


def test_a_just_restarted_container_gets_the_whole_silence_threshold() -> None:
    """After a reboot or slot upgrade the agent's last heartbeat is from before
    the node went down; the restarted container's agent must get the whole
    threshold, counted from the container's start."""
    now = datetime.now(UTC)
    rh = _loop(now, status="starting", restarts=5, running_since=now - timedelta(seconds=90))
    assert agent_silent_report(rh, "kea", now - timedelta(minutes=12), now) is None
    rh2 = _loop(now, status="starting", restarts=5, running_since=now - timedelta(minutes=4))
    assert agent_silent_report(rh2, "kea", now - timedelta(minutes=12), now) is not None


async def test_a_crash_loop_fires_after_the_grace_and_recovery_resolves(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-loop-1")
    server, headers = await _kea_server(db_session, host="ddi-loop-1", appliance_id=appliance.id)
    await db_session.commit()
    now = datetime.now(UTC).replace(microsecond=0)

    # What the control plane has already watched: the drill's six restarts.
    await _seed(db_session, appliance, _loop(now))
    await _supervisor_hb(client, appliance, token, _loop(now))
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("crash_loop:")
    assert is_not_serving(row.daemon_status, row.daemon_reason) is True
    assert daemon_reported_by(row.daemon_status, row.daemon_reason) == "supervisor"
    assert row.daemon_status_since == now - timedelta(minutes=4)

    # The restarted agent saying ``ok`` between crashes does not hide it.
    await _agent_hb(client, headers, {"status": "ok"})
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_DEGRADED

    matches = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, now + timedelta(minutes=2)
    )
    hit = [m for m in matches if m[0] == f"dhcp_server:{server.id}"]
    assert len(hit) == 1
    msg = hit[0][2]
    assert "Supervisor reported: crash_loop:" in msg
    assert "The agent is heartbeating" not in msg and "Agent reported" not in msg

    # Not before the grace: a loop established 4 minutes ago is not an alert
    # one minute earlier.
    early = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, now - timedelta(minutes=1)
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
    after = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, now + timedelta(minutes=2)
    )
    assert f"dhcp_server:{server.id}" not in {m[0] for m in after}


async def test_a_single_restart_raises_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reboot shape over HTTP: a container with a lifetime count of 6 is
    restarted once (the node rebooted), ended a minute ago and is not ready
    yet. Nothing is stamped, whatever the lifetime count."""
    appliance, token = await _appliance(db_session, "ddi-loop-2")
    server, headers = await _kea_server(db_session, host="ddi-loop-2", appliance_id=appliance.id)
    await db_session.commit()
    now = datetime.now(UTC)
    before = _loop(now, restarts=6, history=[(now - timedelta(hours=2), 6)])
    await _seed(db_session, appliance, before)
    after = _loop(now, restarts=7, status="starting", running_since=now - timedelta(seconds=50))
    await _supervisor_hb(client, appliance, token, after)
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK
    appl = await db_session.get(type(appliance), appliance.id)
    assert appl is not None
    await db_session.refresh(appl)
    # The heartbeat recorded the one restart it saw (and dropped the history
    # the "supervisor" sent).
    hist = appl.role_health["dhcp-kea"][RESTART_HISTORY_KEY]
    assert [h["n"] for h in hist] == [6, 7]
    matches = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, now + timedelta(minutes=30)
    )
    assert f"dhcp_server:{server.id}" not in {m[0] for m in matches}


async def test_the_drill_over_successive_heartbeats(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#2188 case 4 as the control plane sees it: supervisor heartbeats whose
    restartCount climbs 1 -> 3 -> 4 -> 7. The third restart observed makes it
    a loop; the stamp is not written before it."""
    appliance, token = await _appliance(db_session, "ddi-loop-8")
    server, headers = await _kea_server(db_session, host="ddi-loop-8", appliance_id=appliance.id)
    await db_session.commit()
    now = datetime.now(UTC).replace(microsecond=0)
    await _seed(
        db_session, appliance, _loop(now, restarts=1, history=[(now - timedelta(minutes=20), 1)])
    )

    seen: list[str | None] = []
    for n in (3, 4, 7):
        await _supervisor_hb(
            client, appliance, token, _loop(now, restarts=n, status="unhealthy", history=[])
        )
        seen.append((await _reload(db_session, server.id)).daemon_reason)
    assert not (seen[0] or "").startswith("crash_loop:")  # two restarts
    assert (seen[1] or "").startswith("crash_loop:")  # three
    assert "6 restarts in the last 15 min" in (seen[2] or "")


async def test_an_oom_loop_with_many_restarts_reads_as_an_oom(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-loop-9")
    server, headers = await _kea_server(db_session, host="ddi-loop-9", appliance_id=appliance.id)
    await db_session.commit()
    now = datetime.now(UTC).replace(microsecond=0)
    await _seed(db_session, appliance, _loop(now, reason="OOMKilled"))
    await _supervisor_hb(client, appliance, token, _loop(now, reason="OOMKilled"))
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("oom_killed:")
    # A later termination the kubelet calls Error does not demote it.
    await _supervisor_hb(client, appliance, token, _loop(now, restarts=8))
    row = await _reload(db_session, server.id)
    assert (row.daemon_reason or "").startswith("oom_killed:")


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
    rh = _loop(now, status="healthy", restarts=0, history=[])
    # The supervisor has been heartbeating without a break for ten minutes.
    seeded = _loop(now, status="healthy", restarts=0, history=[])
    seeded["dhcp-kea"][HEARD_SINCE_KEY] = _iso(now - timedelta(minutes=10))
    await _seed(db_session, appliance, seeded)

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
    # The supervisor watched the whole silence, so the grace runs from the
    # agent's last heartbeat.
    since = row.daemon_status_since
    assert since == silent_since
    young = await _matching_agent_daemon_degraded_subjects(
        db_session, _RULE, since + timedelta(minutes=4)
    )
    assert f"dhcp_server:{server.id}" not in {m[0] for m in young}
    late = since + timedelta(minutes=6)
    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, late)
    hit = [m for m in matches if m[0] == f"dhcp_server:{server.id}"]
    # Its wording says the agent is NOT heartbeating.
    assert len(hit) == 1 and "The agent is not heartbeating" in hit[0][2]

    # The agent coming back says ``ok`` and the alert resolves.
    await _agent_hb(client, headers, {"status": "ok"})
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK
    after = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, late)
    assert f"dhcp_server:{server.id}" not in {m[0] for m in after}


async def test_a_supervisor_back_from_a_gap_does_not_call_the_agent_silent(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A node reboot or a control-plane outage: neither the supervisor nor the
    agent was heard for 12 minutes. The supervisor's first heartbeat back is
    not evidence that the AGENT is silent; the agent gets the whole threshold
    from that heartbeat, and the stored run-start is reset."""
    appliance, token = await _appliance(db_session, "ddi-loop-10")
    now = datetime.now(UTC).replace(microsecond=0)
    server, _h = await _kea_server(
        db_session,
        host="ddi-loop-10",
        appliance_id=appliance.id,
        last_seen_at=now - timedelta(minutes=12),
    )
    seeded = _loop(now, status="healthy", restarts=0, history=[])
    seeded["dhcp-kea"][HEARD_SINCE_KEY] = _iso(now - timedelta(hours=2))
    await _seed(db_session, appliance, seeded)
    appl = await db_session.get(type(appliance), appliance.id)
    assert appl is not None
    appl.last_seen_at = now - timedelta(minutes=12)
    await db_session.commit()

    await _supervisor_hb(
        client, appliance, token, _loop(now, status="healthy", restarts=0, history=[])
    )
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK
    fresh = await db_session.get(type(appliance), appliance.id)
    assert fresh is not None
    await db_session.refresh(fresh)
    heard = datetime.fromisoformat(fresh.role_health["dhcp-kea"][HEARD_SINCE_KEY])
    assert heard >= now


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
    # A supervisor that has been heartbeating for hours: only the pause keeps
    # the hour-old silence from being stamped.
    seeded = _loop(datetime.now(UTC), status="healthy", restarts=0, history=[])
    seeded["dhcp-kea"][HEARD_SINCE_KEY] = _iso(datetime.now(UTC) - timedelta(hours=2))
    await _seed(db_session, appliance, seeded)
    rh = _loop(datetime.now(UTC), status="healthy", restarts=0, history=[])
    await _supervisor_hb(client, appliance, token, rh)
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK
    # Unpaused, the same heartbeat does stamp it (the control).
    srv = await db_session.get(DHCPServer, server.id)
    assert srv is not None
    srv.maintenance_mode = False
    await db_session.commit()
    await _supervisor_hb(client, appliance, token, rh)
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_DEGRADED


async def test_the_wording_follows_the_source(db_session: AsyncSession) -> None:
    """The agent's own report keeps its wording; a kubelet-sourced OOM says the
    supervisor reported it (#2962)."""
    from app.services.agents.container_oom import container_oom_report

    now = datetime.now(UTC).replace(microsecond=0)
    await _appliance(db_session, "ddi-loop-5")
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


@pytest.mark.parametrize(
    ("reason", "source"),
    [
        # The agents' own records (agent/dns oom_watch, agent/dhcp oom_watch).
        ("oom_killed: named was killed for exceeding 512Mi (once, last at x)", "agent"),
        (
            "oom_killed: Kea was killed by the OOM killer in the DHCP container for "
            "exceeding 1Gi",
            "agent",
        ),
        (
            "oom_killed: the OOM killer fired in the DHCP container (Kea, almost "
            "certainly) for exceeding 1Gi",
            "agent",
        ),
        ("start deferred, no bundle yet", "agent"),
        ("config_apply_reverted: named-checkconf failed", "agent"),
        ("", "agent"),
        # The supervisor's verdicts.
        ("crash_loop: the dhcp-kea container (Kea ...) is crash-looping", "supervisor"),
        ("agent_unreachable: the agent in the dns-bind9 container ...", "supervisor"),
    ],
)
def test_reason_source_reads_every_prefix(reason: str, source: str) -> None:
    assert reason_source(reason) == source


@pytest.mark.parametrize(
    ("driver", "service"),
    [
        ("bind9", "dns-bind9"),
        ("powerdns", "dns-powerdns"),
        ("technitium", "dns-technitium"),
        ("kea", "dhcp-kea"),
    ],
)
def test_every_kubelet_oom_reads_as_the_supervisor(driver: str, service: str) -> None:
    from app.services.agents.container_oom import container_oom_report

    now = datetime.now(UTC)
    rh = _role_health(killed_at=now - timedelta(minutes=1), running_since=None, service=service)
    rep = container_oom_report(rh, driver, now)
    assert rep is not None
    assert reason_source(rep[0]["reason"]) == "supervisor"
    assert daemon_reported_by(STATUS_DEGRADED, rep[0]["reason"]) == "supervisor"
    assert daemon_reported_by(STATUS_OK, None) is None
    assert daemon_reported_by(None, None) is None

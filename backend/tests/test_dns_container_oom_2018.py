"""An OOM kill the agent died in still reads not serving (#2018).

On the appliance the kubelet sets ``memory.oom.group`` on the dns-bind9
container, so when named reaches the container's memory limit the kernel
kills named AND the DNS agent together. The agent's own OOM record
(``daemon_oom.json``, #1725 / #1898) is written from the agent's supervisor
loop after it sees named gone, so it never is; the restarted agent reports
``ok``; the server row stayed ``ok`` through 13 kills and **Agent daemon not
serving** never fired.

The kubelet saw it (``lastState.terminated.reason: OOMKilled``). The
appliance supervisor reports that per role container on its heartbeat
(``role_health[<svc>]["container"]``), and these tests pin what the control
plane does with it: the server row reads not serving with an ``oom_killed:``
reason, timed from the kill, through both heartbeats, and the alert fires.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.dns import DNSServer, DNSServerGroup
from app.models.settings import PlatformSettings
from app.services.agents.daemon_state import STATUS_DEGRADED, STATUS_OK, is_not_serving
from app.services.alerts import _matching_agent_daemon_degraded_subjects
from app.services.appliance.ca import generate_session_token
from app.services.dns import agent_token as dns_tokens

_RULE = SimpleNamespace(severity="critical")


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _role_health(
    *,
    killed_at: datetime,
    running_since: datetime | None,
    reason: str = "OOMKilled",
    restarts: int = 3,
) -> dict[str, Any]:
    """The supervisor watchdog's report for a dns-bind9 container, in the
    shape ``watchdog.container_runtime`` produces from the pod status."""
    return {
        "dns-bind9": {
            "role": "dns-bind9",
            "status": "healthy" if running_since else "unhealthy",
            "since": _iso(killed_at),
            "container_id": "dns-bind9-abcde",
            "container": {
                "restart_count": restarts,
                "running_since": _iso(running_since) if running_since else None,
                "last_termination": {
                    "reason": reason,
                    "exit_code": 137,
                    "finished_at": _iso(killed_at),
                },
                "memory_limit": "2Gi",
            },
        }
    }


async def _appliance(db: AsyncSession, hostname: str) -> tuple[Appliance, str]:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
        assigned_roles=["dns-bind9"],
        last_seen_at=datetime.now(UTC),
    )
    db.add(row)
    await db.flush()
    return row, token


async def _agent_server(
    db: AsyncSession,
    host: str,
    appliance_id: uuid.UUID | None = None,
    last_seen_at: datetime | None = None,
) -> tuple[DNSServer, dict[str, str]]:
    """A registered BIND9 agent row, as an appliance's agent registers it:
    ``host`` is the node's name, ``appliance_id`` is normally unset."""
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host=host,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        agent_id=uuid.uuid4(),
        agent_fingerprint="fp",
        appliance_id=appliance_id,
        daemon_status=STATUS_OK,
        daemon_status_since=datetime.now(UTC) - timedelta(hours=2),
        last_seen_at=last_seen_at or datetime.now(UTC),
    )
    db.add(server)
    await db.flush()
    token, _exp = dns_tokens.mint_agent_token(str(server.id), str(server.agent_id), "fp")
    server.agent_jwt_hash = dns_tokens.hash_token(token)
    return server, {"Authorization": f"Bearer {token}"}


async def _supervisor_hb(
    client: AsyncClient, row: Appliance, token: str, role_health: dict[str, Any]
) -> None:
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token, "role_health": role_health},
    )
    assert r.status_code == 200, r.text


async def _agent_hb(client: AsyncClient, headers: dict[str, str], daemon: dict) -> None:
    r = await client.post("/api/v1/dns/agents/heartbeat", headers=headers, json={"daemon": daemon})
    assert r.status_code == 200, r.text


async def _reload(db: AsyncSession, server_id: uuid.UUID) -> DNSServer:
    db.expunge_all()
    row = await db.get(DNSServer, server_id)
    assert row is not None
    return row


async def test_a_crash_looping_container_reads_not_serving_and_alerts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The issue's two-view loop: the container is in CrashLoopBackOff, no
    agent heartbeat comes, and the supervisor's report is the only one.
    The row says so, timed from the kill, and the alert fires once the kill
    is past its five-minute grace."""
    appliance, token = await _appliance(db_session, "ddi-oom-1")
    server, _headers = await _agent_server(db_session, host="ddi-oom-1")
    await db_session.commit()

    killed_at = (datetime.now(UTC) - timedelta(minutes=7)).replace(microsecond=0)
    await _supervisor_hb(
        client, appliance, token, _role_health(killed_at=killed_at, running_since=None)
    )

    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert row.daemon_reason is not None
    assert row.daemon_reason.startswith("oom_killed:")
    assert "2Gi" in row.daemon_reason
    assert is_not_serving(row.daemon_status, row.daemon_reason) is True
    assert row.daemon_status_since == killed_at

    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, datetime.now(UTC))
    subjects = {m[0] for m in matches}
    assert f"dns_server:{server.id}" in subjects


async def test_the_restarted_agent_saying_ok_does_not_hide_the_kill(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The one-view kill: the container came back, and the restarted agent
    — a new cgroup, blind to the kill — heartbeats ``ok``. While the
    kubelet's OOMKilled is current, that ``ok`` does not clear the row; once
    the container has stayed up for ten minutes, it does."""
    appliance, _token = await _appliance(db_session, "ddi-oom-2")
    server, headers = await _agent_server(db_session, host="ddi-oom-2", appliance_id=appliance.id)
    now = datetime.now(UTC).replace(microsecond=0)
    killed_at = now - timedelta(minutes=6)
    appliance.role_health = _role_health(
        killed_at=killed_at, running_since=killed_at + timedelta(seconds=20)
    )
    await db_session.commit()

    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("oom_killed:")
    assert row.daemon_status_since == killed_at

    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    assert f"dns_server:{server.id}" in {m[0] for m in matches}

    # A second ``ok`` while the kill is still current keeps the clock.
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status_since == killed_at

    # Ten minutes up: the kill is over, and the agent's ``ok`` stands.
    appl = await db_session.get(Appliance, appliance.id)
    assert appl is not None
    appl.role_health = _role_health(
        killed_at=now - timedelta(minutes=30), running_since=now - timedelta(minutes=11)
    )
    await db_session.commit()
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK
    assert row.daemon_reason is None


async def test_a_container_that_ended_for_another_reason_is_not_an_oom(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-oom-3")
    server, headers = await _agent_server(db_session, host="ddi-oom-3")
    await db_session.commit()

    killed_at = datetime.now(UTC) - timedelta(minutes=2)
    rh = _role_health(killed_at=killed_at, running_since=None, reason="Error")
    await _supervisor_hb(client, appliance, token, rh)
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK
    assert row.daemon_reason is None


async def test_another_appliances_report_does_not_touch_this_server(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, token = await _appliance(db_session, "ddi-oom-4")
    server, _headers = await _agent_server(db_session, host="some-other-node")
    await db_session.commit()

    killed_at = datetime.now(UTC) - timedelta(minutes=7)
    await _supervisor_hb(
        client, appliance, token, _role_health(killed_at=killed_at, running_since=None)
    )
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK


async def test_the_agents_own_oom_record_is_kept(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Where the agent did see the kill (Compose; a kernel that picked named
    alone), its own reason stands rather than being rewritten."""
    appliance, _token = await _appliance(db_session, "ddi-oom-5")
    server, headers = await _agent_server(db_session, host="ddi-oom-5", appliance_id=appliance.id)
    killed_at = datetime.now(UTC) - timedelta(minutes=3)
    appliance.role_health = _role_health(killed_at=killed_at, running_since=killed_at)
    await db_session.commit()

    own = {"status": "degraded", "reason": "oom_killed: named was killed (agent's own record)"}
    await _agent_hb(client, headers, own)
    row = await _reload(db_session, server.id)
    assert row.daemon_reason == own["reason"]


async def test_a_supervisor_that_stopped_reporting_does_not_pin_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The supervisor's last report stays in ``role_health`` when it stops
    heartbeating. A frozen "not running, OOMKilled" must not override the
    agent's ``ok`` for ever: once the supervisor is past its freshness
    window, the agent's word stands."""
    appliance, _token = await _appliance(db_session, "ddi-oom-6")
    server, headers = await _agent_server(db_session, host="ddi-oom-6", appliance_id=appliance.id)
    killed_at = datetime.now(UTC) - timedelta(hours=3)
    appliance.role_health = _role_health(killed_at=killed_at, running_since=None)
    appliance.last_seen_at = datetime.now(UTC) - timedelta(hours=2)
    await db_session.commit()

    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK
    assert row.daemon_reason is None


async def test_a_row_an_earlier_registration_left_is_not_stamped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two BIND9 rows carry this appliance's hostname: the live one and one
    an earlier registration left behind in another group. Only the live one
    is stamped; nothing heartbeats on the other, so a verdict there would
    never clear and its alert would never resolve."""
    appliance, token = await _appliance(db_session, "ddi-oom-7")
    stale, _h1 = await _agent_server(
        db_session, host="ddi-oom-7", last_seen_at=datetime.now(UTC) - timedelta(days=4)
    )
    live, _h2 = await _agent_server(db_session, host="ddi-oom-7")
    await db_session.commit()

    killed_at = datetime.now(UTC) - timedelta(minutes=7)
    await _supervisor_hb(
        client, appliance, token, _role_health(killed_at=killed_at, running_since=None)
    )
    assert (await _reload(db_session, live.id)).daemon_status == STATUS_DEGRADED
    stale_row = await _reload(db_session, stale.id)
    assert stale_row.daemon_status == STATUS_OK
    assert stale_row.daemon_reason is None


async def test_a_kea_oom_does_not_mark_the_dns_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The verdict is per container: an OOM-killed dhcp-kea on the same
    appliance says nothing about named."""
    appliance, token = await _appliance(db_session, "ddi-oom-8")
    server, _headers = await _agent_server(db_session, host="ddi-oom-8")
    await db_session.commit()

    killed_at = datetime.now(UTC) - timedelta(minutes=7)
    rh = _role_health(killed_at=killed_at, running_since=None)
    rh = {"dhcp-kea": {**rh["dns-bind9"], "role": "dhcp", "container_id": "dhcp-kea-x"}}
    await _supervisor_hb(client, appliance, token, rh)
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK

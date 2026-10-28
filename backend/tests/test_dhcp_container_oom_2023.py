"""An OOM kill of the dhcp-kea container reads not serving (#2023).

The DHCP side of #2018. On the appliance the kubelet sets
``memory.oom.group`` on the dhcp-kea container, so when Kea reaches its
memory limit the kernel kills Kea AND the DHCP agent together. The agent
cannot record it, the restarted agent reports ``ok``, and the DHCP server row
stayed ``ok`` through every kill with ``Agent daemon not serving`` silent.

The supervisor already carries the kubelet's ``lastState.terminated.reason``
for ``dhcp-kea`` in ``role_health``; these tests pin what the control plane
does with it for a Kea row: through the supervisor heartbeat and through the
agent heartbeat, with the alert firing.
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
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.settings import PlatformSettings
from app.services.agents.container_oom import container_oom_report
from app.services.agents.daemon_state import STATUS_DEGRADED, STATUS_OK, is_not_serving
from app.services.alerts import _matching_agent_daemon_degraded_subjects
from app.services.appliance.ca import generate_session_token
from app.services.dhcp import agent_token as dhcp_tokens

_RULE = SimpleNamespace(severity="critical")


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _role_health(
    *,
    killed_at: datetime,
    running_since: datetime | None,
    reason: str = "OOMKilled",
    service: str = "dhcp-kea",
    restarts: int = 4,
) -> dict[str, Any]:
    """The supervisor watchdog's report for a role container, in the shape
    ``watchdog.container_runtime`` produces from the pod status."""
    return {
        service: {
            "role": "dhcp",
            "status": "healthy" if running_since else "unhealthy",
            "since": _iso(killed_at),
            "container_id": f"{service}-abcde",
            "container": {
                "restart_count": restarts,
                "running_since": _iso(running_since) if running_since else None,
                "last_termination": {
                    "reason": reason,
                    "exit_code": 137,
                    "finished_at": _iso(killed_at),
                },
                "memory_limit": "1Gi",
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
        assigned_roles=["dhcp"],
        last_seen_at=datetime.now(UTC),
    )
    db.add(row)
    await db.flush()
    return row, token


async def _kea_server(
    db: AsyncSession,
    host: str,
    appliance_id: uuid.UUID | None = None,
    last_seen_at: datetime | None = None,
) -> tuple[DHCPServer, dict[str, str]]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        host=host,
        port=67,
        driver="kea",
        roles=["primary"],
        status="active",
        server_group_id=grp.id,
        agent_id=uuid.uuid4(),
        agent_registered=True,
        agent_approved=True,
        agent_fingerprint="fp",
        appliance_id=appliance_id,
        daemon_status=STATUS_OK,
        daemon_status_since=datetime.now(UTC) - timedelta(hours=2),
        agent_last_seen=last_seen_at or datetime.now(UTC),
    )
    db.add(server)
    await db.flush()
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(server.id), agent_id=str(server.agent_id), fingerprint="fp"
    )
    server.agent_token_hash = dhcp_tokens.hash_token(token)
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
    r = await client.post("/api/v1/dhcp/agents/heartbeat", headers=headers, json={"daemon": daemon})
    assert r.status_code == 200, r.text


async def _reload(db: AsyncSession, server_id: uuid.UUID) -> DHCPServer:
    db.expunge_all()
    row = await db.get(DHCPServer, server_id)
    assert row is not None
    return row


def test_the_report_maps_a_kea_row_onto_the_dhcp_kea_container() -> None:
    now = datetime.now(UTC)
    rh = _role_health(killed_at=now - timedelta(minutes=2), running_since=None)
    got = container_oom_report(rh, "kea", now)
    assert got is not None
    report, _killed = got
    assert report["reason"].startswith("oom_killed:")
    assert "dhcp-kea" in report["reason"] and "1Gi" in report["reason"]
    # The DNS advice does not follow the verdict onto a DHCP row.
    assert "RPZ" not in report["reason"]
    # An agentless Windows DHCP row has no container to blame.
    assert container_oom_report(rh, "windows_dhcp", now) is None


async def test_a_crash_looping_kea_container_reads_not_serving_and_alerts(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """CrashLoopBackOff, no agent heartbeat: the supervisor's report is the
    only one. The row says so, timed from the kill, and the alert fires once
    the kill is past its grace."""
    appliance, token = await _appliance(db_session, "ddi-oomd-1")
    server, _headers = await _kea_server(db_session, host="ddi-oomd-1")
    await db_session.commit()

    killed_at = (datetime.now(UTC) - timedelta(minutes=7)).replace(microsecond=0)
    await _supervisor_hb(
        client, appliance, token, _role_health(killed_at=killed_at, running_since=None)
    )

    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("oom_killed:")
    assert is_not_serving(row.daemon_status, row.daemon_reason) is True
    assert row.daemon_status_since == killed_at

    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, datetime.now(UTC))
    assert f"dhcp_server:{server.id}" in {m[0] for m in matches}


async def test_the_restarted_agent_saying_ok_does_not_hide_the_kill(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The container came back and the restarted agent (a new cgroup, blind
    to the kill) heartbeats ``ok``. While the kubelet's OOMKilled is current
    that ``ok`` does not clear the row; ten minutes up, it does."""
    appliance, _token = await _appliance(db_session, "ddi-oomd-2")
    server, headers = await _kea_server(db_session, host="ddi-oomd-2", appliance_id=appliance.id)
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
    assert f"dhcp_server:{server.id}" in {m[0] for m in matches}

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
    appliance, token = await _appliance(db_session, "ddi-oomd-3")
    server, headers = await _kea_server(db_session, host="ddi-oomd-3")
    await db_session.commit()

    rh = _role_health(
        killed_at=datetime.now(UTC) - timedelta(minutes=2),
        running_since=None,
        reason="Error",
        restarts=1,
    )
    await _supervisor_hb(client, appliance, token, rh)
    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK
    assert row.daemon_reason is None


async def test_the_agents_own_oom_record_is_kept(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Where the agent saw the kill itself (Compose), its reason stands."""
    appliance, _token = await _appliance(db_session, "ddi-oomd-4")
    server, headers = await _kea_server(db_session, host="ddi-oomd-4", appliance_id=appliance.id)
    killed_at = datetime.now(UTC) - timedelta(minutes=3)
    appliance.role_health = _role_health(killed_at=killed_at, running_since=killed_at)
    await db_session.commit()

    own = {"status": "degraded", "reason": "oom_killed: the OOM killer fired (agent's own record)"}
    await _agent_hb(client, headers, own)
    row = await _reload(db_session, server.id)
    assert row.daemon_reason == own["reason"]


async def test_a_dns_container_oom_does_not_mark_the_kea_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The verdict is per container: a killed dns-bind9 on the same
    appliance says nothing about Kea."""
    appliance, token = await _appliance(db_session, "ddi-oomd-5")
    server, headers = await _kea_server(db_session, host="ddi-oomd-5")
    await db_session.commit()

    rh = _role_health(
        killed_at=datetime.now(UTC) - timedelta(minutes=7),
        running_since=None,
        service="dns-bind9",
    )
    await _supervisor_hb(client, appliance, token, rh)
    await _agent_hb(client, headers, {"status": "ok"})
    assert (await _reload(db_session, server.id)).daemon_status == STATUS_OK


async def test_a_row_an_earlier_registration_left_is_not_stamped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Two Kea rows carry this appliance's hostname; only the live one is
    stamped, or the dead row's verdict would never clear."""
    appliance, token = await _appliance(db_session, "ddi-oomd-6")
    stale, _h1 = await _kea_server(
        db_session, host="ddi-oomd-6", last_seen_at=datetime.now(UTC) - timedelta(days=4)
    )
    live, _h2 = await _kea_server(db_session, host="ddi-oomd-6")
    await db_session.commit()

    killed_at = datetime.now(UTC) - timedelta(minutes=7)
    await _supervisor_hb(
        client, appliance, token, _role_health(killed_at=killed_at, running_since=None)
    )
    assert (await _reload(db_session, live.id)).daemon_status == STATUS_DEGRADED
    assert (await _reload(db_session, stale.id)).daemon_status == STATUS_OK


async def test_a_supervisor_that_stopped_reporting_does_not_pin_the_row(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    appliance, _token = await _appliance(db_session, "ddi-oomd-7")
    server, headers = await _kea_server(db_session, host="ddi-oomd-7", appliance_id=appliance.id)
    appliance.role_health = _role_health(
        killed_at=datetime.now(UTC) - timedelta(hours=3), running_since=None
    )
    appliance.last_seen_at = datetime.now(UTC) - timedelta(hours=2)
    await db_session.commit()

    await _agent_hb(client, headers, {"status": "ok"})
    row = await _reload(db_session, server.id)
    assert row.daemon_status == STATUS_OK


async def test_an_oom_on_one_ha_node_is_not_stamped_on_its_peer(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A Kea HA pair on two appliances, one group: a kill of node A's
    dhcp-kea container marks A's row only. Each supervisor reports its own
    containers, and both paths (A's supervisor heartbeat, each agent's own
    heartbeat) resolve the row's OWNING appliance, so B's ``ok`` stands. One
    row is owned by FK and the other by hostname, the two ownership shapes."""
    node_a, token_a = await _appliance(db_session, "ddi-oomha-a")
    node_b, token_b = await _appliance(db_session, "ddi-oomha-b")
    row_a, headers_a = await _kea_server(db_session, host="ddi-oomha-a", appliance_id=node_a.id)
    row_b, headers_b = await _kea_server(db_session, host="ddi-oomha-b")
    row_b.server_group_id = row_a.server_group_id
    await db_session.commit()

    killed_at = datetime.now(UTC) - timedelta(minutes=7)
    await _supervisor_hb(
        client, node_a, token_a, _role_health(killed_at=killed_at, running_since=None)
    )
    # Node B's supervisor reports a healthy container.
    await _supervisor_hb(client, node_b, token_b, {})

    assert (await _reload(db_session, row_a.id)).daemon_status == STATUS_DEGRADED
    assert (await _reload(db_session, row_b.id)).daemon_status == STATUS_OK

    # B's agent heartbeating ``ok`` is not overridden by A's kill...
    await _agent_hb(client, headers_b, {"status": "ok"})
    assert (await _reload(db_session, row_b.id)).daemon_status == STATUS_OK
    # ...and A's restarted agent saying ``ok`` does not clear A's.
    await _agent_hb(client, headers_a, {"status": "ok"})
    row = await _reload(db_session, row_a.id)
    assert row.daemon_status == STATUS_DEGRADED
    assert (row.daemon_reason or "").startswith("oom_killed:")

    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, datetime.now(UTC))
    subjects = {m[0] for m in matches}
    assert f"dhcp_server:{row_a.id}" in subjects
    assert f"dhcp_server:{row_b.id}" not in subjects


async def test_the_agents_config_apply_echo_does_not_hide_a_kill(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A killed Kea that also failed a config apply: the agent's
    ``dhcp4_config_rejected`` echo is a #882 verdict (not "not serving"), so
    letting it stand would hide the kill. The kubelet's OOM wins the daemon
    field; the config verdict keeps its own column."""
    appliance, _token = await _appliance(db_session, "ddi-oomd-8")
    server, headers = await _kea_server(db_session, host="ddi-oomd-8", appliance_id=appliance.id)
    killed_at = datetime.now(UTC) - timedelta(minutes=2)
    appliance.role_health = _role_health(killed_at=killed_at, running_since=killed_at)
    await db_session.commit()

    await _agent_hb(
        client, headers, {"status": "degraded", "reason": "dhcp4_config_rejected: bad subnet"}
    )
    row = await _reload(db_session, server.id)
    assert (row.daemon_reason or "").startswith("oom_killed:")
    assert is_not_serving(row.daemon_status, row.daemon_reason) is True

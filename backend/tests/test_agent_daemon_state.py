"""Agent daemon-state ingest, its exposure on the server row, and the
``agent_daemon_degraded`` alert (#1067).

The failure this covers is the mirror of #882's, one field over: a DNS
agent that registers, heartbeats every 30 s and never starts ``named``
(no bundle yet) said so on every heartbeat — ``daemon: {"status":
"degraded", "reason": "start deferred, no bundle yet"}`` — and the control
plane dropped the field, so the server read ``active``, seen seconds ago,
config ok, for as long as it took someone to look at the pod.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dhcp.servers import ServerResponse as DHCPServerResponse
from app.api.v1.dns.router import ServerResponse as DNSServerResponse
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.services.agents.daemon_state import (
    STATUS_DEGRADED,
    STATUS_OK,
    apply_reported_daemon_state,
    is_config_apply_verdict,
    is_not_serving,
    is_unhealthy,
)
from app.services.alerts import _matching_agent_daemon_degraded_subjects
from app.services.dhcp import agent_token as dhcp_tokens
from app.services.dns import agent_token as dns_tokens

_RULE = SimpleNamespace(severity="critical")
_T0 = datetime(2026, 9, 21, 12, 0, 0, tzinfo=UTC)
DEFERRED = {"status": STATUS_DEGRADED, "reason": "start deferred, no bundle yet"}


def _row() -> SimpleNamespace:
    return SimpleNamespace(daemon_status=None, daemon_reason=None, daemon_status_since=None)


def _report(row: object, payload: dict | None, at: datetime = _T0) -> None:
    apply_reported_daemon_state(row, payload, agent_kind="dns", server_id="s1", now=at)


# ── ingest ────────────────────────────────────────────────────────────────


def test_a_degraded_report_is_persisted_with_its_reason_and_since() -> None:
    row = _row()
    _report(row, DEFERRED)
    assert row.daemon_status == STATUS_DEGRADED
    assert row.daemon_reason == "start deferred, no bundle yet"
    assert row.daemon_status_since == _T0


def test_an_empty_report_leaves_the_last_known_state_alone() -> None:
    """``daemon: {}`` is what a pre-#1061 agent sends, and what the DNS agent
    sends until something sets its dict. Neither is a verdict."""
    row = _row()
    _report(row, DEFERRED)
    _report(row, {}, at=_T0 + timedelta(minutes=1))
    _report(row, None, at=_T0 + timedelta(minutes=2))
    _report(row, {"status": "   "}, at=_T0 + timedelta(minutes=3))
    assert row.daemon_status == STATUS_DEGRADED
    assert row.daemon_reason == "start deferred, no bundle yet"
    assert row.daemon_status_since == _T0


def test_since_moves_only_when_the_state_changes() -> None:
    """The stamp means 'since this state', not 'last reported': a heartbeat
    every 30 s must not keep resetting the clock the alert reads, and nor
    must a newer reason for the same state. The same ``degraded`` crossing
    from not serving to a config-apply echo IS a new state."""
    row = _row()
    _report(row, DEFERRED)
    _report(row, DEFERRED, at=_T0 + timedelta(minutes=5))
    assert row.daemon_status_since == _T0
    _report(
        row,
        {"status": STATUS_DEGRADED, "reason": "config_apply_reverted: boom"},
        at=_T0 + timedelta(minutes=6),
    )
    assert row.daemon_status_since == _T0 + timedelta(minutes=6)
    assert row.daemon_reason == "config_apply_reverted: boom"
    _report(
        row,
        {"status": STATUS_DEGRADED, "reason": "config_apply_revert_failed: boom"},
        at=_T0 + timedelta(minutes=7),
    )
    assert row.daemon_status_since == _T0 + timedelta(minutes=6)  # another echo, same state
    _report(row, {"status": STATUS_OK}, at=_T0 + timedelta(minutes=8))
    assert row.daemon_status_since == _T0 + timedelta(minutes=8)


def test_a_deferral_after_an_old_revert_starts_its_own_clock() -> None:
    """What the state clock is for. A row that has echoed a revert for hours
    and then defers its start (a restart with no rendered config) must not
    inherit the revert's start time: the alert would skip its grace and page
    the moment a normal first boot began, quoting hours it never lasted."""
    row = _row()
    _report(row, {"status": STATUS_DEGRADED, "reason": "config_apply_reverted: boom"})
    later = _T0 + timedelta(hours=3)
    _report(row, DEFERRED, at=later)
    assert row.daemon_status == STATUS_DEGRADED
    assert row.daemon_status_since == later


def test_ok_clears_the_reason() -> None:
    row = _row()
    _report(row, DEFERRED)
    _report(row, {"status": STATUS_OK, "reason": "stale text a buggy agent sent"})
    assert row.daemon_status == STATUS_OK
    assert row.daemon_reason is None


def test_a_word_this_control_plane_has_not_seen_is_still_stored() -> None:
    """Unlike #882's closed vocabulary, a daemon status is a health signal and
    anything but ``ok`` reads as not serving (short of a config-apply echo,
    which is #882's). Hiding a newer agent's word behind the last known
    state would recreate the gap for the next word."""
    row = _row()
    _report(row, {"status": STATUS_OK})
    _report(row, {"status": "down", "reason": "named exited 1"}, at=_T0 + timedelta(minutes=1))
    assert row.daemon_status == "down"
    assert is_unhealthy(row.daemon_status)
    assert is_not_serving(row.daemon_status, row.daemon_reason) is True
    assert row.daemon_status_since == _T0 + timedelta(minutes=1)


def test_oversized_fields_are_clipped_to_the_columns() -> None:
    row = _row()
    _report(row, {"status": "d" * 100, "reason": "r" * 9000})
    assert len(row.daemon_status) == 20
    assert len(row.daemon_reason) == 2000


def test_null_is_unknown_not_unhealthy() -> None:
    assert not is_unhealthy(None)
    assert not is_unhealthy(STATUS_OK)
    assert is_unhealthy(STATUS_DEGRADED)


# ── not serving vs a config-apply echo ────────────────────────────────────

# Every daemon ``reason`` the two agents send, spelled as their sources spell
# it. ``True`` = the agent echoing a failed config apply, which is #882's to
# report. The other half of this contract is pinned in each agent's own suite
# (agent/dns/tests/test_config_revert.py, agent/dhcp/tests/test_config_revert.py
# and test_config_test_preflight.py assert the exact prefixes), which run on
# every agent change without pulling agent/ into this suite's CI gate (#821).
_AGENT_REASONS = [
    ("start deferred, no bundle yet", False),  # dns supervisor.py
    ("config_apply_reverted: named-checkconf failed", True),  # dns + dhcp sync.py
    ("config_apply_revert_failed: rndc reconfig failed", True),  # dns sync.py
    ("config_apply_no_previous: named-checkconf failed", True),  # dns sync.py
    ("dhcp4_config_rejected: pool 10.0.0.0/24 is not part of the subnet", True),
    ("dhcp6_config_rejected: unknown option", True),
    ("dhcp4_socket_unreachable: [Errno 111] Connection refused", False),
    ("dhcp6_socket_unreachable: [Errno 2] No such file or directory", False),
]


@pytest.mark.parametrize(("reason", "echo"), _AGENT_REASONS)
def test_a_config_apply_echo_is_told_apart_from_a_daemon_that_is_down(
    reason: str, echo: bool
) -> None:
    assert is_config_apply_verdict(reason) is echo
    assert is_not_serving(STATUS_DEGRADED, reason) is (not echo)


def test_not_serving_is_unknown_on_null_and_matches_only_a_leading_echo() -> None:
    assert is_not_serving(None, None) is None
    assert is_not_serving(STATUS_OK, None) is False
    assert is_not_serving("down", None) is True  # a word we have never seen
    assert is_not_serving(STATUS_DEGRADED, "") is True
    # Only the agent's own prefix counts; a reason that merely mentions one
    # is still a daemon that is not serving.
    assert is_not_serving(STATUS_DEGRADED, "waiting after config_apply_reverted: x") is True


# ── the heartbeat handlers, both families ─────────────────────────────────


async def _dns_agent(db: AsyncSession) -> tuple[DNSServer, dict[str, str]]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.53",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        agent_id=uuid.uuid4(),
        agent_fingerprint="fp",
    )
    db.add(server)
    await db.flush()
    token, _exp = dns_tokens.mint_agent_token(str(server.id), str(server.agent_id), "fp")
    server.agent_jwt_hash = dns_tokens.hash_token(token)
    await db.commit()
    return server, {"Authorization": f"Bearer {token}"}


async def _dhcp_agent(db: AsyncSession) -> tuple[DHCPServer, dict[str, str]]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    server = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        host="10.0.0.67",
        port=67,
        driver="kea",
        roles=["primary"],
        status="active",
        server_group_id=grp.id,
        agent_id=uuid.uuid4(),
        agent_registered=True,
        agent_approved=True,
        agent_fingerprint="fp",
    )
    db.add(server)
    await db.flush()
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(server.id), agent_id=str(server.agent_id), fingerprint="fp"
    )
    server.agent_token_hash = dhcp_tokens.hash_token(token)
    await db.commit()
    return server, {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_dns_heartbeat_persists_the_daemon_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _dns_agent(db_session)

    resp = await client.post(
        "/api/v1/dns/agents/heartbeat", headers=headers, json={"daemon": DEFERRED}
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.daemon_status == STATUS_DEGRADED
    assert server.daemon_reason == "start deferred, no bundle yet"
    assert server.daemon_status_since is not None
    since = server.daemon_status_since
    # The same handler call stamps last_seen_at and since.
    assert abs((server.last_seen_at - since).total_seconds()) < 5

    # A pre-#1061 heartbeat (daemon: {}) leaves it standing.
    resp = await client.post("/api/v1/dns/agents/heartbeat", headers=headers, json={"daemon": {}})
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.daemon_status == STATUS_DEGRADED
    assert server.daemon_status_since == since

    resp = await client.post(
        "/api/v1/dns/agents/heartbeat", headers=headers, json={"daemon": {"status": "ok"}}
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.daemon_status == STATUS_OK
    assert server.daemon_reason is None
    assert server.daemon_status_since >= since


@pytest.mark.asyncio
async def test_dhcp_heartbeat_persists_the_daemon_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    server, headers = await _dhcp_agent(db_session)
    degraded = {
        "status": "degraded",
        "reason": "dhcp4_socket_unreachable: [Errno 111] Connection refused",
    }

    resp = await client.post(
        "/api/v1/dhcp/agents/heartbeat",
        headers=headers,
        # The DHCP agent also ships a top-level ``status`` derived from the
        # same dict (heartbeat.py:74); ``daemon`` is the source both read.
        json={"status": "degraded", "daemon": degraded},
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.daemon_status == STATUS_DEGRADED
    assert server.daemon_reason == "dhcp4_socket_unreachable: [Errno 111] Connection refused"
    assert server.daemon_status_since is not None

    resp = await client.post(
        "/api/v1/dhcp/agents/heartbeat", headers=headers, json={"daemon": {"status": "ok"}}
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(server)
    assert server.daemon_status == STATUS_OK
    assert server.daemon_reason is None


# ── the operator's read path ──────────────────────────────────────────────


def _stamped(server: object) -> None:
    for attr in ("id", "created_at", "modified_at"):
        if getattr(server, attr, None) is None:
            setattr(server, attr, uuid.uuid4() if attr == "id" else _T0)


def _dns_model(**daemon: object) -> DNSServer:
    s = DNSServer(
        group_id=uuid.uuid4(),
        name="ns1",
        driver="bind9",
        host="ns1",
        port=53,
        roles=["authoritative"],
        status="active",
        is_enabled=True,
        notes="",
        pending_approval=False,
        is_primary=True,
        maintenance_mode=False,
        is_trial_boot=False,
        reboot_requested=False,
        # #1111's stored-bundle counters: NOT NULL with a default that only
        # applies at flush, and this instance is never flushed.
        bundle_dirty_seq=0,
        bundle_render_count=0,
        **daemon,
    )
    _stamped(s)
    return s


def _dhcp_model(**daemon: object) -> DHCPServer:
    s = DHCPServer(
        name="kea1",
        description="",
        driver="kea",
        host="kea1",
        port=67,
        roles=["primary"],
        status="active",
        agent_registered=True,
        agent_approved=True,
        maintenance_mode=False,
        is_trial_boot=False,
        reboot_requested=False,
        **daemon,
    )
    _stamped(s)
    return s


def test_dns_server_response_exposes_the_daemon_state() -> None:
    s = _dns_model(
        daemon_status=STATUS_DEGRADED,
        daemon_reason="start deferred, no bundle yet",
        daemon_status_since=_T0,
    )
    out = DNSServerResponse.from_model(s)
    assert out.daemon_status == STATUS_DEGRADED
    assert out.daemon_reason == "start deferred, no bundle yet"
    assert out.daemon_status_since == _T0
    assert out.daemon_not_serving is True
    assert out.model_dump()["daemon_status"] == STATUS_DEGRADED


def test_dhcp_server_response_exposes_the_daemon_state() -> None:
    s = _dhcp_model(daemon_status=STATUS_OK, daemon_reason=None, daemon_status_since=_T0)
    out = DHCPServerResponse.from_model(s)
    assert out.daemon_status == STATUS_OK
    assert out.daemon_reason is None
    assert out.daemon_status_since == _T0
    assert out.daemon_not_serving is False


@pytest.mark.parametrize(
    ("status", "reason", "expected"),
    [
        (None, None, None),  # never reported: unknown, not healthy, not an alarm
        (STATUS_OK, None, False),
        (STATUS_DEGRADED, "start deferred, no bundle yet", True),
        (STATUS_DEGRADED, "dhcp4_socket_unreachable: [Errno 111] Connection refused", True),
        (STATUS_DEGRADED, "config_apply_reverted: named-checkconf failed", False),
        (STATUS_DEGRADED, "dhcp4_config_rejected: bad pool", False),
    ],
)
def test_both_responses_publish_the_one_not_serving_reading(
    status: str | None, reason: str | None, expected: bool | None
) -> None:
    """The chip, the banner and the dashboard read ``daemon_not_serving``
    instead of re-deriving it from ``daemon_status`` — the re-derivation is
    what put a red 'not serving' chip on every routine revert while the alert
    (correctly) stayed quiet."""
    dns = DNSServerResponse.from_model(_dns_model(daemon_status=status, daemon_reason=reason))
    dhcp = DHCPServerResponse.from_model(_dhcp_model(daemon_status=status, daemon_reason=reason))
    assert dns.daemon_not_serving is expected
    assert dhcp.daemon_not_serving is expected


# ── the alert matcher ─────────────────────────────────────────────────────


async def _dns_server(db: AsyncSession, name: str, **kw: object) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    s = DNSServer(group_id=group.id, name=name, driver="bind9", host="10.0.0.53", port=53, **kw)
    db.add(s)
    await db.flush()
    return s


async def _dhcp_server(db: AsyncSession, name: str, **kw: object) -> DHCPServer:
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(group)
    await db.flush()
    s = DHCPServer(
        server_group_id=group.id, name=name, driver="kea", host="10.0.0.67", port=67, **kw
    )
    db.add(s)
    await db.flush()
    return s


@pytest.mark.asyncio
async def test_matcher_fires_once_degraded_has_outlasted_the_grace(
    db_session: AsyncSession,
) -> None:
    now = datetime.now(UTC)
    await _dns_server(
        db_session,
        "ns-stuck",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="start deferred, no bundle yet",
        daemon_status_since=now - timedelta(minutes=12),
    )
    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    assert len(matches) == 1
    subject_id, display, message, severity = matches[0]
    assert subject_id.startswith("dns_server:")
    assert display == "ns-stuck (DNS)"
    assert "12 min" in message
    assert "start deferred, no bundle yet" in message
    assert severity == "critical"


@pytest.mark.asyncio
async def test_matcher_waits_out_a_normal_first_boot(db_session: AsyncSession) -> None:
    """Every fresh member defers its daemon for the seconds it takes the first
    bundle to land, and reports ``degraded`` meanwhile. That is not an alarm."""
    now = datetime.now(UTC)
    await _dns_server(
        db_session,
        "ns-booting",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="start deferred, no bundle yet",
        daemon_status_since=now - timedelta(seconds=40),
    )
    assert await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now) == []


@pytest.mark.asyncio
async def test_matcher_ignores_ok_null_maintenance_and_config_apply_verdicts(
    db_session: AsyncSession,
) -> None:
    now = datetime.now(UTC)
    old = now - timedelta(minutes=30)
    await _dns_server(db_session, "ns-ok", daemon_status=STATUS_OK, daemon_status_since=old)
    await _dns_server(db_session, "ns-never")  # NULL: never reported
    await _dns_server(
        db_session,
        "ns-paused",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="start deferred, no bundle yet",
        daemon_status_since=old,
        maintenance_mode=True,
    )
    # A failed apply is #882's alarm, at the severity #882 gives its verdict —
    # whichever verdict it was, and however each agent spells the echo. Firing
    # here as well would page twice for one event.
    await _dns_server(
        db_session,
        "ns-reverted",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="config_apply_reverted: named-checkconf failed",
        daemon_status_since=old,
    )
    await _dns_server(
        db_session,
        "ns-no-previous",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="config_apply_no_previous: named-checkconf failed",
        daemon_status_since=old,
    )
    # The DHCP agent leaves Kea's refusal in place when there is nothing to
    # roll back to (no_previous) or the rollback fails too (revert_failed).
    await _dhcp_server(
        db_session,
        "kea-rejected",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="dhcp4_config_rejected: pool 10.0.0.0/24 is not part of the subnet",
        daemon_status_since=old,
    )
    assert await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now) == []


@pytest.mark.asyncio
async def test_matcher_spans_both_families(db_session: AsyncSession) -> None:
    now = datetime.now(UTC)
    await _dhcp_server(
        db_session,
        "kea-dark",
        daemon_status=STATUS_DEGRADED,
        daemon_reason="dhcp4_socket_unreachable: [Errno 111] Connection refused",
        daemon_status_since=now - timedelta(minutes=9),
    )
    matches = await _matching_agent_daemon_degraded_subjects(db_session, _RULE, now)
    assert [m[0].split(":")[0] for m in matches] == ["dhcp_server"]
    assert matches[0][1] == "kea-dark (DHCP)"

"""#980 — DHCP packet-loss metrics and the two Kea packet-path settings.

Three things under test, and what each would look like if it broke:

* the bundle plumbing for ``kea_thread_pool_size`` / ``kea_packet_logging``
  — a value stored and shipped but never rendered is a silent no-op, and a
  value not folded into the ETag never reaches a running agent at all;
* the ingest path's NULL-vs-0 discipline — an agent too old to measure loss
  must be UNKNOWN, because 0 reads as "this server has dropped nothing",
  which is the false reassurance the issue was filed about;
* the alert evaluator, which must fire on measured loss and stay silent on
  unmeasured — not the other way round.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dhcp.base import ConfigBundle, PoolDef, ScopeDef, ServerOptionsDef
from app.drivers.dhcp.kea import KeaDriver
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.metrics import DHCPMetricSample
from app.services.alerts import (
    RULE_TYPE_DHCP_PACKETS_DROPPED,
    _matching_dhcp_packets_dropped_subjects,
)
from app.services.dhcp.config_bundle import build_config_bundle

CIDR = "10.98.0.0/24"


def _bundle(**kw) -> ConfigBundle:
    return ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000980",
        server_name="kea-980",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=(
            ScopeDef(
                subnet_cidr=CIDR,
                pools=(PoolDef(start_ip="10.98.0.100", end_ip="10.98.0.200"),),
            ),
        ),
        client_classes=(),
        generated_at=datetime.now(UTC),
        **kw,
    )


# ── driver render + ETag ────────────────────────────────────────────────


def test_thread_pool_size_is_rendered() -> None:
    cfg = json.loads(KeaDriver().render_config(_bundle(kea_thread_pool_size=2)))
    mt = cfg["Dhcp4"]["multi-threading"]
    assert mt["thread-pool-size"] == 2
    # A pool of N is a resize, not a mode change: with MT off one thread has
    # to both receive and process, which measured 15,170 socket drops in a
    # run where a pool of one had none.
    assert mt["enable-multi-threading"] is True


def test_bundle_defaults_to_one_worker_not_keas_auto() -> None:
    """Kea's own default sizes the pool from the machine's CPU count with no
    regard for the container's cgroup share — verified live: a container
    limited to 0.20 CPU started ten workers. A bundle built without a group
    must not inherit that."""
    assert _bundle().kea_thread_pool_size == 1


def test_thread_pool_size_shifts_the_etag() -> None:
    """Not folded into the ETag means a change never wakes a long-polling
    agent — the #430 silent no-op."""
    assert (
        _bundle(kea_thread_pool_size=1).compute_etag()
        != _bundle(kea_thread_pool_size=4).compute_etag()
    )


def test_packet_logging_shows_in_the_rendered_preview() -> None:
    """The preview is what an operator checks a setting against.

    It already omits most daemon plumbing and does not parse as a Kea
    config, but it does carry the group tunables — ``dhcp_socket_type``
    (#365) and ``cache-threshold`` (#637) are both there — so a #980 knob
    that was invisible would have the operator seeing one of the two
    settings they just changed.
    """
    on = json.loads(KeaDriver().render_config(_bundle(kea_packet_logging=True)))
    assert "loggers" not in on["Dhcp4"], "default must render exactly as before"

    off = json.loads(KeaDriver().render_config(_bundle(kea_packet_logging=False)))
    assert off["Dhcp4"]["loggers"] == [{"name": "kea-dhcp4.packets", "severity": "WARN"}]


def test_packet_logging_shifts_the_etag() -> None:
    assert (
        _bundle(kea_packet_logging=True).compute_etag()
        != _bundle(kea_packet_logging=False).compute_etag()
    )


# ── build_config_bundle: group column → bundle ──────────────────────────


async def _group_with_server(db: AsyncSession, **group_kw) -> DHCPServer:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", **group_kw)
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()
    return srv


async def test_group_pool_size_reaches_the_bundle(db_session: AsyncSession) -> None:
    srv = await _group_with_server(db_session, kea_thread_pool_size=4)
    bundle = await build_config_bundle(db_session, srv)
    assert bundle.kea_thread_pool_size == 4


async def test_group_zero_is_not_coalesced_to_the_default(
    db_session: AsyncSession,
) -> None:
    """0 means "let Kea auto-size" — the one setting an operator uses to opt
    OUT of this change. A truthiness coalesce would silently put them back
    on the default they were escaping."""
    srv = await _group_with_server(db_session, kea_thread_pool_size=0)
    bundle = await build_config_bundle(db_session, srv)
    assert bundle.kea_thread_pool_size == 0


async def test_group_packet_logging_off_reaches_the_bundle(
    db_session: AsyncSession,
) -> None:
    """False is falsy; the same coalesce hazard, in the other type."""
    srv = await _group_with_server(db_session, kea_packet_logging=False)
    bundle = await build_config_bundle(db_session, srv)
    assert bundle.kea_packet_logging is False


# ── group API round-trip ────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> str:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


async def test_group_api_round_trips_the_packet_path_settings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    await db_session.commit()
    h = {"Authorization": f"Bearer {token}"}

    r = await client.post(
        "/api/v1/dhcp/server-groups", headers=h, json={"name": f"g-{uuid.uuid4().hex[:6]}"}
    )
    assert r.status_code == 201, r.text
    gid = r.json()["id"]
    assert r.json()["kea_thread_pool_size"] == 1
    assert r.json()["kea_packet_logging"] is True

    r = await client.put(
        f"/api/v1/dhcp/server-groups/{gid}",
        headers=h,
        json={"kea_thread_pool_size": 0, "kea_packet_logging": False},
    )
    assert r.status_code == 200, r.text
    assert r.json()["kea_thread_pool_size"] == 0
    assert r.json()["kea_packet_logging"] is False


async def test_group_api_rejects_an_absurd_pool_size(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/dhcp/server-groups",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": f"g-{uuid.uuid4().hex[:6]}", "kea_thread_pool_size": 5000},
    )
    assert r.status_code == 422, r.text


# ── the alert evaluator ─────────────────────────────────────────────────


async def _server_with_samples(db: AsyncSession, rows: list[dict]) -> DHCPServer:
    srv = await _group_with_server(db)
    base = datetime.now(UTC) - timedelta(minutes=5)
    for i, row in enumerate(rows):
        db.add(
            DHCPMetricSample(
                server_id=srv.id,
                bucket_at=base + timedelta(minutes=i),
                discover=row.get("discover", 10),
                **{k: v for k, v in row.items() if k != "discover"},
            )
        )
    await db.flush()
    return srv


def _rule() -> AlertRule:
    return AlertRule(
        name="t", rule_type=RULE_TYPE_DHCP_PACKETS_DROPPED, severity="warning", enabled=True
    )


async def test_alert_fires_on_measured_socket_loss(db_session: AsyncSession) -> None:
    srv = await _server_with_samples(db_session, [{"socket_drop": 12, "receive_drop": 0}])
    matches = await _matching_dhcp_packets_dropped_subjects(db_session, _rule())
    assert [m[0] for m in matches] == [str(srv.id)]
    assert "lost 12 packet(s)" in matches[0][2]


async def test_alert_is_silent_when_loss_was_measured_as_zero(
    db_session: AsyncSession,
) -> None:
    await _server_with_samples(db_session, [{"socket_drop": 0, "receive_drop": 0}])
    assert await _matching_dhcp_packets_dropped_subjects(db_session, _rule()) == []


async def test_alert_is_silent_when_loss_was_never_measured(
    db_session: AsyncSession,
) -> None:
    """An agent older than #980 reports neither counter. SUM over its rows is
    NULL, and NULL must not be read as either loss or its absence — the
    server is skipped, not alarmed on and not vouched for."""
    await _server_with_samples(db_session, [{"discover": 500}])
    assert await _matching_dhcp_packets_dropped_subjects(db_session, _rule()) == []


async def test_alert_never_fires_on_receive_drop_alone(
    db_session: AsyncSession,
) -> None:
    """THE REGRESSION THIS RULE MUST NOT HAVE.

    ``pkt4-receive-drop`` counts packets Kea read and discarded ON PURPOSE as
    well as by accident. Verified against kea-dhcp4 3.0.3: a client matching
    a ``DROP`` client-class increments it once per blocked packet, and a
    ``DROP`` class is exactly what the shipped DHCP MAC blocklist renders;
    the HA hook drops out-of-scope queries in hot-standby the same way.

    A default-on rule that counted it would therefore fire permanently, and
    never auto-resolve, on two ordinary correctly-working configurations.
    """
    await _server_with_samples(db_session, [{"socket_drop": 0, "receive_drop": 5000}])
    assert await _matching_dhcp_packets_dropped_subjects(db_session, _rule()) == []


async def test_alert_is_silent_when_only_socket_drop_is_unmeasured(
    db_session: AsyncSession,
) -> None:
    """The subtle half: ``receive_drop`` always arrives from a #980 agent, so
    a server whose procfs is unreadable has receive_drop set and socket_drop
    NULL. Testing the pair for "was this measured?" would call that
    measured-and-clean; it must read as unmeasured."""
    await _server_with_samples(db_session, [{"receive_drop": 3}])
    assert await _matching_dhcp_packets_dropped_subjects(db_session, _rule()) == []


async def test_alert_reports_receive_drop_as_context_when_it_fires(
    db_session: AsyncSession,
) -> None:
    """It is not the trigger, but it is worth telling the operator about —
    labelled as possibly-deliberate rather than as lost traffic."""
    await _server_with_samples(db_session, [{"socket_drop": 7, "receive_drop": 3}])
    matches = await _matching_dhcp_packets_dropped_subjects(db_session, _rule())
    msg = matches[0][2]
    assert "lost 7 packet(s)" in msg
    assert "3 packet(s) were read and then discarded" in msg
    assert "deliberate drops" in msg


async def test_alert_floor_is_honoured(db_session: AsyncSession) -> None:
    await _server_with_samples(db_session, [{"socket_drop": 5}])
    rule = _rule()
    rule.min_free_addresses = 100
    assert await _matching_dhcp_packets_dropped_subjects(db_session, rule) == []
    rule.min_free_addresses = 5
    assert len(await _matching_dhcp_packets_dropped_subjects(db_session, rule)) == 1


# ── the ingest path ─────────────────────────────────────────────────────
#
# Two behaviours, one of them a deliberate change to a shipped endpoint.
#
# NULL discipline: an agent that omits the loss fields (older than #980, or
# unable to read procfs) must store NULL, and an agent that reports 0 must
# store 0. Collapsing those makes an un-upgraded fleet read as a fleet with
# no packet loss.
#
# Accumulation: a second report for an existing bucket is ADDED, not
# substituted. The agent floors ``bucket_at`` to the minute while its own
# interval is 60 s +/- 3 s of jitter, so a tick early in a minute followed by
# a 57-59 s gap lands two genuinely different deltas in the same bucket.
# Overwriting — the original behaviour — silently discarded one of them,
# which for a loss counter discards exactly the minute being looked for.


async def _committed_server(db: AsyncSession) -> DHCPServer:
    """Create a server, commit, and hand back a LIVE instance.

    ``commit()`` expires every attribute, so touching ``srv.id`` afterwards
    triggers a lazy refresh outside the async greenlet and raises
    MissingGreenlet. Re-getting after the commit rebinds it to the session.
    """
    srv = await _group_with_server(db)
    sid = srv.id
    await db.commit()
    got = await db.get(DHCPServer, sid)
    assert got is not None
    return got


async def _post_metric(client: AsyncClient, server: DHCPServer, **body):
    from app.api.v1.dhcp.agents import _auth_agent
    from app.main import app

    app.dependency_overrides[_auth_agent] = lambda: (server, {})
    try:
        return await client.post("/api/v1/dhcp/agents/metrics", json=body)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def _sample(db: AsyncSession, server_id, at) -> DHCPMetricSample:
    """Read the row back with a fresh SELECT.

    Not ``db.get`` after ``expire_all``: the endpoint commits in the app's
    own session, so the test session's identity map holds a stale instance
    and expiring it makes the next attribute access try to check out a
    connection of its own.
    """
    row = (
        await db.execute(
            select(DHCPMetricSample)
            .where(DHCPMetricSample.server_id == server_id)
            .where(DHCPMetricSample.bucket_at == at)
        )
    ).scalar_one_or_none()
    return row


async def test_omitted_loss_fields_store_null_not_zero(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _committed_server(db_session)
    sid = srv.id
    at = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)

    r = await _post_metric(client, srv, bucket_at=at.isoformat(), discover=5)
    assert r.status_code == 200, r.text

    row = await _sample(db_session, sid, at)
    assert row is not None
    assert row.discover == 5
    assert row.socket_drop is None
    assert row.receive_drop is None


async def test_reported_zero_stores_zero(client: AsyncClient, db_session: AsyncSession) -> None:
    """The other side of the same coin: a working agent that measured no loss
    must be distinguishable from one that cannot measure."""
    srv = await _committed_server(db_session)
    sid = srv.id
    at = datetime(2026, 9, 6, 10, 1, tzinfo=UTC)

    r = await _post_metric(
        client, srv, bucket_at=at.isoformat(), discover=5, socket_drop=0, receive_drop=0
    )
    assert r.status_code == 200, r.text

    row = await _sample(db_session, sid, at)
    assert row.socket_drop == 0
    assert row.receive_drop == 0


async def test_a_second_report_for_one_bucket_accumulates(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _committed_server(db_session)
    sid = srv.id
    at = datetime(2026, 9, 6, 10, 2, tzinfo=UTC)

    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=5, socket_drop=2)
    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=7, socket_drop=3)

    row = await _sample(db_session, sid, at)
    assert row.discover == 12
    assert row.socket_drop == 5


async def test_an_unmeasured_second_poll_does_not_erase_a_measured_first(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """UNKNOWN + n = n. One poll failing to read procfs must not throw away
    what its neighbour in the same bucket did measure."""
    srv = await _committed_server(db_session)
    sid = srv.id
    at = datetime(2026, 9, 6, 10, 3, tzinfo=UTC)

    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=1, socket_drop=9)
    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=1)

    row = await _sample(db_session, sid, at)
    assert row.socket_drop == 9
    assert row.discover == 2


async def test_a_measured_second_poll_fills_an_unmeasured_first(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _committed_server(db_session)
    sid = srv.id
    at = datetime(2026, 9, 6, 10, 4, tzinfo=UTC)

    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=1)
    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=1, socket_drop=4)

    row = await _sample(db_session, sid, at)
    assert row.socket_drop == 4


async def test_two_unmeasured_polls_leave_the_bucket_unmeasured(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _committed_server(db_session)
    sid = srv.id
    at = datetime(2026, 9, 6, 10, 5, tzinfo=UTC)

    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=1)
    await _post_metric(client, srv, bucket_at=at.isoformat(), discover=1)

    row = await _sample(db_session, sid, at)
    assert row.socket_drop is None


# ── the agent/server column-name boundary ───────────────────────────────


def test_agent_metric_columns_match_the_ingest_model() -> None:
    """The agent's column names must be exactly the ingest model's fields.

    ``DHCPMetricReport`` does not set ``extra="forbid"`` — deliberately, so a
    newer agent posting a field an older control plane has never heard of
    loses that field rather than having the whole sample 422'd mid-upgrade.
    The cost of that choice is that a *typo* is equally silent: the agent
    would post ``socket_drops``, pydantic would drop it, the column would
    stay NULL forever, and every surface would render "loss not measured" on
    a fleet that is measuring perfectly well.

    So the boundary is pinned here instead. Reads the agent source rather
    than importing it: ``agent/dhcp`` is a separate distribution and is not
    installed in the backend's environment.
    """
    import ast
    from pathlib import Path

    from app.api.v1.dhcp.agents import DHCPMetricReport

    agent_src = (
        Path(__file__).resolve().parents[2] / "agent" / "dhcp" / "spatium_dhcp_agent" / "metrics.py"
    )
    if not agent_src.exists():  # pragma: no cover - see docstring
        import pytest

        pytest.skip(f"agent source not present at {agent_src} (backend-only checkout)")

    tree = ast.parse(agent_src.read_text())
    stat_map: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "_STAT_MAP" for t in node.targets
        ):
            assert isinstance(node.value, ast.Dict)
            for k, v in zip(node.value.keys, node.value.values, strict=True):
                assert isinstance(k, ast.Constant) and isinstance(v, ast.Constant)
                stat_map[k.value] = v.value
    assert stat_map, "could not find _STAT_MAP in the agent source"

    # Every column the agent computes a delta for must be a field the server
    # stores. ``socket_drop`` is not in _STAT_MAP — it comes from procfs, not
    # from Kea — so it is added here explicitly rather than being forgotten.
    agent_columns = set(stat_map.values()) | {"socket_drop"}
    # ``batch_id`` is the #1077 replay-dedupe envelope, stamped by the spool's
    # Shipper on every push rather than computed by the poller.
    model_fields = set(DHCPMetricReport.model_fields) - {"bucket_at", "batch_id"}
    assert agent_columns == model_fields, (
        f"agent sends {sorted(agent_columns - model_fields)} the server ignores; "
        f"server expects {sorted(model_fields - agent_columns)} the agent never sends"
    )

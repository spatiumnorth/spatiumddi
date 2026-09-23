"""Server half of the agent push spool (#1077).

Agents spool a push the control plane did not acknowledge and replay it on
reconnect, stamped with a ``batch_id``. What this covers, and what each
failure would look like:

* **Replay dedupe.** The batch in flight when the control plane went away is
  replayed even if it was committed (the response was lost). Without the
  receipt, a replayed lease batch is harmless but a replayed METRIC batch is
  not: both DNS and DHCP metrics accumulate per bucket, so a replay would
  silently double a minute of traffic — or of packet loss.
* **No batch_id = old behaviour.** A pre-#1077 agent must not be deduped
  into losing data, and two genuinely different deltas for one bucket must
  still both count (the #980 jitter collision).
* **Retention-aware ingest.** A replayed multi-day backlog must not insert
  log rows the nightly prune would delete on its next run — but a line with
  no parseable timestamp (stamped "now" by the parser) must never be dropped.
* **Heartbeat spool status.** NULL = never reported; a heartbeat without the
  field must not erase what a newer one recorded.
* **The alert.** Fires on a recent trim, critical when lease events were
  lost, silent on NULL and on an old trim.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agent_ingest import AgentIngestReceipt
from app.models.dhcp import DHCPLease, DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.logs import DHCPLogEntry, DNSQueryLogEntry
from app.models.metrics import DHCPMetricSample, DNSMetricSample
from app.services.agents.ingest_receipt import RECEIPT_RETENTION_DAYS, prune_receipts
from app.services.agents.spool_status import apply_reported_spool
from app.services.alerts import _matching_agent_spool_trimmed_subjects
from app.tasks.prune_logs import DEFAULT_RETENTION_HOURS

_RULE = SimpleNamespace(severity="warning")


def _bid() -> str:
    return uuid.uuid4().hex


# ── fixtures ──────────────────────────────────────────────────────────────


async def _dhcp_server(db: AsyncSession) -> DHCPServer:
    group = DHCPServerGroup(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DHCPServer(
        name=f"kea-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        status="active",
        server_group_id=group.id,
    )
    db.add(srv)
    await db.flush()
    sid = srv.id
    await db.commit()
    got = await db.get(DHCPServer, sid)
    assert got is not None
    return got


async def _dns_server(db: AsyncSession) -> DNSServer:
    group = DNSServerGroup(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    srv = DNSServer(
        group_id=group.id,
        name=f"ns-{uuid.uuid4().hex[:6]}",
        driver="bind9",
        host="10.0.0.53",
        port=53,
    )
    db.add(srv)
    await db.flush()
    sid = srv.id
    await db.commit()
    got = await db.get(DNSServer, sid)
    assert got is not None
    return got


async def _post(client: AsyncClient, kind: str, server: object, path: str, body: dict):
    from app.main import app

    if kind == "dhcp":
        from app.api.v1.dhcp.agents import _auth_agent
    else:
        from app.api.v1.dns.agents import _auth_agent  # type: ignore[no-redef]
    # An ``exp`` far in the future so the heartbeat does not rotate the token.
    far = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    app.dependency_overrides[_auth_agent] = lambda: (server, {"exp": far})
    try:
        return await client.post(f"/api/v1/{kind}/agents/{path}", json=body)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


async def _count(db: AsyncSession, model: type, server_id: uuid.UUID) -> int:
    return int(
        await db.scalar(select(func.count()).select_from(model).where(model.server_id == server_id))
        or 0
    )


async def _metric(db: AsyncSession, model: type, server_id: uuid.UUID, at: datetime):
    return (
        await db.execute(
            select(model).where(model.server_id == server_id).where(model.bucket_at == at)
        )
    ).scalar_one_or_none()


def _bucket() -> datetime:
    return datetime.now(UTC).replace(second=0, microsecond=0) - timedelta(minutes=3)


# ── DHCP metrics: the accumulate path is where a replay would hurt ────────


async def test_dhcp_metric_replay_is_not_double_counted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dhcp_server(db_session)
    at = _bucket()
    body = {"bucket_at": at.isoformat(), "discover": 7, "socket_drop": 3, "batch_id": _bid()}

    r1 = await _post(client, "dhcp", srv, "metrics", body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["duplicate"] is False
    r2 = await _post(client, "dhcp", srv, "metrics", body)
    assert r2.status_code == 200, r2.text
    assert r2.json() == {"status": "ok", "duplicate": True}

    row = await _metric(db_session, DHCPMetricSample, srv.id, at)
    assert row is not None
    assert row.discover == 7
    assert row.socket_drop == 3


async def test_dhcp_metrics_without_batch_id_still_accumulate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Negative control: a pre-#1077 agent sends no batch_id, and two
    different deltas landing in one bucket (the #980 jitter collision) are
    both real — dedupe must not swallow the second."""
    srv = await _dhcp_server(db_session)
    at = _bucket()
    body = {"bucket_at": at.isoformat(), "discover": 7}
    assert (await _post(client, "dhcp", srv, "metrics", body)).status_code == 200
    assert (await _post(client, "dhcp", srv, "metrics", body)).status_code == 200
    row = await _metric(db_session, DHCPMetricSample, srv.id, at)
    assert row is not None and row.discover == 14


async def test_distinct_batch_ids_in_one_bucket_both_count(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dhcp_server(db_session)
    at = _bucket()
    for n in (4, 5):
        r = await _post(
            client,
            "dhcp",
            srv,
            "metrics",
            {"bucket_at": at.isoformat(), "discover": n, "batch_id": _bid()},
        )
        assert r.status_code == 200
    row = await _metric(db_session, DHCPMetricSample, srv.id, at)
    assert row is not None and row.discover == 9


# ── DNS metrics now accumulate (the #980 fix, DNS side) ───────────────────


async def test_dns_metrics_accumulate_and_dedupe(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns_server(db_session)
    at = _bucket()
    first = {"bucket_at": at.isoformat(), "queries_total": 100, "nxdomain": 2, "batch_id": _bid()}
    second = {"bucket_at": at.isoformat(), "queries_total": 40, "nxdomain": 1, "batch_id": _bid()}
    assert (await _post(client, "dns", srv, "metrics", first)).status_code == 200
    assert (await _post(client, "dns", srv, "metrics", second)).status_code == 200
    replay = await _post(client, "dns", srv, "metrics", first)
    assert replay.json()["duplicate"] is True

    row = await _metric(db_session, DNSMetricSample, srv.id, at)
    assert row is not None
    # Overwrite (the old behaviour) would read 40 / 1; the replay, undeduped,
    # would read 240 / 5.
    assert row.queries_total == 140
    assert row.nxdomain == 3


# ── DNS query log: dedupe + retention-aware ingest ────────────────────────


def _bind_line(ts: datetime | None, qname: str, port: int = 54321) -> str:
    head = ts.strftime("%d-%b-%Y %H:%M:%S.000 ") if ts is not None else ""
    return (
        f"{head}client @0x7f8b1c001234 192.0.2.5#{port} "
        f"({qname}): query: {qname} IN A +E(0)K (10.0.0.1)"
    )


async def test_query_log_replay_inserts_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns_server(db_session)
    now = datetime.now(UTC)
    body = {
        "lines": [_bind_line(now - timedelta(minutes=2), f"q{i}.example") for i in range(3)],
        "batch_id": _bid(),
    }
    r1 = await _post(client, "dns", srv, "query-log-entries", body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["inserted"] == 3
    r2 = await _post(client, "dns", srv, "query-log-entries", body)
    assert r2.json()["duplicate"] is True
    assert r2.json()["inserted"] == 0
    assert await _count(db_session, DNSQueryLogEntry, srv.id) == 3


async def test_query_log_without_batch_id_is_not_deduped(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns_server(db_session)
    body = {"lines": [_bind_line(datetime.now(UTC) - timedelta(minutes=1), "a.example")]}
    await _post(client, "dns", srv, "query-log-entries", body)
    await _post(client, "dns", srv, "query-log-entries", body)
    assert await _count(db_session, DNSQueryLogEntry, srv.id) == 2


async def test_query_log_drops_lines_past_retention_but_not_undated_ones(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns_server(db_session)
    now = datetime.now(UTC)
    old = now - timedelta(hours=DEFAULT_RETENTION_HOURS + 2)
    body = {
        "lines": [
            _bind_line(old, "stale.example"),
            _bind_line(now - timedelta(minutes=5), "fresh.example"),
            # No leading timestamp: the parser stamps arrival time, so this
            # must never be counted as expired.
            _bind_line(None, "undated.example"),
        ],
        "batch_id": _bid(),
    }
    r = await _post(client, "dns", srv, "query-log-entries", body)
    assert r.status_code == 200, r.text
    assert r.json()["expired"] == 1
    assert r.json()["inserted"] == 2
    names = set(
        (
            await db_session.execute(
                select(DNSQueryLogEntry.qname).where(DNSQueryLogEntry.server_id == srv.id)
            )
        )
        .scalars()
        .all()
    )
    assert names == {"fresh.example", "undated.example"}


# ── DHCP activity log: same two properties ────────────────────────────────


def _kea_line(ts: datetime, mac: str) -> str:
    return (
        f"{ts.strftime('%Y-%m-%d %H:%M:%S.000')} INFO  [kea-dhcp4.leases/12345.139] "
        f"DHCP4_LEASE_ALLOC [hwtype=1 {mac}], cid=[no info], "
        "tid=0x12345678: lease 192.0.2.10 has been allocated for 3600 seconds"
    )


async def test_dhcp_log_dedupe_and_expiry(client: AsyncClient, db_session: AsyncSession) -> None:
    srv = await _dhcp_server(db_session)
    now = datetime.now(UTC)
    body = {
        "lines": [
            _kea_line(now - timedelta(hours=DEFAULT_RETENTION_HOURS + 1), "aa:bb:cc:dd:ee:01"),
            _kea_line(now - timedelta(minutes=1), "aa:bb:cc:dd:ee:02"),
            # Unparseable → kept with the raw text, stamped with arrival time.
            "some kea line with no recognisable shape",
        ],
        "batch_id": _bid(),
    }
    r1 = await _post(client, "dhcp", srv, "log-entries", body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["expired"] == 1
    assert r1.json()["inserted"] == 2
    r2 = await _post(client, "dhcp", srv, "log-entries", body)
    assert r2.json()["duplicate"] is True
    assert await _count(db_session, DHCPLogEntry, srv.id) == 2


# ── lease events + the other DHCP batch streams ───────────────────────────


async def _lease_seed(db: AsyncSession) -> DHCPServer:
    space = IPSpace(name=f"sp-sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.71.0.0/16", name="sp-blk")
    db.add(block)
    await db.flush()
    db.add(Subnet(space_id=space.id, block_id=block.id, network="10.71.1.0/24", name="sp-sn"))
    await db.flush()
    return await _dhcp_server(db)


async def test_lease_event_replay_is_a_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _lease_seed(db_session)
    now = datetime.now(UTC)
    body = {
        "leases": [
            {
                "ip_address": "10.71.1.50",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "hostname": "laptop",
                "state": "active",
                "starts_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
            }
        ],
        "batch_id": _bid(),
    }
    r1 = await _post(client, "dhcp", srv, "lease-events", body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["upserted"] == 1
    assert r1.json()["duplicate"] is False
    r2 = await _post(client, "dhcp", srv, "lease-events", body)
    assert r2.status_code == 200, r2.text
    assert r2.json() == {"status": "ok", "duplicate": True, "upserted": 0}
    assert await _count(db_session, DHCPLease, srv.id) == 1


async def test_released_lease_state_is_ingested_and_tears_down_the_mirror(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Kea 3.0's CSV state 3 is ``released``; the agent now reports it as such
    (it used to be mis-mapped to active). It must be accepted and treated like
    any other non-active state: lease row updated, auto IPAM mirror removed."""
    from app.models.ipam import IPAddress

    srv = await _lease_seed(db_session)
    now = datetime.now(UTC)
    lease = {
        "ip_address": "10.71.1.60",
        "mac_address": "aa:bb:cc:dd:ee:60",
        "state": "active",
        "starts_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
    }
    r = await _post(client, "dhcp", srv, "lease-events", {"leases": [lease], "batch_id": _bid()})
    assert r.status_code == 200, r.text
    mirror = select(func.count()).select_from(IPAddress).where(IPAddress.address == "10.71.1.60")
    assert await db_session.scalar(mirror) == 1

    r = await _post(
        client,
        "dhcp",
        srv,
        "lease-events",
        {"leases": [{**lease, "state": "released"}], "batch_id": _bid()},
    )
    assert r.status_code == 200, r.text
    states = (
        (await db_session.execute(select(DHCPLease.state).where(DHCPLease.server_id == srv.id)))
        .scalars()
        .all()
    )
    assert states == ["released"]
    assert await db_session.scalar(mirror) == 0


async def test_fingerprint_replay_is_a_duplicate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dhcp_server(db_session)
    body = {
        "fingerprints": [{"mac_address": "aa:bb:cc:00:00:01", "option_55": "1,3,6"}],
        "batch_id": _bid(),
    }
    r1 = await _post(client, "dhcp", srv, "dhcp-fingerprints", body)
    assert r1.status_code == 200, r1.text
    assert r1.json()["duplicate"] is False
    r2 = await _post(client, "dhcp", srv, "dhcp-fingerprints", body)
    assert r2.json()["duplicate"] is True
    assert r2.json()["upserted"] == 0


async def test_receipt_shares_the_ingest_transaction(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """One receipt per committed batch, keyed on (server, batch)."""
    srv = await _dhcp_server(db_session)
    bid = _bid()
    await _post(
        client,
        "dhcp",
        srv,
        "metrics",
        {"bucket_at": _bucket().isoformat(), "discover": 1, "batch_id": bid},
    )
    rows = (
        (
            await db_session.execute(
                select(AgentIngestReceipt).where(AgentIngestReceipt.server_id == srv.id)
            )
        )
        .scalars()
        .all()
    )
    assert [(r.batch_id, r.stream) for r in rows] == [(bid, "dhcp.metrics")]


@pytest.mark.parametrize(
    "bad",
    [
        "A" * 32,  # uppercase
        "a" * 31,  # short
        "a" * 33,  # long
        "g" * 32,  # not hex
        "x'; drop table dhcp_lease; --",
    ],
)
async def test_malformed_batch_id_is_422(
    client: AsyncClient, db_session: AsyncSession, bad: str
) -> None:
    srv = await _dhcp_server(db_session)
    r = await _post(client, "dhcp", srv, "lease-events", {"leases": [], "batch_id": bad})
    assert r.status_code == 422, r.text
    r = await _post(
        client,
        "dhcp",
        srv,
        "metrics",
        {"bucket_at": _bucket().isoformat(), "batch_id": bad},
    )
    assert r.status_code == 422, r.text


# ── receipt prune ─────────────────────────────────────────────────────────


async def test_prune_removes_only_expired_receipts(db_session: AsyncSession) -> None:
    sid = uuid.uuid4()
    now = datetime.now(UTC)
    db_session.add_all(
        [
            AgentIngestReceipt(
                server_id=sid,
                batch_id=_bid(),
                stream="dns.metrics",
                received_at=now - timedelta(days=RECEIPT_RETENTION_DAYS + 1),
            ),
            AgentIngestReceipt(
                server_id=sid,
                batch_id=_bid(),
                stream="dns.metrics",
                received_at=now - timedelta(days=1),
            ),
        ]
    )
    await db_session.commit()
    assert await prune_receipts(db_session) == 1
    # Idempotent: a second pass finds nothing.
    assert await prune_receipts(db_session) == 0
    await db_session.commit()
    remaining = await db_session.scalar(
        select(func.count())
        .select_from(AgentIngestReceipt)
        .where(AgentIngestReceipt.server_id == sid)
    )
    assert remaining == 1


# ── heartbeat spool status ────────────────────────────────────────────────


def _spool(trim_at: datetime | None = None, stream: str = "query_log", bytes_: int = 0) -> dict:
    per = {
        "enabled": True,
        "entries": 1 if bytes_ else 0,
        "bytes": bytes_,
        "cap_bytes": 1000,
        "oldest_at": None,
        "trimmed_entries_total": 2 if trim_at else 0,
        "trimmed_bytes_total": 2048 if trim_at else 0,
        "last_trim_at": trim_at.isoformat() if trim_at else None,
        "expired_entries_total": 0,
        "rejected_entries_total": 0,
        "write_failures_total": 0,
    }
    return {
        "enabled": True,
        "cap_bytes": 268435456,
        "bytes": bytes_,
        "entries": per["entries"],
        "oldest_at": None,
        "trimmed_entries_total": per["trimmed_entries_total"],
        "trimmed_bytes_total": per["trimmed_bytes_total"],
        "last_trim_at": per["last_trim_at"],
        "expired_entries_total": 0,
        "streams": {stream: per},
        "some_future_field": 1,
    }


async def test_heartbeat_persists_spool_and_omission_leaves_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    srv = await _dns_server(db_session)
    r = await _post(client, "dns", srv, "heartbeat", {"spool": _spool(bytes_=3_355_443)})
    assert r.status_code == 200, r.text
    row = (
        await db_session.execute(select(DNSServer.spool_status).where(DNSServer.id == srv.id))
    ).scalar_one()
    assert row is not None and row["bytes"] == 3_355_443
    assert "some_future_field" not in row  # extra keys tolerated, not stored

    # A heartbeat without the field (a pre-#1077 agent, or a downgrade) must
    # not turn a known report into NULL.
    r = await _post(client, "dns", srv, "heartbeat", {})
    assert r.status_code == 200, r.text
    row = (
        await db_session.execute(select(DNSServer.spool_status).where(DNSServer.id == srv.id))
    ).scalar_one()
    assert row is not None and row["bytes"] == 3_355_443


async def test_dhcp_heartbeat_persists_spool(client: AsyncClient, db_session: AsyncSession) -> None:
    srv = await _dhcp_server(db_session)
    r = await _post(client, "dhcp", srv, "heartbeat", {"spool": _spool(bytes_=10)})
    assert r.status_code == 200, r.text
    row = (
        await db_session.execute(select(DHCPServer.spool_status).where(DHCPServer.id == srv.id))
    ).scalar_one()
    assert row is not None and row["streams"]["query_log"]["bytes"] == 10


async def test_malformed_spool_report_does_not_fail_the_heartbeat(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A telemetry bug must not take the agent offline (no ACKs, no rotation)."""
    srv = await _dns_server(db_session)
    r = await _post(client, "dns", srv, "heartbeat", {"spool": {"bytes": -5}})
    assert r.status_code == 200, r.text
    row = (
        await db_session.execute(select(DNSServer.spool_status).where(DNSServer.id == srv.id))
    ).scalar_one()
    assert row is None


def test_apply_reported_spool_none_is_a_no_op() -> None:
    row = SimpleNamespace(spool_status={"bytes": 5})
    apply_reported_spool(row, None, agent_kind="dns", server_id="s")
    assert row.spool_status == {"bytes": 5}


# ── alert ─────────────────────────────────────────────────────────────────


async def _server_with_spool(db: AsyncSession, spool: dict | None) -> DNSServer:
    srv = await _dns_server(db)
    srv.spool_status = spool
    await db.commit()
    return srv


async def test_alert_fires_warning_on_recent_log_trim(db_session: AsyncSession) -> None:
    srv = await _server_with_spool(
        db_session, _spool(datetime.now(UTC) - timedelta(hours=1), "query_log")
    )
    hits = await _matching_agent_spool_trimmed_subjects(db_session, _RULE)
    mine = [h for h in hits if h[0] == f"dns_server:{srv.id}"]
    assert len(mine) == 1
    _, _, message, severity = mine[0]
    assert severity == "warning"
    assert "query_log" in message
    assert "2.0 KiB" in message


async def test_alert_is_critical_when_lease_events_were_trimmed(
    db_session: AsyncSession,
) -> None:
    srv = await _dhcp_server(db_session)
    srv.spool_status = _spool(datetime.now(UTC) - timedelta(minutes=5), "lease_events")
    await db_session.commit()
    hits = await _matching_agent_spool_trimmed_subjects(db_session, _RULE)
    mine = [h for h in hits if h[0] == f"dhcp_server:{srv.id}"]
    assert len(mine) == 1
    assert mine[0][3] == "critical"
    assert "Lease events" in mine[0][2]


async def test_alert_silent_on_old_trim_null_and_backlog_only(
    db_session: AsyncSession,
) -> None:
    old = await _server_with_spool(
        db_session, _spool(datetime.now(UTC) - timedelta(hours=30), "query_log")
    )
    null = await _server_with_spool(db_session, None)
    backlog = await _server_with_spool(db_session, _spool(None, bytes_=500))
    hits = {h[0] for h in await _matching_agent_spool_trimmed_subjects(db_session, _RULE)}
    for srv in (old, null, backlog):
        assert f"dns_server:{srv.id}" not in hits

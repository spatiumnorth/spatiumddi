"""DNS query log / DHCP activity log forwarding to syslog targets (#4545).

What each group guards:

* **Opt-in.** Both streams are off on a new target and on every target that
  predates the feature; a target that is off never receives an entry.
* **Filters and sampling** decide per entry, per target.
* **Framing.** One event per entry in the target's own syslog format.
* **Decoupling.** The agent's ingest request returns while the collector is
  stuck, memory stays bounded, and what is lost is counted, persisted on the
  target row and raised by the ``log_forward_dropping`` alert.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit_forward import AuditForwardTarget
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.services import audit_forward, log_stream_forward
from app.services.alerts import _matching_log_forward_dropping_subjects
from app.services.log_stream_forward import accepts, dhcp_event, dns_event

# ── helpers ───────────────────────────────────────────────────────────────


def _target(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "name": "siem",
        "format": "rfc5424_json",
        "host": "siem.example.test",
        "port": 514,
        "protocol": "udp",
        "facility": 16,
        "ca_cert_pem": None,
        "stream_dns_query_log": True,
        "stream_dhcp_activity_log": True,
        "log_stream_filters": None,
        "dns_query_sample_percent": 100,
    }
    base.update(kw)
    return base


def _dns(**kw: Any) -> dict[str, Any]:
    ev = {
        "stream": "dns_query_log",
        "timestamp": "2026-11-19T10:00:00+00:00",
        "severity": "info",
        "server_id": str(uuid.uuid4()),
        "server_name": "ns1",
        "server_group_id": str(uuid.uuid4()),
        "client_ip": "192.0.2.5",
        "client_port": 54321,
        "qname": "www.example.test",
        "qclass": "IN",
        "qtype": "A",
        "flags": "+E(0)K",
        "view": None,
        "rcode": "NOERROR",
        "answer_count": 1,
        "raw": "raw line",
    }
    ev.update(kw)
    return ev


def _dhcp(**kw: Any) -> dict[str, Any]:
    ev = {
        "stream": "dhcp_activity_log",
        "timestamp": "2026-11-19T10:00:00+00:00",
        "severity": "info",
        "server_id": str(uuid.uuid4()),
        "server_name": "kea1",
        "server_group_id": str(uuid.uuid4()),
        "code": "DHCP4_LEASE_ALLOC",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ip_address": "192.0.2.10",
        "transaction_id": "0x1",
        "raw": "raw line",
    }
    ev.update(kw)
    return ev


# ── opt-in, filters, sampling ─────────────────────────────────────────────


def test_a_target_without_the_stream_flag_gets_nothing() -> None:
    off = _target(stream_dns_query_log=False, stream_dhcp_activity_log=False)
    assert not accepts(off, _dns())
    assert not accepts(off, _dhcp())
    only_dns = _target(stream_dhcp_activity_log=False)
    assert accepts(only_dns, _dns())
    assert not accepts(only_dns, _dhcp())


def test_dns_filters() -> None:
    group, server = str(uuid.uuid4()), str(uuid.uuid4())
    t = _target(
        log_stream_filters={
            "dns_server_group_ids": [group],
            "dns_rcodes": ["NXDOMAIN"],
            "dns_qtypes": ["AAAA"],
        }
    )
    hit = _dns(server_group_id=group, rcode="NXDOMAIN", qtype="AAAA")
    assert accepts(t, hit)
    assert not accepts(t, _dns(server_group_id=str(uuid.uuid4()), rcode="NXDOMAIN", qtype="AAAA"))
    assert not accepts(t, _dns(server_group_id=group, rcode="NOERROR", qtype="AAAA"))
    assert not accepts(t, _dns(server_group_id=group, rcode="NXDOMAIN", qtype="A"))
    # An unrecorded rcode is UNKNOWN: it never passes an rcode filter.
    assert not accepts(t, _dns(server_group_id=group, rcode=None, qtype="AAAA"))
    by_server = _target(log_stream_filters={"dns_server_ids": [server]})
    assert accepts(by_server, _dns(server_id=server))
    assert not accepts(by_server, _dns())


def test_dhcp_filters() -> None:
    group = str(uuid.uuid4())
    t = _target(
        log_stream_filters={
            "dhcp_server_group_ids": [group],
            "dhcp_codes": ["DHCP4_LEASE_ALLOC"],
        }
    )
    assert accepts(t, _dhcp(server_group_id=group))
    assert not accepts(t, _dhcp(server_group_id=group, code="DHCP4_PACKET_DROP_0001"))
    assert not accepts(t, _dhcp(code="DHCP4_LEASE_ALLOC"))
    # DNS-only filters do not narrow the DHCP stream.
    assert accepts(_target(log_stream_filters={"dns_rcodes": ["SERVFAIL"]}), _dhcp())


def test_sampling_applies_to_queries_only(monkeypatch: pytest.MonkeyPatch) -> None:
    t = _target(dns_query_sample_percent=10)
    monkeypatch.setattr(log_stream_forward, "_rand", lambda: 5.0)
    assert accepts(t, _dns())
    monkeypatch.setattr(log_stream_forward, "_rand", lambda: 50.0)
    assert not accepts(t, _dns())
    assert accepts(t, _dhcp())
    assert accepts(_target(dns_query_sample_percent=100), _dns())


def test_filter_validation() -> None:
    norm = log_stream_forward.normalize_filters
    assert norm(None) is None and norm({}) is None and norm({"dns_rcodes": []}) is None
    assert norm({"dns_rcodes": ["nxdomain", " NXDOMAIN "]}) == {"dns_rcodes": ["NXDOMAIN"]}
    with pytest.raises(ValueError):
        norm({"nope": ["x"]})
    with pytest.raises(ValueError):
        norm({"dns_server_ids": ["not-a-uuid"]})


# ── framing ───────────────────────────────────────────────────────────────


def render(target: dict[str, Any], event: dict[str, Any]) -> str:
    return audit_forward.render_log_stream_lines(target, [event])[0]


def test_framing_per_format() -> None:
    ev = _dns()
    five = render(_target(format="rfc5424_json"), ev)
    # facility 16 (local0) * 8 + severity 6 (info) = 134
    assert five.startswith("<134>1 2026-11-19T10:00:00+00:00 ")
    assert " spatiumddi - DNSQUERY - " in five
    assert json.loads(five.split(" - DNSQUERY - ", 1)[1])["qname"] == "www.example.test"

    three = render(_target(format="rfc3164"), ev)
    assert three.startswith("<134>Nov 19 10:00:00 ")
    assert json.loads(three.split("spatiumddi: ", 1)[1])["client_ip"] == "192.0.2.5"

    bare = render(_target(format="json_lines"), ev)
    assert json.loads(bare) == ev
    assert "\n" not in bare


def test_log_events_are_redacted_like_every_other_forwarded_payload() -> None:
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\n-----END PRIVATE KEY-----"
    line = render(_target(), _dns(raw=f"leaked {pem}"))
    assert "MIIEvQIBADANBgkqhkiG9w0B" not in line
    assert render(_target(), _dns(raw=None)).count("raw") == 1


def test_dhcp_severity_and_msgid() -> None:
    row = SimpleNamespace(
        ts=datetime(2026, 11, 19, 10, 0, tzinfo=UTC),
        server_id=uuid.uuid4(),
        server_name="kea1",
        severity="ERROR",
        code="DHCP4_PACKET_DROP_0001",
        mac_address="aa:bb:cc:dd:ee:ff",
        ip_address=None,
        transaction_id=None,
        raw="x",
    )
    ev = dhcp_event(row, uuid.uuid4())
    line = render(_target(format="rfc5424_json"), ev)
    # severity 3 (err): 16 * 8 + 3 = 131
    assert line.startswith("<131>1 ") and " DHCPLOG " in line
    row.severity = "FATAL"
    assert render(_target(), dhcp_event(row, None)).startswith("<130>1 ")  # crit


def test_dns_event_carries_the_logs_page_fields() -> None:
    row = SimpleNamespace(
        ts=datetime(2026, 11, 19, 10, 0, tzinfo=UTC),
        server_id=uuid.uuid4(),
        server_name="ns1",
        client_ip="192.0.2.5",
        client_port=1,
        qname="a.example",
        qclass="IN",
        qtype="A",
        flags="+",
        view="internal",
        rcode="NXDOMAIN",
        answer_count=0,
        raw="r",
    )
    ev = dns_event(row, uuid.uuid4())
    for key in ("timestamp", "server_name", "client_ip", "qname", "qtype", "rcode", "view"):
        assert ev[key] is not None


# ── the settings API ──────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


_URL = "/api/v1/settings/audit-forward-targets"


async def test_streams_default_off_and_round_trip(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    body = {"name": "plain", "kind": "syslog", "host": "siem.example.test"}
    r = await client.post(_URL, headers=h, json=body)
    assert r.status_code == 201, r.text
    t = r.json()
    assert t["stream_dns_query_log"] is False
    assert t["stream_dhcp_activity_log"] is False
    assert t["log_stream_filters"] is None
    assert t["dns_query_sample_percent"] == 100
    assert t["log_stream_dropped_total"] == 0

    r = await client.put(
        f"{_URL}/{t['id']}",
        headers=h,
        json={
            "stream_dns_query_log": True,
            "log_stream_filters": {"dns_rcodes": ["servfail"]},
            "dns_query_sample_percent": 25,
        },
    )
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["stream_dns_query_log"] is True
    assert got["log_stream_filters"] == {"dns_rcodes": ["SERVFAIL"]}
    assert got["dns_query_sample_percent"] == 25


async def test_streams_refused_where_they_cannot_be_delivered(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    webhook = {
        "name": "hook",
        "kind": "webhook",
        "url": "https://hooks.example.test/x",
        "stream_dns_query_log": True,
    }
    r = await client.post(_URL, headers=h, json=webhook)
    assert r.status_code == 422, r.text
    cef = {
        "name": "cef",
        "kind": "syslog",
        "host": "siem.example.test",
        "format": "rfc5424_cef",
        "stream_dhcp_activity_log": True,
    }
    assert (await client.post(_URL, headers=h, json=cef)).status_code == 422
    ok = await client.post(
        _URL, headers=h, json={"name": "ok", "kind": "syslog", "host": "siem.example.test"}
    )
    tid = ok.json()["id"]
    # An update is judged on the merged row.
    r = await client.put(
        f"{_URL}/{tid}", headers=h, json={"format": "rfc5424_leef", "stream_dns_query_log": True}
    )
    assert r.status_code == 422
    assert (
        await client.put(f"{_URL}/{tid}", headers=h, json={"dns_query_sample_percent": 0})
    ).status_code == 422
    assert (
        await client.put(f"{_URL}/{tid}", headers=h, json={"log_stream_filters": {"x": ["y"]}})
    ).status_code == 422


# ── ingest → forward ──────────────────────────────────────────────────────


async def _dns_server(db: AsyncSession) -> DNSServer:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
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


async def _dhcp_server(db: AsyncSession) -> DHCPServer:
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
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


async def _post(client: AsyncClient, kind: str, server: object, path: str, body: dict):
    from app.main import app

    if kind == "dhcp":
        from app.api.v1.dhcp.agents import _auth_agent
    else:
        from app.api.v1.dns.agents import _auth_agent  # type: ignore[no-redef]
    far = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
    app.dependency_overrides[_auth_agent] = lambda: (server, {"exp": far})
    try:
        return await client.post(f"/api/v1/{kind}/agents/{path}", json=body)
    finally:
        app.dependency_overrides.pop(_auth_agent, None)


def _bind_line(qname: str, port: int = 54321) -> str:
    ts = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%d-%b-%Y %H:%M:%S.000 ")
    return (
        f"{ts}client @0x7f8b1c001234 192.0.2.5#{port} "
        f"({qname}): query: {qname} IN A +E(0)K (10.0.0.1)"
    )


def _kea_line() -> str:
    ts = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S.000")
    return (
        f"{ts} INFO  [kea-dhcp4.leases/12345.139] DHCP4_LEASE_ALLOC "
        "[hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x12345678: "
        "lease 192.0.2.10 has been allocated for 3600 seconds"
    )


async def _add_target(db: AsyncSession, **kw: Any) -> AuditForwardTarget:
    t = AuditForwardTarget(
        name=f"siem-{uuid.uuid4().hex[:6]}",
        kind="syslog",
        host="siem.example.test",
        port=514,
        protocol="tcp",
        **kw,
    )
    db.add(t)
    await db.commit()
    log_stream_forward.invalidate()
    return t


async def _settle() -> None:
    """Wait for routing and delivery to finish."""
    st = log_stream_forward._state  # noqa: SLF001
    for _ in range(500):
        busy = st.ingress or any(
            tq.events or (tq.task is not None and not tq.task.done()) for tq in st.targets.values()
        )
        if not busy and (st.pump is None or st.pump.done()):
            return
        await asyncio.sleep(0.01)
    raise AssertionError("log stream forwarder did not settle")


class _Wire:
    """A fake collector that records every batch it is handed."""

    def __init__(self) -> None:
        self.batches: list[list[str]] = []

    async def __call__(
        self, host: str, port: int, protocol: str, messages: list[str], ca_cert_pem: Any = None
    ) -> None:
        self.batches.append(list(messages))

    @property
    def lines(self) -> list[str]:
        return [m for b in self.batches for m in b]


async def test_opted_in_target_receives_dns_and_dhcp_entries(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    wire = _Wire()
    monkeypatch.setattr(audit_forward, "_send_syslog_batch", wire)
    await _add_target(db_session, stream_dns_query_log=True, stream_dhcp_activity_log=True)
    dns, dhcp = await _dns_server(db_session), await _dhcp_server(db_session)

    r = await _post(
        client,
        "dns",
        dns,
        "query-log-entries",
        {"lines": [_bind_line("one.example"), _bind_line("two.example", 2)]},
    )
    assert r.status_code == 200 and r.json()["inserted"] == 2
    await _settle()
    names = {json.loads(m.split(" - DNSQUERY - ", 1)[1])["qname"] for m in wire.lines}
    assert names == {"one.example", "two.example"}
    sample = json.loads(wire.lines[0].split(" - DNSQUERY - ", 1)[1])
    assert sample["server_name"] == dns.name
    assert sample["server_group_id"] == str(dns.group_id)

    r = await _post(client, "dhcp", dhcp, "log-entries", {"lines": [_kea_line()]})
    assert r.status_code == 200 and r.json()["inserted"] == 1
    await _settle()
    last = json.loads(wire.lines[-1].split(" - DHCPLOG - ", 1)[1])
    assert last["code"] == "DHCP4_LEASE_ALLOC" and last["mac_address"] == "aa:bb:cc:dd:ee:ff"


async def test_target_without_the_stream_receives_nothing(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    wire = _Wire()
    monkeypatch.setattr(audit_forward, "_send_syslog_batch", wire)
    await _add_target(db_session)  # streams default off
    dns = await _dns_server(db_session)
    r = await _post(client, "dns", dns, "query-log-entries", {"lines": [_bind_line("a.example")]})
    assert r.json()["inserted"] == 1
    await _settle()
    assert wire.batches == []
    # With nobody opted in, the ingest path stops building events at all.
    assert not log_stream_forward.wants("dns_query_log")


async def test_ingest_returns_while_the_collector_is_stuck_and_drops_are_counted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = asyncio.Event()  # never set: the collector accepts and never answers

    async def stuck(*a: Any, **k: Any) -> None:
        await gate.wait()

    monkeypatch.setattr(audit_forward, "_send_syslog_batch", stuck)
    monkeypatch.setattr(log_stream_forward, "TARGET_QUEUE_CAP", 5)
    monkeypatch.setattr(log_stream_forward, "BATCH_SIZE", 2)
    monkeypatch.setattr(log_stream_forward, "SEND_TIMEOUT_S", 60.0)
    monkeypatch.setattr(log_stream_forward, "DROP_FLUSH_S", 3600.0)
    target = await _add_target(db_session, stream_dns_query_log=True)
    tid = target.id
    dns = await _dns_server(db_session)

    for i in range(4):
        lines = [_bind_line(f"q{i}-{j}.example", 1000 + i * 10 + j) for j in range(5)]
        r = await asyncio.wait_for(
            _post(client, "dns", dns, "query-log-entries", {"lines": lines}), timeout=5
        )
        assert r.status_code == 200 and r.json()["inserted"] == 5

    # Routing finishes (the sender is stuck, so nothing else can).
    st = log_stream_forward._state  # noqa: SLF001
    for _ in range(300):
        if not st.ingress and (st.pump is None or st.pump.done()):
            break
        await asyncio.sleep(0.01)
    tq = st.targets[str(tid)]
    # 20 events, 2 taken by the stuck batch, the rest bounded by the cap.
    assert len(tq.events) <= 5
    dropped = sum(tq.unflushed.values())
    assert dropped == 20 - 2 - len(tq.events) and dropped > 0

    await log_stream_forward.flush_drops()
    db_session.expire_all()
    row = (
        await db_session.execute(select(AuditForwardTarget).where(AuditForwardTarget.id == tid))
    ).scalar_one()
    assert row.log_stream_dropped_total == dropped
    assert row.log_stream_last_drop_at is not None

    hits = await _matching_log_forward_dropping_subjects(db_session, SimpleNamespace())
    assert [h[0] for h in hits] == [str(tid)]
    # The alert resolves once the drops are old.
    row.log_stream_last_drop_at = datetime.now(UTC) - timedelta(hours=1)
    await db_session.commit()
    assert await _matching_log_forward_dropping_subjects(db_session, SimpleNamespace()) == []


async def test_a_batch_that_keeps_failing_is_dropped_and_counted(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []

    async def refused(*a: Any, **k: Any) -> None:
        calls.append(1)
        raise ConnectionRefusedError

    monkeypatch.setattr(audit_forward, "_send_syslog_batch", refused)
    monkeypatch.setattr(log_stream_forward, "RETRY_BACKOFF_S", 0.0)
    monkeypatch.setattr(log_stream_forward, "DROP_FLUSH_S", 3600.0)
    target = await _add_target(db_session, stream_dns_query_log=True)
    dns = await _dns_server(db_session)
    r = await _post(client, "dns", dns, "query-log-entries", {"lines": [_bind_line("a.example")]})
    assert r.status_code == 200
    await _settle()
    assert len(calls) == log_stream_forward.SEND_ATTEMPTS
    tq = log_stream_forward._state.targets[str(target.id)]  # noqa: SLF001
    assert sum(tq.unflushed.values()) == 1


async def test_dns_filters_apply_at_ingest(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    wire = _Wire()
    monkeypatch.setattr(audit_forward, "_send_syslog_batch", wire)
    dns = await _dns_server(db_session)
    await _add_target(
        db_session,
        stream_dns_query_log=True,
        log_stream_filters={"dns_server_group_ids": [str(uuid.uuid4())]},
    )
    await _add_target(
        db_session,
        stream_dns_query_log=True,
        log_stream_filters={"dns_qtypes": ["AAAA"]},
    )
    await _add_target(
        db_session,
        stream_dns_query_log=True,
        log_stream_filters={"dns_server_group_ids": [str(dns.group_id)], "dns_qtypes": ["A"]},
    )
    r = await _post(client, "dns", dns, "query-log-entries", {"lines": [_bind_line("a.example")]})
    assert r.json()["inserted"] == 1
    await _settle()
    # Only the third target's filters match this query.
    assert len(wire.lines) == 1


# ── the alert rule is seeded once, by the migration (not at startup) ───────


async def test_migration_seeds_the_drop_alert_once_and_startup_does_not(
    db_session: AsyncSession,
) -> None:
    import importlib.util
    from pathlib import Path

    from sqlalchemy import func

    from app.models.alerts import AlertRule
    from app.services import alerts

    path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "e5a2c8d4f7b1_audit_forward_target_log_streams.py"
    )
    spec = importlib.util.spec_from_file_location("_mig_e5a2c8d4f7b1", path)
    assert spec is not None and spec.loader is not None
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    # A startup seed would re-create the rule after an operator deletes it.
    assert not hasattr(alerts, "seed_log_forward_dropping_alert_rule")
    for _ in range(2):
        await db_session.execute(mig.SEED_LOG_FORWARD_DROPPING_RULE_SQL, mig.seed_params())
        await db_session.commit()
    n = await db_session.scalar(
        select(func.count())
        .select_from(AlertRule)
        .where(AlertRule.rule_type == alerts.RULE_TYPE_LOG_FORWARD_DROPPING)
    )
    assert n == 1
    rule = await db_session.scalar(
        select(AlertRule).where(AlertRule.rule_type == alerts.RULE_TYPE_LOG_FORWARD_DROPPING)
    )
    assert rule is not None and rule.enabled and rule.severity == "warning"


async def test_shutdown_flushes_drops_and_stops_every_task(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = asyncio.Event()

    async def stuck(*a: Any, **k: Any) -> None:
        await gate.wait()

    monkeypatch.setattr(audit_forward, "_send_syslog_batch", stuck)
    monkeypatch.setattr(log_stream_forward, "SEND_TIMEOUT_S", 60.0)
    monkeypatch.setattr(log_stream_forward, "DROP_FLUSH_S", 3600.0)
    target = await _add_target(db_session, stream_dns_query_log=True)
    tid = target.id
    await log_stream_forward.refresh_targets()
    st = log_stream_forward._state  # noqa: SLF001
    tq = st.targets[str(tid)]
    tq.events.append({"stream": "dns_query_log"})
    tq.task = asyncio.get_running_loop().create_task(
        log_stream_forward._send_loop(tq)
    )  # noqa: SLF001
    await asyncio.sleep(0.05)
    log_stream_forward._record_drop(tq, "dns_query_log", 3)  # noqa: SLF001
    task = tq.task

    await log_stream_forward.shutdown()

    assert task.done()
    db_session.expire_all()
    row = (
        await db_session.execute(select(AuditForwardTarget).where(AuditForwardTarget.id == tid))
    ).scalar_one()
    assert row.log_stream_dropped_total == 3

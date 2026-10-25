"""InfluxDB push export (issue #889).

Three things are worth pinning here, because each fails *silently* rather
than loudly:

* **Line-protocol escaping.** A comma in a subnet description or a space
  in a server name is not an error at the server — it re-parses as a
  different tag, or as a field, and the series quietly forks. The rules
  differ per position, which is why every position gets a case.
* **Endpoint + auth selection per version.** v3 is not a third client;
  it is the v2 endpoint with bearer auth and bucket=database naming. A
  regression that collapsed the two token schemes would work against
  InfluxDB 3 and break every v2 install.
* **Watermark advance.** Advancing on a *failed* push is how you get a
  permanent hole in a Grafana dashboard that nothing reports.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import (
    DHCPLease,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.dns import DNSServer, DNSServerGroup
from app.models.influxdb import InfluxDBTarget
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.models.metrics import DNSMetricSample
from app.services.influxdb.client import (
    InfluxDBWriteError,
    InfluxTargetConfig,
    build_write_request,
)
from app.services.influxdb.collect import (
    REPUSH_OVERLAP_SECONDS,
    collect_dhcp_scope_lease_points,
    collect_dns_points,
)
from app.services.influxdb.line_protocol import Point, render_batch, render_point
from app.services.influxdb.push import is_due, push_target

# ── line protocol ──────────────────────────────────────────────────


def test_render_point_escapes_every_position() -> None:
    line = render_point(
        Point(
            measurement="dns queries,agg",
            tags={"server": "ns1 dc=1", "zone": "a,b"},
            fields={"queries total": 5},
            timestamp=1700000000,
        )
    )
    # Measurement escapes comma + space, but NOT '=' (legal unescaped there).
    assert line.startswith(r"dns\ queries\,agg,")
    assert r"server=ns1\ dc\=1" in line
    assert r"zone=a\,b" in line
    assert r"queries\ total=5i" in line
    assert line.endswith(" 1700000000")


def test_integer_and_float_and_bool_field_types() -> None:
    line = render_point(
        Point(
            measurement="m",
            tags={},
            fields={"i": 3, "f": 1.5, "b": True},
            timestamp=1,
        )
    )
    # bool must not render as an int — a `1i` where the series holds
    # booleans is a field-type conflict InfluxDB rejects for the whole
    # batch, not just the point.
    assert "b=true" in line
    assert "i=3i" in line
    assert "f=1.5" in line


def test_empty_tag_values_are_dropped() -> None:
    line = render_point(
        Point(measurement="m", tags={"a": "", "b": "x"}, fields={"v": 1}, timestamp=1)
    )
    assert "a=" not in line
    assert "b=x" in line


def test_newlines_cannot_terminate_a_point_early() -> None:
    line = render_point(
        Point(
            measurement="m",
            tags={"desc": "line1\nline2"},
            fields={"v": 1},
            timestamp=1,
        )
    )
    assert "\n" not in line


def test_string_field_is_quoted_and_escaped() -> None:
    line = render_point(Point(measurement="m", tags={}, fields={"s": 'a"b\\c'}, timestamp=1))
    assert 's="a\\"b\\\\c"' in line


def test_field_less_point_is_refused_not_shipped() -> None:
    # A field-less line is a parse error that rejects the whole batch it
    # arrives in, so it must never reach the wire.
    with pytest.raises(ValueError):
        render_point(Point(measurement="m", tags={"a": "b"}, fields={}, timestamp=1))


def test_render_batch_joins_with_newlines() -> None:
    body = render_batch(
        [
            Point(measurement="a", tags={}, fields={"v": 1}, timestamp=1),
            Point(measurement="b", tags={}, fields={"v": 2}, timestamp=2),
        ]
    )
    assert body.split("\n") == ["a v=1i 1", "b v=2i 2"]


# ── endpoint + auth per version ────────────────────────────────────


def test_v1_uses_write_endpoint_and_basic_auth() -> None:
    req = build_write_request(
        InfluxTargetConfig(
            version="v1",
            url="http://influx:8086/",
            database="spatium",
            username="admin",
            password="s3cret",
        )
    )
    assert req.url == "http://influx:8086/write"
    assert req.params["db"] == "spatium"
    assert req.params["precision"] == "s"
    assert req.auth == ("admin", "s3cret")
    assert "Authorization" not in req.headers


def test_v1_without_credentials_sends_no_auth() -> None:
    req = build_write_request(
        InfluxTargetConfig(version="v1", url="http://influx:8086", database="spatium")
    )
    assert req.auth is None


def test_v2_uses_token_scheme() -> None:
    req = build_write_request(
        InfluxTargetConfig(
            version="v2", url="http://influx:8086", org="acme", bucket="ddi", token="tok"
        )
    )
    assert req.url == "http://influx:8086/api/v2/write"
    assert req.params["org"] == "acme"
    assert req.params["bucket"] == "ddi"
    assert req.headers["Authorization"] == "Token tok"


def test_v3_reuses_v2_endpoint_with_bearer_and_optional_org() -> None:
    req = build_write_request(
        InfluxTargetConfig(version="v3", url="http://influx:8181", bucket="ddi", token="tok")
    )
    assert req.url == "http://influx:8181/api/v2/write"
    # v3 names a *database* in the bucket parameter, and org is optional
    # (Core / Enterprise accept-and-ignore it).
    assert req.params["bucket"] == "ddi"
    assert "org" not in req.params
    assert req.headers["Authorization"] == "Bearer tok"


def test_v2_requires_org_but_v3_does_not() -> None:
    with pytest.raises(ValueError, match="org is required"):
        build_write_request(InfluxTargetConfig(version="v2", url="http://x", bucket="b", token="t"))


@pytest.mark.parametrize(
    ("cfg", "match"),
    [
        (InfluxTargetConfig(version="v1", url="", database="d"), "url is required"),
        (InfluxTargetConfig(version="v1", url="http://x"), "database is required"),
        (
            InfluxTargetConfig(version="v2", url="http://x", org="o", bucket="b"),
            "token is required",
        ),
        (
            InfluxTargetConfig(version="v3", url="http://x", token="t"),
            "database is required",
        ),
        (InfluxTargetConfig(version="v9", url="http://x"), "unsupported InfluxDB version"),
    ],
)
def test_incomplete_targets_are_refused(cfg: InfluxTargetConfig, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        build_write_request(cfg)


# ── per-target interval gating ─────────────────────────────────────


def test_never_pushed_target_is_always_due() -> None:
    now = datetime.now(UTC)
    assert is_due(InfluxDBTarget(push_interval_seconds=3600, last_push_at=None), now)


def test_interval_gate_holds_until_elapsed() -> None:
    now = datetime.now(UTC)
    row = InfluxDBTarget(push_interval_seconds=300, last_push_at=now - timedelta(seconds=299))
    assert not is_due(row, now)
    row.last_push_at = now - timedelta(seconds=300)
    assert is_due(row, now)


# ── CRUD API ───────────────────────────────────────────────────────


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


def _v2_body(**over: object) -> dict:
    body = {
        "name": "grafana",
        "enabled": True,
        "version": "v2",
        "url": "http://influx:8086",
        "verify_tls": True,
        "timeout_seconds": 10,
        "database": "",
        "username": "",
        "org": "acme",
        "bucket": "ddi",
        "token": "tok",
        "measurement_prefix": "spatiumddi_",
        "push_interval_seconds": 60,
        "push_dns_metrics": True,
        "push_dhcp_metrics": True,
        "push_subnet_utilization": True,
        "push_dhcp_scope_leases": True,
    }
    body.update(over)
    return body


@pytest.mark.asyncio
async def test_crud_roundtrip_never_returns_the_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin(db_session)}"}

    r = await client.get("/api/v1/settings/influxdb-targets", headers=h)
    assert r.status_code == 200, r.text
    assert r.json() == []

    secret = "s3cret-" + uuid.uuid4().hex
    r = await client.post(
        "/api/v1/settings/influxdb-targets", headers=h, json=_v2_body(token=secret)
    )
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["token_set"] is True
    # The secret must never appear in the response, under any key. (The
    # needle is randomised so it can't collide with a field *name* — an
    # earlier version of this assertion matched "token_set".)
    assert secret not in r.text

    target_id = created["id"]
    # Omitting ``token`` on update means "keep what's stored" — the
    # operator editing an interval must not silently clear the credential.
    body = _v2_body(push_interval_seconds=120)
    body.pop("token")
    r = await client.put(f"/api/v1/settings/influxdb-targets/{target_id}", headers=h, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["push_interval_seconds"] == 120
    assert r.json()["token_set"] is True

    r = await client.delete(f"/api/v1/settings/influxdb-targets/{target_id}", headers=h)
    assert r.status_code == 204
    r = await client.get("/api/v1/settings/influxdb-targets", headers=h)
    assert r.json() == []


@pytest.mark.asyncio
async def test_unwritable_target_is_422_at_save_not_a_push_error_later(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin(db_session)}"}
    r = await client.post("/api/v1/settings/influxdb-targets", headers=h, json=_v2_body(bucket=""))
    assert r.status_code == 422, r.text
    assert "bucket is required" in r.text


@pytest.mark.asyncio
async def test_non_superadmin_is_forbidden(client: AsyncClient, db_session: AsyncSession) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Plain",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db_session.add(user)
    await db_session.flush()
    h = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    assert (await client.get("/api/v1/settings/influxdb-targets", headers=h)).status_code == 403


# ── collect + watermark ────────────────────────────────────────────


async def _dns_sample(db: AsyncSession, bucket_at: datetime, queries: int) -> uuid.UUID:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        name=f"ns {uuid.uuid4().hex[:4]}",
        driver="bind9",
        host="10.0.0.53",
        port=53,
    )
    db.add(server)
    await db.flush()
    db.add(
        DNSMetricSample(
            server_id=server.id,
            bucket_at=bucket_at,
            queries_total=queries,
            noerror=queries,
            nxdomain=0,
            servfail=0,
            recursion=0,
            rate_dropped=0,
            rate_slipped=0,
        )
    )
    await db.flush()
    return server.id


@pytest.mark.asyncio
async def test_collect_dns_points_reports_the_newest_bucket(db_session: AsyncSession) -> None:
    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    await _dns_sample(db_session, base, 10)
    await _dns_sample(db_session, base + timedelta(minutes=1), 20)

    points, newest = await collect_dns_points(db_session, None)
    assert len(points) == 2
    assert newest == base + timedelta(minutes=1)
    # The bucket's own timestamp travels with the point — not "now" —
    # so a backfill lands on the hour the traffic actually happened.
    assert {p.timestamp for p in points} == {
        int(base.timestamp()),
        int((base + timedelta(minutes=1)).timestamp()),
    }


@pytest.mark.asyncio
async def test_collect_dns_points_replays_a_window_behind_the_mark(
    db_session: AsyncSession,
) -> None:
    """A late-arriving sample must not be skipped forever.

    The forward drain alone is a strict ``>`` on the watermark, so an
    agent that reports a bucket after the cursor passed it would never be
    exported. The replay window covers that. Re-sending is free — line
    protocol overwrites a point with the same measurement, tags and
    timestamp.
    """
    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    await _dns_sample(db_session, base, 10)

    inside_replay = base + timedelta(seconds=REPUSH_OVERLAP_SECONDS - 60)
    points, newest = await collect_dns_points(db_session, inside_replay)
    assert len(points) == 1
    # A replayed row is already behind the cursor, so it must not become
    # the new one — that is what would drag the watermark backwards.
    assert newest is None

    beyond_replay = base + timedelta(seconds=REPUSH_OVERLAP_SECONDS + 60)
    points, newest = await collect_dns_points(db_session, beyond_replay)
    assert points == []
    assert newest is None


@pytest.mark.asyncio
async def test_truncated_batch_never_drags_the_watermark_backwards(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row cap must not be able to move the cursor the wrong way.

    Folding the replay window into the drain's lower bound would, on a
    fleet dense enough to fill the cap inside that window, return a
    truncated batch whose maximum is *below* the watermark — pulling the
    cursor back a little further every tick until it pinned on the oldest
    retained sample. The export would stop advancing while every push
    still reported success. Separate budgets make it unrepresentable.
    """
    monkeypatch.setattr("app.services.influxdb.collect.MAX_ROWS_PER_PUSH", 2)
    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    for i in range(6):
        await _dns_sample(db_session, base + timedelta(seconds=i), 1)

    # Watermark sits above four of the six samples, all of them inside the
    # replay window — exactly the shape that used to regress.
    watermark = base + timedelta(seconds=3)
    points, newest = await collect_dns_points(db_session, watermark)
    assert points  # the replay still ships
    assert newest is not None
    assert newest > watermark


@pytest.mark.asyncio
async def test_successful_push_advances_the_watermark_and_prefixes(
    db_session: AsyncSession,
) -> None:
    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    await _dns_sample(db_session, base, 42)

    row = InfluxDBTarget(
        name=f"t-{uuid.uuid4().hex[:6]}",
        version="v2",
        url="http://influx:8086",
        org="acme",
        bucket="ddi",
        token_encrypted=encrypt_str("tok"),
        measurement_prefix="pfx_",
        push_dhcp_metrics=False,
        push_subnet_utilization=False,
        push_dhcp_scope_leases=False,
    )
    db_session.add(row)
    await db_session.flush()

    sent: list[str] = []

    async def _capture(cfg: object, body: str) -> None:
        sent.append(body)

    now = datetime.now(UTC)
    with patch("app.services.influxdb.push.write_lines", new=_capture):
        result = await push_target(db_session, row, now=now)

    assert result.ok and result.points == 1
    assert sent and sent[0].startswith("pfx_dns_queries,")
    assert row.last_dns_bucket_at == base
    assert row.last_push_error is None


@pytest.mark.asyncio
async def test_failed_push_leaves_the_watermark_alone(db_session: AsyncSession) -> None:
    """Advancing on failure is how a dashboard gets a permanent hole.

    The samples stay in Postgres until ``prune_metrics`` retires them, so
    a target that recovers inside the retention window backfills — but
    only if the cursor never moved past what was actually delivered.
    """
    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    await _dns_sample(db_session, base, 42)

    row = InfluxDBTarget(
        name=f"t-{uuid.uuid4().hex[:6]}",
        version="v2",
        url="http://influx:8086",
        org="acme",
        bucket="ddi",
        token_encrypted=encrypt_str("tok"),
        push_dhcp_metrics=False,
        push_subnet_utilization=False,
        push_dhcp_scope_leases=False,
    )
    db_session.add(row)
    await db_session.flush()

    async def _boom(cfg: object, body: str) -> None:
        raise InfluxDBWriteError("HTTP 401: unauthorized")

    now = datetime.now(UTC)
    with patch("app.services.influxdb.push.write_lines", new=_boom):
        result = await push_target(db_session, row, now=now)

    assert not result.ok
    assert row.last_dns_bucket_at is None
    assert row.last_push_error == "HTTP 401: unauthorized"
    # ``last_push_at`` still moves, or a fast-failing target would be
    # retried on every 30 s beat tick instead of on its own interval.
    assert row.last_push_at == now


@pytest.mark.asyncio
async def test_malformed_url_is_recorded_not_raised(db_session: AsyncSession) -> None:
    """A bad URL must fail *this* target, not abort the whole sweep.

    ``httpx.InvalidURL`` derives from ``Exception``, not from
    ``httpx.HTTPError`` — so catching only the latter let a URL that
    passed the save-time scheme check escape ``push_target`` entirely,
    rolling back every other target's state update in the same
    transaction and leaving nothing to explain why.
    """
    # A body is required for the request to be built at all — an empty
    # batch short-circuits before httpx is reached.
    await _dns_sample(db_session, datetime.now(UTC).replace(microsecond=0), 1)
    row = InfluxDBTarget(
        name=f"t-{uuid.uuid4().hex[:6]}",
        version="v2",
        # Scheme is valid, so this passes the save-time check; the port
        # is not a number, which httpx only discovers at request time.
        url="http://influx:80o86",
        org="acme",
        bucket="ddi",
        token_encrypted=encrypt_str("tok"),
        push_dhcp_metrics=False,
        push_subnet_utilization=False,
        push_dhcp_scope_leases=False,
    )
    db_session.add(row)
    await db_session.flush()

    result = await push_target(db_session, row, now=datetime.now(UTC))
    assert not result.ok
    assert "InvalidURL" in (row.last_push_error or "")
    # The cursor must not have moved — nothing was delivered.
    assert row.last_dns_bucket_at is None


@pytest.mark.asyncio
async def test_scope_lease_gauge_counts_addresses_not_rows(
    db_session: AsyncSession,
) -> None:
    """Under Kea HA both partners mirror the same lease.

    ``dhcp_lease`` is per-server — "one lease event arrives here twice",
    per the model's own docstring — so a bare row count reports 2x the
    addresses actually in use on exactly the deployments redundancy is
    for, and disagrees with ``pool_occupancy.py``, which dedupes.
    """
    space = IPSpace(name=f"s-{uuid.uuid4().hex[:6]}", description="")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.62.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.62.0.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()

    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, name="ha-scope")
    primary = DHCPServer(
        name=f"kea-a-{uuid.uuid4().hex[:4]}",
        host="10.0.0.1",
        driver="kea",
        server_group_id=group.id,
    )
    secondary = DHCPServer(
        name=f"kea-b-{uuid.uuid4().hex[:4]}",
        host="10.0.0.2",
        driver="kea",
        server_group_id=group.id,
    )
    db_session.add_all([scope, primary, secondary])
    await db_session.flush()

    # One address, mirrored by both HA partners; plus a second address on
    # one partner only.
    for server in (primary, secondary):
        db_session.add(
            DHCPLease(
                server_id=server.id,
                scope_id=scope.id,
                ip_address="10.62.0.10",
                mac_address="aa:bb:cc:00:00:01",
                state="active",
            )
        )
    db_session.add(
        DHCPLease(
            server_id=primary.id,
            scope_id=scope.id,
            ip_address="10.62.0.11",
            mac_address="aa:bb:cc:00:00:02",
            state="active",
        )
    )
    await db_session.flush()

    points = await collect_dhcp_scope_lease_points(db_session, datetime.now(UTC))
    gauge = next(p for p in points if p.tags["scope_id"] == str(scope.id))
    assert gauge.fields["active_leases"] == 2  # not 3


# ── #980 loss counters in the DHCP export ──────────────────────────


async def _dhcp_sample(db: AsyncSession, bucket_at: datetime, **loss: int | None) -> uuid.UUID:
    from app.models.dhcp import DHCPServer, DHCPServerGroup
    from app.models.metrics import DHCPMetricSample

    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DHCPServer(
        server_group_id=group.id,
        name=f"kea {uuid.uuid4().hex[:4]}",
        driver="kea",
        host="10.0.0.67",
        port=67,
    )
    db.add(server)
    await db.flush()
    db.add(
        DHCPMetricSample(
            server_id=server.id,
            bucket_at=bucket_at,
            discover=5,
            offer=5,
            request=5,
            ack=5,
            nak=0,
            decline=0,
            release=0,
            inform=0,
            **loss,
        )
    )
    await db.flush()
    return server.id


@pytest.mark.asyncio
async def test_dhcp_export_carries_the_loss_counters(db_session: AsyncSession) -> None:
    """#980 — they were the only DHCPMetricSample columns the exporter missed."""
    from app.services.influxdb.collect import collect_dhcp_points

    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    await _dhcp_sample(db_session, base, socket_drop=12, receive_drop=3)

    points, _ = await collect_dhcp_points(db_session, None)
    assert len(points) == 1
    assert points[0].fields["socket_drop"] == 12
    assert points[0].fields["receive_drop"] == 3


@pytest.mark.asyncio
async def test_dhcp_export_omits_an_unmeasured_counter(db_session: AsyncSession) -> None:
    """Line protocol has no null, so an unmeasured counter must be OMITTED.

    Writing 0 would assert "no packets were lost" on a server nobody looked
    at — the same false reassurance #980 exists to remove, published into the
    operator's long-term metrics store where it outlives the agent upgrade
    that would have corrected it. An absent field leaves a gap in the series,
    which is the honest rendering.
    """
    from app.services.influxdb.collect import collect_dhcp_points

    base = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=10)
    await _dhcp_sample(db_session, base, socket_drop=None, receive_drop=None)

    points, _ = await collect_dhcp_points(db_session, None)
    assert len(points) == 1
    assert "socket_drop" not in points[0].fields
    assert "receive_drop" not in points[0].fields
    # The traffic counters are unaffected — the point is still emitted.
    assert points[0].fields["discover"] == 5


# ── #1989: a blank secret keeps the stored one; clearing is explicit ──────


@pytest.mark.asyncio
async def test_blank_secret_keeps_it_and_only_the_flag_clears(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin(db_session)}"}
    url = "/api/v1/settings/influxdb-targets"

    # v2 token: ``""`` is what a form sends once its field was typed in and
    # cleared. Before #1989 it cleared the token and the save was refused.
    r = await client.post(url, headers=h, json=_v2_body(token="tok-secret"))
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    r = await client.put(
        f"{url}/{tid}", headers=h, json=_v2_body(token="", push_interval_seconds=90)
    )
    assert r.status_code == 200, r.text
    assert r.json()["token_set"] is True
    assert r.json()["push_interval_seconds"] == 90

    # The flag removes it: a v2 target without a token fails the writable
    # check, so the explicit clear is refused rather than silently applied.
    r = await client.put(f"{url}/{tid}", headers=h, json=_v2_body(token="", clear_token=True))
    assert r.status_code == 422, r.text
    assert "token is required" in r.text

    # v1 password: blank keeps, flag clears, a new value replaces and wins
    # over the flag.
    v1 = {
        **_v2_body(),
        "version": "v1",
        "database": "ddi",
        "username": "u",
        "name": "v1t",
        "password": "pw-secret",
    }
    r = await client.post(url, headers=h, json=v1)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert r.json()["password_set"] is True
    r = await client.put(f"{url}/{pid}", headers=h, json={**v1, "password": ""})
    assert r.json()["password_set"] is True
    r = await client.put(f"{url}/{pid}", headers=h, json={**v1, "password": None})
    assert r.json()["password_set"] is True
    r = await client.put(
        f"{url}/{pid}", headers=h, json={**v1, "password": "new", "clear_password": True}
    )
    assert r.json()["password_set"] is True
    r = await client.put(
        f"{url}/{pid}", headers=h, json={**v1, "password": "", "clear_password": True}
    )
    assert r.status_code == 200, r.text
    assert r.json()["password_set"] is False


@pytest.mark.asyncio
async def test_clearing_a_secret_is_audited_without_the_secret(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = {"Authorization": f"Bearer {await _superadmin(db_session)}"}
    url = "/api/v1/settings/influxdb-targets"
    v1 = {
        **_v2_body(),
        "version": "v1",
        "database": "ddi",
        "username": "u",
        "name": "v1-audit",
        "password": "pw-very-secret",
        "token": None,
    }
    r = await client.post(url, headers=h, json=v1)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    # A blank-keep save changes no secret; the explicit clear does.
    r = await client.put(f"{url}/{pid}", headers=h, json={**v1, "password": ""})
    assert r.status_code == 200, r.text
    r = await client.put(
        f"{url}/{pid}", headers=h, json={**v1, "password": "", "clear_password": True}
    )
    assert r.status_code == 200, r.text

    rows = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.resource_type == "influxdb_target", AuditLog.resource_id == pid)
                .order_by(AuditLog.seq)
            )
        )
        .scalars()
        .all()
    )
    changes = [(a.action, a.new_value["secret_changes"]) for a in rows]
    assert changes == [
        ("create", ["password_set"]),
        ("update", []),
        ("update", ["password_cleared"]),
    ]
    assert rows[-1].new_value["password_set"] is False
    assert all("pw-very-secret" not in repr(a.new_value) for a in rows)


# ── #1990: the last SUCCESSFUL push is kept apart from the last attempt ──


@pytest.mark.asyncio
async def test_last_success_survives_a_later_failure(db_session: AsyncSession) -> None:
    row = InfluxDBTarget(
        name=f"t-{uuid.uuid4().hex[:6]}",
        version="v2",
        url="http://influx:8086",
        org="acme",
        bucket="ddi",
        token_encrypted=encrypt_str("tok"),
        push_dns_metrics=True,
        push_dhcp_metrics=False,
        push_subnet_utilization=False,
        push_dhcp_scope_leases=False,
    )
    db_session.add(row)
    await db_session.flush()
    assert row.last_success_at is None

    async def _one_dns_point(db: object, since: object) -> tuple[list[Point], None]:
        return [Point("dns_q", {}, {"n": 1}, 1_700_000_000_000_000_000)], None

    async def _boom(cfg: object, body: str) -> None:
        raise InfluxDBWriteError("HTTP 500")

    async def _ok(cfg: object, body: str) -> None:
        return None

    t1 = datetime.now(UTC) - timedelta(minutes=10)
    with (
        patch("app.services.influxdb.push.write_lines", new=_boom),
        patch("app.services.influxdb.push.collect.collect_dns_points", new=_one_dns_point),
    ):
        await push_target(db_session, row, now=t1)
    # Never delivered: an attempt, but no success.
    assert row.last_push_at == t1
    assert row.last_success_at is None

    t2 = t1 + timedelta(minutes=5)
    with (
        patch("app.services.influxdb.push.write_lines", new=_ok),
        patch("app.services.influxdb.push.collect.collect_dns_points", new=_one_dns_point),
    ):
        await push_target(db_session, row, now=t2)
    assert row.last_success_at == t2

    t3 = t2 + timedelta(minutes=5)
    with (
        patch("app.services.influxdb.push.write_lines", new=_boom),
        patch("app.services.influxdb.push.collect.collect_dns_points", new=_one_dns_point),
    ):
        await push_target(db_session, row, now=t3)
    assert row.last_push_at == t3
    assert row.last_success_at == t2
    assert row.last_push_error == "HTTP 500"


# ── #2749: a push that sent nothing is not a push the destination accepted ──


@pytest.mark.asyncio
async def test_empty_push_is_not_recorded_as_accepted(db_session: AsyncSession) -> None:
    row = InfluxDBTarget(
        name=f"t-{uuid.uuid4().hex[:6]}",
        version="v2",
        url="http://192.0.2.10:8086",
        org="acme",
        bucket="ddi",
        token_encrypted=encrypt_str("tok"),
        push_dns_metrics=True,
        push_dhcp_metrics=False,
        push_subnet_utilization=False,
        push_dhcp_scope_leases=False,
    )
    db_session.add(row)
    await db_session.flush()

    async def _boom(cfg: object, body: str) -> None:
        raise InfluxDBWriteError("ConnectTimeout")

    async def _one_dns_point(db: object, since: object) -> tuple[list[Point], None]:
        return [Point("dns_q", {}, {"n": 1}, 1_700_000_000_000_000_000)], None

    t1 = datetime.now(UTC) - timedelta(minutes=10)
    with (
        patch("app.services.influxdb.push.write_lines", new=_boom),
        patch("app.services.influxdb.push.collect.collect_dns_points", new=_one_dns_point),
    ):
        await push_target(db_session, row, now=t1)
    assert row.last_push_error == "ConnectTimeout"

    # The operator unticks everything: nothing to send, nobody contacted.
    row.push_dns_metrics = False
    t2 = t1 + timedelta(minutes=5)
    res = await push_target(db_session, row, now=t2)
    assert res.points == 0
    assert row.last_success_at is None  # never accepted
    assert row.last_push_error == "ConnectTimeout"  # failure not erased
    assert row.last_push_at == t2  # interval gating still advances
    assert row.last_push_points == 0

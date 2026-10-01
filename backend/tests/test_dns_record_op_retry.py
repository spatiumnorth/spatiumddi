"""DNS record ops: backoff, unacknowledged ops, supersession, reporting (#1232).

* Retries went out on every heartbeat, so a ~2.5 minute daemon outage spent
  all of them. They back off now.
* An op shipped and never acknowledged (agent restart, lost response) stayed
  ``in_flight`` forever. It returns to the retry path.
* Every op carries the whole desired RRset (#773), so retrying an older op
  after a newer one for the same RRset applied would put the old state back.
  The older one is ``superseded`` instead.
* A failed op was reported nowhere. ``dns_record_op_failed`` fires.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.services import acme as acme_svc
from app.services import alerts
from app.services.dns import agent_token as dns_tokens
from app.services.dns.agent_config import page_pending_ops
from app.services.dns.record_ops import (
    IN_FLIGHT_ACK_TIMEOUT,
    MAX_OP_ATTEMPTS,
    ack_op,
    apply_acks,
    reset_unacknowledged_ops,
    retry_delay,
)


async def _server(db: AsyncSession) -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver="bind9",
        host="10.0.0.1",
        name=f"srv-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        is_enabled=True,
        agent_id=uuid.uuid4(),
    )
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add_all([server, zone])
    await db.flush()
    return server, zone


def _op(
    server: DNSServer,
    zone: DNSZone,
    *,
    name: str = "www",
    values: tuple[str, ...] = ("10.0.0.5",),
    state: str = "pending",
    created_at: datetime | None = None,
    rrset: bool = True,
) -> DNSRecordOp:
    record: dict = {"name": name, "type": "A", "value": values[-1]}
    if rrset:
        record["rrset"] = {"ttl": 3600, "members": [{"value": v} for v in values]}
    op = DNSRecordOp(
        server_id=server.id, zone_name=zone.name, op="create", record=record, state=state
    )
    if created_at is not None:
        op.created_at = created_at
        op.updated_at = created_at
    return op


# ── Backoff ──────────────────────────────────────────────────────────────────


def test_the_retry_schedule_backs_off_to_a_cap() -> None:
    delays = [retry_delay(n).total_seconds() for n in range(1, MAX_OP_ATTEMPTS)]
    assert delays == [30, 60, 120, 240, 480, 900, 900]
    # Long enough to ride out a daemon restart or upgrade, which the old
    # five-heartbeat budget (~2.5 min) was not.
    assert sum(delays) > 40 * 60


async def test_a_failed_attempt_waits_before_shipping_again(db_session: AsyncSession) -> None:
    server, zone = await _server(db_session)
    op = _op(server, zone, state="in_flight")
    db_session.add(op)
    await db_session.flush()

    await ack_op(db_session, str(op.id), "error", "rndc: connection refused", server_id=server.id)
    assert op.state == "pending"
    assert op.attempts == 1
    assert op.next_attempt_at is not None

    page, _ = await page_pending_ops(db_session, server)
    assert page == [], "an op backing off must not ship on the next poll"

    op.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    page, _ = await page_pending_ops(db_session, server)
    assert [p["op_id"] for p in page] == [str(op.id)]


async def test_the_last_attempt_fails_the_op(db_session: AsyncSession) -> None:
    server, zone = await _server(db_session)
    op = _op(server, zone, state="in_flight")
    op.attempts = MAX_OP_ATTEMPTS - 1
    db_session.add(op)
    await db_session.flush()
    await ack_op(db_session, str(op.id), "error", "NOTAUTH", server_id=server.id)
    assert op.state == "failed"
    assert op.next_attempt_at is None


# ── Acks ─────────────────────────────────────────────────────────────────────


async def test_an_ack_for_another_servers_op_is_ignored(db_session: AsyncSession) -> None:
    server, zone = await _server(db_session)
    other, _ = await _server(db_session)
    op = _op(server, zone, state="in_flight")
    db_session.add(op)
    await db_session.flush()
    await ack_op(db_session, str(op.id), "ok", server_id=other.id)
    assert op.state == "in_flight"


async def test_a_late_ack_after_the_reset_is_honoured_once(db_session: AsyncSession) -> None:
    """The reset already counted the attempt; a late error must not count it
    again, and a late ok is still true."""
    server, zone = await _server(db_session)
    op = _op(server, zone, state="pending")
    op.attempts = 1
    op.next_attempt_at = datetime.now(UTC) + timedelta(minutes=1)
    db_session.add(op)
    await db_session.flush()

    await ack_op(db_session, str(op.id), "error", "late", server_id=server.id)
    assert (op.state, op.attempts) == ("pending", 1)
    await ack_op(db_session, str(op.id), "ok", server_id=server.id)
    assert op.state == "applied"
    assert op.next_attempt_at is None


# ── Never acknowledged ───────────────────────────────────────────────────────


async def test_an_op_never_acknowledged_returns_to_the_retry_path(
    db_session: AsyncSession,
) -> None:
    server, zone = await _server(db_session)
    shipped = datetime.now(UTC) - IN_FLIGHT_ACK_TIMEOUT - timedelta(seconds=5)
    stale = _op(server, zone, state="in_flight", created_at=shipped)
    fresh = _op(server, zone, name="api", state="in_flight")
    db_session.add_all([stale, fresh])
    await db_session.flush()

    assert await reset_unacknowledged_ops(db_session, server.id) == 1
    assert stale.state == "pending"
    assert stale.attempts == 1
    assert "no acknowledgement" in (stale.last_error or "")
    assert stale.next_attempt_at is not None
    assert fresh.state == "in_flight", "an op inside the ack window is left alone"


async def test_shipping_stamps_the_dispatch_time(db_session: AsyncSession) -> None:
    server, zone = await _server(db_session)
    op = _op(server, zone, created_at=datetime.now(UTC) - timedelta(hours=1))
    db_session.add(op)
    await db_session.flush()
    await page_pending_ops(db_session, server)
    assert op.state == "in_flight"
    # Measured from dispatch, not from creation, or an op queued long ago
    # would be reset the moment it shipped.
    assert op.updated_at > datetime.now(UTC) - timedelta(minutes=1)


# ── Supersession ─────────────────────────────────────────────────────────────


async def test_a_failed_op_with_a_newer_op_for_its_rrset_is_superseded(
    db_session: AsyncSession,
) -> None:
    server, zone = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(minutes=2)
    older = _op(server, zone, values=("10.0.0.5",), state="in_flight", created_at=t0)
    newer = _op(
        server, zone, values=("10.0.0.5", "10.0.0.6"), created_at=t0 + timedelta(seconds=30)
    )
    db_session.add_all([older, newer])
    await db_session.flush()

    await ack_op(db_session, str(older.id), "error", "timeout", server_id=server.id)
    assert older.state == "superseded"
    assert older.superseded_by == newer.id


async def test_shipping_a_newer_op_retires_one_backing_off(db_session: AsyncSession) -> None:
    """Without this the older op retries AFTER the newer one applied and puts
    the RRset back the way it was."""
    server, zone = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(minutes=2)
    older = _op(server, zone, values=("10.0.0.5",), created_at=t0)
    older.attempts = 1
    older.next_attempt_at = datetime.now(UTC) + timedelta(minutes=5)
    newer = _op(server, zone, values=("10.0.0.6",), created_at=t0 + timedelta(seconds=30))
    other = _op(server, zone, name="api", created_at=t0 - timedelta(seconds=30))
    other.attempts = 1
    other.next_attempt_at = datetime.now(UTC) + timedelta(minutes=5)
    db_session.add_all([older, newer, other])
    await db_session.flush()

    page, _ = await page_pending_ops(db_session, server)
    assert [p["op_id"] for p in page] == [str(newer.id)]
    assert (older.state, older.superseded_by) == ("superseded", newer.id)
    assert other.state == "pending", "a different RRset is not superseded"


async def test_an_op_without_an_rrset_is_never_superseded(db_session: AsyncSession) -> None:
    """A DNS pool op (``rrset_action``) says nothing about its siblings."""
    server, zone = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(minutes=2)
    older = _op(server, zone, state="in_flight", created_at=t0, rrset=False)
    newer = _op(server, zone, created_at=t0 + timedelta(seconds=30), rrset=False)
    db_session.add_all([older, newer])
    await db_session.flush()
    await ack_op(db_session, str(older.id), "error", "x", server_id=server.id)
    assert older.state == "pending"


async def test_an_acme_wait_follows_the_superseding_op(db_session: AsyncSession) -> None:
    """The ACME DNS-01 wait resolves a superseded op to the outcome of the op
    that carries its change; ``superseded`` alone would read as never applied."""
    server, zone = await _server(db_session)
    newest = _op(server, zone, state="pending")
    db_session.add(newest)
    await db_session.flush()
    middle = _op(server, zone, state="superseded")
    middle.superseded_by = newest.id
    db_session.add(middle)
    await db_session.flush()
    oldest = _op(server, zone, state="superseded")
    oldest.superseded_by = middle.id
    db_session.add(oldest)
    await db_session.flush()

    assert await acme_svc._effective_op_state(db_session, oldest) == "pending"
    newest.state = "applied"
    assert await acme_svc._effective_op_state(db_session, oldest) == "applied"


# ── Reporting ────────────────────────────────────────────────────────────────


async def test_a_failed_op_raises_the_alert_for_24_hours(db_session: AsyncSession) -> None:
    server, zone = await _server(db_session)
    op = _op(server, zone, state="failed")
    op.last_error = "update failed: REFUSED"
    db_session.add(op)
    await db_session.flush()
    now = datetime.now(UTC)

    matches = await alerts._matching_dns_record_op_failed_subjects(db_session, None, now)  # type: ignore[arg-type]
    assert len(matches) == 1
    subject, _display, message, _sev = matches[0]
    assert subject == f"dns_server:{server.id}"
    assert "REFUSED" in message and zone.name.rstrip(".") in message
    # The zone is an FQDN; the sentence must not end "example.." (#1298 review).
    assert ".." not in message

    later = now + timedelta(hours=25)
    assert await alerts._matching_dns_record_op_failed_subjects(db_session, None, later) == []  # type: ignore[arg-type]


# ── Review follow-ups ────────────────────────────────────────────────────────


async def test_the_heartbeat_commits_the_reset(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The reset first ran inside the long-poll, whose transaction a 304 rolls
    back — so it never stuck, and stranded ops stayed stranded. The heartbeat
    always commits."""
    server, zone = await _server(db_session)
    server.agent_fingerprint = "fp"
    token, _exp = dns_tokens.mint_agent_token(str(server.id), str(server.agent_id), "fp")
    server.agent_jwt_hash = dns_tokens.hash_token(token)
    shipped = datetime.now(UTC) - IN_FLIGHT_ACK_TIMEOUT - timedelta(seconds=5)
    stale = _op(server, zone, state="in_flight", created_at=shipped)
    acked = _op(server, zone, name="api", state="in_flight", created_at=shipped)
    db_session.add_all([stale, acked])
    await db_session.commit()
    stale_id, acked_id = stale.id, acked.id

    resp = await client.post(
        "/api/v1/dns/agents/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={"ops_ack": [{"op_id": str(acked_id), "result": "ok", "dispatch": 0}]},
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    states = dict(
        (
            await db_session.execute(
                select(DNSRecordOp.id, DNSRecordOp.state).where(
                    DNSRecordOp.id.in_([stale_id, acked_id])
                )
            )
        )
        .tuples()
        .all()
    )
    # The ack in the same heartbeat wins over the reset for its own op.
    assert states == {stale_id: "pending", acked_id: "applied"}


async def test_the_page_stamps_each_ops_dispatch(db_session: AsyncSession) -> None:
    server, zone = await _server(db_session)
    op = _op(server, zone)
    op.attempts = 2
    db_session.add(op)
    await db_session.flush()
    page, _ = await page_pending_ops(db_session, server)
    assert page[0]["dispatch"] == 2


async def test_a_late_error_for_an_earlier_dispatch_is_not_charged_again(
    db_session: AsyncSession,
) -> None:
    """Shipped (dispatch 0), reset for no ack (attempt 1), re-shipped
    (dispatch 1): the delayed error from dispatch 0 is already counted."""
    server, zone = await _server(db_session)
    op = _op(server, zone, state="in_flight")
    op.attempts = 1
    db_session.add(op)
    await db_session.flush()

    await apply_acks(
        db_session, server.id, [{"op_id": str(op.id), "result": "error", "dispatch": 0}]
    )
    assert (op.state, op.attempts) == ("in_flight", 1)
    await apply_acks(
        db_session, server.id, [{"op_id": str(op.id), "result": "error", "dispatch": 1}]
    )
    assert (op.state, op.attempts) == ("pending", 2)


async def test_ops_queued_in_one_transaction_never_supersede_each_other(
    db_session: AsyncSession,
) -> None:
    """``created_at`` is the transaction start, so two ops from one transaction
    tie; the tie says nothing about which was stamped last."""
    server, zone = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(minutes=2)
    first = _op(server, zone, values=("10.0.0.5",), state="applied", created_at=t0)
    second = _op(server, zone, values=("10.0.0.5", "10.0.0.6"), state="in_flight", created_at=t0)
    db_session.add_all([first, second])
    await db_session.flush()
    await ack_op(db_session, str(second.id), "error", "timeout", server_id=server.id)
    assert second.state == "pending", "the op carrying 10.0.0.6 must retry"


async def test_an_apex_op_keys_the_same_with_or_without_a_name(
    db_session: AsyncSession,
) -> None:
    """The RRset stamping reads an empty name as ``@``; supersession must too."""
    server, zone = await _server(db_session)
    t0 = datetime.now(UTC) - timedelta(minutes=2)
    older = _op(server, zone, name="", state="in_flight", created_at=t0)
    newer = _op(server, zone, name="@", created_at=t0 + timedelta(seconds=30))
    db_session.add_all([older, newer])
    await db_session.flush()
    await ack_op(db_session, str(older.id), "error", "x", server_id=server.id)
    assert (older.state, older.superseded_by) == ("superseded", newer.id)


async def test_an_agentless_failure_does_not_raise_the_retry_alert(
    db_session: AsyncSession,
) -> None:
    """An agentless driver applies once, inline, and hands the failure to the
    caller; the rule's "after every retry" would be false for it."""
    server, zone = await _server(db_session)
    server.driver = "route53"
    op = _op(server, zone, state="failed")
    db_session.add(op)
    await db_session.flush()
    assert await alerts._matching_dns_record_op_failed_subjects(db_session, None) == []  # type: ignore[arg-type]

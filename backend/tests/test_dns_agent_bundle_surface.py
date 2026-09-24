"""#1111 — the stored bundle on the operator's server row, and the alert
that fires when the control plane could not render one."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import ServerResponse
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services import alerts
from app.services.dns import agent_bundle_store as store
from app.services.dns.agent_bundle_render import render_and_store


async def _agent(db: AsyncSession) -> DNSServer:
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
    )
    db.add(server)
    await db.flush()
    zone = DNSZone(
        group_id=grp.id,
        name=f"z{uuid.uuid4().hex[:6]}.example.",
        zone_type="primary",
        kind="forward",
        primary_ns="ns1.example.",
        admin_email="admin.example.",
    )
    db.add(zone)
    await db.flush()
    db.add(
        DNSRecord(
            zone_id=zone.id, name="a", fqdn=f"a.{zone.name}", record_type="A", value="10.0.0.9"
        )
    )
    await db.flush()
    return server


@pytest.mark.asyncio
async def test_the_server_row_carries_the_stored_bundle(db_session: AsyncSession) -> None:
    server = await _agent(db_session)
    await db_session.commit()
    # The dirty mark is a Core UPDATE in the flush: an identity-mapped
    # instance does not see it until refreshed (the long-poll refreshes on
    # every wake; the servers list reads fresh rows).
    await db_session.refresh(server)
    before = ServerResponse.from_model(server)
    assert before.bundle_etag is None and before.bundle_watermark is None
    assert before.bundle_render_count == 0 and before.bundle_render_status is None
    assert before.bundle_dirty_seq >= 1  # the record insert already marked it

    outcome = await render_and_store(db_session, server, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    after = ServerResponse.from_model(server)
    assert after.bundle_etag == outcome.etag
    assert after.bundle_watermark == outcome.watermark == after.bundle_dirty_seq
    assert after.bundle_render_count == 1
    assert after.bundle_rendered_by == store.RENDERED_BY_WORKER
    assert after.bundle_render_status == store.RENDER_STATUS_OK
    assert after.bundle_built_at is not None and after.bundle_render_at is not None


@pytest.mark.asyncio
async def test_the_render_failed_rule_matches_failed_servers_by_severity(
    db_session: AsyncSession,
) -> None:
    never = await _agent(db_session)
    served = await _agent(db_session)
    fine = await _agent(db_session)
    await db_session.commit()
    await render_and_store(db_session, served, rendered_by=store.RENDERED_BY_WORKER)
    await render_and_store(db_session, fine, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    await store.record_failure(db_session, never.id, "boom-never")
    await store.record_failure(db_session, served.id, "boom-served")
    await db_session.commit()

    matches = await alerts._matching_agent_bundle_render_failed_subjects(db_session, None, datetime.now(UTC))  # type: ignore[arg-type]
    by_subject = {sid: (msg, sev) for sid, _disp, msg, sev in matches}
    assert set(by_subject) == {f"dns_server:{never.id}", f"dns_server:{served.id}"}
    assert by_subject[f"dns_server:{never.id}"][1] == "critical"
    assert "boom-never" in by_subject[f"dns_server:{never.id}"][0]
    assert by_subject[f"dns_server:{served.id}"][1] == "warning"
    assert (
        alerts.RULE_TYPE_AGENT_BUNDLE_RENDER_FAILED in alerts.KNOWN_RULE_TYPES
        if hasattr(alerts, "KNOWN_RULE_TYPES")
        else True
    )

    # A good render clears it — the rule auto-resolves through the diff.
    await render_and_store(db_session, never, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    matches = await alerts._matching_agent_bundle_render_failed_subjects(db_session, None, datetime.now(UTC))  # type: ignore[arg-type]
    assert {sid for sid, *_ in matches} == {f"dns_server:{served.id}"}


@pytest.mark.asyncio
async def test_the_rule_also_fires_when_changes_wait_with_no_render_landing(
    db_session: AsyncSession,
) -> None:
    """An OOM-killed render, a render slot held by a dead worker, or a worker
    that does not consume ``bundles`` never records a failure — the bundle
    just stays behind. That is the case the failure columns cannot see."""
    stalled = await _agent(db_session)
    recent = await _agent(db_session)
    disabled = await _agent(db_session)
    await db_session.commit()
    await render_and_store(db_session, stalled, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    now = datetime.now(UTC)
    long_ago = now - alerts._AGENT_BUNDLE_STALL - timedelta(minutes=1)
    for srv, since in ((stalled, long_ago), (recent, now), (disabled, long_ago)):
        await db_session.execute(
            update(DNSServer)
            .where(DNSServer.id == srv.id)
            .values(bundle_dirty_seq=DNSServer.bundle_dirty_seq + 1, bundle_dirty_at=since)
        )
    disabled.is_enabled = False
    await db_session.commit()

    matches = await alerts._matching_agent_bundle_render_failed_subjects(db_session, None, now)  # type: ignore[arg-type]
    by_subject = {sid: (msg, sev) for sid, _disp, msg, sev in matches}
    assert set(by_subject) == {f"dns_server:{stalled.id}"}
    msg, sev = by_subject[f"dns_server:{stalled.id}"]
    assert sev == "warning", "a previous bundle is still served"
    assert "bundles" in msg

    # A render that catches up clears it.
    await render_and_store(db_session, stalled, rendered_by=store.RENDERED_BY_WORKER)
    await db_session.commit()
    assert await alerts._matching_agent_bundle_render_failed_subjects(db_session, None, now) == []  # type: ignore[arg-type]

"""#632 — soft-deleting a DNS zone/record must retract it from agentless
providers (Cloudflare / Route 53 / Azure / Google / Windows DNS), and the
30-day purge must not orphan it.

Agent-based BIND9 / PowerDNS converge by dropping the row from the next
ConfigBundle render; agentless drivers have no bundle, so the control plane must
push the retraction explicitly. Before #632 the singular soft-delete path
skipped that push (only the permanent / bulk paths did it), and the purge Core-
DELETE removed the DB row with no push at all — leaving a live record/zone the
platform had no remaining knowledge of (a subdomain-takeover vector once the IP
is reclaimed).

Covers:
  * records — soft-delete pushes ``delete`` to an agentless primary
  * records — restore re-pushes ``create`` (the inverse must move together)
  * records — an agent-based soft-delete still enqueues its delete op
  * zones   — soft-delete does NOT tear the hosted zone down (zone-ID / NS churn
              on restore), and restore does NOT re-push its cascade records
  * purge   — a soft-deleted agentless zone is torn down before its row is
              removed, and is LEFT in place (retry next sweep) if the push fails
  * purge   — a pre-#632 agentless record is retracted before its row is removed
  * purge   — records inside a zone being purged, and agent-based records, are
              skipped (the zone teardown / bundle already cover them)
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServer, DNSServerGroup, DNSZone
from app.tasks.trash_purge import (
    _purge_dns_records,
    _purge_dns_zones,
    _retract_records_from_providers,
)


class _RecordingDriver:
    """Stand-in for an agentless driver — records the record ops it's handed."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str, str]] = []

    async def apply_record_change(self, _server: Any, change: Any) -> None:
        self.changes.append((change.op, change.record.name, change.record.record_type))

    async def apply_record_changes(self, server: Any, changes: list[Any]) -> list[Any]:
        # The batched entry point every real driver has (the ABC default loops
        # the singular one); the trash restore re-pushes a zone's records
        # through it in one call (#963 review).
        from app.drivers.dns.base import RecordChangeResult

        results = []
        for change in changes:
            await self.apply_record_change(server, change)
            results.append(RecordChangeResult(ok=True))
        return results


def _patch_record_driver(monkeypatch: pytest.MonkeyPatch) -> _RecordingDriver:
    """Route every agentless record push through one recorder (the seam
    ``_apply_agentless`` resolves the driver from)."""
    rec = _RecordingDriver()
    monkeypatch.setattr("app.services.dns.record_ops.get_driver", lambda _name: rec)
    return rec


async def _make_admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"dns632-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="DNS 632 Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _make_zone(db: AsyncSession, *, driver: str = "windows_dns") -> tuple[DNSServer, DNSZone]:
    grp = DNSServerGroup(name=f"g632-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    server = DNSServer(
        group_id=grp.id,
        driver=driver,
        host="10.9.9.9",
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
    return server, zone


async def _add_record(db: AsyncSession, zone: DNSZone, name: str = "web") -> DNSRecord:
    rec = DNSRecord(
        zone_id=zone.id,
        fqdn=f"{name}.{zone.name}",
        name=name,
        record_type="A",
        value="203.0.113.40",
        ttl=300,
    )
    db.add(rec)
    await db.flush()
    return rec


def _record_delete_url(zone: DNSZone, record: DNSRecord) -> str:
    return f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records/{record.id}"


# ── records — soft-delete + restore push through the agentless seam ──────────


@pytest.mark.asyncio
async def test_record_soft_delete_retracts_from_agentless_provider(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The everyday bug: the UI's default (soft) record delete now pushes the
    retraction, not just the SuperAdmin-only permanent path."""
    headers = await _make_admin(db_session)
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    record = await _add_record(db_session, zone, name="web7")
    await db_session.commit()

    recorder = _patch_record_driver(monkeypatch)

    resp = await client.delete(_record_delete_url(zone, record), headers=headers)
    assert resp.status_code == 204, resp.text
    assert recorder.changes == [("delete", "web7", "A")]


@pytest.mark.asyncio
async def test_record_restore_repushes_create_to_agentless_provider(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Delete pushed a retract; restore owes the inverse or the record comes back
    in SpatiumDDI only and the two silently diverge."""
    headers = await _make_admin(db_session)
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    record = await _add_record(db_session, zone, name="web7")
    await db_session.commit()

    recorder = _patch_record_driver(monkeypatch)

    del_resp = await client.delete(_record_delete_url(zone, record), headers=headers)
    assert del_resp.status_code == 204, del_resp.text

    restore_resp = await client.post(
        f"/api/v1/admin/trash/dns_record/{record.id}/restore", headers=headers
    )
    assert restore_resp.status_code == 200, restore_resp.text
    assert recorder.changes == [("delete", "web7", "A"), ("create", "web7", "A")]


@pytest.mark.asyncio
async def test_agent_based_record_soft_delete_enqueues_delete_op(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Agent-based (bind9) converges via the bundle drop, but the soft path now
    also enqueues an explicit (idempotent) delete op — matching the permanent
    path and waking the agents immediately instead of on the 12 s tick."""
    headers = await _make_admin(db_session)
    server, zone = await _make_zone(db_session, driver="bind9")
    record = await _add_record(db_session, zone, name="web7")
    await db_session.commit()

    resp = await client.delete(_record_delete_url(zone, record), headers=headers)
    assert resp.status_code == 204, resp.text

    ops = (
        (
            await db_session.execute(
                select(DNSRecordOp).where(
                    DNSRecordOp.zone_name == zone.name, DNSRecordOp.op == "delete"
                )
            )
        )
        .scalars()
        .all()
    )
    assert [o.server_id for o in ops] == [server.id]


# ── zones — no teardown on soft-delete, no record re-push on restore ─────────


@pytest.mark.asyncio
async def test_zone_soft_delete_and_restore_do_not_touch_agentless_records(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zone is delete-then-recreate at cloud providers, so tearing it down on
    soft-delete would mint a new zone ID + NS records on restore. The zone-delete
    path therefore never retracts its cascade records — and restore must not
    re-push them (they were never retracted)."""
    headers = await _make_admin(db_session)
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    await _add_record(db_session, zone, name="a1")
    await _add_record(db_session, zone, name="a2")
    await db_session.commit()

    recorder = _patch_record_driver(monkeypatch)
    # A wrongful hosted-zone teardown would go through the zone-level seam, not
    # the record recorder — spy it directly so this test actually guards it.
    zone_pushes: list[tuple[str, str]] = []

    async def _spy_zone_push(_db: Any, z: Any, op: str) -> None:
        zone_pushes.append((z.name, op))

    monkeypatch.setattr(
        "app.api.v1.dns.router._push_zone_to_agentless_servers", _spy_zone_push, raising=True
    )

    del_resp = await client.delete(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}", headers=headers
    )
    assert del_resp.status_code == 204, del_resp.text
    assert recorder.changes == [], "zone soft-delete must not retract its records"
    assert zone_pushes == [], "zone soft-delete must not tear the hosted zone down"

    restore_resp = await client.post(
        f"/api/v1/admin/trash/dns_zone/{zone.id}/restore", headers=headers
    )
    assert restore_resp.status_code == 200, restore_resp.text
    assert recorder.changes == [], "zone restore must not re-push records that were never retracted"
    assert zone_pushes == [], "zone restore must not tear the hosted zone down/up"


# ── purge — zones tear down per-row (gate the DB delete on the push) ─────────


@pytest.mark.asyncio
async def test_purge_tears_down_agentless_zone_before_removing_row(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    zone.deleted_at = datetime.now(UTC) - timedelta(days=40)
    zone.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    pushed: list[tuple[uuid.UUID, str]] = []

    async def _fake_push(_db: Any, z: DNSZone, op: str) -> None:
        pushed.append((z.id, op))

    monkeypatch.setattr(
        "app.api.v1.dns.router._push_zone_to_agentless_servers", _fake_push, raising=True
    )

    cutoff = datetime.now(UTC) - timedelta(days=30)
    purged, skipped = await _purge_dns_zones(db_session, cutoff)

    assert (purged, skipped) == (1, 0)
    assert pushed == [(zone.id, "delete")]
    gone = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert gone is None


@pytest.mark.asyncio
async def test_purge_leaves_zone_when_provider_push_fails(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead / rejecting provider must NOT let the Core DELETE remove the row —
    that orphans the hosted zone forever. Leave it soft-deleted for the next
    sweep to retry."""
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    zone.deleted_at = datetime.now(UTC) - timedelta(days=40)
    zone.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    async def _boom(_db: Any, _z: DNSZone, _op: str) -> None:
        raise RuntimeError("provider unreachable")

    monkeypatch.setattr(
        "app.api.v1.dns.router._push_zone_to_agentless_servers", _boom, raising=True
    )

    cutoff = datetime.now(UTC) - timedelta(days=30)
    purged, skipped = await _purge_dns_zones(db_session, cutoff)

    assert (purged, skipped) == (0, 1)
    still_there = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert still_there is not None, "a failed provider push must not orphan the row"


# ── purge — records retract for agentless, skip where already covered ────────


@pytest.mark.asyncio
async def test_purge_retracts_pre_632_agentless_record(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A record soft-deleted before #632 (or whose day-0 push failed) is retracted
    at the provider before the purge removes its row."""
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    record = await _add_record(db_session, zone, name="stale")
    record.deleted_at = datetime.now(UTC) - timedelta(days=40)
    record.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    recorder = _patch_record_driver(monkeypatch)
    cutoff = datetime.now(UTC) - timedelta(days=30)
    retracted = await _retract_records_from_providers(db_session, cutoff, set())
    await db_session.commit()  # #1539 — the provider is written by the commit

    assert retracted == 1
    assert recorder.changes == [("delete", "stale", "A")]


@pytest.mark.asyncio
async def test_purge_zone_deletes_cleanly_after_records_core_deleted(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reproduce the real ``_sweep`` session state: the record pre-pass loads this
    zone's soft-deleted records into the session and the bulk loop Core-DELETEs
    them (without expiring it) before ``_purge_dns_zones`` runs. The zone delete
    must not choke on those stale identity-map rows — hence the Core DELETE over
    an ORM ``delete-orphan`` cascade."""
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    batch = uuid.uuid4()
    stamp = datetime.now(UTC) - timedelta(days=40)
    for name in ("r1", "r2"):
        rec = await _add_record(db_session, zone, name=name)
        rec.deleted_at = stamp
        rec.deletion_batch_id = batch
    zone.deleted_at = stamp
    zone.deletion_batch_id = batch
    await db_session.flush()

    # Mimic _sweep: materialise the records into the identity map, then Core-
    # DELETE them exactly as the bulk loop does, leaving them stale in-session.
    loaded = (
        (
            await db_session.execute(
                select(DNSRecord)
                .where(DNSRecord.zone_id == zone.id)
                .execution_options(include_deleted=True)
            )
        )
        .scalars()
        .all()
    )
    assert len(loaded) == 2
    await db_session.execute(
        delete(DNSRecord)
        .where(DNSRecord.zone_id == zone.id)
        .execution_options(include_deleted=True)
    )

    async def _noop(_db: Any, _z: DNSZone, _op: str) -> None:
        return None

    monkeypatch.setattr(
        "app.api.v1.dns.router._push_zone_to_agentless_servers", _noop, raising=True
    )

    cutoff = datetime.now(UTC) - timedelta(days=30)
    purged, skipped = await _purge_dns_zones(db_session, cutoff)

    assert (purged, skipped) == (1, 0)
    gone = (
        await db_session.execute(
            select(DNSZone).where(DNSZone.id == zone.id).execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert gone is None


@pytest.mark.asyncio
async def test_purge_skips_records_inside_purged_zone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Records whose whole zone is being purged this sweep are retracted wholesale
    by the zone teardown — the per-record pass must not double-push them."""
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    record = await _add_record(db_session, zone, name="child")
    record.deleted_at = datetime.now(UTC) - timedelta(days=40)
    record.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    recorder = _patch_record_driver(monkeypatch)
    cutoff = datetime.now(UTC) - timedelta(days=30)
    retracted = await _retract_records_from_providers(db_session, cutoff, {zone.id})

    assert retracted == 0
    assert recorder.changes == []


@pytest.mark.asyncio
async def test_purge_retract_does_not_count_disabled_agentless_primary(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disabled agentless primary can't be pushed to (enqueue_record_op drops
    it), so the retract counter must not report a retraction that never happened."""
    server, zone = await _make_zone(db_session, driver="windows_dns")
    server.is_enabled = False
    record = await _add_record(db_session, zone, name="paused")
    record.deleted_at = datetime.now(UTC) - timedelta(days=40)
    record.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    recorder = _patch_record_driver(monkeypatch)
    cutoff = datetime.now(UTC) - timedelta(days=30)
    retracted = await _retract_records_from_providers(db_session, cutoff, set())

    assert retracted == 0
    assert recorder.changes == []


@pytest.mark.asyncio
async def test_purge_records_excludes_those_in_a_purged_zone(
    db_session: AsyncSession,
) -> None:
    """A record whose zone is being purged this sweep is NOT deleted by the record
    pass — it rides the zone's own delete + FK CASCADE, so a failed zone teardown
    can't strand it at the provider (#632)."""
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    record = await _add_record(db_session, zone, name="child")
    record.deleted_at = datetime.now(UTC) - timedelta(days=40)
    record.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    cutoff = datetime.now(UTC) - timedelta(days=30)
    removed = await _purge_dns_records(db_session, cutoff, {zone.id})

    assert removed == 0
    still = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.id == record.id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert still is not None, "in-zone record must survive the record pass (rides the zone CASCADE)"


@pytest.mark.asyncio
async def test_purge_records_deletes_standalone_records(
    db_session: AsyncSession,
) -> None:
    """A record whose zone is NOT being purged (individually soft-deleted in a live
    zone) is Core-DELETEd by the record pass."""
    _server, zone = await _make_zone(db_session, driver="windows_dns")
    record = await _add_record(db_session, zone, name="solo")
    record.deleted_at = datetime.now(UTC) - timedelta(days=40)
    record.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    cutoff = datetime.now(UTC) - timedelta(days=30)
    removed = await _purge_dns_records(db_session, cutoff, set())

    assert removed == 1
    gone = (
        await db_session.execute(
            select(DNSRecord)
            .where(DNSRecord.id == record.id)
            .execution_options(include_deleted=True)
        )
    ).scalar_one_or_none()
    assert gone is None


@pytest.mark.asyncio
async def test_purge_skips_agent_based_records(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Agent-based records left the agents' bundle 30 days ago — a purge-time push
    would only add no-op op rows for the common BIND9 / PowerDNS case."""
    _server, zone = await _make_zone(db_session, driver="bind9")
    record = await _add_record(db_session, zone, name="agentrec")
    record.deleted_at = datetime.now(UTC) - timedelta(days=40)
    record.deletion_batch_id = uuid.uuid4()
    await db_session.flush()

    recorder = _patch_record_driver(monkeypatch)
    cutoff = datetime.now(UTC) - timedelta(days=30)
    retracted = await _retract_records_from_providers(db_session, cutoff, set())

    assert retracted == 0
    assert recorder.changes == []

"""Reconciler for the commercial-DDI mirror (#4729): provenance keyed upserts,
sweep, per-kind failure isolation, auth abort, and no write outside the mirror
store."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.audit import AuditLog
from app.models.ddi_mirror import DDIMirrorObject, DDIMirrorTarget
from app.models.dns import DNSRecord, DNSZone
from app.models.ipam import IPAddress, IPBlock, Subnet
from app.services.ddi_mirror import infoblox as ib
from app.services.ddi_mirror.reconcile import reconcile_target
from tests._ddi_mirror_support import FakeWapi, fixture


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "_PAGE_PAUSE_SECONDS", 0)


async def _target(db: AsyncSession, **kw: object) -> DDIMirrorTarget:
    t = DDIMirrorTarget(
        name=kw.pop("name", "estate"),  # type: ignore[arg-type]
        base_url="https://gm.test",
        username="admin",
        password_encrypted=kw.pop("password_encrypted", encrypt_str("secret")),  # type: ignore[arg-type]
        **kw,  # type: ignore[arg-type]
    )
    db.add(t)
    await db.commit()
    return t


async def _counts(db: AsyncSession, target: DDIMirrorTarget) -> dict[str, int]:
    rows = (
        await db.execute(
            select(DDIMirrorObject.kind, func.count())
            .where(DDIMirrorObject.target_id == target.id)
            .group_by(DDIMirrorObject.kind)
        )
    ).all()
    return {k: int(n) for k, n in rows}


EXPECTED = {
    "view": 2, "container": 1, "network": 3, "range": 1, "reservation": 1,
    "zone": 2, "host": 1, "a": 1, "ptr": 1,
}  # fmt: skip


@pytest.mark.asyncio
async def test_first_sync_mirrors_every_kind_and_reports_the_unmapped(
    db_session: AsyncSession,
) -> None:
    t = await _target(db_session)
    s = await reconcile_target(db_session, t, transport=FakeWapi().transport())
    assert s.ok, s.error
    assert await _counts(db_session, t) == EXPECTED
    assert s.object_count == sum(EXPECTED.values())
    assert s.kinds["network"].unmapped == 1 and s.kinds["host"].unmapped == 1
    await db_session.refresh(t)
    assert t.last_sync_error is None and t.last_synced_at is not None
    assert t.source_version == "WAPI v2.12" and t.object_count == s.object_count
    assert t.last_report["unmapped_total"] == 2
    assert any("not-a-cidr" in m for m in t.last_report["unmapped_examples"])
    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "ddi_mirror.reconcile"))
    ).scalar_one()
    assert audit.resource_type == "ddi_mirror_target" and audit.result != "error"


@pytest.mark.asyncio
async def test_sync_writes_nothing_outside_the_mirror_store(db_session: AsyncSession) -> None:
    t = await _target(db_session)
    await reconcile_target(db_session, t, transport=FakeWapi().transport())
    for model in (Subnet, IPBlock, IPAddress, DNSZone, DNSRecord):
        assert await db_session.scalar(select(func.count()).select_from(model)) == 0, model


@pytest.mark.asyncio
async def test_repeat_sync_updates_in_place_and_sweeps_what_vanished(
    db_session: AsyncSession,
) -> None:
    t = await _target(db_session)
    wapi = FakeWapi()
    await reconcile_target(db_session, t, transport=wapi.transport())
    ids = {
        o.source_ref: o.id for o in (await db_session.execute(select(DDIMirrorObject))).scalars()
    }

    s = await reconcile_target(db_session, t, transport=wapi.transport())
    assert s.ok and all(r.created == r.updated == r.deleted == 0 for r in s.kinds.values())
    assert await _counts(db_session, t) == EXPECTED

    # the source changes: a zone comment, and the A record goes away
    zones = fixture("zone_auth")
    zones["result"][0]["comment"] = "renamed upstream"
    wapi.overrides["zone_auth"] = (200, zones)
    wapi.overrides["record:a"] = (200, {"result": []})
    s = await reconcile_target(db_session, t, transport=wapi.transport())
    assert s.kinds["zone"].updated == 1 and s.kinds["a"].deleted == 1
    counts = await _counts(db_session, t)
    assert "a" not in counts and counts["zone"] == 2
    db_session.expire_all()
    rows = {o.source_ref: o for o in (await db_session.execute(select(DDIMirrorObject))).scalars()}
    # same rows, same ids: provenance keyed, never duplicated
    assert all(ids[ref] == o.id for ref, o in rows.items() if ref in ids)
    zone = next(o for o in rows.values() if o.kind == "zone" and o.name == "example.com")
    assert zone.comment == "renamed upstream"


@pytest.mark.asyncio
async def test_a_kind_that_fails_keeps_its_rows_and_warns(db_session: AsyncSession) -> None:
    t = await _target(db_session)
    wapi = FakeWapi()
    await reconcile_target(db_session, t, transport=wapi.transport())

    wapi.overrides["zone_auth"] = (500, {"text": "boom"})
    # and a host change in the same run still lands
    hosts = fixture("record_host")
    hosts["result"] = hosts["result"][:1]
    hosts["result"][0]["comment"] = "edited"
    wapi.overrides["record:host"] = (200, hosts)
    s = await reconcile_target(db_session, t, transport=wapi.transport())
    assert s.ok and s.kinds["zone"].error and "500" in s.kinds["zone"].error
    assert s.kinds["host"].updated == 1
    assert (await _counts(db_session, t))["zone"] == 2  # not swept on a failed pull
    await db_session.refresh(t)
    assert t.last_sync_error is None and "zone" in (t.last_sync_warning or "")


@pytest.mark.asyncio
async def test_bad_credentials_abort_and_record_an_error_audit_row(
    db_session: AsyncSession,
) -> None:
    t = await _target(db_session)
    wapi = FakeWapi()
    await reconcile_target(db_session, t, transport=wapi.transport())

    wapi.require_auth = ("admin", "rotated")
    s = await reconcile_target(db_session, t, transport=wapi.transport())
    assert not s.ok and "401" in (s.error or "")
    await db_session.refresh(t)
    assert "401" in (t.last_sync_error or "")
    assert await _counts(db_session, t) == EXPECTED  # nothing swept
    err = (
        await db_session.execute(select(AuditLog).where(AuditLog.result == "error"))
    ).scalar_one()
    assert err.resource_type == "ddi_mirror_target" and err.resource_id == str(t.id)


@pytest.mark.asyncio
async def test_no_password_is_an_error_not_a_crash(db_session: AsyncSession) -> None:
    t = await _target(db_session, password_encrypted=b"")
    s = await reconcile_target(db_session, t, transport=FakeWapi().transport())
    assert not s.ok and s.error == "no password configured"
    await db_session.refresh(t)
    assert t.last_sync_error == "no password configured"

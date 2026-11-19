"""A reconcile that raises is recorded on its row (#2141).

The reconcilers stamp ``last_sync_error`` / ``last_synced_at`` inside
the same transaction as their mirror writes, so a raise that reaches
the sweep task used to roll the stamp back with everything else: no
visible error, no audit row for the Integrations dashboard, and — since
the interval gate keys on ``last_synced_at`` — a retry on every beat
tick. Every sweep, every "Sync Now" task and the block-sync sweep now
record the crash in a transaction of its own.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.ipam import IPSpace
from app.services.integration_sync_failure import describe_sync_crash
from tests.test_sync_sweep_rollback import (
    _SWEEPS,
    _make_space,
    _platform_settings,
    _sweep_targets,
)

_RESOURCE_TYPES = {
    "kubernetes": "kubernetes_cluster",
    "docker": "docker_host",
    "tailscale": "tailscale_tenant",
    "netbird": "netbird_instance",
    "unifi": "unifi_controller",
    "proxmox": "proxmox_node",
    "cloud": "cloud_endpoint",
    "opnsense": "opnsense_router",
    "fortinet": "fortinet_firewall",
    "panos": "panos_firewall",
    "meraki": "meraki_org",
}


class _Summary:
    ok = True
    error = None

    def __getattr__(self, name: str) -> object:  # every counter a _run_one reads
        return 0


@pytest.mark.asyncio
@pytest.mark.parametrize("sweep", _SWEEPS)
async def test_a_raising_reconcile_is_recorded(db_session: AsyncSession, sweep: str) -> None:
    space = await _make_space(db_session)
    module, reconcile_path, flag, factory = _sweep_targets(space.id)[sweep]
    await _platform_settings(db_session, **{flag: True})
    a, b = factory(), factory()
    db_session.add_all([a, b])
    await db_session.commit()
    model = type(a)
    ids = {a.id, b.id}
    partial_space = f"partial-{uuid.uuid4().hex[:8]}"

    crashed: list[uuid.UUID] = []
    calls: list[uuid.UUID] = []

    async def _fake_reconcile(db: AsyncSession, target):  # noqa: ANN001
        calls.append(target.id)
        if not crashed:
            crashed.append(target.id)
            # A partial write the rollback must discard, then the raise.
            db.add(IPSpace(name=partial_space, description=""))
            await db.flush()
            raise RuntimeError("boom: reconcile exploded")
        return _Summary()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconcile_path, _fake_reconcile)
        result = await module._run_sweep()

        assert result["errors"] == 1 and result["ok"] == 1
        (bad,) = crashed
        (good,) = ids - {bad}

        db_session.expire_all()
        bad_row = await db_session.get(model, bad)
        good_row = await db_session.get(model, good)
        assert bad_row.last_sync_error == "RuntimeError: boom: reconcile exploded"
        assert bad_row.last_synced_at is not None
        # The other target's state is left alone (the fake never stamps it).
        assert good_row.last_sync_error is None
        assert good_row.last_synced_at is None
        # The partial reconcile was still rolled back.
        assert (
            await db_session.execute(select(IPSpace).where(IPSpace.name == partial_space))
        ).scalar_one_or_none() is None
        # The error audit row the Integrations dashboard lists.
        audit = (
            (
                await db_session.execute(
                    select(AuditLog)
                    .where(AuditLog.resource_id == str(bad))
                    .where(AuditLog.result == "error")
                )
            )
            .scalars()
            .all()
        )
        assert len(audit) == 1
        assert audit[0].resource_type == _RESOURCE_TYPES[sweep]
        assert audit[0].error_detail == bad_row.last_sync_error

        # The interval gate now backs the crashed target off.
        calls.clear()
        again = await module._run_sweep()
        assert bad not in calls
        assert again["skipped_interval"] >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("sweep", _SWEEPS)
async def test_sync_now_records_a_raise(db_session: AsyncSession, sweep: str) -> None:
    space = await _make_space(db_session)
    module, reconcile_path, _flag, factory = _sweep_targets(space.id)[sweep]
    row = factory()
    db_session.add(row)
    await db_session.commit()
    model, row_id = type(row), row.id

    async def _raise(db: AsyncSession, target):  # noqa: ANN001, ARG001
        raise RuntimeError("boom now")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconcile_path, _raise)
        result = await module._run_one(str(row_id))

    assert result == {"status": "error", "error": "RuntimeError: boom now"}
    db_session.expire_all()
    fresh = await db_session.get(model, row_id)
    assert fresh.last_sync_error == "RuntimeError: boom now"
    assert fresh.last_synced_at is not None


@pytest.mark.asyncio
async def test_block_sync_sweep_records_a_raise(db_session: AsyncSession) -> None:
    from app.models.unifi import UnifiController  # noqa: PLC0415
    from app.tasks import block_sync  # noqa: PLC0415

    space = await _make_space(db_session)
    controller = UnifiController(name=f"u-{uuid.uuid4().hex[:6]}", ipam_space_id=space.id)
    db_session.add(controller)
    await db_session.commit()
    cid = controller.id

    async def _armed(db: AsyncSession):  # noqa: ANN202, ARG001
        return [], [controller], [], []

    async def _enabled(db: AsyncSession, module_id: str) -> bool:  # noqa: ARG001
        return True

    async def _raise(db: AsyncSession, target):  # noqa: ANN001, ARG001
        raise RuntimeError("push exploded")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("app.services.block_sync.reconcile.armed_targets", _armed)
        mp.setattr("app.services.block_sync.reconcile.reconcile_unifi", _raise)
        mp.setattr(block_sync, "is_module_enabled", _enabled)
        result = await block_sync._run_sweep()

    assert result["errors"] == 1
    db_session.expire_all()
    fresh = await db_session.get(UnifiController, cid)
    assert fresh.last_block_sync_error == "RuntimeError: push exploded"
    assert fresh.last_block_sync_at is not None
    # Block-sync errors stay off the mirror's own fields.
    assert fresh.last_sync_error is None


def test_describe_sync_crash_drops_sql_and_parameters() -> None:
    orig = Exception('duplicate key value violates unique constraint "uq_router_name"')
    exc = IntegrityError("INSERT INTO router (name, secret) VALUES ($1, $2)", ("x", "s3cr3t"), orig)
    text = describe_sync_crash(exc)
    assert "uq_router_name" in text
    assert "s3cr3t" not in text and "INSERT" not in text
    assert text.startswith("IntegrityError: ")
    assert len(describe_sync_crash(RuntimeError("x" * 5000))) == 1000


def test_describe_sync_crash_redacts_credentials_in_urls() -> None:
    import httpx  # noqa: PLC0415

    req = httpx.Request("GET", "https://admin:hunter2@ctl.example/api/v1?api_token=TKN123&site=x")
    resp = httpx.Response(401, request=req)
    # httpx's raise_for_status() message carries the full URL.
    exc = httpx.HTTPStatusError(
        f"Client error '401 Unauthorized' for url '{req.url}'", request=req, response=resp
    )
    text = describe_sync_crash(exc)
    assert "hunter2" not in text and "TKN123" not in text
    assert "site=x" in text and "ctl.example" in text


def test_describe_sync_crash_redacts_a_failing_row_detail() -> None:
    from sqlalchemy.exc import DBAPIError  # noqa: PLC0415

    orig = Exception(
        'null value in column "name" of relation "unifi_controller" violates not-null '
        "constraint\nDETAIL:  Failing row contains (abc, null, gAAAAAsecretcipher, (x))."
    )
    exc = DBAPIError("UPDATE unifi_controller SET x=$1", ("gAAAAAparam",), orig)
    text = describe_sync_crash(exc)
    assert "gAAAAA" not in text
    assert "not-null" in text and "Failing row contains (…)" in text

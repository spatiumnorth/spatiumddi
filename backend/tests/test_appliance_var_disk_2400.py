"""#2400 — an appliance's /var against kubelet eviction.

A 1.5 GiB upgrade image on a 15 GB /var pushed a single-node appliance past
the kubelet's 5 % eviction threshold; the kubelet then evicted the api,
worker and supervisor until 15 % was free, and nothing had warned. These
pin the three things that now look at /var before that happens:

* the slot-upgrade scheduling pre-flight (422 naming the numbers);
* the Fleet row's
  finding, judged by ``services/appliance/var_disk`` with the same lines as
  the existing ``appliance_disk_usage`` alert (which it must agree with);
* the reclaim of a stored upgrade image every node has already written.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    Appliance,
    ApplianceUpgradeImage,
)
from app.models.audit import AuditLog
from app.models.auth import User
from app.services import alerts as alerts_svc
from app.services.alerts import evaluate_all
from app.services.appliance import var_disk

GIB = 1024**3
MIB = 1024**2
TOTAL = 15 * GIB


def _health(*, free: int, total: int = TOTAL, exact: bool = True) -> dict:
    part: dict = {"mount": "/var", "label": "Data", "total_bytes": total}
    if exact:
        # used deliberately inconsistent with available: the reserve.
        part["used_bytes"] = total - free - total * 5 // 100
        part["available_bytes"] = free
    else:
        part["used_bytes"] = total - free
    return {"host_disk_partitions": [part]}


async def _node(
    db: AsyncSession,
    *,
    free: int | None,
    last_seen: datetime | None = None,
    hostname: str | None = None,
    architecture: str | None = "amd64",
    installed: str | None = None,
) -> Appliance:
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname=hostname or f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        cert_serial="0001",
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        architecture=architecture,
        supervisor_version="2026.09.01-1",
        last_seen_at=last_seen if last_seen is not None else datetime.now(UTC),
        cluster_health=_health(free=free) if free is not None else {},
        installed_appliance_version=installed,
    )
    db.add(row)
    await db.flush()
    return row


async def _image(
    db: AsyncSession,
    *,
    size: int = 1536 * MIB,
    version: str = "2026.10.20-1",
    architecture: str | None = "amd64",
    uploaded_at: datetime | None = None,
) -> ApplianceUpgradeImage:
    img = ApplianceUpgradeImage(
        id=uuid.uuid4(),
        filename=f"spatiumddi-appliance-slot-{version}-amd64.raw.xz",
        size_bytes=size,
        sha256=uuid.uuid4().hex + uuid.uuid4().hex,
        appliance_version=version,
        architecture=architecture,
    )
    if uploaded_at is not None:
        img.uploaded_at = uploaded_at
    db.add(img)
    await db.flush()
    return img


# ── the reader + evaluator ─────────────────────────────────────────


def test_reading_prefers_the_kubelets_own_measure() -> None:
    """``total - used`` counts ext4's 5 % root reserve as free; the kubelet
    does not."""
    r = var_disk.var_disk_reading(_health(free=2 * GIB))
    assert r is not None and r.exact and r.free_bytes == 2 * GIB


def test_reading_falls_back_for_an_older_supervisor() -> None:
    r = var_disk.var_disk_reading(_health(free=2 * GIB, exact=False))
    assert r is not None and not r.exact and r.free_bytes == 2 * GIB


@pytest.mark.parametrize(
    "ch", [None, {}, {"host_disk_partitions": "x"}, {"host_disk_partitions": [{"mount": "/"}]}]
)
def test_no_reading_is_unknown(ch) -> None:
    assert var_disk.var_disk_reading(ch) is None
    assert var_disk.evaluate_var_disk(None) is None


def test_eviction_headroom_is_hard_plus_minimum_reclaim() -> None:
    from app.services.appliance import upgrade_image_space

    assert var_disk.EVICTION_HEADROOM_PCT == 15
    assert upgrade_image_space.EVICTION_HEADROOM_PCT == var_disk.EVICTION_HEADROOM_PCT
    # #2572's spool rule reads the same 5 % trigger, defined once.
    assert upgrade_image_space.EVICTION_HARD_PCT is var_disk.EVICTION_HARD_PCT == 5
    assert var_disk.EVICTION_HEADROOM_PCT == (
        var_disk.EVICTION_HARD_PCT + var_disk.EVICTION_MINIMUM_RECLAIM_PCT
    )


@pytest.mark.parametrize(
    ("used_pct", "severity"),
    [(50, None), (79, None), (80, "warning"), (86, "warning"), (87, "critical"), (97, "critical")],
)
def test_severity_bands(used_pct: int, severity: str | None) -> None:
    """The Fleet row's lines are the ``appliance_disk_usage`` alert's, in its
    terms (``used_bytes`` as reported)."""
    ch = _health(free=TOTAL * (100 - used_pct) // 100, exact=False)
    f = var_disk.evaluate_var_disk(var_disk.var_disk_reading(ch))
    assert (f.severity if f else None) == severity


def test_lines_are_the_alerts_lines() -> None:
    assert var_disk.WARN_USED_PCT == alerts_svc._APPLIANCE_DISK_USAGE_DEFAULT_PCT
    assert var_disk.CRITICAL_USED_PCT == alerts_svc._APPLIANCE_DISK_CRITICAL_PCT


def test_disk_pressure_is_critical_whatever_the_reading() -> None:
    f = var_disk.evaluate_var_disk(
        var_disk.var_disk_reading(_health(free=TOTAL // 2)), disk_pressure=True
    )
    assert f is not None and f.severity == "critical" and "DiskPressure" in f.detail
    f = var_disk.evaluate_var_disk(None, disk_pressure=True)
    assert f is not None and f.severity == "critical"


# ── scheduling pre-flight ──────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"disk-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Disk Admin",
        hashed_password=hash_password("test-pw-2400"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _schedule(client: AsyncClient, headers, appliance: Appliance, image_id) -> object:
    return await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/upgrade",
        headers=headers,
        json={"desired_appliance_version": "2026.10.20-1", "slot_image_id": str(image_id)},
    )


@pytest.mark.asyncio
async def test_scheduling_refuses_an_upgrade_that_would_leave_var_in_eviction(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The ddi1 numbers: 15 GB /var, 2.5 GiB free, a 1.5 GiB image —
    1 GiB left, under the 2.25 GiB the kubelet needs to stop evicting."""
    headers = await _headers(db_session)
    node = await _node(db_session, free=2560 * MIB, hostname="ddi1")
    image = await _image(db_session)
    await db_session.commit()

    resp = await _schedule(client, headers, node, image.id)
    assert resp.status_code == 422, resp.text
    detail = resp.json()["detail"]
    assert "ddi1" in detail
    assert "1536 MiB" in detail  # the image
    assert "2304 MiB" in detail  # 15 % of /var that must stay free
    assert "2560 MiB" in detail  # what is free
    await db_session.refresh(node)
    assert node.desired_appliance_version is None


@pytest.mark.asyncio
async def test_scheduling_proceeds_with_room_to_spare(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    headers = await _headers(db_session)
    node = await _node(db_session, free=6 * GIB)
    image = await _image(db_session)
    await db_session.commit()
    resp = await _schedule(client, headers, node, image.id)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["no_reading", "stale_reading"])
async def test_an_unknown_reading_does_not_refuse(
    db_session: AsyncSession, client: AsyncClient, case: str
) -> None:
    """Unknown is not a refusal: the host runner still checks (rc 7)."""
    headers = await _headers(db_session)
    if case == "no_reading":
        node = await _node(db_session, free=None)
    else:
        node = await _node(
            db_session, free=100 * MIB, last_seen=datetime.now(UTC) - timedelta(hours=1)
        )
    image = await _image(db_session)
    await db_session.commit()
    resp = await _schedule(client, headers, node, image.id)
    assert resp.status_code == 200, resp.text


# ── the alert is main's appliance_disk_usage rule, not a second one ─


async def _no_delivery(rule, event, targets):  # type: ignore[no-untyped-def]
    return (False, False, False)


async def _open(db: AsyncSession, rule: AlertRule) -> list[AlertEvent]:
    return list(
        (
            await db.execute(
                select(AlertEvent).where(
                    AlertEvent.rule_id == rule.id, AlertEvent.resolved_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )


@pytest.mark.asyncio
async def test_fleet_row_and_the_usage_alert_agree(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1.appliance.supervisor import _var_disk_finding

    monkeypatch.setattr(alerts_svc, "_deliver", _no_delivery)
    rule = AlertRule(
        name="Appliance /var (agreement test)",
        rule_type="appliance_disk_usage",
        threshold_percent=80,
        severity="warning",
        enabled=True,
    )
    db_session.add(rule)
    nodes = {
        pct: await _node(db_session, free=TOTAL * (100 - pct) // 100)
        for pct in (50, 79, 80, 86, 87, 95)
    }
    await db_session.commit()
    await evaluate_all(db_session)
    by_subject = {e.subject_id: e.severity for e in await _open(db_session, rule)}
    for pct, node in nodes.items():
        finding = _var_disk_finding(node)
        assert by_subject.get(str(node.id)) == (finding["severity"] if finding else None), pct


@pytest.mark.asyncio
async def test_fleet_row_carries_the_finding(db_session: AsyncSession) -> None:
    from app.api.v1.appliance.supervisor import _var_disk_finding

    low = await _node(db_session, free=TOTAL * 3 // 100)
    fine = await _node(db_session, free=TOTAL // 2)
    stale = await _node(
        db_session, free=TOTAL // 100, last_seen=datetime.now(UTC) - timedelta(hours=1)
    )
    assert _var_disk_finding(low)["severity"] == "critical"
    assert _var_disk_finding(fine) is None
    assert _var_disk_finding(stale) is None


# ── reclaiming a stored image every node has committed to ─────────


@pytest.fixture()
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from app.api.v1.appliance import upgrade_images

    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", None)
    return tmp_path


def _bytes(store: Path, image: ApplianceUpgradeImage) -> Path:
    from app.api.v1.appliance.upgrade_images import _image_path

    p = _image_path(image.id)
    assert p.parent == store
    p.write_bytes(b"xz")
    return p


_OLD = datetime.now(UTC) - timedelta(days=1)
_ANCIENT = datetime.now(UTC) - timedelta(days=8)
V = "2026.10.20-1"


def _committed(node: Appliance, version: str = V) -> Appliance:
    """Running ``version`` on a committed (durable, non-trial) boot."""
    node.installed_appliance_version = version
    node.current_slot = "slot_b"
    node.durable_default = "slot_b"
    node.is_trial_boot = False
    node.slot_b_version = version
    return node


def _scheduled_once(db: AsyncSession, image: ApplianceUpgradeImage) -> None:
    db.add(
        AuditLog(
            user_display_name="t",
            auth_source="local",
            action="appliance.upgrade_scheduled",
            resource_type="appliance",
            resource_id=str(uuid.uuid4()),
            resource_display="n",
            new_value={"slot_image_id": str(image.id)},
            result="success",
        )
    )


async def _reclaim(db: AsyncSession) -> list[str]:
    from app.api.v1.appliance.upgrade_images import reclaim_committed_upgrade_images

    return await reclaim_committed_upgrade_images(db)


@pytest.mark.asyncio
async def test_an_image_every_node_runs_is_reclaimed(db_session: AsyncSession, store: Path) -> None:
    image = await _image(db_session, uploaded_at=_OLD)
    _scheduled_once(db_session, image)
    a = _committed(await _node(db_session, free=TOTAL // 2))
    b = _committed(await _node(db_session, free=TOTAL // 2))
    path = _bytes(store, image)
    await db_session.flush()

    assert await _reclaim(db_session) == [f"{image.filename} ({image.appliance_version})"]
    assert not path.exists()
    assert await db_session.get(ApplianceUpgradeImage, image.id) is None
    audit = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "appliance.upgrade_image_reclaimed")
        )
    ).scalar_one()
    assert audit.new_value["running_on"] == sorted([a.hostname, b.hostname])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "one_node_lacks_it",
        "scheduled",
        "too_new",
        "no_node_has_it",
        # review finding 3 — written but not committed
        "only_in_inactive_slot",
        "trial_boot",
        # review finding 4 — a node awaiting approval on another version
        "pending_node_on_old_version",
        "never_scheduled_and_a_day_old",
    ],
)
async def test_an_image_still_needed_is_kept(
    db_session: AsyncSession, store: Path, case: str
) -> None:
    image = await _image(db_session, uploaded_at=datetime.now(UTC) if case == "too_new" else _OLD)
    if case != "never_scheduled_and_a_day_old":
        _scheduled_once(db_session, image)
    a = await _node(db_session, free=TOTAL // 2)
    if case not in ("no_node_has_it", "only_in_inactive_slot", "trial_boot"):
        _committed(a)
    if case == "only_in_inactive_slot":
        # The write happened; the node still runs the old version (it rolled
        # back, or the operator never rebooted into it).
        a.installed_appliance_version = "2026.10.01-1"
        a.current_slot = a.durable_default = "slot_a"
        a.slot_b_version = V
    if case == "trial_boot":
        a.installed_appliance_version = V
        a.current_slot = "slot_b"
        a.durable_default = "slot_a"
        a.is_trial_boot = True
    if case == "one_node_lacks_it":
        await _node(db_session, free=TOTAL // 2, installed="2026.10.01-1")
    if case == "pending_node_on_old_version":
        p = await _node(db_session, free=TOTAL // 2, installed="2026.10.01-1")
        p.state = "pending_approval"
    if case == "scheduled":
        a.desired_slot_image_url = (
            f"https://cp/api/v1/appliance/upgrade-images/{image.id}/raw.xz?t=x"
        )
    path = _bytes(store, image)
    await db_session.flush()

    assert await _reclaim(db_session) == []
    assert path.exists()
    assert await db_session.get(ApplianceUpgradeImage, image.id) is not None


@pytest.mark.asyncio
async def test_a_never_scheduled_image_is_reclaimed_after_a_week(
    db_session: AsyncSession, store: Path
) -> None:
    image = await _image(db_session, uploaded_at=_ANCIENT)
    _committed(await _node(db_session, free=TOTAL // 2))
    _bytes(store, image)
    await db_session.flush()
    assert len(await _reclaim(db_session)) == 1


@pytest.mark.asyncio
async def test_a_node_of_another_architecture_does_not_hold_an_image(
    db_session: AsyncSession, store: Path
) -> None:
    image = await _image(db_session, uploaded_at=_OLD, architecture="amd64")
    _scheduled_once(db_session, image)
    _committed(await _node(db_session, free=TOTAL // 2))
    await _node(db_session, free=TOTAL // 2, architecture="arm64")  # never takes amd64
    _bytes(store, image)
    await db_session.flush()
    assert len(await _reclaim(db_session)) == 1


@pytest.mark.asyncio
async def test_a_rolling_run_holds_the_image_until_it_finishes(
    db_session: AsyncSession, store: Path
) -> None:
    """Review finding 1: the run turns ``succeeded`` after the last node's
    state changed; the periodic sweep must still reclaim afterwards."""
    from app.models.system_upgrade import RUN_KINDS, SystemUpgradeRun

    image = await _image(db_session, uploaded_at=_OLD)
    _committed(await _node(db_session, free=TOTAL // 2))
    run = SystemUpgradeRun(
        kind=RUN_KINDS[0],
        target_version=V,
        state="running",
        plan={"slot_image_id": str(image.id)},
    )
    db_session.add(run)
    path = _bytes(store, image)
    await db_session.flush()
    assert await _reclaim(db_session) == []
    assert path.exists()

    run = await db_session.get(SystemUpgradeRun, run.id)
    run.state = "succeeded"
    await db_session.commit()
    assert len(await _reclaim(db_session)) == 1
    assert not path.exists()


def test_the_sweep_is_a_beat_task_not_a_heartbeat_hook() -> None:
    """Review findings 1 + 2."""
    import inspect

    from app.api.v1.appliance import supervisor
    from app.celery_app import celery_app

    assert "reclaim" not in inspect.getsource(supervisor.supervisor_heartbeat)
    entry = celery_app.conf.beat_schedule["appliances-reclaim-upgrade-images"]
    assert entry["task"] == "app.tasks.upgrade_image_reclaim.reclaim_upgrade_images"
    import app.tasks.upgrade_image_reclaim as task_mod

    assert task_mod.reclaim_upgrade_images.name == entry["task"]


@pytest.mark.asyncio
async def test_reclaim_mirror_delete_uses_a_short_timeout(
    db_session: AsyncSession, store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding 2: not the 1800 s upload/download timeout."""
    from app.api.v1.appliance import upgrade_images

    seen: list = []

    async def fake_delete(image_id, *, timeout=None):
        seen.append(timeout)

    monkeypatch.setattr(upgrade_images.settings, "slot_image_mirror_url", "http://mirror")
    monkeypatch.setattr(upgrade_images, "_delete_from_mirror", fake_delete)
    image = await _image(db_session, uploaded_at=_OLD)
    _scheduled_once(db_session, image)
    _committed(await _node(db_session, free=TOTAL // 2))
    await db_session.flush()
    assert len(await _reclaim(db_session)) == 1
    assert len(seen) == 1 and seen[0] is not None and seen[0].read <= 30


@pytest.mark.asyncio
async def test_bytes_go_only_after_the_row_delete_is_committed(
    db_session: AsyncSession, store: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding 5: a leftover file is recoverable, a schedule pointing
    at an image whose bytes vanished is not."""
    from app.api.v1.appliance import upgrade_images
    from app.db import AsyncSessionLocal

    image = await _image(db_session, uploaded_at=_OLD)
    _scheduled_once(db_session, image)
    _committed(await _node(db_session, free=TOTAL // 2))
    _bytes(store, image)
    await db_session.commit()
    row_visible_elsewhere: list[bool] = []
    real = upgrade_images._delete_image_bytes

    async def spy(image_id, **kw):
        async with AsyncSessionLocal() as other:
            row_visible_elsewhere.append(
                await other.get(ApplianceUpgradeImage, image_id) is not None
            )
        await real(image_id, **kw)

    monkeypatch.setattr(upgrade_images, "_delete_image_bytes", spy)
    assert len(await _reclaim(db_session)) == 1
    assert row_visible_elsewhere == [False]


@pytest.mark.asyncio
async def test_reclaim_yields_to_an_in_flight_schedule(
    db_session: AsyncSession, store: Path
) -> None:
    """Review finding 5: a scheduling transaction (holding the catalogue lock
    shared since it resolved the image) or a second replica's sweep makes
    this pass a no-op rather than deleting under it."""
    from app.db import AsyncSessionLocal
    from app.services.appliance.slot_image_target import resolve_slot_image_target

    image = await _image(db_session, uploaded_at=_OLD)
    _scheduled_once(db_session, image)
    _committed(await _node(db_session, free=TOTAL // 2))
    path = _bytes(store, image)
    await db_session.commit()

    async with AsyncSessionLocal() as scheduler:
        await resolve_slot_image_target(scheduler, base_url="https://cp", slot_image_id=image.id)
        # The schedule has not committed yet.
        assert await _reclaim(db_session) == []
        assert path.exists()
        await scheduler.rollback()
    assert len(await _reclaim(db_session)) == 1


@pytest.mark.asyncio
async def test_cluster_node_card_carries_the_finding(db_session: AsyncSession) -> None:
    from app.api.v1.appliance.cluster import (
        HostPartition,
        NodeVitals,
        _merge_supervisor_host_state,
    )

    await _node(db_session, free=TOTAL * 3 // 100, hostname="ddi1")
    await _node(db_session, free=TOTAL // 2, hostname="ddi2")
    await db_session.flush()
    snap = {
        "available": True,
        "nodes": [
            {"name": "ddi1", "disk_pressure": False},
            {"name": "ddi2", "disk_pressure": False},
            {"name": "ddi3", "disk_pressure": True},  # no supervisor reading
        ],
    }
    await _merge_supervisor_host_state(db_session, snap)
    by = {n["name"]: n.get("var_disk_finding") for n in snap["nodes"]}
    assert by["ddi1"]["severity"] == "critical"
    assert by["ddi2"] is None
    assert by["ddi3"]["severity"] == "critical"
    # The response model keeps both, rather than dropping them unseen.
    part = snap["nodes"][0]["host_disk_partitions"][0]
    assert HostPartition(**part).available_bytes == TOTAL * 3 // 100
    assert "var_disk_finding" in NodeVitals.model_fields


@pytest.mark.asyncio
async def test_copilot_fleet_row_carries_var(db_session: AsyncSession) -> None:
    from app.services.ai.tools.appliance import _row_to_dict

    low = await _node(db_session, free=TOTAL * 3 // 100)
    unknown = await _node(db_session, free=None)
    d = _row_to_dict(low)
    assert d["var_free_bytes"] == TOTAL * 3 // 100 and d["var_total_bytes"] == TOTAL
    assert d["var_disk_finding"]["severity"] == "critical"
    d = _row_to_dict(unknown)
    assert d["var_free_bytes"] is None and d["var_disk_finding"] is None


@pytest.mark.asyncio
async def test_cluster_node_card_does_not_judge_a_stale_reading(db_session: AsyncSession) -> None:
    """Review finding 7: same freshness rule as Fleet and the alert."""
    from app.api.v1.appliance.cluster import _merge_supervisor_host_state

    await _node(
        db_session,
        free=TOTAL // 100,
        hostname="old1",
        last_seen=datetime.now(UTC) - timedelta(hours=1),
    )
    await db_session.flush()
    snap = {"available": True, "nodes": [{"name": "old1", "disk_pressure": False}]}
    await _merge_supervisor_host_state(db_session, snap)
    assert snap["nodes"][0].get("var_disk_finding") is None
    assert snap["nodes"][0]["host_disk_partitions"]  # the bars still show

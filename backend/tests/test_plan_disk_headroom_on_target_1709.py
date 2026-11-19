"""A node already running the target is not asked for /var room.

The way out of a failed rolling run is a new Plan to the same target: the
nodes the failed run already upgraded go through the new run's chain without
a reboot and stage nothing (``per_node``: ``mirror_ready`` and ``stage`` skip
a node whose ``installed_appliance_version`` is the target). ``disk_headroom``
still asked those nodes for room to stage the slot image, and an upgrade is
what shrinks a node's /var (it keeps the old slot's images beside the new
ones). ddi-pg's nightly three-node walk on 2026-10-13 (nightly-20261012) left
the run failed with member-1 and the seed on the target at 4.37 and 4.63 GiB
free: a new Plan was refused on exactly those two nodes, and so was every
node's preflight in the chain of the run it would have started.

The contract: Plan, and every node's preflight in a run's chain, judge /var
only on the nodes that will stage the image, i.e. not on a node already
reporting the target. Such nodes are named in ``detail.on_target``. With no
target given, every row is judged, as before.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services.upgrades import preflight

TARGET = "2026.10.13-900"
FROM = "0.0.0-nightly-20261012+0042a7e"
TOTAL = 24_390_250_496  # each node's /var on the walk


async def _node(
    db: AsyncSession, hostname: str, used: int, installed: str, *, seen_ago_s: int = 30
) -> None:
    der = os.urandom(32)
    db.add(
        Appliance(
            id=uuid.uuid4(),
            hostname=hostname,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            installed_appliance_version=installed,
            last_seen_at=datetime.now(UTC) - timedelta(seconds=seen_ago_s),
            cluster_health={
                "host_disk_partitions": [
                    {"mount": "/var", "total_bytes": TOTAL, "used_bytes": used}
                ]
            },
        )
    )


async def _the_walks_failed_state(db: AsyncSession, *, member3_used: int = 15_569_227_776) -> None:
    """The four approved rows when the walk's run had failed (base-read, 20:10Z)."""
    await _node(db, "ddipg-member-1", 19_700_604_928, TARGET)  # 4.37 GiB free
    await _node(db, "ddipg-seed", 19_423_834_112, TARGET)  # 4.63 GiB free
    await _node(db, "ddipg-member-3", member3_used, FROM)  # stranded, 8.22 GiB free
    # A replaced member's row, approved, silent since before the run.
    await _node(db, "ddipg-member-2", 15_734_013_952, FROM, seen_ago_s=7200)
    await db.commit()


def _only_disk_headroom_is_real(monkeypatch: pytest.MonkeyPatch) -> None:
    ok = preflight.PreflightResult(name="x", level="ok", message="fine", detail={})

    def _sync(**_k: Any) -> preflight.PreflightResult:
        return ok

    async def _async(**_k: Any) -> preflight.PreflightResult:
        return ok

    for name in ("check_inflight_conflict", "check_version_path", "check_quorum"):
        monkeypatch.setattr(preflight, name, _sync)
    for name in (
        "check_replication_lag",
        "check_mirror_disk_headroom",
        "check_kea_ha_version_skew",
        "check_powerdns_lmdb_migration",
        "check_etcd_snapshot_freshness",
        "check_pre_upgrade_backup",
    ):
        monkeypatch.setattr(preflight, name, _async)


def _disk(report: preflight.PreflightReport) -> preflight.PreflightResult:
    (result,) = [r for r in report.results if r.name == "disk_headroom"]
    return result


@pytest.mark.asyncio
async def test_a_new_plan_in_the_walks_failed_state_is_not_refused_on_var(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _the_walks_failed_state(db_session)
    _only_disk_headroom_is_real(monkeypatch)

    report = await preflight.run_all(target_version=TARGET)
    disk = _disk(report)

    assert disk.level != "fail", disk.message
    assert report.can_start is True
    assert disk.detail["on_target"] == ["ddipg-member-1", "ddipg-seed"]
    assert [e["node"] for e in disk.detail["nodes"]] == ["ddipg-member-3"]
    # The stale leftover row is still reported, as before.
    assert [e["node"] for e in disk.detail["unverified"]] == ["ddipg-member-2"]


@pytest.mark.asyncio
async def test_the_new_runs_chain_skips_the_nodes_already_on_the_target(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    await _the_walks_failed_state(db_session)
    _only_disk_headroom_is_real(monkeypatch)

    report = await preflight.run_all(
        target_version=TARGET,
        disk_nodes=["ddipg-member-1", "ddipg-member-3", "ddipg-seed"],
    )
    disk = _disk(report)

    assert disk.level == "ok", disk.message
    assert disk.detail["on_target"] == ["ddipg-member-1", "ddipg-seed"]
    assert [e["node"] for e in disk.detail["nodes"]] == ["ddipg-member-3"]


@pytest.mark.asyncio
async def test_a_node_still_to_stage_without_room_still_fails_alone(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    # member-3 at 4.0 GiB free, short of the 5 GiB it needs to stage.
    await _the_walks_failed_state(db_session, member3_used=TOTAL - 4 * 1024**3)
    _only_disk_headroom_is_real(monkeypatch)

    report = await preflight.run_all(target_version=TARGET)
    disk = _disk(report)

    assert disk.level == "fail"
    assert [e["node"] for e in disk.detail["short"]] == ["ddipg-member-3"]
    assert report.can_start is False


@pytest.mark.asyncio
async def test_with_no_target_every_row_is_judged(db_session: AsyncSession) -> None:
    await _the_walks_failed_state(db_session)

    result = await preflight.check_node_disk_headroom()

    assert result.level == "fail"
    assert sorted(e["node"] for e in result.detail["short"]) == ["ddipg-member-1", "ddipg-seed"]

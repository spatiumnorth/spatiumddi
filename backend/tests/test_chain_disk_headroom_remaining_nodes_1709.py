"""A node's preflight judges /var only on the nodes the run has still to upgrade.

``disk_headroom`` (#1234) asks every approved appliance's heartbeat-reported
/var for room to stage the slot image (4 GiB + 1 GiB), and every node's chain
re-runs it. Upgrading a node shrinks its /var (it keeps the old slot's images
beside the new ones), so the run's own progress failed it. ddi-pg's nightly
three-node walk on 2026-10-13 (nightly-20261012): member-1 and the seed done,
at 4.37 and 4.63 GiB free; member-3, the node left to upgrade, at 8.22 GiB.
The chain's preflight for member-3 failed on ``disk_headroom`` and the run
ended with member-3 stranded on the old version.

The contract: Plan still judges every approved appliance; a node's preflight
in the chain judges only the run's nodes still to upgrade (this one and those
after it), so an upgraded node, or an approved row that is not part of the run
(a replaced member's leftover row), is not asked for room the run will never
use there.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services.appliance.slot_image_target import SlotImageTarget
from app.services.upgrades import per_node, preflight

GIB = 1024**3
TOTAL = 24_390_250_496  # each node's /var on the walk


async def _node(db: AsyncSession, hostname: str, used: int, *, seen_ago_s: int = 30) -> None:
    der = os.urandom(32)
    db.add(
        Appliance(
            id=uuid.uuid4(),
            hostname=hostname,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            last_seen_at=datetime.now(UTC) - timedelta(seconds=seen_ago_s),
            cluster_health={
                "host_disk_partitions": [
                    {"mount": "/var", "total_bytes": TOTAL, "used_bytes": used}
                ]
            },
        )
    )


async def _the_walks_fleet(db: AsyncSession) -> None:
    """The four approved rows at 20:10Z (the manager's base-read)."""
    await _node(db, "ddipg-member-1", 19_700_604_928)  # upgraded, 4.37 GiB free
    await _node(db, "ddipg-seed", 19_423_834_112)  # upgraded, 4.63 GiB free
    await _node(db, "ddipg-member-3", 15_569_227_776)  # still to upgrade, 8.22 GiB
    # A replaced member's row, approved, silent since before the run.
    await _node(db, "ddipg-member-2", 15_734_013_952, seen_ago_s=7200)
    await db.commit()


@pytest.mark.asyncio
async def test_plan_still_judges_every_approved_appliance(db_session: AsyncSession) -> None:
    await _the_walks_fleet(db_session)

    result = await preflight.check_node_disk_headroom()

    assert result.level == "fail"
    assert sorted(e["node"] for e in result.detail["short"]) == ["ddipg-member-1", "ddipg-seed"]


@pytest.mark.asyncio
async def test_a_nodes_preflight_judges_only_the_nodes_still_to_upgrade(
    db_session: AsyncSession,
) -> None:
    await _the_walks_fleet(db_session)

    result = await preflight.check_node_disk_headroom(nodes=["DDIPG-Member-3"])

    assert result.level == "ok", result.message
    assert [e["node"] for e in result.detail["nodes"]] == ["ddipg-member-3"]
    assert result.detail["unverified"] == []


@pytest.mark.asyncio
async def test_a_node_still_to_upgrade_without_room_still_fails(
    db_session: AsyncSession,
) -> None:
    await _the_walks_fleet(db_session)

    result = await preflight.check_node_disk_headroom(nodes=["ddipg-member-3", "ddipg-seed"])

    assert result.level == "fail"
    assert [e["node"] for e in result.detail["short"]] == ["ddipg-seed"]


@pytest.mark.asyncio
async def test_nodes_with_no_report_are_unverified_not_judged_by_this_pod(
    db_session: AsyncSession,
) -> None:
    await _the_walks_fleet(db_session)

    result = await preflight.check_node_disk_headroom(nodes=["ddipg-member-9"])

    assert result.level == "warn"
    assert "ddipg-member-9" in result.message


@pytest.mark.asyncio
async def test_the_drive_hands_each_node_the_nodes_still_to_upgrade(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.models.system_upgrade import SystemUpgradeRun
    from app.services.upgrades import orchestrator as orch

    run = SystemUpgradeRun(
        kind="cluster_rolling",
        state="running",
        target_version="2026.10.14-1",
        source_versions={},
        plan={
            "node_order": ["ddipg-member-1", "ddipg-seed", "ddipg-member-3"],
            "slot_image_url": "https://example.test/x.raw.xz",
        },
        progress={"per_node": {"ddipg-member-1": {"ok": True}}, "events": []},
        lease_holder="worker-a",
    )
    db_session.add(run)
    await db_session.commit()
    seen: list[dict[str, Any]] = []

    async def _single(*_a: Any, **kwargs: Any) -> per_node.SingleNodeResult:
        seen.append(kwargs)
        return per_node.SingleNodeResult(
            node_name=kwargs["node_name"],
            target_version=kwargs["target_version"],
            ok=False,
            failed_at="preflight",
            steps=[],
        )

    async def _no_alert(*_a: Any, **_k: Any) -> None:
        return None

    monkeypatch.setattr(orch.per_node, "single_node_upgrade", _single)
    monkeypatch.setattr(orch.upgrade_alerts, "emit_upgrade_failed_alert", _no_alert)
    monkeypatch.setattr(orch.mutex, "release_if_held", lambda **_k: True)
    monkeypatch.delenv("NODE_NAME", raising=False)

    await orch._drive_loop(db_session, run, asyncio.Event())

    assert seen[0]["node_name"] == "ddipg-seed"
    assert seen[0].get("remaining_nodes") == ["ddipg-seed", "ddipg-member-3"]


@pytest.mark.asyncio
async def test_a_nodes_chain_judges_the_nodes_it_was_handed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []

    async def _run_all(**kwargs: Any) -> preflight.PreflightReport:
        calls.append(kwargs)
        return preflight.PreflightReport(
            target_version=kwargs["target_version"],
            current_version="2026.10.13-1",
            overall="fail",
            can_start=False,
            results=[preflight.PreflightResult("disk_headroom", "fail", "stop here", {})],
        )

    monkeypatch.setattr(per_node.preflight, "run_all", _run_all)

    await per_node.single_node_upgrade(
        db_session,
        node_name="ddipg-seed",
        target_version="2026.10.14-1",
        slot_image=SlotImageTarget(url="https://example.test/x.raw.xz"),
        remaining_nodes=["ddipg-seed", "ddipg-member-3"],
    )

    assert calls[0].get("disk_nodes") == ["ddipg-seed", "ddipg-member-3"]

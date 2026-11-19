"""no_lanwide_control_plane_ports conformity check (#285 Phase 5).

FAILs only on a CONFIRMED LAN-wide node; stale / unverified nodes WARN
(unknown, never PASS and never connectivity-FAIL); no reporting node is
not_applicable (#2259).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.services.conformity.checks import (
    STATUS_FAIL,
    STATUS_NOT_APPLICABLE,
    STATUS_PASS,
    STATUS_WARN,
    check_no_lanwide_control_plane_ports,
)

NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


async def _node(
    db: AsyncSession, *, lanwide: bool | None, marker: str | None, last_seen: datetime | None
) -> None:
    der = os.urandom(32)
    db.add(
        Appliance(
            id=uuid.uuid4(),
            hostname=f"n-{uuid.uuid4().hex[:6]}",
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            base_conf_marker=marker,
            base_lanwide_k3s=lanwide,
            last_seen_at=last_seen,
        )
    )
    await db.flush()


async def _run(db: AsyncSession):
    return await check_no_lanwide_control_plane_ports(
        db, target=None, target_kind="platform", args={"stale_minutes": 30}, now=NOW
    )


async def test_non_platform_not_applicable(db_session: AsyncSession) -> None:
    out = await check_no_lanwide_control_plane_ports(
        db_session, target=None, target_kind="subnet", args={}, now=NOW
    )
    assert out.status == STATUS_NOT_APPLICABLE


async def test_empty_is_not_applicable(db_session: AsyncSession) -> None:
    out = await _run(db_session)
    assert out.status == STATUS_NOT_APPLICABLE and out.diagnostic.get("reported") == 0


async def test_confirmed_lanwide_fails(db_session: AsyncSession) -> None:
    await _node(db_session, lanwide=False, marker="a", last_seen=NOW)
    await _node(db_session, lanwide=True, marker="b", last_seen=NOW)
    out = await _run(db_session)
    assert out.status == STATUS_FAIL
    assert len(out.diagnostic["lanwide_hosts"]) == 1


async def test_all_hardened_fresh_pass(db_session: AsyncSession) -> None:
    await _node(db_session, lanwide=False, marker="a", last_seen=NOW)
    await _node(db_session, lanwide=False, marker="b", last_seen=NOW - timedelta(minutes=5))
    out = await _run(db_session)
    assert out.status == STATUS_PASS
    assert "hardened" in out.diagnostic and not out.diagnostic.get("stale")


async def test_stale_hardened_node_warns(db_session: AsyncSession) -> None:
    # A hardened node not seen for >30 min → warn, not PASS and not FAIL.
    await _node(db_session, lanwide=False, marker="a", last_seen=NOW - timedelta(hours=2))
    out = await _run(db_session)
    assert out.status == STATUS_WARN
    assert len(out.diagnostic["stale"]) == 1


async def test_unverified_node_warns(db_session: AsyncSession) -> None:
    # Reported a marker but classification unknown (None) → warn.
    await _node(db_session, lanwide=None, marker="a", last_seen=NOW)
    out = await _run(db_session)
    assert out.status == STATUS_WARN
    assert len(out.diagnostic["unverified"]) == 1

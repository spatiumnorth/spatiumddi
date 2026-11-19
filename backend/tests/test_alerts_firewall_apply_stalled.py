"""firewall.apply_stalled alert matcher (issue #285 Phase 2d).

Fires when a node's control-plane-rendered firewall hash stays un-applied
past the grace window with a clean ``ok`` status — and crucially does NOT
fire on an apply error or a deliberate auto-revert (those own their own
state and would never resolve).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.firewall import FirewallApplyState
from app.models.settings import PlatformSettings
from app.services.alerts import (
    _FIREWALL_STALE_GRACE,
    _matching_firewall_apply_stalled_subjects,
)

_RULE = SimpleNamespace(severity="warning")


async def _appliance(db: AsyncSession, **st_kw: object) -> Appliance:
    # #2794 — the matcher only runs while fleet enforcement is on.
    cfg = await db.get(PlatformSettings, 1)
    if cfg is None:
        cfg = PlatformSettings(id=1)
        db.add(cfg)
    cfg.firewall_enabled = True
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname="cp-1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        last_seen_at=datetime.now(UTC),  # fresh → "host runner is the laggard"
    )
    db.add(a)
    await db.flush()
    db.add(FirewallApplyState(appliance_id=a.id, **st_kw))
    await db.flush()
    return a


async def test_stalls_after_grace(db_session: AsyncSession) -> None:
    a = await _appliance(db_session, rendered_hash="r1", applied_hash="a0", applied_status="ok")
    now = datetime.now(UTC)
    # First observation: stamps the watermark, no match yet.
    assert await _matching_firewall_apply_stalled_subjects(db_session, _RULE, now) == []
    await db_session.flush()
    st = await db_session.get(FirewallApplyState, a.id)
    assert st is not None and st.stalled_since == now

    # Within grace → still no match.
    within = now + _FIREWALL_STALE_GRACE
    assert await _matching_firewall_apply_stalled_subjects(db_session, _RULE, within) == []

    # Past grace → fires, attributed to this appliance at the rule severity.
    past = now + _FIREWALL_STALE_GRACE + timedelta(seconds=1)
    m = await _matching_firewall_apply_stalled_subjects(db_session, _RULE, past)
    assert len(m) == 1
    sid, disp, msg, sev = m[0]
    assert sid == str(a.id) and sev == "warning"
    assert "Firewall drift on cp-1" in msg


async def test_converged_clears_watermark_no_match(db_session: AsyncSession) -> None:
    old = datetime.now(UTC) - timedelta(hours=1)
    a = await _appliance(
        db_session,
        rendered_hash="r1",
        applied_hash="r1",  # converged
        applied_status="ok",
        stalled_since=old,
    )
    m = await _matching_firewall_apply_stalled_subjects(db_session, _RULE, datetime.now(UTC))
    assert m == []
    st = await db_session.get(FirewallApplyState, a.id)
    assert st is not None and st.stalled_since is None  # watermark cleared


async def test_error_status_not_stalled(db_session: AsyncSession) -> None:
    # An apply error is the node's own *applied-error* state, not a stall —
    # and the watermark is cleared so it never alarms here.
    old = datetime.now(UTC) - timedelta(hours=1)
    a = await _appliance(
        db_session,
        rendered_hash="r1",
        applied_hash="a0",
        applied_status="error:apply",
        stalled_since=old,
    )
    m = await _matching_firewall_apply_stalled_subjects(db_session, _RULE, datetime.now(UTC))
    assert m == []
    st = await db_session.get(FirewallApplyState, a.id)
    assert st is not None and st.stalled_since is None


async def test_reverted_status_not_stalled(db_session: AsyncSession) -> None:
    # A deliberate auto-revert (2c) must never alarm — applied_hash !=
    # rendered_hash permanently, so it would otherwise never resolve.
    await _appliance(db_session, rendered_hash="r1", applied_hash="a0", applied_status="reverted")
    far = datetime.now(UTC) + timedelta(days=1)
    assert await _matching_firewall_apply_stalled_subjects(db_session, _RULE, far) == []


async def test_no_rendered_hash_ignored(db_session: AsyncSession) -> None:
    # A node the control plane never rendered for (firewall_enabled off) is
    # not a stall candidate.
    await _appliance(db_session, applied_hash="a0", applied_status="ok")
    far = datetime.now(UTC) + timedelta(days=1)
    assert await _matching_firewall_apply_stalled_subjects(db_session, _RULE, far) == []

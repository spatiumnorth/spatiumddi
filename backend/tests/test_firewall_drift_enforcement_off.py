"""Drift is only meaningful while enforcement is on (#2794).

The heartbeat stores the server's rendered hash only while
``firewall_enabled`` is on. Turning enforcement off used to leave that hash
behind, so ``/effective`` (and the MCP tool, and the apply-stalled alarm)
reported drift forever on any node whose last enforced render differed from
what it had applied. With enforcement off there is no render the node is
expected to match: drift is False, the stale hash is cleared, and turning
enforcement back on starts from a fresh render.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.firewall import FirewallApplyState, FirewallPolicy, FirewallRule
from app.models.settings import PlatformSettings
from app.services.ai.tools import firewall as fw
from app.services.alerts import (
    _FIREWALL_STALE_GRACE,
    _matching_firewall_apply_stalled_subjects,
)
from app.services.appliance.ca import generate_session_token
from app.services.appliance.firewall_merge import reset_policy_cache
from app.services.feature_modules import invalidate_cache

FW = "/api/v1/appliance/firewall"
_SESSION: list[AsyncSession] = []


@pytest.fixture(autouse=True)
def _reset_caches():
    reset_policy_cache()
    invalidate_cache()
    yield
    reset_policy_cache()
    invalidate_cache()


async def _setup(db: AsyncSession, *, enabled: bool) -> tuple[Appliance, str, dict, User]:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    s.supervisor_registration_enabled = True
    s.firewall_enabled = enabled
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="cp-1",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
        session_token_hash=token_hash,
        last_seen_at=datetime.now(UTC),
    )
    db.add(row)
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    p = FirewallPolicy(name="fleet", scope_kind="fleet", enabled=True)
    db.add(p)
    await db.flush()
    db.add(
        FirewallRule(
            policy_id=p.id, seq=10, action="accept", protocol="udp", ports=[514], comment="syslog"
        )
    )
    await db.flush()
    hdr = {"Authorization": f"Bearer {create_access_token(str(u.id))}"}
    return row, token, hdr, u


async def _hb(client: AsyncClient, row: Appliance, token: str, **fields: object) -> dict:
    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token, **fields},
    )
    assert r.status_code == 200, r.text
    return r.json()


async def _eff(client: AsyncClient, row: Appliance, hdr: dict) -> dict:
    # The test client shares one session with the app; the heartbeat's core
    # upsert does not refresh identity-mapped rows (separate sessions in prod).
    _SESSION[0].expunge_all()
    r = await client.get(f"{FW}/appliances/{row.id}/effective", headers=hdr)
    assert r.status_code == 200, r.text
    return r.json()


async def _state(db: AsyncSession, aid: uuid.UUID) -> FirewallApplyState | None:
    db.expunge_all()
    return (
        await db.execute(select(FirewallApplyState).where(FirewallApplyState.appliance_id == aid))
    ).scalar_one_or_none()


async def _set_enforcement(db: AsyncSession, on: bool) -> None:
    s = await db.get(PlatformSettings, 1)
    assert s is not None
    s.firewall_enabled = on
    await db.commit()
    reset_policy_cache()
    invalidate_cache()


async def test_on_then_off_then_on_cycle(client: AsyncClient, db_session: AsyncSession) -> None:
    _SESSION[:] = [db_session]
    row, token, hdr, user = await _setup(db_session, enabled=True)
    await db_session.commit()

    # On, node has not applied the render yet -> real drift.
    await _hb(client, row, token)
    eff = await _eff(client, row, hdr)
    assert eff["rendered_hash"] and eff["drift"] is True

    # On and applied -> converged.
    await _hb(
        client, row, token, firewall_applied_hash=eff["rendered_hash"], firewall_applied_status="ok"
    )
    eff = await _eff(client, row, hdr)
    assert eff["drift"] is False

    # Change the fleet rule: the next render differs from what was applied.
    pol = (await db_session.execute(select(FirewallRule))).scalars().first()
    assert pol is not None
    pol.ports = [515]
    await db_session.commit()
    reset_policy_cache()
    await _hb(client, row, token)
    assert (await _eff(client, row, hdr))["drift"] is True

    # Off: no render is expected of the node -> no drift anywhere, hash cleared.
    await _set_enforcement(db_session, False)
    eff = await _eff(client, row, hdr)
    assert eff["firewall_enabled"] is False
    assert eff["drift"] is False and eff["rendered_hash"] is None
    mcp = await fw.find_firewall_effective(
        db_session, user, fw.FindFirewallEffectiveArgs(appliance_id=str(row.id))
    )
    assert mcp["drift"] is False and mcp["rendered_hash"] is None
    await _hb(client, row, token)
    st = await _state(db_session, row.id)
    assert st is not None and st.rendered_hash is None and st.stalled_since is None
    assert (await _eff(client, row, hdr))["drift"] is False

    # Back on, node still running the old applied ruleset -> drift again.
    await _set_enforcement(db_session, True)
    await _hb(client, row, token)
    eff = await _eff(client, row, hdr)
    assert eff["rendered_hash"] and eff["drift"] is True


async def test_stale_hash_ignored_even_before_next_heartbeat(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The read paths do not depend on a heartbeat having cleared the row."""
    row, token, hdr, user = await _setup(db_session, enabled=False)
    db_session.add(FirewallApplyState(appliance_id=row.id, rendered_hash="r1", applied_hash="a0"))
    await db_session.commit()
    assert (await _eff(client, row, hdr))["drift"] is False
    mcp = await fw.find_firewall_effective(
        db_session, user, fw.FindFirewallEffectiveArgs(appliance_id=str(row.id))
    )
    assert mcp["drift"] is False


async def test_apply_stalled_alarm_silent_when_enforcement_off(db_session: AsyncSession) -> None:
    row, _t, _h, _u = await _setup(db_session, enabled=False)
    db_session.add(
        FirewallApplyState(
            appliance_id=row.id, rendered_hash="r1", applied_hash="a0", applied_status="ok"
        )
    )
    await db_session.flush()
    rule = SimpleNamespace(severity="warning")
    now = datetime.now(UTC)
    await _matching_firewall_apply_stalled_subjects(db_session, rule, now)
    past = now + _FIREWALL_STALE_GRACE + timedelta(seconds=1)
    assert await _matching_firewall_apply_stalled_subjects(db_session, rule, past) == []
    # Control: with enforcement on the same row does fire.
    s = await db_session.get(PlatformSettings, 1)
    assert s is not None
    s.firewall_enabled = True
    await db_session.flush()
    await _matching_firewall_apply_stalled_subjects(db_session, rule, now)
    assert len(await _matching_firewall_apply_stalled_subjects(db_session, rule, past)) == 1

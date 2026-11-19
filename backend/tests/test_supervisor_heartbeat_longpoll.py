"""Supervisor heartbeat long-poll (#358 Phase 1b).

The heartbeat gains an opt-in ``wait_seconds`` that asks the control
plane to hold the response open (Redis-woken) until a per-appliance
desired-state change or a bounded timeout, so operator commands
(upgrade / reboot / role / host-config) start in ~0 s instead of
waiting a full heartbeat interval.

``long_poll`` in the response reports whether the control plane actually
HELD the heartbeat (entered the wake wait), not merely that the
supervisor opted in — the supervisor keys its re-arm cadence off it:
* ``wait_seconds`` omitted (pre-#358 supervisor) → immediate return,
  ``long_poll=False`` (byte-for-byte the old behavior).
* ``wait_seconds`` > 0 but a concrete command is already pending →
  immediate return with ``long_poll=False`` (a pending command is never
  delayed, and the supervisor keeps its normal interval cadence rather
  than re-arming every floor while the intent persists).
* ``wait_seconds`` > 0 and idle → the handler holds, then returns
  ``long_poll=True``. A tiny ``wait_seconds`` keeps the case fast and
  works whether or not Redis is reachable (the wait degrades to a
  bounded sleep when it isn't).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid

from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import appliance_channel, publish_wake
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _enable(db: AsyncSession) -> None:
    s = await db.get(PlatformSettings, 1)
    if s is None:
        s = PlatformSettings(id=1)
        db.add(s)
    # Only /supervisor/register needs the flag since #2798; kept on for parity.
    s.supervisor_registration_enabled = True
    await db.flush()


async def _approved_supervisor(db: AsyncSession) -> tuple[Appliance, str]:
    token, token_hash = generate_session_token()
    der = os.urandom(32)
    row = Appliance(
        id=uuid.uuid4(),
        hostname="agent-longpoll",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        session_token_hash=token_hash,
    )
    db.add(row)
    await db.flush()
    return row, token


async def test_heartbeat_long_poll_off_by_default(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # A supervisor that doesn't send wait_seconds (pre-#358) gets the old
    # immediate-return behavior with long_poll=False — keeps the
    # rolling-upgrade skew window safe.
    await _enable(db_session)
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={"appliance_id": str(row.id), "session_token": token},
    )
    assert r.status_code == 200, r.text
    assert r.json()["long_poll"] is False


async def test_heartbeat_pending_command_returns_immediately_not_held(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # wait_seconds>0 but a concrete pending command (a desired upgrade)
    # short-circuits the hold: the response returns immediately with the
    # desired state AND long_poll=False, so the supervisor does NOT re-arm
    # on the short floor for the whole duration the upgrade intent persists.
    await _enable(db_session)
    row, token = await _approved_supervisor(db_session)
    row.desired_appliance_version = "2026.06.07-1"
    row.desired_slot_image_url = "https://example.invalid/slot.raw.xz"
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(row.id),
            "session_token": token,
            "wait_seconds": 5,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["long_poll"] is False
    assert body["desired_appliance_version"] == "2026.06.07-1"


async def test_heartbeat_holds_when_idle_and_reports_long_poll(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # wait_seconds>0 with nothing pending → the handler actually holds on
    # the wake wait, then returns long_poll=True. A 1 s wait keeps it fast
    # and is Redis-agnostic: with Redis up it times out, with Redis down the
    # wait degrades to a bounded sleep — either way long_poll is True.
    await _enable(db_session)
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()

    r = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(row.id),
            "session_token": token,
            "wait_seconds": 1,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["long_poll"] is True


async def test_heartbeat_wake_shortens_the_hold(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The core feature, end to end: a wake published on the appliance
    # channel while a heartbeat is held returns it EARLY (the cases above
    # only exercise the timeout path). Needs a reachable Redis (present in
    # the dev/test env). wait_seconds=25 vs a ~2 s subscribe delay gives a
    # wide margin, so "returned well under the cap" reliably means the wake
    # delivered rather than the hold timing out.
    await _enable(db_session)
    row, token = await _approved_supervisor(db_session)
    await db_session.commit()
    aid = row.id

    async def _hold() -> Response:
        return await client.post(
            "/api/v1/appliance/supervisor/heartbeat",
            json={"appliance_id": str(aid), "session_token": token, "wait_seconds": 25},
        )

    t0 = time.monotonic()
    task = asyncio.create_task(_hold())
    # Let the handler persist telemetry + subscribe before we wake it — the
    # wake is edge-triggered, so publishing too early would be missed.
    await asyncio.sleep(2.0)
    await publish_wake(appliance_channel(aid))
    r = await task
    elapsed = time.monotonic() - t0

    assert r.status_code == 200, r.text
    assert r.json()["long_poll"] is True
    assert elapsed < 15.0, f"wake did not shorten the hold (took {elapsed:.1f}s)"

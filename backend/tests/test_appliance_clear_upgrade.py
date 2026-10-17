"""#786 — "Clear failed upgrade" has to make the HOST forget, not just the DB.

The red "Upgrade failed" card renders from ``last_upgrade_state`` /
``last_upgrade_progress``, and the heartbeat re-publishes both verbatim
from host sidecar files every ~30 s. Clearing only the ``desired_*``
columns — what the endpoint used to do — left the card up forever, and a
reboot didn't help because those sidecars live on the persistent /var.

So the endpoint now (a) clears our copy for an immediate UI response,
(b) raises a one-shot command telling the supervisor to reset the host,
and (c) drops a heartbeat report that still carries the dismissed
failure. Without (c) the very next heartbeat — collected before the
supervisor ever saw the command — would re-stamp what we just cleared.

The flag is retired on ACKNOWLEDGEMENT: the first heartbeat reporting a
state other than ``failed`` is exactly what a successful host reset
produces, so the command rides every response until the host has actually
complied. A wall-clock window could expire before it was ever delivered.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token


async def _make_superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-786"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _seed_failed_appliance(db: AsyncSession) -> Appliance:
    """An appliance sitting in the state the operator wants to dismiss."""
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:8]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ff" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
        supervisor_version="2026.07.30-1",
        installed_appliance_version="2026.07.21-1",
        desired_appliance_version="2026.07.30-1",
        desired_slot_image_url="https://cp.local/x.raw.xz",
        last_upgrade_state="failed",
        last_upgrade_state_at=datetime.now(UTC),
        last_upgrade_progress={"step": "failed", "pct": 40},
        last_upgrade_log_tail="urllib.error.HTTPError: HTTP Error 404",
    )
    db.add(appliance)
    await db.flush()
    return appliance


@pytest.mark.asyncio
async def test_clear_upgrade_clears_the_visible_failure(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The four columns the failure card reads must go, not just desired_*."""
    headers = await _make_superadmin(db_session)
    appliance = await _seed_failed_appliance(db_session)
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/clear-upgrade", headers=headers
    )
    assert resp.status_code == 200, resp.text

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.last_upgrade_state is None
    assert refreshed.last_upgrade_progress is None
    assert refreshed.last_upgrade_log_tail is None
    assert refreshed.desired_appliance_version is None


@pytest.mark.asyncio
async def test_clear_upgrade_raises_the_host_command(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Clearing our copy is not enough on its own — the host owns this state."""
    headers = await _make_superadmin(db_session)
    appliance = await _seed_failed_appliance(db_session)
    await db_session.commit()

    await client.post(f"/api/v1/appliance/appliances/{appliance.id}/clear-upgrade", headers=headers)

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.clear_upgrade_requested is True
    assert refreshed.clear_upgrade_requested_at is not None


async def _heartbeat_ready(db: AsyncSession) -> tuple[Appliance, str]:
    """An approved supervisor that can post heartbeats."""
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True

    token, token_hash = generate_session_token()
    appliance = await _seed_failed_appliance(db)
    appliance.session_token_hash = token_hash
    await db.flush()
    return appliance, token


@pytest.mark.asyncio
async def test_pending_clear_suppresses_the_stale_heartbeat_report(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The heartbeat racing the clear carries state collected BEFORE the
    supervisor saw the command. Ingesting it would undo the clear — which
    is precisely why the failure used to survive a clear and a reboot.
    """
    appliance, token = await _heartbeat_ready(db_session)
    appliance.clear_upgrade_requested = True
    appliance.clear_upgrade_requested_at = datetime.now(UTC)
    appliance.last_upgrade_state = None
    appliance.last_upgrade_progress = None
    appliance.last_upgrade_log_tail = None
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            # Exactly what a supervisor that hasn't seen the command yet sends.
            "last_upgrade_state": "failed",
            "last_upgrade_state_at": datetime.now(UTC).isoformat(),
            "last_upgrade_progress": {"step": "failed", "pct": 40},
            "last_upgrade_log_tail": "HTTP Error 404",
        },
    )
    assert resp.status_code == 200, resp.text
    # The command rides back so the supervisor can act on it.
    assert resp.json()["clear_upgrade_requested"] is True

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.last_upgrade_state is None, "stale failure must not be re-stamped"
    assert refreshed.last_upgrade_progress is None
    assert refreshed.last_upgrade_log_tail is None


@pytest.mark.asyncio
async def test_pending_clear_does_not_swallow_a_retrys_progress(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Clear-then-retry is the normal recovery gesture. Suppression is
    scoped to the dismissed ``failed`` report, so an upgrade started right
    after the clear still reports its progress."""
    appliance, token = await _heartbeat_ready(db_session)
    appliance.clear_upgrade_requested = True
    appliance.clear_upgrade_requested_at = datetime.now(UTC)
    appliance.last_upgrade_state = None
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "last_upgrade_state": "in-flight",
            "last_upgrade_progress": {"step": "downloading", "pct": 12},
        },
    )
    assert resp.status_code == 200, resp.text

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.last_upgrade_state == "in-flight"
    assert refreshed.last_upgrade_progress == {"step": "downloading", "pct": 12}


@pytest.mark.asyncio
async def test_heartbeat_ingests_normally_once_no_clear_is_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The suppression is scoped to an outstanding clear — the host stays
    the source of truth the rest of the time."""
    appliance, token = await _heartbeat_ready(db_session)
    appliance.clear_upgrade_requested = False
    appliance.last_upgrade_state = None
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "last_upgrade_state": "failed",
        },
    )
    assert resp.status_code == 200, resp.text

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.last_upgrade_state == "failed"


@pytest.mark.asyncio
async def test_expiring_clear_is_delivered_immediately_not_long_polled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The heartbeat that expires the flag still carries the command, so it
    must not be treated as idle and held. A clear also nulls
    ``desired_appliance_version``, so nothing else keeps the request pending
    — reading the post-expiry row here would hold the very response that
    delivers the clear for up to the hold cap."""
    appliance, token = await _heartbeat_ready(db_session)
    appliance.desired_appliance_version = None
    appliance.desired_slot_image_url = None
    appliance.clear_upgrade_requested = True
    appliance.clear_upgrade_requested_at = datetime.now(UTC) - timedelta(seconds=16)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "wait_seconds": 25,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["clear_upgrade_requested"] is True, "the expiring heartbeat still delivers it"
    assert body["long_poll"] is False, "a pending command must not be held"


@pytest.mark.asyncio
async def test_clear_is_retired_by_the_hosts_acknowledgement(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A non-``failed`` report is the ack — that is precisely what a
    successful host reset produces — and it retires the command."""
    appliance, token = await _heartbeat_ready(db_session)
    appliance.clear_upgrade_requested = True
    appliance.clear_upgrade_requested_at = datetime.now(UTC)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "last_upgrade_state": "ready",
        },
    )
    assert resp.status_code == 200, resp.text

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.clear_upgrade_requested is False
    assert refreshed.clear_upgrade_requested_at is None
    # …and the ack itself is ingested, not swallowed: blanket suppression
    # used to drop the host's post-reset ``ready`` and leave the chip blank.
    assert refreshed.last_upgrade_state == "ready"


@pytest.mark.asyncio
async def test_clear_keeps_riding_until_the_host_complies(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The failure this replaces: a stopwatch could retire the command
    before a slow, restarting or offline supervisor ever received it. An
    unacknowledged clear must still be pending, and still be delivered."""
    appliance, token = await _heartbeat_ready(db_session)
    appliance.clear_upgrade_requested = True
    appliance.clear_upgrade_requested_at = datetime.now(UTC) - timedelta(minutes=2)
    # The endpoint nulls these; start from that state so the assertion
    # below proves suppression rather than re-reading the seed.
    appliance.last_upgrade_state = None
    appliance.last_upgrade_progress = None
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "last_upgrade_state": "failed",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["clear_upgrade_requested"] is True

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.clear_upgrade_requested is True, "still unacknowledged"
    assert refreshed.last_upgrade_state is None, "the stale failure stays suppressed"


@pytest.mark.asyncio
async def test_clear_gives_up_on_a_host_that_can_never_comply(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Backstop: a host that cannot unlink a trigger it does not own would
    otherwise pin the flag on forever, permanently suppressing this
    appliance's heartbeat long-poll."""
    appliance, token = await _heartbeat_ready(db_session)
    appliance.clear_upgrade_requested = True
    appliance.clear_upgrade_requested_at = datetime.now(UTC) - timedelta(minutes=11)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/supervisor/heartbeat",
        json={
            "appliance_id": str(appliance.id),
            "session_token": token,
            "last_upgrade_state": "failed",
        },
    )
    assert resp.status_code == 200, resp.text

    refreshed = (
        await db_session.execute(select(Appliance).where(Appliance.id == appliance.id))
    ).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.clear_upgrade_requested is False


# --- #2021: a cancel must not claim to stop an apply the host already began --


async def _seed_scheduled(db: AsyncSession, state: str | None, age_s: int = 5) -> Appliance:
    appliance = await _seed_failed_appliance(db)
    appliance.last_upgrade_state = state
    appliance.last_upgrade_state_at = (
        datetime.now(UTC) - timedelta(seconds=age_s) if state else None
    )
    appliance.last_upgrade_progress = {"step": "downloading", "pct": 10} if state else None
    appliance.last_upgrade_log_tail = None
    await db.flush()
    return appliance


@pytest.mark.asyncio
async def test_cancel_before_the_host_starts_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _make_superadmin(db_session)
    appliance = await _seed_scheduled(db_session, "ready")
    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/clear-upgrade", headers=headers
    )
    assert resp.status_code == 200, resp.text
    await db_session.refresh(appliance)
    assert appliance.desired_appliance_version is None
    assert appliance.clear_upgrade_requested is True


@pytest.mark.asyncio
async def test_cancel_after_the_host_started_is_refused_and_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.models.audit import AuditLog

    headers = await _make_superadmin(db_session)
    appliance = await _seed_scheduled(db_session, "in-flight")
    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/clear-upgrade", headers=headers
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "upgrade_already_started"
    await db_session.refresh(appliance)
    assert appliance.desired_appliance_version == "2026.07.30-1"
    assert appliance.desired_slot_image_url == "https://cp.local/x.raw.xz"
    assert appliance.clear_upgrade_requested is False
    assert appliance.last_upgrade_state == "in-flight"
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_id == str(appliance.id),
                    AuditLog.action == "appliance.upgrade_clear_refused",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1 and rows[0].result == "failed"


@pytest.mark.asyncio
async def test_a_dead_in_flight_stamp_does_not_lock_the_operator_out(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A stale stamp is a dead runner; 'cancel and re-apply' must still work."""
    headers = await _make_superadmin(db_session)
    appliance = await _seed_scheduled(db_session, "in-flight", age_s=900)
    resp = await client.post(
        f"/api/v1/appliance/appliances/{appliance.id}/clear-upgrade", headers=headers
    )
    assert resp.status_code == 200, resp.text

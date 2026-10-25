"""Tests for ``POST /api/v1/appliance/self-register-bootstrap`` (#272 Phase 1).

The endpoint mints a one-shot pairing code for the local supervisor on
full-stack / frontend-core appliances, where the installer wizard
didn't capture a pairing code (the control plane is local). Gates:

* Variant must be ``control-plane`` (or a legacy alias).
* The caller must present the one-time token the local supervisor wrote
  to the host release-state directory. Without it nothing else runs: no
  orphan rows are cleared and the registration gate is not touched.
* The api's host bind-mounted ``role-config:ROLE`` must match.
* No LIVE ``Appliance`` row may exist (``last_seen_at IS NOT NULL``);
  orphan rows from a botched earlier attempt get cleared.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import supervisor as supervisor_mod
from app.models.appliance import Appliance, PairingCode
from app.models.audit import AuditLog
from app.models.settings import PlatformSettings

# ── Helpers ────────────────────────────────────────────────────────


async def _enable_supervisor_registration(db: AsyncSession) -> None:
    stmt = select(PlatformSettings).where(PlatformSettings.id == 1)
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = PlatformSettings(id=1, supervisor_registration_enabled=True)
        db.add(row)
    else:
        row.supervisor_registration_enabled = True
    await db.flush()


@pytest.fixture(autouse=True)
def _no_failure_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(supervisor_mod, "_CONSUME_FAILURE_DELAY_S", 0.0)


@pytest.fixture
def stub_host_role(monkeypatch: pytest.MonkeyPatch):
    """Yields a setter so each test picks the host role independently.

    Production reads from /etc/spatiumddi-host/role-config; tests
    patch ``_read_host_role`` to return the value the test claims
    the host is configured as. Returning ``None`` simulates a
    non-appliance deploy (no bind mount).
    """

    def _set(role: str | None) -> None:
        monkeypatch.setattr(supervisor_mod, "_read_host_role", lambda: role)

    return _set


_TOKEN = "a1" * 32


@pytest.fixture(autouse=True)
def host_token_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The host release-state token file, holding ``_TOKEN``.

    ``raising=False`` so the refusal tests below also run against a build
    that has no token check at all.
    """
    path = tmp_path / "self-bootstrap.token"
    path.write_text(_TOKEN)
    monkeypatch.setattr(supervisor_mod, "_SELF_BOOTSTRAP_TOKEN_FILE", path, raising=False)
    return path


def _body(variant: str, token: str | None = _TOKEN) -> dict:
    body: dict = {"appliance_variant": variant}
    if token is not None:
        body["bootstrap_token"] = token
    return body


# ── Tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_works_without_module_gate_enabled(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # The self-bootstrap endpoint deliberately does NOT honour the
    # ``supervisor_registration_enabled`` gate — the local supervisor
    # MUST be able to register or the appliance is unusable. The
    # gate applies to the public /supervisor/register endpoint only.
    # No PlatformSettings row → gate is off → endpoint still works.
    stub_host_role("full-stack")
    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("full-stack"),
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_happy_path_mints_code(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    await _enable_supervisor_registration(db_session)
    await db_session.commit()
    stub_host_role("full-stack")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("full-stack"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["code"]) == 8
    assert body["code"].isdigit()
    assert body["control_plane_url"].startswith("http://")
    assert "spatium-control-spatiumddi-api" in body["control_plane_url"]
    assert body["expires_in_seconds"] == 600

    # A pairing_code row landed with a 10-min expiry.
    rows = (await db_session.execute(select(PairingCode))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.persistent is False
    assert row.code_last_two == body["code"][-2:]
    assert row.expires_at is not None
    assert row.expires_at - datetime.now(UTC) > timedelta(minutes=9)

    # Audit row written.
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "appliance.self_bootstrap_minted")
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_frontend_core_variant_accepted(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    await _enable_supervisor_registration(db_session)
    await db_session.commit()
    stub_host_role("frontend-core")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("frontend-core"),
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_variant_mismatch_refused(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # Caller claims full-stack but host actually frontend-core.
    # Pretending to be a different variant doesn't let you mint codes
    # for it.
    await _enable_supervisor_registration(db_session)
    await db_session.commit()
    stub_host_role("frontend-core")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("full-stack"),
    )
    assert resp.status_code == 403
    # No pairing code created.
    rows = (await db_session.execute(select(PairingCode))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_no_host_role_config_refused(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # Non-appliance deploy — role-config not mounted. Caller could
    # be anywhere on the cluster; we refuse.
    await _enable_supervisor_registration(db_session)
    await db_session.commit()
    stub_host_role(None)

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("full-stack"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_application_variant_refused(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # Application variant uses the operator-typed pairing-code flow.
    # The endpoint refuses to short-circuit that.
    await _enable_supervisor_registration(db_session)
    await db_session.commit()
    stub_host_role("application")  # contrived — application normally has CONTROL_PLANE_URL filled

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("application"),  # pydantic Literal blocks this
    )
    # Pydantic rejects the unknown literal at validation time → 422.
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_single_shot_after_live_appliance(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # Pre-existing LIVE Appliance row (last_seen_at IS NOT NULL)
    # simulates a control plane that's already registered a
    # heartbeating supervisor — the endpoint refuses 409.
    await _enable_supervisor_registration(db_session)
    db_session.add(
        Appliance(
            hostname="test",
            public_key_der=b"\x00" * 32,
            public_key_fingerprint="a" * 64,
            state="approved",
            last_seen_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    stub_host_role("full-stack")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("full-stack"),
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_orphan_appliance_cleared_on_self_bootstrap(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # Phase 1 audit follow-up — a pre-existing row with
    # ``last_seen_at IS NULL`` is an orphan from a botched earlier
    # self-bootstrap. The endpoint clears it + mints a fresh code
    # so the supervisor can recover without operator intervention.
    await _enable_supervisor_registration(db_session)
    orphan = Appliance(
        hostname="test1",
        public_key_der=b"\x00" * 32,
        public_key_fingerprint="a" * 64,
        state="approved",
        last_seen_at=None,
    )
    db_session.add(orphan)
    await db_session.commit()
    orphan_id = orphan.id
    stub_host_role("full-stack")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("full-stack"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["code"]) == 8
    assert body["control_plane_url"].startswith("http")

    # Orphan row deleted; audit row records the clearance.
    remaining = (await db_session.execute(select(Appliance))).scalars().all()
    assert orphan_id not in {a.id for a in remaining}
    audit_actions = {
        a.action
        for a in (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.resource_id == str(orphan_id))
                )
            )
            .scalars()
            .all()
        )
    }
    assert "appliance.self_bootstrap_orphan_cleared" in audit_actions


# ── Local-caller proof ─────────────────────────────────────────────


async def _assert_nothing_changed(db_session: AsyncSession, orphan_id) -> None:
    """A refused call left the database exactly as it found it."""
    db_session.expire_all()
    assert (await db_session.execute(select(PairingCode))).scalars().all() == []
    remaining = {a.id for a in (await db_session.execute(select(Appliance))).scalars().all()}
    assert orphan_id in remaining
    row = (
        await db_session.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    assert row is None or row.supervisor_registration_enabled is False
    actions = {
        a.action
        for a in (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action.like("appliance.self_bootstrap%"))
            )
        )
        .scalars()
        .all()
    }
    assert actions == set()


async def _seed_unheartbeated_row(db_session: AsyncSession):
    # A row registered but not yet heartbeated — e.g. the real local
    # supervisor between /supervisor/register and its first heartbeat.
    row = Appliance(
        hostname="local-supervisor",
        public_key_der=b"\x01" * 32,
        public_key_fingerprint="b" * 64,
        state="approved",
        last_seen_at=None,
    )
    db_session.add(row)
    await db_session.commit()
    return row.id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        pytest.param(None, id="no-token"),
        pytest.param("", id="empty-token"),
        pytest.param("b2" * 32, id="wrong-token"),
        pytest.param(_TOKEN[:-1], id="truncated-token"),
    ],
)
async def test_caller_without_the_host_token_is_refused_and_changes_nothing(
    db_session: AsyncSession, client: AsyncClient, stub_host_role, token: str | None
) -> None:
    # The variant and the host role are both right — they are public
    # strings — but the caller cannot show the token from the host file.
    orphan_id = await _seed_unheartbeated_row(db_session)
    stub_host_role("control-plane")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("control-plane", token),
    )
    assert resp.status_code == 403, resp.text
    assert "code" not in resp.json()
    await _assert_nothing_changed(db_session, orphan_id)


@pytest.mark.asyncio
async def test_refused_when_the_host_token_file_is_absent(
    db_session: AsyncSession, client: AsyncClient, stub_host_role, host_token_file: Path
) -> None:
    # No attempt in flight (or a non-appliance deploy): even a caller that
    # guesses the old token value gets nothing.
    host_token_file.unlink()
    orphan_id = await _seed_unheartbeated_row(db_session)
    stub_host_role("control-plane")

    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("control-plane"),
    )
    assert resp.status_code == 403, resp.text
    await _assert_nothing_changed(db_session, orphan_id)


@pytest.mark.asyncio
async def test_a_too_short_host_file_never_matches(
    db_session: AsyncSession, client: AsyncClient, stub_host_role, host_token_file: Path
) -> None:
    # An empty or truncated file must not let an equally short claim through.
    host_token_file.write_text("")
    stub_host_role("control-plane")
    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("control-plane", ""),
    )
    assert resp.status_code == 403

    host_token_file.write_text("abc")
    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("control-plane", "abc"),
    )
    assert resp.status_code == 403
    assert (await db_session.execute(select(PairingCode))).scalars().all() == []


@pytest.mark.asyncio
async def test_local_supervisor_with_the_token_mints_and_opens_registration(
    db_session: AsyncSession, client: AsyncClient, stub_host_role
) -> None:
    # The proven caller still gets the full first-boot behaviour: a code
    # that auto-approves, and the registration gate switched on.
    stub_host_role("control-plane")
    resp = await client.post(
        "/api/v1/appliance/self-register-bootstrap",
        json=_body("control-plane"),
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    rows = (await db_session.execute(select(PairingCode))).scalars().all()
    assert len(rows) == 1 and rows[0].auto_approve is True
    settings_row = (
        await db_session.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one()
    assert settings_row.supervisor_registration_enabled is True

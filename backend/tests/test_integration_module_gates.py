"""An integration's feature module is its one switch (#2196, #2197).

Every ``integrations.*`` module used to be shadowed by a
``PlatformSettings.integration_*_enabled`` column, and that column — not the
module — was what the beat sweeps, the Tailscale token alert and the
dashboards gated on. The toggle endpoint mirrored one into the other, so the
two drifted two ways:

* a module turned on before ``PlatformSettings(1)`` existed skipped the
  mirror, and the row was later created with every flag false (#2196);
* Fortinet and Meraki were never in the mirror map, so their periodic sync
  never ran on any install, and four flags were missing from the settings
  API (#2197).

Now every reader asks the module, and the column is a derived copy. These
tests pin both halves: the behaviour (sweeps, alerts, dashboard and the
settings API follow the module, with or without a settings row), and the
structure (every integration module has a mirror entry, a settings-API
field, a gated sweep and a dashboard panel; nothing in the app reads the
columns), so a twelfth integration cannot silently miss one.

The conftest patches every module default to True, so each test writes an
explicit override row rather than relying on the default.
"""

from __future__ import annotations

import importlib
import re
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import Group, Role, User
from app.models.feature_module import FeatureModule
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm_svc

_APP = Path(__file__).resolve().parents[1] / "app"

# Integration module -> the task module whose ``_run_sweep`` it gates.
_SWEEP_TASK: dict[str, str] = {
    "integrations.kubernetes": "kubernetes_sync",
    "integrations.docker": "docker_sync",
    "integrations.proxmox": "proxmox_sync",
    "integrations.tailscale": "tailscale_sync",
    "integrations.unifi": "unifi_sync",
    "integrations.cloud": "cloud_sync",
    "integrations.opnsense": "opnsense_sync",
    "integrations.netbird": "netbird_sync",
    "integrations.paloalto": "panos_sync",
    "integrations.fortinet": "fortinet_sync",
    "integrations.meraki": "meraki_sync",
}

_INTEGRATION_MODULES = sorted(m.id for m in fm_svc.MODULES if m.id.startswith("integrations."))


async def _set_module(db: AsyncSession, module_id: str, enabled: bool) -> None:
    await fm_svc.set_module_enabled(db, module_id, enabled, user_id=None)


async def _commit(db: AsyncSession) -> None:
    await db.commit()
    fm_svc.invalidate_cache()


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"sa-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _settings_editor(db: AsyncSession) -> dict[str, str]:
    """Holds ``write`` on ``settings`` but is not a superadmin."""
    role = Role(
        name=f"settings-editor-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": "write", "resource_type": "settings"}],
    )
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    user = User(
        username=f"ed-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Editor",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=False,
    )
    user.groups = [group]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# ── Behaviour: the sweeps follow the module ─────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("module_id", sorted(_SWEEP_TASK))
async def test_sweep_runs_when_the_module_is_on_and_no_settings_row_exists(
    db_session: AsyncSession, module_id: str
) -> None:
    """#2196 — the exact state the QA node was in, for every integration
    (#2197 — Fortinet and Meraki included)."""
    await _set_module(db_session, module_id, True)
    await _commit(db_session)
    assert await db_session.get(PlatformSettings, 1) is None

    task = importlib.import_module(f"app.tasks.{_SWEEP_TASK[module_id]}")
    result = await task._run_sweep()
    assert result.get("status") != "disabled", (module_id, result)


@pytest.mark.asyncio
@pytest.mark.parametrize("module_id", sorted(_SWEEP_TASK))
async def test_turning_the_module_off_stops_the_sweep_whatever_the_column_says(
    db_session: AsyncSession, module_id: str
) -> None:
    column = fm_svc.INTEGRATION_SETTINGS_MIRROR[module_id]
    db_session.add(PlatformSettings(id=1, **{column: True}))
    await _set_module(db_session, module_id, False)
    await _commit(db_session)

    task = importlib.import_module(f"app.tasks.{_SWEEP_TASK[module_id]}")
    assert await task._run_sweep() == {"status": "disabled"}


@pytest.mark.asyncio
async def test_tailscale_token_refresh_follows_the_module(db_session: AsyncSession) -> None:
    from app.tasks.tailscale_sync import refresh_token_expiry  # noqa: PLC0415

    await _set_module(db_session, "integrations.tailscale", True)
    await _commit(db_session)
    assert await db_session.get(PlatformSettings, 1) is None
    assert (await refresh_token_expiry(db_session)).get("status") != "disabled"


# ── Behaviour: the toggle endpoint ──────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("module_id", ["integrations.fortinet", "integrations.meraki"])
async def test_toggle_on_a_fresh_install_creates_the_row_and_mirrors_it(
    client: AsyncClient, db_session: AsyncSession, module_id: str
) -> None:
    headers = await _superadmin(db_session)
    await _commit(db_session)
    assert await db_session.get(PlatformSettings, 1) is None

    r = await client.patch(
        f"/api/v1/admin/feature-modules/{module_id}", json={"enabled": True}, headers=headers
    )
    assert r.status_code == 200, r.text

    db_session.expire_all()
    ps = await db_session.get(PlatformSettings, 1)
    assert ps is not None
    assert getattr(ps, fm_svc.INTEGRATION_SETTINGS_MIRROR[module_id]) is True

    fm_svc.invalidate_cache()
    task = importlib.import_module(f"app.tasks.{_SWEEP_TASK[module_id]}")
    assert (await task._run_sweep()).get("status") != "disabled"


# ── Behaviour: the settings API ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_settings_reports_all_eleven_flags_from_the_module(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    # Columns deliberately say the OPPOSITE of the modules.
    db_session.add(
        PlatformSettings(
            id=1,
            integration_fortinet_enabled=False,
            integration_meraki_enabled=True,
            integration_tailscale_enabled=False,
        )
    )
    for mid in _INTEGRATION_MODULES:
        await _set_module(db_session, mid, False)
    await _set_module(db_session, "integrations.fortinet", True)
    await _set_module(db_session, "integrations.tailscale", True)
    await _commit(db_session)

    r = await client.get("/api/v1/settings", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    flags = {k: v for k, v in body.items() if re.fullmatch(r"integration_[a-z]+_enabled", k)}
    assert set(flags) == set(fm_svc.INTEGRATION_SETTINGS_MIRROR.values())
    on = {k for k, v in flags.items() if v}
    assert on == {"integration_fortinet_enabled", "integration_tailscale_enabled"}


@pytest.mark.asyncio
async def test_put_settings_switches_the_module_and_round_trips(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    for mid in _INTEGRATION_MODULES:
        await _set_module(db_session, mid, False)
    await _commit(db_session)

    want = {col: (i % 2 == 0) for i, col in enumerate(fm_svc.INTEGRATION_SETTINGS_MIRROR.values())}
    r = await client.put("/api/v1/settings", json=want, headers=headers)
    assert r.status_code == 200, r.text
    assert {k: r.json()[k] for k in want} == want

    r = await client.get("/api/v1/settings", headers=headers)
    assert {k: r.json()[k] for k in want} == want

    db_session.expire_all()
    rows = {
        row.id: row.enabled for row in (await db_session.execute(select(FeatureModule))).scalars()
    }
    ps = await db_session.get(PlatformSettings, 1)
    for col, value in want.items():
        mid = fm_svc.INTEGRATION_FIELD_TO_MODULE[col]
        assert rows[mid] is value, mid
        assert getattr(ps, col) is value, col  # the derived copy followed

    turned_on = {fm_svc.INTEGRATION_FIELD_TO_MODULE[c] for c, v in want.items() if v}
    audited = {
        a.resource_id
        for a in (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "feature_module")
            )
        ).scalars()
    }
    assert turned_on <= audited

    fm_svc.invalidate_cache()
    task = importlib.import_module("app.tasks.meraki_sync")
    expected_meraki = want["integration_meraki_enabled"]
    assert ((await task._run_sweep()).get("status") != "disabled") is expected_meraki


@pytest.mark.asyncio
async def test_a_settings_editor_cannot_switch_an_integration(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _settings_editor(db_session)
    await _set_module(db_session, "integrations.fortinet", False)
    await _commit(db_session)

    r = await client.put(
        "/api/v1/settings", json={"integration_fortinet_enabled": True}, headers=headers
    )
    assert r.status_code == 403, r.text
    db_session.expire_all()
    row = await db_session.get(FeatureModule, "integrations.fortinet")
    assert row is not None and row.enabled is False

    # Echoing the current value back is not a change, so it is allowed —
    # a form that sends the whole object must not 403 on fields it never
    # touched.
    r = await client.put(
        "/api/v1/settings", json={"integration_fortinet_enabled": False}, headers=headers
    )
    assert r.status_code == 200, r.text


# ── Behaviour: the Integrations dashboard ───────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_panels_follow_the_module(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    await _set_module(db_session, "integrations.fortinet", True)
    await _set_module(db_session, "integrations.meraki", False)
    await _commit(db_session)
    assert await db_session.get(PlatformSettings, 1) is None

    r = await client.get("/api/v1/dashboards/integrations/summary", headers=headers)
    assert r.status_code == 200, r.text
    enabled = {p["kind"]: p["enabled"] for p in r.json()["panels"]}
    assert enabled["fortinet"] is True
    assert enabled["meraki"] is False


# ── Behaviour: the startup reconcile of the derived copy ────────────────


@pytest.mark.asyncio
async def test_the_mirror_reconcile_heals_drift_and_is_idempotent(
    db_session: AsyncSession,
) -> None:
    """The state an upgraded #2196 / #2197 install is in: modules on, columns
    false. The reconcile API startup runs must correct it, and a second run
    (every later boot, or a second replica) must change nothing — it writes
    no audit row, so ``False`` is what keeps it from committing every boot."""
    db_session.add(PlatformSettings(id=1))
    for mid in _INTEGRATION_MODULES:
        await _set_module(db_session, mid, False)
    await _set_module(db_session, "integrations.fortinet", True)
    await _set_module(db_session, "integrations.meraki", True)
    await _commit(db_session)

    assert await fm_svc.sync_integration_settings_mirror(db_session) is True
    await _commit(db_session)
    db_session.expire_all()
    ps = await db_session.get(PlatformSettings, 1)
    assert ps is not None
    on = {col for col in fm_svc.INTEGRATION_SETTINGS_MIRROR.values() if getattr(ps, col) is True}
    assert on == {"integration_fortinet_enabled", "integration_meraki_enabled"}

    assert await fm_svc.sync_integration_settings_mirror(db_session) is False


@pytest.mark.asyncio
async def test_the_mirror_reconcile_leaves_a_fresh_install_without_a_row(
    db_session: AsyncSession,
) -> None:
    """Every integration off and no settings row: nothing to copy, so the
    reconcile reports no change and API startup does not commit a row into
    existence."""
    for mid in _INTEGRATION_MODULES:
        await _set_module(db_session, mid, False)
    await _commit(db_session)

    assert await fm_svc.sync_integration_settings_mirror(db_session) is False
    await db_session.rollback()
    assert await db_session.get(PlatformSettings, 1) is None


# ── Structure: a twelfth integration cannot miss a wire ─────────────────


def test_every_integration_module_has_a_mirror_entry_and_nothing_else_does() -> None:
    assert sorted(fm_svc.INTEGRATION_SETTINGS_MIRROR) == _INTEGRATION_MODULES


def test_every_mirror_column_exists_and_every_integration_column_is_mapped() -> None:
    columns = {
        c.name
        for c in PlatformSettings.__table__.columns
        if re.fullmatch(r"integration_[a-z]+_enabled", c.name)
    }
    assert set(fm_svc.INTEGRATION_SETTINGS_MIRROR.values()) == columns


def test_every_integration_flag_is_in_both_settings_schemas() -> None:
    from app.api.v1.settings.router import SettingsResponse, SettingsUpdate  # noqa: PLC0415

    for col in fm_svc.INTEGRATION_SETTINGS_MIRROR.values():
        assert col in SettingsResponse.model_fields, col
        assert col in SettingsUpdate.model_fields, col


def test_every_integration_module_gates_a_sweep_on_itself() -> None:
    sources = "\n".join(p.read_text() for p in (_APP / "tasks").glob("*.py"))
    for mid in _INTEGRATION_MODULES:
        assert f'is_module_enabled(db, "{mid}")' in sources, mid
    assert sorted(_SWEEP_TASK) == _INTEGRATION_MODULES


def test_every_integration_module_has_a_dashboard_panel() -> None:
    from app.api.v1.dashboards.integrations import _PANELS  # noqa: PLC0415

    assert sorted(row[2] for row in _PANELS) == _INTEGRATION_MODULES


def test_nothing_in_the_app_gates_on_the_derived_columns() -> None:
    """The columns are a derived copy. A reader of one is the #2196 bug
    waiting to recur, so only the files that write or serialise it may
    name it."""
    allowed = {
        _APP / "models" / "settings.py",
        _APP / "services" / "feature_modules.py",
        _APP / "api" / "v1" / "settings" / "router.py",
    }
    pattern = re.compile(r"integration_[a-z]+_enabled")
    offenders = [
        str(p.relative_to(_APP))
        for p in _APP.rglob("*.py")
        if p not in allowed and pattern.search(p.read_text())
    ]
    assert offenders == []

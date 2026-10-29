"""A completed nightly upgrade stops being "pending" (#3026).

A nightly's release tag is ``nightly-YYYY.MM.DD`` while the slot it installs
reports ``0.0.0-nightly-YYYYMMDD+<sha>``. The auto-clear compared the two as
strings, so a finished upgrade stayed pending and the supervisor could fire it
again over the rollback slot.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.versions import is_installed_target
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.settings import PlatformSettings
from app.services.appliance.ca import generate_session_token

NIGHTLY = "0.0.0-nightly-20261028+623cc9f"


# Kept identical to CASES in
# agent/supervisor/tests/test_fleet_upgrade_already_installed_3026.py, and
# test_supervisor_copy_agrees runs the supervisor's copy over this list too.
CASES: list[tuple[str | None, str | None, bool]] = [
    # A nightly tag names a night: any build of that night is it.
    (NIGHTLY, "nightly-2026.10.28", True),
    (NIGHTLY, "nightly-20261028", True),
    (NIGHTLY, "0.0.0-nightly-20261028", True),
    (NIGHTLY, " nightly-2026.10.28 ", True),
    ("0.0.0-nightly-20261028", "nightly-2026.10.28", True),
    # A full nightly version names one build: only that build is it.
    (NIGHTLY, NIGHTLY, True),
    (NIGHTLY, "0.0.0-nightly-20261028+deadbee", False),
    (NIGHTLY, "nightly-2026.10.27", False),
    (NIGHTLY, "nightly-2026.10.29", False),
    ("0.0.0-nightly-20261018+4be23dc", "nightly-2026.10.28", False),
    # Not real dates, and malformed tags, never match.
    ("0.0.0-nightly-20261399+623cc9f", "nightly-2026.13.99", False),
    (NIGHTLY, "nightly-2026.10.28-1", False),
    (NIGHTLY, "nightly-2026-10-28", False),
    (NIGHTLY, "nightly", False),
    # Releases: tag == version.
    ("2026.10.03-1", "2026.10.03-1", True),
    ("2026.10.03-1", "2026.10.03-2", False),
    ("1.0.0", "1.0.0", True),
    ("1.0.0", "1.0.1", False),
    ("1.0.0-rc.1", "1.0.0", False),
    # A release tag never matches a nightly, and unknowns never match.
    (NIGHTLY, "2026.10.28-1", False),
    ("2026.10.28-1", "nightly-2026.10.28", False),
    ("dev", "nightly-2026.10.28", False),
    ("nightly-2026.10.28", "nightly-2026.10.28", True),
    (None, "nightly-2026.10.28", False),
    (NIGHTLY, None, False),
    (NIGHTLY, "", False),
    ("", "", False),
]


@pytest.mark.parametrize(("installed", "target", "expected"), CASES)
def test_is_installed_target(installed: str | None, target: str | None, expected: bool) -> None:
    assert is_installed_target(installed, target) is expected


def _supervisor_matcher():  # type: ignore[no-untyped-def]
    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "agent/supervisor/spatium_supervisor/appliance_state.py"
    )
    if not path.exists():
        pytest.skip("agent/supervisor is not in this checkout")
    spec = importlib.util.spec_from_file_location("_sup_appliance_state_3026", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.installed_is_target


def test_supervisor_copy_agrees() -> None:
    """The supervisor carries its own copy (a separate package). The control
    plane deciding "done" while the supervisor decides "fire" is the bug this
    issue was, so both must answer every case the same way."""
    sup = _supervisor_matcher()
    installs = sorted({c[0] for c in CASES if c[0] is not None}) + [None]
    targets = sorted({c[1] for c in CASES if c[1] is not None}) + [None]
    for installed in installs:
        for target in targets:
            assert sup(installed, target) is is_installed_target(installed, target), (
                installed,
                target,
            )


_URL = "/api/v1/appliance/supervisor/heartbeat"


async def _appliance(db: AsyncSession, *, installed: str, desired: str) -> tuple[Appliance, str]:
    settings_row = await db.get(PlatformSettings, 1)
    if settings_row is None:
        settings_row = PlatformSettings(id=1)
        db.add(settings_row)
    settings_row.supervisor_registration_enabled = True
    token, token_hash = generate_session_token()
    appliance = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:8]}",
        state=APPLIANCE_STATE_APPROVED,
        public_key_der=b"fake-key",
        public_key_fingerprint="ff" * 32,
        cert_serial="0000",
        deployment_kind="appliance",
        supervisor_version=installed,
        installed_appliance_version=installed,
        desired_appliance_version=desired,
        desired_slot_image_url="https://cp.local/x.raw.xz",
        session_token_hash=token_hash,
    )
    db.add(appliance)
    await db.commit()
    return appliance, token


async def _beat(client: AsyncClient, db: AsyncSession, a: Appliance, token: str) -> Appliance:
    resp = await client.post(
        _URL,
        json={
            "appliance_id": str(a.id),
            "session_token": token,
            "installed_appliance_version": NIGHTLY,
            "last_upgrade_state": "ready",
        },
    )
    assert resp.status_code == 200, resp.text
    row = (await db.execute(select(Appliance).where(Appliance.id == a.id))).scalar_one()
    await db.refresh(row)
    return row


@pytest.mark.asyncio
async def test_finished_nightly_upgrade_is_cleared(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, token = await _appliance(
        db_session, installed="0.0.0-nightly-20261018+4be23dc", desired="nightly-2026.10.28"
    )
    row = await _beat(client, db_session, a, token)
    assert row.desired_appliance_version is None
    assert row.desired_slot_image_url is None


@pytest.mark.asyncio
async def test_a_genuinely_pending_nightly_upgrade_stays_pending(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    a, token = await _appliance(
        db_session, installed="0.0.0-nightly-20261018+4be23dc", desired="nightly-2026.10.29"
    )
    row = await _beat(client, db_session, a, token)
    assert row.desired_appliance_version == "nightly-2026.10.29"
    assert row.desired_slot_image_url is not None


def test_reclaim_sees_a_committed_nightly() -> None:
    """The reclaim sweep keeps an image while any node still needs it. A
    nightly image's label is its release tag, so a string compare said no
    node had ever committed it and nightly images were never reclaimed."""
    from app.api.v1.appliance.upgrade_images import _node_has_committed

    assert _node_has_committed(NIGHTLY, "slot_b", "slot_b", False, "nightly-2026.10.28")
    # On a trial boot, or still on the old night, the image is still needed.
    assert not _node_has_committed(NIGHTLY, "slot_b", "slot_a", True, "nightly-2026.10.28")
    assert not _node_has_committed(
        "0.0.0-nightly-20261018+4be23dc", "slot_a", "slot_a", False, "nightly-2026.10.28"
    )


@pytest.mark.asyncio
async def test_image_usage_lists_the_nodes_running_a_nightly_image(
    db_session: AsyncSession,
) -> None:
    from app.models.appliance import ApplianceUpgradeImage
    from app.services.appliance.upgrade_image_catalog import image_usage

    a, _token = await _appliance(db_session, installed=NIGHTLY, desired="nightly-2026.10.28")
    a.slot_a_version = "0.0.0-nightly-20261018+4be23dc"
    a.slot_b_version = NIGHTLY
    tonight = ApplianceUpgradeImage(
        filename="tonight.raw.xz",
        size_bytes=1,
        sha256="a" * 64,
        appliance_version="nightly-2026.10.28",
    )
    other = ApplianceUpgradeImage(
        filename="other.raw.xz",
        size_bytes=1,
        sha256="b" * 64,
        appliance_version="nightly-2026.10.27",
    )
    db_session.add_all([tonight, other])
    await db_session.commit()
    usage = await image_usage(db_session, [tonight, other])
    assert usage[tonight.id].installed_on == [a.hostname]
    assert usage[other.id].installed_on == []

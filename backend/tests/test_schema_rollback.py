"""Going back to an older release on a database a newer one migrated (#1227).

Reproduced live on a single-node appliance: after a slot rollback from a
nightly to 2026.09.04-1, the database stayed at the nightly's head, the older
release's migrate Job failed with "Can't locate revision", its api / worker /
beat waited on migrate forever, and the nightly's api kept serving behind the
older UI. Nothing refused the rollback and nothing explained it afterwards.

These pin the guard in front of every path that can move a node backwards,
and the verdict logic under it, against the REAL migration tree: a fixture
tree would pass while the real one's shape (merges, the bundled heads) broke.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import slot as slot_api
from app.config import settings
from app.core import schema_check as schema_module
from app.core.security import create_access_token, hash_password
from app.db import AsyncSessionLocal
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
)
from app.models.auth import User
from app.models.backup import BackupTarget
from app.models.release_schema import ReleaseSchemaHead
from app.services.appliance.slot import SlotStatus
from app.services.upgrades import preflight
from app.services.upgrades import schema_rollback as sr

# The tree's own head, and a revision behind it. ``e6b2d94f1a37`` was the
# head of the nightly amoona6 reproduced from; this change has since been
# re-chained after #1298's migration, so it is further behind, still an
# ancestor.
PREVIOUS_HEAD = "e6b2d94f1a37"
# The release the reproduction rolled back TO, and the head its tree ended at.
OLD_RELEASE = "2026.09.04-1"
OLD_RELEASE_HEAD = "f3b8d21c74ae"


def _head() -> str:
    head, err = schema_module.expected_alembic_head()
    assert err is None and head is not None
    return head


@pytest.fixture(autouse=True)
async def _alembic_version() -> AsyncIterator[None]:
    """The per-worker test DB is built by ``create_all`` and has no
    ``alembic_version``; production does. Stamp it at the tree's head, as a
    database the NEWER release just migrated would be."""
    async with AsyncSessionLocal() as s:
        await s.execute(
            text(
                "CREATE TABLE IF NOT EXISTS alembic_version ("
                "version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
            )
        )
        await s.execute(text("DELETE FROM alembic_version"))
        await s.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:v)"), {"v": _head()}
        )
        await s.commit()
    yield
    async with AsyncSessionLocal() as s:
        await s.execute(text("DROP TABLE IF EXISTS alembic_version"))
        await s.commit()


async def _set_db_revision(revision: str) -> None:
    async with AsyncSessionLocal() as s:
        await s.execute(text("UPDATE alembic_version SET version_num = :v"), {"v": revision})
        await s.commit()


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test Admin",
        hashed_password=hash_password("test-pw-1227"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# ── the verdict, against the real tree ────────────────────────────────


def _judge(**kw: object) -> sr.SchemaRollbackCheck:
    args: dict[str, object] = {
        "target_version": "v",
        "target_head": PREVIOUS_HEAD,
        "head_source": "recorded",
        "database_revision": _head(),
        "script": sr._script_directory(),
    }
    args.update(kw)
    return sr.judge(**args)  # type: ignore[arg-type]


def test_database_ahead_of_the_target_is_incompatible() -> None:
    # The reproduction's shape: the target release was built with a head the
    # database has since moved past.
    check = _judge()
    assert check.verdict == "incompatible"
    assert "Can't locate revision" in check.message


def test_target_ahead_of_the_database_is_compatible() -> None:
    # An ordinary forward move: the target's migrate step upgrades.
    assert _judge(target_head=_head(), database_revision=PREVIOUS_HEAD).verdict == "compatible"


def test_same_revision_is_compatible() -> None:
    assert _judge(target_head=_head()).verdict == "compatible"


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_version": None},
        {"target_head": None, "head_source": None},
        {"database_revision": None},
        {"script": None},
        # A revision this tree has never heard of: this api is itself older
        # than the database, and can say nothing about another release.
        {"database_revision": "aaaa1111bbbb"},
        {"target_head": "aaaa1111bbbb"},
    ],
)
def test_what_cannot_be_judged_is_unknown_never_a_verdict(overrides: dict) -> None:
    # "unknown" must never be read as either answer: refusing on it would
    # block every rollback on an install that recorded nothing, and passing
    # it as "compatible" would claim a fact nobody established.
    assert _judge(**overrides).verdict == "unknown"


def test_the_bundled_table_agrees_with_the_migration_tree() -> None:
    """Every release head in the bundled table is a revision in this tree and
    an ancestor of its head. A generator that read the wrong files, or a table
    copied from another branch, fails here rather than at a rollback."""
    heads = sr._bundled_heads()
    assert heads.get(OLD_RELEASE) == OLD_RELEASE_HEAD
    script = sr._script_directory()
    for version, head in heads.items():
        assert sr._in_tree(script, head), version
        assert sr._descends_from(script, _head(), head), version


def test_the_bundled_table_only_names_releases() -> None:
    path = Path(sr._BUNDLED)
    doc = json.loads(path.read_text())
    assert set(doc) == {"_comment", "releases"}
    for version in doc["releases"]:
        assert not version.startswith(("nightly", "0.0.0")), version


# ── the lookup: bundled first, then recorded ──────────────────────────


@pytest.mark.asyncio
async def test_the_reproduced_rollback_is_refused(db_session: AsyncSession) -> None:
    # 2026.09.04-1 predates the table, so its head comes from the bundled
    # file — which is exactly the release the reproduction rolled back to.
    check = await sr.check_release_can_run(db_session, OLD_RELEASE)
    assert check.verdict == "incompatible"
    assert check.head_source == "bundled"
    assert check.target_head == OLD_RELEASE_HEAD
    assert check.database_revision == _head()


@pytest.mark.asyncio
async def test_the_bundled_table_wins_for_a_release_it_lists(db_session: AsyncSession) -> None:
    """A wrong recorded row must not turn a refusal into a pass (#1300 QA walk):
    the bundled table is generated from the tags, so for a release it lists it
    is the truth."""
    db_session.add(ReleaseSchemaHead(version=OLD_RELEASE, alembic_head=_head()))
    await db_session.commit()
    check = await sr.check_release_can_run(db_session, OLD_RELEASE)
    assert check.head_source == "bundled"
    assert check.verdict == "incompatible"


@pytest.mark.asyncio
async def test_a_recorded_head_answers_for_a_build_no_tag_names(db_session: AsyncSession) -> None:
    nightly = "0.0.0-nightly-20261001+abcdef0"
    db_session.add(ReleaseSchemaHead(version=nightly, alembic_head=_head()))
    await db_session.commit()
    check = await sr.check_release_can_run(db_session, nightly)
    assert check.head_source == "recorded"
    assert check.verdict == "compatible"


@pytest.mark.asyncio
async def test_a_version_nobody_recorded_is_unknown(db_session: AsyncSession) -> None:
    check = await sr.check_release_can_run(db_session, "0.0.0-20260101+abcdef0")
    assert check.verdict == "unknown"


# ── recording ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_record_running_release_upserts_and_skips_unnamed(
    db_session: AsyncSession,
) -> None:
    db_session.add(ReleaseSchemaHead(version="2026.10.06-1", alembic_head="stale"))
    await db_session.commit()
    written = await sr.record_running_release(db_session, ["2026.10.06-1", "dev", "", None, " "])
    assert written == ["2026.10.06-1"]
    rows = (await db_session.execute(select(ReleaseSchemaHead))).scalars().all()
    assert [(r.version, r.alembic_head) for r in rows] == [("2026.10.06-1", _head())]


@pytest.mark.asyncio
async def test_record_this_release_waits_for_head(monkeypatch: pytest.MonkeyPatch) -> None:
    """A release that starts BEHIND its head would record a head it does not
    run at, and a later rollback would trust it."""
    monkeypatch.setattr(settings, "version", "2026.10.06-1")
    await _set_db_revision(PREVIOUS_HEAD)
    await sr.record_this_release()
    async with AsyncSessionLocal() as s:
        assert (await s.get(ReleaseSchemaHead, "2026.10.06-1")) is None

    await _set_db_revision(_head())
    await sr.record_this_release()
    async with AsyncSessionLocal() as s:
        row = await s.get(ReleaseSchemaHead, "2026.10.06-1")
        assert row is not None and row.alembic_head == _head()


def _booted(version: str | None) -> SlotStatus:
    return SlotStatus(
        appliance_mode=True,
        current_slot="slot_a",
        durable_default="slot_a",
        is_trial_boot=False,
        upgrade_state="ready",
        upgrade_state_at=None,
        log_tail="",
        slot_a_version=version,
        slot_b_version="2026.10.06-1",
    )


@pytest.mark.asyncio
async def test_record_this_release_skips_a_booted_slot_that_is_not_this_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The #1300 QA walk: after a rollback to a nightly that cannot migrate,
    the newer release's api keeps running on the nightly's slot. It must not
    record the nightly at its own head, or the next rollback to the nightly
    reads as compatible."""
    import app.services.appliance.slot as slot_module

    nightly = "0.0.0-nightly-20260930+f838ab8"
    monkeypatch.setattr(settings, "version", "2026.10.06-1")
    monkeypatch.setattr(slot_module, "get_slot_status", lambda: _booted(nightly))
    await _set_db_revision(_head())
    await sr.record_this_release()
    async with AsyncSessionLocal() as s:
        assert (await s.get(ReleaseSchemaHead, nightly)) is None
        row = await s.get(ReleaseSchemaHead, "2026.10.06-1")
        assert row is not None and row.alembic_head == _head()


@pytest.mark.asyncio
async def test_record_this_release_records_the_booted_slot_when_it_is_this_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.services.appliance.slot as slot_module

    monkeypatch.setattr(settings, "version", "2026.10.06-1")
    monkeypatch.setattr(slot_module, "get_slot_status", lambda: _booted("2026.10.06-1"))
    await _set_db_revision(_head())
    await sr.record_this_release()
    async with AsyncSessionLocal() as s:
        row = await s.get(ReleaseSchemaHead, "2026.10.06-1")
        assert row is not None and row.alembic_head == _head()


@pytest.mark.asyncio
async def test_record_this_release_records_a_nightly_slot_under_its_slot_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A nightly's images are tagged ``nightly-YYYYMMDD`` (its settings.version)
    while its slot carries ``0.0.0-nightly-YYYYMMDD+<sha>``. The slot name is
    what a rollback looks up, so it must be recorded, or a rollback to any
    nightly reads ``unknown`` and goes through unchecked."""
    import app.services.appliance.slot as slot_module

    nightly = "0.0.0-nightly-20260930+f838ab8"
    monkeypatch.setattr(settings, "version", "nightly-20260930")
    monkeypatch.setattr(slot_module, "get_slot_status", lambda: _booted(nightly))
    await _set_db_revision(_head())
    await sr.record_this_release()
    async with AsyncSessionLocal() as s:
        row = await s.get(ReleaseSchemaHead, nightly)
        assert row is not None and row.alembic_head == _head()


def test_a_nightly_slot_from_another_night_is_not_this_build() -> None:
    assert not sr._slot_is_this_build("0.0.0-nightly-20260929+aaaaaaa", "nightly-20260930")
    assert not sr._slot_is_this_build("0.0.0-nightly-20260930+aaaaaaa", "2026.10.06-1")
    assert sr._slot_is_this_build(" 2026.10.06-1 ", "2026.10.06-1")


# ── the migrate step says what happened ───────────────────────────────


def test_unknown_database_revision_is_explained() -> None:
    msg = "Can't locate revision identified by 'aaaa1111bbbb'"
    explained = schema_module.explain_unknown_revision(msg, ["aaaa1111bbbb"])
    assert explained is not None
    assert explained.startswith(msg)
    assert "NEWER SpatiumDDI release" in explained


def test_a_mistyped_target_is_not_blamed_on_a_newer_release() -> None:
    # `alembic upgrade nosuchrev` raises the same wording; the database is
    # fine and saying otherwise sends the operator the wrong way.
    msg = "Can't locate revision identified by 'nosuchrev'"
    assert schema_module.explain_unknown_revision(msg, [_head()]) is None
    assert schema_module.explain_unknown_revision("some other failure", ["x"]) is None


# ── POST /appliance/slot-upgrade/rollback ─────────────────────────────


def _slots(current: str, a: str | None, b: str | None) -> SlotStatus:
    return SlotStatus(
        appliance_mode=True,
        current_slot=current,  # type: ignore[arg-type]
        durable_default=current,  # type: ignore[arg-type]
        is_trial_boot=False,
        upgrade_state="ready",
        upgrade_state_at=None,
        log_tail="",
        slot_a_version=a,
        slot_b_version=b,
    )


@pytest.fixture
def _rollback_env(monkeypatch: pytest.MonkeyPatch) -> list[str | None]:
    fired: list[str | None] = []
    monkeypatch.setattr(slot_api, "is_apply_in_flight", lambda: False)
    monkeypatch.setattr(slot_api, "can_rollback", lambda: True)
    monkeypatch.setattr(slot_api, "schedule_rollback", lambda t=None: fired.append(t))
    monkeypatch.setattr(
        slot_api, "get_slot_status", lambda: _slots("slot_b", OLD_RELEASE, "0.0.0-new")
    )
    return fired


@pytest.mark.asyncio
async def test_rollback_to_a_release_that_cannot_start_is_refused(
    client: AsyncClient, db_session: AsyncSession, _rollback_env: list[str | None]
) -> None:
    headers = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/appliance/slot-upgrade/rollback", json={"target_slot": None}, headers=headers
    )
    assert r.status_code == 409
    detail = r.json()["detail"]
    # The UI keys its confirmation on this code, not on the prose.
    assert detail["code"] == sr.REFUSAL_CODE
    assert detail["target_version"] == OLD_RELEASE
    assert detail["database_revision"] == _head()
    assert _rollback_env == []  # nothing written to the host


@pytest.mark.asyncio
async def test_acknowledged_rollback_proceeds_and_is_audited(
    client: AsyncClient, db_session: AsyncSession, _rollback_env: list[str | None]
) -> None:
    headers = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/appliance/slot-upgrade/rollback",
        json={"target_slot": "slot_a", "acknowledge_schema_rollback": True},
        headers=headers,
    )
    assert r.status_code == 202, r.text
    assert r.json()["schema_check"]["verdict"] == "incompatible"
    assert _rollback_env == ["slot_a"]


@pytest.mark.asyncio
async def test_rollback_onto_the_running_slot_is_not_judged(
    client: AsyncClient,
    db_session: AsyncSession,
    _rollback_env: list[str | None],
) -> None:
    # Pointing at the slot already running changes nothing about which code
    # meets the database.
    headers = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/appliance/slot-upgrade/rollback", json={"target_slot": "slot_b"}, headers=headers
    )
    assert r.status_code == 202, r.text
    assert r.json()["schema_check"] is None


@pytest.mark.asyncio
async def test_rollback_to_an_unknown_release_proceeds(
    client: AsyncClient,
    db_session: AsyncSession,
    _rollback_env: list[str | None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        slot_api, "get_slot_status", lambda: _slots("slot_b", "0.0.0-old", "0.0.0-new")
    )
    headers = await _superadmin(db_session)
    await db_session.commit()
    r = await client.post(
        "/api/v1/appliance/slot-upgrade/rollback", json={"target_slot": None}, headers=headers
    )
    assert r.status_code == 202, r.text
    assert r.json()["schema_check"]["verdict"] == "unknown"


# ── Fleet: set-next-boot / set-default-slot / upgrade ─────────────────


async def _appliance(
    db: AsyncSession, *, control_plane: bool, old_slot_version: str = OLD_RELEASE
) -> Appliance:
    row = Appliance(
        id=uuid.uuid4(),
        hostname=f"ddi-{uuid.uuid4().hex[:6]}",
        state=APPLIANCE_STATE_APPROVED,
        cluster_role=CLUSTER_ROLE_PRIMARY if control_plane else None,
        public_key_der=b"fake-key",
        public_key_fingerprint=uuid.uuid4().hex * 2,
        cert_serial="0000",
        deployment_kind="appliance",
        current_slot="slot_b",
        slot_a_version=old_slot_version,
        slot_b_version="0.0.0-new",
    )
    db.add(row)
    await db.flush()
    return row


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["set-next-boot", "set-default-slot"])
async def test_fleet_slot_action_onto_an_old_release_is_refused(
    client: AsyncClient, db_session: AsyncSession, action: str
) -> None:
    headers = await _superadmin(db_session)
    row = await _appliance(db_session, control_plane=True)
    await db_session.commit()
    url = f"/api/v1/appliance/appliances/{row.id}/{action}"

    r = await client.post(url, json={"slot": "slot_a"}, headers=headers)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == sr.REFUSAL_CODE

    r = await client.post(
        url, json={"slot": "slot_a", "acknowledge_schema_rollback": True}, headers=headers
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_fleet_commit_of_the_running_slot_is_not_judged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    row = await _appliance(db_session, control_plane=True)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/appliance/appliances/{row.id}/set-default-slot",
        json={"slot": "slot_b"},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_a_data_plane_appliance_is_never_judged(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # Its release never touches the database, so going back is always safe.
    headers = await _superadmin(db_session)
    row = await _appliance(db_session, control_plane=False)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/appliance/appliances/{row.id}/set-next-boot",
        json={"slot": "slot_a"},
        headers=headers,
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_fleet_downgrade_of_a_control_plane_node_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin(db_session)
    row = await _appliance(db_session, control_plane=True)
    await db_session.commit()
    r = await client.post(
        f"/api/v1/appliance/appliances/{row.id}/upgrade",
        json={
            "desired_appliance_version": OLD_RELEASE,
            "desired_slot_image_url": "https://example.invalid/old.raw.xz",
        },
        headers=headers,
    )
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == sr.REFUSAL_CODE
    await db_session.refresh(row)
    assert row.desired_appliance_version is None


# ── preflight: is there a backup to go back to? ───────────────────────


async def _backup_target(db: AsyncSession, *, status: str, age: timedelta) -> None:
    db.add(
        BackupTarget(
            name=f"t-{uuid.uuid4().hex[:6]}",
            kind="local_volume",
            passphrase_encrypted=b"x",
            last_run_status=status,
            last_run_at=datetime.now(UTC) - age,
        )
    )


@pytest.mark.asyncio
async def test_pre_upgrade_backup_does_not_apply_without_appliances() -> None:
    r = await preflight.check_pre_upgrade_backup()
    assert r.level == "ok"
    assert r.detail == {"appliances": 0}


@pytest.mark.asyncio
async def test_pre_upgrade_backup_warns_when_there_is_none(db_session: AsyncSession) -> None:
    await _appliance(db_session, control_plane=True)
    # A target whose NEWEST run failed does not count, even though some
    # earlier run may have succeeded: last_run_* only knows the newest.
    await _backup_target(db_session, status="failed", age=timedelta(hours=1))
    await db_session.commit()
    r = await preflight.check_pre_upgrade_backup()
    assert r.level == "warn"
    assert r.detail["newest_backup_at"] is None


@pytest.mark.asyncio
async def test_pre_upgrade_backup_warns_when_stale_and_passes_when_fresh(
    db_session: AsyncSession,
) -> None:
    await _appliance(db_session, control_plane=True)
    await _backup_target(db_session, status="success", age=timedelta(hours=30))
    await db_session.commit()
    assert (await preflight.check_pre_upgrade_backup()).level == "warn"

    await _backup_target(db_session, status="success", age=timedelta(hours=2))
    await db_session.commit()
    r = await preflight.check_pre_upgrade_backup()
    assert r.level == "ok"
    assert r.detail["age_hours"] == pytest.approx(2, abs=0.1)

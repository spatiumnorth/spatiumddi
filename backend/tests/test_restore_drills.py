"""Restore-verification drills (issue #702).

A drill replays a backup target's newest archive into a throwaway
database and asserts against the result. The tests here cover the
parts that carry real risk if they regress:

* **scratch-database safety** — the one place a bug would replay a
  backup over production. Name generation, the live-name collision
  guard, and the drop-refuses-unprefixed guard;
* **URL derivation** — swapping the database name without losing
  driver, credentials, or query string;
* **verdict rollup** — driven through the real ``_execute``: a skip
  is not a failure, one fail sinks the drill, an unsupported
  ``format_version`` is caught the way the restore path catches it,
  and a preflight failure is ``error`` (says nothing about the
  archive) rather than ``failed``;
* **the alert matcher** — subject is the target (not the run), only
  the latest *finished* drill counts, ``error`` deliberately does not
  mask the previous verdict, targets without scheduled drills never
  match (or the event could never resolve), and an empty destination
  gets its own wording;
* **the readiness rollup** — a transient ``error`` does not erase a
  prior pass, a later failure supersedes one, and the REST endpoint
  and the Copilot tool return byte-identical answers;
* **mutex recovery** — a stranded ``in_progress`` flag must not lock
  a target out of manual drills forever;
* **audit** — scheduled drills are audited too, not just manual ones;
* **RBAC** — the whole surface is superadmin-only.

Nothing here talks to a real destination or spawns psql: the parts
that do are thin subprocess wrappers, and the logic worth pinning
down sits either side of them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertEvent, AlertRule
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.backup import BackupTarget, RestoreDrill
from app.services.alerts import (
    RULE_TYPE_RESTORE_DRILL_FAILED,
    _matching_restore_drill_failed_subjects,
)
from app.services.backup.drill import (
    FAIL,
    PASS,
    SCRATCH_DB_PREFIX,
    SKIP,
    Assertion,
    DrillError,
    _scratch_db_name,
    _scratch_url,
)


async def _make_user(
    db: AsyncSession,
    *,
    superadmin: bool = True,
    username: str = "drilladmin",
) -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_target(
    db: AsyncSession,
    *,
    name: str = "vault",
    drill_enabled: bool = True,
) -> BackupTarget:
    """A backup target with drills scheduled by default.

    Scheduled is the case most of these tests are about, and the alert
    matcher deliberately only considers targets that have drills turned
    on — pass ``drill_enabled=False`` to exercise that boundary.
    """
    target = BackupTarget(
        name=name,
        description="",
        kind="local_volume",
        enabled=True,
        config={"path": "/var/lib/spatiumddi/backups"},
        passphrase_encrypted=encrypt_str("hunter2hunter2"),
        drill_enabled=drill_enabled,
        drill_cron="0 5 * * 0" if drill_enabled else None,
    )
    db.add(target)
    await db.flush()
    return target


async def _make_drill(
    db: AsyncSession,
    target: BackupTarget,
    *,
    state: str,
    started_at: datetime,
    assertions: list[dict[str, object]] | None = None,
) -> RestoreDrill:
    drill = RestoreDrill(
        target_id=target.id,
        state=state,
        triggered_by="schedule",
        filename="spatiumddi-backup-20260724.zip",
        assertions=assertions if assertions is not None else [],
        started_at=started_at,
        finished_at=started_at + timedelta(seconds=30),
    )
    db.add(drill)
    await db.flush()
    return drill


# ── scratch database safety ───────────────────────────────────────────


def test_scratch_db_name_is_prefixed_and_unique() -> None:
    first = _scratch_db_name("spatiumddi")
    second = _scratch_db_name("spatiumddi")
    assert first.startswith(SCRATCH_DB_PREFIX)
    assert second.startswith(SCRATCH_DB_PREFIX)
    assert first != second, "scratch names must not collide between drills"


def test_scratch_db_name_refuses_to_match_the_live_database(monkeypatch) -> None:
    """The guard that stops a drill replaying over production.

    The name is random, so the collision has to be forced: pin the
    token and hand in the live name it would produce. Contrived — the
    prefix makes a real collision essentially impossible — but this is
    the one failure whose blast radius is the whole install, so it is
    asserted rather than assumed.
    """
    from app.services.backup import drill as drill_mod

    monkeypatch.setattr(drill_mod.secrets_mod, "token_hex", lambda _n: "deadbeef")
    colliding_live_name = f"{SCRATCH_DB_PREFIX}deadbeef"
    with pytest.raises(DrillError, match="collided with the live database"):
        _scratch_db_name(colliding_live_name)
    # Sanity: the same pinned token against a normal live name is fine.
    assert _scratch_db_name("spatiumddi") == colliding_live_name


def test_scratch_url_swaps_only_the_database_name() -> None:
    url = _scratch_url(
        "postgresql+asyncpg://spatium:pw@db.internal:5432/spatiumddi",
        "spatiumddi_drill_abc123",
    )
    assert url == "postgresql+asyncpg://spatium:pw@db.internal:5432/spatiumddi_drill_abc123"


def test_scratch_url_preserves_query_string() -> None:
    """A TLS-required deployment carries ``?ssl=require``; dropping it
    would make the drill fail to connect for reasons that have
    nothing to do with the archive."""
    url = _scratch_url(
        "postgresql+asyncpg://spatium:pw@db:5432/spatiumddi?ssl=require",
        "spatiumddi_drill_deadbe",
    )
    assert url.endswith("/spatiumddi_drill_deadbe?ssl=require")


@pytest.mark.asyncio
async def test_drop_scratch_db_refuses_unprefixed_name(monkeypatch) -> None:
    """``_drop_scratch_db`` must never issue DROP against a name it
    didn't generate, whatever the caller passes."""
    from app.services.backup import drill as drill_mod

    issued: list[str] = []

    async def _spy(sql: str, **kwargs: object) -> None:
        issued.append(sql)

    monkeypatch.setattr(drill_mod, "_run_maintenance_sql", _spy)
    await drill_mod._drop_scratch_db("spatiumddi", live_db_url="postgresql://x/y")
    assert issued == [], "refused to drop a database outside the drill prefix"

    await drill_mod._drop_scratch_db(f"{SCRATCH_DB_PREFIX}abc123", live_db_url="postgresql://x/y")
    assert len(issued) == 1
    assert SCRATCH_DB_PREFIX in issued[0]


# ── verdict rollup ────────────────────────────────────────────────────


class _FakeDriver:
    """Stands in for a destination driver. No network, no disk."""

    def __init__(self, *, archives: list[Any] | None = None, payload: bytes = b"zip") -> None:
        self._archives = archives if archives is not None else [_listing("newest.zip")]
        self._payload = payload
        self.max_bytes_seen: list[int | None] = []

    async def list_archives(self, *, config: dict[str, Any]) -> list[Any]:
        return self._archives

    async def download(
        self, *, config: dict[str, Any], filename: str, max_bytes: int | None = None
    ) -> bytes:
        from app.services.backup.targets.base import ArchiveTooLargeError

        self.max_bytes_seen.append(max_bytes)
        if max_bytes is not None and len(self._payload) > max_bytes:
            raise ArchiveTooLargeError(filename, max_bytes)
        return self._payload


def _listing(filename: str, *, when: datetime | None = None) -> Any:
    from app.services.backup.targets.base import ArchiveListing

    return ArchiveListing(
        filename=filename,
        size_bytes=1234,
        created_at=when or datetime.now(UTC),
    )


def _wire_drill(
    monkeypatch,
    *,
    assertions: list[Assertion],
    driver: _FakeDriver | None = None,
    manifest: dict[str, Any] | None = None,
) -> None:
    """Point ``_execute`` at fakes for everything external.

    Leaves the verdict rollup, the format-version gate and the
    ordering of phases as the real code — those are what the tests
    using this actually exercise.
    """
    from app.services.backup import drill as drill_mod

    monkeypatch.setattr(drill_mod, "get_destination", lambda kind: driver or _FakeDriver())
    monkeypatch.setattr(drill_mod, "decrypt_config_secrets", lambda d, c: c)
    monkeypatch.setattr(drill_mod, "decrypt_str", lambda b: "passphrase")
    monkeypatch.setattr(drill_mod, "decrypt_secrets", lambda blob, passphrase: {"SECRET_KEY": "x"})
    monkeypatch.setattr(
        drill_mod,
        "extract_archive_members",
        lambda b: (
            manifest if manifest is not None else {"format_version": 2},
            b"dump",
            "custom",
            b"enc",
        ),
    )

    async def _noop(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(drill_mod, "preflight", _noop)
    monkeypatch.setattr(drill_mod, "_create_scratch_db", _noop)
    monkeypatch.setattr(drill_mod, "_drop_scratch_db", _noop)
    monkeypatch.setattr(drill_mod, "_replay_into_scratch", _noop)

    async def _assertions(_url: str) -> list[Assertion]:
        return assertions

    monkeypatch.setattr(drill_mod, "_assert_against_scratch", _assertions)


@pytest.mark.asyncio
async def test_skip_does_not_fail_the_drill(monkeypatch) -> None:
    """A skipped check (schema skew makes it unanswerable) is not a
    finding — only an actual ``fail`` is.

    Exercises the real rollup in ``_execute`` rather than
    re-implementing the ``any(status == FAIL)`` expression inline: a
    flipped rollup has to fail this test.
    """
    from app.services.backup.drill import _execute

    _wire_drill(
        monkeypatch,
        assertions=[Assertion("audit_chain_intact", SKIP, "schema skew")],
    )
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.state == "passed"
    assert {a.status for a in outcome.assertions} == {PASS, SKIP}


@pytest.mark.asyncio
async def test_one_failed_check_fails_the_drill(monkeypatch) -> None:
    from app.services.backup.drill import _execute

    _wire_drill(
        monkeypatch,
        assertions=[
            Assertion("core_tables_populated", PASS, "ok"),
            Assertion("audit_chain_intact", FAIL, "3 breaks"),
        ],
    )
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.state == "failed"


@pytest.mark.asyncio
async def test_unsupported_format_version_fails_the_drill(monkeypatch) -> None:
    """The real restore path refuses an archive whose format_version it
    doesn't know. A drill that waved it through would report an
    unrestorable archive as restorable — the exact failure this
    feature exists to catch."""
    from app.services.backup.drill import _execute

    _wire_drill(
        monkeypatch,
        assertions=[Assertion("core_tables_populated", PASS, "ok")],
        manifest={"format_version": 99},
    )
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.state == "failed"
    readable = [a for a in outcome.assertions if a.name == "archive_readable"]
    assert readable and readable[0].status == FAIL
    assert "99" in readable[0].detail


@pytest.mark.asyncio
async def test_preflight_failure_is_error_not_failed(monkeypatch) -> None:
    """A missing CREATEDB privilege says nothing about the archive, so
    it must not read as a failed backup."""
    from app.services.backup import drill as drill_mod
    from app.services.backup.drill import DrillError, _execute

    async def _boom(**kwargs: Any) -> None:
        raise DrillError("role lacks CREATEDB")

    monkeypatch.setattr(drill_mod, "preflight", _boom)
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.state == "error"
    assert outcome.error is not None and "CREATEDB" in outcome.error
    assert outcome.assertions == [], "nothing was checked, so nothing should be claimed"


@pytest.mark.asyncio
async def test_newest_archive_is_the_one_drilled(monkeypatch) -> None:
    now = datetime.now(UTC)
    driver = _FakeDriver(
        archives=[
            _listing("older.zip", when=now - timedelta(days=3)),
            _listing("newest.zip", when=now),
            _listing("middle.zip", when=now - timedelta(days=1)),
        ]
    )
    _wire_drill(monkeypatch, assertions=[], driver=driver)
    from app.services.backup.drill import _execute

    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.filename == "newest.zip"


@pytest.mark.asyncio
async def test_drill_download_passes_the_archive_cap(monkeypatch) -> None:
    """The drill asks the driver to stop at the archive cap, so an archive
    whose listing understates its size is not read into memory whole."""
    from app.services.backup.archive import MAX_ARCHIVE_BYTES
    from app.services.backup.drill import _execute

    driver = _FakeDriver()
    _wire_drill(
        monkeypatch, assertions=[Assertion("core_tables_populated", PASS, "ok")], driver=driver
    )
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.state == "passed"
    assert driver.max_bytes_seen == [MAX_ARCHIVE_BYTES]


@pytest.mark.asyncio
async def test_drill_reports_an_archive_past_the_cap_as_error(monkeypatch) -> None:
    """A listing that declares a small size for an archive the driver then
    finds past the cap ends the drill as an error naming the cap, not as a
    failed backup."""
    from app.services.backup import drill as drill_mod
    from app.services.backup.drill import _execute
    from app.services.backup.targets.base import ArchiveListing

    monkeypatch.setattr(drill_mod, "MAX_ARCHIVE_BYTES", 2)
    understated = ArchiveListing(filename="newest.zip", size_bytes=1, created_at=datetime.now(UTC))
    driver = _FakeDriver(archives=[understated], payload=b"zip")
    _wire_drill(monkeypatch, assertions=[], driver=driver)
    target = BackupTarget(name="t", kind="local_volume", config={}, passphrase_encrypted=b"x")
    outcome = await _execute(target, live_db_url="postgresql+asyncpg://u:p@h:5432/live")
    assert outcome.state == "error"
    assert outcome.error is not None and "cap" in outcome.error


def test_assertion_serialises_for_jsonb() -> None:
    a = Assertion("core_tables_populated", PASS, "user=3, alembic_version=1")
    assert a.as_dict() == {
        "name": "core_tables_populated",
        "status": "pass",
        "detail": "user=3, alembic_version=1",
    }


# ── alert matcher ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alert_matches_target_whose_latest_drill_failed(
    db_session: AsyncSession,
) -> None:
    target = await _make_target(db_session, name="failing-vault")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="passed", started_at=now - timedelta(days=2))
    await _make_drill(
        db_session,
        target,
        state="failed",
        started_at=now,
        assertions=[{"name": "passphrase_opens_secrets", "status": "fail", "detail": "bad key"}],
    )
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    matches = await _matching_restore_drill_failed_subjects(db_session, rule)
    assert len(matches) == 1
    subject_id, display, message = matches[0]
    assert subject_id == str(target.id)
    assert display == "failing-vault"
    # The failed check name belongs in the message — an operator
    # paged at 03:00 shouldn't have to open the UI to learn what broke.
    assert "passphrase_opens_secrets" in message


@pytest.mark.asyncio
async def test_alert_clears_when_latest_drill_passes(db_session: AsyncSession) -> None:
    target = await _make_target(db_session, name="recovered-vault")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="failed", started_at=now - timedelta(days=1))
    await _make_drill(db_session, target, state="passed", started_at=now)
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    assert await _matching_restore_drill_failed_subjects(db_session, rule) == []


@pytest.mark.asyncio
async def test_error_drill_does_not_mask_the_previous_verdict(
    db_session: AsyncSession,
) -> None:
    """An unreachable destination says nothing about the archive.

    A later ``error`` must not resolve an open event opened by an
    earlier ``failed`` — we know no more than we did before, and
    silently clearing would be the dangerous reading.
    """
    target = await _make_target(db_session, name="flaky-vault")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="failed", started_at=now - timedelta(hours=2))
    await _make_drill(db_session, target, state="error", started_at=now)
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    matches = await _matching_restore_drill_failed_subjects(db_session, rule)
    assert len(matches) == 1, "the earlier failure still stands"


@pytest.mark.asyncio
async def test_running_drill_neither_opens_nor_resolves(db_session: AsyncSession) -> None:
    target = await _make_target(db_session, name="busy-vault")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="failed", started_at=now - timedelta(hours=2))
    await _make_drill(db_session, target, state="running", started_at=now)
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    matches = await _matching_restore_drill_failed_subjects(db_session, rule)
    assert len(matches) == 1, "an in-flight drill hasn't given a verdict yet"


@pytest.mark.asyncio
async def test_one_subject_per_target_not_per_failed_drill(
    db_session: AsyncSession,
) -> None:
    """A target failing nightly holds one open event, not one per run."""
    target = await _make_target(db_session, name="nightly-fail")
    now = datetime.now(UTC)
    for days in range(4):
        await _make_drill(db_session, target, state="failed", started_at=now - timedelta(days=days))
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    matches = await _matching_restore_drill_failed_subjects(db_session, rule)
    assert len(matches) == 1


@pytest.mark.asyncio
async def test_target_never_drilled_does_not_match(db_session: AsyncSession) -> None:
    await _make_target(db_session, name="undrilled")
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    assert await _matching_restore_drill_failed_subjects(db_session, rule) == []


# ── API surface ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_drills_requires_superadmin(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, superadmin=False, username="plainuser")
    res = await client.get("/api/v1/backup/drills", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_list_drills_returns_target_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, username="drilllist")
    target = await _make_target(db_session, name="listable")
    await _make_drill(db_session, target, state="passed", started_at=datetime.now(UTC))
    res = await client.get("/api/v1/backup/drills", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 1
    assert body[0]["target_name"] == "listable"
    assert body[0]["state"] == "passed"


@pytest.mark.asyncio
async def test_list_drills_filters_by_state(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, username="drillfilter")
    target = await _make_target(db_session, name="mixed")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="passed", started_at=now - timedelta(hours=1))
    await _make_drill(db_session, target, state="failed", started_at=now)
    res = await client.get(
        "/api/v1/backup/drills?state=failed",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert [d["state"] for d in res.json()] == ["failed"]


@pytest.mark.asyncio
async def test_get_missing_drill_404s(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, username="drill404")
    res = await client.get(
        f"/api/v1/backup/drills/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_run_drill_rejects_when_one_is_already_running(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, username="drillbusy")
    target = await _make_target(db_session, name="already-busy")
    target.drill_last_status = "in_progress"
    # Stamped just now, so the staleness escape correctly does NOT
    # apply and the 409 stands.
    target.drill_last_at = datetime.now(UTC)
    await db_session.flush()
    res = await client.post(
        f"/api/v1/backup/drills/run/{target.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 409


# ── target schedule validation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_enabling_drills_without_a_cron_is_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """``drill_enabled`` with no schedule would never fire — a silent
    no-op the operator would read as "drills are on"."""
    _, token = await _make_user(db_session, username="drillcron")
    target = await _make_target(db_session, name="no-cron", drill_enabled=False)
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        json={"drill_enabled": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422
    assert "drill_cron" in res.json()["detail"]


@pytest.mark.asyncio
async def test_setting_drill_cron_stamps_next_run(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, username="drillsched")
    target = await _make_target(db_session, name="scheduled")
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        json={"drill_enabled": True, "drill_cron": "0 5 * * 0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["drill_enabled"] is True
    assert body["drill_cron"] == "0 5 * * 0"
    assert body["drill_next_run_at"] is not None


@pytest.mark.asyncio
async def test_clearing_drill_cron_clears_next_run(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, username="drillclear")
    target = await _make_target(db_session, name="clearable")
    target.drill_enabled = True
    target.drill_cron = "0 5 * * 0"
    target.drill_next_run_at = datetime.now(UTC) + timedelta(days=1)
    await db_session.flush()
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        json={"drill_enabled": False, "drill_cron": None},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert res.json()["drill_next_run_at"] is None


@pytest.mark.asyncio
async def test_invalid_drill_cron_is_rejected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session, username="drillbadcron")
    target = await _make_target(db_session, name="bad-cron")
    res = await client.patch(
        f"/api/v1/backup/targets/{target.id}",
        json={"drill_cron": "not a cron"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 422


# ── sweep mutex ───────────────────────────────────────────────────────


def test_stale_mutex_detection() -> None:
    """A worker killed mid-drill leaves ``in_progress`` behind; without
    the staleness escape the target would stop drilling forever."""
    from app.services.backup.drill import (
        STALE_IN_PROGRESS_SECONDS,
        drill_mutex_is_stale,
    )

    now = datetime.now(UTC)
    target = BackupTarget(
        name="x",
        kind="local_volume",
        config={},
        passphrase_encrypted=b"",
        drill_last_status="in_progress",
    )

    target.drill_last_at = now - timedelta(seconds=30)
    assert drill_mutex_is_stale(target, now) is False, "a drill running 30s ago is genuinely held"

    target.drill_last_at = now - timedelta(seconds=STALE_IN_PROGRESS_SECONDS + 60)
    assert drill_mutex_is_stale(target, now) is True

    target.drill_last_at = None
    assert drill_mutex_is_stale(target, now) is True, "never stamped reads as stale"


# ── MCP tools ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_find_restore_drills_gated_to_superadmin(db_session: AsyncSession) -> None:
    from app.services.ai.tools.backup import FindRestoreDrillsArgs, find_restore_drills

    user, _ = await _make_user(db_session, superadmin=False, username="mcpplain")
    rows = await find_restore_drills(db_session, user, FindRestoreDrillsArgs())
    assert len(rows) == 1
    assert "error" in rows[0]


@pytest.mark.asyncio
async def test_readiness_reports_undrilled_target_as_unverified(
    db_session: AsyncSession,
) -> None:
    """Drills off must not read as healthy — an untested backup is an
    unknown, not a pass."""
    from app.services.ai.tools.backup import (
        RestoreDrillReadinessArgs,
        get_restore_drill_readiness,
    )

    user, _ = await _make_user(db_session, username="mcpready")
    await _make_target(db_session, name="never-drilled", drill_enabled=False)
    out = await get_restore_drill_readiness(db_session, user, RestoreDrillReadinessArgs())
    assert out["total_targets"] == 1
    assert out["verified_targets"] == 0
    assert out["unverified_targets"] == 1
    row = out["targets"][0]
    assert row["verified"] is False
    assert row["drills_scheduled"] is False
    assert row["last_passed_at"] is None


@pytest.mark.asyncio
async def test_readiness_reports_hours_since_last_pass(db_session: AsyncSession) -> None:
    from app.services.ai.tools.backup import (
        RestoreDrillReadinessArgs,
        get_restore_drill_readiness,
    )

    user, _ = await _make_user(db_session, username="mcpaged")
    target = await _make_target(db_session, name="aged")
    target.drill_last_status = "passed"
    await _make_drill(
        db_session,
        target,
        state="passed",
        started_at=datetime.now(UTC) - timedelta(hours=48),
    )
    out = await get_restore_drill_readiness(db_session, user, RestoreDrillReadinessArgs())
    row = out["targets"][0]
    assert row["verified"] is True
    assert row["hours_since_last_pass"] is not None
    assert 47 <= row["hours_since_last_pass"] <= 49


# ── seed rule ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_seed_rule_is_idempotent(monkeypatch) -> None:
    """Seeding twice must not produce two rules.

    The seeder keys on ``rule_type``, which is what lets an operator
    rename or disable the rule without a restart undoing it. Uses a
    stub session because the real seeder opens ``AsyncSessionLocal``
    against the live database rather than the test session.
    """
    from app.services import alerts as alerts_mod

    class _Session:
        def __init__(self, existing: object | None) -> None:
            self._existing = existing
            self.added: list[Any] = []
            self.committed = False

        async def scalar(self, *args: Any, **kwargs: Any) -> Any:
            return self._existing

        def add(self, obj: Any) -> None:
            self.added.append(obj)

        async def commit(self) -> None:
            self.committed = True

        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

    first = _Session(existing=None)
    monkeypatch.setattr("app.db.AsyncSessionLocal", lambda: first)
    await alerts_mod.seed_restore_drill_failed_alert_rule()
    assert len(first.added) == 1
    assert first.committed is True
    seeded = first.added[0]
    assert seeded.rule_type == RULE_TYPE_RESTORE_DRILL_FAILED
    assert seeded.enabled is True
    assert seeded.severity == "critical"

    # Second call — the rule already exists, so nothing is added and an
    # operator's edits to it survive the restart.
    second = _Session(existing=object())
    monkeypatch.setattr("app.db.AsyncSessionLocal", lambda: second)
    await alerts_mod.seed_restore_drill_failed_alert_rule()
    assert second.added == []
    assert second.committed is False


@pytest.mark.asyncio
async def test_alert_ignores_target_with_drills_disabled(
    db_session: AsyncSession,
) -> None:
    """An ad-hoc drill on an unscheduled target must not open an event
    that nothing can resolve.

    The manual run-now endpoint drills regardless of ``drill_enabled``,
    so without this filter one failed ad-hoc drill would open a
    critical alert whose documented resolution ("the next drill
    passes") can never happen — there is no next drill.
    """
    target = await _make_target(db_session, name="adhoc-only", drill_enabled=False)
    await _make_drill(db_session, target, state="failed", started_at=datetime.now(UTC))
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    assert await _matching_restore_drill_failed_subjects(db_session, rule) == []


@pytest.mark.asyncio
async def test_disabling_the_target_resolves_the_alert(db_session: AsyncSession) -> None:
    """Turning a target off is an operator-reachable way to clear the
    event, rather than leaving a critical alert stuck forever."""
    target = await _make_target(db_session, name="switch-off")
    await _make_drill(db_session, target, state="failed", started_at=datetime.now(UTC))
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    assert len(await _matching_restore_drill_failed_subjects(db_session, rule)) == 1
    target.enabled = False
    await db_session.flush()
    assert await _matching_restore_drill_failed_subjects(db_session, rule) == []


@pytest.mark.asyncio
async def test_empty_destination_gets_its_own_alert_wording(
    db_session: AsyncSession,
) -> None:
    """ "The archive didn't survive" is the wrong story when there is no
    archive — it sends the operator hunting for corruption instead of
    finding an empty destination."""
    target = await _make_target(db_session, name="empty-dest")
    await _make_drill(
        db_session,
        target,
        state="failed",
        started_at=datetime.now(UTC),
        assertions=[
            {
                "name": "archive_available",
                "status": "fail",
                "detail": "the destination holds no archives",
            }
        ],
    )
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    matches = await _matching_restore_drill_failed_subjects(db_session, rule)
    assert len(matches) == 1
    message = matches[0][2]
    assert "holds no archives" in message
    assert "did not survive" not in message


# ── readiness rollup ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_readiness_error_does_not_erase_a_prior_pass(
    db_session: AsyncSession,
) -> None:
    """A destination that was briefly unreachable disproves nothing.

    The alert path treats ``error`` as leaving the previous verdict
    standing; the readiness rollup must agree, or a transient S3 blip
    would report a backup proven yesterday as unverified.
    """
    from app.services.backup.drill import compute_drill_readiness

    target = await _make_target(db_session, name="blipped")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="passed", started_at=now - timedelta(days=1))
    await _make_drill(db_session, target, state="error", started_at=now)
    target.drill_last_status = "error"
    await db_session.flush()

    rows = await compute_drill_readiness(db_session)
    row = next(r for r in rows if r["target_name"] == "blipped")
    assert row["verified"] is True
    assert row["latest_verdict"] == "error"
    assert row["last_passed_at"] is not None


@pytest.mark.asyncio
async def test_readiness_failure_supersedes_an_older_pass(
    db_session: AsyncSession,
) -> None:
    from app.services.backup.drill import compute_drill_readiness

    target = await _make_target(db_session, name="regressed")
    now = datetime.now(UTC)
    await _make_drill(db_session, target, state="passed", started_at=now - timedelta(days=5))
    await _make_drill(db_session, target, state="failed", started_at=now)
    rows = await compute_drill_readiness(db_session)
    row = next(r for r in rows if r["target_name"] == "regressed")
    assert row["verified"] is False
    assert row["last_passed_at"] is not None, "the old pass is still reported, just superseded"


@pytest.mark.asyncio
async def test_readiness_endpoint_matches_the_copilot_tool(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The UI and the assistant must not disagree about whether a
    backup is proven."""
    from app.services.ai.tools.backup import (
        RestoreDrillReadinessArgs,
        get_restore_drill_readiness,
    )

    user, token = await _make_user(db_session, username="readyparity")
    target = await _make_target(db_session, name="parity")
    await _make_drill(db_session, target, state="passed", started_at=datetime.now(UTC))

    res = await client.get(
        "/api/v1/backup/drills/readiness", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    via_tool = await get_restore_drill_readiness(db_session, user, RestoreDrillReadinessArgs())
    assert res.json()["targets"] == via_tool["targets"]
    assert res.json()["verified_targets"] == via_tool["verified_targets"]


@pytest.mark.asyncio
async def test_readiness_requires_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, superadmin=False, username="readyplain")
    res = await client.get(
        "/api/v1/backup/drills/readiness", headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_stale_mutex_does_not_block_a_manual_drill(
    client: AsyncClient, db_session: AsyncSession, monkeypatch
) -> None:
    """A mutex stranded by an api restart must not 409 the operator
    forever — there is no other way to clear the flag."""
    from app.services.backup import drill as drill_mod
    from app.services.backup.drill import STALE_IN_PROGRESS_SECONDS

    _, token = await _make_user(db_session, username="drillstale")
    target = await _make_target(db_session, name="stranded")
    target.drill_last_status = "in_progress"
    target.drill_last_at = datetime.now(UTC) - timedelta(seconds=STALE_IN_PROGRESS_SECONDS + 120)
    await db_session.flush()

    async def _fake_execute(_target: Any, *, live_db_url: str) -> Any:
        return drill_mod.DrillOutcome(state="passed", assertions=[])

    monkeypatch.setattr(drill_mod, "_execute", _fake_execute)
    res = await client.post(
        f"/api/v1/backup/drills/run/{target.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, "a stranded mutex must not lock out manual drills"


@pytest.mark.asyncio
async def test_scheduled_drill_writes_an_audit_row(db_session: AsyncSession, monkeypatch) -> None:
    """Non-negotiable #4 admits no 'unless a cron did it' exception —
    and find_backup_audit_history would otherwise never show a
    scheduled drill."""
    from app.services.backup import drill as drill_mod

    target = await _make_target(db_session, name="audited")

    async def _fake_execute(_target: Any, *, live_db_url: str) -> Any:
        return drill_mod.DrillOutcome(state="passed", assertions=[])

    monkeypatch.setattr(drill_mod, "_execute", _fake_execute)
    await drill_mod.run_drill_for_target(db_session, target=target, triggered_by="schedule")
    await db_session.flush()

    row = await db_session.scalar(select(AuditLog).where(AuditLog.action == "backup_restore_drill"))
    assert row is not None
    assert row.resource_display == "audited"
    assert row.new_value["triggered_by"] == "schedule"


@pytest.mark.asyncio
async def test_no_alert_event_rows_leak_between_targets(
    db_session: AsyncSession,
) -> None:
    """Two failing targets are two distinct subjects."""
    now = datetime.now(UTC)
    a = await _make_target(db_session, name="vault-a")
    b = await _make_target(db_session, name="vault-b")
    await _make_drill(db_session, a, state="failed", started_at=now)
    await _make_drill(db_session, b, state="failed", started_at=now)
    rule = AlertRule(
        name="drill failed",
        rule_type=RULE_TYPE_RESTORE_DRILL_FAILED,
        severity="critical",
        enabled=True,
    )
    matches = await _matching_restore_drill_failed_subjects(db_session, rule)
    assert {m[1] for m in matches} == {"vault-a", "vault-b"}
    assert await db_session.scalar(select(AlertEvent).limit(1)) is None

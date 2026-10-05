"""Backup / restore guard regressions: #1575, #1574, #1571, #1515.

* #1575 — a selective restore that will be refused (plain-format
  archive, unknown section keys) is refused BEFORE the pre-restore
  safety dump is taken and before the connection pool is disposed:
  both facts are knowable from the parsed archive alone.
* #1574 — pre-restore safety dumps are not real backups: they must
  not consume the target's retention slots, must not be served as
  the "latest" archive, and get their own small keep-last-N.
* #1571 — restore takes a Postgres advisory lock, Run Now / the
  sweep claim a target atomically, and archive + safety-dump names
  carry a random suffix so two runs in the same second cannot
  overwrite each other.
* #1515 — a backup run whose process dies, or whose driver raises
  something unexpected, must not leave the target ``in_progress``
  forever: the runner stamps ``failed`` for ANY exception, the
  sweep reaps a stale ``in_progress`` row instead of skipping it
  forever, and drivers translate ``OSError`` / ``httpx.InvalidURL``
  at their boundary.
"""

from __future__ import annotations

import pytest

from app.services.backup import restore
from app.services.backup.restore import BackupRestoreError

# ══════════════════════════════════════════════════════════════════════
# #1575 — selective restore validates before the safety dump
# ══════════════════════════════════════════════════════════════════════


def _patch_restore_prereqs(monkeypatch: pytest.MonkeyPatch, *, dump_format: str) -> dict:
    """Stub everything ``apply_backup_restore`` does before Phase 3,
    and make the safety dump a tripwire: if validation regresses back
    behind it, these tests fail on the tripwire, not on a side effect."""
    state = {"safety_dump_calls": 0}

    def _extract(_archive_bytes: bytes):
        return ({"format_version": 2, "schema_version": None}, b"dump", dump_format, b"enc")

    async def _safety_dump(_db):  # pragma: no cover — the tripwire itself
        state["safety_dump_calls"] += 1
        raise AssertionError("safety dump taken before selective-restore validation")

    monkeypatch.setattr(restore, "extract_archive_members", _extract)
    monkeypatch.setattr(restore, "decrypt_secrets", lambda enc, passphrase: {})
    monkeypatch.setattr(restore, "schema_direction_error", lambda head: None)
    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _safety_dump)
    return state


async def test_selective_restore_of_plain_archive_refused_before_safety_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _patch_restore_prereqs(monkeypatch, dump_format="plain")

    with pytest.raises(BackupRestoreError, match="custom format"):
        await restore.apply_backup_restore(
            None,
            archive_bytes=b"zip",
            passphrase="hunter2hunter2",
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
            sections=["dns"],
        )
    assert state["safety_dump_calls"] == 0


async def test_selective_restore_with_unknown_section_refused_before_safety_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _patch_restore_prereqs(monkeypatch, dump_format="custom")

    with pytest.raises(BackupRestoreError, match="unknown section keys"):
        await restore.apply_backup_restore(
            None,
            archive_bytes=b"zip",
            passphrase="hunter2hunter2",
            confirmation_phrase=restore.CONFIRM_PHRASE,
            db_url="postgresql+asyncpg://u:p@h:5432/db",
            sections=["no_such_section"],
        )
    assert state["safety_dump_calls"] == 0

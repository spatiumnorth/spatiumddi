"""Is a backup restore replaying or migrating this database right now? (#4678)

A Full restore replays the archive's schema, head included, and only then
migrates it up to this release's head. For those seconds ``alembic_version``
reads the ARCHIVE's head, so a pod waiting in ``wait-for-migrate`` for that
head passes its wait, starts, and stays up on the schema the restore then
moves on from. The restore holds a session-level advisory lock for the whole
replay and upgrade (``apply_backup_restore``); the init container asks this
module whether it is held and keeps waiting while it is.

``python -m app.core.restore_gate`` exits 1 while a restore is running, 0
otherwise. It fails OPEN on anything it cannot answer (no database yet, no
asyncpg, an older image without this module): the schema comparison the wait
already does stays the gate, and this only ever adds waiting.
"""

from __future__ import annotations

import asyncio
import os
import sys
import zlib

#: Session-level Postgres advisory lock serialising restores (#1571). Fixed
#: key (a whole-install operation, so there is only ever one restore at a
#: time), derived from a label so it cannot collide with the crc32-based
#: per-resource keys elsewhere by accident.
RESTORE_LOCK_KEY = zlib.crc32(b"spatiumddi:backup-restore") - 2**31


#: Sessions holding the restore lock. ``pg_locks`` shows a bigint key as its
#: high half in ``classid`` and its low half in ``objid``, with ``objsubid`` 1.
#: ``pid IS NOT NULL`` keeps a prepared transaction's lock from turning a
#: ``NOT IN`` over this into NULL.
RESTORE_LOCK_HOLDERS_SQL = (
    "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted "
    "AND pid IS NOT NULL AND objsubid = 1 "
    f"AND ((classid::bigint << 32) | objid::bigint) = {RESTORE_LOCK_KEY} "
    "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
)


async def restore_in_progress(dsn: str) -> bool:
    """True when a session holds the restore lock.

    A read of ``pg_locks``, never a ``pg_try_advisory_lock``: taking the lock,
    even for an instant, would refuse a restore that started in that instant
    as "already in progress", and every waiting pod polls this every few
    seconds.
    """
    import asyncpg  # noqa: PLC0415

    conn = await asyncpg.connect(dsn=dsn, timeout=5, command_timeout=10)
    try:
        return bool(await conn.fetchval(f"SELECT EXISTS ({RESTORE_LOCK_HOLDERS_SQL})"))
    finally:
        await conn.close()


def main() -> int:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        return 0
    dsn = url.replace("postgresql+asyncpg://", "postgresql://", 1)
    try:
        return 1 if asyncio.run(restore_in_progress(dsn)) else 0
    except Exception:  # noqa: BLE001 — fail open, see the module docstring
        return 0


if __name__ == "__main__":
    sys.exit(main())

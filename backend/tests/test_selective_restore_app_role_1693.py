"""#1693 — a selective restore works as the appliance's own database role,
and one that fails leaves the database as it was.

An appliance connects as the role CloudNativePG creates for the app: the owner
of every table, but not a superuser. Selective restore emptied the selected
sections' FK-cascade closure with ``TRUNCATE … CASCADE`` in one psql
transaction, which committed, and only then loaded the archive's rows in a
second one with ``pg_restore --data-only --disable-triggers``. That flag
emits ``ALTER TABLE … DISABLE TRIGGER ALL``, and PostgreSQL lets only a
superuser disable the triggers that enforce a foreign key. So on an appliance
the load failed on the first table carrying one, after every table in the
closure had been emptied: ``alembic_version`` among them, which leaves the
api not ready, so the operator cannot reach the restore page to undo it.
CI's Postgres connects as a superuser and never saw it.

These run the real restore (``pg_dump``, ``pg_restore``, ``psql``) against a
scratch database built from the models and owned by a role that is not a
superuser, the shape an appliance has. Its IPAM rows close the
``ip_address`` <-> ``dns_record`` reference cycle, so no load order alone can
satisfy the foreign keys.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import uuid
import zipfile
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings
from app.models.base import Base
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.backup import restore
from app.services.backup.archive import _pg_env_from_url, _pg_subprocess_env
from app.services.backup.crypto import encrypt_secrets

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")),
    reason="needs the PostgreSQL client tools",
)

_URL = os.environ["DATABASE_URL"]
_PASSPHRASE = "restore-1693-passphrase"
_HEAD = "r1693_archive_head"


def _url_for(dbname: str, user: str | None = None, password: str | None = None) -> str:
    parts = urlsplit(_URL)
    netloc = parts.netloc
    if user is not None:
        netloc = f"{user}:{password}@{netloc.rsplit('@', 1)[-1]}"
    return urlunsplit(parts._replace(netloc=netloc, path=f"/{dbname}"))


def _dsn(url: str) -> str:
    return url.replace("+asyncpg", "")


async def _admin() -> asyncpg.Connection:
    return await asyncpg.connect(_dsn(_url_for("postgres")))


async def _pg_dump(url: str) -> bytes:
    """The archive's dump, taken the way ``build_backup_archive`` takes it."""
    import asyncio

    pg_env, _ = _pg_env_from_url(url)
    proc = await asyncio.create_subprocess_exec(
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--quote-all-identifiers",
        env=_pg_subprocess_env(pg_env),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    assert proc.returncode == 0, err.decode()
    return out


def _archive(dump: bytes) -> bytes:
    """An archive of this install: its own keys, so the rewrap is a no-op."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "manifest.json",
            json.dumps(
                {"format": "spatiumddi-backup", "format_version": 2, "dump_format": "custom"}
            ),
        )
        zf.writestr("database.dump", dump)
        zf.writestr(
            "secrets.enc",
            encrypt_secrets(
                {
                    "platform_secret_key": settings.secret_key,
                    "platform_credential_encryption_key": settings.credential_encryption_key or "",
                },
                passphrase=_PASSPHRASE,
            ),
        )
    return buf.getvalue()


async def _state(url: str) -> dict[str, Any]:
    """What the IPAM section, the records tied to it, and the schema pin hold."""
    conn = await asyncpg.connect(_dsn(url))
    try:
        return {
            "subnets": [
                tuple(r)
                for r in await conn.fetch("SELECT network::text, name FROM subnet ORDER BY 1")
            ],
            # Both directions of the cycle: the address's record, the record's address.
            "addresses": [
                tuple(r)
                for r in await conn.fetch(
                    "SELECT host(a.address), a.hostname, r.name FROM ip_address a "
                    "LEFT JOIN dns_record r ON r.id = a.dns_record_id ORDER BY 1"
                )
            ],
            "records": [
                tuple(r)
                for r in await conn.fetch(
                    "SELECT r.name, host(a.address) FROM dns_record r "
                    "LEFT JOIN ip_address a ON a.id = r.ip_address_id ORDER BY 1"
                )
            ],
            "zones": await conn.fetchval("SELECT count(*) FROM dns_zone"),
            "alembic_version": [
                r[0] for r in await conn.fetch("SELECT version_num FROM alembic_version")
            ],
        }
    finally:
        await conn.close()


async def _foreign_keys(url: str) -> list[tuple[str, str, str, bool]]:
    """Every foreign key in the schema, with its definition and validity."""
    conn = await asyncpg.connect(_dsn(url))
    try:
        rows = await conn.fetch(
            "SELECT c.conrelid::regclass::text, c.conname, pg_get_constraintdef(c.oid), "
            "c.convalidated FROM pg_constraint c "
            "JOIN pg_namespace n ON n.oid = c.connamespace "
            "WHERE c.contype = 'f' AND n.nspname = 'public' ORDER BY 1, 2"
        )
        return [tuple(r) for r in rows]
    finally:
        await conn.close()


class _RequestSession:
    """The restore closes the request's session before the replay."""

    async def close(self) -> None:
        return None


async def _restore(
    url: str,
    archive: bytes,
    monkeypatch: pytest.MonkeyPatch,
    sections: tuple[str, ...] = ("ipam",),
) -> Any:
    async def _no_safety_dump(_db: object) -> None:
        # The safety dump reads the app's own DATABASE_URL, not this database.
        return None

    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _no_safety_dump)
    return await restore.apply_backup_restore(
        _RequestSession(),
        archive_bytes=archive,
        passphrase=_PASSPHRASE,
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url=url,
        sections=list(sections),
    )


# An audited write, as far as the database sees one: ``seq`` comes from its
# sequence, and ``row_hash`` is not checked here.
_AUDIT_INSERT = (
    "INSERT INTO audit_log (id, user_display_name, auth_source, action, resource_type, "
    "resource_id, resource_display, result, row_hash) "
    "VALUES ($1, 'admin', 'local', 'create', 'subnet', $2, 'x', 'success', 'h') RETURNING seq"
)


async def _sequences_behind_their_rows(conn: asyncpg.Connection) -> list[tuple[str, int, int]]:
    """Every sequence a table owns (a serial's or an identity's) whose next
    value is not past the largest value its column holds: (sequence, next, max)."""
    owned = await conn.fetch(
        "SELECT s.oid::regclass::text AS seq, c.oid::regclass::text AS tbl, a.attname AS col "
        "FROM pg_depend d "
        "JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S' "
        "JOIN pg_class c ON c.oid = d.refobjid "
        "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = d.refobjsubid "
        "WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass "
        "AND d.deptype IN ('a', 'i') ORDER BY 1"
    )
    behind = []
    for r in owned:
        last_value, is_called = await conn.fetchrow(f"SELECT last_value, is_called FROM {r['seq']}")
        largest = await conn.fetchval(f'SELECT max("{r["col"]}") FROM {r["tbl"]}')
        next_value = last_value + 1 if is_called else last_value
        if largest is not None and next_value <= largest:
            behind.append((r["seq"], next_value, largest))
    return behind


@pytest.fixture
async def appliance_db() -> AsyncIterator[tuple[str, bytes, dict[str, Any]]]:
    """(the app role's URL, an archive of its database, the archived state).

    A database owned by a role that is NOT a superuser, its schema created by
    that role (so it owns every table, as the app role does after the
    migrations), holding two addresses whose A records point back at them.
    """
    suffix = uuid.uuid4().hex[:10]
    role, password, dbname = (
        f"r1693_app_{suffix}",
        f"pw-{suffix}",
        f"spatiumddi_test_r1693_{suffix}",
    )
    admin = await _admin()
    try:
        await admin.execute(
            f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}' "
            "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
        )
        await admin.execute(f'CREATE DATABASE "{dbname}" OWNER "{role}"')
    finally:
        await admin.close()
    url = _url_for(dbname, role, password)
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        conn2 = await asyncpg.connect(_dsn(url))
        try:
            assert not await conn2.fetchval(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
            )
            # Alembic's table, which create_all does not make.
            await conn2.execute(
                "CREATE TABLE alembic_version (version_num varchar(32) NOT NULL, "
                "CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))"
            )
            await conn2.execute("INSERT INTO alembic_version VALUES ($1)", _HEAD)
        finally:
            await conn2.close()
        async with AsyncSession(engine, expire_on_commit=False) as db:
            group = DNSServerGroup(name=f"g1693-{suffix}")
            space = IPSpace(name=f"sp1693-{suffix}", description="")
            db.add_all([group, space])
            await db.flush()
            zone = DNSZone(
                group_id=group.id,
                name="r1693.example.",
                zone_type="primary",
                kind="forward",
                primary_ns="ns1.example.",
                admin_email="admin.example.",
            )
            block = IPBlock(space_id=space.id, network="10.93.0.0/16", name="b")
            db.add_all([zone, block])
            await db.flush()
            subnet = Subnet(
                space_id=space.id, block_id=block.id, network="10.93.1.0/24", name="archived"
            )
            db.add(subnet)
            await db.flush()
            for last, host in (("10", "alpha"), ("11", "beta")):
                ip = IPAddress(
                    subnet_id=subnet.id,
                    address=f"10.93.1.{last}",
                    status="allocated",
                    hostname=host,
                )
                db.add(ip)
                await db.flush()
                rec = DNSRecord(
                    zone_id=zone.id,
                    name=host,
                    fqdn=f"{host}.r1693.example",
                    record_type="A",
                    value=f"10.93.1.{last}",
                    auto_generated=True,
                    ip_address_id=ip.id,
                )
                db.add(rec)
                await db.flush()
                ip.dns_record_id = rec.id
            await db.commit()
        archived = await _state(url)
        archive = _archive(await _pg_dump(url))
        yield url, archive, archived
    finally:
        await engine.dispose()
        admin = await _admin()
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
            await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        finally:
            await admin.close()


_ARCHIVED = {
    "subnets": [("10.93.1.0/24", "archived")],
    "addresses": [("10.93.1.10", "alpha", "alpha"), ("10.93.1.11", "beta", "beta")],
    "records": [("alpha", "10.93.1.10"), ("beta", "10.93.1.11")],
    "zones": 1,
    "alembic_version": [_HEAD],
}


async def test_the_fixture_holds_what_an_appliance_would(appliance_db) -> None:
    """Pins the premise: both directions of the reference cycle are set."""
    _url, _archive_bytes, archived = appliance_db
    assert archived == _ARCHIVED


async def test_a_selective_restore_that_fails_part_way_changes_nothing(
    appliance_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``pg_restore`` dies part way through the archive. Whatever it had
    loaded, and the emptying of the closure before it, must not commit."""
    url, archive, _archived = appliance_db
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        members = {name: zf.read(name) for name in zf.namelist()}
    dump = members["database.dump"]
    members["database.dump"] = dump[: len(dump) * 2 // 3]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    before = await _state(url)
    keys_before = await _foreign_keys(url)

    with pytest.raises(restore.BackupRestoreError):
        await _restore(url, buf.getvalue(), monkeypatch)

    assert await _state(url) == before
    assert await _foreign_keys(url) == keys_before


async def test_the_selective_replay_hands_its_tools_the_allowlisted_env(
    appliance_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1572 for the selective path: every pg tool the restore starts gets
    the allowlisted environment, never the api's own."""
    import asyncio

    url, archive, _archived = appliance_db
    real_exec = asyncio.create_subprocess_exec
    envs: list[tuple[str, dict[str, str]]] = []

    async def _recording_exec(program: str, *args: Any, **kwargs: Any) -> Any:
        envs.append((program, dict(kwargs.get("env") or {})))
        return await real_exec(program, *args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _recording_exec)
    monkeypatch.setenv("SPATIUM_TEST_SECRET_SENTINEL", "must-not-leak")

    # Whether the restore lands is the other tests' business; the
    # environment the tools got is this one's.
    with contextlib.suppress(restore.BackupRestoreError):
        await _restore(url, archive, monkeypatch)

    programs = [program for program, _env in envs]
    assert "pg_restore" in programs and "psql" in programs
    for program, env in envs:
        assert env, f"{program} inherited the api's whole environment"
        assert "SPATIUM_TEST_SECRET_SENTINEL" not in env, program


async def test_a_selective_restore_as_the_app_role_brings_the_section_back(
    appliance_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reported case: restore ``ipam`` as a role that is not a superuser.
    Writes made after the backup are undone, the rows come back with their
    records, the schema pin is back, and every foreign key is as it was."""
    url, archive, archived = appliance_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        await conn.execute("DELETE FROM dns_record WHERE name = 'alpha'")
        await conn.execute("DELETE FROM ip_address WHERE hostname = 'alpha'")
        await conn.execute("UPDATE subnet SET name = 'renamed after the backup'")
    finally:
        await conn.close()
    keys_before = await _foreign_keys(url)

    outcome = await _restore(url, archive, monkeypatch)

    assert outcome.selective
    assert "ipam" in (outcome.restored_sections or [])
    assert "dns_record" in outcome.cascade_widened_tables
    assert await _state(url) == archived
    assert await _foreign_keys(url) == keys_before


async def test_rows_that_point_at_something_gone_are_refused_and_change_nothing(
    appliance_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The archive's zone belongs to a DNS server group deleted since the
    backup, outside what a restore of ``ipam`` reloads. Loading it would leave
    a zone pointing at nothing, so the restore is refused with the foreign
    key named, after the closure was emptied and reloaded inside the same
    transaction, and the database is left exactly as it was."""
    url, archive, _archived = appliance_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        await conn.execute("DELETE FROM dns_server_group")
    finally:
        await conn.close()
    before = await _state(url)
    keys_before = await _foreign_keys(url)

    with pytest.raises(restore.BackupRestoreError, match="violates foreign key constraint"):
        await _restore(url, archive, monkeypatch)

    assert await _state(url) == before
    assert await _foreign_keys(url) == keys_before


@pytest.mark.parametrize("section", ["dns", "dhcp", "auth"])
async def test_other_sections_restore_as_the_app_role_too(
    appliance_db, monkeypatch: pytest.MonkeyPatch, section: str
) -> None:
    """Every large section's closure holds a reference cycle (``auth``'s holds
    both: ``ip_address``/``dns_record``/``nmap_scan`` and ``asn``/``provider``),
    so each needs what ``ipam`` needs."""
    url, archive, archived = appliance_db
    keys_before = await _foreign_keys(url)

    async def _no_safety_dump(_db: object) -> None:
        return None

    monkeypatch.setattr(restore, "_write_pre_restore_safety_dump", _no_safety_dump)
    outcome = await restore.apply_backup_restore(
        _RequestSession(),
        archive_bytes=archive,
        passphrase=_PASSPHRASE,
        confirmation_phrase=restore.CONFIRM_PHRASE,
        db_url=url,
        sections=[section],
    )

    assert outcome.selective
    assert await _state(url) == archived
    assert await _foreign_keys(url) == keys_before


async def test_a_selective_restore_leaves_each_sequence_it_reloads_past_its_rows(
    appliance_db, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``TRUNCATE … RESTART IDENTITY`` sends every sequence the emptied
    tables own back to its start, and ``pg_restore --data-only --table``
    brings back their rows, not their sequences. ``audit_log.seq`` is one,
    under a unique index, so the next audited write (a login is one)
    collided with a restored row and answered 409, and so did every one
    after it until the sequence had climbed past the rows.

    Writes audited after the backup move the sequence on, and the restore
    undoes them. Afterwards no sequence may sit behind its rows, and the
    next audited write lands after the restored chain."""
    url, _fixture_archive, _archived = appliance_db
    conn = await asyncpg.connect(_dsn(url))
    try:
        # What migration d92f4a18c763 makes on an appliance; create_all does not.
        await conn.execute("ALTER SEQUENCE audit_log_seq_seq OWNED BY audit_log.seq")
        await conn.execute("CREATE UNIQUE INDEX ix_audit_log_seq ON audit_log (seq)")
        for i in range(5):
            await conn.fetchval(_AUDIT_INSERT, uuid.uuid4(), f"archived-{i}")
    finally:
        await conn.close()
    archive = _archive(await _pg_dump(url))
    conn = await asyncpg.connect(_dsn(url))
    try:
        for i in range(3):
            await conn.fetchval(_AUDIT_INSERT, uuid.uuid4(), f"after-the-backup-{i}")
    finally:
        await conn.close()

    outcome = await _restore(url, archive, monkeypatch, sections=("audit",))

    assert outcome.selective
    assert "audit" in (outcome.restored_sections or [])
    conn = await asyncpg.connect(_dsn(url))
    try:
        assert await conn.fetchval("SELECT count(*) FROM audit_log") == 5
        assert await _sequences_behind_their_rows(conn) == []
        # Raises UniqueViolationError on ix_audit_log_seq if the sequence is behind.
        seq = await conn.fetchval(_AUDIT_INSERT, uuid.uuid4(), "after-the-restore")
        assert seq > await conn.fetchval("SELECT max(seq) FROM audit_log WHERE seq <> $1", seq)
    finally:
        await conn.close()

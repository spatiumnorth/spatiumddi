"""The DNS server group's own TSIG key is encrypted at rest and rotatable (#1364).

It was the one credential stored in clear, and not a minor one: the BIND9
agent grants it allow-update and allow-transfer on every primary zone the
group serves, by key rather than address. Anyone reading the database or an
unencrypted backup could transfer and rewrite every zone.
"""

from __future__ import annotations

import base64
import importlib.util
import pathlib
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dns import DNSServerGroup
from app.services.dns.tsig import (
    ensure_group_tsig_key,
    group_tsig_secret,
    legacy_group_key,
    set_group_tsig_secret,
)

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "b3c71e9a4d25_dns_group_tsig_secret_encrypted.py"
)


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"tk-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TSIG Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_a_minted_key_is_stored_encrypted(db_session: AsyncSession) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    assert ensure_group_tsig_key(group) is True
    await db_session.flush()

    secret = group_tsig_secret(group)
    assert secret and len(base64.b64decode(secret)) == 32
    raw = (
        await db_session.execute(
            text("SELECT tsig_key_secret_encrypted FROM dns_server_group WHERE id = :id"),
            {"id": group.id},
        )
    ).scalar_one()
    assert secret.encode() not in bytes(raw)
    assert decrypt_str(bytes(raw)) == secret


async def test_an_undecryptable_key_is_reminted(db_session: AsyncSession) -> None:
    """A key that no longer decrypts (the install key changed without a
    rewrap) is no key: the group gets a fresh one rather than shipping none."""
    group = DNSServerGroup(
        name=f"g-{uuid.uuid4().hex[:6]}",
        tsig_key_name="spatium-old",
        tsig_key_secret_encrypted=b"not-a-fernet-token",
    )
    db_session.add(group)
    await db_session.flush()

    assert group_tsig_secret(group) is None
    assert legacy_group_key(group) is None
    assert ensure_group_tsig_key(group) is True
    assert group_tsig_secret(group)
    # Under its existing name, not one re-derived from the (since renamed)
    # group: a view or ACL citing ``key "spatium-old"`` must still resolve.
    assert group.tsig_key_name == "spatium-old"


async def test_a_rotated_key_reaches_the_agent_bundle(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """What the rotation is for: the next bundle carries the new secret."""
    from app.models.dns import DNSServer
    from app.services.dns.agent_config import build_config_bundle

    headers = await _admin(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", tsig_key_name="spatium-b")
    set_group_tsig_secret(group, "b2xkLXNlY3JldA==")
    db_session.add(group)
    await db_session.flush()
    server = DNSServer(group_id=group.id, name="s1", driver="bind9", host="127.0.0.1", port=53)
    db_session.add(server)
    await db_session.commit()
    group_id, server_id = group.id, server.id

    resp = await client.post(
        f"/api/v1/dns/groups/{group_id}/group-tsig-key/rotate", headers=headers
    )
    assert resp.status_code == 200, resp.text

    db_session.expire_all()
    loaded = (
        await db_session.execute(select(DNSServer).where(DNSServer.id == server_id))
    ).scalar_one()
    bundle = await build_config_bundle(db_session, loaded)
    group = await db_session.get(DNSServerGroup, group_id)
    assert group is not None
    keys = {k["name"]: k["secret"] for k in bundle["tsig_keys"]}
    assert keys["spatium-b"] == group_tsig_secret(group) != "b2xkLXNlY3JldA=="


def test_an_exclude_secrets_archive_blanks_the_legacy_plaintext_column() -> None:
    """The plaintext column is kept, unread, for one release; a diagnostic
    archive that scrubs the encrypted copy must not ship this one in clear."""
    from app.services.backup.archive import _scrub_dump_text

    dump = (
        'COPY "public"."dns_server_group" ("id", "name", "tsig_key_secret", '
        '"tsig_key_secret_encrypted") FROM stdin;\n'
        "1\tdefault\tcGxhaW4=\t\\\\x6162\n"
        "2\tother\t\\N\t\\N\n"
        "\\.\n"
    )
    rows = [line.split("\t") for line in _scrub_dump_text(dump).splitlines()[1:3]]
    assert rows[0] == ["1", "default", "\\N", "\\\\x"]
    assert rows[1] == ["2", "other", "\\N", "\\N"]


async def test_rotate_replaces_the_secret_and_keeps_the_name(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", tsig_key_name="spatium-g")
    set_group_tsig_secret(group, "b2xkLXNlY3JldA==")
    db_session.add(group)
    await db_session.commit()
    group_id = group.id

    resp = await client.post(
        f"/api/v1/dns/groups/{group_id}/group-tsig-key/rotate", headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert "b2xkLXNlY3JldA==" not in resp.text

    db_session.expire_all()
    group = await db_session.get(DNSServerGroup, group_id)
    assert group is not None
    assert group.tsig_key_name == "spatium-g"
    new = group_tsig_secret(group)
    assert new and new != "b2xkLXNlY3JldA=="
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "rotate", AuditLog.resource_id == str(group_id)
            )
        )
    ).scalar_one()
    assert audit.resource_type == "dns_server_group"
    assert new not in str(audit.new_value)


async def test_rotate_needs_a_superadmin(client: AsyncClient, db_session: AsyncSession) -> None:
    user = User(
        username=f"ro-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Viewer",
        hashed_password=hash_password("x"),
    )
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add_all([user, group])
    await db_session.commit()
    resp = await client.post(
        f"/api/v1/dns/groups/{group.id}/group-tsig-key/rotate",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_the_migration_encrypts_existing_plaintext(db_session: AsyncSession) -> None:
    """Replay the migration's upgrade against a plaintext column, the shape an
    upgrading install has, and check what it leaves behind. The DDL runs in
    the test's transaction, which the fixture rolls back; nothing commits."""
    spec = importlib.util.spec_from_file_location("m_b3c71e9a4d25", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", tsig_key_name="spatium-m")
    db_session.add(group)
    await db_session.flush()

    # Put the table back in its pre-#1364 shape for this transaction. The test
    # schema is built from the models, which no longer map the plaintext
    # column; on a real install it is still there (expand/contract, #296).
    await db_session.execute(
        text("ALTER TABLE dns_server_group ADD COLUMN tsig_key_secret VARCHAR(255)")
    )
    await db_session.execute(
        text("ALTER TABLE dns_server_group DROP COLUMN tsig_key_secret_encrypted")
    )
    await db_session.execute(
        text("UPDATE dns_server_group SET tsig_key_secret = 'cGxhaW4=' WHERE id = :id"),
        {"id": group.id},
    )

    def _upgrade(sync_conn) -> None:  # noqa: ANN001
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module.upgrade()

    conn = await db_session.connection()
    await conn.run_sync(_upgrade)

    columns = {
        r[0]
        for r in (
            await db_session.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'dns_server_group'"
                )
            )
        ).all()
    }
    # Kept for the old pods of a rolling upgrade; the next release drops it.
    assert "tsig_key_secret" in columns
    raw = (
        await db_session.execute(
            text("SELECT tsig_key_secret_encrypted FROM dns_server_group WHERE id = :id"),
            {"id": group.id},
        )
    ).scalar_one()
    assert decrypt_str(bytes(raw)) == "cGxhaW4="

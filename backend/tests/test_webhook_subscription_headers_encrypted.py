"""Typed-webhook subscription headers are secrets (#1579).

A subscription's custom headers are documented as "auth tokens, routing
hints" — in practice ``Authorization: Bearer …`` receiver credentials.
They were plaintext JSONB, returned in full on every subscription
response, and not registered as a secret column, so backup rewrap
skipped them and "exclude secrets" archives kept them. The HMAC
``secret`` on the same row was already Fernet-encrypted; the headers
now get the same treatment, mirroring #1506 for audit-forward targets.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import uuid
from datetime import UTC, datetime

import httpx
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.webhooks.router import (
    WebhookSubscriptionWrite,
    _apply_body,
    _to_response,
)
from app.core.crypto import decrypt_dict, encrypt_dict
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.event_subscription import EventOutbox, EventSubscription
from app.services import event_delivery

# Fixtures only; nothing here is ever sent anywhere real.
_HEADERS = {
    "Authorization": "Bearer fixture-token-not-real",
    "X-Routing": "blue",
}
_TOKEN = "fixture-token-not-real"

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "d27e1d8716bd_webhook_subscription_headers_encrypted.py"
)

_SUBS = "/api/v1/webhooks"


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"wh-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Webhook Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _body(**overrides: object) -> WebhookSubscriptionWrite:
    data: dict[str, object] = {
        "name": f"sub-{uuid.uuid4().hex[:6]}",
        "url": "https://receiver.example.test/hook",
        "headers": dict(_HEADERS),
    }
    data.update(overrides)
    return WebhookSubscriptionWrite(**data)  # type: ignore[arg-type]


def _bare_sub() -> EventSubscription:
    sub = EventSubscription(
        id=uuid.uuid4(),
        name="unit",
        description="",
        enabled=True,
        url="https://receiver.example.test/hook",
        timeout_seconds=10,
        max_attempts=8,
    )
    sub.created_at = datetime.now(UTC)
    sub.modified_at = datetime.now(UTC)
    return sub


# ── storage + write-only contract (unit) ─────────────────────────────


def test_apply_body_encrypts_headers_at_rest() -> None:
    sub = _bare_sub()
    _apply_body(sub, _body(), creating=True)
    assert sub.headers_encrypted is not None
    # The ciphertext must not contain the credential, in whole or part.
    assert _TOKEN.encode() not in bytes(sub.headers_encrypted)
    # Round-trip: what delivery will send is exactly what was written.
    assert decrypt_dict(sub.headers_encrypted) == _HEADERS
    assert event_delivery.subscription_headers(sub) == _HEADERS


def test_update_headers_none_keeps_empty_dict_clears() -> None:
    sub = _bare_sub()
    _apply_body(sub, _body(), creating=True)
    stored = sub.headers_encrypted

    _apply_body(sub, _body(headers=None), creating=False)
    assert sub.headers_encrypted == stored, "omitted headers must keep the stored dict"

    _apply_body(sub, _body(headers={"X-New": "1"}), creating=False)
    assert decrypt_dict(sub.headers_encrypted) == {"X-New": "1"}

    _apply_body(sub, _body(headers={}), creating=False)
    assert sub.headers_encrypted is None, "an explicit empty dict clears the headers"
    assert event_delivery.subscription_headers(sub) == {}


def test_response_carries_names_and_flag_never_values() -> None:
    sub = _bare_sub()
    _apply_body(sub, _body(), creating=True)
    resp = _to_response(sub)
    assert resp.headers_set is True
    assert resp.header_names == ["Authorization", "X-Routing"]
    dumped = resp.model_dump_json()
    assert _TOKEN not in dumped
    assert "blue" not in dumped

    empty = _to_response(_bare_sub())
    assert empty.headers_set is False
    assert empty.header_names == []


# ── delivery path ────────────────────────────────────────────────────


async def test_deliver_one_sends_the_decrypted_headers() -> None:
    sub = _bare_sub()
    sub.headers_encrypted = encrypt_dict({**_HEADERS, "X-SpatiumDDI-Event": "spoofed"})
    row = EventOutbox(
        id=uuid.uuid4(),
        subscription_id=sub.id,
        event_type="test.ping",
        payload={"event_type": "test.ping"},
        state="in_flight",
        attempts=0,
        next_attempt_at=datetime.now(UTC),
    )
    seen: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as client:
        status_code, error = await event_delivery._deliver_one(  # noqa: SLF001
            client, sub, row, "", "test"
        )
    assert (status_code, error) == (200, None)
    sent = seen[0].headers
    assert sent["authorization"] == _HEADERS["Authorization"]
    assert sent["x-routing"] == "blue"
    # The platform-owned family still wins over a spoofed custom header.
    assert sent["x-spatiumddi-event"] == "test.ping"


async def test_deliver_one_reports_undecryptable_headers() -> None:
    sub = _bare_sub()
    sub.headers_encrypted = b"not-a-fernet-token"
    row = EventOutbox(
        id=uuid.uuid4(),
        subscription_id=sub.id,
        event_type="test.ping",
        payload={},
        state="in_flight",
        attempts=0,
        next_attempt_at=datetime.now(UTC),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
        status_code, error = await event_delivery._deliver_one(  # noqa: SLF001
            c, sub, row, "", "test"
        )
    assert status_code is None
    assert error is not None and "headers decrypt failed" in error


# ── API surface ──────────────────────────────────────────────────────


async def test_api_stores_encrypted_and_never_returns_values(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    resp = await client.post(
        _SUBS,
        headers=headers,
        json={
            "name": f"api-{uuid.uuid4().hex[:6]}",
            "url": "https://receiver.example.test/hook",
            "headers": dict(_HEADERS),
        },
    )
    assert resp.status_code == 201, resp.text
    assert _TOKEN not in resp.text
    body = resp.json()
    assert body["headers_set"] is True
    assert body["header_names"] == ["Authorization", "X-Routing"]
    assert "headers" not in body

    raw = (
        await db_session.execute(
            text("SELECT headers_encrypted FROM event_subscription WHERE id = :id"),
            {"id": body["id"]},
        )
    ).scalar_one()
    assert _TOKEN.encode() not in bytes(raw)
    assert decrypt_dict(bytes(raw)) == _HEADERS

    # List + get stay clean too.
    for path in (_SUBS, f"{_SUBS}/{body['id']}"):
        read = await client.get(path, headers=headers)
        assert read.status_code == 200
        assert _TOKEN not in read.text

    # An update that omits headers keeps them; an explicit {} clears.
    keep = await client.put(
        f"{_SUBS}/{body['id']}",
        headers=headers,
        json={"name": body["name"], "url": body["url"]},
    )
    assert keep.status_code == 200, keep.text
    assert keep.json()["headers_set"] is True

    cleared = await client.put(
        f"{_SUBS}/{body['id']}",
        headers=headers,
        json={"name": body["name"], "url": body["url"], "headers": {}},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["headers_set"] is False
    assert cleared.json()["header_names"] == []


async def test_a_header_write_nulls_the_legacy_plaintext_copy(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The pre-#1579 plaintext column must not outlive a clear or a replace
    on this build, or a schema downgrade sends the old credential again.
    An edit that leaves headers alone leaves it."""
    headers = await _admin(db_session)
    created = await client.post(
        _SUBS,
        headers=headers,
        json={"name": f"lg-{uuid.uuid4().hex[:6]}", "url": "https://r.example.test/h"},
    )
    assert created.status_code == 201, created.text
    sid, name, url = created.json()["id"], created.json()["name"], created.json()["url"]

    async def _legacy() -> object:
        db_session.expire_all()
        return (
            await db_session.execute(
                text("SELECT headers FROM event_subscription WHERE id = :id"), {"id": sid}
            )
        ).scalar_one()

    async def _seed_legacy() -> None:
        await db_session.execute(
            text("UPDATE event_subscription SET headers = CAST(:h AS jsonb) WHERE id = :id"),
            {"h": json.dumps(_HEADERS), "id": sid},
        )
        await db_session.commit()

    await _seed_legacy()
    keep = await client.put(f"{_SUBS}/{sid}", headers=headers, json={"name": name, "url": url})
    assert keep.status_code == 200, keep.text
    assert await _legacy() == _HEADERS, "an edit that leaves headers alone keeps it"

    cleared = await client.put(
        f"{_SUBS}/{sid}", headers=headers, json={"name": name, "url": url, "headers": {}}
    )
    assert cleared.status_code == 200, cleared.text
    assert await _legacy() is None

    await _seed_legacy()
    replaced = await client.put(
        f"{_SUBS}/{sid}",
        headers=headers,
        json={"name": name, "url": url, "headers": {"Authorization": "Bearer new"}},
    )
    assert replaced.status_code == 200, replaced.text
    assert await _legacy() is None


# ── backup coverage ──────────────────────────────────────────────────


def test_rewrap_and_scrub_registrations_cover_the_new_column() -> None:
    from app.services.backup.rewrap import (
        ENCRYPTED_COLUMNS,
        LEGACY_PLAINTEXT_SECRET_COLUMNS,
        redactable_columns,
    )

    assert ("event_subscription", "id", "headers_encrypted") in ENCRYPTED_COLUMNS
    # Operator-re-enterable, so an "exclude secrets" archive blanks it.
    assert ("event_subscription", "id", "headers_encrypted") in redactable_columns()
    # …and NULLs the leftover plaintext column from before the move.
    assert ("event_subscription", "headers") in LEGACY_PLAINTEXT_SECRET_COLUMNS


def test_an_exclude_secrets_archive_drops_both_header_copies() -> None:
    from app.services.backup.archive import _scrub_dump_text

    dump = (
        'COPY "public"."event_subscription" ("id", "name", "headers", '
        '"headers_encrypted", "secret_encrypted") FROM stdin;\n'
        '1\tsub\t{"Authorization": "Bearer fixture-token-not-real"}'
        "\t\\\\xdeadbeef\t\\\\xfeedface\n"
        "\\.\n"
    )
    out = _scrub_dump_text(dump)
    assert _TOKEN not in out
    assert "deadbeef" not in out
    row = out.splitlines()[1].split("\t")
    assert row[2] == "\\N", "the legacy plaintext JSONB column is NULLed"
    assert row[3] == "\\\\x", "the encrypted column is blanked to an empty bytea"


# ── migration ────────────────────────────────────────────────────────


async def test_the_migration_encrypts_existing_plaintext(db_session: AsyncSession) -> None:
    """Replay the upgrade (and downgrade) against the pre-#1579 shape. The
    DDL runs in the test's transaction, which the fixture rolls back."""
    spec = importlib.util.spec_from_file_location("m_d27e1d8716bd", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    sub = EventSubscription(
        name=f"m-{uuid.uuid4().hex[:6]}",
        description="",
        enabled=True,
        url="https://receiver.example.test/hook",
    )
    db_session.add(sub)
    await db_session.flush()

    # The test schema is built from the models, which map the plaintext
    # column (deferred, write-only); drop the
    # encrypted one to get the pre-#1579 shape.
    await db_session.execute(text("ALTER TABLE event_subscription DROP COLUMN headers_encrypted"))
    await db_session.execute(
        text("UPDATE event_subscription SET headers = CAST(:h AS jsonb) WHERE id = :id"),
        {"h": json.dumps(_HEADERS), "id": sub.id},
    )

    def _run(fn_name: str):  # noqa: ANN202
        def _inner(sync_conn) -> None:  # noqa: ANN001
            from alembic.migration import MigrationContext
            from alembic.operations import Operations

            ctx = MigrationContext.configure(sync_conn)
            with Operations.context(ctx):
                getattr(module, fn_name)()

        return _inner

    conn = await db_session.connection()
    await conn.run_sync(_run("upgrade"))

    row = (
        await db_session.execute(
            text("SELECT headers, headers_encrypted FROM event_subscription WHERE id = :id"),
            {"id": sub.id},
        )
    ).one()
    # Kept, unread, for the old pods of a rolling upgrade; next release drops it.
    assert row[0] == _HEADERS
    assert decrypt_dict(bytes(row[1])) == _HEADERS

    await conn.run_sync(_run("downgrade"))
    back = (
        await db_session.execute(
            text("SELECT headers FROM event_subscription WHERE id = :id"), {"id": sub.id}
        )
    ).scalar_one()
    assert back == _HEADERS


async def test_a_downgrade_does_not_bring_back_cleared_headers(db_session: AsyncSession) -> None:
    """A subscription whose headers were cleared after the upgrade has no
    encrypted value but kept its pre-upgrade plaintext; the downgrade used
    to copy only rows WITH an encrypted value, so the cleared credential
    was served again by the old build."""
    spec = importlib.util.spec_from_file_location("m_d27e1d8716bd_b", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    sub = EventSubscription(
        name=f"m-{uuid.uuid4().hex[:6]}",
        description="",
        enabled=True,
        url="https://receiver.example.test/hook",
    )
    db_session.add(sub)
    await db_session.flush()
    # Upgraded install, then cleared on the new build: encrypted NULL, but
    # the kept plaintext column still holds the pre-upgrade token.
    await db_session.execute(
        text(
            "UPDATE event_subscription SET headers = CAST(:h AS jsonb), "
            "headers_encrypted = NULL WHERE id = :id"
        ),
        {"h": json.dumps(_HEADERS), "id": sub.id},
    )

    def _downgrade(sync_conn) -> None:  # noqa: ANN001
        from alembic.migration import MigrationContext
        from alembic.operations import Operations

        ctx = MigrationContext.configure(sync_conn)
        with Operations.context(ctx):
            module.downgrade()

    conn = await db_session.connection()
    await conn.run_sync(_downgrade)
    back = (
        await db_session.execute(
            text("SELECT headers FROM event_subscription WHERE id = :id"), {"id": sub.id}
        )
    ).scalar_one()
    assert back is None

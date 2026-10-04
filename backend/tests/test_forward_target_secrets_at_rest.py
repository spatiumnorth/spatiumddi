"""Webhook forward-target URLs and Authorization headers are secrets (#1502).

For a Slack, Discord or Teams target the incoming-webhook URL is the
credential: whoever has it can post into the channel. Both it and a generic
target's ``Authorization`` header used to sit in plaintext columns, came back
from the API, and were written to the logs by httpx on every delivery. The
same went for the legacy single-webhook pair on ``platform_settings``, which
``GET /settings`` also returned in clear.
"""

from __future__ import annotations

import importlib.util
import logging
import pathlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.crypto import decrypt_str, encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit_forward import AuditForwardTarget
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services import audit_forward as svc
from app.services.forward_secrets import apply_write_only, redact, url_display

# Fixtures only; nothing here is ever contacted.
_SLACK = "https://hooks.slack.example/services/T0FIXTURE/B0FIXTURE/s3cr3tPathToken"
_TEAMS = (
    "https://prod.westus.environment.example:443/workflows/abc/triggers/manual/paths/"
    "invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=s1gN4tureFixture"
)
_GENERIC = "https://collector.example.test/ingest/t0kenInPath"
_AUTH = "Bearer hdr-fixture-9f8e7d"

_MIGRATION = (
    pathlib.Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "e51ab0dede3e_forward_webhook_secrets_encrypted.py"
)

_TARGETS = "/api/v1/settings/audit-forward-targets"


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"fw-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Forward Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _webhook_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": f"chat-{uuid.uuid4().hex[:6]}",
        "enabled": True,
        "kind": "webhook",
        "webhook_flavor": "generic",
        "url": _GENERIC,
        "auth_header": _AUTH,
    }
    body.update(overrides)
    return body


async def _raw(db: AsyncSession, target_id: str) -> tuple[bytes | None, bytes | None]:
    row = (
        await db.execute(
            text(
                "SELECT url_encrypted, auth_header_encrypted FROM audit_forward_target "
                "WHERE id = :id"
            ),
            {"id": target_id},
        )
    ).one()
    return (
        bytes(row[0]) if row[0] is not None else None,
        bytes(row[1]) if row[1] is not None else None,
    )


def _session_from(db: AsyncSession):  # noqa: ANN202
    """Point the service's ephemeral session at the test transaction."""

    @asynccontextmanager
    async def _ctx() -> AsyncIterator[AsyncSession]:
        yield db

    return _ctx


# ── helpers ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        (_SLACK, "https://hooks.slack.example/…"),
        (_TEAMS, "https://prod.westus.environment.example:443/…"),
        ("https://user:pw@collector.example.test", "https://collector.example.test/…"),
        ("https://collector.example.test/", "https://collector.example.test"),
        ("http://[2001:db8::1]:8080/x", "http://[2001:db8::1]:8080/…"),
        ("not a url", "…"),
        ("", ""),
    ],
)
def test_url_display_is_scheme_and_host_only(url: str, shown: str) -> None:
    assert url_display(url) == shown


def test_write_only_contract() -> None:
    stored = encrypt_str("old")
    assert apply_write_only(stored, None) is stored
    assert apply_write_only(stored, "") is None
    new = apply_write_only(stored, "new")
    assert new is not None and decrypt_str(new) == "new"


def test_redact_catches_a_renormalised_url() -> None:
    # httpx renders the URL its own way; the path and query alone must go too.
    text_in = (
        f"POST https://HOOKS.slack.example/services/T0FIXTURE/B0FIXTURE/s3cr3tPathToken {_AUTH}"
    )
    out = redact(text_in, _SLACK, _AUTH)
    assert "s3cr3tPathToken" not in out and "hdr-fixture" not in out
    assert "sig=s1gN4ture" not in redact(f"failed: {_TEAMS}", _TEAMS)


# ── send path: logs and errors ─────────────────────────────────────


async def test_the_httpx_request_line_shows_only_the_host(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """httpx logs every request with its full URL at INFO."""
    seen: list[httpx.Request] = []

    class _Client(httpx.AsyncClient):
        def __init__(self, *args: object, **kwargs: object) -> None:
            def _handler(request: httpx.Request) -> httpx.Response:
                seen.append(request)
                return httpx.Response(200)

            kwargs["transport"] = httpx.MockTransport(_handler)
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    caplog.set_level(logging.INFO, logger="httpx")
    with patch.object(svc.httpx, "AsyncClient", _Client):
        await svc._send_webhook(_SLACK, "", {"text": "hi"})  # noqa: SLF001

    assert str(seen[0].url) == _SLACK  # the real URL was still used
    lines = [r.getMessage() for r in caplog.records if r.name == "httpx"]
    assert lines and all("s3cr3tPathToken" not in line for line in lines), lines
    assert any("https://hooks.slack.example/…" in line for line in lines), lines


async def test_a_delivery_failure_log_does_not_quote_the_url() -> None:
    target = {
        "name": "chat",
        "kind": "webhook",
        "webhook_flavor": "generic",
        "url": _GENERIC,
        "auth_header": _AUTH,
        "min_severity": None,
        "resource_types": None,
    }
    boom = AsyncMock(side_effect=RuntimeError(f"cannot reach {_GENERIC} with {_AUTH}"))
    with capture_logs() as logs, patch.object(svc, "_send_webhook", new=boom):
        await svc._deliver_to_target(target, {"action": "x", "result": "success"})  # noqa: SLF001
    failed = [e for e in logs if e["event"] == "audit_forward_target_failed"]
    assert failed, logs
    assert "t0kenInPath" not in str(failed) and "hdr-fixture" not in str(failed)


# ── API + storage ──────────────────────────────────────────────────


async def test_create_stores_ciphertext_and_returns_no_secret(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    resp = await client.post(_TARGETS, headers=headers, json=_webhook_body())
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "url" not in data and "auth_header" not in data
    assert data["url_set"] is True and data["auth_header_set"] is True
    assert data["url_display"] == "https://collector.example.test/…"
    assert "t0kenInPath" not in resp.text and "hdr-fixture" not in resp.text

    url_ct, auth_ct = await _raw(db_session, data["id"])
    assert url_ct and auth_ct
    assert b"t0kenInPath" not in url_ct and b"hdr-fixture" not in auth_ct
    assert decrypt_str(url_ct) == _GENERIC and decrypt_str(auth_ct) == _AUTH

    listed = await client.get(_TARGETS, headers=headers)
    assert "t0kenInPath" not in listed.text and "hdr-fixture" not in listed.text


async def test_an_update_without_the_secrets_keeps_them(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The UI leaves both out to mean "keep"; the header used to be wiped."""
    headers = await _admin(db_session)
    body = _webhook_body()
    created = (await client.post(_TARGETS, headers=headers, json=body)).json()
    tid = created["id"]

    edit = {k: v for k, v in body.items() if k not in ("url", "auth_header")}
    resp = await client.put(f"{_TARGETS}/{tid}", headers=headers, json={**edit, "enabled": False})
    assert resp.status_code == 200, resp.text
    assert resp.json()["url_set"] is True and resp.json()["auth_header_set"] is True
    url_ct, auth_ct = await _raw(db_session, tid)
    assert url_ct and decrypt_str(url_ct) == _GENERIC
    assert auth_ct and decrypt_str(auth_ct) == _AUTH

    # ``null`` keeps too; ``""`` clears; a value replaces.
    resp = await client.put(
        f"{_TARGETS}/{tid}",
        headers=headers,
        json={**edit, "url": _SLACK, "auth_header": "", "webhook_flavor": "slack"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["auth_header_set"] is False
    assert resp.json()["url_display"] == "https://hooks.slack.example/…"
    url_ct, auth_ct = await _raw(db_session, tid)
    assert url_ct and decrypt_str(url_ct) == _SLACK and auth_ct is None

    resp = await client.put(
        f"{_TARGETS}/{tid}", headers=headers, json={**edit, "url": None, "auth_header": None}
    )
    assert resp.status_code == 200, resp.text
    url_ct, _ = await _raw(db_session, tid)
    assert url_ct and decrypt_str(url_ct) == _SLACK


async def test_a_failed_save_does_not_echo_the_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """SQLAlchemy's error text lists every bound parameter of the INSERT."""
    headers = await _admin(db_session)
    body = _webhook_body()
    assert (await client.post(_TARGETS, headers=headers, json=body)).status_code == 201
    resp = await client.post(_TARGETS, headers=headers, json=body)  # same name
    assert resp.status_code == 400, resp.text
    assert "create failed" in resp.text
    assert "t0kenInPath" not in resp.text and "hdr-fixture" not in resp.text
    assert "[parameters:" not in resp.text


async def test_the_send_path_decrypts_and_posts_to_the_stored_url(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    created = (
        await client.post(
            _TARGETS,
            headers=headers,
            json=_webhook_body(name="discord-ish", url=_SLACK, webhook_flavor="slack"),
        )
    ).json()
    await client.post(_TARGETS, headers=headers, json=_webhook_body(name="collector"))

    with patch.object(svc, "_ephemeral_session", _session_from(db_session)):
        targets = await svc._load_targets()  # noqa: SLF001
    by_name = {t["name"]: t for t in targets}
    assert by_name["discord-ish"]["url"] == _SLACK
    assert by_name["collector"]["url"] == _GENERIC
    assert by_name["collector"]["auth_header"] == _AUTH

    send = AsyncMock()
    with patch.object(svc, "_send_webhook", new=send):
        for t in targets:
            await svc._deliver_to_target(t, {"action": "x", "result": "success"})  # noqa: SLF001
    posted = {call.args[0]: call.args[1] for call in send.await_args_list}
    # A chat flavor never forwards the header; generic does.
    assert posted == {_SLACK: "", _GENERIC: _AUTH}

    # The Test button goes through the same decryption.
    send.reset_mock()
    with patch.object(svc, "_send_webhook", new=send):
        resp = await client.post(f"{_TARGETS}/{created['id']}/test", headers=headers)
    assert resp.status_code == 200, resp.text
    assert send.await_args is not None and send.await_args.args[0] == _SLACK


async def test_an_undecryptable_url_skips_the_target(db_session: AsyncSession) -> None:
    db_session.add(
        AuditForwardTarget(
            name=f"stale-{uuid.uuid4().hex[:6]}",
            kind="webhook",
            url_encrypted=b"not-a-fernet-token",
        )
    )
    await db_session.flush()
    with patch.object(svc, "_ephemeral_session", _session_from(db_session)):
        targets = await svc._load_targets()  # noqa: SLF001
    assert all(t["kind"] != "webhook" for t in targets)


# ── legacy single webhook on platform_settings ─────────────────────


async def test_the_legacy_settings_webhook_is_write_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    with capture_logs() as logs:
        resp = await client.put(
            "/api/v1/settings",
            headers=headers,
            json={
                "audit_forward_webhook_enabled": True,
                "audit_forward_webhook_url": _TEAMS,
                "audit_forward_webhook_auth_header": _AUTH,
            },
        )
    assert resp.status_code == 200, resp.text
    for leak in ("s1gN4tureFixture", "hdr-fixture"):
        assert leak not in resp.text
        assert leak not in str(logs)
    data = resp.json()
    assert "audit_forward_webhook_url" not in data
    assert "audit_forward_webhook_auth_header" not in data
    assert data["audit_forward_webhook_url_set"] is True
    assert data["audit_forward_webhook_auth_header_set"] is True
    assert data["audit_forward_webhook_url_display"] == (
        "https://prod.westus.environment.example:443/…"
    )

    ps = (await db_session.execute(select(PlatformSettings))).scalar_one()
    assert ps.audit_forward_webhook_url_encrypted
    assert decrypt_str(ps.audit_forward_webhook_url_encrypted) == _TEAMS

    got = await client.get("/api/v1/settings", headers=headers)
    assert "s1gN4tureFixture" not in got.text and "hdr-fixture" not in got.text

    # With no targets configured, the legacy fallback decrypts it.
    with patch.object(svc, "_ephemeral_session", _session_from(db_session)):
        targets = await svc._load_targets()  # noqa: SLF001
    legacy = [t for t in targets if t["kind"] == "webhook"]
    assert legacy and legacy[0]["url"] == _TEAMS and legacy[0]["auth_header"] == _AUTH

    # An explicit empty string clears.
    resp = await client.put(
        "/api/v1/settings", headers=headers, json={"audit_forward_webhook_auth_header": ""}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["audit_forward_webhook_auth_header_set"] is False
    assert resp.json()["audit_forward_webhook_url_set"] is True


# ── support bundle ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("line", "secret", "kept"),
    [
        (
            "POST https://hooks.slack.com/services/T0000FAKE/B0000FAKE/fakeFakeFake000",
            "fakeFakeFake000",
            "https://hooks.slack.com/",
        ),
        (
            "POST https://discord.com/api/webhooks/123456789012345678/fAkE-tOkEn_000",
            "fAkE-tOkEn_000",
            "https://discord.com/api/webhooks/",
        ),
        (
            "POST https://tenant.webhook.office.com/webhookb2/0000-fake@0000/IncomingWebhook/x",
            "IncomingWebhook",
            "https://tenant.webhook.office.com/",
        ),
        (
            f"POST {_TEAMS} 202",
            "s1gN4tureFixture",
            "sv=1.0&sig=",
        ),
    ],
)
def test_the_support_bundle_scrubber_strips_chat_webhook_secrets(
    line: str, secret: str, kept: str
) -> None:
    """A log line that prints a chat webhook URL by some other route than
    httpx (which the sender already filters) must not ship it either."""
    from app.services.support_bundle.scrub import redact_secrets

    cleaned, kinds = redact_secrets(line)
    assert secret not in cleaned and kept in cleaned, cleaned
    assert kinds
    # Idempotent: the replacement does not re-trigger the safety net.
    assert redact_secrets(cleaned)[1] == []


# ── backups ────────────────────────────────────────────────────────


def test_an_exclude_secrets_archive_nulls_the_plaintext_leftovers() -> None:
    from app.services.backup.archive import _scrub_dump_text

    dump = (
        'COPY "public"."audit_forward_target" ("id", "name", "url", "auth_header", '
        '"url_encrypted", "auth_header_encrypted") FROM stdin;\n'
        "1\tchat\thttps://old.example/x\tBearer y\t\\\\x6162\t\\\\x6364\n"
        "\\.\n"
        'COPY "public"."platform_settings" ("id", "audit_forward_webhook_url", '
        '"audit_forward_webhook_auth_header", "audit_forward_webhook_url_encrypted", '
        '"audit_forward_webhook_auth_header_encrypted") FROM stdin;\n'
        "1\thttps://old.example/y\tBasic z\t\\\\x6566\t\\\\x6768\n"
        "\\.\n"
    )
    lines = _scrub_dump_text(dump).splitlines()
    assert lines[1].split("\t") == ["1", "chat", "\\N", "\\N", "\\\\x", "\\\\x"]
    assert lines[4].split("\t") == ["1", "\\N", "\\N", "\\\\x", "\\\\x"]


# ── migration ──────────────────────────────────────────────────────


async def test_the_migration_encrypts_existing_plaintext(db_session: AsyncSession) -> None:
    """Replay the upgrade (and downgrade) against the pre-#1502 shape. The DDL
    runs in the test's transaction, which the fixture rolls back."""
    spec = importlib.util.spec_from_file_location("m_e51ab0dede3e", _MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    target = AuditForwardTarget(name=f"m-{uuid.uuid4().hex[:6]}", kind="webhook")
    db_session.add(target)
    if await db_session.get(PlatformSettings, 1) is None:
        db_session.add(PlatformSettings(id=1))
    await db_session.flush()

    # The test schema is built from the models, which no longer map the
    # plaintext columns; on an upgrading install they are there, NOT NULL.
    for table, plain, encrypted in module._PAIRS:  # noqa: SLF001
        await db_session.execute(
            text(f"ALTER TABLE {table} ADD COLUMN {plain} VARCHAR(1024) NOT NULL DEFAULT ''")
        )
        await db_session.execute(text(f"ALTER TABLE {table} DROP COLUMN {encrypted}"))
    await db_session.execute(
        text("UPDATE audit_forward_target SET url = :u, auth_header = :a WHERE id = :id"),
        {"u": _SLACK, "a": _AUTH, "id": target.id},
    )
    await db_session.execute(
        text("UPDATE platform_settings SET audit_forward_webhook_url = :u WHERE id = 1"),
        {"u": _GENERIC},
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
            text(
                "SELECT url, auth_header, url_encrypted, auth_header_encrypted "
                "FROM audit_forward_target WHERE id = :id"
            ),
            {"id": target.id},
        )
    ).one()
    # Kept, unread, for the old pods of a rolling upgrade; next release drops it.
    assert row[0] == _SLACK
    assert decrypt_str(bytes(row[2])) == _SLACK and decrypt_str(bytes(row[3])) == _AUTH
    ps = (
        await db_session.execute(
            text(
                "SELECT audit_forward_webhook_url_encrypted, "
                "audit_forward_webhook_auth_header_encrypted FROM platform_settings WHERE id = 1"
            )
        )
    ).one()
    assert decrypt_str(bytes(ps[0])) == _GENERIC and ps[1] is None
    nullable = {
        r[0]: r[1]
        for r in (
            await db_session.execute(
                text(
                    "SELECT column_name, is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'audit_forward_target' "
                    "AND column_name IN ('url', 'auth_header')"
                )
            )
        ).all()
    }
    # So the "exclude secrets" archive's NULL restores.
    assert nullable == {"url": "YES", "auth_header": "YES"}

    # Downgrade copies a value changed since the upgrade back into the clear.
    await db_session.execute(
        text("UPDATE audit_forward_target SET url_encrypted = :v WHERE id = :id"),
        {"v": encrypt_str(_TEAMS), "id": target.id},
    )
    await conn.run_sync(_run("downgrade"))
    back = (
        await db_session.execute(
            text("SELECT url FROM audit_forward_target WHERE id = :id"), {"id": target.id}
        )
    ).scalar_one()
    assert back == _TEAMS

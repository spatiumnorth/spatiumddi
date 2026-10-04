"""Telegram delivery for webhook forward targets (``webhook_flavor="telegram"``).

Covers the rendered message (HTML escaping, truncation, severity icons),
the request that reaches the Bot API (URL, chat fields), how Telegram's
error answers are reported, the create/update validation, the token's
storage (Fernet at rest, write-only in the API), and that the token never
shows up in a log line, an exception message or an API response.

The Bot API is never contacted: the send path runs through a real
``httpx.AsyncClient`` on an ``httpx.MockTransport``, so the request is
built and logged exactly as in production.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_str
from app.core.security import create_access_token, hash_password
from app.models.audit_forward import AuditForwardTarget
from app.models.auth import User
from app.services import audit_forward as svc

# Obviously fake, but shaped like a real token so the validators accept it.
TOKEN = "123456789:AAFakeTokenForTestsOnly_abcdefghijkl"
OTHER_TOKEN = "987654321:AAAnotherFakeTokenForTests_zyxwvuts"
CHAT_ID = "-1001234567890"


# ── Payload helpers (same shapes as test_audit_forward.py) ─────────


def _audit(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "evt-1",
        "timestamp": "2026-04-22T12:00:00+00:00",
        "action": "create",
        "resource_type": "dns_zone",
        "resource_id": "z-1",
        "resource_display": "example.com.",
        "result": "success",
        "user_id": "u-1",
        "user_display_name": "alice",
        "auth_source": "local",
        "changed_fields": ["name"],
        "old_value": None,
        "new_value": {"name": "example.com."},
    }
    base.update(overrides)
    return base


def _alert(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "alert",
        "rule_id": "rule-1",
        "rule_name": "Appliance storage degraded",
        "rule_type": "appliance_storage_degraded",
        "severity": "critical",
        "fired_at": "2026-04-22T12:00:00+00:00",
        "subject_type": "appliance",
        "subject_id": "ap-1",
        "subject_display": "ddi1",
        "message": "array root_a is degraded (1 of 2 members)",
    }
    base.update(overrides)
    return base


def _digest(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "digest",
        "title": "SpatiumDDI Daily Operator Digest",
        "severity": "info",
        "resource_type": "ai.digest",
        "fired_at": "2026-04-22T06:00:00+00:00",
        "message": "all quiet",
        "summary": "all quiet",
    }
    base.update(overrides)
    return base


def _target(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "tg",
        "kind": "webhook",
        "webhook_flavor": "telegram",
        "url": "",
        "auth_header": "",
        "telegram_bot_token": TOKEN,
        "telegram_chat_id": CHAT_ID,
        "telegram_message_thread_id": None,
        "telegram_api_base": "",
        "min_severity": None,
        "resource_types": None,
    }
    base.update(overrides)
    return base


def _utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


# ── Message rendering ──────────────────────────────────────────────


def test_alert_renders_as_html_with_severity_icon() -> None:
    body = svc._shape_webhook_body("telegram", _alert())
    assert body == {
        "text": (
            "🚨 <b>[CRITICAL] Appliance storage degraded</b>\n"
            "ddi1\narray root_a is degraded (1 of 2 members)"
        ),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }


def test_digest_and_audit_payloads_render() -> None:
    digest = svc._shape_webhook_body("telegram", _digest())["text"]
    assert digest == "ℹ️ <b>SpatiumDDI Daily Operator Digest</b>\nall quiet"
    # The "Test target" button sends an audit-shaped payload.
    audit = svc._shape_webhook_body("telegram", _audit())["text"]
    assert audit == "ℹ️ <b>create · dns_zone</b>\nexample.com. (success) by alice"


@pytest.mark.parametrize(
    ("payload", "icon"),
    [
        (_alert(severity="warning"), "⚠️"),
        (_alert(severity="info"), "ℹ️"),
        (_audit(result="denied"), "⛔"),
        (_audit(result="failed"), "🚨"),
    ],
)
def test_severity_icons(payload: dict[str, Any], icon: str) -> None:
    assert svc._shape_webhook_body("telegram", payload)["text"].startswith(icon + " <b>")


def test_no_slack_markup_leaks_into_telegram() -> None:
    """The workaround this replaces (the Slack flavor pointed at the Bot
    API) rendered ``:rotating_light:`` and ``*title*`` literally."""
    text = svc._shape_webhook_body("telegram", _alert())["text"]
    assert ":rotating_light:" not in text
    assert "*" not in text


def test_dynamic_text_is_html_escaped() -> None:
    text = svc._shape_webhook_body(
        "telegram",
        _alert(
            rule_name="<b>rule</b> & co",
            subject_display="a<b",
            message='x > y & "z" <script>',
        ),
    )["text"]
    assert "&lt;b&gt;rule&lt;/b&gt; &amp; co" in text
    assert "a&lt;b" in text
    assert 'x &gt; y &amp; "z" &lt;script&gt;' in text
    # The only tags are the ones we emit.
    assert re.findall(r"<[^>]*>", text) == ["<b>", "</b>"]


def test_long_text_is_truncated_without_cutting_an_entity() -> None:
    # Every raw "&" becomes the five-character "&amp;"; a cut in the
    # wrong place would leave "&am", which Telegram rejects outright.
    text = svc._shape_webhook_body("telegram", _digest(summary="&" * 5000))["text"]
    assert _utf16_len(text) <= 4096
    assert text.endswith("&amp;…")
    body = text.split("\n", 1)[1]
    assert re.fullmatch(r"(&amp;)+…", body)


def test_truncation_counts_utf16_units() -> None:
    """Telegram measures in UTF-16 code units; an emoji outside the BMP is
    two of them, so counting Python characters would overshoot."""
    text = svc._shape_webhook_body("telegram", _digest(summary="😀" * 3000))["text"]
    assert _utf16_len(text) <= 4096
    assert text.endswith("…")


def test_short_text_is_not_truncated() -> None:
    text = svc._shape_webhook_body("telegram", _digest(summary="x" * 3000))["text"]
    assert "…" not in text
    assert text.endswith("x" * 3000)


# ── The request that reaches the Bot API ───────────────────────────


def _mock_client(handler: Callable[[httpx.Request], httpx.Response]) -> Callable[[], Any]:
    transport = httpx.MockTransport(handler)

    def factory() -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport, timeout=5.0)

    return factory


class _Recorder:
    """A Bot API stand-in: records requests, answers from a queue."""

    def __init__(self, *responses: httpx.Response) -> None:
        self.requests: list[httpx.Request] = []
        self._responses = list(responses) or [httpx.Response(200, json={"ok": True})]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]

    def json(self, i: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[i].content)


async def test_send_posts_to_the_bot_api_with_chat_fields() -> None:
    api = _Recorder()
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        await svc._deliver_to_target(_target(telegram_message_thread_id=42), _alert())
    assert len(api.requests) == 1
    req = api.requests[0]
    assert req.method == "POST"
    assert str(req.url) == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert req.headers["content-type"] == "application/json"
    sent = api.json()
    assert sent["chat_id"] == -1001234567890  # an integer, not a string
    assert sent["message_thread_id"] == 42
    assert sent["parse_mode"] == "HTML"
    assert sent["disable_web_page_preview"] is True
    assert sent["text"].startswith("🚨 <b>[CRITICAL] Appliance storage degraded</b>")


async def test_channel_username_and_no_topic() -> None:
    api = _Recorder()
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        await svc._deliver_to_target(_target(telegram_chat_id="@my_alerts_channel"), _audit())
    sent = api.json()
    assert sent["chat_id"] == "@my_alerts_channel"
    assert "message_thread_id" not in sent


async def test_self_hosted_api_base() -> None:
    api = _Recorder()
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        await svc._deliver_to_target(
            _target(telegram_api_base="https://bot-api.example.com/"), _audit()
        )
    assert str(api.requests[0].url) == f"https://bot-api.example.com/bot{TOKEN}/sendMessage"


async def test_telegram_never_goes_through_the_generic_webhook_sender() -> None:
    api = _Recorder()
    with (
        patch.object(svc, "_telegram_client", new=_mock_client(api)),
        patch.object(svc, "_send_webhook", new=AsyncMock()) as generic,
    ):
        await svc._deliver_to_target(_target(), _alert())
    generic.assert_not_awaited()
    assert len(api.requests) == 1


async def test_min_severity_still_gates_telegram() -> None:
    api = _Recorder()
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        await svc._deliver_to_target(_target(min_severity="error"), _alert(severity="info"))
    assert api.requests == []


# ── Telegram's error answers ───────────────────────────────────────


async def _send_expecting_error(*responses: httpx.Response) -> tuple[str, _Recorder]:
    api = _Recorder(*responses)
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        with pytest.raises(svc.TelegramDeliveryError) as err:
            await svc._deliver_to_target(_target(), _alert(), raise_errors=True)
    msg = str(err.value)
    assert TOKEN not in msg
    return msg, api


async def test_chat_not_found_is_explained() -> None:
    msg, _ = await _send_expecting_error(
        httpx.Response(
            400,
            json={"ok": False, "error_code": 400, "description": "Bad Request: chat not found"},
        )
    )
    assert "Bad Request: chat not found" in msg
    assert "bot has been added to that chat" in msg


async def test_forbidden_is_explained() -> None:
    msg, _ = await _send_expecting_error(
        httpx.Response(
            403,
            json={
                "ok": False,
                "error_code": 403,
                "description": "Forbidden: bot is not a member of the channel chat",
            },
        )
    )
    assert "bot is not a member of the channel chat" in msg
    assert "admin allowed to post" in msg


async def test_bad_token_is_explained() -> None:
    msg, _ = await _send_expecting_error(
        httpx.Response(401, json={"ok": False, "error_code": 401, "description": "Unauthorized"})
    )
    assert "rejected the bot token" in msg


async def test_non_json_error_reports_the_status() -> None:
    msg, _ = await _send_expecting_error(httpx.Response(502, text="<html>bad gateway</html>"))
    assert "HTTP 502" in msg
    assert "<html>" not in msg


async def test_short_429_is_retried_once() -> None:
    api = _Recorder(
        httpx.Response(
            429,
            json={
                "ok": False,
                "error_code": 429,
                "description": "Too Many Requests: retry after 2",
                "parameters": {"retry_after": 2},
            },
        ),
        httpx.Response(200, json={"ok": True}),
    )
    with (
        patch.object(svc, "_telegram_client", new=_mock_client(api)),
        patch.object(svc.asyncio, "sleep", new=AsyncMock()) as sleep,
    ):
        await svc._deliver_to_target(_target(), _alert(), raise_errors=True)
    sleep.assert_awaited_once_with(2)
    assert len(api.requests) == 2


async def test_long_429_is_reported_not_waited_out() -> None:
    limited = httpx.Response(
        429,
        json={
            "ok": False,
            "error_code": 429,
            "description": "Too Many Requests: retry after 30",
            "parameters": {"retry_after": 30},
        },
    )
    with patch.object(svc.asyncio, "sleep", new=AsyncMock()) as sleep:
        msg, api = await _send_expecting_error(limited)
    sleep.assert_not_awaited()
    assert len(api.requests) == 1
    assert "rate-limited the bot for 30 s" in msg


async def test_429_is_retried_at_most_once() -> None:
    limited = httpx.Response(
        429,
        json={"ok": False, "error_code": 429, "parameters": {"retry_after": 1}},
    )
    with patch.object(svc.asyncio, "sleep", new=AsyncMock()):
        msg, api = await _send_expecting_error(limited)
    assert len(api.requests) == 2
    assert "rate-limited" in msg


async def test_failure_is_logged_and_swallowed_by_default() -> None:
    """Alert fan-out and audit forwarding must not be broken by one dead
    target — the log-and-continue contract the other kinds follow."""
    api = _Recorder(httpx.Response(400, json={"ok": False, "description": "chat not found"}))
    with (
        patch.object(svc, "_telegram_client", new=_mock_client(api)),
        patch.object(svc, "logger", new=MagicMock()) as log,
    ):
        await svc._deliver_to_target(_target(), _alert())  # no raise
    log.warning.assert_called_once()
    assert log.warning.call_args.args[0] == "audit_forward_target_failed"
    assert "chat not found" in log.warning.call_args.kwargs["error"]


# ── The token never leaks ──────────────────────────────────────────


async def test_httpx_request_log_line_does_not_carry_the_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """httpx logs ``HTTP Request: POST <full url>`` at INFO, and the app's
    root logger runs at INFO — so without the filter every delivery wrote
    the token to the log."""
    caplog.set_level(logging.INFO, logger="httpx")
    api = _Recorder()
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        await svc._deliver_to_target(_target(), _alert())
    lines = [r.getMessage() for r in caplog.records if r.name == "httpx"]
    assert lines, "expected httpx's request log line"
    assert all(TOKEN not in line for line in lines)
    assert any("/bot[REDACTED]/sendMessage" in line for line in lines)


async def test_transport_error_does_not_carry_the_token() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

    with (
        patch.object(svc, "_telegram_client", new=_mock_client(boom)),
        patch.object(svc, "logger", new=MagicMock()) as log,
    ):
        with pytest.raises(svc.TelegramDeliveryError) as err:
            await svc._deliver_to_target(_target(), _alert(), raise_errors=True)
    assert TOKEN not in str(err.value)
    assert "Could not reach the Telegram Bot API at https://api.telegram.org" in str(err.value)
    # ``from None`` — no chained httpx exception (which holds the URL).
    assert err.value.__cause__ is None and err.value.__suppress_context__
    logged = json.dumps(log.warning.call_args.kwargs)
    assert TOKEN not in logged


def test_redaction_helper() -> None:
    line = f"POST https://api.telegram.org/bot{TOKEN}/sendMessage failed"
    assert svc.redact_telegram_tokens(line) == (
        "POST https://api.telegram.org/bot[REDACTED]/sendMessage failed"
    )
    # Ordinary text with colons is left alone.
    for text in ("12:30:45", "2001:db8::1", "dns_zone:create", "port 5432:tcp"):
        assert svc.redact_telegram_tokens(text) == text


# ── API: create / update / test ────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _body(**overrides: object) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "Telegram ops",
        "enabled": True,
        "kind": "webhook",
        "webhook_flavor": "telegram",
        "telegram_bot_token": TOKEN,
        "telegram_chat_id": CHAT_ID,
    }
    base.update(overrides)
    return base


_URL = "/api/v1/settings/audit-forward-targets"


async def test_create_stores_the_token_encrypted_and_never_returns_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    r = await client.post(_URL, headers=h, json=_body(telegram_message_thread_id=7))
    assert r.status_code == 201, r.text
    assert TOKEN not in r.text
    created = r.json()
    assert created["webhook_flavor"] == "telegram"
    assert created["telegram_bot_token_set"] is True
    assert created["telegram_chat_id"] == CHAT_ID
    assert created["telegram_message_thread_id"] == 7
    assert created["telegram_api_base"] == ""
    assert "telegram_bot_token" not in created

    row = await db_session.get(AuditForwardTarget, uuid.UUID(created["id"]))
    assert row is not None
    assert row.telegram_bot_token_encrypted
    assert TOKEN.encode() not in row.telegram_bot_token_encrypted
    assert decrypt_str(row.telegram_bot_token_encrypted) == TOKEN

    r = await client.get(_URL, headers=h)
    assert r.status_code == 200
    assert TOKEN not in r.text
    assert r.json()[0]["telegram_bot_token_set"] is True


async def test_update_without_a_token_keeps_the_stored_one(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    r = await client.post(_URL, headers=h, json=_body())
    target_id = r.json()["id"]

    body = _body(telegram_chat_id="@my_alerts_channel")
    del body["telegram_bot_token"]
    r = await client.put(f"{_URL}/{target_id}", headers=h, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["telegram_chat_id"] == "@my_alerts_channel"
    assert r.json()["telegram_bot_token_set"] is True
    # An empty string from the form means the same as omitting it.
    r = await client.put(f"{_URL}/{target_id}", headers=h, json={**body, "telegram_bot_token": ""})
    assert r.status_code == 200, r.text
    row = await db_session.get(AuditForwardTarget, uuid.UUID(target_id))
    assert row is not None
    await db_session.refresh(row)
    assert decrypt_str(row.telegram_bot_token_encrypted or b"") == TOKEN

    r = await client.put(
        f"{_URL}/{target_id}", headers=h, json={**body, "telegram_bot_token": OTHER_TOKEN}
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(row)
    assert decrypt_str(row.telegram_bot_token_encrypted or b"") == OTHER_TOKEN


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"telegram_bot_token": None}, "telegram_bot_token is required"),
        ({"telegram_bot_token": "  "}, "telegram_bot_token is required"),
        ({"telegram_chat_id": ""}, "telegram_chat_id is required"),
        ({"telegram_chat_id": "not a chat"}, "telegram_chat_id must be"),
        ({"telegram_chat_id": "@abc"}, "telegram_chat_id must be"),
        ({"telegram_api_base": "http://bot-api.example.com"}, "telegram_api_base"),
        ({"telegram_api_base": "https://u:p@bot-api.example.com"}, "telegram_api_base"),
        ({"telegram_api_base": "https://bot-api.example.com/?x=1"}, "telegram_api_base"),
        ({"telegram_message_thread_id": 0}, "telegram_message_thread_id"),
    ],
)
async def test_invalid_telegram_targets_are_422(
    client: AsyncClient, db_session: AsyncSession, overrides: dict[str, Any], fragment: str
) -> None:
    h = await _superadmin(db_session)
    r = await client.post(_URL, headers=h, json=_body(**overrides))
    assert r.status_code == 422, r.text
    assert fragment in r.text
    # A validation error on another field must not echo the token either
    # (FastAPI's 422 body includes the rejected input).
    assert TOKEN not in r.text


@pytest.mark.parametrize(
    "bad_token",
    [
        "not-a-token",
        # Path characters would change the endpoint the URL points at.
        "123456789:AAFakeToken/../../getUpdates",
        "123456789:AAFakeTokenForTestsOnly?chat_id=1",
    ],
)
async def test_malformed_token_is_422_without_echoing_it(
    client: AsyncClient, db_session: AsyncSession, bad_token: str
) -> None:
    h = await _superadmin(db_session)
    r = await client.post(_URL, headers=h, json=_body(telegram_bot_token=bad_token))
    assert r.status_code == 422, r.text
    assert "does not look like a Bot API token" in r.text
    assert bad_token not in r.text


async def test_other_flavors_do_not_need_telegram_fields(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    r = await client.post(
        _URL,
        headers=h,
        json={
            "name": "Slack",
            "kind": "webhook",
            "webhook_flavor": "slack",
            "url": "https://chat.example.com/hook",
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["telegram_bot_token_set"] is False


async def test_test_endpoint_sends_through_telegram(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    target_id = (await client.post(_URL, headers=h, json=_body())).json()["id"]
    api = _Recorder()
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        r = await client.post(f"{_URL}/{target_id}/test", headers=h)
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ok", "target": "Telegram ops"}
    assert TOKEN not in r.text
    assert str(api.requests[0].url) == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    sent = api.json()
    assert sent["chat_id"] == -1001234567890
    assert sent["text"].startswith("ℹ️ <b>test_forward · audit_forward_target</b>\nTelegram ops")


async def test_test_endpoint_surfaces_telegrams_reason(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    target_id = (await client.post(_URL, headers=h, json=_body())).json()["id"]
    api = _Recorder(
        httpx.Response(
            400,
            json={"ok": False, "error_code": 400, "description": "Bad Request: chat not found"},
        )
    )
    with patch.object(svc, "_telegram_client", new=_mock_client(api)):
        r = await client.post(f"{_URL}/{target_id}/test", headers=h)
    assert r.status_code == 502
    assert "chat not found" in r.json()["detail"]
    assert TOKEN not in r.text


async def test_load_targets_decrypts_telegram_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The delivery path reads targets through its own session; point it
    at the test session so the row written through the API is visible."""
    h = await _superadmin(db_session)
    await client.post(_URL, headers=h, json=_body(telegram_message_thread_id=3))

    @asynccontextmanager
    async def _session() -> AsyncIterator[AsyncSession]:
        yield db_session

    with patch.object(svc, "_ephemeral_session", new=_session):
        targets = await svc._load_targets()
    assert len(targets) == 1
    t = targets[0]
    assert t["kind"] == "webhook"
    assert t["webhook_flavor"] == "telegram"
    assert t["telegram_bot_token"] == TOKEN
    assert t["telegram_chat_id"] == CHAT_ID
    assert t["telegram_message_thread_id"] == 3

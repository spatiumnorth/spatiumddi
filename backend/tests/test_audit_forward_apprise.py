"""Apprise as a webhook forward-target flavor (#1503).

A target with ``webhook_flavor="apprise"`` keeps one Apprise service URL in
the encrypted, write-only URL column from #1502. These tests pin the parts
that are ours: validation without echo, the scheme-only display, delivery
off the event loop with our severity mapped, the service's own error text on
the Test button without the token, and that neither our logs nor a support
bundle carry the URL's secret parts.

No real service is contacted. Apprise runs for real; it is cut off at its
own boundary, ``requests.post``, or pointed at a local HTTP server.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.crypto import decrypt_str
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services import alerts
from app.services import apprise_delivery as ad
from app.services import audit_forward as svc

# Fixtures only. The token has the real shape so the scrubbers see what
# they would see in production; it was never issued.
_BOT_ID = "123456789"
_BOT_SECRET = "AAHfixtureFixtureFixtureFixture12345"
_CHAT = "987650001"
_TGRAM = f"tgram://{_BOT_ID}:{_BOT_SECRET}/{_CHAT}"
_TGRAM_B = "tgram://555000111:BBGotherOtherOtherOtherOther6789/42420001"
_NTFY = "ntfys://alice:Ntfy-Passw0rd-fixture@ntfy.example.test/spatium-alerts"

_TARGETS = "/api/v1/settings/audit-forward-targets"


def _telegram_reply(status: int, description: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    body: dict[str, Any] = {"ok": status == 200}
    if description:
        body["description"] = description
        body["error_code"] = status
    else:
        body["result"] = {"message_id": 1}
    resp.content = json.dumps(body).encode()
    resp.text = resp.content.decode()
    return resp


def _assert_no_secret(text_out: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in text_out, (secret, text_out)


# ── local HTTP endpoint for json:// ────────────────────────────────


class _Recorder(BaseHTTPRequestHandler):
    hits: list[tuple[str, dict[str, Any]]] = []
    delay = 0.0

    def do_POST(self) -> None:  # noqa: N802 — stdlib API
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        type(self).hits.append((self.path, body))
        if type(self).delay:
            time.sleep(type(self).delay)
        self.send_response(500 if "fail" in self.path else 200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def local_endpoint() -> Iterator[int]:
    _Recorder.hits = []
    _Recorder.delay = 0.0
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()


# ── URL handling ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        (_TGRAM, "tgram://…"),
        (_NTFY, "ntfys://…"),
        ("pover://ukeyfixture@apptokenfixture", "pover://…"),
        ("JSON://collector.example.test/x", "json://…"),
        ("not a url", "…"),
        ("", ""),
    ],
)
def test_url_display_is_the_scheme_only(url: str, shown: str) -> None:
    assert ad.url_display(url) == shown


def test_scrub_removes_every_secret_part_and_keeps_the_server() -> None:
    needles = ad.secret_needles(_NTFY + "?priority=high&token=QueryT0kenFixture")
    line = (
        "POST https://ntfy.example.test/spatium-alerts as alice with "
        "Ntfy-Passw0rd-fixture token QueryT0kenFixture priority=high"
    )
    out = ad.scrub(line, needles)
    _assert_no_secret(out, "Ntfy-Passw0rd-fixture", "QueryT0kenFixture", "spatium-alerts")
    assert "https://…" in out  # a URL is cut to its scheme
    assert "priority" in out  # option names are not secrets

    tg = ad.scrub(f"/bot{_BOT_ID}:{_BOT_SECRET}/sendMessage", ad.secret_needles(_TGRAM))
    _assert_no_secret(tg, _BOT_ID, _BOT_SECRET)


async def test_check_url_accepts_service_urls_without_sending() -> None:
    def _no_network(*_a: object, **_k: object) -> None:
        raise AssertionError("validation must not make a request")

    with (
        patch("requests.post", _no_network),
        patch("requests.get", _no_network),
        patch.object(requests.Session, "request", _no_network),
    ):
        for url in (
            _TGRAM,
            _NTFY,
            "pover://ukeyfixtureukeyfixtureukeyfi@atokenfixtureatokenfixtureatoke",
            "gotifys://gotify.example.test/AbCdEfGhIjKlMn",
            "json://collector.example.test/hook",
        ):
            assert await ad.check_url(url) is None, url


@pytest.mark.parametrize(
    "url",
    [
        "tgram://not-a-token-but-a-s3cret/1",
        "nosuchscheme://s3cret@example.test/x",
        "not a url at all s3cret",
        f"{_TGRAM}, {_NTFY}",  # one target, one URL
    ],
)
async def test_check_url_rejects_without_echo(url: str) -> None:
    problem = await ad.check_url(url)
    assert problem
    _assert_no_secret(problem, "s3cret", _BOT_SECRET, "Ntfy-Passw0rd-fixture")


# ── sending ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("severity", "apprise_type"),
    [
        ("info", "info"),
        ("warn", "warning"),
        ("warning", "warning"),
        ("error", "failure"),
        ("denied", "failure"),
        ("critical", "failure"),
        ("something-new", "info"),
    ],
)
async def test_send_maps_our_severity(
    local_endpoint: int, severity: str, apprise_type: str
) -> None:
    await ad.send(
        f"json://127.0.0.1:{local_endpoint}/hook",
        title="[CRITICAL] zone drift",
        body="example.test\nserial mismatch",
        severity=severity,
    )
    assert _Recorder.hits, "nothing was posted"
    _, posted = _Recorder.hits[-1]
    assert posted["type"] == apprise_type
    assert posted["title"] == "[CRITICAL] zone drift"
    assert posted["message"] == "example.test\nserial mismatch"


async def test_send_runs_off_the_event_loop() -> None:
    loop_thread = threading.get_ident()
    seen_threads: list[int] = []

    def _slow_post(*_a: object, **_k: object) -> MagicMock:
        seen_threads.append(threading.get_ident())
        time.sleep(0.6)
        return _telegram_reply(200)

    ticks = 0

    async def _ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.05)
            ticks += 1

    ticker = asyncio.create_task(_ticker())
    try:
        with patch("requests.post", _slow_post):
            await ad.send(_TGRAM, title="t", body="b", severity="info")
    finally:
        ticker.cancel()
    assert seen_threads and loop_thread not in seen_threads
    # The loop kept running while the request blocked its thread.
    assert ticks >= 5, ticks


async def test_a_failure_carries_the_service_reason_but_no_secret() -> None:
    with patch("requests.post", return_value=_telegram_reply(400, "Bad Request: chat not found")):
        with pytest.raises(ad.AppriseDeliveryError) as err:
            await ad.send(_TGRAM, title="t", body="b", severity="warning")
    message = str(err.value)
    assert "chat not found" in message
    assert message.startswith("Telegram")
    _assert_no_secret(message, _BOT_SECRET, _BOT_ID, _CHAT, "tgram://1")


async def test_a_hung_service_times_out(local_endpoint: int) -> None:
    _Recorder.delay = 3.0
    started = time.monotonic()
    with patch.object(ad, "CALL_TIMEOUT_SECONDS", 0.5):
        with pytest.raises(ad.AppriseDeliveryError) as err:
            await ad.send(
                f"json://127.0.0.1:{local_endpoint}/hook?rto=10",
                title="t",
                body="b",
                severity="info",
            )
    assert "did not answer" in str(err.value)
    assert time.monotonic() - started < 2.5


async def test_concurrent_sends_keep_their_own_errors() -> None:
    def _post(url: str, *_a: object, **_k: object) -> MagicMock:
        time.sleep(0.2)  # overlap the two calls
        if _BOT_SECRET in url:
            return _telegram_reply(400, "Bad Request: chat not found")
        return _telegram_reply(403, "Forbidden: bot was blocked by the user")

    with patch("requests.post", side_effect=_post):
        results = await asyncio.gather(
            ad.send(_TGRAM, title="a", body="a", severity="info"),
            ad.send(_TGRAM_B, title="b", body="b", severity="info"),
            return_exceptions=True,
        )
    first, second = (str(r) for r in results)
    assert "chat not found" in first and "blocked" not in first
    assert "blocked by the user" in second and "chat not found" not in second
    for message in (first, second):
        _assert_no_secret(message, _BOT_SECRET, "BBGotherOtherOtherOtherOther6789")


async def test_no_log_record_carries_the_secret(
    caplog: pytest.LogCaptureFixture, local_endpoint: int
) -> None:
    """Every logger, every level, during a send, a failure and a validation."""
    caplog.set_level(1)  # below DEBUG: everything that is created
    secret_url = f"json://bob:Js0nPassw0rdFixture@127.0.0.1:{local_endpoint}/T0kenPathSegment"
    with patch.object(logging.getLogger("apprise"), "level", 1):
        await ad.send(secret_url, title="t", body="b", severity="info")
        with patch("requests.post", return_value=_telegram_reply(400, "Unauthorized")):
            with pytest.raises(ad.AppriseDeliveryError):
                await ad.send(_TGRAM, title="t", body="b", severity="info")
        await ad.check_url("tgram://not-a-token-Js0nPassw0rdFixture/1")

    rendered = [(r.name, r.getMessage()) for r in caplog.records]
    for name, message in rendered:
        _assert_no_secret(
            f"{name}: {message}", "Js0nPassw0rdFixture", "T0kenPathSegment", _BOT_SECRET
        )
    # Non-vacuous: urllib3 did log the request line, with the path redacted.
    request_lines = [m for n, m in rendered if n.startswith("urllib3") and "POST" in m]
    assert request_lines and "[redacted]" in request_lines[0], rendered
    # pytest attaches its handler to non-propagating loggers too, so Apprise's
    # own lines (TRACE included) were checked above as well. In the app they
    # never reach a handler: the logger does not propagate.
    assert any(n == "apprise" for n, _ in rendered)
    assert logging.getLogger("apprise").propagate is False


# ── the forwarding service ─────────────────────────────────────────


def _apprise_target(url: str = _TGRAM) -> dict[str, Any]:
    return {
        "name": "phone",
        "kind": "webhook",
        "webhook_flavor": "apprise",
        "url": url,
        "auth_header": "",
        "min_severity": None,
        "resource_types": None,
    }


async def test_deliver_hands_title_body_and_severity_to_apprise() -> None:
    send = AsyncMock()
    alert = {
        "kind": "alert",
        "rule_name": "Zone drift",
        "severity": "critical",
        "subject_display": "example.test",
        "message": "serial mismatch",
    }
    with (
        patch.object(svc.apprise_delivery, "send", send),
        patch.object(svc, "_send_webhook", AsyncMock(side_effect=AssertionError("no JSON POST"))),
    ):
        await svc._deliver_to_target(_apprise_target(), alert)  # noqa: SLF001
    send.assert_awaited_once_with(
        _TGRAM,
        title="[CRITICAL] Zone drift",
        body="example.test\nserial mismatch",
        severity="critical",
    )


async def test_deliver_logs_redacted_and_raises_only_when_asked() -> None:
    with (
        patch("requests.post", return_value=_telegram_reply(400, "Bad Request: chat not found")),
        capture_logs() as logs,
    ):
        await svc._deliver_to_target(_apprise_target(), {"action": "x"})  # noqa: SLF001
        with pytest.raises(ad.AppriseDeliveryError):
            await svc._deliver_to_target(  # noqa: SLF001
                _apprise_target(), {"action": "x"}, raise_errors=True
            )
    failed = [e for e in logs if e["event"] == "audit_forward_target_failed"]
    assert len(failed) == 2 and "chat not found" in failed[0]["error"]
    _assert_no_secret(str(logs), _BOT_SECRET, _BOT_ID)


async def test_an_alert_rule_without_the_webhook_channel_skips_apprise() -> None:
    send = AsyncMock()
    rule = SimpleNamespace(
        id=uuid.uuid4(),
        name="r",
        rule_type="x",
        notify_syslog=False,
        notify_webhook=False,
        notify_smtp=False,
    )
    event = SimpleNamespace(
        id=uuid.uuid4(),
        severity="critical",
        fired_at=datetime.now(UTC),
        subject_type="dns_zone",
        subject_id="1",
        subject_display="example.test",
        message="m",
    )
    with patch.object(svc.apprise_delivery, "send", send):
        assert await alerts._deliver(rule, event, [_apprise_target()]) == (
            False,
            False,
            False,
        )  # noqa: SLF001
        send.assert_not_awaited()
        rule.notify_webhook = True
        assert await alerts._deliver(rule, event, [_apprise_target()]) == (
            False,
            True,
            False,
        )  # noqa: SLF001
    send.assert_awaited_once()


# ── API ────────────────────────────────────────────────────────────


async def _admin(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ap-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Apprise Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "name": f"apprise-{uuid.uuid4().hex[:6]}",
        "enabled": True,
        "kind": "webhook",
        "webhook_flavor": "apprise",
        "url": _TGRAM,
    }
    body.update(overrides)
    return body


async def _stored_url(db: AsyncSession, target_id: str) -> str | None:
    row = (
        await db.execute(
            text("SELECT url_encrypted FROM audit_forward_target WHERE id = :id"),
            {"id": target_id},
        )
    ).one()
    return decrypt_str(bytes(row[0])) if row[0] is not None else None


async def test_create_encrypts_and_shows_only_the_scheme(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    resp = await client.post(_TARGETS, headers=headers, json=_body())
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["webhook_flavor"] == "apprise"
    assert data["url_set"] is True and data["url_display"] == "tgram://…"
    _assert_no_secret(resp.text, _BOT_SECRET, _BOT_ID)
    raw = (
        await db_session.execute(
            text("SELECT url_encrypted FROM audit_forward_target WHERE id = :id"),
            {"id": data["id"]},
        )
    ).scalar_one()
    assert _BOT_SECRET.encode() not in bytes(raw)
    assert await _stored_url(db_session, data["id"]) == _TGRAM
    listed = await client.get(_TARGETS, headers=headers)
    _assert_no_secret(listed.text, _BOT_SECRET, _BOT_ID)


async def test_an_unusable_url_is_a_422_without_echo(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    bad = "tgram://not-a-token-S3cretFixture/1"
    resp = await client.post(_TARGETS, headers=headers, json=_body(url=bad))
    assert resp.status_code == 422, resp.text
    _assert_no_secret(resp.text, "S3cretFixture", "not-a-token")
    listed = await client.get(_TARGETS, headers=headers)
    assert listed.json() == []

    resp = await client.post(_TARGETS, headers=headers, json=_body(url=None))
    assert resp.status_code == 422, resp.text


async def test_update_keeps_the_url_and_guards_flavor_switches(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    body = _body()
    tid = (await client.post(_TARGETS, headers=headers, json=body)).json()["id"]
    edit = {k: v for k, v in body.items() if k != "url"}

    resp = await client.put(f"{_TARGETS}/{tid}", headers=headers, json={**edit, "enabled": False})
    assert resp.status_code == 200, resp.text
    assert await _stored_url(db_session, tid) == _TGRAM

    resp = await client.put(f"{_TARGETS}/{tid}", headers=headers, json={**edit, "url": ""})
    assert resp.status_code == 422, resp.text
    # Away from Apprise with the stored tgram:// URL: refused.
    resp = await client.put(
        f"{_TARGETS}/{tid}", headers=headers, json={**edit, "webhook_flavor": "slack"}
    )
    assert resp.status_code == 422, resp.text
    resp = await client.put(f"{_TARGETS}/{tid}", headers=headers, json={**edit, "url": _NTFY})
    assert resp.status_code == 200, resp.text
    assert resp.json()["url_display"] == "ntfys://…"
    assert await _stored_url(db_session, tid) == _NTFY

    # Into Apprise with a stored https:// webhook URL: refused too.
    generic = {
        "name": f"g-{uuid.uuid4().hex[:6]}",
        "kind": "webhook",
        "webhook_flavor": "generic",
        "url": "https://collector.example.test/in",
    }
    gid = (await client.post(_TARGETS, headers=headers, json=generic)).json()["id"]
    switched = {k: v for k, v in generic.items() if k != "url"} | {"webhook_flavor": "apprise"}
    resp = await client.put(f"{_TARGETS}/{gid}", headers=headers, json=switched)
    assert resp.status_code == 422, resp.text


async def test_the_test_button_reports_the_reason_without_the_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _admin(db_session)
    tid = (await client.post(_TARGETS, headers=headers, json=_body())).json()["id"]

    with patch("requests.post", return_value=_telegram_reply(400, "Bad Request: chat not found")):
        resp = await client.post(f"{_TARGETS}/{tid}/test", headers=headers)
    assert resp.status_code == 502, resp.text
    assert "chat not found" in resp.text
    _assert_no_secret(resp.text, _BOT_SECRET, _BOT_ID)

    with patch("requests.post", return_value=_telegram_reply(200)) as post:
        resp = await client.post(f"{_TARGETS}/{tid}/test", headers=headers)
    assert resp.status_code == 200, resp.text
    assert post.call_args is not None and _BOT_SECRET in post.call_args.args[0]


async def test_load_targets_carries_the_apprise_flavor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from contextlib import asynccontextmanager

    headers = await _admin(db_session)
    await client.post(_TARGETS, headers=headers, json=_body(name="phone"))

    @asynccontextmanager
    async def _session() -> Any:
        yield db_session

    with patch.object(svc, "_ephemeral_session", _session):
        targets = await svc._load_targets()  # noqa: SLF001
        _, legacy_webhook = await svc._load_forward_config()  # noqa: SLF001
    assert [(t["name"], t["webhook_flavor"], t["url"]) for t in targets] == [
        ("phone", "apprise", _TGRAM)
    ]
    # The legacy single-webhook shim is a JSON POST; it never picks Apprise.
    assert legacy_webhook is None


# ── support bundle ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("line", "secrets"),
    [
        (f"url={_TGRAM}", [_BOT_SECRET]),
        (f"POST /bot{_BOT_ID}:{_BOT_SECRET}/sendMessage", [_BOT_SECRET]),
        (_NTFY, ["Ntfy-Passw0rd-fixture"]),
        ("ntfys://tk_abcdefFixture@ntfy.example.test/t", ["tk_abcdefFixture"]),
        ("pover://ukeyFixture1234@appTokenFixture5678", ["ukeyFixture1234", "appTokenFixture5678"]),
        ("gotifys://gotify.example.test/AppT0kenFixture", ["AppT0kenFixture"]),
        ("gotify://gotify.example.test/sub/AppT0kenFixture", ["AppT0kenFixture"]),
        ("matrixs://bob:MatrixPassFixture@hs.example.test/#ops", ["MatrixPassFixture"]),
        ("matrixs://syt_MatrixTokenFixture@hs.example.test", ["syt_MatrixTokenFixture"]),
        ("mmosts://user:MmostPassFixture@chat.example.test/hook", ["MmostPassFixture"]),
        ("json://collector.example.test/in?token=QueryTokenFixture", ["QueryTokenFixture"]),
    ],
)
def test_the_support_bundle_scrubber_strips_apprise_secrets(line: str, secrets: list[str]) -> None:
    from app.services.support_bundle.scrub import redact_secrets

    out, kinds = redact_secrets(line)
    assert kinds, line
    _assert_no_secret(out, *secrets)
    # Idempotent: a cleaned line does not trip the safety net again.
    again, kinds_again = redact_secrets(out)
    assert again == out and not kinds_again

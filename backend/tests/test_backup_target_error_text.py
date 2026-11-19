"""Backup destination errors never store an empty reason (#2402).

httpx's ``ReadTimeout`` / ``WriteTimeout`` carry no message, so the
WebDAV driver stored ``"WebDAV PUT failed: "`` — the operator saw a
failure with no cause. These tests drive the real driver over an httpx
``MockTransport`` that raises the timeout and assert on the text the
runner would store as ``last_run_error``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.core.exc_text import describe_exc
from app.services.backup.targets.base import BackupDestinationError
from app.services.backup.targets.webdav import WebDAVDestination

CONFIG = {
    "url": "https://dav.example.test/backups",
    "username": "u",
    "password": "p",
    "verify_tls": "true",
}


def _patch_client(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    def _client(self: Any, config: dict[str, Any]) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(WebDAVDestination, "_client", _client)


@pytest.mark.asyncio
async def test_put_timeout_names_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, httpx.ReadTimeout(""))
    with pytest.raises(BackupDestinationError) as ei:
        await WebDAVDestination().write(
            config=CONFIG, filename="spatiumddi-backup-20261022-010101.zip", archive_bytes=b"x"
        )
    msg = str(ei.value)
    assert msg.startswith("WebDAV PUT failed: ")
    assert msg != "WebDAV PUT failed: "
    assert "ReadTimeout" in msg
    assert "timed out" in msg


@pytest.mark.asyncio
async def test_test_connection_timeout_is_not_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, httpx.WriteTimeout(""))
    res = await WebDAVDestination().test_connection(config=CONFIG)
    assert res["ok"] is False
    assert "WriteTimeout" in res["error"]


@pytest.mark.asyncio
async def test_non_empty_message_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, httpx.ConnectError("connection refused"))
    with pytest.raises(BackupDestinationError, match="WebDAV PUT failed: connection refused"):
        await WebDAVDestination().write(
            config=CONFIG, filename="spatiumddi-backup-20261022-010101.zip", archive_bytes=b"x"
        )


def test_describe_exc_fallbacks() -> None:
    assert describe_exc(ValueError("boom")) == "boom"
    assert describe_exc(KeyError()) == "KeyError"
    assert "timed out" in describe_exc(TimeoutError())
    assert describe_exc(OSError()) == "OSError"

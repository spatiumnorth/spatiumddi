"""Credentials in a DNS blocklist feed URL stay out of everything but the fetch.

A feed URL may carry credentials — ``https://user:pass@host/list.txt`` or
``?token=…``. The stored URL is what the fetch uses; every other place the URL
or a failed fetch surfaces shows it without them:

* the exception a failed fetch raises (httpx's own message spells out the
  full request URL, and Celery writes the exception into its retry / failure
  log lines and the result backend) — for a status failure, a timeout, and a
  redirect hop whose ``Location`` carries its own credentials;
* the list's ``last_sync_error`` and the worker log lines;
* the REST responses (create / get / list) and the copilot tool, which return
  the URL with its credentials masked;
* an edit that sends the masked URL back unchanged keeps the stored URL, and
  one that would store the mask as the credential is refused.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import traceback
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core import safe_fetch
from app.core.safe_fetch import (
    CREDENTIAL_MASK,
    FetchFailedError,
    has_masked_credentials,
    mask_url_credentials,
    safe_get_text,
)
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSBlockList
from app.services.ai.tools.dns import ListDNSBlockListsArgs, list_dns_blocklists
from app.tasks import dns as dns_tasks

PUBLIC_IP = "93.184.216.34"
USER = "feeduser"
PASSWORD = "pw-Hunter2-xyz"
TOKEN = "tok-Abc123-qrs"
CRED_URL = f"https://{USER}:{PASSWORD}@{PUBLIC_IP}/list.txt?token={TOKEN}&format=hosts"
HOP_PASSWORD = "hop-Secret-777"
HOP_TOKEN = "hop-Token-888"
HOP_URL = f"https://u2:{HOP_PASSWORD}@{PUBLIC_IP}/moved.txt?api_key={HOP_TOKEN}"
SECRETS = (PASSWORD, TOKEN, HOP_PASSWORD, HOP_TOKEN)


def _assert_clean(text: str, where: str) -> None:
    for secret in SECRETS:
        assert secret not in text, f"{secret!r} appears in {where}: {text[:500]}"


def _exc_text(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc)) + repr(exc) + str(exc)


def _handler(kind: str):  # type: ignore[no-untyped-def]
    def handle(request: httpx.Request) -> httpx.Response:
        if kind == "timeout":
            raise httpx.ReadTimeout(f"read timed out for {request.url}", request=request)
        if kind == "connect":
            raise httpx.ConnectError(f"could not reach {request.url}", request=request)
        if kind == "redirect" and "moved" not in request.url.path:
            return httpx.Response(302, headers={"location": HOP_URL})
        code = {"401": 401, "500": 500}.get(kind, 404)
        return httpx.Response(code, text=f"denied for {request.url}")

    return handle


# ── The masking helper ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("url", "masked"),
    [
        (
            CRED_URL,
            f"https://{USER}:{CREDENTIAL_MASK}@{PUBLIC_IP}/list.txt"
            f"?token={CREDENTIAL_MASK}&format=hosts",
        ),
        (
            "https://ghp_abc123@feeds.example/l.txt",
            f"https://{CREDENTIAL_MASK}@feeds.example/l.txt",
        ),
        (
            "https://feeds.example/l.txt?apikey=k1&sig=s1&X-Amz-Signature=s2&page=2",
            f"https://feeds.example/l.txt?apikey={CREDENTIAL_MASK}&sig={CREDENTIAL_MASK}"
            f"&X-Amz-Signature={CREDENTIAL_MASK}&page=2",
        ),
        ("https://feeds.example/hosts.txt", "https://feeds.example/hosts.txt"),
        ("https://feeds.example/l.txt?token=", "https://feeds.example/l.txt?token="),
    ],
)
def test_mask_url_credentials(url: str, masked: str) -> None:
    assert mask_url_credentials(url) == masked
    assert has_masked_credentials(masked) == (masked != url)
    assert not has_masked_credentials(url)


# ── The fetch ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("kind", ["404", "401", "500", "timeout", "connect", "redirect"])
async def test_failed_fetch_error_carries_no_credentials(kind: str) -> None:
    with pytest.raises(FetchFailedError) as info:
        await safe_get_text(CRED_URL, label="t", transport=httpx.MockTransport(_handler(kind)))
    exc = info.value
    assert isinstance(exc, httpx.HTTPError), "a caller's autoretry_for must still match"
    _assert_clean(_exc_text(exc), "the raised exception")
    assert exc.__suppress_context__


# ── The refresh task ──────────────────────────────────────────────────────


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


def _wire_task(monkeypatch: pytest.MonkeyPatch, db: AsyncSession, kind: str) -> None:
    monkeypatch.setattr(
        safe_fetch, "GuardedTransport", lambda **kw: httpx.MockTransport(_handler(kind))
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)


async def _list(db: AsyncSession, name: str = "creds") -> DNSBlockList:
    bl = DNSBlockList(name=name, source_type="url", feed_url=CRED_URL, feed_format="domains")
    db.add(bl)
    await db.commit()
    return bl


@pytest.mark.parametrize("kind", ["404", "401", "500", "timeout", "redirect"])
async def test_refresh_failure_surfaces_carry_no_credentials(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    caplog.set_level(logging.DEBUG)
    _wire_task(monkeypatch, db_session, kind)
    bl = await _list(db_session)

    with pytest.raises(httpx.HTTPError) as info:
        await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    # What Celery logs on retry / failure and stores as the task result.
    _assert_clean(_exc_text(info.value), "the exception Celery records")
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    _assert_clean(bl.last_sync_error or "", "last_sync_error")
    out, err = capfd.readouterr()
    _assert_clean(out + err, "the worker output")
    _assert_clean("\n".join(r.getMessage() for r in caplog.records), "the log records")


async def test_celery_retry_and_failure_records_carry_no_credentials(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    """The task run through Celery itself (eagerly): its retry and failure
    log lines and the stored result carry no credentials."""
    caplog.set_level(logging.DEBUG)
    bl = await _list(db_session, "creds-celery")
    monkeypatch.setattr(
        settings,
        "database_url",
        db_session.bind.url.render_as_string(hide_password=False),  # type: ignore[union-attr]
    )
    monkeypatch.setattr(
        safe_fetch, "GuardedTransport", lambda **kw: httpx.MockTransport(_handler("404"))
    )
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)
    monkeypatch.setattr(dns_tasks.refresh_blocklist_feed, "max_retries", 1)

    result = await asyncio.to_thread(dns_tasks.refresh_blocklist_feed.apply, args=[str(bl.id)])

    assert result.state == "FAILURE"
    _assert_clean(repr(result.result) + str(result.traceback), "the task result")
    out, err = capfd.readouterr()
    logged = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
    assert "retry" in logged.lower(), "the retry path was not exercised"
    _assert_clean(out + err + logged, "the Celery log lines")


# ── The API and the copilot tool ──────────────────────────────────────────


async def _headers(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username="feedcreds",
        email="feedcreds@example.com",
        display_name="feedcreds",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_api_and_tool_return_the_url_masked(
    client: httpx.AsyncClient, db_session: AsyncSession
) -> None:
    user, headers = await _headers(db_session)
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "creds-api", "source_type": "url", "feed_url": CRED_URL},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    _assert_clean(resp.text, "the create response")
    masked = resp.json()["feed_url"]
    assert masked == mask_url_credentials(CRED_URL)
    bl_id = resp.json()["id"]

    for path in (f"/api/v1/dns/blocklists/{bl_id}", "/api/v1/dns/blocklists"):
        resp = await client.get(path, headers=headers)
        assert resp.status_code == 200, resp.text
        _assert_clean(resp.text, path)
        assert masked in resp.text

    rows: list[dict[str, Any]] = await list_dns_blocklists(
        db_session, user, ListDNSBlockListsArgs()
    )
    _assert_clean(repr(rows), "the copilot tool")
    assert rows[0]["feed_url"] == masked

    # The stored URL is untouched — it is what the fetch uses.
    stored = await db_session.get(DNSBlockList, bl_id)
    assert stored is not None
    await db_session.refresh(stored)
    assert stored.feed_url == CRED_URL


async def test_edit_with_masked_url_keeps_or_refuses(
    client: httpx.AsyncClient, db_session: AsyncSession
) -> None:
    _, headers = await _headers(db_session)
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "creds-edit", "source_type": "url", "feed_url": CRED_URL},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    bl_id = resp.json()["id"]
    masked = resp.json()["feed_url"]

    # The form sends the masked URL back along with another change.
    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}",
        json={"feed_url": masked, "description": "edited"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    stored = await db_session.get(DNSBlockList, bl_id)
    assert stored is not None
    await db_session.refresh(stored)
    assert stored.feed_url == CRED_URL
    assert stored.description == "edited"

    # A different URL that still carries the mask would store "***" as the
    # credential: refused, and the stored URL is unchanged.
    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}",
        json={"feed_url": masked.replace("list.txt", "other.txt")},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    _assert_clean(resp.text, "the 422")
    await db_session.refresh(stored)
    assert stored.feed_url == CRED_URL

    # Real new credentials are stored.
    new_url = f"https://{USER}:new-pw-55@{PUBLIC_IP}/list.txt"
    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}", json={"feed_url": new_url}, headers=headers
    )
    assert resp.status_code == 200, resp.text
    assert "new-pw-55" not in resp.text
    await db_session.refresh(stored)
    assert stored.feed_url == new_url

    # Creating a list from a masked URL is refused too.
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "creds-copy", "source_type": "url", "feed_url": masked},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text

"""The DNS blocklist feed fetch goes through the guarded outbound fetch.

A blocklist feed URL is typed by an operator and fetched by the control
plane. These pin that the fetch:

* only speaks http / https, and the API refuses anything else on save;
* refuses loopback, link-local (incl. the cloud-metadata address), the
  unspecified address and IPv4-mapped forms of them — before the request,
  at connect time (a name answered differently the second time), and on
  every redirect hop;
* still reaches private (RFC 1918) addresses, so an internal feed mirror
  keeps working — the same line the shared guard draws for every other
  integration;
* stores a fixed, reader-safe ``last_sync_error`` — never the exception
  text, a resolved address, a response body or the URL's credentials;
* still fetches an ordinary public feed (the control case).
"""

from __future__ import annotations

import contextlib
import socket
from collections.abc import Iterable
from typing import Any

import httpcore
import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import safe_fetch
from app.core.safe_fetch import (
    REDIRECT_LIMIT_MESSAGE,
    SCHEME_REFUSED_MESSAGE,
    TARGET_REFUSED_MESSAGE,
    FetchFailedError,
    FetchRefusedError,
    GuardedTransport,
    safe_get_text,
)
from app.core.security import create_access_token, hash_password
from app.core.ssrf import classify_address
from app.models.auth import User
from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.tasks import dns as dns_tasks

PUBLIC_IP = "93.184.216.34"


class _Recorder:
    """httpx MockTransport handler that records every request it serves."""

    def __init__(self, routes: dict[str, httpx.Response] | None = None) -> None:
        self.routes = routes or {}
        self.seen: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.seen.append(url)
        return self.routes.get(url, httpx.Response(200, text="ok.example\n"))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)


# ── Address classification ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("addr", "reason"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.169.254", "cloud_metadata"),
        ("169.254.10.1", "link_local"),
        ("fe80::1%eth0", "link_local"),
        ("::ffff:127.0.0.1", "loopback"),
        ("::ffff:169.254.169.254", "cloud_metadata"),
        ("0.0.0.0", "unspecified"),
        ("0.1.2.3", "unspecified"),
        ("::", "unspecified"),
        ("10.0.0.5", None),
        ("192.168.1.1", None),
        ("fd00::1", None),
        (PUBLIC_IP, None),
    ],
)
def test_classify_address(addr: str, reason: str | None) -> None:
    assert classify_address(addr) == reason


# ── Before the request ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/feed.txt",
        "http://[::1]/feed.txt",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fe80::1]/feed.txt",
        "http://[::ffff:127.0.0.1]/feed.txt",
        "http://0.0.0.0:8000/feed.txt",
    ],
)
async def test_blocked_targets_refused_before_any_request(url: str) -> None:
    rec = _Recorder()
    with pytest.raises(FetchRefusedError) as ei:
        await safe_get_text(url, label="t", transport=rec.transport())
    assert str(ei.value) == TARGET_REFUSED_MESSAGE
    assert rec.seen == []


@pytest.mark.parametrize(
    "url", ["ftp://feeds.example/list.txt", "file:///etc/passwd", "gopher://x/", "http:///nohost"]
)
async def test_non_http_schemes_refused(url: str) -> None:
    rec = _Recorder()
    with pytest.raises(FetchRefusedError) as ei:
        await safe_get_text(url, label="t", transport=rec.transport())
    assert str(ei.value) == SCHEME_REFUSED_MESSAGE
    assert rec.seen == []


async def test_private_address_feed_is_fetched() -> None:
    """An internal mirror on RFC 1918 space keeps working."""
    rec = _Recorder()
    text = await safe_get_text(
        "http://10.20.30.40/mirror/list.txt", label="t", transport=rec.transport()
    )
    assert text == "ok.example\n"
    assert rec.seen == ["http://10.20.30.40/mirror/list.txt"]


async def test_public_feed_is_fetched() -> None:
    rec = _Recorder()
    text = await safe_get_text(
        f"https://{PUBLIC_IP}/list.txt", label="t", transport=rec.transport()
    )
    assert text == "ok.example\n"


# ── Redirects ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://127.0.0.1:6379/",
        "http://[::1]/",
        "ftp://feeds.example/list.txt",
    ],
)
async def test_redirect_to_blocked_target_refused_at_the_hop(location: str) -> None:
    start = f"http://{PUBLIC_IP}/list.txt"
    rec = _Recorder({start: httpx.Response(302, headers={"location": location})})
    with pytest.raises(FetchRefusedError):
        await safe_get_text(start, label="t", transport=rec.transport())
    # Only the first request was made; the hop was refused before dialling.
    assert rec.seen == [start]


async def test_redirect_to_private_mirror_is_followed() -> None:
    start = f"http://{PUBLIC_IP}/list.txt"
    target = "http://192.168.10.5/list.txt"
    rec = _Recorder({start: httpx.Response(301, headers={"location": target})})
    assert await safe_get_text(start, label="t", transport=rec.transport()) == "ok.example\n"
    assert rec.seen == [start, target]


async def test_redirect_loop_hits_the_hop_limit() -> None:
    start = f"http://{PUBLIC_IP}/a"
    rec = _Recorder({start: httpx.Response(302, headers={"location": "/a"})})
    with pytest.raises(FetchRefusedError) as ei:
        await safe_get_text(start, label="t", transport=rec.transport(), max_redirects=3)
    assert str(ei.value) == REDIRECT_LIMIT_MESSAGE
    assert len(rec.seen) == 4


# ── At connect time ───────────────────────────────────────────────────────


class _FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self) -> None:
        self.written = b""
        self._reply = [b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nok.example\n"]

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._reply.pop(0) if self._reply else b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.written += buffer

    async def aclose(self) -> None:
        return None

    async def start_tls(self, *a: Any, **kw: Any) -> httpcore.AsyncNetworkStream:
        raise AssertionError("not used for http")

    def get_extra_info(self, info: str) -> Any:
        return None


class _InnerBackend(httpcore.AsyncNetworkBackend):
    def __init__(self) -> None:
        self.dialled: list[tuple[str, int]] = []
        self.stream = _FakeStream()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.dialled.append((host, port))
        return self.stream

    async def connect_unix_socket(self, *a: Any, **kw: Any) -> httpcore.AsyncNetworkStream:
        raise AssertionError("unexpected")

    async def sleep(self, seconds: float) -> None:
        return None


def _preflight_sees_public(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-request check resolves the name to a public address."""

    def fake_getaddrinfo(host: str, *a: Any, **kw: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 0))]

    monkeypatch.setattr("app.core.ssrf.socket.getaddrinfo", fake_getaddrinfo)


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["169.254.169.254"],
        [PUBLIC_IP, "169.254.169.254"],
        ["::ffff:127.0.0.1"],
    ],
)
async def test_name_answered_differently_at_connect_is_refused(
    monkeypatch: pytest.MonkeyPatch, answers: list[str]
) -> None:
    _preflight_sees_public(monkeypatch)
    inner = _InnerBackend()

    async def resolver(host: str, port: int) -> list[str]:
        return answers

    transport = GuardedTransport(label="t", inner_backend=inner, resolver=resolver)
    with pytest.raises(FetchRefusedError) as ei:
        await safe_get_text("http://feeds.example/list.txt", label="t", transport=transport)
    assert str(ei.value) == TARGET_REFUSED_MESSAGE
    assert inner.dialled == []


async def test_connect_dials_the_checked_address(monkeypatch: pytest.MonkeyPatch) -> None:
    _preflight_sees_public(monkeypatch)
    inner = _InnerBackend()

    async def resolver(host: str, port: int) -> list[str]:
        assert host == "feeds.example"
        return [PUBLIC_IP]

    transport = GuardedTransport(label="t", inner_backend=inner, resolver=resolver)
    text = await safe_get_text("http://feeds.example/list.txt", label="t", transport=transport)
    assert text == "ok.example\n"
    # The IP literal that passed the check is what was dialled …
    assert inner.dialled == [(PUBLIC_IP, 80)]
    # … and the request still names the host.
    assert b"Host: feeds.example" in inner.stream.written


async def test_connect_refuses_unix_sockets() -> None:
    from app.core.safe_fetch import GuardedNetworkBackend
    from app.core.ssrf import SSRFBlockedError

    with pytest.raises(SSRFBlockedError):
        await GuardedNetworkBackend(label="t").connect_unix_socket("/var/run/docker.sock")


# ── The refresh task ──────────────────────────────────────────────────────


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


def _wire_task(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, rec: _Recorder | None
) -> None:
    if rec is not None:
        monkeypatch.setattr(safe_fetch, "GuardedTransport", lambda **kw: rec.transport())
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)


async def _list(db: AsyncSession, url: str) -> DNSBlockList:
    bl = DNSBlockList(
        name=f"g-{abs(hash(url))}", source_type="url", feed_url=url, feed_format="domains"
    )
    db.add(bl)
    await db.commit()
    return bl


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/admin/feed",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/feed",
    ],
)
async def test_refresh_refuses_blocked_feed_with_generic_error(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    rec = _Recorder()
    _wire_task(monkeypatch, db_session, rec)
    bl = await _list(db_session, url)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "error"
    assert rec.seen == [], "the feed was requested"
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    assert bl.last_sync_error == f"Fetch refused: {TARGET_REFUSED_MESSAGE}"
    for leak in ("127.0.0.1", "169.254", "::1", "meta-data", "8000"):
        assert leak not in bl.last_sync_error


async def test_refresh_redirect_to_metadata_is_refused(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    start = f"http://{PUBLIC_IP}/list.txt"
    rec = _Recorder(
        {start: httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})}
    )
    _wire_task(monkeypatch, db_session, rec)
    bl = await _list(db_session, start)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "error"
    assert rec.seen == [start]
    await db_session.refresh(bl)
    assert bl.last_sync_error == f"Fetch refused: {TARGET_REFUSED_MESSAGE}"


async def test_refresh_http_error_stores_status_only(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    url = f"https://feeduser:s3cret-pw@{PUBLIC_IP}/list.txt?token=tok-123"
    body = "internal stack trace at 10.9.8.7 — db password hunter2"
    rec = _Recorder()

    def handler(request: httpx.Request) -> httpx.Response:
        rec.seen.append(str(request.url))
        return httpx.Response(500, text=body)

    monkeypatch.setattr(safe_fetch, "GuardedTransport", lambda **kw: httpx.MockTransport(handler))
    _wire_task(monkeypatch, db_session, None)
    bl = await _list(db_session, url)

    with pytest.raises(FetchFailedError):
        await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert len(rec.seen) == 1
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    assert bl.last_sync_error == "Fetch failed: HTTP 500"


async def test_refresh_transport_error_stores_no_exception_text(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"could not reach {request.url} via 10.0.0.9", request=request)

    monkeypatch.setattr(safe_fetch, "GuardedTransport", lambda **kw: httpx.MockTransport(handler))
    _wire_task(monkeypatch, db_session, None)
    bl = await _list(db_session, f"http://u:pw@{PUBLIC_IP}/list.txt")

    with pytest.raises(FetchFailedError):
        await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    await db_session.refresh(bl)
    assert bl.last_sync_error == "Fetch failed: could not connect"


async def test_refresh_public_feed_still_syncs(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control case: an ordinary public feed goes through the guard and syncs."""
    url = f"https://{PUBLIC_IP}/hosts.txt"
    rec = _Recorder({url: httpx.Response(200, text="a.example.com\nb.example.com\n")})
    _wire_task(monkeypatch, db_session, rec)
    bl = await _list(db_session, url)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "success"
    assert rec.seen == [url]
    await db_session.refresh(bl)
    assert bl.last_sync_status == "success"
    assert bl.entry_count == 2
    domains = (
        await db_session.execute(
            select(DNSBlockListEntry.domain).where(DNSBlockListEntry.list_id == bl.id)
        )
    ).scalars()
    assert set(domains) == {"a.example.com", "b.example.com"}


# ── The API, on save ──────────────────────────────────────────────────────


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="feedguard",
        email="feedguard@example.com",
        display_name="feedguard",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.parametrize(
    ("feed_url", "detail"),
    [
        ("ftp://feeds.example/list.txt", SCHEME_REFUSED_MESSAGE),
        ("file:///etc/passwd", SCHEME_REFUSED_MESSAGE),
        ("http://127.0.0.1/feed", TARGET_REFUSED_MESSAGE),
        ("http://169.254.169.254/latest/meta-data/", TARGET_REFUSED_MESSAGE),
        ("http://[fe80::1]/feed", TARGET_REFUSED_MESSAGE),
    ],
)
async def test_create_refuses_unsafe_feed_url(
    client: httpx.AsyncClient, db_session: AsyncSession, feed_url: str, detail: str
) -> None:
    headers = await _superadmin_headers(db_session)
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "guarded", "source_type": "url", "feed_url": feed_url},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert detail in resp.text
    # The resolved address is not echoed back.
    assert "127.0.0.1" not in resp.text.replace(feed_url, "")


async def test_create_accepts_private_mirror_and_update_refuses_metadata(
    client: httpx.AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _superadmin_headers(db_session)
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "mirror", "source_type": "url", "feed_url": "http://10.1.2.3/hosts.txt"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    bl_id = resp.json()["id"]

    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}",
        json={"feed_url": "http://169.254.169.254/latest/meta-data/"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert TARGET_REFUSED_MESSAGE in resp.text

    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}",
        json={"feed_url": "gopher://feeds.example/"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text

    # Clearing the feed URL is still allowed.
    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}", json={"feed_url": None}, headers=headers
    )
    assert resp.status_code == 200, resp.text

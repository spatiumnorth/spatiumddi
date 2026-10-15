"""Client-address trust: X-Real-IP only from a trusted proxy (#626, #1221).

The api used to run uvicorn with ``--forwarded-allow-ips *`` (so
``request.client`` followed the client-supplied X-Forwarded-For chain, #626)
and ``get_trusted_client_ip`` then believed ``X-Real-IP`` from ANY caller.
nginx overwrites that header, but compose published the api on every
interface, so a client talking to :8000 directly chose its own address: past
the login throttle, the ACME allowfrom gate, and into audit rows (#1221).

Now uvicorn runs ``--no-proxy-headers`` and :class:`TrustedProxyMiddleware`
applies ``X-Real-IP`` / ``X-Forwarded-Proto`` only when the real TCP peer is
in ``TRUSTED_PROXY_CIDRS``. These pin that, down to the audit row a failed
login from a forging peer leaves behind.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.request_meta import (
    DEFAULT_TRUSTED_PROXY_CIDRS,
    TrustedProxyMiddleware,
    get_trusted_client_ip,
    parse_trusted_proxies,
)
from app.main import app
from app.models.audit import AuditLog

DEFAULT = parse_trusted_proxies(DEFAULT_TRUSTED_PROXY_CIDRS)


async def _through(
    peer: str | None,
    headers: dict[str, str],
    trusted: Any = DEFAULT,
    scope_type: str = "http",
) -> dict[str, Any]:
    """Run one request scope through the middleware; return the scope the
    app behind it saw."""
    seen: dict[str, Any] = {}

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        seen.update(scope)

    scope: dict[str, Any] = {
        "type": scope_type,
        "scheme": "ws" if scope_type == "websocket" else "http",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": (peer, 4444) if peer else None,
    }
    await TrustedProxyMiddleware(inner, trusted)(scope, None, None)
    return seen


# ── the middleware ───────────────────────────────────────────────────────────


async def test_x_real_ip_from_an_untrusted_peer_is_ignored() -> None:
    """#1221: a client reaching the api directly sends its own X-Real-IP."""
    seen = await _through("203.0.113.50", {"x-real-ip": "10.0.0.1"})
    assert seen["client"][0] == "203.0.113.50"
    assert seen["state"]["tcp_peer"] == "203.0.113.50"


async def test_x_real_ip_from_a_trusted_proxy_is_the_client() -> None:
    """The nginx topology: the peer is the proxy, X-Real-IP is its $remote_addr."""
    seen = await _through("172.18.0.5", {"x-real-ip": "198.51.100.7"})
    assert seen["client"] == ("198.51.100.7", 4444)
    assert seen["state"]["tcp_peer"] == "172.18.0.5"


async def test_x_forwarded_for_is_never_used() -> None:
    """A trust list that covers the LAN can't split an XFF chain of LAN
    addresses into real and forged hops, so XFF is not read at all."""
    seen = await _through("172.18.0.5", {"x-forwarded-for": "1.2.3.4"})
    assert seen["client"][0] == "172.18.0.5"


@pytest.mark.parametrize("value", ["not-an-ip", "", "   "])
async def test_a_malformed_x_real_ip_keeps_the_peer(value: str) -> None:
    seen = await _through("10.1.1.1", {"x-real-ip": value})
    assert seen["client"][0] == "10.1.1.1"


async def test_ipv6_x_real_ip_from_a_trusted_proxy() -> None:
    seen = await _through("fd00::5", {"x-real-ip": "2001:db8::7"})
    assert seen["client"][0] == "2001:db8::7"


async def test_forwarded_proto_is_applied_only_from_a_trusted_proxy() -> None:
    """The refresh cookie's Secure flag and the slot-image URLs read the
    scheme, so the proxy's X-Forwarded-Proto must still land, and only its."""
    trusted = await _through("10.0.0.9", {"x-forwarded-proto": "https"})
    assert trusted["scheme"] == "https"
    untrusted = await _through("203.0.113.50", {"x-forwarded-proto": "https"})
    assert untrusted["scheme"] == "http"


async def test_forwarded_proto_maps_to_ws_schemes_on_a_websocket() -> None:
    seen = await _through("10.0.0.9", {"x-forwarded-proto": "https"}, scope_type="websocket")
    assert seen["scheme"] == "wss"


async def test_an_unknown_forwarded_proto_is_ignored() -> None:
    seen = await _through("10.0.0.9", {"x-forwarded-proto": "gopher"})
    assert seen["scheme"] == "http"


async def test_star_trusts_every_peer() -> None:
    seen = await _through("203.0.113.50", {"x-real-ip": "198.51.100.7"}, trusted=None)
    assert seen["client"][0] == "198.51.100.7"


async def test_a_scope_without_a_client_passes_through() -> None:
    seen = await _through(None, {"x-real-ip": "198.51.100.7"})
    assert seen["client"] is None


# ── parsing ──────────────────────────────────────────────────────────────────


def test_default_covers_the_shipped_proxy_ranges() -> None:
    from app.core.request_meta import _is_trusted

    for peer in ("127.0.0.1", "::1", "10.42.0.7", "172.18.0.5", "192.168.1.10", "100.64.3.2"):
        assert _is_trusted(peer, DEFAULT), peer
    for peer in ("203.0.113.50", "8.8.8.8", "2001:db8::1"):
        assert not _is_trusted(peer, DEFAULT), peer


def test_star_parses_to_trust_all() -> None:
    assert parse_trusted_proxies("*") is None
    assert parse_trusted_proxies(" * ") is None


@pytest.mark.parametrize("spec", ["", " , ", "10.0.0.0/8,not-a-cidr", "300.1.1.1"])
def test_a_bad_spec_is_an_error_not_a_guess(spec: str) -> None:
    """A typo must fail the boot, not silently trust nobody (every user in one
    rate-limit bucket) or everybody."""
    with pytest.raises(ValueError):
        parse_trusted_proxies(spec)


def test_the_setting_is_validated_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    from pydantic import ValidationError

    from app.config import Settings

    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8,nope")
    with pytest.raises(ValidationError):
        Settings()


# ── the helper no longer reads the header on its own ─────────────────────────


def test_get_trusted_client_ip_does_not_read_x_real_ip_itself() -> None:
    """The #1221 defect: the helper believed X-Real-IP from anyone. It now
    returns the address the middleware resolved and nothing else."""
    request = Request(
        {
            "type": "http",
            "headers": [(b"x-real-ip", b"10.0.0.1")],
            "client": ("203.0.113.50", 1),
        }
    )
    assert get_trusted_client_ip(request) == "203.0.113.50"


# ── end to end: the audit row a forged header leaves behind ──────────────────


async def _failed_login_source_ip(
    db_session: AsyncSession, peer: str, headers: dict[str, str]
) -> str | None:
    name = f"ghost-{uuid.uuid4().hex[:8]}"
    transport = ASGITransport(app=app, client=(peer, 5555))
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post(
            "/api/v1/auth/login",
            json={"username": name, "password": "wrong"},
            headers=headers,
        )
    assert r.status_code in (401, 429), r.text
    row = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "login", AuditLog.resource_display == name)
        )
    ).scalar_one()
    return row.source_ip


async def test_a_forged_x_real_ip_from_a_direct_client_is_not_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    source = await _failed_login_source_ip(db_session, "203.0.113.50", {"X-Real-IP": "10.9.9.9"})
    assert source == "203.0.113.50"


async def test_the_proxy_supplied_x_real_ip_is_audited(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    source = await _failed_login_source_ip(db_session, "172.18.0.5", {"X-Real-IP": "198.51.100.7"})
    assert source == "198.51.100.7"


# ── #1868: many users behind ONE proxy keep independent throttle buckets ─────


async def test_two_clients_behind_one_proxy_have_independent_login_buckets(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reported shape: an outer reverse proxy fronts the frontend nginx,
    so every request reaches the api from ONE TCP peer. The api must key the
    per-IP login budget on the real client the proxy chain reports in
    ``X-Real-IP`` and not on that peer; otherwise a busy morning returns 429 to
    the whole organisation. One client exhausting its budget must not touch
    another's."""
    from redis.asyncio import Redis

    from app.config import settings
    from app.core import auth_throttle

    monkeypatch.setattr(auth_throttle, "_LOGIN_RL_MAX", 3)
    salt = uuid.uuid4().int % 200
    alice, bob = f"198.51.100.{salt}", f"203.0.113.{salt}"
    proxy = "172.18.0.5"  # one trusted peer for both
    r = Redis.from_url(settings.redis_url)
    try:
        await r.delete(f"login_rl:{alice}", f"login_rl:{bob}", f"login_rl:{proxy}")
    finally:
        await r.aclose()

    async def attempt(real_ip: str) -> int:
        transport = ASGITransport(app=app, client=(proxy, 5555))
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post(
                "/api/v1/auth/login",
                json={"username": f"ghost-{uuid.uuid4().hex[:8]}", "password": "wrong"},
                headers={"X-Real-IP": real_ip},
            )
        return resp.status_code

    assert [await attempt(alice) for _ in range(4)] == [401, 401, 401, 429]
    # Bob shares alice's proxy and nothing else: his budget is untouched.
    assert [await attempt(bob) for _ in range(3)] == [401, 401, 401]
    assert await attempt(bob) == 429
    assert await attempt(alice) == 429


# ── #1868: the diagnostics that name the cause of a proxy misconfiguration ───


async def test_a_refused_host_is_named_in_the_log() -> None:
    """``TRUSTED_HOSTS`` + a proxy that rewrites Host: Starlette answers a bare
    400. The cause (which Host arrived) must reach the log, once per name."""
    from structlog.testing import capture_logs

    from app.core.request_meta import LoggingTrustedHostMiddleware

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        raise AssertionError("must not reach the app")

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    LoggingTrustedHostMiddleware._seen.clear()
    mw = LoggingTrustedHostMiddleware(inner, allowed_hosts=["ddi.example.com"])
    scope = {"type": "http", "headers": [(b"host", b"spatiumddi-frontend:8000")]}
    with capture_logs() as logs:
        await mw(scope, None, send)
        await mw(scope, None, send)
    assert sent[0]["status"] == 400
    refused = [e for e in logs if e["event"] == "trusted_hosts_refused_host"]
    assert len(refused) == 1 and refused[0]["host"] == "spatiumddi-frontend"


async def test_a_forwarded_prefix_from_a_trusted_proxy_is_warned_about() -> None:
    """Sub-paths are unsupported; a blank page is all the operator sees."""
    from structlog.testing import capture_logs

    from app.core import request_meta

    request_meta._prefix_warned = False
    with capture_logs() as logs:
        await _through("10.0.0.9", {"x-forwarded-prefix": "/spatium"})
    assert [
        e["forwarded_prefix"] for e in logs if e["event"] == "reverse_proxy_sub_path_unsupported"
    ] == ["/spatium"]
    request_meta._prefix_warned = False
    with capture_logs() as logs:
        await _through("10.0.0.9", {"x-forwarded-prefix": "/"})
        await _through("203.0.113.50", {"x-forwarded-prefix": "/spatium"})
    assert not [e for e in logs if e["event"] == "reverse_proxy_sub_path_unsupported"]


async def test_an_empty_external_url_logs_the_fallback(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The SSO callback URL is built from the request when External URL is
    empty; that is the silent cause of "redirect_uri mismatch" behind a proxy."""
    from structlog.testing import capture_logs

    from app.api.v1.auth.router import _app_base_url
    from app.models.settings import PlatformSettings

    row = await db_session.get(PlatformSettings, 1)
    if row is None:
        row = PlatformSettings(id=1)
        db_session.add(row)
    row.app_base_url = ""
    await db_session.flush()
    request = Request(
        {
            "type": "http",
            "scheme": "http",
            "server": ("ddi.example.com", 80),
            "path": "/api/v1/auth/x/start",
            "headers": [(b"host", b"ddi.example.com")],
        }
    )
    with capture_logs() as logs:
        assert await _app_base_url(db_session, request) == "http://ddi.example.com"
    assert [e["built_url"] for e in logs if e["event"] == "sso_external_url_not_set"] == [
        "http://ddi.example.com"
    ]
    row.app_base_url = "https://ddi.example.com/"
    await db_session.flush()
    with capture_logs() as logs:
        assert await _app_base_url(db_session, request) == "https://ddi.example.com"
    assert not [e for e in logs if e["event"] == "sso_external_url_not_set"]

"""Per-request hook for web exposure detection (#3651).

A pure ASGI middleware, added INSIDE ``TrustedProxyMiddleware`` so
``scope["client"]`` is already the spoofing-resistant client address.

The hot path is dead cheap and does no I/O for the overwhelmingly common
request, one from private address space: classify, return. Only a request from
a public address loads the (10 s cached) configuration, and only when the
``security.web_exposure`` module is on does anything get counted. Counting is a
synchronous in-process increment; Redis is touched by a background flush, never
by the request. The hook never alters or refuses a request: enforcement lives in
``services/web_exposure/mitigations`` and only on ``/auth/login``.

Excluded from every signal, exactly as maintenance mode exempts them
(non-negotiable #5): agent / supervisor surfaces, health and metrics, and the
ACME / HELD routes that are reachable from outside by design.
"""

from __future__ import annotations

from typing import Any

from app.core.maintenance_mode import EXEMPT_PREFIXES
from app.services.web_exposure import store
from app.services.web_exposure.classify import bucket_of, classify, is_private_fast
from app.services.web_exposure.config import get_runtime_config

# maintenance mode exempts auth + settings for its own reasons; here the login
# page IS /settings/public, so only the agent-facing prefixes carry over.
_EXCLUDED_PREFIXES: tuple[str, ...] = tuple(
    p for p in EXEMPT_PREFIXES if p not in ("/api/v1/auth", "/api/v1/settings")
) + ("/.well-known/", "/api/v1/acme")

LOGIN_PAGE_PATH = "/api/v1/settings/public"
VERSION_PATH = "/api/v1/version"


def _excluded(path: str) -> bool:
    return path.startswith(_EXCLUDED_PREFIXES)


def _is_login_path(path: str) -> bool:
    return path.startswith("/api/v1/auth/login")


class WebExposureMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not scope.get("client"):
            await self.app(scope, receive, send)
            return
        ip: str = scope["client"][0]
        path: str = scope.get("path", "")
        try:
            if _excluded(path):
                pass
            elif is_private_fast(ip):
                await self._maybe_note_unattributable(scope, ip)
            else:
                rt = await get_runtime_config()
                if rt.enabled and classify(ip, rt.trusted) == "external":
                    send = self._observe(scope, ip, path, send)
        except Exception:  # noqa: BLE001 — detection must never fail a request
            pass
        await self.app(scope, receive, send)

    def _observe(self, scope: Any, ip: str, path: str, send: Any) -> Any:
        bucket = bucket_of(ip)
        if bucket is None:
            return send
        method = scope.get("method", "GET")
        if method == "GET" and path == LOGIN_PAGE_PATH:
            store.record(bucket, ip, store.SIGNAL_LOGIN_PAGE, path=path)
        elif method == "GET" and path == VERSION_PATH:
            store.record(bucket, ip, store.SIGNAL_VERSION, path=path)
        if not path.startswith("/api/v1/") or _is_login_path(path):
            return send

        async def observing_send(message: Any) -> None:
            if message["type"] == "http.response.start" and message.get("status") in (401, 403):
                store.record(bucket, ip, store.SIGNAL_UNAUTH, path=path)
            await send(message)

        return observing_send

    async def _maybe_note_unattributable(self, scope: Any, ip: str) -> None:
        """A proxy that sends ``X-Forwarded-For`` but no ``X-Real-IP`` leaves
        every client looking like the proxy: exposure is unknowable until the
        proxy is configured (REVERSE_PROXY.md). Cheap header test first."""
        names = {k for k, _ in scope.get("headers", [])}
        if b"x-forwarded-for" not in names or b"x-real-ip" in names:
            return
        rt = await get_runtime_config()
        if rt.enabled:
            bucket = bucket_of(ip)
            if bucket:
                store.record(bucket, ip, store.SIGNAL_PROXY_NO_REAL_IP)

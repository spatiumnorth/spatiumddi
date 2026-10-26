"""App-wide cap on the size of a request body (#2780).

nginx admits 1 MiB on ``/api/`` (more on the backup and upgrade-image
locations), but the api port itself (127.0.0.1 on compose, a ClusterIP
Service on Kubernetes) has no body limit, and FastAPI reads a JSON body
whole into memory before any dependency runs. This middleware bounds that
for every route, in front of everything else:

* a declared ``Content-Length`` over the cap is answered **413** before
  any of the body is read and before the app sees the request;
* a body without one (chunked) is counted as it arrives and refused as soon
  as it passes the cap, so no more than the cap is ever read.

The cap is ``MAX_REQUEST_BODY_BYTES`` (default 8 MiB, eight times nginx's
``/api/`` limit). Routes that legitimately take more carry an explicit,
reasoned allowance in :data:`ALLOWANCES`, sized to the limit the route
already enforces itself; ``tests/test_body_limit.py`` fails when a route
with a larger limit of its own is not covered, or an allowance matches no
route. A route's allowance never lowers the cap: the larger of the two
applies.

Every body route an allowance covers also checks the caller's credentials
from the request headers before reading the body (``app.api.pre_body_auth``;
``tests/test_pre_body_auth.py`` fails when one does not), as do the upload
routes; this cap is what bounds everything else.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass

from fastapi import HTTPException, Request, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MIB = 1024 * 1024
GIB = 1024 * MIB

# Headroom for the multipart framing around a file whose own size limit the
# handler enforces (boundaries, part headers, the small form fields).
_FORM_OVERHEAD = MIB

DEFAULT_MAX_REQUEST_BODY_BYTES = 8 * MIB


@dataclass(frozen=True)
class Allowance:
    """A route that may take a body larger than the app-wide cap."""

    methods: frozenset[str]
    pattern: re.Pattern[str]
    max_bytes: int
    reason: str


def _allow(methods: str, pattern: str, max_bytes: int, reason: str) -> Allowance:
    return Allowance(frozenset(methods.split()), re.compile(pattern), max_bytes, reason)


ALLOWANCES: tuple[Allowance, ...] = (
    _allow(
        "POST",
        r"/api/v1/appliance/upgrade-images",
        4 * GIB + _FORM_OVERHEAD,
        "Appliance upgrade image upload (upgrade_images.MAX_UPLOAD_BYTES, 4 GiB).",
    ),
    _allow(
        "POST",
        r"/api/v1/backup/.+",
        2 * GIB + _FORM_OVERHEAD,
        "Backup archive restore / preview upload (backup router _MAX_UPLOAD_BYTES, 2 GiB).",
    ),
    _allow(
        "POST",
        r"/api/v1/dns/import/.+",
        50 * MIB + _FORM_OVERHEAD,
        "DNS importers: a 50 MiB BIND9 archive, and the preview it produced sent back "
        "to commit (dns_import router _MAX_UPLOAD_BYTES).",
    ),
    _allow(
        "POST",
        r"/api/v1/dhcp/import/.+",
        25 * MIB + _FORM_OVERHEAD,
        "DHCP importers: a 25 MiB Kea / ISC config, and the preview sent back to "
        "commit (dhcp_import router _MAX_UPLOAD_BYTES).",
    ),
    _allow(
        "POST",
        r"/api/v1/ipam/import/.+",
        25 * MIB + _FORM_OVERHEAD,
        "IPAM imports: a 25 MiB CSV / JSON / XLSX file (io_router _MAX_UPLOAD_BYTES), "
        "and the NetBox preview sent back to commit.",
    ),
    _allow(
        "POST",
        r"/api/v1/dns/groups/[^/]+/zones/[^/]+/import/spreadsheet/(preview|commit)",
        10 * MIB + _FORM_OVERHEAD,
        "DNS zone spreadsheet import (dns router _SHEET_MAX_UPLOAD_BYTES, 10 MiB).",
    ),
    _allow(
        "POST",
        r"/api/v1/appliance/supervisor/pcap/upload/[^/]+",
        100 * MIB + 16 * MIB + _FORM_OVERHEAD,
        "Supervisor packet-capture upload: the hard capture ceiling plus the 16 MiB "
        "framing headroom the handler allows (pcap runner HARD_MAX_BYTES).",
    ),
    _allow(
        "POST",
        r"/api/v1/dns/agents/ingested-records",
        64 * MIB,
        "DNS agent ships every externally-updated record of one dynamic zone in a "
        "single request; a large AD-integrated zone exceeds the default cap.",
    ),
)


def limit_for(method: str, path: str, default: int) -> int:
    """The body cap for a request: the app-wide cap, or a route's larger
    allowance."""
    limit = default
    trimmed = path.rstrip("/") or "/"
    for allowance in ALLOWANCES:
        if method in allowance.methods and allowance.pattern.fullmatch(trimmed):
            limit = max(limit, allowance.max_bytes)
    return limit


class RequestBodyTooLarge(HTTPException):
    """413 for a body over the limit a handler reads under
    (:func:`read_body_capped`)."""

    def __init__(self, max_bytes: int) -> None:
        super().__init__(status.HTTP_413_CONTENT_TOO_LARGE, too_large_detail(max_bytes))


def too_large_detail(max_bytes: int) -> str:
    return f"Request body is larger than this endpoint accepts ({max_bytes} bytes)."


def _declared_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _send_413(send: Send, max_bytes: int) -> None:
    body = json.dumps({"detail": too_large_detail(max_bytes)}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status.HTTP_413_CONTENT_TOO_LARGE,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class RequestBodyLimitMiddleware:
    """Pure ASGI middleware enforcing :func:`limit_for` on every request."""

    def __init__(self, app: ASGIApp, *, max_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = limit_for(scope.get("method", ""), scope.get("path", ""), self.max_bytes)
        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            await _send_413(send, limit)
            return

        seen = 0
        started = False
        refused = False

        async def limited_receive() -> Message:
            # Once the body passes the cap the 413 is sent from here, before
            # the app reads any more, and the app is told the client went
            # away. Raising instead is not reliable: FastAPI turns an error
            # while reading the body into its own 400, and a
            # ``BaseHTTPMiddleware`` in between re-wraps ``receive``.
            nonlocal seen, refused
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit and not started:
                    refused = True
                    await _send_413(send, limit)
                    return {"type": "http.disconnect"}
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if refused:
                return  # the 413 has been sent; the app's answer is dropped
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except Exception:
            # The app failing on the disconnect it was handed is expected;
            # the 413 has already been sent.
            if not refused:
                raise


async def read_body_capped(request: Request, max_bytes: int) -> bytes:
    """Read the whole body of ``request``, refusing (413) one larger than
    ``max_bytes`` without reading past it. For a handler that reads its own
    body under a limit tighter than the app-wide cap (HELD)."""
    declared = _declared_length(request.scope)
    if declared is not None and declared > max_bytes:
        raise RequestBodyTooLarge(max_bytes)
    chunks: list[bytes] = []
    size = 0
    stream: AsyncIterator[bytes] = request.stream()
    async for chunk in stream:
        size += len(chunk)
        if size > max_bytes:
            raise RequestBodyTooLarge(max_bytes)
        chunks.append(chunk)
    return b"".join(chunks)

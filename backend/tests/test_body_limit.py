"""The app-wide request body cap (#2780, ``app.core.body_limit``).

The api port has no body limit of its own and FastAPI reads a JSON body
whole before any dependency runs, so every request body is capped in an
ASGI middleware in front of everything else. These tests send bodies as
streams that record how much the server read.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import AsyncIterator

import pytest
from fastapi import Body, FastAPI
from fastapi.routing import APIRoute
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.body_limit import (
    ALLOWANCES,
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    RequestBodyLimitMiddleware,
    limit_for,
)
from app.main import app
from app.models.settings import BRANDING_ASSET_MAX_BYTES
from app.services.e911.held import MAX_REQUEST_BYTES as HELD_MAX_REQUEST_BYTES
from app.services.pcap.runner import HARD_MAX_BYTES as PCAP_HARD_MAX_BYTES
from tests.test_pre_body_auth import _effective_routes
from tests.test_upgrade_images import _hdr, _token

upgrade_images = importlib.import_module("app.api.v1.appliance.upgrade_images")
backup_router = importlib.import_module("app.api.v1.backup.router")
dhcp_import_router = importlib.import_module("app.api.v1.dhcp_import.router")
dns_router = importlib.import_module("app.api.v1.dns.router")
dns_import_router = importlib.import_module("app.api.v1.dns_import.router")
io_router = importlib.import_module("app.api.v1.ipam.io_router")

MIB = 1024 * 1024


class _Body:
    """A request body that records how much of it the server pulled."""

    def __init__(self, payload: bytes, chunk: int = 64 * 1024) -> None:
        self.payload = payload
        self.chunk = chunk
        self.sent = 0

    async def stream(self) -> AsyncIterator[bytes]:
        for i in range(0, len(self.payload), self.chunk):
            piece = self.payload[i : i + self.chunk]
            self.sent += len(piece)
            yield piece


def _mini_app(max_bytes: int) -> tuple[FastAPI, list[int]]:
    """A FastAPI app behind the middleware, recording handler calls."""
    calls: list[int] = []
    mini = FastAPI()

    @mini.post("/echo")
    async def echo(payload: dict = Body(...)) -> dict:  # noqa: B008
        calls.append(len(payload.get("data", "")))
        return {"ok": True}

    @mini.post("/api/v1/dns/import/bind9/commit")
    async def big(payload: dict = Body(...)) -> dict:  # noqa: B008
        calls.append(len(payload.get("data", "")))
        return {"ok": True}

    mini.add_middleware(RequestBodyLimitMiddleware, max_bytes=max_bytes)
    return mini, calls


def _json(size: int) -> bytes:
    return b'{"data": "' + b"a" * size + b'"}'


async def _mini_post(mini: FastAPI, path: str, body: _Body, *, declare: bool):  # noqa: ANN202
    headers = {"Content-Type": "application/json"}
    if declare:
        headers["Content-Length"] = str(len(body.payload))
    async with AsyncClient(transport=ASGITransport(app=mini), base_url="http://t") as c:
        return await c.post(path, content=body.stream(), headers=headers)


# ── the middleware ───────────────────────────────────────────────────


async def test_a_declared_oversized_body_is_refused_before_it_is_read() -> None:
    mini, calls = _mini_app(64 * 1024)
    body = _Body(_json(200_000))
    resp = await _mini_post(mini, "/echo", body, declare=True)
    assert resp.status_code == 413, resp.text
    assert "larger than" in resp.json()["detail"]
    assert body.sent == 0
    assert calls == []


async def test_a_chunked_oversized_body_stops_at_the_cap() -> None:
    mini, calls = _mini_app(64 * 1024)
    body = _Body(_json(2 * MIB), chunk=16 * 1024)
    resp = await _mini_post(mini, "/echo", body, declare=False)
    assert resp.status_code == 413, resp.text
    assert calls == []
    # Read up to the cap, plus at most the chunk in flight.
    assert body.sent <= 64 * 1024 + 2 * 16 * 1024


async def test_a_body_under_the_cap_is_served() -> None:
    mini, calls = _mini_app(64 * 1024)
    for declare in (True, False):
        body = _Body(_json(10_000))
        resp = await _mini_post(mini, "/echo", body, declare=declare)
        assert resp.status_code == 200, resp.text
    assert calls == [10_000, 10_000]


async def test_a_route_with_an_allowance_takes_more_than_the_cap() -> None:
    mini, calls = _mini_app(64 * 1024)
    body = _Body(_json(200_000))
    resp = await _mini_post(mini, "/api/v1/dns/import/bind9/commit", body, declare=True)
    assert resp.status_code == 200, resp.text
    assert calls == [200_000]


def test_an_allowance_never_lowers_the_cap() -> None:
    assert limit_for("POST", "/api/v1/dns/import/bind9/preview", 1 << 40) == 1 << 40
    assert limit_for("GET", "/api/v1/dns/import/bind9/preview", 10) == 10
    assert limit_for("POST", "/api/v1/ipam/spaces", 10) == 10


# ── wiring ───────────────────────────────────────────────────────────


def test_the_cap_is_outermost_and_defaults_to_8_mib() -> None:
    assert DEFAULT_MAX_REQUEST_BODY_BYTES == 8 * MIB
    assert settings.max_request_body_bytes == DEFAULT_MAX_REQUEST_BODY_BYTES
    outermost = app.user_middleware[0]
    assert outermost.cls is RequestBodyLimitMiddleware
    assert outermost.kwargs["max_bytes"] == settings.max_request_body_bytes


async def test_an_unauthenticated_oversized_json_body_gets_413_unread(
    client: AsyncClient,
) -> None:
    body = _Body(_json(9 * MIB))
    resp = await client.post(
        "/api/v1/ipam/spaces",
        content=body.stream(),
        headers={"Content-Type": "application/json", "Content-Length": str(len(body.payload))},
    )
    assert resp.status_code == 413, resp.text
    assert body.sent == 0


async def test_an_oversized_chunked_json_body_stops_at_the_cap(client: AsyncClient) -> None:
    body = _Body(_json(12 * MIB), chunk=256 * 1024)
    resp = await client.post(
        "/api/v1/ipam/spaces",
        content=body.stream(),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413, resp.text
    assert body.sent <= 8 * MIB + 2 * 256 * 1024


async def test_a_normal_json_request_still_works(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _token(db_session, username="capjson")
    resp = await client.post("/api/v1/ipam/spaces", json={"name": "cap-space"}, headers=_hdr(token))
    assert resp.status_code == 201, resp.text


async def test_an_upload_route_over_the_cap_reaches_its_login_check(
    client: AsyncClient,
) -> None:
    """The BIND9 importer takes up to 50 MiB, so a 20 MiB upload is not
    refused by the cap; with no login it is refused (401) by the route's
    own check, still without being read."""
    body = _Body(b"x" * 1024)
    resp = await client.post(
        "/api/v1/dns/import/bind9/preview",
        content=body.stream(),
        headers={
            "Content-Type": "multipart/form-data; boundary=b",
            "Content-Length": str(20 * MIB),
        },
    )
    assert resp.status_code == 401, resp.text
    assert body.sent == 0


# ── allowances ───────────────────────────────────────────────────────


def _sample(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x", path)


def test_every_allowance_has_a_reason_and_matches_a_route() -> None:
    routes = [
        (method, _sample(path))
        for path, route in _effective_routes(app.routes)
        if isinstance(route, APIRoute)
        for method in route.methods
    ]
    for allowance in ALLOWANCES:
        assert allowance.reason.strip(), allowance
        assert allowance.max_bytes > DEFAULT_MAX_REQUEST_BODY_BYTES, allowance
        matched = [
            p for m, p in routes if m in allowance.methods and allowance.pattern.fullmatch(p)
        ]
        assert matched, f"allowance {allowance.pattern.pattern} matches no route"


@pytest.mark.parametrize(
    ("method", "path", "own_limit"),
    [
        ("POST", "/api/v1/appliance/upgrade-images", upgrade_images.MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/backup/restore", backup_router._MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/backup/manifest-preview", backup_router._MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/dns/import/bind9/preview", dns_import_router._MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/dhcp/import/kea/preview", dhcp_import_router._MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/dhcp/import/isc/preview", dhcp_import_router._MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/ipam/import/preview", io_router._MAX_UPLOAD_BYTES),
        ("POST", "/api/v1/ipam/import/addresses/commit", io_router._MAX_UPLOAD_BYTES),
        (
            "POST",
            "/api/v1/dns/groups/x/zones/x/import/spreadsheet/preview",
            dns_router._SHEET_MAX_UPLOAD_BYTES,
        ),
        (
            "POST",
            "/api/v1/appliance/supervisor/pcap/upload/x",
            PCAP_HARD_MAX_BYTES + 16 * MIB,
        ),
        ("PUT", "/api/v1/settings/branding/logo", BRANDING_ASSET_MAX_BYTES),
        ("POST", "/held/self", HELD_MAX_REQUEST_BYTES),
    ],
)
def test_a_route_with_a_larger_limit_of_its_own_is_covered(
    method: str, path: str, own_limit: int
) -> None:
    """Every route that enforces a limit above the cap has an allowance at
    least that large, so the cap never refuses what the route accepts."""
    assert limit_for(method, path, DEFAULT_MAX_REQUEST_BODY_BYTES) >= own_limit


# ── HELD reads its own body, under a tighter limit ───────────────────


async def test_held_self_query_stops_reading_at_its_document_limit(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HELD self-query has no login to check (it is unauthenticated by
    design, and off unless enabled), so it reads no further than its 64 KiB
    document limit, answering with the same HELD error as before."""
    from app.api.v1.e911 import held_router

    monkeypatch.setattr(settings, "e911_self_query_enabled", True)

    async def never_limited(_ip: str) -> bool:
        return False

    monkeypatch.setattr(held_router, "e911_self_query_rate_limited", never_limited)
    body = _Body(b"<locationRequest>" + b" " * MIB + b"</locationRequest>", chunk=4096)
    resp = await client.post(
        "/held/self",
        content=body.stream(),
        headers={"Content-Type": "application/held+xml"},
    )
    assert resp.status_code == 400, resp.text
    assert "larger than" in resp.text
    assert body.sent <= HELD_MAX_REQUEST_BYTES + 2 * 4096

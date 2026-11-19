"""#2855 — the slot-image mirror's PUT takes an image-sized body.

The mirror is the same app as the api, run with ``SLOT_IMAGE_MIRROR_MODE``,
so the app-wide request body cap (``app.core.body_limit``, 8 MiB by
default) applies to it too. The api stores every upgrade image through the
mirror's ``PUT /api/v1/appliance/internal/slot-images/{id}``, so without an
allowance for that route every upload, repair and GitHub import on a
cluster with the mirror enabled was refused (413 at the mirror, 502 at the
api).

The allowance is sized like the upload's own limit, and the mirror checks
the caller's ``X-Mirror-Auth`` header before it reads any of the body.

These tests mount the real mirror router behind the real middleware and send
bodies a little over the 8 MiB cap as streams, so nothing image-sized is
allocated.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import slot_image_mirror, upgrade_images
from app.config import settings
from app.core.body_limit import (
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    RequestBodyLimitMiddleware,
    limit_for,
)
from tests.test_pre_body_auth import _post, _roomy_disk, _upload_body
from tests.test_upgrade_images import _BASE, _hdr, _token

MIB = 1024 * 1024
GIB = 1024 * MIB
PREFIX = "/api/v1/appliance/internal/slot-images"
IMAGE = uuid.UUID("2855aaaa-0000-4000-8000-000000002855")
# Over the app-wide cap, small enough to send in a test.
OVER_CAP = DEFAULT_MAX_REQUEST_BODY_BYTES + MIB


class _Stream:
    """A request body of ``size`` bytes, sent in chunks, that records how
    much of it the server pulled."""

    def __init__(self, size: int, chunk: int = MIB) -> None:
        self.size = size
        self.chunk = chunk
        self.sent = 0

    async def stream(self) -> AsyncIterator[bytes]:
        while self.sent < self.size:
            piece = b"i" * min(self.chunk, self.size - self.sent)
            self.sent += len(piece)
            yield piece


@pytest.fixture
def mirror_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("SPATIUM_SLOT_IMAGE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "slot_image_mirror_secret", "test-mirror-secret-2855")
    return tmp_path


@pytest.fixture
def mirror_app(mirror_dir: Path) -> FastAPI:
    """The mirror as it is deployed: the mirror router behind the app-wide
    body cap at its default."""
    app = FastAPI()
    app.include_router(slot_image_mirror.router, prefix=PREFIX)
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=DEFAULT_MAX_REQUEST_BODY_BYTES)
    return app


def _mirror_client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://mirror")


def _put_hdr(image: uuid.UUID = IMAGE) -> dict[str, str]:
    return {"X-Mirror-Auth": slot_image_mirror.mirror_auth_token("put", image)}


def test_the_mirror_write_allowance_matches_the_upload_limit() -> None:
    limit = limit_for("PUT", f"{PREFIX}/{IMAGE}", DEFAULT_MAX_REQUEST_BODY_BYTES)
    assert limit == upgrade_images.MAX_UPLOAD_BYTES
    # Only the write: reads and deletes carry no body.
    for method in ("GET", "HEAD", "DELETE", "POST"):
        assert limit_for(method, f"{PREFIX}/{IMAGE}", DEFAULT_MAX_REQUEST_BODY_BYTES) == (
            DEFAULT_MAX_REQUEST_BODY_BYTES
        )


async def test_an_image_over_the_cap_with_a_declared_length_is_stored(
    mirror_app: FastAPI, mirror_dir: Path
) -> None:
    body = _Stream(OVER_CAP)
    headers = {**_put_hdr(), "Content-Length": str(OVER_CAP)}
    async with _mirror_client(mirror_app) as c:
        resp = await c.put(f"{PREFIX}/{IMAGE}", content=body.stream(), headers=headers)
    assert resp.status_code == 204, resp.text
    assert (mirror_dir / f"{IMAGE}.raw.xz").stat().st_size == OVER_CAP


async def test_a_chunked_image_over_the_cap_is_stored(
    mirror_app: FastAPI, mirror_dir: Path
) -> None:
    body = _Stream(OVER_CAP)
    async with _mirror_client(mirror_app) as c:
        resp = await c.put(f"{PREFIX}/{IMAGE}", content=body.stream(), headers=_put_hdr())
    assert resp.status_code == 204, resp.text
    assert (mirror_dir / f"{IMAGE}.raw.xz").stat().st_size == OVER_CAP


async def test_a_declared_image_size_body_is_not_refused_up_front(
    mirror_app: FastAPI, mirror_dir: Path
) -> None:
    """A body declaring a 3 GiB image is let through to the route (the
    cluster's own upload was 1.9 GB). Only a little of it is sent."""
    body = _Stream(MIB)
    headers = {**_put_hdr(), "Content-Length": str(3 * GIB)}
    async with _mirror_client(mirror_app) as c:
        resp = await c.put(f"{PREFIX}/{IMAGE}", content=body.stream(), headers=headers)
    assert resp.status_code != 413, resp.text
    assert resp.status_code == 204, resp.text


async def test_a_body_over_the_upload_limit_is_still_refused(mirror_app: FastAPI) -> None:
    body = _Stream(MIB)
    headers = {**_put_hdr(), "Content-Length": str(upgrade_images.MAX_UPLOAD_BYTES + 1)}
    async with _mirror_client(mirror_app) as c:
        resp = await c.put(f"{PREFIX}/{IMAGE}", content=body.stream(), headers=headers)
    assert resp.status_code == 413, resp.text
    assert body.sent == 0


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        (None, 401),
        ("0" * 64, 403),
        # A valid token for another operation on the same image.
        ("get", 403),
    ],
    ids=["no-header", "wrong-token", "get-token"],
)
async def test_a_caller_without_the_put_token_is_refused_before_the_body_is_read(
    mirror_app: FastAPI, mirror_dir: Path, token: str | None, expected: int
) -> None:
    headers: dict[str, str] = {}
    if token == "get":
        headers["X-Mirror-Auth"] = slot_image_mirror.mirror_auth_token("get", IMAGE)
    elif token is not None:
        headers["X-Mirror-Auth"] = token
    body = _Stream(OVER_CAP)
    h = {**headers, "Content-Length": str(OVER_CAP)}
    async with _mirror_client(mirror_app) as c:
        resp = await c.put(f"{PREFIX}/{IMAGE}", content=body.stream(), headers=h)
    assert resp.status_code == expected, resp.text
    assert body.sent == 0
    assert list(mirror_dir.iterdir()) == []


async def test_a_put_to_a_non_uuid_id_is_refused_before_the_body_is_read(
    mirror_app: FastAPI, mirror_dir: Path
) -> None:
    body = _Stream(OVER_CAP)
    async with _mirror_client(mirror_app) as c:
        resp = await c.put(
            f"{PREFIX}/not-a-uuid",
            content=body.stream(),
            headers={"X-Mirror-Auth": "a" * 64},
        )
    assert resp.status_code == 403, resp.text
    assert body.sent == 0


# ── end to end: the api stores an upload through the mirror ──────────


class _RoutedClient(httpx.AsyncClient):
    """``httpx.AsyncClient`` whose requests go to ``target`` in-process."""

    target: FastAPI

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = httpx.ASGITransport(app=self.target)
        super().__init__(*args, **kwargs)


async def test_an_upload_over_the_cap_is_stored_through_the_mirror(
    db_session: AsyncSession,
    client: AsyncClient,
    mirror_app: FastAPI,
    mirror_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reported path: an operator upload on the api, stored through the
    mirror's PUT. Before #2855 the mirror answered 413 and the api 502."""
    token = await _token(db_session, username="mirroradmin2855")
    _roomy_disk(monkeypatch)
    monkeypatch.setattr(
        slot_image_mirror.shutil,
        "disk_usage",
        lambda _p: SimpleNamespace(total=100 * GIB, used=10 * GIB, free=90 * GIB),
    )
    # The api's own client (``client``) is already built; only the clients
    # the api opens towards the mirror from here on are routed to it.
    monkeypatch.setattr(
        httpx, "AsyncClient", type("Routed", (_RoutedClient,), {"target": mirror_app})
    )
    monkeypatch.setattr(settings, "slot_image_mirror_url", "http://mirror")

    content = b"m" * OVER_CAP
    body = _upload_body(content)
    resp = await _post(client, _BASE, body, headers=_hdr(token), content_length=len(body.payload))
    assert resp.status_code == 200, resp.text
    row = resp.json()
    assert row["sha256"] == hashlib.sha256(content).hexdigest()
    assert row["size_bytes"] == OVER_CAP
    stored = mirror_dir / f"{row['id']}.raw.xz"
    assert stored.stat().st_size == OVER_CAP

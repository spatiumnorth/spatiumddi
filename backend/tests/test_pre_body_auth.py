"""Large-body routes authorise from the headers before the body is read.

nginx admits up to 4 GiB on ``/api/v1/appliance/upgrade-images`` and 2 GiB
on ``/api/v1/backup/``, with request buffering off. FastAPI reads a route's
body before it resolves the route's dependencies, so on those routes a
caller who may not upload must be answered before a byte of the body is
read: a multipart file part is otherwise spooled onto the api pod's disk,
and a JSON body held in memory, before the 401 / 403.

The same holds for every route ``app.core.body_limit`` gives a body
allowance above the app-wide cap: the importers' JSON routes and the DNS
agent routes check the caller's credentials before the body is parsed.

These tests send the body as a stream that records whether it was read,
and count the temporary files Starlette's multipart parser creates.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import AsyncIterator
from types import SimpleNamespace

import pytest
import starlette.formparsers
from fastapi import APIRouter, Body
from fastapi.routing import APIRoute
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.pre_body_auth import (
    EFFECTIVE_CONTEXT_VAR,
    PreBodyAuthRoute,
    PreBodyAuthUploadRoute,
    auth_checks,
    takes_upload,
)
from app.api.v1.appliance import slot_image_mirror, upgrade_images
from app.api.v1.dns import agents as dns_agents
from app.core.body_limit import DEFAULT_MAX_REQUEST_BODY_BYTES, limit_for
from app.main import app
from app.models.audit import AuditLog
from app.models.dns import DNSServer, DNSServerGroup
from app.services.appliance import upgrade_image_space
from app.services.dns import agent_token as dns_agent_token
from tests.test_settings_branding import _tiny_png
from tests.test_upgrade_images import _BASE, _hdr, _token

GIB = 1024**3
_BOUNDARY = "spatiumtestboundary"
_MULTIPART = f"multipart/form-data; boundary={_BOUNDARY}"


class _Body:
    """A request body that records whether the server read any of it."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.read = False

    async def stream(self) -> AsyncIterator[bytes]:
        self.read = True
        for i in range(0, len(self.payload), 4096):
            yield self.payload[i : i + 4096]


def _multipart(fields: dict[str, str], file_field: str, content: bytes) -> bytes:
    out = b""
    for name, value in fields.items():
        out += (
            f"--{_BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n"
        ).encode()
    out += (
        f"--{_BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="{file_field}"; filename="f.bin"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    out += content + f"\r\n--{_BOUNDARY}--\r\n".encode()
    return out


def _upload_body(content: bytes = b"x" * 200_000) -> _Body:
    return _Body(
        _multipart(
            {
                "sha256": hashlib.sha256(content).hexdigest(),
                "appliance_version": "1.0.0",
            },
            "file",
            content,
        )
    )


@pytest.fixture
def spools(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Every temporary file Starlette's multipart parser creates."""
    created: list[object] = []
    real = starlette.formparsers.SpooledTemporaryFile

    def counting(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        f = real(*args, **kwargs)
        created.append(f)
        return f

    monkeypatch.setattr(starlette.formparsers, "SpooledTemporaryFile", counting)
    return created


def _roomy_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    def usage(_path):  # noqa: ANN001, ANN202
        return SimpleNamespace(total=100 * GIB, used=10 * GIB, free=90 * GIB)

    monkeypatch.setattr(upgrade_image_space, "shutil", SimpleNamespace(disk_usage=usage))


def _full_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    def usage(_path):  # noqa: ANN001, ANN202
        return SimpleNamespace(total=100 * GIB, used=100 * GIB - 1, free=1)

    monkeypatch.setattr(upgrade_image_space, "shutil", SimpleNamespace(disk_usage=usage))


async def _post(
    client: AsyncClient,
    path: str,
    body: _Body,
    *,
    headers: dict[str, str] | None = None,
    content_length: int | None = None,
    content_type: str = _MULTIPART,
):  # noqa: ANN202
    h = {"Content-Type": content_type, **(headers or {})}
    if content_length is not None:
        h["Content-Length"] = str(content_length)
    return await client.post(path, content=body.stream(), headers=h)


# ── upgrade-image upload ─────────────────────────────────────────────


async def test_upload_without_credentials_and_no_length_is_refused_unread(
    client: AsyncClient, spools: list[object], monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _roomy_disk(monkeypatch)
    body = _upload_body()
    resp = await _post(client, _BASE, body)
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_upload_without_credentials_and_a_large_length_is_refused_unread(
    client: AsyncClient, spools: list[object], monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _roomy_disk(monkeypatch)
    body = _upload_body()
    resp = await _post(client, _BASE, body, content_length=4 * GIB - 1)
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_upload_with_an_invalid_token_is_refused_unread(
    client: AsyncClient, spools: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    _roomy_disk(monkeypatch)
    body = _upload_body()
    resp = await _post(
        client, _BASE, body, headers=_hdr("not-a-token"), content_length=len(body.payload)
    )
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_free_space_is_not_reported_to_an_unauthenticated_caller(
    client: AsyncClient, spools: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The headroom refusal says how close the node is to its eviction
    line, so it is answered only once the caller is authorised."""
    _full_disk(monkeypatch)
    body = _upload_body()
    resp = await _post(client, _BASE, body, content_length=len(body.payload))
    assert resp.status_code == 401, resp.text
    assert body.read is False


async def test_upload_by_a_user_without_the_permission_is_refused_unread(
    db_session: AsyncSession,
    client: AsyncClient,
    spools: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _roomy_disk(monkeypatch)
    token = await _token(db_session, superadmin=False, username="plainupload")
    body = _upload_body()
    resp = await _post(client, _BASE, body, headers=_hdr(token), content_length=len(body.payload))
    assert resp.status_code == 403, resp.text
    # The answer the route's own permission dependency gives.
    assert resp.json()["detail"] == "Permission denied: need 'admin' on 'appliance'"
    assert body.read is False
    assert spools == []
    # ...and the denial is audited the same way.
    denied = (
        (await db_session.execute(select(AuditLog).where(AuditLog.result == "denied")))
        .scalars()
        .all()
    )
    assert [(r.action, r.resource_type) for r in denied] == [("admin", "appliance")]


async def test_superadmin_upload_without_a_length_is_refused_unread(
    db_session: AsyncSession,
    client: AsyncClient,
    spools: list[object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """A chunked upload has no size to check against the receiving node's
    free space, so it is refused (411) rather than spooled unchecked."""
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _roomy_disk(monkeypatch)
    token = await _token(db_session, username="chunkedadmin")
    body = _upload_body()
    resp = await _post(client, _BASE, body, headers=_hdr(token))
    assert resp.status_code == 411, resp.text
    assert "Content-Length" in resp.json()["detail"]
    assert body.read is False
    assert spools == []
    assert list(tmp_path.iterdir()) == []


async def test_superadmin_upload_over_the_headroom_is_refused_unread(
    db_session: AsyncSession,
    client: AsyncClient,
    spools: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _full_disk(monkeypatch)
    token = await _token(db_session, username="fulladmin")
    body = _upload_body()
    resp = await _post(client, _BASE, body, headers=_hdr(token), content_length=len(body.payload))
    assert resp.status_code == 422, resp.text
    assert "evict" in resp.json()["detail"]
    assert body.read is False
    assert spools == []


async def test_superadmin_streamed_upload_with_a_length_still_stores(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(upgrade_images, "SLOT_IMAGE_DIR", tmp_path)
    _roomy_disk(monkeypatch)
    token = await _token(db_session, username="honestadmin")
    content = b"y" * 300_000
    body = _upload_body(content)
    resp = await _post(client, _BASE, body, headers=_hdr(token), content_length=len(body.payload))
    assert resp.status_code == 200, resp.text
    assert body.read is True
    row = resp.json()
    assert row["sha256"] == hashlib.sha256(content).hexdigest()
    assert row["size_bytes"] == len(content)
    assert (tmp_path / f"{row['id']}.raw.xz").exists()


async def test_import_from_github_json_body_is_refused_unread_without_credentials(
    client: AsyncClient,
) -> None:
    body = _Body(b'{"tag": "' + b"a" * 100_000 + b'"}')
    resp = await _post(
        client,
        f"{_BASE}/import-from-github",
        body,
        content_type="application/json",
        content_length=len(body.payload),
    )
    assert resp.status_code == 401, resp.text
    assert body.read is False


# ── backup ───────────────────────────────────────────────────────────


async def test_backup_restore_without_credentials_is_refused_unread(
    client: AsyncClient, spools: list[object]
) -> None:
    body = _Body(
        _multipart(
            {"passphrase": "p" * 12, "confirmation_phrase": "RESTORE-FROM-BACKUP"},
            "archive",
            b"z" * 200_000,
        )
    )
    resp = await _post(client, "/api/v1/backup/restore", body)
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_backup_manifest_preview_by_a_non_superadmin_is_refused_unread(
    db_session: AsyncSession, client: AsyncClient, spools: list[object]
) -> None:
    token = await _token(db_session, superadmin=False, username="plainbackup")
    body = _Body(_multipart({}, "archive", b"z" * 200_000))
    resp = await _post(
        client,
        "/api/v1/backup/manifest-preview",
        body,
        headers=_hdr(token),
        content_length=len(body.payload),
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == "Superadmin required"
    assert body.read is False
    assert spools == []


async def test_backup_target_json_body_is_refused_unread_without_credentials(
    client: AsyncClient,
) -> None:
    body = _Body(b'{"name": "' + b"a" * 100_000 + b'"}')
    resp = await _post(
        client,
        "/api/v1/backup/targets",
        body,
        content_type="application/json",
        content_length=len(body.payload),
    )
    assert resp.status_code == 401, resp.text
    assert body.read is False


# ── upload routes on the importer and settings routers (#2780) ────


async def test_bind9_import_without_credentials_is_refused_unread(
    client: AsyncClient, spools: list[object]
) -> None:
    body = _Body(_multipart({}, "file", b"$ORIGIN example.com.\n" * 20_000))
    resp = await _post(client, "/api/v1/dns/import/bind9/preview", body)
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_kea_import_without_credentials_is_refused_unread(
    client: AsyncClient, spools: list[object]
) -> None:
    body = _Body(_multipart({}, "file", b"{}" + b" " * 200_000))
    resp = await _post(client, "/api/v1/dhcp/import/kea/preview", body)
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_zone_spreadsheet_import_without_credentials_is_refused_unread(
    client: AsyncClient, spools: list[object]
) -> None:
    zone = "00000000-0000-4000-8000-000000000001"
    body = _Body(_multipart({}, "file", b"name,type,value\n" * 20_000))
    resp = await _post(
        client,
        f"/api/v1/dns/groups/{zone}/zones/{zone}/import/spreadsheet/preview",
        body,
    )
    assert resp.status_code == 401, resp.text
    assert body.read is False
    assert spools == []


async def test_ipam_import_by_a_user_without_the_permission_is_refused_unread(
    db_session: AsyncSession, client: AsyncClient, spools: list[object]
) -> None:
    """The IPAM router's permission gate is a router-level dependency, and
    it runs before the body too: 403 with the same detail and a ``denied``
    audit row, the upload unread."""
    token = await _token(db_session, superadmin=False, username="plainimport")
    body = _Body(_multipart({"strategy": "skip"}, "file", b"network\n10.0.0.0/24\n" * 10_000))
    resp = await _post(
        client,
        "/api/v1/ipam/import/preview",
        body,
        headers=_hdr(token),
        content_length=len(body.payload),
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"].startswith("Permission denied")
    assert body.read is False
    assert spools == []
    denied = (
        (await db_session.execute(select(AuditLog).where(AuditLog.result == "denied")))
        .scalars()
        .all()
    )
    assert len(denied) == 1


async def test_logo_upload_by_a_non_superadmin_is_refused_unread(
    db_session: AsyncSession, client: AsyncClient, spools: list[object]
) -> None:
    token = await _token(db_session, superadmin=False, username="plainlogo")
    body = _Body(_multipart({}, "file", b"\x89PNG" + b"0" * 200_000))
    resp = await client.put(
        "/api/v1/settings/branding/logo",
        content=body.stream(),
        headers={**_hdr(token), "Content-Type": _MULTIPART},
    )
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"] == "Superadmin required"
    assert body.read is False
    assert spools == []


async def test_superadmin_streamed_logo_upload_still_stores(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _token(db_session, username="logoadmin")
    png = _tiny_png()
    body = _Body(_multipart({}, "file", png))
    resp = await client.put(
        "/api/v1/settings/branding/logo",
        content=body.stream(),
        headers={**_hdr(token), "Content-Type": _MULTIPART},
    )
    assert resp.status_code == 200, resp.text
    assert body.read is True
    public = (await client.get("/api/v1/settings/public")).json()
    assert public["logo_sha256"] == hashlib.sha256(png).hexdigest()


# ── JSON routes on the importer routers ──────────────────────────────

# Not JSON at all: a route that parsed it would answer 422, not 401 / 403.
_UNPARSEABLE = b"{" + b"x" * 200_000


async def _post_json(
    client: AsyncClient, path: str, body: _Body, headers=None
):  # noqa: ANN001, ANN202
    return await _post(
        client,
        path,
        body,
        headers=headers,
        content_type="application/json",
        content_length=len(body.payload),
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/dns/import/bind9/commit",
        "/api/v1/dns/import/powerdns/preview",
        "/api/v1/dhcp/import/kea/commit",
        "/api/v1/dhcp/import/windows/preview",
        "/api/v1/ipam/import/preview-json",
        "/api/v1/ipam/import/netbox/commit",
    ],
)
async def test_import_json_route_without_credentials_is_refused_unparsed(
    client: AsyncClient, path: str
) -> None:
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(client, path, body)
    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"] == "Not authenticated"
    assert body.read is False


async def test_import_json_route_with_an_invalid_token_is_refused_unparsed(
    client: AsyncClient,
) -> None:
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(
        client, "/api/v1/dns/import/bind9/commit", body, headers=_hdr("not-a-token")
    )
    assert resp.status_code == 401, resp.text
    assert body.read is False


async def test_import_json_route_by_a_non_superadmin_is_refused_unparsed(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """The route's own ``SuperAdmin`` answer, before the body is read."""
    token = await _token(db_session, superadmin=False, username="plainjson")
    for path in ("/api/v1/dhcp/import/kea/commit", "/api/v1/ipam/import/netbox/preview"):
        body = _Body(_UNPARSEABLE)
        resp = await _post_json(client, path, body, headers=_hdr(token))
        assert resp.status_code == 403, (path, resp.text)
        assert resp.json()["detail"] == "Superadmin required"
        assert body.read is False


async def test_import_json_route_for_a_superadmin_still_reads_the_body(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    token = await _token(db_session, username="jsonadmin")
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(client, "/api/v1/dns/import/bind9/commit", body, headers=_hdr(token))
    assert body.read is True
    # The body is parsed (and refused as JSON) only once the caller is known.
    assert resp.status_code == 422, resp.text


# ── DNS agent routes ─────────────────────────────────────────────────


async def _dns_agent_headers(db: AsyncSession) -> dict[str, str]:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()
    server = DNSServer(
        group_id=group.id,
        driver="bind9",
        host="10.0.0.53",
        name=f"ns-{uuid.uuid4().hex[:6]}",
        is_primary=True,
        agent_id=uuid.uuid4(),
        agent_fingerprint="fp",
    )
    db.add(server)
    await db.flush()
    token, _exp = dns_agent_token.mint_agent_token(str(server.id), str(server.agent_id), "fp")
    server.agent_jwt_hash = dns_agent_token.hash_token(token)
    await db.commit()
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "headers,detail",
    [
        ({}, "Missing Bearer token"),
        ({"Authorization": "Basic abc"}, "Missing Bearer token"),
    ],
)
async def test_agent_ingest_without_an_agent_token_is_refused_unparsed(
    client: AsyncClient, headers: dict[str, str], detail: str
) -> None:
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(client, "/api/v1/dns/agents/ingested-records", body, headers=headers)
    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"] == detail
    assert body.read is False


async def test_agent_ingest_with_an_invalid_agent_token_is_refused_unparsed(
    client: AsyncClient,
) -> None:
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(
        client,
        "/api/v1/dns/agents/ingested-records",
        body,
        headers={"Authorization": "Bearer not-a-token"},
    )
    assert resp.status_code == 401, resp.text
    assert resp.json()["detail"].startswith("Invalid token")
    assert body.read is False


async def test_agent_ingest_with_a_user_token_is_refused_unparsed(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """A user's session token is not an agent token."""
    token = await _token(db_session, username="notanagent")
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(
        client, "/api/v1/dns/agents/ingested-records", body, headers=_hdr(token)
    )
    assert resp.status_code == 401, resp.text
    assert body.read is False


async def test_agent_ingest_with_a_valid_agent_token_still_reads_the_body(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    headers = await _dns_agent_headers(db_session)
    body = _Body(_UNPARSEABLE)
    resp = await _post_json(client, "/api/v1/dns/agents/ingested-records", body, headers=headers)
    assert body.read is True
    assert resp.status_code == 422, resp.text

    body = _Body(b'{"zone_name": "nosuch.example.com", "records": []}')
    resp = await _post_json(client, "/api/v1/dns/agents/ingested-records", body, headers=headers)
    assert body.read is True
    assert resp.status_code == 200, resp.text


async def test_agent_register_without_the_bootstrap_key_is_refused_unparsed(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DNS_AGENT_KEY", "the-bootstrap-key")
    for headers in ({}, {"X-DNS-Agent-Key": "wrong"}):
        body = _Body(_UNPARSEABLE)
        resp = await _post_json(client, "/api/v1/dns/agents/register", body, headers=headers)
        assert resp.status_code == 401, resp.text
        assert resp.json()["detail"] == "Invalid bootstrap key"
        assert body.read is False

    body = _Body(_UNPARSEABLE)
    resp = await _post_json(
        client,
        "/api/v1/dns/agents/register",
        body,
        headers={"X-DNS-Agent-Key": "the-bootstrap-key"},
    )
    assert body.read is True
    assert resp.status_code == 422, resp.text


async def test_an_overridden_agent_check_is_not_run_before_the_body(
    client: AsyncClient,
) -> None:
    """Tests replace ``_auth_agent`` through ``dependency_overrides``; the
    override is what the route then authorises with."""
    app.dependency_overrides[dns_agents._auth_agent] = lambda: (None, {})
    try:
        body = _Body(_UNPARSEABLE)
        resp = await _post_json(client, "/api/v1/dns/agents/ingested-records", body)
    finally:
        app.dependency_overrides.pop(dns_agents._auth_agent, None)
    assert body.read is True
    assert resp.status_code == 422, resp.text


# ── structure ────────────────────────────────────────────────────────

# The nginx locations that raise the body limit above the 1 MiB default
# (frontend/default.conf.template and the chart's frontend-tls-config.yaml).
# A route under one of these that takes a body must authorise first.
_LARGE_BODY_PREFIXES = ("/api/v1/backup/", "/api/v1/appliance/upgrade-images")


def _effective_routes(routes):  # noqa: ANN001, ANN202
    """(full path, route) for every API route, through included routers."""
    for r in routes:
        candidates = getattr(r, "effective_candidates", None)
        if candidates is not None:
            for c in candidates():
                if hasattr(c, "effective_candidates"):
                    yield from _effective_routes([c])
                elif isinstance(c.original_route, APIRoute):
                    yield c.path, c.original_route
        elif isinstance(r, APIRoute):
            yield r.path, r
        else:
            nested = getattr(r, "original_router", None)
            if nested is not None:
                yield from _effective_routes(nested.routes)


# The slot-image mirror's router is mounted only on the mirror Deployment
# (``SLOT_IMAGE_MIRROR_MODE``), which is the same app; the api the tests
# import does not carry it, so it is added here at the path it is served on.
_MIRROR_PREFIX = "/api/v1/appliance/internal/slot-images"


def _deployed_routes():  # noqa: ANN202
    """(full path, route) for every API route either deployment serves: the
    api, and the slot-image mirror."""
    yield from _effective_routes(app.routes)
    for r in slot_image_mirror.router.routes:
        if isinstance(r, APIRoute):
            yield _MIRROR_PREFIX + r.path, r


# The one form route that is not an upload: the SSO callback, whose body
# is the identity provider's signed response, i.e. the credential itself.
_FORM_ROUTES_READ_FIRST = {
    ("POST", "/api/v1/auth/{provider_id}/callback"): "the SSO response is the credential",
}


def test_every_upload_route_checks_the_login_before_reading_the_body() -> None:
    """Every route taking a multipart / form body (a file upload) uses the
    route class, so a new upload route on a plain router fails here."""
    uploads = [
        (method, path, route)
        for path, route in _effective_routes(app.routes)
        if takes_upload(route)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"})
    ]
    found = {(m, p) for m, p, _ in uploads}
    # Guard against the walk silently finding nothing.
    for expected in (
        ("POST", "/api/v1/dns/import/bind9/preview"),
        ("POST", "/api/v1/dhcp/import/kea/preview"),
        ("POST", "/api/v1/dhcp/import/isc/preview"),
        ("POST", "/api/v1/ipam/import/preview"),
        ("POST", "/api/v1/ipam/import/commit"),
        ("POST", "/api/v1/ipam/import/addresses/preview"),
        ("POST", "/api/v1/ipam/import/addresses/commit"),
        ("POST", "/api/v1/dns/groups/{group_id}/zones/{zone_id}/import/spreadsheet/preview"),
        ("POST", "/api/v1/dns/groups/{group_id}/zones/{zone_id}/import/spreadsheet/commit"),
        ("PUT", "/api/v1/settings/branding/logo"),
    ):
        assert expected in found, expected
    unchecked = sorted(
        f"{m} {p}"
        for m, p, r in uploads
        if not isinstance(r, PreBodyAuthRoute) and (m, p) not in _FORM_ROUTES_READ_FIRST
    )
    assert unchecked == []
    assert set(_FORM_ROUTES_READ_FIRST) <= found


def test_router_level_dependencies_are_still_visible() -> None:
    """The IPAM upload routes' permission gate is a router-level dependency,
    reached through a FastAPI-private context variable. If a FastAPI upgrade
    removes it, the login is still checked first but that gate silently
    moves back behind the body read; this fails so the change is seen."""
    assert EFFECTIVE_CONTEXT_VAR is not None, (
        "fastapi.routing._effective_route_context_var is gone: "
        "app.api.pre_body_auth must find router-level dependencies another way"
    )


def test_every_body_route_under_a_large_body_location_authorises_first() -> None:
    found = [
        (path, route)
        for path, route in _effective_routes(app.routes)
        if path.startswith(_LARGE_BODY_PREFIXES) and route.dependant.body_params
    ]
    paths = {p for p, _ in found}
    # Guard against the walk silently finding nothing.
    assert "/api/v1/appliance/upgrade-images" in paths
    assert "/api/v1/backup/restore" in paths
    wrong = [p for p, r in found if not isinstance(r, PreBodyAuthRoute)]
    assert wrong == []


def _checks_before_body(route: APIRoute) -> bool:
    if not isinstance(route, PreBodyAuthRoute):
        return False
    return not isinstance(route, PreBodyAuthUploadRoute) or takes_upload(route)


def test_every_body_route_with_a_large_allowance_authorises_first() -> None:
    """Every route ``app.core.body_limit`` lets take more than the app-wide
    cap checks the caller before reading the body, JSON routes included.

    A route with no body parameter is included too: FastAPI reads nothing
    before it runs its dependencies, so such a route may read its body as a
    raw stream in the handler (the slot-image mirror write, the pcap
    upload), and must then declare its authorisation as a dependency rather
    than call it from the handler, where this test cannot see it."""
    found = []
    for path, route in _deployed_routes():
        concrete = re.sub(r"\{[^}]+\}", "x", path)
        for method in route.methods - {"HEAD", "OPTIONS"}:
            if limit_for(method, concrete, DEFAULT_MAX_REQUEST_BODY_BYTES) > (
                DEFAULT_MAX_REQUEST_BODY_BYTES
            ):
                found.append((method, path, route))
    paths = {p for _, p, _ in found}
    # Guard against the walk silently finding nothing.
    for expected in (
        "/api/v1/dns/agents/ingested-records",
        "/api/v1/dns/import/bind9/commit",
        "/api/v1/dhcp/import/kea/commit",
        "/api/v1/ipam/import/preview-json",
        "/api/v1/ipam/import/netbox/commit",
        "/api/v1/appliance/internal/slot-images/{image_id}",
        "/api/v1/appliance/supervisor/pcap/upload/{capture_id}",
    ):
        assert expected in paths, expected
    wrong = sorted(
        f"{m} {p}"
        for m, p, r in found
        if not (_checks_before_body(r) if r.dependant.body_params else auth_checks(r))
    )
    assert wrong == []


def test_every_body_route_on_the_dns_agent_router_authorises_first() -> None:
    found = [
        (path, route)
        for path, route in _effective_routes(app.routes)
        if path.startswith("/api/v1/dns/agents/") and route.dependant.body_params
    ]
    assert "/api/v1/dns/agents/heartbeat" in {p for p, _ in found}
    assert [p for p, r in found if not _checks_before_body(r)] == []


def test_a_body_route_with_no_authorisation_is_refused_when_built() -> None:
    router = APIRouter(route_class=PreBodyAuthRoute)

    async def open_upload(payload: dict = Body(...)) -> dict:  # noqa: B008
        return payload

    with pytest.raises(RuntimeError, match="no authorisation dependency"):
        router.add_api_route("/open", open_upload, methods=["POST"])

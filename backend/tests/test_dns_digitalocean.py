"""Offline unit tests for the DigitalOcean DNS driver (issue #37).

DigitalOcean is a tier-3 provider with no test account, so every test
monkeypatches :meth:`DigitalOceanDNSDriver._client` to return a fake
async-context-manager client that serves canned envelopes and records the
calls made against it. Nothing here touches the network.

Unlike Cloudflare, DigitalOcean has no success-envelope (a 2xx status is the
success signal) and no opaque zone id — records are scoped by the bare domain
name and the record list has no server-side ``data`` filter, so multi-value
RRset disambiguation (issue #331) happens entirely client-side.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.digitalocean import DigitalOceanDNSDriver


class _FakeResponse:
    """Minimal stand-in for an ``httpx.Response`` (status + json())."""

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Async-context-manager fake of ``httpx.AsyncClient``.

    Each verb pops the next queued response off the matching list and
    records ``(method, path, params, json)`` for assertion. A queued
    response can be a ``_FakeResponse`` or a zero-arg callable returning
    one (so a test can vary the reply by call order).
    """

    def __init__(self, queues: dict[str, list[Any]]) -> None:
        self._queues = queues
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def _next(self, method: str, path: str, params: Any, body: Any) -> _FakeResponse:
        self.calls.append({"method": method, "path": path, "params": params, "json": body})
        queue = self._queues.get(method)
        if not queue:
            raise AssertionError(f"unexpected {method} {path} (no queued response)")
        item = queue.pop(0)
        return item() if callable(item) else item

    async def get(self, path: str, params: Any = None) -> _FakeResponse:
        return self._next("get", path, params, None)

    async def post(self, path: str, json: Any = None) -> _FakeResponse:
        return self._next("post", path, None, json)

    async def put(self, path: str, json: Any = None) -> _FakeResponse:
        return self._next("put", path, None, json)

    async def delete(self, path: str, params: Any = None) -> _FakeResponse:
        return self._next("delete", path, params, None)


def _domains(names: list[str], *, next_url: str | None = None) -> dict[str, Any]:
    """Build a DigitalOcean ``GET /v2/domains`` response."""
    return {
        "domains": [{"name": n} for n in names],
        "links": {"pages": {"next": next_url}} if next_url else {"pages": {}},
        "meta": {"total": len(names)},
    }


def _records(recs: list[dict[str, Any]], *, next_url: str | None = None) -> dict[str, Any]:
    """Build a DigitalOcean ``GET /v2/domains/{d}/records`` response."""
    return {
        "domain_records": recs,
        "links": {"pages": {"next": next_url}} if next_url else {"pages": {}},
        "meta": {"total": len(recs)},
    }


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> DigitalOceanDNSDriver:
    driver = DigitalOceanDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda token: fake)
    return driver


class _Server:
    """Stub DNSServer row — only the attrs the driver reads."""

    id = "srv-1"
    name = "do-test"
    credentials_encrypted = b"x"


_CREDS = {"api_token": "tok"}


# ── _list_zones pagination ──────────────────────────────────────────────
async def test_list_zones_paginates_and_flags_reverse(monkeypatch: pytest.MonkeyPatch) -> None:
    page1 = _domains(["example.com", "10.in-addr.arpa"], next_url="https://api/domains?page=2")
    page2 = _domains(["example.net"])
    fake = _FakeClient({"get": [_FakeResponse(200, page1), _FakeResponse(200, page2)]})
    driver = _patch_client(monkeypatch, fake)

    zones = await driver._list_zones(_Server(), _CREDS)

    assert [z.name for z in zones] == ["example.com.", "10.in-addr.arpa.", "example.net."]
    # No opaque zone id — the bare domain name is the handle.
    assert [z.zone_id for z in zones] == ["example.com", "10.in-addr.arpa", "example.net"]
    # Reverse-zone detection.
    assert zones[1].is_reverse is True
    assert zones[0].is_reverse is False
    # Two pages → two GETs (page 2 followed via links.pages.next).
    assert sum(1 for c in fake.calls if c["method"] == "get") == 2
    assert fake.calls[0]["path"] == "/domains"
    assert fake.calls[0]["params"] == {"per_page": 50, "page": 1}
    assert fake.calls[1]["params"] == {"per_page": 50, "page": 2}


# ── _list_zone_records relativization + TTL handling ────────────────────
async def test_list_zone_records_relativizes_and_normalizes_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _records(
        [
            {"id": 1, "name": "@", "type": "A", "data": "1.2.3.4", "ttl": 1800},
            {"id": 2, "name": "www", "type": "A", "data": "5.6.7.8", "ttl": 300},
            {
                "id": 3,
                "name": "@",
                "type": "MX",
                "data": "mail.example.com.",
                "ttl": 3600,
                "priority": 10,
            },
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    # Apex stays "@"; sub-label kept relative; ttl=1800 (default) → None.
    assert recs[0] == RecordData(name="@", record_type="A", value="1.2.3.4", ttl=None)
    assert recs[1] == RecordData(name="www", record_type="A", value="5.6.7.8", ttl=300)
    assert recs[2].name == "@"
    assert recs[2].priority == 10
    assert recs[2].ttl == 3600
    # Records are scoped by the bare domain name (no zone-id lookup).
    assert fake.calls[0]["path"] == "/domains/example.com/records"
    assert fake.calls[0]["params"] == {"per_page": 50, "page": 1}


# ── _apply_record create ────────────────────────────────────────────────
async def test_apply_record_create_posts_relative_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(201, {"domain_record": {"id": 99}})]})
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="1.1.1.1", ttl=None),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["path"] == "/domains/example.com/records"
    # ttl omitted when None → DigitalOcean applies its account default.
    assert post["json"] == {"type": "A", "name": "www", "data": "1.1.1.1"}


async def test_apply_record_create_apex_uses_at_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(201, {"domain_record": {"id": 1}})]})
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="A", value="9.9.9.9", ttl=600),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = fake.calls[0]
    # Apex renders as "@" (DigitalOcean takes relative names), ttl threaded.
    assert post["json"] == {"type": "A", "name": "@", "data": "9.9.9.9", "ttl": 600}


# ── _apply_record update (existing record found → PUT) ──────────────────
async def test_apply_record_update_puts_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(
                    200,
                    _records([{"id": 42, "name": "www", "type": "A", "data": "2.2.2.2"}]),
                ),
            ],
            "put": [_FakeResponse(200, {"domain_record": {"id": 42}})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="2.2.2.2", ttl=120),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    put = next(c for c in fake.calls if c["method"] == "put")
    assert put["path"] == "/domains/example.com/records/42"
    assert put["json"]["data"] == "2.2.2.2"
    assert put["json"]["ttl"] == 120


# ── _apply_record update with no match → falls back to create (POST) ────
async def test_apply_record_update_missing_creates(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _records([]))],  # no existing record
            "post": [_FakeResponse(201, {"domain_record": {"id": 7}})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="A", value="3.3.3.3", ttl=None),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    assert [c["method"] for c in fake.calls] == ["get", "post"]
    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["name"] == "@"
    assert post["path"] == "/domains/example.com/records"


# ── _apply_record delete (found → DELETE) ───────────────────────────────
async def test_apply_record_delete_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(
                    200,
                    _records([{"id": 55, "name": "www", "type": "A", "data": "1.1.1.1"}]),
                ),
            ],
            "delete": [_FakeResponse(204, None)],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="1.1.1.1"),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    delete = next(c for c in fake.calls if c["method"] == "delete")
    assert delete["path"] == "/domains/example.com/records/55"


# ── _apply_record delete with no match → no-op (no DELETE issued) ───────
async def test_apply_record_delete_missing_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_FakeResponse(200, _records([]))]})  # nothing to delete
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="gone", record_type="A", value="1.1.1.1"),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    # Only the lookup happened — no DELETE.
    assert [c["method"] for c in fake.calls] == ["get"]


# ── _apply_record update targets the right value of a multi-value RRset ──
async def test_apply_record_update_matches_content_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A round-robin A name has two values on DigitalOcean; updating the TTL of
    the ``5.6.7.8`` record must PUT against *its* id, not the first row's
    (issue #331). DigitalOcean has no server-side data filter, so the match is
    purely client-side."""
    multi = _records(
        [
            {"id": 100, "type": "A", "name": "www", "data": "1.2.3.4"},
            {"id": 101, "type": "A", "name": "www", "data": "5.6.7.8"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, multi)],
            "put": [_FakeResponse(200, {"domain_record": {"id": 101}})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="5.6.7.8", ttl=600),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    # We PUT against the id whose data actually matched the op value.
    put = next(c for c in fake.calls if c["method"] == "put")
    assert put["path"] == "/domains/example.com/records/101"
    assert put["json"]["data"] == "5.6.7.8"
    assert put["json"]["ttl"] == 600


# ── _apply_record delete targets the right value of a multi-value RRset ──
async def test_apply_record_delete_matches_content_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``delete A 1.2.3.4`` against a 2-value RRset must DELETE the row holding
    ``1.2.3.4`` even if DigitalOcean lists ``5.6.7.8`` first (issue #331)."""
    multi = _records(
        [
            {"id": 200, "type": "A", "name": "www", "data": "5.6.7.8"},
            {"id": 201, "type": "A", "name": "www", "data": "1.2.3.4"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, multi)],
            "delete": [_FakeResponse(204, None)],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="1.2.3.4"),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    delete = next(c for c in fake.calls if c["method"] == "delete")
    # The value-keyed row, not the first-listed sibling.
    assert delete["path"] == "/domains/example.com/records/201"


# ── _apply_record delete is a no-op when no value matches ───────────────
async def test_apply_record_delete_no_content_match_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If DigitalOcean returns sibling values but none equal the op value, the
    delete must be a safe no-op (no DELETE issued) rather than removing a
    wrong-value row (issue #331)."""
    multi = _records(
        [
            {"id": 300, "type": "A", "name": "www", "data": "5.6.7.8"},
            {"id": 301, "type": "A", "name": "www", "data": "9.9.9.9"},
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, multi)]})
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="1.2.3.4"),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    # Only the lookup happened — no DELETE against a non-matching value.
    assert [c["method"] for c in fake.calls] == ["get"]


# ── _find_record_id disambiguates MX rows by priority too ───────────────
async def test_apply_record_delete_mx_matches_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two MX records at the apex share a content host but differ by priority;
    deleting one must match content *and* priority (issue #331)."""
    multi = _records(
        [
            {"id": 10, "type": "MX", "name": "@", "data": "mail.example.com.", "priority": 10},
            {"id": 20, "type": "MX", "name": "@", "data": "mail.example.com.", "priority": 20},
        ]
    )
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, multi)],
            "delete": [_FakeResponse(204, None)],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="MX", value="mail.example.com.", priority=20),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    delete = next(c for c in fake.calls if c["method"] == "delete")
    assert delete["path"] == "/domains/example.com/records/20"


# ── _find_record_id pages through records to find a match ───────────────
async def test_find_record_id_follows_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    """The target value lives on page 2 — the client-side matcher must follow
    links.pages.next before giving up."""
    page1 = _records(
        [{"id": 1, "type": "A", "name": "www", "data": "1.1.1.1"}],
        next_url="https://api/domains/example.com/records?page=2",
    )
    page2 = _records([{"id": 2, "type": "A", "name": "www", "data": "2.2.2.2"}])
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, page1), _FakeResponse(200, page2)],
            "delete": [_FakeResponse(204, None)],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="2.2.2.2"),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    assert sum(1 for c in fake.calls if c["method"] == "get") == 2
    delete = next(c for c in fake.calls if c["method"] == "delete")
    assert delete["path"] == "/domains/example.com/records/2"


# ── _apply_zone create ───────────────────────────────────────────────────
async def test_apply_zone_create_posts_bare_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(201, {"domain": {"name": "example.org"}})]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "create")

    post = fake.calls[0]
    assert post["path"] == "/domains"
    assert post["json"] == {"name": "example.org"}


async def test_apply_zone_delete_uses_bare_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"delete": [_FakeResponse(204, None)]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "delete")

    assert [c["method"] for c in fake.calls] == ["delete"]
    assert fake.calls[0]["path"] == "/domains/example.org"


# ── #1889 — deleting a zone already absent at the provider is done ──────
async def test_apply_zone_delete_already_absent_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = {"id": "not_found", "message": "The resource you requested could not be found."}
    fake = _FakeClient({"delete": [_FakeResponse(404, body)]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "gone.example."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "delete")

    assert [c["method"] for c in fake.calls] == ["delete"]


async def test_apply_zone_delete_other_errors_still_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for status in (401, 429, 500):
        fake = _FakeClient({"delete": [_FakeResponse(status, {"message": "nope"})]})
        driver = _patch_client(monkeypatch, fake)
        zone = type("Z", (), {"name": "gone.example."})()
        with pytest.raises(CloudDNSError):
            await driver._apply_zone(_Server(), _CREDS, zone, "delete")


async def test_apply_zone_delete_404_without_not_found_id_still_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only DigitalOcean's documented ``{"id": "not_found"}`` means gone: a
    404 that is not its verdict on the domain must not drop the zone."""
    for body in ({}, {"id": "something_else", "message": "?"}):
        fake = _FakeClient({"delete": [_FakeResponse(404, body)]})
        driver = _patch_client(monkeypatch, fake)
        zone = type("Z", (), {"name": "gone.example."})()
        with pytest.raises(CloudDNSError):
            await driver._apply_zone(_Server(), _CREDS, zone, "delete")


# ── Error surfacing ─────────────────────────────────────────────────────
async def test_non_2xx_raises_clouddnserror(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"id": "unauthorized", "message": "Unable to authenticate you."}
    fake = _FakeClient({"get": [_FakeResponse(401, payload)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "Unable to authenticate you." in str(exc.value)


async def test_error_envelope_message_surfaced(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"id": "not_found", "message": "The resource you requested could not be found."}
    fake = _FakeClient({"get": [_FakeResponse(404, payload)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zone_records(_Server(), _CREDS, "example.com.")
    assert "could not be found" in str(exc.value)


async def test_non_2xx_without_message_falls_back_to_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient({"get": [_FakeResponse(500, "not json")]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "HTTP 500" in str(exc.value)


async def test_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = DigitalOceanDNSDriver()
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="A", value="1.1.1.1"),
        target_serial=1,
    )
    with pytest.raises(CloudDNSError):
        await driver._apply_record(_Server(), {}, change)


# ── Static helpers ──────────────────────────────────────────────────────
def test_relativize_helper() -> None:
    driver = DigitalOceanDNSDriver()
    assert driver._relativize("@", "example.com.") == "@"
    assert driver._relativize("www", "example.com.") == "www"
    assert driver._relativize("example.com.", "example.com.") == "@"
    assert driver._relativize("a.b.example.com.", "example.com") == "a.b"


def test_write_name_helper() -> None:
    driver = DigitalOceanDNSDriver()
    assert driver._write_name("@") == "@"
    assert driver._write_name("") == "@"
    assert driver._write_name("www") == "www"
    assert driver._write_name("www.") == "www"


def test_capabilities_shape() -> None:
    caps = DigitalOceanDNSDriver().capabilities()
    assert caps["name"] == "digitalocean"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["views"] is False
    assert caps["rpz"] is False
    # DigitalOcean exposes no online DNSSEC management via the API.
    assert caps["dnssec_online"] is False
    assert "CAA" in caps["record_types"]
    assert "SVCB" not in caps["record_types"]
    assert "HTTPS" not in caps["record_types"]

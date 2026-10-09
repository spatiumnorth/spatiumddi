"""Offline unit tests for the Linode DNS Manager driver (issue #29 / #37).

Linode is a token-only tier-3 provider with no test account, so every test
monkeypatches :meth:`LinodeDNSDriver._client` to return a fake
async-context-manager client that serves canned envelopes and records the
calls made against it. Nothing here touches the network.

Linode differs from Cloudflare in two ways the harness models:

* No ``{"success": bool}`` envelope — failure is a non-2xx status plus a
  ``{"errors": [{"reason"}]}`` body.
* Pagination is ``{"data": [...], "page", "pages", "results"}`` and record
  names are relative to the zone (apex is the empty string).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.linode import LinodeDNSDriver


class _FakeResponse:
    """Minimal stand-in for an ``httpx.Response`` (status + json())."""

    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    """Async-context-manager fake of ``httpx.AsyncClient``.

    Each verb pops the next queued response off the matching list and
    records ``(method, path, params, headers, json)`` for assertion. A
    queued response can be a ``_FakeResponse`` or a zero-arg callable
    returning one (so a test can vary the reply by call order).
    """

    def __init__(self, queues: dict[str, list[Any]]) -> None:
        self._queues = queues
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def _next(self, method: str, path: str, params: Any, headers: Any, body: Any) -> _FakeResponse:
        self.calls.append(
            {"method": method, "path": path, "params": params, "headers": headers, "json": body}
        )
        queue = self._queues.get(method)
        if not queue:
            raise AssertionError(f"unexpected {method} {path} (no queued response)")
        item = queue.pop(0)
        return item() if callable(item) else item

    async def get(self, path: str, params: Any = None, headers: Any = None) -> _FakeResponse:
        return self._next("get", path, params, headers, None)

    async def post(self, path: str, json: Any = None, headers: Any = None) -> _FakeResponse:
        return self._next("post", path, None, headers, json)

    async def put(self, path: str, json: Any = None, headers: Any = None) -> _FakeResponse:
        return self._next("put", path, None, headers, json)

    async def delete(self, path: str, params: Any = None, headers: Any = None) -> _FakeResponse:
        return self._next("delete", path, params, headers, None)


def _env(data: Any, *, page: int = 1, pages: int = 1) -> dict[str, Any]:
    """Build a Linode-shaped paginated list envelope."""
    items = data if isinstance(data, list) else [data]
    return {"data": items, "page": page, "pages": pages, "results": len(items)}


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> LinodeDNSDriver:
    driver = LinodeDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda token: fake)
    return driver


class _Server:
    """Stub DNSServer row — only the attrs the driver reads."""

    id = "srv-1"
    name = "linode-test"
    credentials_encrypted = b"x"


_CREDS = {"api_token": "tok"}


# ── _list_zones pagination + reverse flag ───────────────────────────────
async def test_list_zones_paginates_and_flags_reverse(monkeypatch: pytest.MonkeyPatch) -> None:
    page1 = _env(
        [
            {"id": 1, "domain": "example.com", "type": "master"},
            {"id": 2, "domain": "10.in-addr.arpa", "type": "master"},
        ],
        page=1,
        pages=2,
    )
    page2 = _env([{"id": 3, "domain": "example.net", "type": "master"}], page=2, pages=2)
    fake = _FakeClient({"get": [_FakeResponse(200, page1), _FakeResponse(200, page2)]})
    driver = _patch_client(monkeypatch, fake)

    zones = await driver._list_zones(_Server(), _CREDS)

    assert [z.name for z in zones] == ["example.com.", "10.in-addr.arpa.", "example.net."]
    assert [z.zone_id for z in zones] == ["1", "2", "3"]
    # Reverse-zone detection.
    assert zones[1].is_reverse is True
    assert zones[0].is_reverse is False
    # Two pages → two GETs.
    assert sum(1 for c in fake.calls if c["method"] == "get") == 2
    assert fake.calls[0]["params"] == {"page_size": 100, "page": 1}
    assert fake.calls[1]["params"] == {"page_size": 100, "page": 2}


# ── _list_zone_records relativization + TTL handling + MX priority ──────
async def test_list_zone_records_relativizes_and_normalizes_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain_lookup = _env([{"id": 42, "domain": "example.com"}])
    records = _env(
        [
            {"id": 100, "name": "", "type": "A", "target": "1.2.3.4", "ttl_sec": 0},
            {"id": 101, "name": "www", "type": "A", "target": "5.6.7.8", "ttl_sec": 300},
            {
                "id": 102,
                "name": "",
                "type": "MX",
                "target": "mail.example.com",
                "ttl_sec": 3600,
                "priority": 10,
            },
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, domain_lookup), _FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    # Apex (empty name) collapses to "@"; sub-label kept; ttl_sec=0 → None.
    assert recs[0] == RecordData(name="@", record_type="A", value="1.2.3.4", ttl=None)
    assert recs[1] == RecordData(name="www", record_type="A", value="5.6.7.8", ttl=300)
    assert recs[2].name == "@"
    assert recs[2].priority == 10
    assert recs[2].ttl == 3600
    # Domain id was resolved by name via the X-Filter header.
    assert fake.calls[0]["headers"] == {"X-Filter": json.dumps({"domain": "example.com"})}


# ── _apply_record create ────────────────────────────────────────────────
async def test_apply_record_create_posts_relative_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": 42, "domain": "example.com"}]))],
            "post": [_FakeResponse(200, {"id": 500})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="1.1.1.1", ttl=None),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["path"] == "/domains/42/records"
    assert post["json"] == {
        "type": "A",
        "name": "www",  # relative label, not absolute.
        "target": "1.1.1.1",
        "ttl_sec": 0,  # None → zone-default sentinel.
    }


# ── _apply_record create at apex uses empty name ────────────────────────
async def test_apply_record_create_apex_empty_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": 42, "domain": "example.com"}]))],
            "post": [_FakeResponse(200, {"id": 500})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="A", value="3.3.3.3", ttl=None),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["name"] == ""


# ── _apply_record update (existing record found → PUT) ──────────────────
async def test_apply_record_update_puts_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),  # resolve
                # find existing record (target-keyed lookup)
                _FakeResponse(200, _env([{"id": 700, "type": "A", "target": "2.2.2.2"}])),
            ],
            "put": [_FakeResponse(200, {"id": 700})],
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
    assert put["path"] == "/domains/42/records/700"
    assert put["json"]["target"] == "2.2.2.2"
    assert put["json"]["ttl_sec"] == 120


# ── _apply_record update with no match → falls back to create (POST) ────
async def test_apply_record_update_missing_creates(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),  # resolve
                _FakeResponse(200, _env([])),  # no existing record
            ],
            "post": [_FakeResponse(200, {"id": 500})],
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

    assert [c["method"] for c in fake.calls] == ["get", "get", "post"]
    post = next(c for c in fake.calls if c["method"] == "post")
    # Apex name renders as the empty string.
    assert post["json"]["name"] == ""


# ── _apply_record delete (found → DELETE) ───────────────────────────────
async def test_apply_record_delete_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),
                _FakeResponse(200, _env([{"id": 700, "type": "A", "target": "1.1.1.1"}])),
            ],
            "delete": [_FakeResponse(200, {})],
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
    assert delete["path"] == "/domains/42/records/700"


# ── _apply_record delete with no match → no-op (no DELETE issued) ───────
async def test_apply_record_delete_missing_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),
                _FakeResponse(200, _env([])),  # nothing to delete
            ]
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="gone", record_type="A", value="1.1.1.1"),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    # Only the two lookups happened — no DELETE.
    assert [c["method"] for c in fake.calls] == ["get", "get"]


# ── _apply_record update targets the right value of a multi-value RRset ──
async def test_apply_record_update_matches_target_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A round-robin A name has two values on Linode; updating the TTL of the
    ``5.6.7.8`` record must PUT against *its* id, not the first row's
    (issue #331)."""
    multi = _env(
        [
            {"id": 800, "type": "A", "name": "www", "target": "1.2.3.4"},
            {"id": 801, "type": "A", "name": "www", "target": "5.6.7.8"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),  # resolve
                _FakeResponse(200, multi),  # find existing record (name+type X-Filter)
            ],
            "put": [_FakeResponse(200, {"id": 801})],
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

    # The lookup carried the name+type X-Filter so Linode narrows the RRset…
    lookup = fake.calls[1]
    assert lookup["headers"] == {"X-Filter": json.dumps({"type": "A", "name": "www"})}
    # …and we PUT against the id whose target actually matched the op value.
    put = next(c for c in fake.calls if c["method"] == "put")
    assert put["path"] == "/domains/42/records/801"
    assert put["json"]["target"] == "5.6.7.8"
    assert put["json"]["ttl_sec"] == 600


# ── _apply_record delete targets the right value of a multi-value RRset ──
async def test_apply_record_delete_matches_target_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``delete A 1.2.3.4`` against a 2-value RRset must DELETE the row holding
    ``1.2.3.4`` even if Linode lists ``5.6.7.8`` first (issue #331)."""
    multi = _env(
        [
            {"id": 900, "type": "A", "name": "www", "target": "5.6.7.8"},
            {"id": 901, "type": "A", "name": "www", "target": "1.2.3.4"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),
                _FakeResponse(200, multi),
            ],
            "delete": [_FakeResponse(200, {})],
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
    assert delete["path"] == "/domains/42/records/901"


# ── _apply_record delete is a no-op when no value matches ───────────────
async def test_apply_record_delete_no_target_match_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Linode returns sibling values but none equal the op value, the delete
    must be a safe no-op (no DELETE issued) rather than removing a
    wrong-value row (issue #331)."""
    multi = _env(
        [
            {"id": 900, "type": "A", "name": "www", "target": "5.6.7.8"},
            {"id": 901, "type": "A", "name": "www", "target": "9.9.9.9"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),
                _FakeResponse(200, multi),
            ]
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

    # Only the two lookups happened — no DELETE against a non-matching value.
    assert [c["method"] for c in fake.calls] == ["get", "get"]


# ── _find_record_id disambiguates MX rows by priority too ───────────────
async def test_apply_record_delete_mx_matches_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two MX records at the apex share a target host but differ by priority;
    deleting one must match target *and* priority (issue #331)."""
    multi = _env(
        [
            {
                "id": 10,
                "type": "MX",
                "name": "",
                "target": "mail.example.com",
                "priority": 10,
            },
            {
                "id": 20,
                "type": "MX",
                "name": "",
                "target": "mail.example.com",
                "priority": 20,
            },
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": 42, "domain": "example.com"}])),
                _FakeResponse(200, multi),
            ],
            "delete": [_FakeResponse(200, {})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="MX", value="mail.example.com", priority=20),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    delete = next(c for c in fake.calls if c["method"] == "delete")
    assert delete["path"] == "/domains/42/records/20"


# ── _apply_zone create derives soa_email + sends type=master ────────────
async def test_apply_zone_create(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(200, {"id": 99})]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "create")

    post = fake.calls[0]
    assert post["path"] == "/domains"
    assert post["json"] == {
        "domain": "example.org",
        "type": "master",
        "soa_email": "hostmaster@example.org",
    }


async def test_apply_zone_delete_resolves_then_deletes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": 77, "domain": "example.org"}]))],
            "delete": [_FakeResponse(200, {})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "delete")

    assert [c["method"] for c in fake.calls] == ["get", "delete"]
    assert fake.calls[1]["path"] == "/domains/77"


# ── Error surfacing ─────────────────────────────────────────────────────
async def test_error_envelope_raises_clouddnserror(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"errors": [{"reason": "Invalid Token", "field": None}]}
    fake = _FakeClient({"get": [_FakeResponse(401, payload)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "Invalid Token" in str(exc.value)


async def test_error_envelope_with_field_is_qualified(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"errors": [{"reason": "domain must be unique", "field": "domain"}]}
    fake = _FakeClient({"post": [_FakeResponse(400, payload)]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    with pytest.raises(CloudDNSError) as exc:
        await driver._apply_zone(_Server(), _CREDS, zone, "create")
    assert "domain: domain must be unique" in str(exc.value)


async def test_non_2xx_without_errors_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_FakeResponse(500, {})]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "HTTP 500" in str(exc.value)


async def test_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = LinodeDNSDriver()
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
    driver = LinodeDNSDriver()
    assert driver._relativize("", "example.com.") == "@"
    assert driver._relativize("@", "example.com.") == "@"
    assert driver._relativize("www", "example.com.") == "www"
    # Defensive: an absolute name under the zone reduces to relative.
    assert driver._relativize("a.b.example.com.", "example.com") == "a.b"


def test_relative_name_helper() -> None:
    driver = LinodeDNSDriver()
    assert driver._relative_name("@", "example.com.") == ""
    assert driver._relative_name("", "example.com.") == ""
    assert driver._relative_name("www", "example.com.") == "www"
    assert driver._relative_name("www.example.com.", "example.com") == "www"


def test_capabilities_shape() -> None:
    caps = LinodeDNSDriver().capabilities()
    assert caps["name"] == "linode"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["views"] is False
    assert caps["rpz"] is False
    assert caps["dnssec_online"] is False
    assert "CAA" in caps["record_types"]
    assert "SVCB" not in caps["record_types"]
    assert "HTTPS" not in caps["record_types"]


# ── SRV split-form contract (#1526) ─────────────────────────────────────────


async def test_apply_record_create_srv_sends_weight_and_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": 42, "domain": "example.com"}]))],
            "post": [_FakeResponse(200, {"id": 501})],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com",
            ttl=3600,
            priority=10,
            weight=20,
            port=5060,
        ),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["priority"] == 10
    assert post["json"]["weight"] == 20
    assert post["json"]["port"] == 5060
    assert post["json"]["target"] == "sip.example.com"


async def test_list_zone_records_srv_weight_and_port(monkeypatch: pytest.MonkeyPatch) -> None:
    domain_lookup = _env([{"id": 42, "domain": "example.com"}])
    records = _env(
        [
            {
                "id": 103,
                "name": "_sip._tcp",
                "type": "SRV",
                "target": "sip.example.com",
                "ttl_sec": 3600,
                "priority": 10,
                "weight": 20,
                "port": 5060,
            }
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, domain_lookup), _FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    assert recs == [
        RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com",
            ttl=3600,
            priority=10,
            weight=20,
            port=5060,
        )
    ]

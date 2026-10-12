"""Offline unit tests for the Cloudflare DNS driver (issue #37).

Cloudflare is a tier-3 provider with no test account, so every test
monkeypatches :meth:`CloudflareDNSDriver._client` to return a fake
async-context-manager client that serves canned envelopes and records the
calls made against it. Nothing here touches the network.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember
from app.drivers.dns.cloudflare import CloudflareDNSDriver


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


def _env(result: Any, *, total_pages: int = 1, success: bool = True) -> dict[str, Any]:
    """Build a Cloudflare-shaped response envelope."""
    return {
        "success": success,
        "errors": [],
        "result": result,
        "result_info": {"total_pages": total_pages},
    }


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> CloudflareDNSDriver:
    driver = CloudflareDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda token: fake)
    return driver


class _Server:
    """Stub DNSServer row — only the attrs the driver reads."""

    id = "srv-1"
    name = "cf-test"
    credentials_encrypted = b"x"


_CREDS = {"api_token": "tok"}


# ── _list_zones pagination ──────────────────────────────────────────────
async def test_list_zones_paginates_and_flags_reverse(monkeypatch: pytest.MonkeyPatch) -> None:
    page1 = _env(
        [
            {"id": "z1", "name": "example.com"},
            {"id": "z2", "name": "10.in-addr.arpa"},
        ],
        total_pages=2,
    )
    page2 = _env([{"id": "z3", "name": "example.net"}], total_pages=2)
    fake = _FakeClient({"get": [_FakeResponse(200, page1), _FakeResponse(200, page2)]})
    driver = _patch_client(monkeypatch, fake)

    zones = await driver._list_zones(_Server(), _CREDS)

    assert [z.name for z in zones] == ["example.com.", "10.in-addr.arpa.", "example.net."]
    assert [z.zone_id for z in zones] == ["z1", "z2", "z3"]
    # Reverse-zone detection.
    assert zones[1].is_reverse is True
    assert zones[0].is_reverse is False
    # Two pages → two GETs.
    assert sum(1 for c in fake.calls if c["method"] == "get") == 2
    assert fake.calls[0]["params"] == {"per_page": 50, "page": 1}
    assert fake.calls[1]["params"] == {"per_page": 50, "page": 2}


# ── _list_zone_records relativization + TTL handling ────────────────────
async def test_list_zone_records_relativizes_and_normalizes_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    zone_lookup = _env([{"id": "zid"}])
    records = _env(
        [
            {"name": "example.com", "type": "A", "content": "1.2.3.4", "ttl": 1},
            {"name": "www.example.com", "type": "A", "content": "5.6.7.8", "ttl": 300},
            {
                "name": "example.com",
                "type": "MX",
                "content": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            },
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, zone_lookup), _FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    # Apex collapses to "@"; sub-label relativized; ttl=1 → None (automatic).
    assert recs[0] == RecordData(name="@", record_type="A", value="1.2.3.4", ttl=None)
    assert recs[1] == RecordData(name="www", record_type="A", value="5.6.7.8", ttl=300)
    assert recs[2].name == "@"
    assert recs[2].priority == 10
    assert recs[2].ttl == 3600
    # Zone-id was resolved by name (de-dotted).
    assert fake.calls[0]["params"] == {"name": "example.com"}


# ── _apply_record create ────────────────────────────────────────────────
async def test_apply_record_create_posts_absolute_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
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
    assert post["path"] == "/zones/zid/dns_records"
    assert post["json"] == {
        "type": "A",
        "name": "www.example.com",
        "content": "1.1.1.1",
        "ttl": 1,  # None → automatic sentinel.
    }


# ── _apply_record update (existing record found → PUT) ──────────────────
async def test_apply_record_update_puts_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),  # resolve zone
                # find existing record (content-keyed lookup)
                _FakeResponse(200, _env([{"id": "rid", "content": "2.2.2.2"}])),
            ],
            "put": [_FakeResponse(200, _env({"id": "rid"}))],
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
    assert put["path"] == "/zones/zid/dns_records/rid"
    assert put["json"]["content"] == "2.2.2.2"
    assert put["json"]["ttl"] == 120


# ── _apply_record update with no match → falls back to create (POST) ────
async def test_apply_record_update_missing_creates(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),  # resolve zone
                _FakeResponse(200, _env([])),  # no existing record
            ],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
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
    # Apex name renders as the bare zone.
    assert post["json"]["name"] == "example.com"


# ── _apply_record delete (found → DELETE) ───────────────────────────────
async def test_apply_record_delete_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([{"id": "rid", "content": "1.1.1.1"}])),
            ],
            "delete": [_FakeResponse(200, _env({"id": "rid"}))],
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
    assert delete["path"] == "/zones/zid/dns_records/rid"


# ── _apply_record delete with no match → no-op (no DELETE issued) ───────
async def test_apply_record_delete_missing_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
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
async def test_apply_record_update_matches_content_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A round-robin A name has two values on Cloudflare; updating the TTL of
    the ``5.6.7.8`` record must PUT against *its* id, not the first row's
    (issue #331)."""
    multi = _env(
        [
            {"id": "rid-a", "type": "A", "name": "www.example.com", "content": "1.2.3.4"},
            {"id": "rid-b", "type": "A", "name": "www.example.com", "content": "5.6.7.8"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),  # resolve zone
                _FakeResponse(200, multi),  # find existing record (content-filtered)
            ],
            "put": [_FakeResponse(200, _env({"id": "rid-b"}))],
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

    # The lookup carried the content filter so Cloudflare narrows the RRset…
    lookup = fake.calls[1]
    assert lookup["params"] == {"name": "www.example.com", "type": "A", "content": "5.6.7.8"}
    # …and we PUT against the id whose content actually matched the op value.
    put = next(c for c in fake.calls if c["method"] == "put")
    assert put["path"] == "/zones/zid/dns_records/rid-b"
    assert put["json"]["content"] == "5.6.7.8"
    assert put["json"]["ttl"] == 600


# ── _apply_record delete targets the right value of a multi-value RRset ──
async def test_apply_record_delete_matches_content_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``delete A 1.2.3.4`` against a 2-value RRset must DELETE the row holding
    ``1.2.3.4`` even if Cloudflare lists ``5.6.7.8`` first (issue #331)."""
    multi = _env(
        [
            {"id": "rid-keep", "type": "A", "name": "www.example.com", "content": "5.6.7.8"},
            {"id": "rid-drop", "type": "A", "name": "www.example.com", "content": "1.2.3.4"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, multi),
            ],
            "delete": [_FakeResponse(200, _env({"id": "rid-drop"}))],
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

    lookup = fake.calls[1]
    assert lookup["params"]["content"] == "1.2.3.4"
    delete = next(c for c in fake.calls if c["method"] == "delete")
    # The value-keyed row, not the first-listed sibling.
    assert delete["path"] == "/zones/zid/dns_records/rid-drop"


# ── _apply_record delete is a no-op when no value matches ───────────────
async def test_apply_record_delete_no_content_match_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Cloudflare returns sibling values but none equal the op value, the
    delete must be a safe no-op (no DELETE issued) rather than removing a
    wrong-value row (issue #331)."""
    multi = _env(
        [
            {"id": "rid-a", "type": "A", "name": "www.example.com", "content": "5.6.7.8"},
            {"id": "rid-b", "type": "A", "name": "www.example.com", "content": "9.9.9.9"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
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
    """Two MX records at the apex share a content host but differ by priority;
    deleting one must match content *and* priority (issue #331)."""
    multi = _env(
        [
            {
                "id": "mx-10",
                "type": "MX",
                "name": "example.com",
                "content": "mail.example.com",
                "priority": 10,
            },
            {
                "id": "mx-20",
                "type": "MX",
                "name": "example.com",
                "content": "mail.example.com",
                "priority": 20,
            },
        ]
    )
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, multi),
            ],
            "delete": [_FakeResponse(200, _env({"id": "mx-20"}))],
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
    assert delete["path"] == "/zones/zid/dns_records/mx-20"


# ── _apply_zone create includes account when account_id present ─────────
async def test_apply_zone_create_with_account(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(200, _env({"id": "z9"}))]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), {"api_token": "t", "account_id": "acc1"}, zone, "create")

    post = fake.calls[0]
    assert post["path"] == "/zones"
    assert post["json"] == {"name": "example.org", "account": {"id": "acc1"}}


async def test_apply_zone_create_without_account(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(200, _env({"id": "z9"}))]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "create")

    assert fake.calls[0]["json"] == {"name": "example.org"}


async def test_apply_zone_delete_resolves_then_deletes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
            "delete": [_FakeResponse(200, _env({"id": "zid"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "delete")

    assert [c["method"] for c in fake.calls] == ["get", "delete"]
    assert fake.calls[1]["path"] == "/zones/zid"


# ── Error surfacing ─────────────────────────────────────────────────────
async def test_success_false_raises_clouddnserror(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "success": False,
        "errors": [{"code": 1003, "message": "Invalid or missing zone id."}],
        "result": None,
    }
    fake = _FakeClient({"get": [_FakeResponse(200, payload)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "Invalid or missing zone id." in str(exc.value)


async def test_non_2xx_raises_clouddnserror(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"success": False, "errors": [{"message": "Authentication error"}]}
    fake = _FakeClient({"get": [_FakeResponse(403, payload)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "Authentication error" in str(exc.value)


async def test_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = CloudflareDNSDriver()
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="A", value="1.1.1.1"),
        target_serial=1,
    )
    with pytest.raises(CloudDNSError):
        await driver._apply_record(_Server(), {}, change)


# ── Health check (#1455) ────────────────────────────────────────────────
# The health task calls ``health_check`` when a driver has one and
# otherwise SOA-probes ``server.host`` — which for Cloudflare is the
# literal "cloudflare" on 443, so the server read unreachable forever.
async def test_health_check_is_healthy_when_the_api_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient({"get": [_FakeResponse(200, _env([{"id": "z1", "name": "example.com"}]))]})
    driver = _patch_client(monkeypatch, fake)
    monkeypatch.setattr(driver, "_load_credentials", lambda server: _CREDS)

    ok, message = await driver.health_check(_Server())

    assert ok is True
    assert "1 hosted zone" in message
    # It asked the API, not a DNS socket.
    assert [c["path"] for c in fake.calls] == ["/zones"]


async def test_health_check_reports_the_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"success": False, "errors": [{"message": "Invalid API Token"}]}
    fake = _FakeClient({"get": [_FakeResponse(403, payload)]})
    driver = _patch_client(monkeypatch, fake)
    monkeypatch.setattr(driver, "_load_credentials", lambda server: _CREDS)

    ok, message = await driver.health_check(_Server())

    assert ok is False
    assert "Invalid API Token" in message


# ── Static helpers ──────────────────────────────────────────────────────
def test_relativize_helper() -> None:
    driver = CloudflareDNSDriver()
    assert driver._relativize("example.com.", "example.com.") == "@"
    assert driver._relativize("www.example.com", "example.com.") == "www"
    assert driver._relativize("a.b.example.com.", "example.com") == "a.b"


def test_capabilities_shape() -> None:
    caps = CloudflareDNSDriver().capabilities()
    assert caps["name"] == "cloudflare"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["dnssec_online"] is False  # #29 — cloud DNSSEC deferred
    assert caps["apex_cname"] == "flatten"
    assert "CAA" in caps["record_types"]


# ── #783: create / update with the complete desired RRset ──────────────
#
# Cloudflare keeps one row per value and the op names only the NEW value,
# so the per-value lookup cannot find the row an edit changes. These pin
# the set write that replaced it for ops carrying ``rrset``.


def _set_change(
    op: str,
    members: list[tuple[str, int | None]],
    *,
    rtype: str = "TXT",
    name: str = "_dmarc",
    ttl: int | None = 300,
) -> RecordChange:
    value, priority = members[-1]
    return RecordChange(
        op=op,  # type: ignore[arg-type]
        zone_name="example.com.",
        record=RecordData(name=name, record_type=rtype, value=value, ttl=ttl, priority=priority),
        target_serial=1,
        rrset=RRsetData(
            ttl=ttl, members=tuple(RRsetMember(value=v, priority=p) for v, p in members)
        ),
    )


def _row(rid: str, content: str, *, rtype: str = "TXT", ttl: int = 300, **extra: Any) -> dict:
    return {
        "id": rid,
        "type": rtype,
        "name": "_dmarc.example.com",
        "content": content,
        "ttl": ttl,
        **extra,
    }


async def test_update_that_changes_the_value_replaces_the_old_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE regression: editing a value left the old row next to the new one
    (two DMARC records, so no valid DMARC policy at all)."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([_row("old", '"v=DMARC1; p=none"')])),
            ],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
            "delete": [_FakeResponse(200, _env({"id": "old"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _set_change("update", [("v=DMARC1; p=quarantine", None)])
    )

    writes = [(c["method"], c["path"]) for c in fake.calls if c["method"] != "get"]
    # New row first, then the old one goes: the name is never empty.
    assert writes == [
        ("post", "/zones/zid/dns_records"),
        ("delete", "/zones/zid/dns_records/old"),
    ]
    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["content"] == "v=DMARC1; p=quarantine"
    # The set is read by name + type only, not filtered by the new value.
    assert fake.calls[1]["params"]["name"] == "_dmarc.example.com"
    assert "content" not in fake.calls[1]["params"]


async def test_set_write_keeps_siblings_and_adds_the_new_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([_row("a", "10.0.0.1", rtype="A")])),
            ],
            "post": [_FakeResponse(200, _env({"id": "b"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(),
        _CREDS,
        _set_change("create", [("10.0.0.1", None), ("10.0.0.2", None)], rtype="A", name="www"),
    )

    assert [c["method"] for c in fake.calls] == ["get", "get", "post"]
    assert fake.calls[2]["json"]["content"] == "10.0.0.2"


async def test_set_write_corrects_ttl_in_place(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([_row("r", "v=spf1 -all", ttl=3600)])),
            ],
            "put": [_FakeResponse(200, _env({"id": "r"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(_Server(), _CREDS, _set_change("update", [("v=spf1 -all", None)]))

    put = next(c for c in fake.calls if c["method"] == "put")
    assert put["path"] == "/zones/zid/dns_records/r"
    assert put["json"]["ttl"] == 300
    assert [c["method"] for c in fake.calls].count("delete") == 0


@pytest.mark.parametrize(
    ("rtype", "stored", "desired"),
    [
        ("TXT", '"v=spf1 -all"', "v=spf1 -all"),
        ("CNAME", "Target.Example.net", "target.example.net."),
        ("AAAA", "2001:db8:0:0:0:0:0:1", "2001:db8::1"),
    ],
)
async def test_set_write_is_a_noop_when_only_the_spelling_differs(
    monkeypatch: pytest.MonkeyPatch, rtype: str, stored: str, desired: str
) -> None:
    """A converged set costs one read. Compared literally, these would read
    as missing and be POSTed, which Cloudflare refuses as identical."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([_row("r", stored, rtype=rtype)])),
            ],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _set_change("update", [(desired, None)], rtype=rtype)
    )

    assert [c["method"] for c in fake.calls] == ["get", "get"]


async def test_set_write_matches_mx_on_priority_too(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([_row("m10", "mx.example.com", rtype="MX", priority=10)])),
            ],
            "post": [_FakeResponse(200, _env({"id": "m20"}))],
            "delete": [_FakeResponse(200, _env({"id": "m10"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _set_change("update", [("mx.example.com", 20)], rtype="MX", name="@")
    )

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["priority"] == 20
    assert next(c for c in fake.calls if c["method"] == "delete")["path"].endswith("/m10")


async def test_set_write_deletes_nothing_when_cloudflare_reports_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Cloudflare calls the new value a duplicate of a row this driver did
    not recognise, that row may be the record itself: never delete it."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([_row("odd", "v=spf1  -all")])),
            ],
            "post": [
                _FakeResponse(
                    400,
                    {
                        "success": False,
                        "errors": [{"message": "An identical record already exists."}],
                    },
                )
            ],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError, match="left the existing records in place"):
        await driver._apply_record(
            _Server(), _CREDS, _set_change("update", [("v=spf1 -all", None)])
        )

    assert "delete" not in [c["method"] for c in fake.calls]


async def test_delete_with_rrset_stays_a_single_value_delete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A delete's RRset is the survivors; they are already there, so only the
    op's own value is removed (no set write)."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(200, _env([{"id": "gone", "content": "10.0.0.2"}])),
            ],
            "delete": [_FakeResponse(200, _env({"id": "gone"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.2"),
        target_serial=1,
        rrset=RRsetData(ttl=300, members=(RRsetMember(value="10.0.0.1"),)),
    )

    await driver._apply_record(_Server(), _CREDS, change)

    assert [c["method"] for c in fake.calls] == ["get", "get", "delete"]


# ── Cloudflare's ``proxied`` flag survives every write ─────────────────
#
# SpatiumDDI does not model ``proxied``, and a PUT or POST that omits it
# lands DNS-only, which publishes the origin's address. A proxied row's TTL
# also always reads back as 1 (auto), whatever was set.


async def test_set_write_leaves_a_proxied_row_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    """The row's TTL (auto) differs from the op's, but correcting it would PUT
    the row without ``proxied`` and expose the origin: no write at all."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(
                    200, _env([_row("p", "203.0.113.10", rtype="A", ttl=1, proxied=True)])
                ),
            ],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _set_change("update", [("203.0.113.10", None)], rtype="A", name="www")
    )

    assert [c["method"] for c in fake.calls] == ["get", "get"]


async def test_set_write_ttl_correction_carries_proxied(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DNS-only sibling of a proxied row still gets its TTL corrected, and
    the PUT states its proxy status instead of leaving it to the default."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(
                    200,
                    _env(
                        [
                            _row("p", "203.0.113.10", rtype="A", ttl=1, proxied=True),
                            _row("d", "203.0.113.11", rtype="A", ttl=3600, proxied=False),
                        ]
                    ),
                ),
            ],
            "put": [_FakeResponse(200, _env({"id": "d"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(),
        _CREDS,
        _set_change(
            "update", [("203.0.113.10", None), ("203.0.113.11", None)], rtype="A", name="www"
        ),
    )

    puts = [c for c in fake.calls if c["method"] == "put"]
    assert [p["path"] for p in puts] == ["/zones/zid/dns_records/d"]
    assert puts[0]["json"]["ttl"] == 300
    assert puts[0]["json"]["proxied"] is False


async def test_set_write_value_change_keeps_the_record_proxied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Editing a proxied record's address replaces the row; the new row must
    be proxied too, or the edit would publish the new origin address."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(
                    200, _env([_row("old", "203.0.113.10", rtype="A", ttl=1, proxied=True)])
                ),
            ],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
            "delete": [_FakeResponse(200, _env({"id": "old"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _set_change("update", [("203.0.113.20", None)], rtype="A", name="www")
    )

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["content"] == "203.0.113.20"
    assert post["json"]["proxied"] is True
    assert next(c for c in fake.calls if c["method"] == "delete")["path"].endswith("/old")


async def test_set_write_new_name_does_not_send_proxied(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing at the name yet: the create leaves ``proxied`` to Cloudflare."""
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}])), _FakeResponse(200, _env([]))],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _set_change("create", [("203.0.113.20", None)], rtype="A", name="www")
    )

    post = next(c for c in fake.calls if c["method"] == "post")
    assert "proxied" not in post["json"]


async def test_apply_record_update_without_rrset_carries_proxied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The per-value update path (no ``rrset``) PUTs the row it matched; that
    PUT must keep the row proxied too."""
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(200, _env([{"id": "zid"}])),
                _FakeResponse(
                    200, _env([{"id": "rid", "content": "203.0.113.10", "proxied": True}])
                ),
            ],
            "put": [_FakeResponse(200, _env({"id": "rid"}))],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="203.0.113.10", ttl=120),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    put = next(c for c in fake.calls if c["method"] == "put")
    assert put["path"] == "/zones/zid/dns_records/rid"
    assert put["json"]["proxied"] is True


# ── MX / SRV split-form contract (#1526) ────────────────────────────────────


async def test_apply_record_create_srv_sends_data_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SRV goes out as a Cloudflare ``data`` object — priority, weight,
    port and target — not a bare-target content string."""
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
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
    assert post["json"]["data"] == {
        "priority": 10,
        "weight": 20,
        "port": 5060,
        "target": "sip.example.com",
    }
    assert "content" not in post["json"]


async def test_list_zone_records_splits_srv_data(monkeypatch: pytest.MonkeyPatch) -> None:
    zone_lookup = _env([{"id": "zid"}])
    records = _env(
        [
            {
                "name": "_sip._tcp.example.com",
                "type": "SRV",
                "content": "10 20 5060 sip.example.com",
                "ttl": 3600,
                "data": {
                    "priority": 10,
                    "weight": 20,
                    "port": 5060,
                    "target": "sip.example.com",
                },
            },
            {
                "name": "_xmpp._tcp.example.com",
                "type": "SRV",
                "content": "5 0 5222 xmpp.example.com",
                "ttl": 3600,
            },
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, zone_lookup), _FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    out = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    assert out[0] == RecordData(
        name="_sip._tcp",
        record_type="SRV",
        value="sip.example.com",
        ttl=3600,
        priority=10,
        weight=20,
        port=5060,
    )
    # No ``data`` object → the composed content string is split instead.
    assert out[1] == RecordData(
        name="_xmpp._tcp",
        record_type="SRV",
        value="xmpp.example.com",
        ttl=3600,
        priority=5,
        weight=0,
        port=5222,
    )


# ── SRV through the #783 set write (#1526 × #1495) ─────────────────────


async def test_set_write_srv_sends_data_object(monkeypatch: pytest.MonkeyPatch) -> None:
    """An op carrying an RRset takes the set-write path; SRV must still go
    out as a ``data`` object, never a bare-target ``content``."""
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}])), _FakeResponse(200, _env([]))],
            "post": [_FakeResponse(200, _env({"id": "new"}))],
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
            ttl=300,
            priority=10,
            weight=20,
            port=5060,
        ),
        target_serial=1,
        rrset=RRsetData(
            ttl=300,
            members=(RRsetMember(value="sip.example.com", priority=10, weight=20, port=5060),),
        ),
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["data"] == {
        "priority": 10,
        "weight": 20,
        "port": 5060,
        "target": "sip.example.com",
    }
    assert "content" not in post["json"]


@pytest.mark.parametrize(
    "row_extra",
    [
        {
            "content": "20 5060 sip.example.com",
            "priority": 10,
            "data": {"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com"},
        },
        {"content": "20 5060 sip.example.com.", "priority": 10},
        {"content": "10 20 5060 sip.example.com"},
    ],
)
async def test_set_write_srv_converged_is_a_noop(
    monkeypatch: pytest.MonkeyPatch, row_extra: dict[str, Any]
) -> None:
    """A live SRV row matching on all four components is kept untouched,
    whichever shape Cloudflare reports it in."""
    row = {
        "id": "s",
        "type": "SRV",
        "name": "_sip._tcp.example.com",
        "ttl": 300,
        **row_extra,
    }
    fake = _FakeClient(
        {"get": [_FakeResponse(200, _env([{"id": "zid"}])), _FakeResponse(200, _env([row]))]}
    )
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="update",
        zone_name="example.com.",
        record=RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com",
            ttl=300,
            priority=10,
            weight=20,
            port=5060,
        ),
        target_serial=1,
        rrset=RRsetData(
            ttl=300,
            members=(RRsetMember(value="sip.example.com", priority=10, weight=20, port=5060),),
        ),
    )

    await driver._apply_record(_Server(), _CREDS, change)

    assert [c["method"] for c in fake.calls] == ["get", "get"]


# ── #1537 — zone create / delete converge on retry ──────────────────────
def _err(status: int, code: int, message: str = "boom") -> _FakeResponse:
    return _FakeResponse(
        status,
        {"success": False, "errors": [{"code": code, "message": message}], "result": None},
    )


async def test_apply_zone_create_already_exists_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient(
        {
            "post": [_err(400, 1061, "Zone already exists")],
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    await driver._apply_zone(_Server(), _CREDS, zone, "create")
    assert [c["method"] for c in fake.calls] == ["post", "get"]


async def test_apply_zone_create_exists_but_not_visible_still_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1061 with no zone visible to the token is not proof it is ours."""
    fake = _FakeClient(
        {
            "post": [_err(400, 1061, "Zone already exists")],
            "get": [_FakeResponse(200, _env([]))],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(_Server(), _CREDS, zone, "create")


@pytest.mark.parametrize(
    ("status", "code"), [(403, 9109), (429, 971), (500, 1061 + 1), (400, 1097)]
)
async def test_apply_zone_create_other_errors_still_raise(
    monkeypatch: pytest.MonkeyPatch, status: int, code: int
) -> None:
    fake = _FakeClient({"post": [_err(status, code)]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(_Server(), _CREDS, zone, "create")


async def test_apply_zone_delete_absent_zone_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient({"get": [_FakeResponse(200, _env([]))]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    await driver._apply_zone(_Server(), _CREDS, zone, "delete")
    assert [c["method"] for c in fake.calls] == ["get"]


async def test_apply_zone_delete_404_after_lookup_is_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
            "delete": [_err(404, 1001, "Invalid zone")],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    await driver._apply_zone(_Server(), _CREDS, zone, "delete")


@pytest.mark.parametrize("status", [401, 403, 429, 500])
async def test_apply_zone_delete_other_errors_still_raise(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    # Lookup itself failing (auth / throttle) must not read as "absent".
    fake = _FakeClient({"get": [_err(status, 9109)]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(_Server(), _CREDS, zone, "delete")

    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
            "delete": [_err(status, 9109)],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    with pytest.raises(CloudDNSError):
        await driver._apply_zone(_Server(), _CREDS, zone, "delete")


async def test_apply_zone_reports_whether_it_changed_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``False`` = already in the requested state, so the caller's
    partial-failure compensation leaves that server alone (#1537)."""
    zone = type("Z", (), {"name": "example.org."})()
    fake = _FakeClient({"post": [_FakeResponse(200, _env({"id": "zid"}))]})
    assert await _patch_client(monkeypatch, fake)._apply_zone(_Server(), _CREDS, zone, "create")

    fake = _FakeClient(
        {
            "post": [_err(400, 1061, "Zone already exists")],
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
        }
    )
    assert (
        await _patch_client(monkeypatch, fake)._apply_zone(_Server(), _CREDS, zone, "create")
        is False
    )

    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _env([{"id": "zid"}]))],
            "delete": [_FakeResponse(200, _env({"id": "zid"}))],
        }
    )
    assert await _patch_client(monkeypatch, fake)._apply_zone(_Server(), _CREDS, zone, "delete")

    fake = _FakeClient({"get": [_FakeResponse(200, _env([]))]})
    assert (
        await _patch_client(monkeypatch, fake)._apply_zone(_Server(), _CREDS, zone, "delete")
        is False
    )


async def test_apply_zone_1061_from_another_account_raises_the_provider_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cloudflare answers 1061 when a DIFFERENT account holds the domain
    active too. The confirming lookup is scoped to the configured account,
    and a miss re-raises Cloudflare's own error rather than "not found"."""
    fake = _FakeClient(
        {
            "post": [_err(400, 1061, "example.org already exists")],
            "get": [_FakeResponse(200, _env([]))],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    creds = {"api_token": "tok", "account_id": "acct-a"}
    with pytest.raises(CloudDNSError, match="already exists"):
        await driver._apply_zone(_Server(), creds, zone, "create")
    assert fake.calls[1]["params"] == {"name": "example.org", "account.id": "acct-a"}


async def test_apply_zone_delete_lookup_is_scoped_to_the_configured_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token spanning several accounts must not delete the same-named
    zone in whichever account the API happens to list first."""
    fake = _FakeClient({"get": [_FakeResponse(200, _env([]))]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()
    creds = {"api_token": "tok", "account_id": "acct-a"}
    assert await driver._apply_zone(_Server(), creds, zone, "delete") is False
    assert fake.calls[0]["params"] == {"name": "example.org", "account.id": "acct-a"}
    assert [c["method"] for c in fake.calls] == ["get"]

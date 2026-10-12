"""Offline unit tests for the Vultr DNS driver (issue #29 cloud DNS family).

Vultr is a tier-3 token-only provider with no test account, so every test
monkeypatches :meth:`VultrDNSDriver._client` to return a fake
async-context-manager client that serves canned bodies and records the calls
made against it. Nothing here touches the network.

Vultr differs from Cloudflare in several shapes the harness mirrors:
  * no ``success`` envelope — a 2xx status is the only success signal, and
    errors come back as ``{"error": "..."}``;
  * cursor pagination via ``meta.links.next`` (empty → done) rather than
    ``result_info.total_pages``;
  * records are scoped by domain **name**, not an opaque zone id, so there is
    no zone-id resolution GET before record calls;
  * record names are relative with ``""`` for apex (not ``"@"``), the value
    field is ``data``, and updates use **PATCH** (not PUT).
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData
from app.drivers.dns.vultr import VultrDNSDriver


class _FakeResponse:
    """Minimal stand-in for an ``httpx.Response`` (status + json())."""

    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Async-context-manager fake of ``httpx.AsyncClient``.

    Each verb pops the next queued response off the matching list and records
    ``(method, path, params, json)`` for assertion. A queued response can be a
    ``_FakeResponse`` or a zero-arg callable returning one (so a test can vary
    the reply by call order). Includes a ``patch()`` verb (Vultr updates via
    PATCH).
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

    async def patch(self, path: str, json: Any = None) -> _FakeResponse:
        return self._next("patch", path, None, json)

    async def delete(self, path: str, params: Any = None) -> _FakeResponse:
        return self._next("delete", path, params, None)


def _domains_env(domains: list[dict[str, Any]], *, next_cursor: str = "") -> dict[str, Any]:
    """Build a Vultr-shaped list-domains body with cursor pagination."""
    return {
        "domains": domains,
        "meta": {"total": len(domains), "links": {"next": next_cursor, "prev": ""}},
    }


def _records_env(records: list[dict[str, Any]], *, next_cursor: str = "") -> dict[str, Any]:
    """Build a Vultr-shaped list-records body with cursor pagination."""
    return {
        "records": records,
        "meta": {"total": len(records), "links": {"next": next_cursor, "prev": ""}},
    }


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> VultrDNSDriver:
    driver = VultrDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda token: fake)
    return driver


class _Server:
    """Stub DNSServer row — only the attrs the driver reads."""

    id = "srv-1"
    name = "vultr-test"
    credentials_encrypted = b"x"


_CREDS = {"api_token": "tok"}


# ── _list_zones cursor pagination + reverse + dnssec flags ──────────────
async def test_list_zones_paginates_and_flags_reverse(monkeypatch: pytest.MonkeyPatch) -> None:
    page1 = _domains_env(
        [
            {"domain": "example.com", "dns_sec": "disabled"},
            {"domain": "10.in-addr.arpa", "dns_sec": "disabled"},
        ],
        next_cursor="CURSOR2",
    )
    page2 = _domains_env([{"domain": "example.net", "dns_sec": "enabled"}], next_cursor="")
    fake = _FakeClient({"get": [_FakeResponse(200, page1), _FakeResponse(200, page2)]})
    driver = _patch_client(monkeypatch, fake)

    zones = await driver._list_zones(_Server(), _CREDS)

    assert [z.name for z in zones] == ["example.com.", "10.in-addr.arpa.", "example.net."]
    # zone_id is the bare domain name (Vultr scopes by name, not opaque id).
    assert [z.zone_id for z in zones] == ["example.com", "10.in-addr.arpa", "example.net"]
    # Reverse-zone detection.
    assert zones[1].is_reverse is True
    assert zones[0].is_reverse is False
    # dns_sec string → bool.
    assert zones[2].dnssec_enabled is True
    assert zones[0].dnssec_enabled is False
    # Two pages → two GETs; first carries no cursor, second carries it.
    assert sum(1 for c in fake.calls if c["method"] == "get") == 2
    assert fake.calls[0]["params"] == {"per_page": 100}
    assert fake.calls[1]["params"] == {"per_page": 100, "cursor": "CURSOR2"}


# ── _list_zone_records relativization + TTL handling + MX priority ──────
async def test_list_zone_records_relativizes_and_normalizes_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _records_env(
        [
            {"id": "r1", "name": "", "type": "A", "data": "1.2.3.4", "ttl": 0},
            {"id": "r2", "name": "www", "type": "A", "data": "5.6.7.8", "ttl": 300},
            {
                "id": "r3",
                "name": "",
                "type": "MX",
                "data": "mail.example.com",
                "ttl": 3600,
                "priority": 10,
            },
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    # Empty apex name collapses to "@"; sub-label relativized; ttl=0 → None.
    assert recs[0] == RecordData(name="@", record_type="A", value="1.2.3.4", ttl=None)
    assert recs[1] == RecordData(name="www", record_type="A", value="5.6.7.8", ttl=300)
    assert recs[2].name == "@"
    assert recs[2].priority == 10
    assert recs[2].ttl == 3600
    # Records scoped directly by domain name — no zone-id resolution GET.
    assert fake.calls[0]["path"] == "/domains/example.com/records"
    assert fake.calls[0]["params"] == {"per_page": 100}


async def test_list_zone_records_drops_priority_for_non_mx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vultr returns priority 0/-1 for A/CNAME/etc.; it must not leak as 0."""
    records = _records_env(
        [{"id": "r1", "name": "www", "type": "A", "data": "1.1.1.1", "ttl": 60, "priority": -1}]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, records)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com.")

    assert recs[0].priority is None


# ── _apply_record create ────────────────────────────────────────────────
async def test_apply_record_create_posts_relative_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(201, {"record": {"id": "new"}})]})
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
    assert post["json"] == {
        "name": "www",  # relative label (not absolute).
        "type": "A",
        "data": "1.1.1.1",
        "ttl": 0,  # None → automatic sentinel.
    }


async def test_apply_record_create_apex_uses_empty_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """Apex record renders name as the empty string Vultr expects."""
    fake = _FakeClient({"post": [_FakeResponse(201, {"record": {"id": "new"}})]})
    driver = _patch_client(monkeypatch, fake)
    change = RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="@", record_type="A", value="3.3.3.3", ttl=120),
        target_serial=1,
    )

    await driver._apply_record(_Server(), _CREDS, change)

    post = next(c for c in fake.calls if c["method"] == "post")
    assert post["json"]["name"] == ""
    assert post["json"]["ttl"] == 120


# ── _apply_record update (existing record found → PATCH) ────────────────
async def test_apply_record_update_patches_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(
                    200,
                    _records_env([{"id": "rid", "name": "www", "type": "A", "data": "2.2.2.2"}]),
                ),
            ],
            "patch": [_FakeResponse(204, {})],
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

    patch = next(c for c in fake.calls if c["method"] == "patch")
    assert patch["path"] == "/domains/example.com/records/rid"
    assert patch["json"]["data"] == "2.2.2.2"
    assert patch["json"]["ttl"] == 120


# ── _apply_record update with no match → falls back to create (POST) ────
async def test_apply_record_update_missing_creates(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, _records_env([]))],  # no existing record
            "post": [_FakeResponse(201, {"record": {"id": "new"}})],
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
    # Apex name renders as the empty string.
    assert post["json"]["name"] == ""


# ── _apply_record delete (found → DELETE) ───────────────────────────────
async def test_apply_record_delete_dispatches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [
                _FakeResponse(
                    200,
                    _records_env([{"id": "rid", "name": "www", "type": "A", "data": "1.1.1.1"}]),
                ),
            ],
            "delete": [_FakeResponse(204, {})],
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
    assert delete["path"] == "/domains/example.com/records/rid"


# ── _apply_record delete with no match → no-op (no DELETE issued) ───────
async def test_apply_record_delete_missing_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_FakeResponse(200, _records_env([]))]})
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
    """A round-robin A name has two values on Vultr; updating the TTL of the
    ``5.6.7.8`` record must PATCH against *its* id, not the first row's
    (issue #331)."""
    multi = _records_env(
        [
            {"id": "rid-a", "type": "A", "name": "www", "data": "1.2.3.4"},
            {"id": "rid-b", "type": "A", "name": "www", "data": "5.6.7.8"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, multi)],
            "patch": [_FakeResponse(204, {})],
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

    # We PATCH against the id whose data actually matched the op value.
    patch = next(c for c in fake.calls if c["method"] == "patch")
    assert patch["path"] == "/domains/example.com/records/rid-b"
    assert patch["json"]["data"] == "5.6.7.8"
    assert patch["json"]["ttl"] == 600


# ── _apply_record delete targets the right value of a multi-value RRset ──
async def test_apply_record_delete_matches_content_in_multivalue_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``delete A 1.2.3.4`` against a 2-value RRset must DELETE the row holding
    ``1.2.3.4`` even if Vultr lists ``5.6.7.8`` first (issue #331)."""
    multi = _records_env(
        [
            {"id": "rid-keep", "type": "A", "name": "www", "data": "5.6.7.8"},
            {"id": "rid-drop", "type": "A", "name": "www", "data": "1.2.3.4"},
        ]
    )
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, multi)],
            "delete": [_FakeResponse(204, {})],
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
    assert delete["path"] == "/domains/example.com/records/rid-drop"


# ── _apply_record delete is a no-op when no value matches ───────────────
async def test_apply_record_delete_no_content_match_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If Vultr returns sibling values but none equal the op value, the delete
    must be a safe no-op (no DELETE issued) rather than removing a wrong-value
    row (issue #331)."""
    multi = _records_env(
        [
            {"id": "rid-a", "type": "A", "name": "www", "data": "5.6.7.8"},
            {"id": "rid-b", "type": "A", "name": "www", "data": "9.9.9.9"},
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
    deleting one must match data *and* priority (issue #331)."""
    multi = _records_env(
        [
            {"id": "mx-10", "type": "MX", "name": "", "data": "mail.example.com", "priority": 10},
            {"id": "mx-20", "type": "MX", "name": "", "data": "mail.example.com", "priority": 20},
        ]
    )
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, multi)],
            "delete": [_FakeResponse(204, {})],
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
    assert delete["path"] == "/domains/example.com/records/mx-20"


# ── _find_record_id pages through a multi-page record set ───────────────
async def test_find_record_id_follows_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    """The target record lives on the second cursor page; the lookup must page."""
    page1 = _records_env(
        [{"id": "other", "type": "A", "name": "www", "data": "9.9.9.9"}],
        next_cursor="NEXT",
    )
    page2 = _records_env([{"id": "want", "type": "A", "name": "www", "data": "1.1.1.1"}])
    fake = _FakeClient(
        {
            "get": [_FakeResponse(200, page1), _FakeResponse(200, page2)],
            "delete": [_FakeResponse(204, {})],
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

    # Two list pages walked, then the delete against the page-2 row.
    assert [c["method"] for c in fake.calls] == ["get", "get", "delete"]
    assert fake.calls[1]["params"] == {"per_page": 100, "cursor": "NEXT"}
    delete = next(c for c in fake.calls if c["method"] == "delete")
    assert delete["path"] == "/domains/example.com/records/want"


# ── _apply_zone create + delete ─────────────────────────────────────────
async def test_apply_zone_create(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(201, {"domain": {"domain": "example.org"}})]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "create")

    post = fake.calls[0]
    assert post["path"] == "/domains"
    # Empty zone (no "ip" key) + DNSSEC off.
    assert post["json"] == {"domain": "example.org", "dns_sec": "disabled"}


async def test_apply_zone_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"delete": [_FakeResponse(204, {})]})
    driver = _patch_client(monkeypatch, fake)
    zone = type("Z", (), {"name": "example.org."})()

    await driver._apply_zone(_Server(), _CREDS, zone, "delete")

    assert [c["method"] for c in fake.calls] == ["delete"]
    assert fake.calls[0]["path"] == "/domains/example.org"


# ── Error surfacing ─────────────────────────────────────────────────────
async def test_error_envelope_raises_clouddnserror(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"error": "Invalid API key.", "status": 401}
    fake = _FakeClient({"get": [_FakeResponse(401, payload)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "Invalid API key." in str(exc.value)


async def test_non_2xx_without_error_body_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-2xx with no parseable error body still raises with the status."""
    fake = _FakeClient({"get": [_FakeResponse(500, "boom")]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError) as exc:
        await driver._list_zones(_Server(), _CREDS)
    assert "HTTP 500" in str(exc.value)


async def test_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = VultrDNSDriver()
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
    driver = VultrDNSDriver()
    assert driver._relativize("", "example.com.") == "@"
    assert driver._relativize("@", "example.com.") == "@"
    assert driver._relativize("www", "example.com.") == "www"
    assert driver._relativize("example.com.", "example.com.") == "@"
    assert driver._relativize("a.b.example.com.", "example.com") == "a.b"


def test_relative_name_helper() -> None:
    driver = VultrDNSDriver()
    assert driver._relative_name("@") == ""
    assert driver._relative_name("") == ""
    assert driver._relative_name("www") == "www"
    assert driver._relative_name("www.") == "www"


def test_capabilities_shape() -> None:
    caps = VultrDNSDriver().capabilities()
    assert caps["name"] == "vultr"
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["views"] is False
    assert caps["rpz"] is False
    # Vultr has no online DNSSEC signing API.
    assert caps["dnssec_online"] is False
    assert "CAA" in caps["record_types"]
    assert "HTTPS" not in caps["record_types"]


# ── SRV split-form contract (#1526) ─────────────────────────────────────────


async def test_apply_record_create_srv_packs_weight_port_into_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vultr has a priority field but no weight/port fields: SRV data is
    "<weight> <port> <target>" with priority kept separate."""
    fake = _FakeClient({"post": [_FakeResponse(201, {"record": {"id": "srv1"}})]})
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
    assert post["json"]["data"] == "20 5060 sip.example.com"
    assert post["json"]["priority"] == 10


async def test_list_zone_records_splits_srv_data(monkeypatch: pytest.MonkeyPatch) -> None:
    records = _records_env(
        [
            {
                "id": "r9",
                "name": "_sip._tcp",
                "type": "SRV",
                "data": "20 5060 sip.example.com",
                "ttl": 3600,
                "priority": 10,
            }
        ]
    )
    fake = _FakeClient({"get": [_FakeResponse(200, records)]})
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

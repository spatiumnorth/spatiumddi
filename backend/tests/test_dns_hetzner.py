"""Offline unit tests for the Hetzner DNS driver (Hetzner Cloud API).

Every test monkeypatches :meth:`HetznerDNSDriver._client` to return a fake
async-context-manager client that serves canned envelopes and records the
calls made against it. Nothing here touches the network.

The envelopes mirror the Hetzner Cloud API reference
(https://docs.hetzner.cloud/reference/cloud#zones): ``{"zones": [...]}`` /
``{"rrsets": [...]}`` with ``meta.pagination.next_page``, ``{"rrset": {...}}``
for a single set, and ``{"action": {...}}`` for every write.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns import hetzner as hetzner_mod
from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember
from app.drivers.dns.hetzner import HetznerDNSDriver


class _FakeResponse:
    """Minimal stand-in for an ``httpx.Response`` (status + json())."""

    def __init__(
        self, status_code: int, payload: Any = None, headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = headers or {}

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Async-context-manager fake of ``httpx.AsyncClient``.

    Each verb pops the next queued response off the matching list and
    records ``(method, path, params, json)`` for assertion.
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

    async def delete(self, path: str, params: Any = None) -> _FakeResponse:
        return self._next("delete", path, params, None)

    def writes(self) -> list[dict[str, Any]]:
        return [c for c in self.calls if c["method"] != "get"]


def _page(key: str, items: list[Any], *, page: int = 1, next_page: int | None = None) -> dict:
    return {
        key: items,
        "meta": {
            "pagination": {
                "page": page,
                "per_page": 50,
                "previous_page": page - 1 or None,
                "next_page": next_page,
                "last_page": next_page or page,
                "total_entries": len(items),
            }
        },
    }


def _action(command: str, status: str = "success", **extra: Any) -> dict[str, Any]:
    return {"action": {"id": 7, "command": command, "status": status, "error": None, **extra}}


def _rrset(name: str, rtype: str, values: list[str], ttl: int | None = 3600) -> _FakeResponse:
    return _FakeResponse(
        200,
        {
            "rrset": {
                "id": f"{name}/{rtype}",
                "name": name,
                "type": rtype,
                "ttl": ttl,
                "records": [{"value": v, "comment": ""} for v in values],
            }
        },
    )


_NOT_FOUND = _FakeResponse(404, {"error": {"code": "not_found", "message": "rrset not found"}})


def _patch_client(monkeypatch: pytest.MonkeyPatch, fake: _FakeClient) -> HetznerDNSDriver:
    driver = HetznerDNSDriver()
    monkeypatch.setattr(driver, "_client", lambda token: fake)
    return driver


class _Server:
    """Stub DNSServer row — only the attrs the driver reads."""

    id = "srv-1"
    name = "hz-test"
    credentials_encrypted = b"x"


_CREDS = {"api_token": "tok"}


def _change(op: str, rec: RecordData, rrset: RRsetData | None = None) -> RecordChange:
    return RecordChange(op=op, zone_name="example.com.", record=rec, target_serial=0, rrset=rrset)


# ── Auth + base URL ─────────────────────────────────────────────────────
def test_client_uses_cloud_api_and_bearer_token() -> None:
    client = HetznerDNSDriver()._client("secret-token")
    assert str(client.base_url).rstrip("/") == "https://api.hetzner.cloud/v1"
    assert client.headers["Authorization"] == "Bearer secret-token"
    # The DNS-Console header must be gone — sending it would leak the token
    # under a name nothing reads.
    assert "Auth-API-Token" not in client.headers


# ── Zone reads ──────────────────────────────────────────────────────────
async def test_list_zones_follows_next_page_and_skips_secondary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    page1 = _page(
        "zones",
        [
            {"id": 1, "name": "example.com", "mode": "primary", "record_count": 4},
            {"id": 2, "name": "sec.example", "mode": "secondary"},
        ],
        next_page=2,
    )
    page2 = _page("zones", [{"id": 3, "name": "2.0.192.in-addr.arpa", "mode": "primary"}], page=2)
    fake = _FakeClient({"get": [_FakeResponse(200, page1), _FakeResponse(200, page2)]})
    driver = _patch_client(monkeypatch, fake)

    zones = await driver._list_zones(_Server(), _CREDS)

    assert [z.name for z in zones] == ["example.com.", "2.0.192.in-addr.arpa."]
    assert zones[0].zone_id == "1" and zones[0].record_count == 4
    assert zones[1].is_reverse is True
    assert [c["params"]["page"] for c in fake.calls] == [1, 2]
    assert all(c["path"] == "/zones" for c in fake.calls)


async def test_list_zone_records_expands_rrsets_and_unquotes_txt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = _page(
        "rrsets",
        [
            {
                "name": "@",
                "type": "MX",
                "ttl": None,
                "records": [{"value": "10 mail.example.com."}],
            },
            {
                "name": "www",
                "type": "A",
                "ttl": 300,
                "records": [{"value": "192.0.2.1"}, {"value": "192.0.2.2"}],
            },
            {
                "name": "@",
                "type": "TXT",
                "ttl": 3600,
                "records": [{"value": '"v=spf1 " "-all"'}, {"value": '"say \\"hi\\""'}],
            },
        ],
    )
    fake = _FakeClient({"get": [_FakeResponse(200, body)]})
    driver = _patch_client(monkeypatch, fake)

    recs = await driver._list_zone_records(_Server(), _CREDS, "example.com")

    assert fake.calls[0]["path"] == "/zones/example.com/rrsets"
    assert RecordData("@", "MX", "10 mail.example.com.", None) in recs
    assert [r.value for r in recs if r.record_type == "A"] == ["192.0.2.1", "192.0.2.2"]
    assert all(r.name == "www" and r.ttl == 300 for r in recs if r.record_type == "A")
    # Multi-string TXT is joined; escaped quotes are unescaped.
    assert {r.value for r in recs if r.record_type == "TXT"} == {"v=spf1 -all", 'say "hi"'}


# ── Value rendering ─────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("rec", "wire"),
    [
        (RecordData("www", "CNAME", "target.example.net"), "target.example.net."),
        (RecordData("www", "CNAME", "target.example.net."), "target.example.net."),
        (RecordData("@", "MX", "10 mail.example.com"), "10 mail.example.com."),
        (RecordData("@", "MX", "mail.example.com", priority=20), "20 mail.example.com."),
        (
            RecordData("_sip._tcp", "SRV", "1 2 5060 sip.example.com"),
            "1 2 5060 sip.example.com.",
        ),
        (RecordData("x", "A", "192.0.2.9"), "192.0.2.9"),
        (RecordData("@", "TXT", "v=spf1 -all"), '"v=spf1 -all"'),
        (RecordData("@", "TXT", 'a "quoted" \\ value'), '"a \\"quoted\\" \\\\ value"'),
        (RecordData("@", "TXT", '"already" "quoted"'), '"already" "quoted"'),
    ],
)
def test_wire_value(rec: RecordData, wire: str) -> None:
    assert HetznerDNSDriver._wire_value(rec) == wire


def test_long_txt_is_split_into_255_byte_strings() -> None:
    value = "k" * 600
    wire = HetznerDNSDriver._wire_value(RecordData("@", "TXT", value))
    parts = wire.split(" ")
    assert [len(p) - 2 for p in parts] == [255, 255, 90]
    # And it round-trips.
    assert HetznerDNSDriver._txt_from_wire(wire) == value


def test_txt_split_counts_bytes_not_characters() -> None:
    # "é" is two bytes in UTF-8: 200 of them are 400 bytes, so a character
    # count would emit one 200-character string BIND reads as 400 bytes.
    value = "é" * 200
    wire = HetznerDNSDriver._wire_value(RecordData("@", "TXT", value))
    parts = [p[1:-1] for p in wire.split(" ")]
    assert [len(p.encode("utf-8")) for p in parts] == [254, 146]
    assert HetznerDNSDriver._txt_from_wire(wire) == value


# ── Record writes: resolved RRset (#783) ────────────────────────────────
async def test_rrset_create_when_missing_posts_whole_set(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_NOT_FOUND], "post": [_FakeResponse(201, _action("create_rrset"))]})
    driver = _patch_client(monkeypatch, fake)
    rrset = RRsetData(ttl=600, members=(RRsetMember("192.0.2.1"), RRsetMember("192.0.2.2")))

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("WWW", "A", "192.0.2.2"), rrset)
    )

    assert fake.calls[0]["path"] == "/zones/example.com/rrsets/www/A"
    (write,) = fake.writes()
    assert write["path"] == "/zones/example.com/rrsets"
    assert write["json"] == {
        "name": "www",
        "type": "A",
        "records": [{"value": "192.0.2.1"}, {"value": "192.0.2.2"}],
        "ttl": 600,
    }


async def test_rrset_update_sets_records_and_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_rrset("www", "A", ["192.0.2.1", "192.0.2.3"], ttl=3600)],
            "post": [
                _FakeResponse(201, _action("set_rrset_records")),
                _FakeResponse(201, _action("change_rrset_ttl")),
            ],
        }
    )
    driver = _patch_client(monkeypatch, fake)
    rrset = RRsetData(ttl=300, members=(RRsetMember("192.0.2.1"), RRsetMember("192.0.2.2")))

    await driver._apply_record(
        _Server(), _CREDS, _change("update", RecordData("www", "A", "192.0.2.2"), rrset)
    )

    set_call, ttl_call = fake.writes()
    assert set_call["path"].endswith("/rrsets/www/A/actions/set_records")
    assert set_call["json"] == {"records": [{"value": "192.0.2.1"}, {"value": "192.0.2.2"}]}
    assert ttl_call["path"].endswith("/rrsets/www/A/actions/change_ttl")
    assert ttl_call["json"] == {"ttl": 300}


async def test_rrset_already_converged_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_rrset("www", "A", ["192.0.2.2", "192.0.2.1"], ttl=300)]})
    driver = _patch_client(monkeypatch, fake)
    rrset = RRsetData(ttl=300, members=(RRsetMember("192.0.2.1"), RRsetMember("192.0.2.2")))

    await driver._apply_record(
        _Server(), _CREDS, _change("update", RecordData("www", "A", "192.0.2.1"), rrset)
    )

    assert fake.writes() == []


async def test_rrset_empty_members_deletes_set(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_rrset("www", "A", ["192.0.2.1"])],
            "delete": [_FakeResponse(201, _action("delete_rrset"))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(),
        _CREDS,
        _change("delete", RecordData("www", "A", "192.0.2.1"), RRsetData(ttl=None, members=())),
    )

    (write,) = fake.writes()
    assert write["method"] == "delete" and write["path"] == "/zones/example.com/rrsets/www/A"


async def test_rrset_mx_members_render_priority(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_NOT_FOUND], "post": [_FakeResponse(201, _action("create_rrset"))]})
    driver = _patch_client(monkeypatch, fake)
    rrset = RRsetData(
        ttl=None,
        members=(
            RRsetMember("mx1.example.com", priority=10),
            RRsetMember("mx2.example.com", priority=20),
        ),
    )

    await driver._apply_record(
        _Server(),
        _CREDS,
        _change("create", RecordData("@", "MX", "mx2.example.com", priority=20), rrset),
    )

    (write,) = fake.writes()
    assert write["json"]["records"] == [
        {"value": "10 mx1.example.com."},
        {"value": "20 mx2.example.com."},
    ]
    assert "ttl" not in write["json"]  # inherit the zone default


# ── Record writes: per-value fallback (no resolved set) ─────────────────
async def test_create_on_missing_rrset_creates_it(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_NOT_FOUND], "post": [_FakeResponse(201, _action("create_rrset"))]})
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("@", "TXT", "hello", ttl=120))
    )

    (write,) = fake.writes()
    assert write["json"] == {
        "name": "@",
        "type": "TXT",
        "records": [{"value": '"hello"'}],
        "ttl": 120,
    }


async def test_create_adds_value_to_existing_set(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_rrset("www", "A", ["192.0.2.1"])],
            "post": [_FakeResponse(201, _action("add_rrset_records"))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("www", "A", "192.0.2.2"))
    )

    (write,) = fake.writes()
    assert write["path"].endswith("/rrsets/www/A/actions/add_records")
    assert write["json"] == {"records": [{"value": "192.0.2.2"}]}


async def test_create_of_present_value_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_rrset("www", "A", ["192.0.2.1"])]})
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("www", "A", "192.0.2.1"))
    )

    assert fake.writes() == []


async def test_delete_removes_one_value_from_multivalue_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeClient(
        {
            "get": [_rrset("www", "A", ["192.0.2.1", "192.0.2.2"])],
            "post": [_FakeResponse(201, _action("remove_rrset_records"))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("delete", RecordData("www", "A", "192.0.2.2"))
    )

    (write,) = fake.writes()
    assert write["path"].endswith("/rrsets/www/A/actions/remove_records")
    assert write["json"] == {"records": [{"value": "192.0.2.2"}]}


async def test_delete_last_value_deletes_rrset(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient(
        {
            "get": [_rrset("www", "A", ["192.0.2.1"])],
            "delete": [_FakeResponse(201, _action("delete_rrset"))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("delete", RecordData("www", "A", "192.0.2.1"))
    )

    (write,) = fake.writes()
    assert write["method"] == "delete"


@pytest.mark.parametrize("live", [_NOT_FOUND, _rrset("www", "A", ["192.0.2.1"])])
async def test_delete_of_absent_value_is_noop(
    monkeypatch: pytest.MonkeyPatch, live: _FakeResponse
) -> None:
    fake = _FakeClient({"get": [live]})
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("delete", RecordData("www", "A", "192.0.2.9"))
    )

    assert fake.writes() == []


async def test_wildcard_name_is_kept_in_path(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"get": [_rrset("*.lab", "A", ["192.0.2.1"])]})
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("*.lab", "A", "192.0.2.1"))
    )

    assert fake.calls[0]["path"] == "/zones/example.com/rrsets/*.lab/A"


# ── Actions ─────────────────────────────────────────────────────────────
async def test_running_action_is_polled_until_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hetzner_mod, "_ACTION_POLL_FIRST_S", 0)
    fake = _FakeClient(
        {
            "get": [
                _NOT_FOUND,
                _FakeResponse(200, _action("create_rrset", "running")),
                _FakeResponse(200, _action("create_rrset")),
            ],
            "post": [_FakeResponse(201, _action("create_rrset", "running"))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
    )

    polls = [c["path"] for c in fake.calls if c["path"].startswith("/zones/actions/")]
    assert polls == ["/zones/actions/7", "/zones/actions/7"]


async def test_failed_action_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    failed = _action("create_rrset", "error")
    failed["action"]["error"] = {"code": "invalid_input", "message": "bad record value"}
    fake = _FakeClient({"get": [_NOT_FOUND], "post": [_FakeResponse(201, failed)]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError, match="bad record value"):
        await driver._apply_record(
            _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
        )


async def test_stuck_action_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hetzner_mod, "_ACTION_POLL_FIRST_S", 0)
    monkeypatch.setattr(hetzner_mod, "_ACTION_TIMEOUT_S", 0)
    fake = _FakeClient(
        {"get": [_NOT_FOUND], "post": [_FakeResponse(201, _action("create_rrset", "running"))]}
    )
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError, match="still 'running'"):
        await driver._apply_record(
            _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
        )


async def test_action_polling_backs_off(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(hetzner_mod.asyncio, "sleep", fake_sleep)
    running = _action("create_rrset", "running")
    fake = _FakeClient(
        {
            "get": [_NOT_FOUND]
            + [_FakeResponse(200, running) for _ in range(4)]
            + [_FakeResponse(200, _action("create_rrset"))],
            "post": [_FakeResponse(201, running)],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
    )

    # 1 s doubling to a 5 s cap: five polls cost five requests, not twenty.
    assert sleeps == [1.0, 2.0, 4.0, 5.0, 5.0]


_LOCKED = _FakeResponse(423, {"error": {"code": "locked", "message": "action running"}})


async def test_locked_zone_write_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hetzner_mod, "_ACTION_POLL_FIRST_S", 0)
    fake = _FakeClient(
        {
            "get": [_NOT_FOUND],
            "post": [_LOCKED, _LOCKED, _FakeResponse(201, _action("create_rrset"))],
        }
    )
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_record(
        _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
    )

    assert [c["path"] for c in fake.writes()] == ["/zones/example.com/rrsets"] * 3


async def test_lock_that_outlasts_the_retry_window_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hetzner_mod, "_LOCKED_RETRY_S", 0)
    fake = _FakeClient({"get": [_NOT_FOUND], "post": [_LOCKED]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError, match="action running"):
        await driver._apply_record(
            _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
        )


async def test_rate_limit_names_the_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hetzner_mod.time, "time", lambda: 1000)
    limited = _FakeResponse(
        429,
        {"error": {"code": "rate_limit_exceeded", "message": "limit"}},
        headers={"RateLimit-Reset": "1042"},
    )
    fake = _FakeClient({"get": [_NOT_FOUND], "post": [limited]})
    driver = _patch_client(monkeypatch, fake)

    with pytest.raises(CloudDNSError, match="rate limit reached .*resets in 42 s"):
        await driver._apply_record(
            _Server(), _CREDS, _change("create", RecordData("x", "A", "192.0.2.1"))
        )


# ── Zone writes ─────────────────────────────────────────────────────────
class _Zone:
    name = "Example.COM."


async def test_apply_zone_create_is_primary_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"post": [_FakeResponse(201, _action("create_zone"))]})
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_zone(_Server(), _CREDS, _Zone(), "create")

    assert fake.calls[0]["path"] == "/zones"
    assert fake.calls[0]["json"] == {"name": "example.com", "mode": "primary"}


async def test_apply_zone_delete_by_name_and_404_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeClient({"delete": [_FakeResponse(201, _action("delete_zone")), _NOT_FOUND]})
    driver = _patch_client(monkeypatch, fake)

    await driver._apply_zone(_Server(), _CREDS, _Zone(), "delete")
    await driver._apply_zone(_Server(), _CREDS, _Zone(), "delete")

    assert [c["path"] for c in fake.calls] == ["/zones/example.com", "/zones/example.com"]


# ── Errors ──────────────────────────────────────────────────────────────
def test_error_envelope_raises_clouddnserror() -> None:
    resp = _FakeResponse(
        401, {"error": {"code": "unauthorized", "message": "unable to authenticate"}}
    )
    with pytest.raises(CloudDNSError, match="unable to authenticate"):
        HetznerDNSDriver._unwrap(resp)


def test_redirect_explains_retired_api() -> None:
    with pytest.raises(CloudDNSError, match="DNS Console API has been retired"):
        HetznerDNSDriver._unwrap(_FakeResponse(301, None))


def test_non_2xx_without_body_reports_status() -> None:
    class _NoJson(_FakeResponse):
        def json(self) -> Any:
            raise ValueError("no body")

    with pytest.raises(CloudDNSError, match="HTTP 503"):
        HetznerDNSDriver._unwrap(_NoJson(503))


async def test_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = HetznerDNSDriver()
    with pytest.raises(CloudDNSError, match="api_token"):
        await driver._list_zones(_Server(), {})


async def test_unsupported_op_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _patch_client(monkeypatch, _FakeClient({}))
    bogus = RecordChange(op="rename", zone_name="example.com.", record=RecordData("x", "A", "1.1.1.1"), target_serial=0)  # type: ignore[arg-type]
    with pytest.raises(CloudDNSError, match="unsupported record op"):
        await driver._apply_record(_Server(), _CREDS, bogus)


# ── Helpers + capabilities ──────────────────────────────────────────────
def test_relativize_helper() -> None:
    rel = HetznerDNSDriver._relativize
    assert rel("@", "example.com.") == "@"
    assert rel("", "example.com.") == "@"
    assert rel("example.com.", "example.com.") == "@"
    assert rel("www.example.com.", "example.com.") == "www"
    assert rel("a.b", "example.com.") == "a.b"


def test_capabilities_shape() -> None:
    caps = HetznerDNSDriver().capabilities()
    assert caps["name"] == "hetzner"
    assert caps["agentless"] is True
    assert caps["dnssec_online"] is False
    assert {"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"} <= set(caps["record_types"])
    assert "api.hetzner.cloud" in caps["notes"]

"""Offline unit tests for the agentless Technitium driver (issue #810).

Every test monkeypatches :meth:`TechnitiumAPIDriver._client` to return a
fake async-context-manager client serving canned envelopes, so nothing here
touches the network. Payload shapes are the ones the #744 importer captured
from a live ``technitium/dns-server:15.4.0``.

Two behaviours get disproportionate attention, because they are the two
that fail silently rather than loudly:

* **HTTP 200 with ``status: "error"``.** Technitium reports application
  failures in the body, not the status line. A driver that trusts
  ``raise_for_status()`` reads every auth failure as an empty success — and
  an empty zone list feeding a sync is how #430 describes deleting the
  world.
* **Value params on delete.** They are how Technitium identifies *which*
  member of an rrset to remove. Dropping them takes out a sibling
  round-robin A record instead of the intended one.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.drivers.dns._cloud_base import CloudDNSError
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember
from app.drivers.dns.technitium_api import TechnitiumAPIDriver


class _FakeResponse:
    """Minimal stand-in for an ``httpx.Response`` (status + json())."""

    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class _FakeClient:
    """Async-context-manager fake of ``httpx.AsyncClient``.

    Serves queued responses in order and records every ``(path, params)``
    for assertion. The driver only ever issues GETs — Technitium accepts
    GET or form-encoded POST for all calls and its own console uses GET.
    """

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def get(self, path: str, params: Any = None) -> _FakeResponse:
        self.calls.append({"path": path, "params": params or {}})
        if not self._responses:
            raise AssertionError(f"unexpected GET {path} (no queued response)")
        item = self._responses.pop(0)
        return item() if callable(item) else item


class _Server:
    """Stand-in for a ``DNSServer`` row — only the fields the driver reads."""

    def __init__(self, creds: dict[str, Any] | None = None) -> None:
        self.id = "11111111-1111-1111-1111-111111111111"
        self.name = "tech1"
        self.credentials_encrypted = b"blob" if creds is not None else None
        self._creds = creds


def _driver(monkeypatch: pytest.MonkeyPatch, responses: list[Any]) -> tuple[Any, _FakeClient]:
    """Return ``(driver, fake_client)`` with ``_client`` + creds patched."""
    drv = TechnitiumAPIDriver()
    fake = _FakeClient(responses)
    monkeypatch.setattr(TechnitiumAPIDriver, "_client", lambda *a, **k: fake)
    monkeypatch.setattr(
        TechnitiumAPIDriver,
        "_load_credentials",
        lambda self, server: getattr(server, "_creds", None)
        or {"api_url": "https://dns.example.test:53443", "api_token": "t"},
    )
    return drv, fake


def _ok(response: Any) -> _FakeResponse:
    return _FakeResponse({"status": "ok", "response": response})


# ── api_url normalisation ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://dns.example.test:53443", "https://dns.example.test:53443"),
        ("https://dns.example.test:53443/", "https://dns.example.test:53443"),
        # Operators paste the path they were browsing. Every call is built
        # as <root>/api/<call>, so the root is what has to be stored.
        ("https://dns.example.test:53443/api/", "https://dns.example.test:53443"),
        ("http://10.0.0.5:5380", "http://10.0.0.5:5380"),
    ],
)
def test_normalize_api_url_strips_back_to_the_root(raw: str, expected: str) -> None:
    assert TechnitiumAPIDriver.normalize_api_url(raw) == expected


def test_normalize_api_url_refuses_a_bare_host() -> None:
    """No scheme means no guess.

    Defaulting to http:// would put the bearer token on the wire in
    cleartext for an operator who simply typed a hostname.
    """
    with pytest.raises(CloudDNSError, match="http:// or https://"):
        TechnitiumAPIDriver.normalize_api_url("dns.example.test:53443")


def test_normalize_api_url_rejects_empty() -> None:
    with pytest.raises(CloudDNSError, match="missing 'api_url'"):
        TechnitiumAPIDriver.normalize_api_url("   ")


def test_missing_token_is_reported_as_missing_not_as_an_auth_failure() -> None:
    drv = TechnitiumAPIDriver()
    with pytest.raises(CloudDNSError, match="missing 'api_token'"):
        drv._creds({"api_url": "https://dns.example.test:53443"})


def test_verify_tls_defaults_to_on() -> None:
    """A credential blob written before the field existed stays strict."""
    drv = TechnitiumAPIDriver()
    _url, _token, verify = drv._creds({"api_url": "https://dns.example.test", "api_token": "t"})
    assert verify is True
    _url, _token, verify = drv._creds(
        {"api_url": "https://dns.example.test", "api_token": "t", "verify_tls": False}
    )
    assert verify is False


# ── the HTTP-200-with-an-error-body trap ───────────────────────────────


@pytest.mark.asyncio
async def test_error_envelope_on_http_200_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, _fake = _driver(
        monkeypatch,
        [_FakeResponse({"status": "error", "errorMessage": "Zone not found"})],
    )
    with pytest.raises(CloudDNSError, match="Zone not found"):
        await drv.pull_zones_from_server(_Server({"api_url": "https://x.test", "api_token": "t"}))


@pytest.mark.asyncio
async def test_invalid_token_says_so_and_says_where_to_fix_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The single most common operator error deserves its own message.

    A generic "error" sends people reading zone config when the actual
    problem is a token revoked in the console.
    """
    drv, _fake = _driver(monkeypatch, [_FakeResponse({"status": "invalid-token"})])
    with pytest.raises(CloudDNSError, match="Create Token"):
        await drv.pull_zones_from_server(_Server({"api_url": "https://x.test", "api_token": "t"}))


@pytest.mark.asyncio
async def test_no_envelope_at_all_is_not_an_empty_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy error page must raise, never read as "zero zones".

    This is the #430 shape: an empty list handed to a sync diff proposes
    deleting everything SpatiumDDI knows about.
    """
    drv, _fake = _driver(monkeypatch, [_FakeResponse("<html>502 Bad Gateway</html>", 502)])
    with pytest.raises(CloudDNSError, match="no API envelope"):
        await drv.pull_zones_from_server(_Server({"api_url": "https://x.test", "api_token": "t"}))


# ── zone reads ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_zones_skips_internal_and_keeps_the_real_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Technitium's built-in zones are noise; a Secondary is not a Primary.

    Reporting a Secondary as Primary would let sync-from-server adopt
    someone else's zone as authoritative.
    """
    drv, fake = _driver(
        monkeypatch,
        [
            _ok(
                {
                    "pageNumber": 1,
                    "totalPages": 1,
                    "zones": [
                        {"name": "example.com", "type": "Primary", "dnssecStatus": "Unsigned"},
                        {"name": "0.in-addr.arpa", "type": "Primary", "internal": True},
                        {
                            "name": "secondary.test",
                            "type": "Secondary",
                            "dnssecStatus": "SignedWithNSEC",
                        },
                    ],
                }
            )
        ],
    )
    zones = await drv.pull_zones_from_server(
        _Server({"api_url": "https://x.test", "api_token": "t"})
    )
    by_name = {z["name"]: z for z in zones}
    assert set(by_name) == {"example.com.", "secondary.test."}
    assert by_name["example.com."]["zone_type"] == "Primary"
    assert by_name["example.com."]["manageable"] is True
    assert by_name["secondary.test."]["zone_type"] == "Secondary"
    assert by_name["secondary.test."]["manageable"] is False
    assert by_name["secondary.test."]["dnssec_enabled"] is True
    assert fake.calls[0]["path"] == "/api/zones/list"


@pytest.mark.asyncio
async def test_list_zones_follows_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, fake = _driver(
        monkeypatch,
        [
            _ok(
                {"pageNumber": 1, "totalPages": 2, "zones": [{"name": "a.test", "type": "Primary"}]}
            ),
            _ok(
                {"pageNumber": 2, "totalPages": 2, "zones": [{"name": "b.test", "type": "Primary"}]}
            ),
        ],
    )
    zones = await drv.pull_zones_from_server(
        _Server({"api_url": "https://x.test", "api_token": "t"})
    )
    assert [z["name"] for z in zones] == ["a.test.", "b.test."]
    assert [c["params"]["pageNumber"] for c in fake.calls] == [1, 2]


@pytest.mark.asyncio
async def test_reverse_zones_are_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, _fake = _driver(
        monkeypatch,
        [
            _ok(
                {
                    "totalPages": 1,
                    "zones": [
                        {"name": "10.in-addr.arpa", "type": "Primary"},
                        {"name": "example.com", "type": "Primary"},
                    ],
                }
            )
        ],
    )
    zones = await drv.pull_zones_from_server(
        _Server({"api_url": "https://x.test", "api_token": "t"})
    )
    flags = {z["name"]: z["is_reverse_lookup"] for z in zones}
    assert flags == {"10.in-addr.arpa.": True, "example.com.": False}


# ── record reads ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pull_zone_records_translates_rdata_and_relativises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drv, fake = _driver(
        monkeypatch,
        [
            _ok(
                {
                    "records": [
                        {
                            "name": "www.example.com",
                            "type": "A",
                            "ttl": 300,
                            "rData": {"ipAddress": "10.0.0.1"},
                        },
                        {
                            "name": "example.com",
                            "type": "MX",
                            "ttl": 3600,
                            "rData": {"exchange": "mail.example.com", "preference": 10},
                        },
                        {
                            "name": "_sip._tcp.example.com",
                            "type": "SRV",
                            "ttl": 60,
                            "rData": {
                                "priority": 10,
                                "weight": 20,
                                "port": 5060,
                                "target": "sip.example.com",
                            },
                        },
                    ]
                }
            )
        ],
    )
    records = await drv.pull_zone_records(
        _Server({"api_url": "https://x.test", "api_token": "t"}), "example.com."
    )
    by_type = {r.record_type: r for r in records}
    assert by_type["A"].name == "www"
    assert by_type["A"].value == "10.0.0.1"
    assert by_type["MX"].name == "@"
    assert by_type["MX"].priority == 10
    assert by_type["SRV"].name == "_sip._tcp"
    assert (by_type["SRV"].weight, by_type["SRV"].port) == (20, 5060)
    assert fake.calls[0]["params"]["listZone"] == "true"


@pytest.mark.asyncio
async def test_pull_zone_records_drops_disabled_and_dnssec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A disabled record is one the daemon deliberately isn't answering with.

    Mirroring it would have SpatiumDDI claim it serves something that
    resolves to NXDOMAIN.
    """
    drv, _fake = _driver(
        monkeypatch,
        [
            _ok(
                {
                    "records": [
                        {
                            "name": "live.example.com",
                            "type": "A",
                            "rData": {"ipAddress": "10.0.0.1"},
                        },
                        {
                            "name": "off.example.com",
                            "type": "A",
                            "disabled": True,
                            "rData": {"ipAddress": "10.0.0.2"},
                        },
                        {"name": "example.com", "type": "DNSKEY", "rData": {"flags": 257}},
                        {"name": "example.com", "type": "SOA", "rData": {"serial": 1}},
                    ]
                }
            )
        ],
    )
    records = await drv.pull_zone_records(
        _Server({"api_url": "https://x.test", "api_token": "t"}), "example.com."
    )
    assert [(r.name, r.value) for r in records] == [("live", "10.0.0.1")]


@pytest.mark.asyncio
async def test_pull_zone_records_translates_tlsa_enum_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The crux of the shared rdata module, exercised through the driver."""
    drv, _fake = _driver(
        monkeypatch,
        [
            _ok(
                {
                    "records": [
                        {
                            "name": "_443._tcp.example.com",
                            "type": "TLSA",
                            "rData": {
                                "certificateUsage": "DANE-EE",
                                "selector": "SPKI",
                                "matchingType": "SHA2-256",
                                "certificateAssociationData": "ABCD",
                            },
                        }
                    ]
                }
            )
        ],
    )
    records = await drv.pull_zone_records(
        _Server({"api_url": "https://x.test", "api_token": "t"}), "example.com."
    )
    assert records[0].value == "3 1 1 abcd"


# ── record writes ──────────────────────────────────────────────────────


def _change(op: str, **kw: Any) -> RecordChange:
    rrset = kw.pop("rrset", None)
    rec = RecordData(
        name=kw.pop("name", "www"),
        record_type=kw.pop("record_type", "A"),
        value=kw.pop("value", "10.0.0.1"),
        ttl=kw.pop("ttl", 300),
        priority=kw.pop("priority", None),
        weight=kw.pop("weight", None),
        port=kw.pop("port", None),
    )
    # ``target_serial`` is required on the dataclass but unused by an
    # agentless driver — it exists for the agent's serial-convergence
    # tracking, which has no analogue when the control plane applies
    # the change itself.
    return RecordChange(op=op, zone_name="example.com.", record=rec, target_serial=0, rrset=rrset)


def _rrset(*values: str, ttl: int | None = None) -> RRsetData:
    return RRsetData(ttl=ttl, members=tuple(RRsetMember(value=v) for v in values))


@pytest.mark.asyncio
async def test_create_record_replaces_the_rrset_not_appends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``overwrite=true`` on the first member is load-bearing.

    Technitium APPENDS at ``overwrite=false``, so editing www A 10.0.0.1 to
    10.0.0.2 would leave the zone answering BOTH, round-robin, forever —
    verified live against 15.4.0 and warned about at length in the agent
    driver. Unlike the agent path there is no structural reload to
    eventually re-converge it, so this never self-heals.
    """
    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}), _change("create")
    )
    call = fake.calls[0]
    assert call["path"] == "/api/zones/records/add"
    assert call["params"]["domain"] == "www.example.com"
    assert call["params"]["zone"] == "example.com"
    assert call["params"]["ipAddress"] == "10.0.0.1"
    assert call["params"]["overwrite"] == "true"
    assert call["params"]["ttl"] == 300


@pytest.mark.asyncio
async def test_rrset_write_clears_once_then_appends_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#783: the whole desired set is replayed, member 0 clearing.

    A single overwriting write per member would leave only the last value;
    no overwriting write at all would accumulate stale ones. Exactly one
    clear, first, is the only sequence this API can express that lands the
    complete set.
    """
    drv, fake = _driver(monkeypatch, [_ok({}), _ok({}), _ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change(
            "update",
            value="10.0.0.1",
            rrset=_rrset("10.0.0.1", "10.0.0.2", "10.0.0.3", ttl=60),
        ),
    )
    assert [c["params"]["overwrite"] for c in fake.calls] == ["true", "false", "false"]
    assert [c["params"]["ipAddress"] for c in fake.calls] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    # The RRset's own TTL wins over the op record's.
    assert {c["params"]["ttl"] for c in fake.calls} == {60}


@pytest.mark.asyncio
async def test_empty_rrset_deletes_rather_than_writing_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty desired set means the RRset should not exist.

    Writing nothing and reporting success would leave the old value served
    while the op reads as applied.
    """
    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change("update", rrset=RRsetData(ttl=None, members=())),
    )
    assert fake.calls[0]["path"] == "/api/zones/records/delete"


@pytest.mark.asyncio
async def test_delete_stays_value_scoped_even_with_an_rrset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Survivors are already correct on the server — don't rebuild them.

    A wipe-and-rebuild would open a window where the name serves less than
    it should, to fix nothing.
    """
    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change("delete", value="10.0.0.2", rrset=_rrset("10.0.0.1", "10.0.0.3")),
    )
    assert len(fake.calls) == 1
    assert fake.calls[0]["path"] == "/api/zones/records/delete"
    assert fake.calls[0]["params"]["ipAddress"] == "10.0.0.2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "message", ["Record already exists", "No such record was found", "ALREADY EXISTS"]
)
async def test_replayed_op_is_an_idempotent_noop(
    monkeypatch: pytest.MonkeyPatch, message: str
) -> None:
    """Non-negotiable #9: tasks must be safe to retry.

    Technitium rejects a replayed create of an identical record and a delete
    of an already-absent one with a normal error envelope, but both mean the
    server is already in the state the op asks for. Raising would mark a
    replayed DNSRecordOp ``failed`` — and, worse, abort a multi-member RRset
    write partway: one member the server already has does not make the
    remaining members optional.
    """
    drv, fake = _driver(
        monkeypatch,
        [
            _FakeResponse({"status": "error", "errorMessage": message}),
            _ok({}),
        ],
    )
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change("create", rrset=_rrset("10.0.0.1", "10.0.0.2")),
    )
    # Both members were attempted — the first not-a-failure didn't stop it.
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_delete_record_sends_the_value_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without them Technitium removes a sibling value from the rrset.

    The delete endpoint identifies the record by its value, exactly like
    add — that is the whole reason ``record_params`` is shared by both.
    """
    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change("delete", value="10.0.0.2"),
    )
    call = fake.calls[0]
    assert call["path"] == "/api/zones/records/delete"
    assert call["params"]["ipAddress"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_apex_record_uses_the_bare_zone_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change("create", name="@", record_type="MX", value="mail.example.com.", priority=10),
    )
    call = fake.calls[0]
    assert call["params"]["domain"] == "example.com"
    assert call["params"]["exchange"] == "mail.example.com"
    assert call["params"]["preference"] == 10


@pytest.mark.asyncio
async def test_mx_preference_zero_survives(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero is the HIGHEST MX priority, not a missing value.

    ``rec.priority or 10`` would silently rewrite it to 10 and quietly
    demote the operator's primary mail exchanger.
    """
    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_record_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}),
        _change("create", name="@", record_type="MX", value="mail.example.com.", priority=0),
    )
    assert fake.calls[0]["params"]["preference"] == 0


@pytest.mark.asyncio
async def test_unsupported_record_type_is_refused_not_guessed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drv, _fake = _driver(monkeypatch, [])
    with pytest.raises(CloudDNSError, match="does not manage ANAME"):
        await drv.apply_record_change(
            _Server({"api_url": "https://x.test", "api_token": "t"}),
            _change("create", record_type="ANAME", value="target.example.com"),
        )


@pytest.mark.asyncio
async def test_unsupported_record_op_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    drv, _fake = _driver(monkeypatch, [])
    with pytest.raises(CloudDNSError, match="unsupported record op"):
        await drv.apply_record_change(
            _Server({"api_url": "https://x.test", "api_token": "t"}), _change("frobnicate")
        )


# ── zone writes ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zone_create_refuses_a_non_primary_zone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Silently creating a Primary instead would be worse than refusing.

    The operator's live server would gain an EMPTY authoritative zone for a
    domain it used to transfer or forward — the whole domain starts
    answering NXDOMAIN. ``capabilities()["zone_types"]`` claims Primary
    only, and this is where that claim is enforced.
    """

    class _Zone:
        name = "secondary.example.com."
        zone_type = "secondary"

    drv, fake = _driver(monkeypatch, [])
    with pytest.raises(CloudDNSError, match="primary zones only"):
        await drv.apply_zone_change(
            _Server({"api_url": "https://x.test", "api_token": "t"}), _Zone(), "create"
        )
    assert fake.calls == []


@pytest.mark.asyncio
async def test_zone_delete_works_for_any_zone_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The zone-type gate is a CREATE concern.

    Refusing to delete a secondary that SpatiumDDI tracks would strand it.
    """

    class _Zone:
        name = "secondary.example.com."
        zone_type = "secondary"

    drv, fake = _driver(monkeypatch, [_ok({})])
    await drv.apply_zone_change(
        _Server({"api_url": "https://x.test", "api_token": "t"}), _Zone(), "delete"
    )
    assert fake.calls[0]["path"] == "/api/zones/delete"


@pytest.mark.asyncio
async def test_zone_create_and_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Zone:
        name = "new.example.com."
        zone_type = "primary"

    drv, fake = _driver(monkeypatch, [_ok({}), _ok({})])
    server = _Server({"api_url": "https://x.test", "api_token": "t"})
    await drv.apply_zone_change(server, _Zone(), "create")
    await drv.apply_zone_change(server, _Zone(), "delete")
    assert fake.calls[0]["path"] == "/api/zones/create"
    assert fake.calls[0]["params"] == {"zone": "new.example.com", "type": "Primary"}
    assert fake.calls[1]["path"] == "/api/zones/delete"
    assert fake.calls[1]["params"] == {"zone": "new.example.com"}


@pytest.mark.asyncio
async def test_refused_connection_names_a_cause(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1613 QA — ``httpx.ConnectError`` for a refused connection stringifies
    to ``""``, so the error read "request failed: " with nothing after it.
    The exception class is always named; its text follows when present."""
    import httpx

    class _Zone:
        name = "new.example.com."
        zone_type = "primary"

    def _refuse() -> Any:
        raise httpx.ConnectError("")

    drv, _ = _driver(monkeypatch, [_refuse])
    with pytest.raises(CloudDNSError) as excinfo:
        await drv.apply_zone_change(
            _Server({"api_url": "https://x.test", "api_token": "t"}), _Zone(), "create"
        )
    message = str(excinfo.value)
    assert "request failed: ConnectError" in message
    assert not message.rstrip().endswith("failed:")


@pytest.mark.asyncio
async def test_unsupported_zone_op_is_refused_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``CloudDNSDriverBase.apply_zone_change`` guards op ahead of the driver.

    Asserted here rather than assumed, because the driver's own defensive
    branch for an unknown op is unreachable while that guard holds — and a
    zone op that slipped through would hit the network before failing.
    """

    class _Zone:
        name = "x.test."

    drv, fake = _driver(monkeypatch, [])
    with pytest.raises(ValueError, match="unsupported op"):
        await drv.apply_zone_change(
            _Server({"api_url": "https://x.test", "api_token": "t"}), _Zone(), "rename"
        )
    assert fake.calls == []


# ── probe ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_probe_uses_the_query_log_free_health_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``/api/dnsClient/healthCheck`` is documented as generating no query
    log entries — which matters, because the UI polls this."""
    drv, fake = _driver(
        monkeypatch,
        [_ok({}), _ok({"totalPages": 1, "zones": [{"name": "a.test", "type": "Primary"}]})],
    )
    result = await drv.probe(_Server({"api_url": "https://x.test", "api_token": "t"}))
    assert result.ok
    assert result.zone_count == 1
    assert fake.calls[0]["path"] == "/api/dnsClient/healthCheck"


@pytest.mark.asyncio
async def test_probe_reports_auth_failure_as_not_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drv, _fake = _driver(monkeypatch, [_FakeResponse({"status": "invalid-token"})])
    result = await drv.probe(_Server({"api_url": "https://x.test", "api_token": "t"}))
    assert not result.ok
    assert "Create Token" in result.message


@pytest.mark.asyncio
async def test_probe_stays_green_when_only_the_zone_count_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auth is already proven by then.

    A token legitimately scoped to a subset of zones must not render as a
    red X on a connection that works.
    """
    drv, _fake = _driver(
        monkeypatch, [_ok({}), _FakeResponse({"status": "error", "errorMessage": "denied"})]
    )
    result = await drv.probe(_Server({"api_url": "https://x.test", "api_token": "t"}))
    assert result.ok
    assert "listing zones failed" in result.message


@pytest.mark.asyncio
async def test_probe_without_credentials_is_a_clean_message() -> None:
    drv = TechnitiumAPIDriver()
    result = await drv.probe(_Server(None))
    assert not result.ok
    assert "no technitium_api credentials" in result.message.lower()


# ── registry + capabilities ────────────────────────────────────────────


def test_registered_agentless_but_not_as_a_cloud_driver() -> None:
    """The distinction is load-bearing.

    ``CLOUD_DNS_DRIVERS`` gates the cloud-import flow and the hosted-provider
    UI; this driver is operator-hosted and belongs in neither.
    """
    from app.drivers.dns import (
        AGENTLESS_DRIVERS,
        CLOUD_DNS_DRIVERS,
        CREDENTIALED_DNS_DRIVERS,
        TOPOLOGY_PULL_DRIVERS,
        get_driver,
        is_agentless,
        supports_topology_pull,
    )

    assert isinstance(get_driver("technitium_api"), TechnitiumAPIDriver)
    assert "technitium_api" in AGENTLESS_DRIVERS
    assert "technitium_api" not in CLOUD_DNS_DRIVERS
    assert "technitium_api" in CREDENTIALED_DNS_DRIVERS
    assert "technitium_api" in TOPOLOGY_PULL_DRIVERS
    assert is_agentless("technitium_api")
    assert supports_topology_pull("technitium_api")


def test_topology_pull_set_still_covers_the_pre_existing_drivers() -> None:
    """The two inline gates this replaced allowed windows_dns + cloud.

    Regression guard for the refactor: narrowing the set would silently
    take zone import away from a driver that had it.
    """
    from app.drivers.dns import CLOUD_DNS_DRIVERS, supports_topology_pull

    assert supports_topology_pull("windows_dns")
    for driver in CLOUD_DNS_DRIVERS:
        assert supports_topology_pull(driver), driver
    # Agent-managed drivers have no control-plane channel to their daemon.
    for driver in ("bind9", "powerdns", "technitium"):
        assert not supports_topology_pull(driver), driver


def test_dnssec_is_not_advertised_and_the_rest_gate_agrees() -> None:
    """Half-advertising signing would put a Sign button on a zone nothing
    would ever sign."""
    from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS

    caps = TechnitiumAPIDriver().capabilities()
    assert caps["dnssec_online"] is False
    assert "technitium_api" not in _DRIVER_GATED_OPERATIONS["dnssec_sign"]
    assert "technitium_api" not in _DRIVER_GATED_OPERATIONS["dnssec_unsign"]


def test_capabilities_advertise_the_agentless_contract() -> None:
    caps = TechnitiumAPIDriver().capabilities()
    assert caps["agentless"] is True
    assert caps["manages_zones"] is True
    assert caps["views"] is False
    assert "A" in caps["record_types"] and "SVCB" in caps["record_types"]


def test_record_type_gate_matches_what_the_driver_advertises() -> None:
    """A type the driver implements must not 422 at the create boundary.

    ``_DRIVER_GATED_RECORD_TYPES`` is a separate list from ``capabilities()``
    and gates SVCB / HTTPS / DNAME to the self-hosted backends. Both
    Technitium drivers are the same daemon, so the same wire capability —
    leaving the new one out made records it can serve unrepresentable.
    """
    from app.api.v1.dns.router import _DRIVER_GATED_RECORD_TYPES

    caps = TechnitiumAPIDriver().capabilities()
    for rtype, allowed in _DRIVER_GATED_RECORD_TYPES.items():
        if rtype in caps["record_types"]:
            assert "technitium_api" in allowed, rtype
        else:
            # ALIAS / LUA are PowerDNS-only and the driver doesn't claim them.
            assert "technitium_api" not in allowed, rtype

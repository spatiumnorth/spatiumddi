"""Regression tests for the shared AXFR helper (``app.drivers.dns._axfr``).

This module had no coverage at all, which is how it shipped a bug that made
every hostname-addressed AXFR fail 100% of the time: ``dns.query.xfr`` takes
an IP *literal* and calls ``dns.inet.af_for_address()`` on it up front, so a
``DNSServer.host`` like ``"dns-bind9"`` raised a bare, message-less
``ValueError`` before a single packet was sent. The #61 drift report and the
pull-importer both surfaced that empty string as the failure reason, so the
symptom was "failed, no reason given" on every BIND9 server.

The tests below pin both halves of the fix: names get resolved before the
transfer, and no failure path is ever allowed to produce a blank message.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from app.drivers.dns._axfr import axfr_zone_records
from app.drivers.dns.base import TsigKey


class _FakeZone:
    """Minimal stand-in for ``dns.zone.Zone`` — an empty zone."""

    def items(self) -> list[Any]:
        return []


@pytest.fixture
def captured_xfr(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patch out the network so we can assert on what ``xfr`` was handed."""
    import dns.query
    import dns.zone

    seen: dict[str, Any] = {}

    def fake_xfr(where: str, origin: Any, **kwargs: Any) -> object:
        seen["where"] = where
        seen["port"] = kwargs.get("port")
        seen["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(dns.query, "xfr", fake_xfr)
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _gen: _FakeZone())
    return seen


async def test_hostname_is_resolved_before_transfer(
    captured_xfr: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hostname must reach ``dns.query.xfr`` as an IP, never as a name.

    This is the actual shipped bug: passing the name through unresolved is
    what raised the bare ValueError.
    """
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 53))],
    )

    await axfr_zone_records(host="dns-bind9", port=53, zone_name="example.com.")

    assert captured_xfr["where"] == "192.0.2.10"


@pytest.mark.parametrize("literal", ["192.0.2.10", "2001:db8::1"])
async def test_ip_literals_pass_through_unchanged(
    literal: str, captured_xfr: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An address that already parses must not take the resolver path."""

    def _boom(*_a: Any, **_kw: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("getaddrinfo called for an IP literal")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)

    await axfr_zone_records(host=literal, port=53, zone_name="example.com.")

    assert captured_xfr["where"] == literal


async def test_resolution_failure_names_the_host(
    captured_xfr: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unresolvable host produces an operator-readable error, not OSError."""

    def _fail(*_a: Any, **_kw: Any) -> Any:
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _fail)

    with pytest.raises(RuntimeError) as excinfo:
        await axfr_zone_records(host="no-such-host", port=53, zone_name="example.com.")

    msg = str(excinfo.value)
    assert "no-such-host" in msg
    assert "example.com." in msg
    assert "resolve" in msg


async def test_all_resolved_addresses_are_tried(
    captured_xfr: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dual-stack host must fall through to its other addresses.

    The first address a resolver returns isn't necessarily the one
    allow-transfer permits, or even one that's routable from here.
    """
    import dns.query

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 53, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 53)),
        ],
    )

    tried: list[str] = []

    def flaky_xfr(where: str, origin: Any, **kwargs: Any) -> object:
        tried.append(where)
        if where == "2001:db8::1":
            raise OSError("No route to host")
        return object()

    monkeypatch.setattr(dns.query, "xfr", flaky_xfr)

    await axfr_zone_records(host="dual.example.", port=53, zone_name="example.com.")

    assert tried == ["2001:db8::1", "192.0.2.10"]


def test_resolve_dedupes_repeated_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """getaddrinfo repeats an address per socket type; don't try it twice."""
    from app.drivers.dns._axfr import resolve_server_address

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 53)),
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.10", 53)),
        ],
    )

    assert resolve_server_address("host.example.", 53, what="AXFR of x") == ["192.0.2.10"]


async def test_message_less_exception_never_surfaces_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bare ``ValueError()`` must not reach the caller as an empty string.

    Callers (drift report, pull-importer) render this text verbatim, so a
    blank message means the UI shows "failed" with no reason — the exact
    thing that made the original bug so hard to diagnose.
    """
    import dns.query

    def _bare(*_a: Any, **_kw: Any) -> Any:
        raise ValueError

    monkeypatch.setattr(dns.query, "xfr", _bare)

    with pytest.raises(RuntimeError) as excinfo:
        await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.")

    msg = str(excinfo.value)
    assert msg.strip()
    assert "ValueError" in msg
    assert "192.0.2.10" in msg


@pytest.mark.parametrize(
    ("exc", "expect_present", "expect_absent"),
    [
        # A routing/connection failure means we never got a DNS answer, so
        # pointing at the transfer ACL sends the operator to the wrong box.
        (OSError(113, "No route to host"), "could not be reached", "allow-transfer"),
        (TimeoutError("timed out"), "did not answer in time", "allow-transfer"),
        # The server DID answer and said no — now the ACL is the right hint.
        (ValueError("Zone transfer error: REFUSED"), "allow-transfer", "could not be reached"),
    ],
)
async def test_hint_matches_the_failure_cause(
    exc: Exception,
    expect_present: str,
    expect_absent: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The next-step hint must match why it failed, not be boilerplate."""
    import dns.query

    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    monkeypatch.setattr(dns.query, "xfr", _raise)

    with pytest.raises(RuntimeError) as excinfo:
        await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.")

    msg = str(excinfo.value)
    assert expect_present in msg
    assert expect_absent not in msg


# ── TSIG-signed transfers (#734) ────────────────────────────────────────────
#
# Agent-managed BIND9 / Technitium grant ``allow-transfer`` to a KEY, not to
# a source address, so an unsigned transfer is REFUSED 100% of the time.
# Verified live against the dev BIND9 on a stock ``allow_transfer: ["none"]``
# group before these were written: unsigned → REFUSED, signed with the group
# key → 7 nodes returned.


def _key(name: str = "spatium-default", algorithm: str = "hmac-sha256") -> TsigKey:
    # Any valid base64 works — dnspython only decodes it, the peer verifies it.
    return TsigKey(name=name, algorithm=algorithm, secret="c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MDE=")


async def test_no_tsig_means_no_keyring(captured_xfr: dict[str, Any]) -> None:
    """The default stays an unsigned transfer — Windows Path A and the
    operator-run BIND9 case authorise by address and must not regress."""
    await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.")
    assert "keyring" not in captured_xfr["kwargs"]


async def test_tsig_is_passed_through_to_the_query(captured_xfr: dict[str, Any]) -> None:
    """The whole point: a key must reach ``dns.query.xfr`` as a keyring."""
    import dns.name

    await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.", tsig=_key())
    kwargs = captured_xfr["kwargs"]
    assert kwargs["keyname"] == dns.name.from_text("spatium-default")
    assert kwargs["keyalgorithm"] == dns.name.from_text("hmac-sha256")
    assert dns.name.from_text("spatium-default") in kwargs["keyring"]


async def test_algorithm_is_honoured_not_defaulted(captured_xfr: dict[str, Any]) -> None:
    """A group on a non-default algorithm must sign with THAT algorithm.

    Signing with the wrong one fails as PeerBadKey, which looks nothing like
    a permissions problem — so silently defaulting would send the operator
    hunting the wrong thing.
    """
    import dns.name

    await axfr_zone_records(
        host="192.0.2.10",
        port=53,
        zone_name="example.com.",
        tsig=_key(algorithm="hmac-sha512"),
    )
    assert captured_xfr["kwargs"]["keyalgorithm"] == dns.name.from_text("hmac-sha512")


@pytest.mark.parametrize(
    ("bad_key", "reason"),
    [
        (TsigKey(name="k.", algorithm="hmac-sha256", secret="not!valid!base64"), "secret"),
        (TsigKey(name="k.", algorithm="hmac-nonsense", secret="c2VjcmV0"), "algorithm"),
    ],
)
async def test_unusable_key_raises_instead_of_degrading(
    bad_key: TsigKey, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unusable key must NOT fall back to an unsigned transfer.

    Degrading would turn a fixable configuration error into the same
    permanent REFUSED that #734 was about, with a hint pointing at
    allow-transfer instead of at the key.
    """
    import dns.query

    def _never_called(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("must not attempt a transfer with an unusable key")

    monkeypatch.setattr(dns.query, "xfr", _never_called)

    with pytest.raises(RuntimeError) as excinfo:
        await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.", tsig=bad_key)
    msg = str(excinfo.value)
    assert "unusable" in msg
    assert reason in msg


@pytest.mark.parametrize("exc_name", ["PeerBadSignature", "PeerBadKey", "PeerBadTime"])
async def test_signature_rejection_does_not_blame_allow_transfer(
    exc_name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rejected signature must not be reported as an ACL problem.

    dnspython signals these by exception TYPE, and its messages contain none
    of the RCODE mnemonics — "The peer didn't like the signature we sent"
    has no "BADSIG" in it — so the hint has to match on the class name.
    Matching on the text instead is a silent no-op, which is why this is
    parametrized over the real class names rather than a message.
    """
    import dns.query

    exc = type(exc_name, (Exception,), {})("The peer didn't like the signature we sent")

    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    monkeypatch.setattr(dns.query, "xfr", _raise)

    with pytest.raises(RuntimeError) as excinfo:
        await axfr_zone_records(host="192.0.2.10", port=53, zone_name="example.com.", tsig=_key())
    msg = str(excinfo.value)
    assert "TSIG signature" in msg
    assert "allow-transfer" not in msg


async def test_apex_ns_is_dropped_unless_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    """#1857 — the import / sync paths never see the apex NS (SpatiumDDI owns
    it at the zone level); the drift report asks for it so it can compare."""
    import dns.query
    import dns.zone

    served = dns.zone.from_text(
        "$TTL 300\n@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n"
        "@ NS ns1.example.net.\nsub NS ns.sub.example.com.\n",
        origin="example.com.",
        relativize=True,
    )
    monkeypatch.setattr(dns.query, "xfr", lambda *_a, **_kw: object())
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _gen: served)

    default = await axfr_zone_records(host="192.0.2.1", port=53, zone_name="example.com.")
    assert [(r.name, r.value) for r in default if r.record_type == "NS"] == [
        ("sub", "ns.sub.example.com.")
    ]
    asked = await axfr_zone_records(
        host="192.0.2.1", port=53, zone_name="example.com.", include_apex_ns=True
    )
    assert sorted((r.name, r.value) for r in asked if r.record_type == "NS") == [
        ("@", "ns1.example.net."),
        ("sub", "ns.sub.example.com."),
    ]
    assert all(r.record_type != "SOA" for r in asked)


async def test_bind_private_signing_record_is_never_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#3198 — an inline-signed BIND9 zone keeps a private ``TYPE65534``
    signing-state record at the apex and serves it in every AXFR (seen live on
    BIND 9.20). Returned, it read as a record extra on the server, so every
    signed zone's drift report said "drift"."""
    import dns.query
    import dns.zone

    served = dns.zone.from_text(
        "$TTL 300\n@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n"
        "@ NS ns1.example.net.\n@ 0 TYPE65534 \\# 5 0DC1710001\nwww A 192.0.2.10\n",
        origin="example.com.",
        relativize=True,
    )
    monkeypatch.setattr(dns.query, "xfr", lambda *_a, **_kw: object())
    monkeypatch.setattr(dns.zone, "from_xfr", lambda _gen: served)

    out = await axfr_zone_records(
        host="192.0.2.1", port=53, zone_name="example.com.", include_apex_ns=True
    )
    assert sorted(r.record_type for r in out) == ["A", "NS"]

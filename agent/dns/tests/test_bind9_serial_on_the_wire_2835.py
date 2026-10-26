"""#2835 — a BIND9 zone serves the control plane's serial, and reports what named serves.

In a group without views a record change reaches named as an RFC 2136 update.
One with no SOA in it is numbered by named itself (``serial-update-method
increment``: 1, 2, 3, …), while the agent reported the op's ``target_serial``
as reached, so the zone read in sync at a serial named never served.

Each update now carries the op's serial as the zone's SOA, in the same message
as the records, when it is later than the one named serves; and the serial the
agent reports is the one named serves afterwards (``reached_serial``).

The wire is driven against a scripted named that behaves the way BIND 9.20 was
measured to: an update whose SOA serial is later than the served one is served
at exactly that serial, anything else is served one past the old serial.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.update
import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _soa_serial
from tests.test_zone_render_over_updates import (
    ZONE,
    _Named,
    _render_text,
    quick,  # noqa: F401 — a fixture
)

ORIGIN = "lab.example.test."


class _FakeNamed:
    """``dns.query.tcp`` against one zone, answering as BIND 9.20 does."""

    def __init__(self, serial: int, *, signed: bool = False, refuse_soa: bool = False):
        self.serial = serial
        self.signed = signed
        self.refuse_soa = refuse_soa
        self.updates: list[dns.update.UpdateMessage] = []
        self.sent_soas: list[list[int]] = []  # per update, as it was sent

    def soa_text(self, serial: int) -> str:
        return f"ns1.{ORIGIN} hostmaster.{ORIGIN} {serial} 3600 600 86400 300"

    def __call__(
        self, q: Any, where: str, timeout: float | None = None, **kw: Any
    ) -> Any:
        assert where == "127.0.0.1"
        if isinstance(q, dns.update.UpdateMessage):
            return self._update(q)
        resp = dns.message.make_response(q)
        # A signed zone answers with its signed serial, kept ahead of the raw.
        shown = self.serial + 7 if self.signed else self.serial
        resp.answer.append(
            dns.rrset.from_text(ORIGIN, 3600, "IN", "SOA", self.soa_text(shown))
        )
        if self.signed:
            resp.answer.append(
                dns.rrset.from_text(
                    ORIGIN,
                    3600,
                    "IN",
                    "RRSIG",
                    f"SOA 13 3 3600 20991231000000 20260101000000 1 {ORIGIN} AAAA",
                )
            )
        return resp

    def _update(self, upd: dns.update.UpdateMessage) -> Any:
        self.updates.append(upd)
        self.sent_soas.append(_soa_serials(upd))
        resp = dns.message.make_response(upd)
        soas = [r for r in upd.update if r.rdtype == dns.rdatatype.SOA]
        if soas and self.refuse_soa:
            resp.set_rcode(dns.rcode.REFUSED)
            return resp
        new = soas[-1][0].serial if soas else None
        if new is not None and bind9._serial_later(new, self.serial):
            self.serial = new
        else:
            self.serial = (self.serial + 1) % 2**32 or 1
        return resp


def _op(
    target: int | None, name: str = "www", value: str = "192.0.2.10"
) -> dict[str, Any]:
    op: dict[str, Any] = {
        "op_id": f"op-{name}-{target}",
        "op": "create",
        "zone_name": ORIGIN,
        "record": {
            "name": name,
            "type": "A",
            "value": value,
            "ttl": 300,
            "rrset": {"ttl": 300, "members": [{"value": value}]},
        },
    }
    if target is not None:
        op["target_serial"] = target
    return op


def _soa_serials(upd: dns.update.UpdateMessage) -> list[int]:
    return [rd.serial for r in upd.update if r.rdtype == dns.rdatatype.SOA for rd in r]


@pytest.fixture
def driver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bind9Driver:
    monkeypatch.setattr(
        bind9.shutil, "which", lambda _n: None
    )  # no rndc unless a test says so
    return Bind9Driver(tmp_path)


def test_two_ops_on_a_new_zone_serve_and_report_the_control_planes_serial(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issue's case: a zone created at ``last_serial`` 0, which named
    loaded at its placeholder 1, takes two record writes."""
    named = _FakeNamed(1)
    monkeypatch.setattr(dns.query, "tcp", named)

    for target in (2026102600, 2026102601):
        driver.apply_record_op(_op(target, name=f"h{target % 100}"))
        assert _soa_serials(named.updates[-1]) == [
            target
        ], "the serial rides the update"
        assert named.serial == target, "named serves the control plane's serial"
        assert driver.reached_serial(ORIGIN) == named.serial == target

    assert len(named.updates) == 2, "one message per op: records and serial together"
    # the SOA keeps the zone's other fields as named serves them
    soa = next(r for r in named.updates[0].update if r.rdtype == dns.rdatatype.SOA)
    assert soa[0].refresh == 3600 and soa[0].minimum == 300 and soa.ttl == 3600


@pytest.mark.parametrize("served", [2026102601, 2026102605])
def test_a_serial_that_is_not_later_is_never_sent(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch, served: int
) -> None:
    """Never lower than what named serves: the update goes without a SOA,
    named numbers it, and THAT is what is reported."""
    named = _FakeNamed(served)
    monkeypatch.setattr(dns.query, "tcp", named)

    driver.apply_record_op(_op(2026102601))

    assert _soa_serials(named.updates[-1]) == []
    assert named.serial == served + 1
    assert driver.reached_serial(ORIGIN) == served + 1


def test_an_op_without_a_target_serial_sends_no_soa_and_reads_nothing(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _FakeNamed(5)
    sent: list[Any] = []

    def tcp(q: Any, *a: Any, **kw: Any) -> Any:
        sent.append(q)
        return named(q, *a, **kw)

    monkeypatch.setattr(dns.query, "tcp", tcp)
    driver.apply_record_op(_op(None))
    assert len(sent) == 1 and isinstance(sent[0], dns.update.UpdateMessage)
    assert _soa_serials(sent[0]) == []
    assert driver.reached_serial(ORIGIN) is None


def test_a_signed_zone_compares_the_raw_serial(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An inline-signed zone answers with its signed serial, which runs ahead
    of the raw zone an update writes to; the raw one comes from zonestatus."""
    named = _FakeNamed(2026102600, signed=True)
    monkeypatch.setattr(dns.query, "tcp", named)
    monkeypatch.setattr(bind9.shutil, "which", lambda n: f"/usr/sbin/{n}")

    def rndc(cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        assert cmd[-2:] == ["zonestatus", ORIGIN]
        out = f"name: {ORIGIN}\nserial: {named.serial}\nsigned serial: {named.serial + 7}\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(subprocess, "run", rndc)
    # signed serial 2026102607 is "later" than the target; the raw one is not
    driver.apply_record_op(_op(2026102601))
    assert _soa_serials(named.updates[-1]) == [2026102601]
    assert driver.reached_serial(ORIGIN) == named.serial == 2026102601


def test_a_soa_the_live_config_refuses_still_lands_the_records(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An update-policy zone still on the pre-#2835 grant refuses the SOA."""
    named = _FakeNamed(3, refuse_soa=True)
    monkeypatch.setattr(dns.query, "tcp", named)

    driver.apply_record_op(_op(2026102601))

    assert named.sent_soas == [[2026102601], []]
    assert named.serial == 4
    assert driver.reached_serial(ORIGIN) == 4


def test_the_agents_key_may_write_the_soa_under_update_policy() -> None:
    out = bind9._render_update_policy(
        {
            "dynamic_update_enabled": True,
            "update_acl": [
                {"action": "deny", "match_kind": "tsig_key", "tsig_key_name": "dc01."}
            ],
        },
        "spatium-loop.",
    )
    assert out.startswith("update-policy { grant spatium-loop. zonesub ANY; ")


# ── reporting what named serves after a structural apply ─────────────────────


def test_served_zone_serials_reads_primaries_and_keeps_the_rest(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _FakeNamed(2026102603)
    monkeypatch.setattr(dns.query, "tcp", named)
    bundle = {
        "zones": [
            {"name": ORIGIN, "type": "primary", "serial": 2026102601},
            {"name": "sec.test.", "type": "secondary", "serial": 9},
            {"name": "fwd.test.", "type": "forward", "serial": 0},
        ]
    }
    assert driver.served_zone_serials(bundle) == {
        ORIGIN.rstrip("."): 2026102603,
        "sec.test": 9,
        "fwd.test": 0,
    }


def test_a_group_with_views_reports_the_bundle_serials(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_wire(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("a group with views reports as it always did")

    monkeypatch.setattr(dns.query, "tcp", no_wire)
    bundle = {
        "views": [{"name": "internal"}],
        "zones": [{"name": ORIGIN, "type": "primary", "serial": 2026102601}],
    }
    assert driver.served_zone_serials(bundle) == {ORIGIN.rstrip("."): 2026102601}


def test_an_unreadable_primary_is_not_reported(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*_a: Any, **_kw: Any) -> Any:
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(dns.query, "tcp", refused)
    bundle = {"zones": [{"name": ORIGIN, "type": "primary", "serial": 2026102601}]}
    assert driver.served_zone_serials(bundle) == {}


# ── a re-render of data named already serves keeps its serial ────────────────


def _dump(serial: int, extra: str = "") -> str:
    """``_render_text``'s records, in the layout named writes a zone back in."""
    return (
        f"$ORIGIN .\n$TTL 3600\t; 1 hour\n{ZONE}\t\tIN SOA\tns1.{ZONE}. host.{ZONE}. (\n"
        f"\t\t\t\t{serial} ; serial\n\t\t\t\t3600 600 86400 300 )\n"
        f"\t\t\tNS\tns1.{ZONE}.\n$ORIGIN {ZONE}.\nns1\t\t\tA\t192.0.2.53\n{extra}"
    )


class _DumpingNamed(_Named):
    def __init__(self, tmp: Path, dump: str, **kw: Any) -> None:
        super().__init__(tmp, **kw)
        self.dump = dump

    def tick(self, _s: float = 0.0) -> None:
        if self.queued and self.writes:
            self.file().write_text(self.dump)
            self.queued = False
            self.held = False


def _setup(
    tmp: Path, monkeypatch: pytest.MonkeyPatch, named: _Named, staged: int
) -> Bind9Driver:
    (tmp / "rendered" / "zones").mkdir(parents=True)
    named.file().write_text(_render_text(staged - 3))
    new = tmp / "rendered.new" / "zones"
    new.mkdir(parents=True)
    (new / f"{ZONE}.db").write_text(_render_text(staged, ttl=3600))
    drv = Bind9Driver(tmp)
    drv.daemon_pid = 4242
    monkeypatch.setattr(drv, "daemon_running", lambda: True)
    monkeypatch.setattr(subprocess, "run", named)
    monkeypatch.setattr(bind9.time, "sleep", named.tick)
    monkeypatch.setattr(bind9, "_ZONE_DUMP_TIMEOUT_S", 5.0)
    return drv


def test_a_render_of_what_named_serves_keeps_the_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quick: None  # noqa: F811
) -> None:
    """Record ops carried both records and serial into named; the next render
    writes them down at that same serial. Moving it on would serve a serial
    the control plane never assigned."""
    named = _DumpingNamed(tmp_path, _dump(2026102605), serving=2026102605, held=True)
    drv = _setup(tmp_path, monkeypatch, named, staged=2026102605)

    drv.swap_and_reload()

    assert _soa_serial(tmp_path / "rendered" / "zones" / f"{ZONE}.db") == 2026102605
    assert named.serving == 2026102605


def test_a_render_with_other_data_at_the_served_serial_still_moves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quick: None  # noqa: F811
) -> None:
    named = _DumpingNamed(
        tmp_path,
        _dump(2026102605, extra="from-rfc2136\t\tA\t192.0.2.99\n"),
        serving=2026102605,
        held=True,
    )
    drv = _setup(tmp_path, monkeypatch, named, staged=2026102605)

    drv.swap_and_reload()

    assert _soa_serial(tmp_path / "rendered" / "zones" / f"{ZONE}.db") == 2026102606

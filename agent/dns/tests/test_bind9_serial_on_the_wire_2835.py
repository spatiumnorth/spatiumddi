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

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.update
import pytest

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.base import SERIAL_UNREAD
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _soa_serial
from tests.test_zone_render_over_updates import (
    ZONE,
    _Named,
    _render_text,
    quick,  # noqa: F401 — a fixture
)

ORIGIN = "lab.example.test."


class _FakeNamed:
    """``dns.query.tcp`` against one zone, answering as BIND 9.20 does.

    Measured against a real named: an update carrying a SOA whose serial is
    later than the raw one is served at exactly that serial; otherwise the raw
    serial goes up by one. An inline-signed zone (``signed``) answers with its
    signed serial, which then becomes the raw one if that is later, or its
    own plus one. A delete of the whole apex NS RRset is ignored, and so is a
    delete of the last apex NS by value (RFC 2136 §3.4.2.4).
    """

    def __init__(
        self,
        serial: int,
        *,
        signed: int | None = None,
        refuse_soa: bool = False,
        authoritative: bool = True,
        ns: tuple[str, ...] = (f"ns1.{ORIGIN}",),
        glue: bool = False,
    ):
        self.serial = serial
        self.signed = signed
        self.refuse_soa = refuse_soa
        self.authoritative = authoritative
        self.ns = list(ns)
        self.glue = glue  # ``ns1 A 127.0.0.1`` present
        self.mname = f"ns1.{ORIGIN}"
        # BIND re-signs asynchronously: the signed serial an update moves to
        # shows only after this many more ``rndc zonestatus`` reads.
        self.sign_lag = 0
        self._pending_signed: int | None = None
        self._lag_left = 0
        # Things that happen to the zone just before our next update lands:
        # a third-party RFC 2136 client's own update (+1), say.
        self.before_next_update: list[Any] = []
        self.fail_reads_after_update = False
        self.queries: list[Any] = []
        self.updates: list[dns.update.UpdateMessage] = []
        self.sent_soas: list[list[int]] = []  # per update, as it was sent

    @property
    def wire_serial(self) -> int:
        return self.signed if self.signed is not None else self.serial

    def _tick_signer(self) -> None:
        if self._pending_signed is not None:
            if self._lag_left <= 0:
                self.signed, self._pending_signed = self._pending_signed, None
            else:
                self._lag_left -= 1

    def soa_text(self, serial: int) -> str:
        return f"{self.mname} hostmaster.{ORIGIN} {serial} 3600 600 86400 300"

    def __call__(
        self, q: Any, where: str, timeout: float | None = None, **kw: Any
    ) -> Any:
        assert where == "127.0.0.1"
        if isinstance(q, dns.update.UpdateMessage):
            return self._update(q)
        self.queries.append(q)
        if self.fail_reads_after_update and self.updates:
            raise ConnectionResetError(104, "Connection reset by peer")
        resp = dns.message.make_response(q)
        if self.authoritative:
            resp.flags |= dns.flags.AA
        qtype = q.question[0].rdtype
        if qtype == dns.rdatatype.NS:
            resp.answer.append(dns.rrset.from_text(ORIGIN, 3600, "IN", "NS", *self.ns))
        else:
            resp.answer.append(
                dns.rrset.from_text(
                    ORIGIN, 3600, "IN", "SOA", self.soa_text(self.wire_serial)
                )
            )
            if self.signed is not None and q.ednsflags & dns.flags.DO:
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

    def zonestatus(
        self, cmd: list[str], *a: Any, **kw: Any
    ) -> subprocess.CompletedProcess:
        """``rndc zonestatus`` as named prints it: raw, then signed."""
        self._tick_signer()
        out = f"name: {ORIGIN}\nserial: {self.serial}\n"
        if self.signed is not None:
            out += f"signed serial: {self.signed}\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    def _update(self, upd: dns.update.UpdateMessage) -> Any:
        while self.before_next_update:
            self.before_next_update.pop(0)(self)
        self.updates.append(upd)
        self.sent_soas.append(_soa_serials(upd))
        resp = dns.message.make_response(upd)
        soas = [r for r in upd.update if r.rdtype == dns.rdatatype.SOA]
        if soas and self.refuse_soa:
            resp.set_rcode(dns.rcode.REFUSED)
            return resp
        origin = dns.name.from_text(ORIGIN)
        glue_name = dns.name.from_text(f"ns1.{ORIGIN}")
        for rrset in upd.update:
            owner = rrset.name.derelativize(origin)
            if rrset.rdtype == dns.rdatatype.NS and owner == origin:
                vals = [rd.target.derelativize(origin).to_text() for rd in rrset]
                if rrset.deleting == dns.rdataclass.ANY:
                    continue  # ignored at the apex
                if rrset.deleting == dns.rdataclass.NONE:
                    for v in vals:
                        if v in self.ns and len(self.ns) > 1:
                            self.ns.remove(v)
                else:
                    self.ns += [v for v in vals if v not in self.ns]
            elif rrset.rdtype == dns.rdatatype.A and owner == glue_name:
                if rrset.deleting is not None:
                    self.glue = False
                elif any(rd.address == "127.0.0.1" for rd in rrset):
                    self.glue = True
            elif rrset.rdtype == dns.rdatatype.SOA and rrset.deleting is None:
                self.mname = rrset[0].mname.derelativize(origin).to_text()
        new = soas[-1][0].serial if soas else None
        if new is not None and bind9._serial_later(new, self.serial):
            self.serial = new
        else:
            self.serial = (self.serial + 1) % 2**32 or 1
        if self.signed is not None:
            later = bind9._serial_later(self.serial, self.signed)
            self._pending_signed = self.serial if later else self.signed + 1
            self._lag_left = self.sign_lag
            self._tick_signer()
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


@pytest.mark.parametrize(
    ("raw", "signed", "target", "wire"),
    [
        # the target is later than both: raw and signed both reach it
        (2026102600, 2026102600, 2026102601, 2026102601),
        # D4: signed ahead of the target (re-signing moved it): no SOA, and
        # the wire serial (signed + 1) is what is reported, not the target
        (2026102601, 2026102603, 2026102602, 2026102604),
    ],
)
def test_a_signed_zone_is_compared_and_reported_at_its_wire_serial(
    driver: Bind9Driver,
    monkeypatch: pytest.MonkeyPatch,
    raw: int,
    signed: int,
    target: int,
    wire: int,
) -> None:
    named = _FakeNamed(raw, signed=signed)
    monkeypatch.setattr(dns.query, "tcp", named)
    monkeypatch.setattr(bind9.shutil, "which", lambda n: f"/usr/sbin/{n}")
    monkeypatch.setattr(subprocess, "run", named.zonestatus)

    driver.apply_record_op(_op(target))

    assert named.sent_soas == [[target] if target == wire else []]
    assert named.wire_serial == wire
    assert driver.reached_serial(ORIGIN) == wire
    bundle = {"zones": [{"name": ORIGIN, "type": "primary", "serial": target}]}
    assert driver.served_zone_serials(bundle) == {ORIGIN.rstrip("."): wire}


def test_an_unanswered_signed_zone_falls_back_to_its_signed_serial(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _FakeNamed(2026102601, authoritative=False)
    monkeypatch.setattr(dns.query, "tcp", named)
    monkeypatch.setattr(bind9.shutil, "which", lambda n: f"/usr/sbin/{n}")

    def rndc(cmd: list[str], *a: Any, **kw: Any) -> subprocess.CompletedProcess:
        out = f"name: {ORIGIN}\nserial: 2026102601\nsigned serial: 2026102604\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(subprocess, "run", rndc)
    bundle = {"zones": [{"name": ORIGIN, "type": "primary", "serial": 2026102601}]}
    assert driver.served_zone_serials(bundle) == {ORIGIN.rstrip("."): 2026102604}


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
        grant_soa=True,
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


# ── review findings ──────────────────────────────────────────────────────────


def test_a_third_party_update_between_read_and_write_is_reported_as_served(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A #641 client updates the zone after our SOA read: our serial is then
    not later, named numbers ours itself, and THAT is what is reported."""
    named = _FakeNamed(2026102600)
    monkeypatch.setattr(dns.query, "tcp", named)

    def third_party(n: _FakeNamed) -> None:
        n.serial += 1  # 2026102601, the very serial our op carries

    named.before_next_update.append(third_party)
    driver.apply_record_op(_op(2026102601))

    assert named.sent_soas == [[2026102601]]
    assert named.serial == 2026102602
    assert driver.reached_serial(ORIGIN) == 2026102602


def test_a_dnssec_op_does_not_report_the_last_record_ops_serial(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _FakeNamed(1)
    monkeypatch.setattr(dns.query, "tcp", named)
    monkeypatch.setattr(driver, "_dnssec_rollover", lambda op: None)

    driver.apply_record_op(_op(2026102601))
    assert driver.reached_serial(ORIGIN) == 2026102601
    named.serial = 2026102603  # moved on since (a re-render, a third party)

    driver.apply_record_op({"op_id": "r", "op": "dnssec_rollover", "zone_name": ORIGIN})
    assert driver.reached_serial(ORIGIN) is None
    for kind in ("dnssec_sign", "dnssec_unsign"):
        driver.apply_record_op(_op(2026102601))
        driver.apply_record_op({"op_id": kind, "op": kind, "zone_name": ORIGIN})
        assert driver.reached_serial(ORIGIN) is None


def test_a_serial_that_cannot_be_read_back_is_unread_not_the_target(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _FakeNamed(1)
    named.fail_reads_after_update = True
    monkeypatch.setattr(dns.query, "tcp", named)

    driver.apply_record_op(_op(2026102601))

    assert named.sent_soas == [[2026102601]]
    assert driver.reached_serial(ORIGIN) is SERIAL_UNREAD


def test_the_soa_read_asks_for_no_recursion_and_needs_an_authoritative_answer(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resolver-enabled named whose zone failed to load answers someone
    else's SOA without AA. That is no read: no SOA is sent, nothing reported."""
    named = _FakeNamed(1, authoritative=False)
    monkeypatch.setattr(dns.query, "tcp", named)

    driver.apply_record_op(_op(2026102601))

    assert all(not (q.flags & dns.flags.RD) for q in named.queries)
    assert named.sent_soas == [[]]
    assert driver.reached_serial(ORIGIN) is SERIAL_UNREAD
    bundle = {"zones": [{"name": ORIGIN, "type": "primary", "serial": 2026102601}]}
    assert driver.served_zone_serials(bundle) == {}


def test_a_refused_soa_is_not_tried_again_until_the_next_render(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    named = _FakeNamed(3, refuse_soa=True)
    monkeypatch.setattr(dns.query, "tcp", named)

    driver.apply_record_op(_op(2026102601))
    driver.apply_record_op(_op(2026102602, name="mail"))

    assert named.sent_soas == [[2026102601], [], []], "one message for the second op"
    driver.render({"options": {}, "tsig_keys": [], "zones": []})
    named.refuse_soa = False
    driver.apply_record_op(_op(2026102603, name="ftp"))
    assert named.sent_soas[-1] == [2026102603]


# ── only the product's own key may write the SOA ─────────────────────────────

_GROUP_KEY = {
    "name": "spatium-loop.",
    "secret": "c2VjcmV0c2VjcmV0",
    "algorithm": "hmac-sha256",
    "loopback": True,
}
_OPERATOR_KEY = {
    "name": "aaa-ops.",
    "secret": "b3BzLXhmZXI=",
    "algorithm": "hmac-sha256",
}


def _policy_render(tmp_path: Path, keys: list[dict[str, Any]]) -> str:
    bundle = {
        "options": {
            "forwarders": [],
            "allow_query": ["any"],
            "allow_transfer": ["none"],
        },
        "tsig_keys": keys,
        "zones": [
            {
                "name": ORIGIN,
                "type": "primary",
                "serial": 2026102601,
                "records": [],
                "dynamic_update_enabled": True,
                "update_acl": [
                    {
                        "action": "grant",
                        "match_kind": "tsig_key",
                        "tsig_key_name": "aaa-ops.",
                        "record_types": ["A"],
                    }
                ],
            }
        ],
    }
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_the_group_key_is_granted_any(tmp_path: Path) -> None:
    conf = _policy_render(tmp_path, [_GROUP_KEY, _OPERATOR_KEY])
    assert "grant spatium-loop. zonesub ANY;" in conf
    assert "grant aaa-ops. zonesub A;" in conf


def test_an_operator_key_standing_in_as_loopback_keeps_its_grant(
    tmp_path: Path,
) -> None:
    """No group key: ``tsig_keys[0]`` is an operator key external clients
    hold, and it must not gain SOA and NS."""
    conf = _policy_render(tmp_path, [_OPERATOR_KEY])
    assert "grant aaa-ops. zonesub;" in conf
    assert "ANY" not in conf


def test_the_sync_loop_reports_nothing_for_an_unread_serial(tmp_path: Path) -> None:
    """``SERIAL_UNREAD`` drops the zone from the report instead of falling
    back to the op's target; another zone in the same pass is reported."""
    from tests import test_zone_state_after_ops as zs

    class _Unread(zs._Driver):
        def reached_serial(self, zone_name: str) -> object:
            return SERIAL_UNREAD if zone_name.startswith("a.") else 2026100107

    zs.ensure_layout(tmp_path)
    driver = _Unread(tmp_path)
    loop = zs.SyncLoop(zs._Cfg(tmp_path), ["tok"], driver, zs._Heartbeat())
    loop._current_structural_etag = zs.STRUCTURAL
    cp = zs._ControlPlane()
    loop._client = lambda: cp  # type: ignore[method-assign]
    cp.bundle = zs._bundle(
        "e1", [zs._op("o1", "a.test.", 2026100105), zs._op("o2", "b.test.", 2026100107)]
    )

    loop._poll_once()

    assert driver.applied == ["o1", "o2"]
    assert cp.zone_state == [[{"zone_name": "b.test", "serial": 2026100107}]]


# ── D5: an apex NS op leaves named with the apex the next render writes ──────


def _note(drv: Bind9Driver, zone: dict[str, Any]) -> None:
    """What ``render`` notes of a zone's apex, without rendering it."""
    drv._apex_lines = []
    drv._remember_apex(zone)
    drv._apex_blob = ("\n" + "\n".join(drv._apex_lines) + "\n").encode()


def _ns_op(target: int, *values: str) -> dict[str, Any]:
    return {
        "op_id": f"ns-{target}",
        "op": "create" if values else "delete",
        "zone_name": ORIGIN,
        "target_serial": target,
        "record": {
            "name": "@",
            "type": "NS",
            "value": values[0] if values else "gone.example.",
            "ttl": 3600,
            "rrset": {"ttl": 3600, "members": [{"value": v} for v in values]},
        },
    }


def _rendered(zone: dict[str, Any]) -> tuple[set[str], bool, str]:
    """``(apex NS, placeholder glue, SOA MNAME)`` as the render writes them."""
    apex = bind9._zone_apex(zone)
    origin = zone["name"]
    declared = {
        bind9._zone_file_name(r["value"], origin).lower()
        for r in zone["records"]
        if r["type"] == "NS" and r["name"] in ("@", "")
    }
    return (
        (declared or {n.lower() for n in apex.ns}),
        apex.placeholder_glue,
        apex.soa_mname,
    )


@pytest.mark.parametrize("primary_ns", ["ns-a.provider.test.", None])
def test_an_apex_ns_op_leaves_named_with_the_rendered_ns_set(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch, primary_ns: str | None
) -> None:
    """The walk's D5: the zone's first NS (``primary_ns``, or the placeholder
    and its glue) stayed beside the op's, while the render writes the op's
    alone; every structural apply then found other data at the same serial."""
    first = primary_ns or f"ns1.{ORIGIN}"
    named = _FakeNamed(2026102600, ns=(first,), glue=primary_ns is None)
    named.mname = first
    monkeypatch.setattr(dns.query, "tcp", named)
    zone: dict[str, Any] = {"name": ORIGIN, "primary_ns": primary_ns, "records": []}
    _note(driver, zone)

    driver.apply_record_op(_ns_op(2026102601, "ns.other.test."))
    zone["records"] = [{"name": "@", "type": "NS", "value": "ns.other.test."}]
    ns, glue, mname = _rendered(zone)
    assert {n.lower() for n in named.ns} == ns == {"ns.other.test."}
    assert named.glue is glue is False
    assert named.mname.lower() == mname.lower()
    assert driver.reached_serial(ORIGIN) == named.serial == 2026102601

    # deleting the last declared NS: the render falls back, and so does named
    driver.apply_record_op(_ns_op(2026102602))
    zone["records"] = []
    ns, glue, mname = _rendered(zone)
    assert {n.lower() for n in named.ns} == ns == {first.lower()}
    assert named.glue is glue
    assert named.mname.lower() == mname.lower()
    assert driver.reached_serial(ORIGIN) == named.serial == 2026102602


def test_two_servers_converge_on_the_same_apex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bind9.shutil, "which", lambda _n: None)
    zone = {"name": ORIGIN, "primary_ns": "ns-a.provider.test.", "records": []}
    servers = []
    for i in range(2):
        named = _FakeNamed(2026102600, ns=("ns-a.provider.test.",))
        drv = Bind9Driver(tmp_path / f"s{i}")
        _note(drv, zone)
        monkeypatch.setattr(dns.query, "tcp", named)
        drv.apply_record_op(_ns_op(2026102601, "ns.other.test.", "ns2.other.test."))
        servers.append(named)
    assert [sorted(n.ns) for n in servers] == [
        ["ns.other.test.", "ns2.other.test."]
    ] * 2
    assert [n.serial for n in servers] == [2026102601, 2026102601]


def test_a_render_of_named_data_behind_named_keeps_named_serial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quick: None  # noqa: F811
) -> None:
    """The cap: named is ahead of the render (a move on an earlier apply) and
    holds the same data. Served at named's own serial, not one past again —
    or every structural apply moves it once more (D5: 03 to 12)."""
    named = _DumpingNamed(tmp_path, _dump(2026102606), serving=2026102606, held=True)
    drv = _setup(tmp_path, monkeypatch, named, staged=2026102605)

    drv.swap_and_reload()

    assert _soa_serial(tmp_path / "rendered" / "zones" / f"{ZONE}.db") == 2026102606
    assert named.serving == 2026102606


def test_a_signed_zone_is_reported_once_the_signer_has_caught_up(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live, the wire still answered the old signed serial straight after
    the update (target 01, read 00, 01 a moment later)."""
    named = _FakeNamed(2026102600, signed=2026102600)
    named.sign_lag = 3
    monkeypatch.setattr(dns.query, "tcp", named)
    monkeypatch.setattr(bind9.shutil, "which", lambda n: f"/usr/sbin/{n}")
    monkeypatch.setattr(subprocess, "run", named.zonestatus)
    monkeypatch.setattr(bind9.time, "sleep", lambda _s: None)

    driver.apply_record_op(_op(2026102601))

    assert named.wire_serial == 2026102601
    assert driver.reached_serial(ORIGIN) == 2026102601


def test_a_signer_that_never_catches_up_is_unread(
    driver: Bind9Driver, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _FakeNamed(2026102600, signed=2026102600)
    named.sign_lag = 10**9
    monkeypatch.setattr(dns.query, "tcp", named)
    monkeypatch.setattr(bind9.shutil, "which", lambda n: f"/usr/sbin/{n}")
    monkeypatch.setattr(subprocess, "run", named.zonestatus)
    monkeypatch.setattr(bind9, "_SIGNED_SETTLE_TIMEOUT_S", 0.0)

    driver.apply_record_op(_op(2026102601))

    assert driver.reached_serial(ORIGIN) is SERIAL_UNREAD

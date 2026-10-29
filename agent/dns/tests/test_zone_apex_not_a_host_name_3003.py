"""#3003: a zone whose own name is not a host name gets an apex BIND loads.

Active Directory's ``_msdcs.<forest root>`` is a zone of its own, and a
``_domainkey.<domain>`` is often delegated to a mail provider: the zone API
accepts both names, since an underscore label is legal in a zone's name. A zone
that names no name server got the placeholder SOA MNAME and NS ``ns1.<zone>``,
its glue ``ns1 A 127.0.0.1`` and, with no Admin Email, the SOA RNAME
``admin.<zone>``. Every one of those names carries the zone's underscore label,
and BIND's default check-names for a primary zone refuses an MNAME, an NS target
or an A owner that is not a host name, and an RNAME whose domain part is not.
named-checkzone refused the file (``bad name (check-names)``), the agent held
the zone back, and it was never served, while the API had answered 201.

For such a zone the placeholder lives outside it: ``invalid.``, the name RFC 6761
reserves never to resolve, which the catalog zone's apex already uses. A Primary
NS, NS records at the apex and an Admin Email the zone does give are served as
before, and a zone whose name is a host name renders the same bytes as before.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.update
import pytest
import structlog

from spatium_dns_agent.drivers import bind9
from spatium_dns_agent.drivers.bind9 import Bind9Driver, _zone_apex
from tests.test_zone_apex_render import (
    LOOPBACK,
    _addresses,
    _ns,
    _rec,
    _served,
    _soa,
    _write,
    _zone,
)

MSDCS = "_msdcs.corp.example.test."
NOT_HOST_NAMES = [MSDCS, "_domainkey.corp.example.test.", "_lab.a6us-2933.test."]

# ── What BIND's check-names refuses in a primary zone, without BIND ─────────
#
# The rule as the control plane measured it against named-checkzone 9.20 with
# the agent's own flags (backend app/core/dns_names.py, #1378, #2916): the SOA
# MNAME and an NS target must be host names, the SOA RNAME a mailbox (a first
# label of anything, host-name labels after it), and an A or AAAA owner a host
# name, Active Directory's ``gc._msdcs.<host>`` excepted.

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _host_name(name: str) -> bool:
    body = name.rstrip(".")
    return not body or all(_HOST_LABEL.match(label) for label in body.split("."))


def _mailbox(name: str) -> bool:
    body = name.rstrip(".")
    return "." not in body or _host_name(body.split(".", 1)[1])


def _check_names_problems(text: str, origin: str) -> list[str]:
    served = _served(text, origin)
    mname, rname, _serial = _soa(served)
    problems = []
    if not _host_name(mname):
        problems.append(f"SOA MNAME {mname}")
    if not _mailbox(rname):
        problems.append(f"SOA RNAME {rname}")
    problems += [f"NS {target}" for target in sorted(_ns(served)) if not _host_name(target)]
    for name, _ttl, rd in served.iterate_rdatas():
        owner = name.to_text()
        if rd.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA) and not _host_name(owner):
            labels = owner.lower().split(".")
            if labels[:2] != ["gc", "_msdcs"]:
                problems.append(f"{dns.rdatatype.to_text(rd.rdtype)} owner {owner}")
    return problems


def test_the_check_names_reading_refuses_what_the_agent_wrote_before() -> None:
    """The file named-checkzone refused on the QA rig (the issue's line 2), as
    nightly-2026.10.28's agent wrote it: the reading must not be vacuous."""
    before = (
        "$TTL 3600\n"
        "@ IN SOA ns1._lab.a6us-2933.test. admin._lab.a6us-2933.test. "
        "( 1 3600 600 86400 300 )\n"
        "@ IN NS ns1._lab.a6us-2933.test.\n"
        "ns1 IN A 127.0.0.1"
    )
    assert _check_names_problems(before, "_lab.a6us-2933.test.") == [
        "SOA MNAME ns1._lab.a6us-2933.test.",
        "SOA RNAME admin._lab.a6us-2933.test.",
        "NS ns1._lab.a6us-2933.test.",
        "A owner ns1._lab.a6us-2933.test.",
    ]


# ── A zone that names nothing: the placeholder is outside it ────────────────


@pytest.mark.parametrize("name", NOT_HOST_NAMES)
def test_a_zone_named_with_an_underscore_label_and_nothing_else_loads(
    tmp_path: Path, name: str
) -> None:
    text, notes = _write(tmp_path, _zone(name))
    assert text.splitlines()[:3] == [
        "$TTL 3600",
        "@ IN SOA invalid. invalid. ( 2026092401 3600 600 86400 300 )",
        "@ IN NS invalid.",
    ]
    assert LOOPBACK not in text
    assert _check_names_problems(text, name) == []
    assert notes == (("placeholder_outside", "invalid."),)


@pytest.mark.parametrize("origin", ["corp.example.test.", "lan."])
def test_a_host_name_zone_keeps_the_placeholder_inside_it(tmp_path: Path, origin: str) -> None:
    """The control: the parent of the zone above is untouched, and so is a
    one-label zone (``ns1.lan.`` is a host name)."""
    text, notes = _write(tmp_path, _zone(origin))
    assert text.splitlines()[1:4] == [
        f"@ IN SOA ns1.{origin} admin.{origin} ( 2026092401 3600 600 86400 300 )",
        f"@ IN NS ns1.{origin}",
        "ns1 IN A 127.0.0.1",
    ]
    assert [k for k, _ in notes] == ["placeholder"]


# ── What the zone does give wins, as for any zone ───────────────────────────


def test_a_primary_ns_outside_it_alone_is_served_and_the_mailbox_falls_back(
    tmp_path: Path,
) -> None:
    """The issue's open question: a Primary NS alone did not serve the zone,
    because ``admin.<zone>`` holds the label too."""
    zone = _zone(MSDCS, primary_ns="dc1.corp.example.test")
    text, notes = _write(tmp_path, zone)
    served = _served(text, MSDCS)
    assert _soa(served)[:2] == ("dc1.corp.example.test.", "invalid.")
    assert _ns(served) == {"dc1.corp.example.test."}
    assert LOOPBACK not in text
    assert _check_names_problems(text, MSDCS) == []
    assert notes == ()


def test_an_admin_email_alone_keeps_the_name_server_outside(tmp_path: Path) -> None:
    zone = _zone(MSDCS, admin_email="hostmaster.corp.example.test.")
    text, notes = _write(tmp_path, zone)
    served = _served(text, MSDCS)
    assert _soa(served)[:2] == ("invalid.", "hostmaster.corp.example.test.")
    assert _ns(served) == {"invalid."}
    assert _check_names_problems(text, MSDCS) == []
    assert notes == (("placeholder_outside", "invalid."),)


def test_an_ad_msdcs_zone_with_its_own_ns_records_is_served_as_declared(
    tmp_path: Path,
) -> None:
    """The shape a forest's ``_msdcs`` zone really has: NS records naming its
    domain controllers, and ``gc._msdcs`` A records, which check-names lets
    through. No Admin Email: the mailbox falls back outside the zone."""
    zone = _zone(
        MSDCS,
        [
            _rec("@", "NS", "dc1.corp.example.test."),
            _rec("@", "NS", "dc2.corp.example.test."),
            _rec("gc", "A", "10.0.0.5"),
        ],
    )
    text, notes = _write(tmp_path, zone)
    served = _served(text, MSDCS)
    assert _ns(served) == {"dc1.corp.example.test.", "dc2.corp.example.test."}
    assert _soa(served)[:2] == ("dc1.corp.example.test.", "invalid.")
    assert _addresses(served, f"gc.{MSDCS}") == {"10.0.0.5"}
    assert _check_names_problems(text, MSDCS) == []
    assert notes == ()


def test_both_fields_given_render_as_for_any_zone(tmp_path: Path) -> None:
    zone = _zone(
        MSDCS,
        primary_ns="dc1.corp.example.test.",
        admin_email="hostmaster.corp.example.test.",
    )
    text, notes = _write(tmp_path, zone)
    assert text.splitlines()[1:3] == [
        (
            "@ IN SOA dc1.corp.example.test. hostmaster.corp.example.test. "
            "( 2026092401 3600 600 86400 300 )"
        ),
        "@ IN NS dc1.corp.example.test.",
    ]
    assert notes == ()


def test_a_stored_primary_ns_inside_it_is_healed_to_the_outside_placeholder() -> None:
    """Only a row stored before #2075 can hold one (the API refuses a Primary
    NS that is not a host name); it is ignored, noted, and the zone loads."""
    zone = _zone(MSDCS, primary_ns="ns1._msdcs.corp.example.test.")
    apex = _zone_apex(zone)
    assert (apex.soa_mname, apex.soa_rname, apex.ns) == ("invalid.", "invalid.", ("invalid.",))
    assert not apex.placeholder_glue
    assert ("unusable_field", "primary_ns='ns1._msdcs.corp.example.test.'") in apex.notes
    assert ("placeholder_outside", "invalid.") in apex.notes


# ── The fallback is loud, and is not the glue the ingest worker skips ───────


def test_render_warns_for_the_outside_placeholder_and_lists_no_glue(
    tmp_path: Path,
) -> None:
    bundle = {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "zones": [
            _zone("corp.example.test."),
            _zone(MSDCS),
            _zone("_domainkey.corp.example.test.", primary_ns="mx.corp.example.test."),
        ],
    }
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        Bind9Driver(state_dir=tmp_path).render(bundle)
    finally:
        structlog.reset_defaults()

    events = {e["event"]: e for e in cap.entries if e["event"].startswith("bind9_zone_apex")}
    assert events["bind9_zone_apex_ns_is_loopback"]["sample"] == ["corp.example.test"]
    outside = events["bind9_zone_apex_ns_never_resolves"]
    assert outside["log_level"] == "warning"
    assert (outside["count"], outside["sample"]) == (1, ["_msdcs.corp.example.test"])
    glue = json.loads((tmp_path / "rendered.new" / bind9.PLACEHOLDER_GLUE_FILE).read_text())
    assert glue == ["corp.example.test"]


# ── The RFC 2136 path leaves named with the apex the render writes ──────────


class _Named:
    """``dns.query.tcp`` for one zone: answers its apex NS and SOA, keeps the
    updates, and answers each NOERROR."""

    def __init__(self, origin: str, ns: list[str], mname: str, rname: str) -> None:
        self.origin, self.ns, self.mname, self.rname = origin, ns, mname, rname
        self.serial = 2026102900
        self.updates: list[dns.update.UpdateMessage] = []

    def __call__(self, q: Any, where: str, timeout: float | None = None, **kw: Any) -> Any:
        assert where == "127.0.0.1"
        resp = dns.message.make_response(q)
        if isinstance(q, dns.update.UpdateMessage):
            self.updates.append(q)
            return resp
        resp.flags |= dns.flags.AA
        if q.question[0].rdtype == dns.rdatatype.NS:
            resp.answer.append(dns.rrset.from_text(self.origin, 3600, "IN", "NS", *self.ns))
        else:
            soa = f"{self.mname} {self.rname} {self.serial} 3600 600 86400 300"
            resp.answer.append(dns.rrset.from_text(self.origin, 3600, "IN", "SOA", soa))
        return resp


def _changes(upd: dns.update.UpdateMessage) -> list[tuple[str, str, str, str]]:
    """``(add | delete, owner, type, rdata)`` for every change in an update."""
    origin = dns.name.from_text(MSDCS)
    out = []
    for rrset in upd.update:
        kind = "add" if rrset.deleting is None else "delete"
        owner = rrset.name.derelativize(origin).to_text()
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        out += [(kind, owner, rtype, rd.to_text()) for rd in rrset] or [(kind, owner, rtype, "")]
    return out


def test_deleting_the_last_ns_record_falls_back_outside_with_no_glue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bind9.shutil, "which", lambda _n: None)
    named = _Named(MSDCS, ["dc1.corp.example.test."], "dc1.corp.example.test.", "invalid.")
    monkeypatch.setattr(dns.query, "tcp", named)
    drv = Bind9Driver(tmp_path)
    zone = {"name": MSDCS, "records": [{"name": "@", "type": "NS", "value": "dc1.corp.example.test."}]}
    drv._apex_lines = []
    drv._remember_apex(zone)
    drv._apex_blob = ("\n" + "\n".join(drv._apex_lines) + "\n").encode()

    drv.apply_record_op(
        {
            "op_id": "ns-gone",
            "op": "delete",
            "zone_name": MSDCS,
            "target_serial": 2026102901,
            "record": {
                "name": "@",
                "type": "NS",
                "value": "dc1.corp.example.test.",
                "ttl": 3600,
                "rrset": {"ttl": 3600, "members": []},
            },
        }
    )
    (upd,) = named.updates
    changes = _changes(upd)
    assert ("add", MSDCS, "NS", "invalid.") in changes
    assert ("delete", MSDCS, "NS", "dc1.corp.example.test.") in changes
    assert not [c for c in changes if c[2] in ("A", "AAAA")]
    (soa,) = [c for c in changes if c[2] == "SOA"]
    assert soa[3].split()[:3] == ["invalid.", "invalid.", "2026102901"]

"""The apex of a BIND9 zone file comes from the zone, not a placeholder (#1153).

Every zone file used to open with the same three lines whatever the zone held:
``SOA ns1.<zone> admin.<zone>``, ``NS ns1.<zone>`` and the glue
``ns1 A 127.0.0.1``. The zone's ``primary_ns`` and ``admin_email`` never
reached the agent, and a zone's own NS records were served beside the
placeholder, so every zone advertised a name server at loopback.

Now the NS set is the zone's own NS records, else its ``primary_ns`` (when it
can resolve), else — the last resort, logged — the placeholder. The SOA MNAME
and RNAME come from ``primary_ns`` / ``admin_email``. A zone that names nothing
renders exactly the bytes it did before.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import dns.rdataclass
import dns.rdatatype
import dns.zone
import pytest
import structlog

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _zone_apex

LOOPBACK = "127.0.0.1"


def _rec(name: str, rtype: str, value: str, ttl: int | None = 3600) -> dict[str, Any]:
    return {
        "name": name,
        "type": rtype,
        "ttl": ttl,
        "value": value,
        "priority": None,
        "weight": None,
        "port": None,
    }


def _zone(
    name: str, records: list[dict[str, Any]] | None = None, **extra: Any
) -> dict[str, Any]:
    zone: dict[str, Any] = {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 2026092401,
        "forwarders": [],
        "forward_only": True,
        "view_name": None,
        "records": records or [],
    }
    zone.update(extra)
    return zone


def _write(
    tmp_path: Path, zone: dict[str, Any]
) -> tuple[str, tuple[tuple[str, str], ...]]:
    path = tmp_path / "zones" / f"{zone['name'].rstrip('.')}.db"
    notes = Bind9Driver(state_dir=tmp_path)._write_zone_file(path, zone)
    return path.read_text(), notes


def _served(text: str, origin: str) -> dns.zone.Zone:
    return dns.zone.from_text(text, origin=origin, relativize=False, check_origin=True)


def _soa(z: dns.zone.Zone) -> tuple[str, str, int]:
    (soa,) = z.find_rdataset(z.origin, dns.rdatatype.SOA)
    return soa.mname.to_text(), soa.rname.to_text(), soa.serial


def _ns(z: dns.zone.Zone) -> set[str]:
    return {r.target.to_text() for r in z.find_rdataset(z.origin, dns.rdatatype.NS)}


def _addresses(z: dns.zone.Zone, name: str) -> set[str]:
    node = z.get_node(name)
    if node is None:
        return set()
    out: set[str] = set()
    for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        rds = node.get_rdataset(dns.rdataclass.IN, rdtype)
        if rds is not None:
            out |= {r.address for r in rds}
    return out


def _all_values(z: dns.zone.Zone) -> set[str]:
    return {rd.to_text() for _, _, rd in z.iterate_rdatas()}


# ── A zone that names no name server renders what it always did ─────────────


@pytest.mark.parametrize("name", ["corp.example.test.", "23.77.10.in-addr.arpa."])
def test_a_zone_that_names_no_name_server_renders_the_same_bytes(
    tmp_path: Path, name: str
) -> None:
    """No primary_ns, no admin_email, no NS records: the placeholder apex is
    still the only apex BIND will load, so the bytes are unchanged — which
    also means an upgrade does not reload these zones."""
    text, notes = _write(tmp_path, _zone(name, [_rec("www", "A", "10.0.0.1")]))
    assert text.splitlines()[:4] == [
        "$TTL 3600",
        f"@ IN SOA ns1.{name} admin.{name} ( 2026092401 3600 600 86400 300 )",
        f"@ IN NS ns1.{name}",
        "ns1 IN A 127.0.0.1",
    ]
    assert [k for k, _ in notes] == ["placeholder"]


def test_a_new_agent_against_an_older_control_plane_renders_as_before(
    tmp_path: Path,
) -> None:
    """A bundle from a control plane that predates #1153 has no primary_ns /
    admin_email keys at all; that reads as unset."""
    zone = _zone("corp.example.test.")
    assert "primary_ns" not in zone and "admin_email" not in zone
    text, _ = _write(tmp_path, zone)
    assert "@ IN NS ns1.corp.example.test." in text.splitlines()


# ── primary_ns / admin_email reach the wire ─────────────────────────────────


def test_primary_ns_outside_the_zone_is_its_ns_and_soa_primary_with_no_glue(
    tmp_path: Path,
) -> None:
    """The issue's own case: a zone whose Primary NS lives elsewhere. Both
    fields are stored without the trailing dot (as the importers and the
    ddi-pg baseline store them) and must still be read as absolute."""
    zone = _zone(
        "lab.example.test.",
        [_rec("probe", "A", "10.10.50.10")],
        primary_ns="ns1.corp.example.test",
        admin_email="hostmaster.corp.example.test",
    )
    text, notes = _write(tmp_path, zone)
    served = _served(text, "lab.example.test.")

    assert _soa(served) == (
        "ns1.corp.example.test.",
        "hostmaster.corp.example.test.",
        2026092401,
    )
    assert _ns(served) == {"ns1.corp.example.test."}
    assert LOOPBACK not in _all_values(served)
    assert notes == ()


def test_primary_ns_inside_the_zone_is_served_at_the_zones_own_address(
    tmp_path: Path,
) -> None:
    """``ns1 A 10.10.50.10`` used to be served beside the invented
    ``ns1 A 127.0.0.1`` — one RRset, two addresses, one of them loopback."""
    zone = _zone(
        "corp.example.test.",
        [_rec("ns1", "A", "10.10.50.10")],
        primary_ns="ns1.corp.example.test.",
    )
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _ns(served) == {"ns1.corp.example.test."}
    assert _addresses(served, "ns1.corp.example.test.") == {"10.10.50.10"}
    assert notes == ()


def test_primary_ns_inside_the_zone_with_no_address_falls_back_loudly(
    tmp_path: Path,
) -> None:
    """BIND will not load a zone whose NS is inside it with no address, and
    the agent does not invent one for the operator's name. The zone keeps
    loading on the placeholder, the SOA still names the operator's primary,
    and the fallback is reported."""
    zone = _zone("corp.example.test.", primary_ns="dns.corp.example.test")
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _soa(served)[0] == "dns.corp.example.test."
    assert _ns(served) == {"ns1.corp.example.test."}
    assert _addresses(served, "ns1.corp.example.test.") == {LOOPBACK}
    assert _addresses(served, "dns.corp.example.test.") == set()
    assert sorted(k for k, _ in notes) == ["placeholder", "unaddressed_primary_ns"]


# ── The zone's own NS records are its NS set ────────────────────────────────


def test_the_zones_own_ns_records_are_its_whole_ns_set(tmp_path: Path) -> None:
    """What the delegation wizard copies into the parent is what the zone
    serves: no placeholder beside it, and the SOA primary is the first."""
    zone = _zone(
        "corp.example.test.",
        [
            _rec("@", "NS", "a.ns.example.net."),
            _rec("@", "NS", "b.ns.example.net."),
            _rec("www", "A", "10.0.0.1"),
        ],
    )
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _ns(served) == {"a.ns.example.net.", "b.ns.example.net."}
    assert _soa(served)[:2] == ("a.ns.example.net.", "admin.corp.example.test.")
    assert LOOPBACK not in _all_values(served)
    assert notes == ()


def test_primary_ns_is_the_soa_primary_but_is_not_added_beside_declared_ns(
    tmp_path: Path,
) -> None:
    """A hidden primary: the SOA names it, the NS set does not. Adding it to
    the NS set would send resolvers to a server that is not meant to answer."""
    zone = _zone(
        "corp.example.test.",
        [_rec("@", "NS", "a.ns.example.net.")],
        primary_ns="hidden.example.net.",
    )
    text, _ = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _soa(served)[0] == "hidden.example.net."
    assert _ns(served) == {"a.ns.example.net."}


def test_relative_ns_records_are_read_the_way_bind_reads_them(tmp_path: Path) -> None:
    zone = _zone(
        "corp.example.test.",
        [_rec("@", "NS", "ns2"), _rec("ns2", "A", "10.0.0.2")],
    )
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _ns(served) == {"ns2.corp.example.test."}
    assert _addresses(served, "ns2.corp.example.test.") == {"10.0.0.2"}
    assert notes == ()


def test_a_declared_ns1_with_no_address_keeps_its_glue(tmp_path: Path) -> None:
    """An operator NS record naming ``ns1.<zone>`` with no address loaded
    before only because of the placeholder glue. It must keep loading."""
    zone = _zone("corp.example.test.", [_rec("@", "NS", "ns1.corp.example.test.")])
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _ns(served) == {"ns1.corp.example.test."}
    assert _addresses(served, "ns1.corp.example.test.") == {LOOPBACK}
    assert [k for k, _ in notes] == ["placeholder"]


def test_a_declared_ns_inside_the_zone_with_no_address_is_reported(
    tmp_path: Path,
) -> None:
    """Not repaired — the record is the operator's — but named, because BIND
    refuses the whole zone for it."""
    zone = _zone("corp.example.test.", [_rec("@", "NS", "ns2.corp.example.test.")])
    _, notes = _write(tmp_path, zone)
    assert notes == (("unaddressed_ns", "ns2.corp.example.test."),)


# ── The placeholder glue is never served beside a real address ──────────────


def test_a_zone_holding_its_own_ns1_address_serves_only_that_address(
    tmp_path: Path,
) -> None:
    """Nothing configured, but the zone holds ``ns1 A 192.0.2.53``: the
    placeholder name resolves to the operator's address, alone."""
    zone = _zone("corp.example.test.", [_rec("ns1", "A", "192.0.2.53")])
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _ns(served) == {"ns1.corp.example.test."}
    assert _addresses(served, "ns1.corp.example.test.") == {"192.0.2.53"}
    assert notes == ()


# ── Unusable stored values are ignored, never written ───────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "ns1 .example.com",
        "ns1.example.com.\n@ IN A 10.6.6.6",
        "bad;name.example.com",
        "ns1..example.com",
        "nś1.example.com",
    ],
)
def test_an_unusable_primary_ns_is_ignored(tmp_path: Path, bad: str) -> None:
    zone = _zone("corp.example.test.", primary_ns=bad, admin_email=bad)
    text, notes = _write(tmp_path, zone)
    served = _served(text, "corp.example.test.")

    assert _soa(served)[:2] == ("ns1.corp.example.test.", "admin.corp.example.test.")
    assert "10.6.6.6" not in text
    assert [k for k, _ in notes].count("unusable_field") == 2


# ── Whatever the zone holds, BIND can load what is rendered ─────────────────

_LOADABLE = {
    "unconfigured": _zone("corp.example.test."),
    "unconfigured-reverse": _zone("23.77.10.in-addr.arpa."),
    "primary-ns-elsewhere": _zone(
        "lab.example.test.", primary_ns="ns1.corp.example.test"
    ),
    "primary-ns-inside-addressed": _zone(
        "corp.example.test.",
        [_rec("ns1", "A", "10.10.50.10")],
        primary_ns="ns1.corp.example.test",
    ),
    "primary-ns-inside-unaddressed": _zone(
        "corp.example.test.", primary_ns="dns.corp.example.test"
    ),
    "primary-ns-is-the-apex": _zone("ts.example.test.", primary_ns="ts.example.test."),
    "declared-ns": _zone("corp.example.test.", [_rec("@", "NS", "a.ns.example.net.")]),
    "declared-ns1-unaddressed": _zone(
        "corp.example.test.", [_rec("@", "NS", "ns1.corp.example.test.")]
    ),
    "ns1-addressed-v6": _zone(
        "corp.example.test.", [_rec("ns1", "AAAA", "2001:db8::53")]
    ),
}


def _loadable_problems(text: str, origin: str) -> list[str]:
    """What BIND's load-time apex checks would refuse (lib/dns/zone.c:
    ``zone_get_from_db`` → "has no NS records", and ``zone_count_ns_rr`` →
    ``zone_check_ns`` → "NS '…' has no address records (A or AAAA)" for an
    NS inside the zone — both fatal for a primary, ``check-integrity no``
    or not)."""
    served = _served(text, origin)
    ns = _ns(served)
    problems = [] if ns else ["no NS records at the apex"]
    for target in ns:
        inside = target == origin or target.endswith("." + origin)
        if inside and not _addresses(served, target):
            problems.append(f"NS {target} has no address records")
    return problems


@pytest.mark.parametrize("case", sorted(_LOADABLE))
def test_every_rendered_apex_passes_binds_load_checks(
    tmp_path: Path, case: str
) -> None:
    zone = _LOADABLE[case]
    text, _ = _write(tmp_path, zone)
    assert _loadable_problems(text, zone["name"]) == []


@pytest.mark.skipif(
    shutil.which("named-checkzone") is None, reason="needs BIND's named-checkzone"
)
@pytest.mark.parametrize("case", sorted(_LOADABLE))
def test_named_checkzone_loads_every_rendered_apex(tmp_path: Path, case: str) -> None:
    zone = _LOADABLE[case]
    _write(tmp_path, zone)
    path = tmp_path / "zones" / f"{zone['name'].rstrip('.')}.db"
    res = subprocess.run(
        ["named-checkzone", zone["name"], str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr


# ── The fallback is loud, once per render ───────────────────────────────────


def test_render_warns_once_for_every_zone_left_on_the_placeholder(
    tmp_path: Path,
) -> None:
    bundle = {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "zones": [
            _zone("a.example.test."),
            _zone("23.77.10.in-addr.arpa."),
            _zone("lab.example.test.", primary_ns="ns1.corp.example.test"),
        ],
    }
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        Bind9Driver(state_dir=tmp_path).render(bundle)
    finally:
        structlog.reset_defaults()

    warned = [e for e in cap.entries if e["event"] == "bind9_zone_apex_ns_is_loopback"]
    assert len(warned) == 1
    assert warned[0]["log_level"] == "warning"
    assert warned[0]["count"] == 2
    assert warned[0]["sample"] == ["23.77.10.in-addr.arpa", "a.example.test"]
    lab = (tmp_path / "rendered.new" / "zones" / "lab.example.test.db").read_text()
    assert "@ IN NS ns1.corp.example.test." in lab.splitlines()


def test_under_views_each_copy_gets_the_apex_and_the_zone_is_counted_once(
    tmp_path: Path,
) -> None:
    bundle = {
        "options": {"recursion_enabled": True, "allow_query": ["any"]},
        "views": [
            {"name": "internal", "match_clients": ["10.0.0.0/8"], "recursion": True},
            {"name": "external", "match_clients": ["any"], "recursion": False},
        ],
        "zones": [
            {**_zone("corp.example.test."), "view_name": "internal"},
            {**_zone("corp.example.test."), "view_name": "external"},
            {
                **_zone("lab.example.test.", primary_ns="ns1.corp.example.test"),
                "view_name": "internal",
            },
        ],
    }
    cap = structlog.testing.LogCapture()
    structlog.configure(processors=[cap])
    try:
        Bind9Driver(state_dir=tmp_path).render(bundle)
    finally:
        structlog.reset_defaults()

    (warned,) = [
        e for e in cap.entries if e["event"] == "bind9_zone_apex_ns_is_loopback"
    ]
    assert warned["count"] == 1
    lab = (
        tmp_path / "rendered.new" / "zones" / "internal" / "lab.example.test.db"
    ).read_text()
    assert "@ IN NS ns1.corp.example.test." in lab.splitlines()


def test_the_apex_is_a_pure_function_of_the_zone() -> None:
    """Same zone, same apex — the renderer's byte comparison between renders
    (``_changed_zones``) is what keeps an unchanged zone from reloading."""
    zone = _zone("corp.example.test.", [_rec("@", "NS", "a.ns.example.net.")])
    assert _zone_apex(zone) == _zone_apex(dict(zone))

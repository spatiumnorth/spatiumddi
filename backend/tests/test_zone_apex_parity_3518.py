"""The control plane's served-apex rule equals the BIND9 agent's (#3518).

``app.services.dns.zone_apex.compute_served_apex`` is a copy of the agent's
``_zone_apex`` (the agent image cannot import ``app``). The records list shows
what the helper computes, so the day the two differ the list says one thing and
BIND serves another. Both get the same zones here.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from app.services.dns.zone_apex import compute_served_apex

_AGENT_ROOT = Path(__file__).parents[2] / "agent/dns"

pytestmark = pytest.mark.skipif(
    not (_AGENT_ROOT / "spatium_dns_agent").exists(), reason="agent package not in this checkout"
)

R = tuple[str, str, str]

# (id, zone name, primary_ns, admin_email, records)
ZONES: list[tuple[str, str, Any, Any, list[R]]] = [
    ("bare", "example.com.", "", "", []),
    ("nulls", "example.com.", None, None, []),
    ("primary-outside", "example.com.", "ns.provider.net.", "", []),
    ("primary-outside-no-dot", "example.com", "ns.provider.net", "hostmaster.example.com", []),
    ("primary-inside-unaddressed", "example.com.", "ns9.example.com.", "", []),
    (
        "primary-inside-addressed",
        "example.com.",
        "ns9.example.com.",
        "",
        [("ns9", "A", "10.0.0.9")],
    ),
    (
        "primary-inside-aaaa",
        "example.com.",
        "NS9.example.com",
        "",
        [("ns9", "AAAA", "2001:db8::9")],
    ),
    ("primary-is-apex", "example.com.", "example.com.", "", [("@", "A", "10.0.0.1")]),
    (
        "declared-relative",
        "example.com.",
        "",
        "",
        [("@", "NS", "ns2"), ("", "NS", "ns3.example.com."), ("ns2", "A", "10.0.0.2")],
    ),
    (
        "declared-beats-primary",
        "example.com.",
        "ns.provider.net.",
        "dns-admin.example.com.",
        [("@", "NS", "ns-a.other.net.")],
    ),
    ("subdomain-ns-is-not-apex", "example.com.", "", "", [("sub", "NS", "ns.sub.example.com.")]),
    ("ns1-addressed", "example.com.", "", "", [("ns1", "A", "10.1.1.1")]),
    ("ns1-addressed-aaaa-fqdn", "example.com.", "", "", [("ns1.example.com.", "AAAA", "::1")]),
    ("msdcs", "_msdcs.example.com.", "", "", []),
    ("msdcs-declared", "_msdcs.example.com.", "", "", [("@", "NS", "dc1.example.com.")]),
    ("domainkey-primary-outside", "_domainkey.example.com.", "ns.provider.net.", "", []),
    ("reverse", "2.0.192.in-addr.arpa.", "", "", []),
    ("reverse-primary-inside", "2.0.192.in-addr.arpa.", "ns.2.0.192.in-addr.arpa.", "", []),
    ("one-label-zone", "lan.", "", "", []),
    ("primary-single-label", "example.com.", "ns1", "", []),
    ("primary-underscore", "example.com.", "ns_1.example.com.", "", []),
    ("primary-unsafe", "example.com.", "ns1.exa;mple.com.", "", []),
    ("primary-long-label", "example.com.", ("a" * 64) + ".example.net.", "", []),
    ("admin-with-at", "example.com.", "", "admin@example.com", []),
    ("admin-single-label", "example.com.", "", "hostmaster", []),
    ("admin-underscore-domain", "example.com.", "", "hostmaster.under_score.example.com.", []),
    ("admin-plus-local", "example.com.", "", "admin+dns.example.com.", []),
    ("admin-ok-msdcs", "_msdcs.example.com.", "", "hostmaster.example.com.", []),
    ("mixed-case", "Example.COM.", "NS.Example.COM.", "", [("NS", "A", "10.0.0.1")]),
]


@pytest.fixture(scope="module")
def agent_zone_apex() -> Any:
    sys.path.insert(0, str(_AGENT_ROOT))
    try:
        from spatium_dns_agent.drivers import bind9
    finally:
        sys.path.remove(str(_AGENT_ROOT))
    return bind9._zone_apex


@pytest.mark.parametrize("case", ZONES, ids=[z[0] for z in ZONES])
def test_the_helper_matches_the_agent(case: Any, agent_zone_apex: Any) -> None:
    _, name, primary_ns, admin_email, records = case
    agent = agent_zone_apex(
        {
            "name": name,
            "primary_ns": primary_ns,
            "admin_email": admin_email,
            "records": [{"name": n, "type": t, "value": v} for n, t, v in records],
        }
    )
    served = compute_served_apex(name, primary_ns, admin_email, records)
    assert served.soa_mname == agent.soa_mname
    assert served.soa_rname == agent.soa_rname
    assert served.placeholder_glue == agent.placeholder_glue
    if served.source == "declared":
        # The agent writes nothing beside the zone's own NS records.
        assert agent.ns == ()
        assert served.ns, "a declared set is never empty"
    else:
        assert served.ns == agent.ns
        assert len(served.ns) == 1


def test_the_table_exercises_every_source() -> None:
    sources = {compute_served_apex(n, p, a, r).source for _, n, p, a, r in ZONES}
    assert sources == {"declared", "primary_ns", "placeholder"}
    glue = {compute_served_apex(n, p, a, r).placeholder_glue for _, n, p, a, r in ZONES}
    assert glue == {True, False}

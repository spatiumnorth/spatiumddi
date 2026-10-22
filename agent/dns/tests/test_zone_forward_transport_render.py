"""A forward zone's upstream transport is its own (#2121), asserted on the
rendered named.conf (the #899 lesson: assert on what BIND reads, not on the
stored row).

Before #2121 a forward zone inherited the group's ``forward_transport``, so a
group forwarding to Cloudflare over DoT sent a Tailscale tailnet zone's
queries to 100.100.100.100:853 over TLS, checked against
``cloudflare-dns.com``. Nothing answers there; every name SERVFAILed.

``FORWARDER_VECTORS`` is duplicated in
``backend/tests/test_zone_forward_transport.py`` against the control-plane
copy of ``_forwarders``; the two modules are byte-identical (a backend parity
test enforces it), so the vectors pin one behaviour across both renderers.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers._forwarders import (
    bind_zone_forwarder,
    zone_tls_statement_name,
)
from spatium_dns_agent.drivers.bind9 import Bind9Driver

TAILNET = "example-tailnet.ts.net."

DOT_GROUP: dict[str, Any] = {
    "forwarders": ["1.1.1.1", "1.0.0.1"],
    "forward_transport": "tls",
    "forward_tls_hostname": "cloudflare-dns.com",
    "forward_tls_verify": True,
}

# (entry, tls statement name or None, expected token)
FORWARDER_VECTORS = [
    ("100.100.100.100", None, "100.100.100.100"),
    ("100.100.100.100@53", None, "100.100.100.100 port 53"),
    ("10.0.0.1@5353", None, "10.0.0.1 port 5353"),
    ("9.9.9.9", "T", "9.9.9.9 port 853 tls T"),
    ("9.9.9.9@8853", "T", "9.9.9.9 port 8853 tls T"),
    # An explicit @53 never gets tls: TLS to port 53 answers nothing.
    ("100.100.100.100@53", "T", "100.100.100.100 port 53"),
    ("2620:fe::fe", "T", "2620:fe::fe port 853 tls T"),
]


@pytest.mark.parametrize("entry,tls_name,expected", FORWARDER_VECTORS)
def test_forwarder_vectors(entry: str, tls_name: str | None, expected: str) -> None:
    assert bind_zone_forwarder(entry, tls_name) == expected


def _bundle(zones: list[dict[str, Any]], options: dict[str, Any]) -> dict[str, Any]:
    return {
        "server": {"name": "s1", "driver": "bind9"},
        "options": options,
        "acls": [],
        "views": [],
        "zones": zones,
        "blocklists": [],
        "tsig_keys": [],
        "pending_ops": [],
    }


def _fwd_zone(name: str, forwarders: list[str], **extra: Any) -> dict[str, Any]:
    return {"name": name, "type": "forward", "forwarders": forwarders, **extra}


def _render(tmp_path: Path, bundle: dict[str, Any]) -> str:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def _zone_line(conf: str, name: str) -> str:
    return next(ln for ln in conf.splitlines() if ln.startswith(f'zone "{name}"'))


@pytest.mark.parametrize(
    "zone_extra",
    [
        # A bundle from a control plane older than #2121: no key at all.
        {},
        {"forward_transport": "do53", "forward_tls_hostname": None},
    ],
)
def test_do53_zone_in_a_dot_group_forwards_plain_dns(
    tmp_path: Path, zone_extra: dict[str, Any]
) -> None:
    conf = _render(
        tmp_path,
        _bundle([_fwd_zone(TAILNET, ["100.100.100.100"], **zone_extra)], DOT_GROUP),
    )
    line = _zone_line(conf, TAILNET)
    assert "forwarders { 100.100.100.100; };" in line
    assert "tls" not in line
    assert "853" not in line
    # The group's own forwarders still go over DoT.
    assert "1.1.1.1 port 853 tls spatium-upstream-tls" in conf
    # No zone tls statement for a plain zone.
    assert "spatium-zone-tls-" not in conf


def test_tls_zone_gets_its_own_statement_and_hostname(tmp_path: Path) -> None:
    zone = _fwd_zone(
        "corp.example.",
        ["9.9.9.9", "149.112.112.112"],
        forward_transport="tls",
        forward_tls_hostname="dns.quad9.net",
    )
    conf = _render(tmp_path, _bundle([zone], DOT_GROUP))
    name = zone_tls_statement_name("dns.quad9.net")
    assert f"tls {name} {{" in conf
    stmt = conf[conf.index(f"tls {name} {{") :]
    stmt = stmt[: stmt.index("};") + 2]
    assert 'remote-hostname "dns.quad9.net";' in stmt
    assert "cloudflare-dns.com" not in stmt
    assert 'ca-file "/etc/ssl/certs/ca-certificates.crt";' in stmt
    line = _zone_line(conf, "corp.example.")
    assert f"9.9.9.9 port 853 tls {name}" in line
    assert "spatium-upstream-tls" not in line
    # Declared before use: BIND resolves a tls name where it is written.
    assert conf.index(f"tls {name} {{") < conf.index('zone "corp.example."')
    assert conf.index(f"tls {name} {{") < conf.index("options {")


def test_explicit_port_53_in_a_tls_zone_never_gets_tls(tmp_path: Path) -> None:
    zone = _fwd_zone(
        TAILNET,
        ["100.100.100.100@53"],
        forward_transport="tls",
        forward_tls_hostname="dns.quad9.net",
    )
    conf = _render(tmp_path, _bundle([zone], DOT_GROUP))
    line = _zone_line(conf, TAILNET)
    assert "forwarders { 100.100.100.100 port 53; };" in line
    assert "tls" not in line
    # Nothing uses the statement, so none is emitted.
    assert "spatium-zone-tls-" not in conf


def test_tls_zone_in_a_do53_group(tmp_path: Path) -> None:
    zone = _fwd_zone(
        "corp.example.", ["9.9.9.9"], forward_transport="tls", forward_tls_hostname="dns.quad9.net"
    )
    conf = _render(tmp_path, _bundle([zone], {"forwarders": ["10.0.0.1"]}))
    name = zone_tls_statement_name("dns.quad9.net")
    assert f"tls {name} {{" in conf
    assert "spatium-upstream-tls" not in conf
    assert "forwarders { 10.0.0.1; };" in conf
    assert f"9.9.9.9 port 853 tls {name}" in _zone_line(conf, "corp.example.")


def test_zones_sharing_a_provider_share_one_statement(tmp_path: Path) -> None:
    zones = [
        _fwd_zone(n, ["9.9.9.9"], forward_transport="tls", forward_tls_hostname="dns.quad9.net")
        for n in ("a.example.", "b.example.")
    ]
    conf = _render(tmp_path, _bundle(zones, {}))
    assert conf.count(f"tls {zone_tls_statement_name('dns.quad9.net')} {{") == 1


def test_statement_name_is_a_safe_identifier() -> None:
    name = zone_tls_statement_name('Evil"; }; .Example.COM')
    assert all(c.isalnum() or c == "-" for c in name)
    assert name.startswith("spatium-zone-tls-")
    # Distinct hostnames that sanitise alike stay distinct.
    assert zone_tls_statement_name("a.b") != zone_tls_statement_name("a-b")


def test_hostnames_differing_only_in_case_share_one_statement(tmp_path: Path) -> None:
    """The statement name is built from the lower-cased host, so two zones
    naming one provider in different case rendered two clauses under ONE
    name, and named refused the duplicate clause: the whole file."""
    zones = [
        _fwd_zone("a.example.", ["9.9.9.9"], forward_transport="tls", forward_tls_hostname=h)
        for h in ("DNS.Quad9.net", "dns.quad9.net")
    ]
    zones[1]["name"] = "b.example."
    conf = _render(tmp_path, _bundle(zones, {}))
    name = zone_tls_statement_name("dns.quad9.net")
    assert conf.count(f"tls {name} {{") == 1
    assert 'remote-hostname "dns.quad9.net";' in conf


@pytest.mark.parametrize(
    "hostname",
    [
        "a" * 63 + ".example.net",
        "dns-over-tls.resolver.internal.corp.example.com",
        "xn--bcher-kva.example",
    ],
)
def test_statement_name_is_one_dns_label(hostname: str) -> None:
    """BIND parses a tls statement name as a domain name: a label over 63
    octets is "not a valid name" and named refuses the file."""
    name = zone_tls_statement_name(hostname)
    assert len(name) <= 63
    assert "." not in name
    assert not name.endswith("-")


@pytest.mark.parametrize(
    "extra",
    [
        # BIND has no client-side HTTP or QUIC transport (#741).
        {"forward_transport": "https", "forward_tls_hostname": "dns.quad9.net"},
        {"forward_transport": "quic", "forward_tls_hostname": "dns.quad9.net"},
        # TLS with no name to verify: never silently opportunistic.
        {"forward_transport": "tls", "forward_tls_hostname": None},
        {"forward_transport": "tls", "forward_tls_hostname": 'x"; };'},
    ],
)
def test_a_zone_bind_cannot_render_faithfully_is_skipped(
    tmp_path: Path, extra: dict[str, Any]
) -> None:
    conf = _render(tmp_path, _bundle([_fwd_zone("corp.example.", ["9.9.9.9"], **extra)], {}))
    assert 'zone "corp.example."' not in conf
    assert "spatium-zone-tls-" not in conf


_NAMED_CHECKCONF = shutil.which("named-checkconf")


@pytest.mark.skipif(_NAMED_CHECKCONF is None, reason="named-checkconf not installed")
def test_rendered_config_loads_in_named_checkconf(tmp_path: Path) -> None:
    zones = [
        _fwd_zone(TAILNET, ["100.100.100.100"]),
        _fwd_zone("lab.example.", ["10.0.0.1@53", "10.0.0.2@5353"]),
        _fwd_zone(
            "corp.example.",
            ["9.9.9.9", "149.112.112.112@853", "10.9.9.9@53"],
            forward_transport="tls",
            forward_tls_hostname="dns.quad9.net",
        ),
        # The same provider in another case: one statement, not a duplicate.
        _fwd_zone(
            "corp2.example.",
            ["9.9.9.9", "2620:fe::9@853", "2001:db8::53@53"],
            forward_transport="tls",
            forward_tls_hostname="DNS.Quad9.net",
        ),
        # A long certificate name: the statement name must stay one label.
        _fwd_zone(
            "long.example.",
            ["10.2.2.2"],
            forward_transport="tls",
            forward_tls_hostname="dns-over-tls.resolver.internal.corp.example.com",
        ),
        # No forwarders: skipped, never an empty forwarders block.
        _fwd_zone("empty.example.", [], forward_transport="tls", forward_tls_hostname="x.example"),
    ]
    conf = _render(tmp_path, _bundle(zones, DOT_GROUP))
    path = tmp_path / "check.conf"
    path.write_text(conf)
    res = subprocess.run([_NAMED_CHECKCONF, str(path)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stdout + res.stderr

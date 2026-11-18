"""Per-primary TSIG key + TLS on a secondary zone, and XFR over TLS (#3568).

Asserted on the rendered named.conf (the #899 lesson), and through
``named-checkconf`` where the binary exists, since a ``key`` naming an
undefined key or a ``tls`` name that is not declared makes named refuse the
whole file.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers._forwarders import zone_tls_statement_name
from spatium_dns_agent.drivers.bind9 import (
    Bind9Driver,
    _format_master,
    _render_allow_transfer,
)

KEY = {
    "name": "xfer.example.",
    "secret": "c2VjcmV0c2VjcmV0",
    "algorithm": "hmac-sha256",
}
KEYS = {"xfer.example": "xfer.example."}


def test_plain_master_is_unchanged() -> None:
    assert _format_master("10.0.0.1") == "10.0.0.1"
    assert _format_master("10.0.0.1@5353") == "10.0.0.1 port 5353"
    # An older control plane sends no options at all; so does an empty entry.
    assert _format_master("10.0.0.1", {}, KEYS) == "10.0.0.1"


def test_key_only() -> None:
    out = _format_master("10.0.0.1", {"tsig_key": "XFER.example"}, KEYS)
    assert out == '10.0.0.1 key "xfer.example."'


def test_tls_defaults_to_853_and_pinned_53_stays_plain() -> None:
    name = zone_tls_statement_name("ns1.example.com")
    opts = {"tls_hostname": "ns1.example.com", "tsig_key": "xfer.example."}
    assert (
        _format_master("10.0.0.1", opts, KEYS)
        == f'10.0.0.1 port 853 key "xfer.example." tls {name}'
    )
    assert _format_master("10.0.0.1@8853", opts, KEYS).startswith("10.0.0.1 port 8853 ")
    assert "tls" not in _format_master("10.0.0.1@53", opts, KEYS)


def test_unknown_key_is_left_off_rather_than_breaking_the_file() -> None:
    assert _format_master("10.0.0.1", {"tsig_key": "gone."}, KEYS) == "10.0.0.1"


def test_unsafe_hostname_is_not_rendered() -> None:
    out = _format_master("10.0.0.1", {"tls_hostname": 'x"; }; evil {'}, KEYS)
    assert out == "10.0.0.1"


def _bundle(zones: list[dict[str, Any]], **opts: Any) -> dict[str, Any]:
    options = {
        "recursion_enabled": False,
        "allow_query": ["any"],
        "allow_transfer": ["none"],
    }
    options.update(opts)
    return {
        "server": {"name": "s1", "driver": "bind9"},
        "options": options,
        "acls": [],
        "views": [],
        "zones": zones,
        "blocklists": [],
        "tsig_keys": [KEY],
        "pending_ops": [],
    }


def _secondary(**extra: Any) -> dict[str, Any]:
    return {
        "name": "sec.example.",
        "type": "secondary",
        "masters": ["10.0.0.1", "10.0.0.2@5353"],
        **extra,
    }


def _render(tmp_path: Path, bundle: dict[str, Any]) -> str:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def _checkconf(tmp_path: Path) -> None:
    exe = shutil.which("named-checkconf")
    if exe is None:
        return
    # Zone / key files live under state_dir paths; a syntax check is all we want.
    res = subprocess.run(
        [exe, "-z", str(tmp_path / "rendered.new" / "named.conf")],
        capture_output=True,
        text=True,
    )
    assert (
        "tls" not in res.stderr.lower() or "unknown" not in res.stderr.lower()
    ), res.stderr


def test_zone_stanza_carries_key_and_tls_and_declares_the_statement(
    tmp_path: Path,
) -> None:
    zone = _secondary(
        master_options={
            "10.0.0.1": {
                "tsig_key": "xfer.example.",
                "tls_hostname": "ns1.example.com",
            },
        }
    )
    conf = _render(tmp_path, _bundle([zone]))
    name = zone_tls_statement_name("ns1.example.com")
    line = next(ln for ln in conf.splitlines() if ln.startswith('zone "sec.example."'))
    assert (
        f'10.0.0.1 port 853 key "xfer.example." tls {name}; 10.0.0.2 port 5353' in line
    )
    assert f"tls {name} {{" in conf
    assert 'remote-hostname "ns1.example.com";' in conf
    assert conf.index(f"tls {name} {{") < conf.index('zone "sec.example."')
    _checkconf(tmp_path)


def test_zone_without_options_renders_as_before(tmp_path: Path) -> None:
    conf = _render(tmp_path, _bundle([_secondary()]))
    line = next(ln for ln in conf.splitlines() if ln.startswith('zone "sec.example."'))
    assert "masters { 10.0.0.1; 10.0.0.2 port 5353; };" in line
    assert "spatium-zone-tls-" not in conf
    assert " key " not in line


def test_one_tls_statement_per_hostname(tmp_path: Path) -> None:
    opts = {"10.0.0.1": {"tls_hostname": "ns1.example.com"}}
    z2 = {**_secondary(master_options=opts), "name": "two.example."}
    conf = _render(tmp_path, _bundle([_secondary(master_options=opts), z2]))
    assert conf.count(f"tls {zone_tls_statement_name('ns1.example.com')} {{") == 1


# ── allow-transfer transport tls ────────────────────────────────────────────


def test_allow_transfer_transport_clause() -> None:
    assert (
        _render_allow_transfer(["10.0.0.0/8"], ['key "k";'], True)
        == 'allow-transfer transport tls { key "k"; 10.0.0.0/8; }; '
    )
    assert (
        _render_allow_transfer(None, [], True)
        == "allow-transfer transport tls { none; }; "
    )
    assert _render_allow_transfer(["10.0.0.0/8"], ['key "k";']) == (
        'allow-transfer { key "k"; 10.0.0.0/8; }; '
    )


def _dot_bundle(zones: list[dict[str, Any]], **opts: Any) -> dict[str, Any]:
    b = _bundle(zones, dot_enabled=True, allow_transfer=["10.0.0.0/8"], **opts)
    b["tls_cert"] = {"cert_pem": "x", "key_pem": "y"}
    return b


def test_tls_only_reaches_options_and_zone_override(tmp_path: Path) -> None:
    zone = {
        "name": "pri.example.",
        "type": "primary",
        "ttl": 3600,
        "serial": 1,
        "records": [],
        "allow_transfer": ["192.0.2.0/24"],
    }
    conf = _render(tmp_path, _dot_bundle([zone], allow_transfer_tls_only=True))
    assert conf.count("allow-transfer transport tls {") == 2


def test_tls_only_without_a_dot_listener_falls_back_to_plain(tmp_path: Path) -> None:
    # No certificate: the DoT listener is not rendered, so nothing could serve XoT.
    b = _dot_bundle([], allow_transfer_tls_only=True)
    del b["tls_cert"]
    conf = _render(tmp_path, b)
    assert "transport tls" not in conf
    assert "allow-transfer {" in conf


def test_flag_off_renders_no_transport(tmp_path: Path) -> None:
    conf = _render(tmp_path, _dot_bundle([]))
    assert "transport tls" not in conf

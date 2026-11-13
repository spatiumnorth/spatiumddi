"""A view's own default forwarders render inside its ``view { }`` block (#3523).

BIND takes ``forwarders`` / ``forward`` in a view, overriding ``options {}`` for
the clients the view matches. A view that sets none keeps the group's, so a
group without per-view forwarders renders byte-identically to before.
"""

from __future__ import annotations

import re
from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver


def _view(name: str, **extra: object) -> dict:
    return {
        "name": name,
        "match_clients": ["any"],
        "match_destinations": [],
        "recursion": True,
        "order": 0,
        **extra,
    }


def _render(tmp_path: Path, views: list[dict], **opts: object) -> str:
    Bind9Driver(state_dir=tmp_path).render(
        {
            "server": {"name": "s1", "driver": "bind9"},
            "options": {"forwarders": ["9.9.9.9"], **opts},
            "acls": [],
            "views": views,
            "zones": [],
            "blocklists": [],
            "tsig_keys": [],
            "pending_ops": [],
        }
    )
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def _block(conf: str, name: str) -> str:
    return re.search(rf'view "{name}" \{{\n(.*?)\n\}};', conf, re.S).group(1)  # type: ignore[union-attr]


def test_view_forwarders_render_inside_the_view_and_others_keep_the_group(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        [
            _view("guest", forwarders=["1.1.1.3", "1.0.0.3@5353"], forward_policy="only"),
            _view("staff"),
        ],
    )
    guest = _block(conf, "guest")
    assert "    forwarders { 1.1.1.3; 1.0.0.3 port 5353; };" in guest
    assert "    forward only;" in guest
    assert "forwarders" not in _block(conf, "staff")
    # The group's own block is untouched.
    assert "forwarders { 9.9.9.9; };" in conf.split('view "guest"')[0]


def test_view_policy_inherits_the_groups_and_is_explicit(tmp_path: Path) -> None:
    conf = _render(
        tmp_path, [_view("guest", forwarders=["1.1.1.3"])], forward_policy="only"
    )
    assert "forward only;" in _block(conf, "guest")
    conf = _render(
        tmp_path,
        [_view("guest", forwarders=["1.1.1.3"], forward_policy="first")],
        forward_policy="only",
    )
    # The view asked for ``first`` while options says ``only``: written out.
    assert "forward first;" in _block(conf, "guest")


def test_view_forwarders_over_tls_get_their_own_tls_statement(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        [
            _view(
                "guest",
                forwarders=["1.1.1.3"],
                forward_transport="tls",
                forward_tls_hostname="family.cloudflare-dns.com",
            )
        ],
    )
    m = re.search(r"forwarders \{ 1\.1\.1\.3 port 853 tls (\S+); \};", _block(conf, "guest"))
    assert m
    tls_name = m.group(1)
    # Declared at the top level, above the view that names it.
    assert conf.index(f"tls {tls_name} {{") < conf.index('view "guest"')
    assert 'remote-hostname "family.cloudflare-dns.com";' in conf


def test_tls_without_a_hostname_is_skipped_not_downgraded(tmp_path: Path) -> None:
    conf = _render(
        tmp_path, [_view("guest", forwarders=["1.1.1.3"], forward_transport="tls")]
    )
    assert "forwarders" not in _block(conf, "guest")


def test_no_view_forwarders_renders_as_before(tmp_path: Path) -> None:
    conf = _render(tmp_path, [_view("guest", forwarders=[]), _view("staff")])
    assert "forwarders" not in _block(conf, "guest")
    assert "forward " not in conf

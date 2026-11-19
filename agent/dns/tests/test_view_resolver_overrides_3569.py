"""Per-view dnssec-validation / allow-recursion / rate-limit / minimal-responses (#3569).

BIND takes each inside a ``view { }`` block, overriding ``options {}`` for the
clients the view matches. A view that sets none keeps the group's, so a group
without per-view overrides renders byte-identically to before.
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
            "options": {"dnssec_validation": "auto", **opts},
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


def test_dnssec_and_allow_recursion_render_in_the_view_only(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        [
            _view(
                "internal",
                dnssec_validation="yes",
                allow_recursion=["10.0.0.0/8", "localhost"],
            ),
            _view("external", dnssec_validation="no", allow_recursion=["none"]),
            _view("plain"),
        ],
    )
    internal = _block(conf, "internal")
    assert "    dnssec-validation yes;" in internal
    assert "    allow-recursion { 10.0.0.0/8; localhost; };" in internal
    external = _block(conf, "external")
    assert "    dnssec-validation no;" in external
    assert "    allow-recursion { none; };" in external
    plain = _block(conf, "plain")
    assert "dnssec-validation" not in plain
    assert "allow-recursion" not in plain
    # The group's own options block is unchanged.
    assert "dnssec-validation auto;" in conf.split('view "internal"')[0]


def test_allow_recursion_is_skipped_on_a_view_with_recursion_off(tmp_path: Path) -> None:
    conf = _render(tmp_path, [_view("auth", recursion=False, allow_recursion=["any"])])
    assert "allow-recursion" not in _block(conf, "auth")


def test_malformed_allow_recursion_fails_closed(tmp_path: Path) -> None:
    conf = _render(tmp_path, [_view("v", allow_recursion=["not an acl!"])])
    assert "    allow-recursion { none; };" in _block(conf, "v")


def test_minimal_responses_is_tri_state(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        [
            _view("on", minimal_responses=True),
            _view("off", minimal_responses=False),
            _view("inherit"),
        ],
        minimal_responses=True,
    )
    assert "    minimal-responses yes;" in _block(conf, "on")
    assert "    minimal-responses no;" in _block(conf, "off")
    assert "minimal-responses" not in _block(conf, "inherit")


def test_rate_limit_override_inherits_the_groups_other_knobs(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        [_view("ext", rrl_responses_per_second=5, rrl_slip=0), _view("int")],
        rrl_enabled=True,
        rrl_responses_per_second=15,
        rrl_window=20,
        rrl_slip=2,
        rrl_exempt_clients=["10.0.0.0/8"],
    )
    ext = _block(conf, "ext")
    assert (
        "    rate-limit { responses-per-second 5; window 20; slip 0; "
        "exempt-clients { 10.0.0.0/8; }; };" in ext
    )
    assert "rate-limit" not in _block(conf, "int")


def test_view_can_enable_or_disable_rate_limit(tmp_path: Path) -> None:
    conf = _render(
        tmp_path,
        [_view("on", rrl_enabled=True), _view("off", rrl_enabled=False)],
    )
    # Group has it off: enabling is the view's own, disabling renders nothing.
    assert "rate-limit { responses-per-second 15; window 15; slip 2; };" in _block(conf, "on")
    assert "rate-limit" not in _block(conf, "off")
    conf = _render(
        tmp_path,
        [_view("off", rrl_enabled=False), _view("numbers_only", rrl_window=30)],
        rrl_enabled=True,
    )
    assert "    rate-limit { responses-per-second 0; };" in _block(conf, "off")
    assert "window 30;" in _block(conf, "numbers_only")


def test_numbers_alone_do_not_switch_rate_limit_on(tmp_path: Path) -> None:
    conf = _render(tmp_path, [_view("v", rrl_responses_per_second=5)])
    assert "rate-limit" not in _block(conf, "v")

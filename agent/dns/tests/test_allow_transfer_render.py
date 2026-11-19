"""#734 — BIND9 never rendered ``allow-transfer``, so nothing could read a zone.

Two independent defects met in the middle:

* The agent granted transfer to the group TSIG key on **dynamic zones only**
  (a narrow #641 ingest-back grant), leaving every static zone at BIND's
  ``none`` default — and static zones are most of them.
* ``DNSServerOptions.allow_transfer`` and ``DNSZone.allow_transfer`` were
  both editable in the UI, persisted, and **never rendered at all**. The
  operator got a 200, saw the value on re-read, and nothing happened.

So the #61 drift report failed with ``REFUSED`` on every zone of the
flagship deployment. Verified live against the dev BIND9 while fixing:
unsigned → ``REFUSED``, signed with the group key → the zone came back, and
the rendered config passes ``named-checkconf``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.bind9 import (
    Bind9Driver,
    _render_allow_transfer,
    _transfer_key_grants,
)

_KEYS = [
    {"name": "spatium-default", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"},
    {"name": "ops-xfer.", "secret": "c2VjcmV0", "algorithm": "hmac-sha256"},
]


# ── The clause builder ──────────────────────────────────────────────────


def test_key_grants_are_deduped_and_ordered() -> None:
    """Every key is granted, not just the first: the control plane picks
    which one to sign with independently, and the two must not disagree."""
    dupes = [*_KEYS, {"name": "spatium-default"}, {"name": ""}, {}]
    assert _transfer_key_grants(dupes) == ['key "spatium-default";', 'key "ops-xfer.";']


def test_no_keys_and_no_acl_renders_explicit_none() -> None:
    """Absent config must stay closed, matching BIND's own default."""
    assert _render_allow_transfer(None, []) == "allow-transfer { none; }; "


@pytest.mark.parametrize("acl", [None, [], ["none"], ["NONE"]])
def test_keys_are_granted_even_when_the_acl_says_none(acl: list[str] | None) -> None:
    """The load-bearing decision. ``["none"]`` is the column DEFAULT, so
    honouring it literally would lock the control plane out of every zone on
    a stock install and leave drift exactly as broken as before the fix."""
    out = _render_allow_transfer(acl, _transfer_key_grants(_KEYS))
    assert out == 'allow-transfer { key "spatium-default"; key "ops-xfer."; }; '


def test_operator_entries_are_unioned_with_the_key_grants() -> None:
    out = _render_allow_transfer(
        ["10.0.0.0/8", "192.0.2.1"], _transfer_key_grants(_KEYS)
    )
    assert "10.0.0.0/8;" in out
    assert "192.0.2.1;" in out
    assert 'key "spatium-default";' in out


def test_none_keeps_its_place_when_mixed_with_other_entries() -> None:
    """BIND reads ``none`` as ``!any`` — deny everyone from that point on — so
    ``["none", "10.0.0.0/8"]`` admits nobody but the key holders. Dropping
    ``none`` would turn it into "admit 10/8", the opposite of the stored
    list and of the Technitium translation of it."""
    out = _render_allow_transfer(["none", "10.0.0.0/8"], _transfer_key_grants(_KEYS))
    assert out == (
        'allow-transfer { key "spatium-default"; key "ops-xfer."; none; 10.0.0.0/8; }; '
    )


def test_trailing_none_is_rendered_in_order() -> None:
    out = _render_allow_transfer(["10.0.0.0/8", "none"], [])
    assert out == "allow-transfer { 10.0.0.0/8; none; }; "


def test_negated_none_is_rendered_verbatim() -> None:
    assert _render_allow_transfer(["!none", "10.0.0.0/8"], []) == (
        "allow-transfer { !none; 10.0.0.0/8; }; "
    )


def test_entries_that_would_end_the_statement_are_dropped() -> None:
    out = _render_allow_transfer(["10.0.0.0/8", "any; }; options { x"], [])
    assert out == "allow-transfer { 10.0.0.0/8; }; "


def test_mixed_none_list_through_a_full_render(tmp_path: Path) -> None:
    b = _bundle(zones=[_zone("closed.test.", allow_transfer=["none", "192.0.2.0/24"])])
    b["options"]["allow_transfer"] = ["none", "10.0.0.0/8"]
    conf = _render(tmp_path, b)
    assert 'key "ops-xfer."; none; 10.0.0.0/8; };' in conf
    zone_line = next(ln for ln in conf.splitlines() if ln.startswith('zone "closed.test."'))
    assert 'key "ops-xfer."; none; 192.0.2.0/24; };' in zone_line


def test_any_is_honoured_when_the_operator_asks_for_it() -> None:
    assert _render_allow_transfer(["any"], []) == "allow-transfer { any; }; "


# ── Through a full render ───────────────────────────────────────────────


def _bundle(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "auto",
            "allow_transfer": ["none"],
        },
        "tsig_keys": _KEYS,
        "zones": [],
    }
    base.update(over)
    return base


def _zone(name: str, **over: Any) -> dict[str, Any]:
    z: dict[str, Any] = {
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "serial": 1,
        "dynamic_update_enabled": False,
        "update_acl": [],
        "allow_transfer": None,
        "records": [],
    }
    z.update(over)
    return z


def _render(tmp_path: Path, bundle: dict[str, Any]) -> str:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_options_block_carries_the_grant(tmp_path: Path) -> None:
    """The server-level clause is what makes EVERY zone readable — primary,
    secondary, stub, RPZ — instead of only the dynamic ones."""
    conf = _render(tmp_path, _bundle())
    assert 'allow-transfer { key "spatium-default"; key "ops-xfer."; };' in conf


def test_static_zone_is_transferable(tmp_path: Path) -> None:
    """The actual regression: a zone with dynamic updates off used to get no
    grant anywhere, so drift could never read it."""
    conf = _render(tmp_path, _bundle(zones=[_zone("static.test.")]))
    # No per-zone clause is needed — but the options one must cover it, and
    # nothing may shadow it with a narrower zone-level clause.
    zone_line = next(
        ln for ln in conf.splitlines() if ln.startswith('zone "static.test."')
    )
    assert "allow-transfer" not in zone_line
    assert "allow-transfer" in conf


def test_zone_override_is_rendered_and_still_grants_the_keys(tmp_path: Path) -> None:
    """A zone-level clause shadows the options one COMPLETELY in BIND, so the
    key grants have to be repeated. Without that, setting a zone override
    would silently re-break drift for that zone — the same bug again."""
    conf = _render(
        tmp_path, _bundle(zones=[_zone("narrow.test.", allow_transfer=["10.0.0.0/8"])])
    )
    zone_line = next(
        ln for ln in conf.splitlines() if ln.startswith('zone "narrow.test."')
    )
    assert (
        'allow-transfer { key "spatium-default"; key "ops-xfer."; 10.0.0.0/8; };'
        in zone_line
    )


def test_zone_without_override_emits_no_zone_level_clause(tmp_path: Path) -> None:
    """None means "inherit". Emitting a clause anyway would make the
    server-level setting unreachable for every primary zone."""
    conf = _render(tmp_path, _bundle(zones=[_zone("inherit.test.")]))
    zone_line = next(
        ln for ln in conf.splitlines() if ln.startswith('zone "inherit.test."')
    )
    assert "allow-transfer" not in zone_line


def test_operator_allow_transfer_reaches_the_config(tmp_path: Path) -> None:
    """The silent no-op half: this value was settable and persisted for
    releases without ever appearing in named.conf."""
    b = _bundle()
    b["options"]["allow_transfer"] = ["10.0.0.0/8"]
    assert "10.0.0.0/8;" in _render(tmp_path, b)


def test_keyless_group_renders_closed(tmp_path: Path) -> None:
    """No key must never fail OPEN. A group with neither key nor ACL stays
    at ``none`` — the fix may not turn an unreadable zone into a public one."""
    conf = _render(tmp_path, _bundle(tsig_keys=[]))
    assert "allow-transfer { none; };" in conf

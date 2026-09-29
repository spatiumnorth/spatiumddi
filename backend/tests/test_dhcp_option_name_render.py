"""#856 — DHCP option-name handling: normalisation and the Kea ``option-def``.

Two defects, both silent:

* ``_normalize_options`` resolved an entry's name with
  ``entry.get("name") or _CODE_TO_NAME.get(int(code)) if code else None``.
  The conditional binds looser than ``or``, so it evaluated as
  ``(name or lookup) if code else None`` — an option identified by NAME with
  no ``code`` was discarded rather than used as-is.
* Option 150 (``tftp-server-address``) has no built-in Kea definition. The
  driver emitted it by name alone, which fails the WHOLE config with
  "definition for the option 'dhcp4.tftp-server-address' does not exist"
  (verified against Kea 3.0.3) — taking DHCP down rather than dropping one
  option. The definition now ships with it.

The matching agent-side renderer bug is covered in
``agent/dhcp/tests/test_render_kea_option_names.py``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.api.v1.dhcp.scopes import _normalize_options
from app.drivers.dhcp.base import ConfigBundle, ScopeDef, ServerOptionsDef
from app.drivers.dhcp.kea import KeaDriver, _render_option_data


def _bundle(options: dict) -> ConfigBundle:
    return ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000000",
        server_name="kea-856",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=(
            ScopeDef(
                subnet_cidr="192.168.20.0/24",
                lease_time=3600,
                options=options,
                pools=(),
                statics=(),
                is_active=True,
            ),
        ),
        client_classes=(),
        generated_at=datetime.now(UTC),
    )


def _dhcp4(options: dict) -> dict:
    return json.loads(KeaDriver().render_config(_bundle(options)))["Dhcp4"]


# ── _normalize_options: the operator-precedence bug ─────────────────────────


def test_name_only_entry_is_kept() -> None:
    """An option given by name with no ``code`` was silently dropped."""
    assert _normalize_options([{"name": "routers", "value": ["192.168.20.254"]}]) == {
        "routers": ["192.168.20.254"]
    }


def test_name_only_alias_still_normalises() -> None:
    assert _normalize_options([{"name": "domain-name-servers", "value": ["192.168.20.1"]}]) == {
        "dns-servers": ["192.168.20.1"]
    }


def test_code_only_entry_resolves_by_code() -> None:
    assert _normalize_options([{"code": 6, "value": ["192.168.20.1"]}]) == {
        "dns-servers": ["192.168.20.1"]
    }


def test_name_wins_over_code_when_both_present() -> None:
    assert _normalize_options([{"code": 3, "name": "routers", "value": ["192.168.20.254"]}]) == {
        "routers": ["192.168.20.254"]
    }


def test_unknown_code_falls_back_to_a_raw_code_key() -> None:
    # #1228 — was ``option-252``, a name no renderer knows. ``code:NN`` is the
    # spelling the renderer emits, and the one the option check can judge.
    assert _normalize_options([{"code": 252, "value": "x"}]) == {"code:252": "x"}


def test_entry_with_neither_name_nor_code_is_skipped() -> None:
    assert _normalize_options([{"value": "orphan"}]) == {}


def test_non_integer_code_is_skipped_not_raised() -> None:
    """A malformed code must not 500 the request."""
    assert _normalize_options([{"code": "abc", "value": "x"}]) == {}


# ── Kea render: option 6 and the option-def ─────────────────────────────────


def test_option_6_renders_as_domain_name_servers() -> None:
    rendered = _render_option_data({"dns-servers": ["192.168.20.1"]})
    assert rendered == [{"name": "domain-name-servers", "data": "192.168.20.1"}]


def test_option_150_ships_its_definition() -> None:
    doc = _dhcp4({"tftp-server-address": ["192.168.20.5"]})
    assert doc["option-def"] == [
        {
            "name": "tftp-server-address",
            "code": 150,
            "space": "dhcp4",
            "type": "ipv4-address",
            "array": True,
        }
    ]


def test_no_option_def_key_when_unused() -> None:
    """Installs that don't use option 150 keep a byte-identical config."""
    assert "option-def" not in _dhcp4({"dns-servers": ["192.168.20.1"]})


@pytest.mark.parametrize(
    ("canonical", "kea_name"),
    [
        ("routers", "routers"),
        ("dns-servers", "domain-name-servers"),
        ("bootfile-name", "boot-file-name"),
        ("mtu", "interface-mtu"),
        ("broadcast-address", "broadcast-address"),
        ("time-offset", "time-offset"),
    ],
)
def test_canonical_names_map_to_kea_names(canonical: str, kea_name: str) -> None:
    rendered = _render_option_data({canonical: "1"})
    assert rendered[0]["name"] == kea_name

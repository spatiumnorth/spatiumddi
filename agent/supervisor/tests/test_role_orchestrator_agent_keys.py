"""Supervisor must not drop non-hex agent bootstrap keys (#1566).

The supervisor validated the DNS / DHCP / Looking Glass bootstrap keys
against ``^[a-f0-9]{32,128}$`` before writing them into the role env.
Nothing else enforces that shape: the control plane stores the key as
a plain string, standalone Compose/Kubernetes agents accept any
non-empty value, and ``.env.example`` only *recommends*
``openssl rand -hex 32``. An operator with a custom key got working
standalone agents and silently broken appliance agents — the key was
logged and omitted, so the agent had no PSK and could not register.

The pattern is now an env-file injection defence only (#237):
whitespace (incl. newlines), quotes, backtick, ``$`` and ``\\`` are
rejected; every other value passes, whatever its shape.
"""

from __future__ import annotations

import pytest

from spatium_supervisor.role_orchestrator import compute_target_env

ALL_ROLES = ["dns-bind9", "dhcp", "looking-glass"]


def _env_with_keys(key: str | None) -> list[str]:
    target = compute_target_env(
        {
            "roles": ALL_ROLES,
            "dns_group_name": "default",
            "dhcp_group_name": "default-dhcp",
            "dns_agent_key": key,
            "dhcp_agent_key": key,
            "lg_agent_key": key,
        }
    )
    return target.env_lines


def _key_lines(lines: list[str]) -> list[str]:
    return [
        line
        for line in lines
        if line.startswith(("DNS_AGENT_KEY=", "DHCP_AGENT_KEY=", "LG_AGENT_KEY="))
    ]


@pytest.mark.parametrize(
    "key",
    [
        "a" * 64,  # openssl rand -hex 32 — the recommended shape
        "A1B2C3" * 8,  # uppercase hex was dropped by the old pattern too
        "my-custom-bootstrap-key",  # operator-chosen passphrase-style key
        "c2VjcmV0LWtleS0xMjM0NTY3OA==",  # base64, incl. padding
        "key_with.dots-and~tildes:and;punct!",  # printable punctuation
        "x",  # short is fine — length is not the contract either
    ],
)
def test_non_hex_keys_are_kept_for_all_roles(key: str) -> None:
    lines = _key_lines(_env_with_keys(key))
    assert lines == [
        f"DNS_AGENT_KEY={key}",
        f"DHCP_AGENT_KEY={key}",
        f"LG_AGENT_KEY={key}",
    ]


@pytest.mark.parametrize(
    "key",
    [
        "abc\nDNS_AGENT_KEY=injected",  # newline = extra env-file line (#237)
        "abc\rdef",
        "has space",
        "has\ttab",
        'dou"ble',
        "sin'gle",
        "back`tick",
        "dol$lar",
        "back\\slash",
        "",  # empty stays omitted, as before
        "k" * 513,  # over the sanity cap
    ],
)
def test_injection_shaped_keys_are_still_dropped(key: str) -> None:
    assert _key_lines(_env_with_keys(key)) == []


def test_hex_key_regression_from_role_chart_fixture() -> None:
    # The exact key shape other supervisor tests use ("a" * 48).
    lines = _key_lines(_env_with_keys("a" * 48))
    assert len(lines) == 3

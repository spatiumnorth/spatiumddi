"""Recursion policy + per-client rate limit reach Technitium (#1761).

The agent never sent ``recursion`` or ``qpmPrefixLimits*``, so the daemon's
own defaults stayed in force: recursion for every private network even on an
authoritative-only group, and 600 queries/min per client with RRL "off".
These drive the real ``render`` -> ``swap_and_reload`` and assert on the
``settings/set`` payloads that reach the (faked) HTTP layer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.technitium import TechnitiumDriver


class _Resp:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.status_code = 200
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


def _apply(tmp_path: Path, options: dict[str, Any]) -> list[dict[str, Any]]:
    """Run a structural apply; return every ``settings/set`` payload sent."""
    sent: list[tuple[str, dict[str, Any]]] = []

    def request(_t: str, _m: str, path: str, params: dict[str, Any]) -> _Resp:
        sent.append((path, dict(params)))
        if path == "zones/records/get":
            return _Resp({"status": "ok", "response": {"records": []}})
        return _Resp({"status": "ok"})

    d = TechnitiumDriver(state_dir=tmp_path)
    d.daemon_running = lambda: True  # type: ignore[method-assign]
    d._wait_for_api_up = lambda **_: None  # type: ignore[method-assign]
    d._get_api_token = lambda: "tok"  # type: ignore[method-assign]
    d._reprovision_token = lambda stale: None  # type: ignore[method-assign]
    d._request = request  # type: ignore[method-assign]
    d.render({"zones": [], "options": options, "tsig_keys": []})
    d.swap_and_reload()
    return [p for path, p in sent if path == "settings/set"]


def _field(payloads: list[dict[str, Any]], key: str) -> list[Any]:
    return [p[key] for p in payloads if key in p]


def test_recursion_off_sends_deny(tmp_path: Path) -> None:
    sets = _apply(tmp_path, {"recursion_enabled": False, "allow_recursion": ["any"]})
    assert _field(sets, "recursion") == ["Deny"]
    assert _field(sets, "recursionNetworkACL") == []


def test_recursion_on_with_acl_sends_specified_acl(tmp_path: Path) -> None:
    sets = _apply(
        tmp_path,
        {
            "recursion_enabled": True,
            "allow_recursion": [
                "203.0.113.0/24",
                "!203.0.113.9",
                "localhost",
                "bogus-acl",
            ],
        },
    )
    assert _field(sets, "recursion") == ["UseSpecifiedNetworkACL"]
    assert _field(sets, "recursionNetworkACL") == [
        "203.0.113.0/24,!203.0.113.9,127.0.0.0/8,::1/128"
    ]


def test_default_is_loopback_plus_private_ranges(tmp_path: Path) -> None:
    # The stored default (#1817) and a bundle without the key. ``localnets``
    # expands to the private ranges the default also lists explicitly: the
    # ACL carries each range once.
    stored_default = [
        "localhost",
        "localnets",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    ]
    for acl in (stored_default, ["localhost", "localnets"], None):
        opts: dict[str, Any] = {"recursion_enabled": True}
        if acl is not None:
            opts["allow_recursion"] = acl
        sets = _apply(tmp_path, opts)
        assert _field(sets, "recursion") == ["UseSpecifiedNetworkACL"], acl
        assert _field(sets, "recursionNetworkACL") == [
            "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
            "169.254.0.0/16,fc00::/7,fe80::/10"
        ], acl


def test_explicit_any_opens_recursion(tmp_path: Path) -> None:
    for acl in (["any"], ["ANY"]):
        sets = _apply(tmp_path, {"recursion_enabled": True, "allow_recursion": acl})
        assert _field(sets, "recursion") == ["Allow"], acl
        assert _field(sets, "recursionNetworkACL") == [], acl


def test_empty_list_denies(tmp_path: Path) -> None:
    sets = _apply(tmp_path, {"recursion_enabled": True, "allow_recursion": []})
    assert _field(sets, "recursion") == ["Deny"]


def test_duplicates_collapse_first_occurrence_kept(tmp_path: Path) -> None:
    sets = _apply(
        tmp_path,
        {
            "recursion_enabled": True,
            "allow_recursion": ["!10.9.0.0/16", "10.0.0.0/8", "10.0.0.0/8", "localnets"],
        },
    )
    assert _field(sets, "recursionNetworkACL") == [
        "!10.9.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
        "169.254.0.0/16,fc00::/7,fe80::/10"
    ]


def test_an_acl_with_no_usable_entry_fails_closed(tmp_path: Path) -> None:
    sets = _apply(tmp_path, {"allow_recursion": ["some-named-acl"]})
    assert _field(sets, "recursion") == ["Deny"]


def test_rrl_off_sends_empty_qpm_limits(tmp_path: Path) -> None:
    sets = _apply(
        tmp_path, {"rrl_enabled": False, "rrl_exempt_clients": ["10.0.0.0/8"]}
    )
    assert _field(sets, "qpmPrefixLimitsIPv4") == [""]
    assert _field(sets, "qpmPrefixLimitsIPv6") == [""]
    assert _field(sets, "qpmLimitBypassList") == [""]


def test_rrl_on_derives_limits_from_the_rrl_fields(tmp_path: Path) -> None:
    sets = _apply(
        tmp_path,
        {
            "rrl_enabled": True,
            "rrl_responses_per_second": 20,
            "rrl_window": 120,
            "rrl_slip": 4,
            "rrl_exempt_clients": ["192.0.2.0/24", "not-an-ip"],
        },
    )
    assert _field(sets, "qpmPrefixLimitsIPv4") == ["32|1200|1200"]
    assert _field(sets, "qpmPrefixLimitsIPv6") == ["128|1200|1200"]
    assert _field(sets, "qpmLimitSampleMinutes") == [2]
    assert _field(sets, "qpmLimitUdpTruncationPercentage") == [25]
    assert _field(sets, "qpmLimitBypassList") == ["192.0.2.0/24"]


def test_rrl_log_only_does_not_enforce(tmp_path: Path) -> None:
    sets = _apply(tmp_path, {"rrl_enabled": True, "rrl_log_only": True})
    assert _field(sets, "qpmPrefixLimitsIPv4") == [""]

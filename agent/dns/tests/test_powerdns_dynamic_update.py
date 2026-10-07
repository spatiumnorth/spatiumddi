"""PowerDNS agent dynamic-update ACL support (issue #641, P3, coarse-only).

Covers ``dnsupdate=yes`` in the rendered pdns.conf and the per-zone
metadata application (``ALLOW-DNSUPDATE-FROM`` / ``TSIG-ALLOW-DNSUPDATE``)
via a fake pdns REST client.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver


class _Resp:
    def __init__(self, status: int = 200) -> None:
        self.status_code = status
        self.text = ""


class _FakeClient:
    """Records pdns REST calls so tests can assert on them."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    def post(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self.calls.append(("POST", url, json))
        return _Resp(201)

    def put(self, url: str, headers: Any = None, json: Any = None) -> _Resp:
        self.calls.append(("PUT", url, json))
        return _Resp(200)

    def delete(self, url: str, headers: Any = None) -> _Resp:
        self.calls.append(("DELETE", url, None))
        return _Resp(200)


def test_render_conf_enables_dnsupdate(tmp_path: Path) -> None:
    conf = PowerDNSDriver(state_dir=tmp_path)._render_conf(api_key="k", log_level=4)
    assert "dnsupdate=yes" in conf


def test_render_conf_turns_off_security_polling(tmp_path: Path) -> None:
    """PowerDNS's secpoll phones secpoll.powerdns.com with its version; an
    empty suffix turns it off (#1353, non-negotiable #17). An absent line
    keeps PowerDNS's default, which is ON, so the line must be there."""
    for alias_resolver in ("1.1.1.1,8.8.8.8", ""):
        conf = PowerDNSDriver(state_dir=tmp_path)._render_conf(
            api_key="k", log_level=4, alias_resolver=alias_resolver
        )
        assert "security-poll-suffix=" in conf.splitlines()


def test_dnsdist_front_turns_off_security_polling() -> None:
    """The dnsdist front secpolls too, on by default (#1353). Its base config
    is built by the image entrypoint rather than the agent, so pin the line
    there: build_conf must emit an empty ``setSecurityPollSuffix``."""
    entrypoint = (
        Path(__file__).resolve().parents[1] / "images" / "dnsdist" / "entrypoint.sh"
    ).read_text()
    build_conf = entrypoint.split("build_conf() {", 1)[1].split("\n}\n", 1)[0]
    assert """echo 'setSecurityPollSuffix("")'""" in build_conf


def test_apply_dynamic_update_sets_metadata(tmp_path: Path) -> None:
    d = PowerDNSDriver(state_dir=tmp_path)
    c = _FakeClient()
    zp = {
        "name": "z.example.com.",
        "update_acl": [
            {"action": "grant", "match_kind": "ip", "ip_cidr": "10.0.0.0/24"},
            {"action": "grant", "match_kind": "tsig_key", "tsig_key_name": "dc01."},
        ],
        "update_tsig_keys": [
            {"name": "dc01.", "algorithm": "hmac-sha256", "secret": "c2VjcmV0"}
        ],
    }
    d._apply_dynamic_update(c, {}, zp)  # type: ignore[arg-type]

    # Referenced key imported into pdns.
    assert any(m == "POST" and url.endswith("/tsigkeys") for (m, url, _) in c.calls)
    # ALLOW-DNSUPDATE-FROM carries the CIDR.
    allow = [
        j
        for (m, url, j) in c.calls
        if m == "PUT" and url.endswith("ALLOW-DNSUPDATE-FROM")
    ]
    assert allow and allow[0]["metadata"] == ["10.0.0.0/24"]
    # TSIG-ALLOW-DNSUPDATE carries the key name, trailing dot stripped.
    tsig = [
        j
        for (m, url, j) in c.calls
        if m == "PUT" and url.endswith("TSIG-ALLOW-DNSUPDATE")
    ]
    assert tsig and tsig[0]["metadata"] == ["dc01"]


def test_apply_dynamic_update_empty_clears_both(tmp_path: Path) -> None:
    d = PowerDNSDriver(state_dir=tmp_path)
    c = _FakeClient()
    d._apply_dynamic_update(  # type: ignore[arg-type]
        c, {}, {"name": "z.example.com.", "update_acl": [], "update_tsig_keys": []}
    )
    dels = [url for (m, url, _) in c.calls if m == "DELETE"]
    assert any("ALLOW-DNSUPDATE-FROM" in u for u in dels)
    assert any("TSIG-ALLOW-DNSUPDATE" in u for u in dels)

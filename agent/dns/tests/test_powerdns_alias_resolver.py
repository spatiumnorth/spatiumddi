"""PowerDNS's ALIAS resolver has no built-in public default (#1353).

The agent used to render ``resolver=1.1.1.1,8.8.8.8`` whenever the control
plane sent no ``alias_resolver``, which it never did, so every PowerDNS server
sent ALIAS targets to Cloudflare and Google. The control plane now sends the
group's plain-DNS forwarders, and with none ALIAS expansion is off.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_dns_agent.drivers.powerdns import PowerDNSDriver, _safe_alias_resolver


def _lines(conf: str) -> list[str]:
    return conf.splitlines()


def test_no_resolver_by_default(tmp_path: Path) -> None:
    conf = _lines(
        PowerDNSDriver(state_dir=tmp_path)._render_conf(api_key="k", log_level=4)
    )
    assert "expand-alias=no" in conf
    assert not [line for line in conf if line.startswith("resolver=")]


def test_the_forwarders_become_the_resolver(tmp_path: Path) -> None:
    conf = _lines(
        PowerDNSDriver(state_dir=tmp_path)._render_conf(
            api_key="k", log_level=4, alias_resolver="10.0.0.53,[2001:db8::53]:5353"
        )
    )
    assert "expand-alias=yes" in conf
    assert "resolver=10.0.0.53,[2001:db8::53]:5353" in conf


@pytest.mark.parametrize("value", [None, "", "   ", 42])
def test_absent_or_empty_is_off(value: object) -> None:
    assert _safe_alias_resolver(value) == ""


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.53\nlaunch=bind",  # a newline would start a new pdns.conf directive
        "ns.example.com",
        "10.0.0.53;rm",
        # Address-shaped but not addresses pdns can parse: each would pass a
        # character-class check and stop pdns starting.
        ",,,",
        "deadbeef",
        "10.0.0.53,",
        "fe80::1%eth0",
        "10.0.0.53:99999",
        "[10.0.0.53]:53",
        "2001:db8::53:53:53:53:53:53",
    ],
)
def test_anything_but_an_address_list_is_refused(value: str) -> None:
    assert _safe_alias_resolver(value) == ""


def test_an_address_list_passes() -> None:
    assert _safe_alias_resolver(" 10.0.0.53:53,::1 ") == "10.0.0.53:53,::1"
    assert _safe_alias_resolver("[2001:db8::53]:5353") == "[2001:db8::53]:5353"


def _staged(tmp_path: Path, old: str | None, new: str) -> PowerDNSDriver:
    if old is not None:
        (tmp_path / "rendered").mkdir()
        (tmp_path / "rendered" / "pdns.conf").write_text(old)
    (tmp_path / "rendered.new").mkdir()
    (tmp_path / "rendered.new" / "pdns.conf").write_text(new)
    (tmp_path / "rendered.new" / "zones.json").write_text("[]")
    return PowerDNSDriver(state_dir=tmp_path)


@pytest.mark.parametrize(
    ("old", "new", "restarts"),
    [
        ("expand-alias=no\n", "expand-alias=yes\nresolver=10.0.0.53\n", True),
        ("expand-alias=no\n", "expand-alias=no\n", False),
    ],
    ids=["changed", "unchanged"],
)
def test_a_changed_pdns_conf_restarts_the_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old: str, new: str, restarts: bool
) -> None:
    """pdns reads pdns.conf only at startup, so without a restart a forwarder
    change (the ALIAS resolver) would wait for the container to restart."""
    driver = _staged(tmp_path, old, new)
    calls: list[str] = []
    monkeypatch.setattr(driver, "daemon_running", lambda: True)
    monkeypatch.setattr(driver, "_restart_daemon", lambda: calls.append("restart"))
    monkeypatch.setattr(driver, "_load_or_generate_api_key", lambda: "k")
    monkeypatch.setattr(
        driver, "_reconcile_zones", lambda *_a: calls.append("reconcile")
    )

    driver.swap_and_reload()
    assert calls == (["restart", "reconcile"] if restarts else ["reconcile"])


def test_the_first_render_starts_rather_than_restarts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    driver = _staged(tmp_path, None, "expand-alias=no\n")
    calls: list[str] = []
    monkeypatch.setattr(driver, "daemon_running", lambda: False)
    monkeypatch.setattr(driver, "start_daemon", lambda: calls.append("start"))
    monkeypatch.setattr(driver, "_wait_for_api_up", lambda: None)
    monkeypatch.setattr(driver, "_restart_daemon", lambda: calls.append("restart"))
    monkeypatch.setattr(driver, "_load_or_generate_api_key", lambda: "k")
    monkeypatch.setattr(driver, "_reconcile_zones", lambda *_a: None)

    driver.swap_and_reload()
    assert calls == ["start"]

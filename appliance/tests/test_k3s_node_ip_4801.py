"""k3s starts with no default route; chrony-wait does not fail the boot (#4801).

``spatium-k3s-node-ip`` (k3s.service ExecStartPre) is run against a stub ``ip``.

    python3 -m pytest appliance/tests/test_k3s_node_ip_4801.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

APPLIANCE = Path(__file__).resolve().parents[1]
EXTRA = APPLIANCE / "mkosi.extra"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-k3s-node-ip"


def _run(tmp_path: Path, *, route4: bool = False, route6: bool = False, a4: str = "", a6: str = ""):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    ip = bindir / "ip"
    ip.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f'  "-4 route show default") {"echo default via 10.0.0.1 dev eth0" if route4 else ":"} ;;\n'
        f'  "-6 route show default") {"echo default via fe80::1 dev eth0" if route6 else ":"} ;;\n'
        f"  \"-o -4 addr show scope global\") printf '%s' '{a4}' ;;\n"
        f"  \"-o -6 addr show scope global\") printf '%s' '{a6}' ;;\n"
        "esac\n"
    )
    ip.chmod(0o755)
    dropin = tmp_path / "spatium-node-ip.yaml"
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "SPATIUM_K3S_NODE_IP_DROPIN": str(dropin),
        "SPATIUM_K3S_NODE_IP_LOG": str(tmp_path / "log"),
    }
    proc = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return dropin


V4 = (
    "2: eth0    inet 192.168.50.7/24 brd 192.168.50.255 scope global eth0\n"
    "9: flannel.1    inet 10.42.0.0/32 scope global flannel.1\n"
)
V6 = "2: eth0    inet6 fd00:1::7/64 scope global eth0\n"


def test_no_route_pins_node_ip_and_iface(tmp_path: Path) -> None:
    dropin = _run(tmp_path, a4=V4)
    text = dropin.read_text()
    assert "node-ip: 192.168.50.7\n" in text
    assert "flannel-iface: eth0\n" in text


def test_ipv6_only_pins_the_v6_address(tmp_path: Path) -> None:
    dropin = _run(tmp_path, a6=V6)
    assert "node-ip: fd00:1::7\n" in dropin.read_text()


def test_default_route_keeps_existing_behaviour(tmp_path: Path) -> None:
    dropin = _run(tmp_path, route4=True, a4=V4)
    assert not dropin.exists()


def test_stale_dropin_removed_once_a_route_exists(tmp_path: Path) -> None:
    (tmp_path / "spatium-node-ip.yaml").write_text("node-ip: 1.2.3.4\n")
    dropin = _run(tmp_path, route6=True, a6=V6)
    assert not dropin.exists()


def test_address_change_is_followed(tmp_path: Path) -> None:
    _run(tmp_path, a4=V4)
    dropin = _run(tmp_path, a4=V4.replace("192.168.50.7", "192.168.50.99"))
    assert "node-ip: 192.168.50.99\n" in dropin.read_text()


def test_no_address_at_all_does_not_fail(tmp_path: Path) -> None:
    dropin = _run(tmp_path)
    assert not dropin.exists()


def test_k3s_unit_runs_it_and_never_blocks_on_it() -> None:
    unit = (EXTRA / "etc/systemd/system/k3s.service").read_text()
    assert "ExecStartPre=-/usr/local/bin/spatium-k3s-node-ip" in unit
    post = (APPLIANCE / "mkosi.postinst").read_text()
    assert 'chmod 0755 "$BUILDROOT/usr/local/bin/spatium-k3s-node-ip"' in post


def test_chrony_wait_is_masked_and_nothing_needs_it() -> None:
    post = (APPLIANCE / "mkosi.postinst").read_text()
    assert 'ln -sfn /dev/null "$BUILDROOT/etc/systemd/system/chrony-wait.service"' in post
    for unit in (EXTRA / "etc/systemd/system").glob("*.service"):
        for line in unit.read_text().splitlines():
            if line.startswith(("After=", "Requires=", "Wants=")):
                assert "time-sync.target" not in line, unit.name


def test_journal_is_persistent() -> None:
    conf = (EXTRA / "etc/systemd/journald.conf.d/50-spatium-persistent.conf").read_text()
    assert "Storage=persistent" in conf

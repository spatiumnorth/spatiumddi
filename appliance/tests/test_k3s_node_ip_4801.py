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


def _run(
    tmp_path: Path,
    *,
    route4: bool = False,
    route6: bool = False,
    a4: str = "",
    a6: str = "",
    nm_iface: str = "",
    cidrs: str = "",
    own4: str = "",
    own6: str = "",
    args: tuple = (),
):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    ip = bindir / "ip"
    ip.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{tmp_path}/calls"\n'
        f"""case "$*" in\n"""
        f'  "-4 route show proto 198") printf "%s" "{own4}" ;;\n'
        f'  "-6 route show proto 198") printf "%s" "{own6}" ;;\n'
        f'  "-4 route show default") {"echo default via 10.0.0.1 dev eth0" if route4 else ":"} ;;\n'
        f'  "-6 route show default") {"echo default via fe80::1 dev eth0" if route6 else ":"} ;;\n'
        f"  \"-o -4 addr show scope global\") printf '%s' '{a4}' ;;\n"
        f"  \"-o -6 addr show scope global\") printf '%s' '{a6}' ;;\n"
        "esac\n"
    )
    ip.chmod(0o755)
    dropin = tmp_path / "spatium-node-ip.yaml"
    nm = tmp_path / "nm"
    nm.mkdir(exist_ok=True)
    if nm_iface:
        (nm / "10-spatium-dhcp.nmconnection").write_text(
            f"[connection]\ninterface-name={nm_iface}\n"
        )
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "SPATIUM_K3S_NODE_IP_DROPIN": str(dropin),
        "SPATIUM_K3S_NODE_IP_LOG": str(tmp_path / "log"),
        "SPATIUM_K3S_NODE_IP_NM_DIR": str(nm),
        "SPATIUM_K3S_NODE_IP_CIDRS": str(tmp_path / "cidrs.yaml"),
    }
    if cidrs:
        (tmp_path / "cidrs.yaml").write_text(cidrs)
    proc = subprocess.run(["sh", str(SCRIPT), *args], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    calls = tmp_path / "calls"
    _run.calls = calls.read_text().splitlines() if calls.exists() else []
    calls.unlink(missing_ok=True)
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


def test_multi_nic_prefers_the_installer_bound_interface(tmp_path: Path) -> None:
    two = (
        "2: ens3    inet 10.9.0.5/24 scope global ens3\n"
        "3: ens4    inet 192.168.50.7/24 scope global ens4\n"
    )
    text = _run(tmp_path, a4=two, nm_iface="ens4").read_text()
    assert "node-ip: 192.168.50.7\n" in text and "flannel-iface: ens4\n" in text


def test_bound_interface_without_address_falls_back(tmp_path: Path) -> None:
    text = _run(tmp_path, a4=V4, nm_iface="ens9").read_text()
    assert "node-ip: 192.168.50.7\n" in text


def _mutations() -> list[str]:
    return [c for c in _run.calls if " route replace " in c or " route del " in c]


def test_no_route_adds_default_service_cidr_route(tmp_path: Path) -> None:
    _run(tmp_path, a4=V4)
    assert _mutations() == ["-4 route replace 10.43.0.0/16 dev eth0 scope link proto 198"]


def test_service_cidr_read_from_cidrs_dropin_dual_stack(tmp_path: Path) -> None:
    _run(
        tmp_path,
        a4=V4,
        cidrs="cluster-cidr: 10.42.0.0/16\nservice-cidr: 10.99.0.0/16,fd00:43::/112\n",
    )
    assert _mutations() == [
        "-4 route replace 10.99.0.0/16 dev eth0 scope link proto 198",
        "-6 route replace fd00:43::/112 dev eth0 proto 198",
    ]


def test_default_route_removes_only_own_routes(tmp_path: Path) -> None:
    _run(
        tmp_path,
        route4=True,
        a4=V4,
        own4="10.43.0.0/16 dev eth0 scope link\n",
        own6="fd00:43::/112 dev eth0\n",
    )
    assert _mutations() == [
        "-4 route del 10.43.0.0/16 proto 198",
        "-6 route del fd00:43::/112 proto 198",
    ]


def test_routes_only_mode_leaves_the_dropin_alone(tmp_path: Path) -> None:
    (tmp_path / "spatium-node-ip.yaml").write_text("node-ip: 1.2.3.4\n")
    dropin = _run(tmp_path, a4=V4, args=("--routes-only",))
    assert dropin.read_text() == "node-ip: 1.2.3.4\n"
    assert len(_mutations()) == 1


def test_nm_dispatcher_hook_reapplies_the_route() -> None:
    hook = EXTRA / "etc/NetworkManager/dispatcher.d/50-spatium-k3s-service-route"
    text = hook.read_text()
    assert "spatium-k3s-node-ip --routes-only" in text
    assert "dhcp4-change" in text and "reapply" in text
    assert os.access(hook, os.X_OK)
    post = (APPLIANCE / "mkosi.postinst").read_text()
    assert "dispatcher.d/50-spatium-k3s-service-route" in post

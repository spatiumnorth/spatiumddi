"""``spatiumddi-netif-reload`` — additional network interfaces (#4428).

These tests EXECUTE the shipped runner against a fake root and stubbed
``ip`` / ``nmcli``, because the property that matters is not visible to
review: a change that cuts the node off from the control plane must be
undone BY THE HOST, with nothing on the control plane noticing anything.

What is covered: the NetworkManager keyfile each interface renders to, the
host's own refusal of the primary interface and of default routes (it does
not trust the control plane), idempotent re-apply, the rollback (deadline
passed, no confirm -> the previous profiles are back and the status says
``reverted``), the confirm path, and that a refused / failed apply neither
claims success nor leaves half a configuration.

What is NOT covered, and only a live appliance proves: that real
NetworkManager accepts these keyfiles, brings a VLAN up on a real NIC and
deletes it on removal, and that the supervisor's confirm really races the
deadline on a box that just changed its own routes.

HOW TO RUN (repo root):
    python3 -m pytest appliance/tests/test_netif_runner_4428.py -v

No database, no Docker, no root, no NetworkManager required.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "appliance" / "mkosi.extra" / "usr" / "local" / "bin"
RUNNER = BIN / "spatiumddi-netif-reload"
UNITS = REPO / "appliance" / "mkosi.extra" / "etc" / "systemd" / "system"
POSTINST = REPO / "appliance" / "mkosi.postinst"

_IP = r"""#!/bin/sh
# `ip -j ...` from fixture files.
echo "ip $*" >> "$STUB_CALLS"
case "$*" in
  *"-d addr show"*) cat "$STUB_DIR/addr.json" ;;
  *"-4 route show"*) cat "$STUB_DIR/route4.json" ;;
  *"-6 route show"*) cat "$STUB_DIR/route6.json" ;;
  *) echo "[]" ;;
esac
"""

_NMCLI = r"""#!/bin/sh
echo "nmcli $*" >> "$STUB_CALLS"
if [ -n "$STUB_NMCLI_FAIL" ]; then
  case "$*" in
    *"$STUB_NMCLI_FAIL"*) echo "Error: $STUB_NMCLI_MSG" >&2; exit 3 ;;
  esac
fi
exit 0
"""

ADDR = [
    {
        "ifname": "lo",
        "link_type": "loopback",
        "flags": ["LOOPBACK", "UP", "LOWER_UP"],
        "operstate": "UNKNOWN",
        "addr_info": [{"local": "127.0.0.1", "prefixlen": 8, "scope": "host"}],
    },
    {
        "ifname": "ens18",
        "link_type": "ether",
        "flags": ["BROADCAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "mtu": 1500,
        "address": "52:54:00:00:00:18",
        "addr_info": [{"local": "192.168.1.10", "prefixlen": 24, "scope": "global"}],
    },
    {
        "ifname": "ens19",
        "link_type": "ether",
        "flags": ["BROADCAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "mtu": 1500,
        "addr_info": [],
    },
    {
        "ifname": "ens19.100",
        "link": "ens19",
        "link_type": "ether",
        "flags": ["BROADCAST", "UP", "LOWER_UP"],
        "operstate": "UP",
        "linkinfo": {"info_kind": "vlan", "info_data": {"id": 100}},
        "addr_info": [],
    },
    {"ifname": "veth1234", "link_type": "ether", "flags": [], "addr_info": []},
]


@pytest.fixture
def host(tmp_path):
    stub = tmp_path / "stub"
    stub.mkdir()
    for name, body in (("ip", _IP), ("nmcli", _NMCLI)):
        (stub / name).write_text(body)
        (stub / name).chmod(0o755)
    (stub / "addr.json").write_text(json.dumps(ADDR))
    (stub / "route4.json").write_text(
        json.dumps(
            [
                {"dst": "default", "gateway": "192.168.1.1", "dev": "ens18", "metric": 100},
                {"dst": "192.168.1.0/24", "dev": "ens18", "protocol": "kernel"},
            ]
        )
    )
    (stub / "route6.json").write_text("[]")
    calls = tmp_path / "calls.txt"
    calls.write_text("")
    root = tmp_path / "root"
    state = root / "var/lib/spatiumddi/release-state"
    state.mkdir(parents=True)
    nm = root / "etc/NetworkManager/system-connections"
    nm.mkdir(parents=True)
    (root / "etc/spatiumddi").mkdir(parents=True)
    (root / "etc/spatiumddi/network-status").write_text("INTERFACE=ens18\nMODE=static\n")
    (root / "run").mkdir()
    # The installer-owned profile: the runner must never touch it.
    (nm / "10-spatium-static.nmconnection").write_text("[connection]\nid=spatium-static\n")
    return {
        "tmp": tmp_path,
        "stub": stub,
        "calls": calls,
        "root": root,
        "state": state,
        "nm": nm,
        "log": root / "var/log/spatiumddi/netif-reload.log",
    }


def run(host, *args, env_extra=None):
    env = {
        **os.environ,
        "SPATIUM_NETIF_ROOT": str(host["root"]),
        "PATH": f"{host['stub']}:{os.environ.get('PATH', '')}",
        "STUB_CALLS": str(host["calls"]),
        "STUB_DIR": str(host["stub"]),
        **(env_extra or {}),
    }
    return subprocess.run(
        [sys.executable, str(RUNNER), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def trigger(host, interfaces, *, hash_="h1", revert=180, marker=None):
    marker = marker or ("enabled" if interfaces else "disabled")
    (host["state"] / "netif-config-pending").write_text(
        f"{marker}\n{hash_}\n"
        + json.dumps({"interfaces": interfaces, "revert_seconds": revert})
        + "\n"
    )


def apply(host, interfaces, **kw):
    env_extra = kw.pop("env_extra", None)
    trigger(host, interfaces, **kw)
    return run(host, env_extra=env_extra)


def status(host):
    return json.loads((host["state"] / "netif-status.json").read_text())


def calls(host):
    return host["calls"].read_text().splitlines()


def nm_calls(host):
    return [c for c in calls(host) if c.startswith("nmcli")]


def keyfile(host, name):
    return host["nm"] / f"20-spatium-netif-{name}.nmconnection"


def eth(name="ens19", **over):
    row = {
        "name": name,
        "kind": "ethernet",
        "parent": None,
        "vlan_id": None,
        "addresses": ["10.9.0.2/24"],
        "mtu": None,
        "up": True,
        "routes": [],
    }
    row.update(over)
    return row


def vlan(**over):
    row = eth(
        "ens19.200",
        kind="vlan",
        parent="ens19",
        vlan_id=200,
        addresses=["10.10.0.2/24"],
    )
    row.update(over)
    return row


# ── rendering + apply ────────────────────────────────────────────────


def test_an_ethernet_interface_renders_to_a_private_never_default_keyfile(host):
    proc = apply(
        host,
        [
            eth(
                mtu=1400,
                routes=[
                    {"destination": "172.16.5.0/24", "gateway": "10.9.0.1", "metric": 50}
                ],
            )
        ],
    )
    assert proc.returncode == 0, proc.stderr
    kf = keyfile(host, "ens19")
    body = kf.read_text()
    assert "id=spatium-netif-ens19" in body
    assert "type=ethernet" in body
    assert "interface-name=ens19" in body
    assert "mtu=1400" in body
    assert "address1=10.9.0.2/24" in body
    assert "route1=172.16.5.0/24,10.9.0.1,50" in body
    # An additional interface must never become the node's way out.
    assert body.count("never-default=true") == 1
    assert "[ipv6]\nmethod=disabled" in body
    # NetworkManager refuses a keyfile that is not mode 0600.
    assert stat.S_IMODE(kf.stat().st_mode) == 0o600


def test_a_vlan_renders_its_parent_and_id_and_is_brought_up_after_the_parent(host):
    proc = apply(host, [vlan(), eth()])
    assert proc.returncode == 0, proc.stderr
    body = keyfile(host, "ens19.200").read_text()
    assert "type=vlan" in body
    assert "[vlan]\nid=200\nparent=ens19" in body
    ups = [c for c in nm_calls(host) if "connection up" in c]
    assert [u.split()[-1] for u in ups] == [
        "spatium-netif-ens19",
        "spatium-netif-ens19.200",
    ]
    # reload comes first so NM has read the files it is asked to bring up.
    assert nm_calls(host)[0] == "nmcli connection reload"


def test_ipv6_and_dual_stack_render_per_family(host):
    apply(host, [eth(addresses=["10.9.0.2/24", "fd00:9::2/64"])])
    body = keyfile(host, "ens19").read_text()
    assert "[ipv4]\nmethod=manual\naddress1=10.9.0.2/24" in body
    assert "[ipv6]\nmethod=manual\naddress1=fd00:9::2/64" in body


def test_a_link_set_down_is_not_autoconnected_and_is_brought_down(host):
    apply(host, [eth(up=False)])
    assert "autoconnect=false" in keyfile(host, "ens19").read_text()
    assert any("connection down id spatium-netif-ens19" in c for c in nm_calls(host))
    assert status(host)["interfaces"]["ens19"].startswith("inactive")


def test_apply_arms_a_deadline_records_the_hash_and_consumes_the_trigger(host):
    before = time.time()
    proc = apply(host, [eth()], hash_="abc", revert=120)
    assert proc.returncode == 0, proc.stderr
    st = status(host)
    assert st["state"] == "pending-confirm"
    assert st["hash"] == "abc"
    assert st["interfaces"] == {"ens19": "active"}
    deadline = int((host["state"] / "netif-revert-deadline").read_text())
    assert before + 119 <= deadline <= time.time() + 121
    assert (host["state"] / "netif-config-hash").read_text().strip() == "abc"
    assert not (host["state"] / "netif-config-pending").exists()
    assert list(host["state"].glob("netif-config-pending.done.*"))


def test_the_installer_owned_profile_is_never_touched(host):
    primary = host["nm"] / "10-spatium-static.nmconnection"
    before = primary.read_text()
    apply(host, [eth()])
    apply(host, [], hash_="h2")
    assert primary.read_text() == before


def test_a_link_with_no_carrier_is_inactive_not_a_failed_apply(host):
    proc = apply(
        host,
        [eth()],
        env_extra={
            "STUB_NMCLI_FAIL": "connection up id spatium-netif-ens19",
            "STUB_NMCLI_MSG": "Connection activation failed: carrier not present",
        },
    )
    assert proc.returncode == 0
    st = status(host)
    assert st["state"] == "pending-confirm"
    assert "carrier not present" in st["interfaces"]["ens19"]
    assert keyfile(host, "ens19").exists()


# ── the host does not trust the control plane ────────────────────────


@pytest.mark.parametrize(
    ("iface", "why"),
    [
        (eth("ens18"), "primary interface"),
        (eth("ens18", addresses=[]), "primary interface"),
    ],
)
def test_the_primary_interface_is_refused_by_the_host(host, iface, why):
    proc = apply(host, [iface])
    assert proc.returncode == 1
    st = status(host)
    assert st["state"] == "failed"
    assert why in st["error"]
    assert not list(host["nm"].glob("20-spatium-netif-*"))
    assert not (host["state"] / "netif-revert-deadline").exists()
    assert not (host["state"] / "netif-config-hash").exists()
    assert list(host["state"].glob("netif-config-pending.failed.*"))


def test_the_interface_carrying_the_default_route_is_refused_even_if_state_is_silent(host):
    (host["root"] / "etc/spatiumddi/network-status").write_text("MODE=dhcp\n")
    proc = apply(host, [eth("ens18")])
    assert proc.returncode == 1
    assert "default route" in status(host)["error"]


@pytest.mark.parametrize(
    "bad",
    [
        eth(routes=[{"destination": "0.0.0.0/0", "gateway": "10.9.0.1"}]),
        eth(addresses=["not-an-address"]),
        eth(name="bad name"),
        eth(mtu=10),
        vlan(vlan_id=5000),
        {**eth(), "kind": "wormhole"},
    ],
)
def test_a_payload_the_host_will_not_apply_leaves_no_trace(host, bad):
    proc = apply(host, [bad])
    assert proc.returncode == 1
    assert status(host)["state"] == "failed"
    assert not list(host["nm"].glob("20-spatium-netif-*"))
    assert nm_calls(host) == []


def test_a_missing_networkmanager_is_a_refusal_not_a_silent_success(host):
    (host["stub"] / "nmcli").unlink()
    proc = run_without_nmcli(host)
    assert proc.returncode == 1
    assert "NetworkManager" in status(host)["error"]


def run_without_nmcli(host):
    trigger(host, [eth()])
    env = {
        **os.environ,
        "SPATIUM_NETIF_ROOT": str(host["root"]),
        "PATH": f"{host['stub']}:/nonexistent",
        "STUB_CALLS": str(host["calls"]),
        "STUB_DIR": str(host["stub"]),
    }
    return subprocess.run(
        [sys.executable, str(RUNNER)], env=env, capture_output=True, text=True, timeout=60
    )


# ── idempotence ──────────────────────────────────────────────────────


def test_reapplying_the_same_config_changes_nothing_and_arms_no_window(host):
    apply(host, [eth()], hash_="h1")
    # Confirm it so the first window is closed.
    (host["state"] / "netif-confirm").write_text("h1\n")
    run(host, "--tick")
    assert not (host["state"] / "netif-revert-deadline").exists()
    first = keyfile(host, "ens19").read_text()
    host["calls"].write_text("")

    proc = apply(host, [eth()], hash_="h1")
    assert proc.returncode == 0
    assert keyfile(host, "ens19").read_text() == first
    assert nm_calls(host) == []  # no reload, no re-activation
    assert not (host["state"] / "netif-revert-deadline").exists()
    assert status(host)["state"] == "applied"


def test_disabling_with_nothing_managed_is_a_quiet_no_op(host):
    """Every existing appliance fires one 'disabled' trigger on upgrade."""
    proc = apply(host, [], hash_="empty")
    assert proc.returncode == 0
    assert nm_calls(host) == []
    assert not (host["state"] / "netif-revert-deadline").exists()
    assert (host["state"] / "netif-config-hash").read_text().strip() == "empty"


def test_removing_an_interface_deletes_only_its_profile(host):
    apply(host, [eth(), eth("ens20", addresses=["10.8.0.2/24"])], hash_="h1")
    apply(host, [eth()], hash_="h2")
    assert keyfile(host, "ens19").exists()
    assert not keyfile(host, "ens20").exists()


# ── rollback ─────────────────────────────────────────────────────────


def _confirmed(host, interfaces, hash_):
    apply(host, interfaces, hash_=hash_)
    (host["state"] / "netif-confirm").write_text(hash_ + "\n")
    run(host, "--tick")


def test_a_confirmed_apply_is_kept(host):
    apply(host, [eth()], hash_="h1")
    (host["state"] / "netif-confirm").write_text("h1\n")
    proc = run(host, "--tick")
    assert proc.returncode == 0
    assert keyfile(host, "ens19").exists()
    assert status(host)["state"] == "applied"
    assert not (host["state"] / "netif-revert-deadline").exists()
    assert not (host["state"] / "netif-confirm").exists()


def test_an_unconfirmed_apply_inside_the_window_is_left_alone(host):
    apply(host, [eth()], hash_="h1", revert=600)
    run(host, "--tick")
    assert keyfile(host, "ens19").exists()
    assert status(host)["state"] == "pending-confirm"


def test_no_confirm_by_the_deadline_restores_the_previous_profiles(host):
    _confirmed(host, [eth(addresses=["10.9.0.2/24"])], "h1")
    good = keyfile(host, "ens19").read_text()

    apply(host, [eth(addresses=["10.9.0.99/24"]), eth("ens20", addresses=["10.8.0.2/24"])], hash_="h2")
    assert keyfile(host, "ens19").read_text() != good
    assert keyfile(host, "ens20").exists()

    # The control plane never confirms; the deadline passes.
    (host["state"] / "netif-revert-deadline").write_text(f"{int(time.time()) - 1}\n")
    host["calls"].write_text("")
    proc = run(host, "--tick")
    assert proc.returncode == 0

    assert keyfile(host, "ens19").read_text() == good
    assert not keyfile(host, "ens20").exists()
    st = status(host)
    assert st["state"] == "reverted"
    assert "could not reach the control plane" in st["error"]
    # Settled, not re-fired: the rolled-back hash stays recorded so the
    # supervisor does not retry the same outage every backoff window.
    assert (host["state"] / "netif-config-hash").read_text().strip() == "h2"
    assert not (host["state"] / "netif-revert-deadline").exists()
    assert nm_calls(host)[0] == "nmcli connection reload"
    assert any("up id spatium-netif-ens19" in c for c in nm_calls(host))


def test_a_first_ever_apply_that_is_not_confirmed_leaves_nothing_behind(host):
    apply(host, [eth(), vlan()], hash_="h1")
    (host["state"] / "netif-revert-deadline").write_text(f"{int(time.time()) - 1}\n")
    run(host, "--tick")
    assert not list(host["nm"].glob("20-spatium-netif-*"))
    assert status(host)["state"] == "reverted"
    # The installer's profile survived the whole thing.
    assert (host["nm"] / "10-spatium-static.nmconnection").exists()


def test_a_confirm_for_a_different_config_does_not_keep_the_change(host):
    apply(host, [eth()], hash_="h2", revert=600)
    (host["state"] / "netif-confirm").write_text("some-older-hash\n")
    run(host, "--tick")
    assert (host["state"] / "netif-revert-deadline").exists()
    assert not (host["state"] / "netif-confirm").exists()
    assert status(host)["state"] == "pending-confirm"


def test_a_planted_symlink_deadline_is_ignored_not_obeyed(host):
    apply(host, [eth()], hash_="h1")
    real = host["tmp"] / "elsewhere"
    real.write_text(f"{int(time.time()) - 1}\n")
    (host["state"] / "netif-revert-deadline").unlink()
    (host["state"] / "netif-revert-deadline").symlink_to(real)
    run(host, "--tick")
    assert keyfile(host, "ens19").exists()  # no revert was driven by it
    assert not (host["state"] / "netif-revert-deadline").exists()


def test_a_failed_reload_restores_what_was_there_and_claims_nothing(host):
    _confirmed(host, [eth()], "h1")
    good = keyfile(host, "ens19").read_text()
    proc = apply(
        host,
        [eth(addresses=["10.9.0.77/24"])],
        hash_="h2",
        env_extra={"STUB_NMCLI_FAIL": "connection reload", "STUB_NMCLI_MSG": "boom"},
    )
    assert proc.returncode == 1
    assert keyfile(host, "ens19").read_text() == good
    st = status(host)
    assert st["state"] == "failed"
    assert "boom" in st["error"]
    assert (host["state"] / "netif-config-hash").read_text().strip() == "h1"
    assert not (host["state"] / "netif-revert-deadline").exists()


# ── inventory ────────────────────────────────────────────────────────


def test_tick_publishes_the_inventory_the_control_plane_validates_against(host):
    proc = run(host, "--tick")
    assert proc.returncode == 0
    inv = json.loads((host["state"] / "netif-inventory.json").read_text())
    assert abs(inv["at_epoch"] - time.time()) < 30
    assert inv["primary_interface"] == "ens18"
    assert inv["default_devs"] == ["ens18"]
    by = {n["name"]: n for n in inv["interfaces"]}
    assert "lo" not in by and "veth1234" not in by  # noise is filtered
    assert by["ens18"]["addresses"] == ["192.168.1.10/24"]
    assert by["ens18"]["kind"] == "ethernet"
    assert by["ens19.100"]["kind"] == "vlan"
    assert by["ens19.100"]["parent"] == "ens19"
    assert by["ens19.100"]["vlan_id"] == 100
    assert {"dst": "default", "gateway": "192.168.1.1", "dev": "ens18", "metric": 100, "protocol": None} in inv["routes"]


# ── shipped wiring ───────────────────────────────────────────────────


def test_the_runner_is_executable_and_the_units_point_at_what_the_supervisor_writes():
    assert RUNNER.stat().st_mode & stat.S_IXUSR
    path_unit = (UNITS / "spatiumddi-netif-reload.path").read_text()
    sup = (
        REPO / "agent/supervisor/spatium_supervisor/appliance_state.py"
    ).read_text()
    # The supervisor's /var/lib/spatiumddi-host is the host's /var/lib/spatiumddi.
    m = re.search(r'_NETIF_TRIGGER_FILE = Path\(\s*"/var/lib/spatiumddi-host/(.+?)"', sup)
    assert m
    assert f"PathChanged=/var/lib/spatiumddi/{m.group(1)}" in path_unit
    service = (UNITS / "spatiumddi-netif-reload.service").read_text()
    assert "ExecStart=/usr/local/bin/spatiumddi-netif-reload\n" in service
    assert "spatiumddi-trigger-guard /var/lib/spatiumddi/" + m.group(1) in service
    tick = (UNITS / "spatiumddi-netif-tick.service").read_text()
    assert "spatiumddi-netif-reload --tick" in tick


def test_the_image_enables_and_chmods_the_units():
    post = POSTINST.read_text()
    for unit in ("spatiumddi-netif-reload.path", "spatiumddi-netif-tick.timer"):
        assert re.search(rf"^\s+{re.escape(unit)} \\$", post, re.M), unit
    for f in (
        "usr/local/bin/spatiumddi-netif-reload",
        "etc/systemd/system/spatiumddi-netif-reload.path",
        "etc/systemd/system/spatiumddi-netif-reload.service",
        "etc/systemd/system/spatiumddi-netif-tick.service",
        "etc/systemd/system/spatiumddi-netif-tick.timer",
    ):
        assert f'"$BUILDROOT/{f}"' in post, f


def test_the_console_adopt_tool_does_not_report_our_profiles_as_strays():
    import importlib.machinery
    import importlib.util

    tool = BIN / "spatium-network-adopt"
    loader = importlib.machinery.SourceFileLoader("spatium_network_adopt_4428", str(tool))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        nm = Path(d)
        for n in ("10-spatium-static", "20-spatium-netif-ens19", "stray-nmtui"):
            (nm / f"{n}.nmconnection").write_text("")
        mod.NM_DIR = nm
        mod.STATIC_KEYFILE = nm / "10-spatium-static.nmconnection"
        mod.DHCP_KEYFILE = nm / "10-spatium-dhcp.nmconnection"
        assert mod._extra_profiles() == ["stray-nmtui.nmconnection"]

"""cloud-init stays off on an installed appliance (issue #1511).

spatium-install only masked cloud-init's units. The masks land in the /etc
overlay, which etc.mount brings up after systemd has loaded its units, so they
never took effect at boot (and cloud-init 25.1 renamed the units too). With
the preseed's CIDATA drive still attached, init-local wrote a DHCP profile
(``cloud-init-<iface>.nmconnection``) beside the STATE one. Once a DHCP
server answered on the segment, a rebooted node could come up on a lease.

Two halves:

* the installer writes ``/etc/cloud/cloud-init.disabled``, which every
  cloud-init unit checks when it starts (after etc.mount), and masks the 25.1
  unit names too;
* ``spatium-etc-render`` heals nodes installed before the fix: on a node
  spatium-install set up, it sets the marker and drops leftover
  ``cloud-init-*.nmconnection`` profiles. A node the installer did not set
  up (a cloud image) keeps cloud-init and its profiles.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from _installer_source import BIN, extract_fn

ETC_RENDER = BIN / "spatium-etc-render"

_STATIC = """network_mode: static
network_interface: eth0
network_ip: 10.0.0.5
network_prefix: 24
network_gateway: 10.0.0.1"""

_CI_PROFILE = "cloud-init-ens18.nmconnection"


# ── installer ─────────────────────────────────────────────────────────


def _do_install_code() -> str:
    body = extract_fn("do_install")
    return "\n".join(ln.split("#", 1)[0] for ln in body.splitlines())


def test_the_installer_writes_the_cloud_init_disabled_marker():
    code = _do_install_code()
    assert re.search(r'"\$MOUNT/etc/cloud/cloud-init\.disabled"', code), (
        "do_install must create /etc/cloud/cloud-init.disabled on the target"
    )


def test_the_installer_masks_the_cloud_init_25_unit_names():
    code = _do_install_code()
    mask = re.search(r"systemctl mask(.*?)>>", code, re.DOTALL)
    assert mask, "do_install no longer masks cloud-init at all"
    for unit in ("cloud-init-main.service", "cloud-init-network.service"):
        assert unit in mask.group(1), f"{unit} is not masked"


# ── etc-render heal ───────────────────────────────────────────────────


def _run_render(tmp_path: Path, *, marker: bool, old_mask: bool) -> Path:
    """Run the shipped ``spatium-etc-render`` against a temp root.

    Same approach as test_network_mtu.py: the paths are rebased with string
    replacement so what runs is the shipped text.
    """
    root = tmp_path / "root"
    state = root / "var/lib/spatium-state"
    state.mkdir(parents=True)
    (state / "spatium-config.yaml").write_text(_STATIC + "\n", encoding="utf-8")
    conns = root / "etc/NetworkManager/system-connections"
    conns.mkdir(parents=True)
    (conns / _CI_PROFILE).write_text("[ipv4]\nmethod=auto\n", encoding="utf-8")
    units = root / "etc/systemd/system"
    units.mkdir(parents=True)
    if old_mask:
        os.symlink("/dev/null", units / "cloud-init-local.service")
    if marker:
        (root / "etc/cloud").mkdir(parents=True)
        (root / "etc/cloud/cloud-init.disabled").write_text("", encoding="utf-8")

    src = ETC_RENDER.read_text(encoding="utf-8")
    src = re.sub(r"^STATE_DIR=.*$", f"STATE_DIR={state}", src, count=1, flags=re.M)
    src = re.sub(r"^LOG=.*$", f"LOG={root}/render.log", src, count=1, flags=re.M)
    for path in ("/etc/NetworkManager", "/etc/spatiumddi", "/etc/cloud", "/etc/systemd/system"):
        src = src.replace(path, f"{root}{path}")
    script = tmp_path / "render.sh"
    script.write_text(src, encoding="utf-8")
    subprocess.run(["sh", str(script)], capture_output=True, text=True, check=False)
    return root


def test_a_pre_fix_install_loses_the_cloud_init_profile_and_gets_the_marker(tmp_path):
    """Installed before #1511: old masks, no marker, leftover profile."""
    root = _run_render(tmp_path, marker=False, old_mask=True)
    conns = root / "etc/NetworkManager/system-connections"
    assert not (conns / _CI_PROFILE).exists()
    assert (root / "etc/cloud/cloud-init.disabled").exists()
    # The STATE profile is still rendered next to it.
    assert (conns / "10-spatium-static.nmconnection").exists()


def test_a_fixed_install_drops_a_profile_that_appears_anyway(tmp_path):
    root = _run_render(tmp_path, marker=True, old_mask=False)
    assert not (root / "etc/NetworkManager/system-connections" / _CI_PROFILE).exists()


def test_a_node_the_installer_did_not_set_up_keeps_cloud_init(tmp_path):
    """No marker, no mask: cloud-init is in charge, leave it alone."""
    root = _run_render(tmp_path, marker=False, old_mask=False)
    assert (root / "etc/NetworkManager/system-connections" / _CI_PROFILE).exists()
    assert not (root / "etc/cloud/cloud-init.disabled").exists()

"""A node's reboot must stop its pods through the kubelet first (#1976).

The Fleet reboot that finishes a per-node upgrade runs ``systemctl reboot``
on the node. Without a kubelet shutdown grace period, systemd then stopped
every container at once while the kubelet died with k3s (KillMode=process),
so the cluster was never told: the node's pods stayed Ready in their
Services' endpoints until node-lifecycle marked the node Unknown about 70 s
after its last heartbeat, and were evicted 30 s after that.

The appliance turns on the kubelet's graceful node shutdown with three
pieces that have to agree, and this test keeps them agreeing:

  * a KubeletConfiguration drop-in in the slot's /usr with the grace periods;
  * an ExecStartPre of k3s.service that copies it, before k3s starts, into
    the directory k3s hands the kubelet as ``--config-dir``
    (``<data-dir>/agent/etc/kubelet.conf.d``, where k3s writes its own
    ``00-k3s-defaults.conf``; the kubelet reads only ``*.conf`` there, in
    name order, later files winning);
  * a logind drop-in letting a delay lock hold the shutdown for at least the
    whole grace period. The image's unattended-upgrades sets 30 s, and with
    less than the grace period the kubelet starts without its shutdown
    manager. logind applies its drop-ins in name order, the last value
    winning, so ours must sort after that package's.

    python3 -m pytest appliance/tests/test_kubelet_graceful_shutdown.py -v
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
EXTRA = REPO / "appliance" / "mkosi.extra"
UNIT = EXTRA / "etc" / "systemd" / "system" / "k3s.service"
DROPIN_NAME = "50-spatium-graceful-shutdown.conf"
DROPIN_SRC = "/usr/lib/spatiumddi/kubelet.conf.d/" + DROPIN_NAME
# k3s: pkg/agent/config/config.go joins <data-dir>, "agent", "etc",
# "kubelet.conf.d"; config.yaml sets no data-dir, so it is the default.
KUBELET_CONFIG_DIR = "/var/lib/rancher/k3s/agent/etc/kubelet.conf.d"
LOGIND_DIR = EXTRA / "usr" / "lib" / "systemd" / "logind.conf.d"
LOGIND_DROPIN = LOGIND_DIR / "zz-spatium-kubelet-shutdown.conf"
MKOSI_CONF = REPO / "appliance" / "mkosi.conf"

pytestmark = pytest.mark.skipif(not UNIT.is_file(), reason="appliance tree not present")

_DURATION = re.compile(r"(\d+(?:\.\d+)?)(h|m|s)")


def _seconds(value: str) -> float:
    """A Go duration as the kubelet's config takes it ("60s", "1m30s")."""
    text = str(value).strip()
    parts = _DURATION.findall(text)
    assert parts and "".join(n + u for n, u in parts) == text, f"not a duration: {value!r}"
    return sum(float(n) * {"h": 3600, "m": 60, "s": 1}[u] for n, u in parts)


def _kubelet_config() -> dict:
    return yaml.safe_load((EXTRA / DROPIN_SRC.lstrip("/")).read_text())


def _unit_lines() -> list[str]:
    return [ln.strip() for ln in UNIT.read_text().splitlines()]


def test_drop_in_turns_graceful_node_shutdown_on() -> None:
    cfg = _kubelet_config()
    assert cfg.get("apiVersion") == "kubelet.config.k8s.io/v1beta1"
    assert cfg.get("kind") == "KubeletConfiguration"
    total = _seconds(cfg["shutdownGracePeriod"])
    critical = _seconds(cfg["shutdownGracePeriodCriticalPods"])
    # 0 turns the feature off; a critical share equal to the whole period
    # leaves ordinary pods (every SpatiumDDI workload) no time at all.
    assert total > 0, "shutdownGracePeriod 0 disables graceful node shutdown"
    assert 0 < critical < total, (total, critical)
    # The control plane's own pods take up to 30 s to stop
    # (terminationGracePeriodSeconds default); give them that much at least.
    assert total - critical >= 30, (total, critical)


def test_drop_in_carries_nothing_but_the_shutdown_settings() -> None:
    """It is merged over k3s's own defaults, so any other field would
    silently override what k3s computed for this node."""
    assert set(_kubelet_config()) == {
        "apiVersion",
        "kind",
        "shutdownGracePeriod",
        "shutdownGracePeriodCriticalPods",
    }


def test_logind_lets_the_kubelet_hold_the_shutdown_for_the_whole_period() -> None:
    parser = configparser.ConfigParser()
    parser.read_string(LOGIND_DROPIN.read_text())
    delay = _seconds(parser["Login"]["InhibitDelayMaxSec"] + "s")
    assert delay >= _seconds(_kubelet_config()["shutdownGracePeriod"]), (
        "logind would end the kubelet's delay lock before its grace period, and the "
        "kubelet would start without its shutdown manager"
    )


def test_logind_drop_in_sorts_after_every_other_one() -> None:
    """logind applies its drop-ins in file-name order, across /etc, /run and
    /usr/lib alike, and the last value wins. unattended-upgrades, which the
    image installs, ships unattended-upgrades-logind-maxdelay.conf with
    InhibitDelayMaxSec=30: a name that sorts after every numbered drop-in,
    the kubelet's own 99-kubelet.conf included. A nightly-20261024 node read
    30 s from it, so a numbered name here would leave the kubelet short."""
    packages = re.findall(r"^\s+([a-z0-9][a-z0-9.+-]*)\s*$", MKOSI_CONF.read_text(), re.M)
    assert "unattended-upgrades" in packages, (
        "the image no longer installs unattended-upgrades: re-check what else "
        "ships a logind drop-in before renaming this file"
    )
    others = [p.name for p in LOGIND_DIR.glob("*.conf") if p != LOGIND_DROPIN]
    names = others + ["unattended-upgrades-logind-maxdelay.conf", "99-kubelet.conf"]
    assert all(LOGIND_DROPIN.name > n for n in names), (LOGIND_DROPIN.name, sorted(names))


def test_k3s_unit_installs_the_drop_in_before_k3s_starts() -> None:
    lines = _unit_lines()
    mkdir = f"ExecStartPre=-/usr/bin/install -d -m 0700 {KUBELET_CONFIG_DIR}"
    copy = (
        f"ExecStartPre=-/usr/bin/install -m 0600 {DROPIN_SRC} "
        f"{KUBELET_CONFIG_DIR}/{DROPIN_NAME}"
    )
    assert mkdir in lines, "k3s.service no longer creates k3s's kubelet drop-in directory"
    assert copy in lines, "k3s.service no longer installs the graceful-shutdown drop-in"
    assert lines.index(mkdir) < lines.index(copy) < lines.index(
        "ExecStart=/usr/local/bin/k3s server"
    )


def test_the_unit_names_the_file_the_image_ships() -> None:
    assert (EXTRA / DROPIN_SRC.lstrip("/")).is_file()


def test_drop_in_sorts_after_k3s_defaults() -> None:
    """The kubelet applies the drop-ins in name order; k3s writes
    00-k3s-defaults.conf (and 10-cli-config.conf for a --kubelet-arg=config),
    and a later file wins, so ours must sort after both. Only *.conf files are
    read at all."""
    assert DROPIN_NAME.endswith(".conf")
    assert sorted([DROPIN_NAME, "00-k3s-defaults.conf", "10-cli-config.conf"])[-1] == DROPIN_NAME

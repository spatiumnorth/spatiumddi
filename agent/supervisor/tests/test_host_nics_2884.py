"""#2884 — Fleet's ``capabilities.host_nics`` reports the HOST's NICs.

The old implementation read ``/sys/class/net`` inside the supervisor
pod's netns (non-hostNetwork), so it reported the pod's ``eth0`` while
``appliance.host_interfaces`` (udev) said ``cni0, enp1s0``.  Both now
come from ``appliance_state.host_network_interfaces()``.
"""

from __future__ import annotations

from spatium_supervisor import appliance_state as st
from spatium_supervisor import heartbeat as hb


def test_capabilities_host_nics_is_the_udev_list(monkeypatch):
    monkeypatch.setattr(st, "host_network_interfaces", lambda: ["cni0", "enp1s0"])
    caps = hb._capabilities_payload()
    assert caps["host_nics"] == ["cni0", "enp1s0"]
    assert "eth0" not in caps["host_nics"]


def test_host_nics_ignores_the_pod_sys_class_net(monkeypatch):
    import os

    # Pod netns would show eth0; it must not leak in.
    monkeypatch.setattr(os, "listdir", lambda p: ["lo", "eth0"])
    monkeypatch.setattr(st, "host_network_interfaces", lambda: ["enp1s0"])
    assert hb._detect_host_nics() == ["enp1s0"]

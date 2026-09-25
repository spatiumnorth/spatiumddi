"""The appliance's kubelet evicts on memory pressure before the kernel does (#1124).

k3s's own kubelet defaults (``pkg/daemons/agent/agent.go``, ``defaultKubeletConfig``)
set ``evictionHard`` to the two disk signals — ``nodefs.available`` and
``imagefs.available`` at 5 % — and drop the kubelet's upstream
``memory.available<100Mi``. With no memory signal the eviction manager, which
ranks by PriorityClass (#983), never sees memory exhaustion; the kernel's global
OOM killer, which ranks by ``oom_score_adj``, does — and on a 6 GiB node beside
a Guaranteed hog it killed the api's uvicorn (container restart reason
``Error``, not ``OOMKilled``: the kill came from the host, not the pod's cgroup).

``/etc/rancher/k3s/config.yaml`` now passes the kubelet a ``memory.available``
hard threshold beside k3s's restated disk floors, a short pressure-transition
period, and kube/system reserves. These tests read the shipped file the way
k3s does — a YAML list of ``flag=value`` strings, each value's commas kept
(k3s sets ``DisableSliceFlagSeparator``) — and pin the invariants the row
``boot/kubelet_memory_eviction_threshold`` grades on a live node:

  * a ``memory.available`` hard threshold at or above the kubelet's own 100Mi
  * ``nodefs.available`` and ``imagefs.available`` still in ``--eviction-hard``
    (the flag REPLACES k3s's map, so a memory-only value silently loses the
    disk axis the #983 ordering was proven on)
  * every quantity parses, the transition period is a duration no longer than
    Kubernetes' 5m default, and the whole reservation leaves a 4 GiB node —
    the appliance's floor — more than half of its memory allocatable

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_k3s_kubelet_eviction.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "appliance" / "mkosi.extra" / "etc" / "rancher" / "k3s" / "config.yaml"

pytestmark = pytest.mark.skipif(not CONFIG.is_file(), reason="appliance tree not present")

# kubernetes pkg/kubelet/eviction/defaults_linux.go: DefaultEvictionHard["memory.available"]
KUBELET_DEFAULT_MEMORY_AVAILABLE_MIB = 100
# k3s pkg/daemons/agent/agent.go defaultKubeletConfig(): the map --eviction-hard replaces
K3S_DISK_FLOORS = {"nodefs.available": "5%", "imagefs.available": "5%"}
# Kubernetes' own evictionPressureTransitionPeriod default (k3s sets the same 5m)
KUBERNETES_TRANSITION_DEFAULT_S = 300
# The appliance's memory floor (config.yaml: "a node whose floor is 4 GiB")
FLOOR_NODE_MIB = 4096

_QTY = re.compile(r"^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|k|M|G|T)?$")
_MULT_MIB = {None: 1 / 2**20, "Ki": 1 / 1024, "Mi": 1, "Gi": 1024, "Ti": 1024**2,
             "k": 1e3 / 2**20, "M": 1e6 / 2**20, "G": 1e9 / 2**20, "T": 1e12 / 2**20}
_DURATION = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def quantity_mib(value: str) -> float:
    m = _QTY.match(value)
    assert m, f"{value!r} is not a Kubernetes quantity"
    return float(m.group(1)) * _MULT_MIB[m.group(2)]


def duration_s(value: str) -> int:
    m = _DURATION.match(value)
    assert m and value, f"{value!r} is not a Go duration"
    h, mi, s = (int(x or 0) for x in m.groups())
    return h * 3600 + mi * 60 + s


def kubelet_args() -> dict[str, str]:
    """The ``kubelet-arg`` list as ``{flag: value}`` — one entry per flag, split on
    the first ``=`` exactly as k3s hands ``--<flag>=<value>`` to the kubelet."""
    doc = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    entries = doc["kubelet-arg"]
    assert isinstance(entries, list) and all(isinstance(e, str) for e in entries)
    out: dict[str, str] = {}
    for entry in entries:
        flag, _, value = entry.partition("=")
        assert flag and value, f"kubelet-arg entry {entry!r} is not flag=value"
        assert flag not in out, f"kubelet-arg sets --{flag} twice"
        out[flag] = value
    return out


def langle_map(value: str) -> dict[str, str]:
    """``--eviction-hard`` / ``--eviction-soft``: ``signal<quantity,...``."""
    out: dict[str, str] = {}
    for pair in value.split(","):
        signal, sep, threshold = pair.partition("<")
        assert sep and signal and threshold, f"{pair!r} is not signal<threshold"
        out[signal] = threshold
    return out


def eq_map(value: str) -> dict[str, str]:
    """``--kube-reserved`` / ``--system-reserved`` / grace periods: ``key=value,...``."""
    out: dict[str, str] = {}
    for pair in value.split(","):
        key, sep, val = pair.partition("=")
        assert sep and key and val, f"{pair!r} is not key=value"
        out[key] = val
    return out


# ── the memory signal ────────────────────────────────────────────────────


def test_eviction_hard_carries_a_memory_available_threshold() -> None:
    args = kubelet_args()
    assert "eviction-hard" in args, (
        "config.yaml passes the kubelet no --eviction-hard at all, so k3s's defaults apply: "
        "the two disk floors and no memory signal (#1124)"
    )
    hard = langle_map(args["eviction-hard"])
    assert "memory.available" in hard, (
        "config.yaml passes the kubelet no memory.available eviction threshold: under "
        "memory pressure the kernel's OOM killer, not the PriorityClass ranking, decides "
        "what dies (#1124)"
    )
    assert quantity_mib(hard["memory.available"]) >= KUBELET_DEFAULT_MEMORY_AVAILABLE_MIB


def test_eviction_hard_restates_k3s_disk_floors() -> None:
    """``--eviction-hard`` replaces k3s's whole map. A value that names the memory
    signal alone would drop nodefs/imagefs — the axis #983's ordering was proven on."""
    args = kubelet_args()
    assert "eviction-hard" in args, "no --eviction-hard (#1124)"
    hard = langle_map(args["eviction-hard"])
    for signal, floor in K3S_DISK_FLOORS.items():
        assert hard.get(signal) == floor, f"--eviction-hard lost k3s's {signal}<{floor}"


def test_a_soft_threshold_if_any_has_a_grace_period_above_the_hard_one() -> None:
    args = kubelet_args()
    if "eviction-soft" not in args:
        return
    soft = langle_map(args["eviction-soft"])
    hard = langle_map(args["eviction-hard"])
    grace = eq_map(args.get("eviction-soft-grace-period", ""))
    for signal, threshold in soft.items():
        assert signal in grace, f"eviction-soft {signal} has no grace period (kubelet refuses)"
        duration_s(grace[signal])
        if signal in hard and not threshold.endswith("%"):
            assert quantity_mib(threshold) > quantity_mib(hard[signal])


# ── recovery and the reserves ────────────────────────────────────────────


def test_pressure_transition_period_is_short_enough_for_a_single_node() -> None:
    """The memory-pressure taint keeps every non-DaemonSet pod — the evicted api's
    replacement first of all — off the node for the whole period; on a single-node
    appliance that is the outage."""
    args = kubelet_args()
    assert "eviction-pressure-transition-period" in args, (
        "no --eviction-pressure-transition-period: Kubernetes' 5m applies (#1124)"
    )
    period = duration_s(args["eviction-pressure-transition-period"])
    assert 0 < period < KUBERNETES_TRANSITION_DEFAULT_S


def test_reserves_are_memory_quantities_and_leave_the_floor_node_room() -> None:
    args = kubelet_args()
    for flag in ("kube-reserved", "system-reserved", "eviction-hard"):
        assert flag in args, f"no --{flag} (#1124)"
    kube = quantity_mib(eq_map(args["kube-reserved"])["memory"])
    system = quantity_mib(eq_map(args["system-reserved"])["memory"])
    hard = quantity_mib(langle_map(args["eviction-hard"])["memory.available"])
    reservation = kube + system + hard
    # The kubelet reports Allocatable = capacity - kube - system - hard: the 4 GiB
    # floor node keeps at least half of itself for pods (2 GiB, against the chart's
    # ~1.2 GiB of requests), and a 6 GiB node the 3883Mi the control-plane sizing
    # budgets from (#1115's 2 GiB platform reserve).
    assert FLOOR_NODE_MIB - reservation >= FLOOR_NODE_MIB / 2
    assert reservation == 2048, reservation
    assert 5931 - reservation == 3883


def test_no_enforcement_on_the_host_daemons_themselves() -> None:
    """Reserves without ``--enforce-node-allocatable`` naming kube/system-reserved:
    the kubelet then only caps the kubepods cgroup, and never puts a memory limit
    on k3s, containerd or systemd — a cap there would OOM-kill the control plane
    to protect the pods."""
    args = kubelet_args()
    enforce = args.get("enforce-node-allocatable", "pods")
    assert set(enforce.split(",")) <= {"pods"}
    assert "kube-reserved-cgroup" not in args and "system-reserved-cgroup" not in args


def test_the_image_gc_band_and_log_flush_survive() -> None:
    """The pre-existing kubelet args (#441) are untouched by the eviction ones."""
    args = kubelet_args()
    assert args["image-gc-high-threshold"] == "95"
    assert args["image-gc-low-threshold"] == "85"
    assert args["log-flush-frequency"] == "5s"

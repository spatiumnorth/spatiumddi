"""Appliance-host telemetry + trigger-file writers for the supervisor.

Ported from the DNS / DHCP agents in #170 Wave C1 — appliance-host
state used to be collected independently by each service agent (DNS
+ DHCP each shipped their own copy of slot_state.py). The supervisor
now owns this surface; service agents drop the host bind mounts and
let the supervisor's heartbeat carry the appliance row's telemetry +
fire the trigger files.

Module responsibilities:

* **Read** appliance-host state — deployment kind, slot UUID match,
  grubenv durable default, installed appliance version, last
  upgrade state from the .state sidecar, snmpd + chrony sync status.
* **Write** appliance-host trigger files — slot-upgrade pending,
  reboot pending, snmpd reload, chrony reload. Host-side systemd
  ``.path`` units (``spatiumddi-slot-upgrade.path`` /
  ``spatiumddi-reboot-agent.path`` / ``spatiumddi-snmp-reload.path``
  / ``spatiumddi-chrony-reload.path``) notice the writes and fire
  the runner scripts.

Reads happen through host bind mounts the supervisor compose entry
keeps (``/etc/spatiumddi-host`` for role + version, ``/boot/efi-host``
for grubenv, ``/var/lib/spatiumddi-host/release-state`` for the
trigger surface, ``/run/udev`` for slot-UUID lookup). On non-
appliance hosts (dev compose, k8s) the mounts don't exist; every
read returns ``None`` and every trigger-file write is short-
circuited by ``detect_deployment_kind()``'s appliance gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

# Bind-mount targets the appliance docker-compose exposes. Same paths
# the api container uses (just different mount source on the agent
# side: agent compose mounts the agent appliance's host, not the
# control plane's). Falling back to None on read failure keeps the
# heartbeat payload clean across non-appliance deploys.
_HOST_ROLE_CONFIG = Path("/etc/spatiumddi-host/role-config")
#: #1017 — what spatium-etc-render actually applied to the network
#: profile at this boot. Same bind mount role-config arrives through, so
#: reading it needs no chart change and no new hostPath.
_HOST_NETWORK_STATUS = Path("/etc/spatiumddi-host/network-status")
_HOST_RELEASE = Path("/etc/spatiumddi-host/appliance-release")
_HOST_GRUBENV = Path("/boot/efi-host/grub/grubenv")
_HOST_SLOT_STATE = Path(
    "/var/lib/spatiumddi-host/release-state/slot-upgrade-pending.state"
)
_PROC_CMDLINE = Path("/proc/cmdline")
_UDEV_DATA = Path("/run/udev/data")

_UUID_RE = re.compile(r"root=UUID=([0-9a-fA-F-]+)")

# #59 — ephemeral / uninteresting net devices the operator would never
# pick as a capture interface (pod veths, docker/cni internal, tunnels).
_IFACE_SKIP_RE = re.compile(r"^(lo$|veth|vnet|docker|kube-|cali|tunl|nodelocaldns)")


def host_network_interfaces() -> list[str]:
    """Host NICs (e.g. ``ens18``, ``cni0``) for the appliance-vantage
    packet-capture interface picker (#59).

    The supervisor pod isn't ``hostNetwork``, so its own
    ``/sys/class/net`` shows pod veths — NOT the host's real NICs. But
    udev writes every host net device into ``/run/udev/data/n<ifindex>``
    with an ``E:ID_NET_NAME=<name>`` line (``ID_NET_NAME_PATH`` as a
    fallback), and ``/run/udev`` is already bind-mounted into the
    supervisor — the same source the slot detector uses for block
    devices. Ephemeral pod veths + loopback are filtered. Returns a
    sorted, de-duplicated list; empty on non-appliance hosts or before
    udev populates net entries (the caller only ships a non-empty list,
    so a transient empty read never wipes the control plane's set).
    """
    names: set[str] = set()
    try:
        entries = list(_UDEV_DATA.iterdir())
    except OSError:
        return []
    for entry in entries:
        # ``n<ifindex>`` files are network devices (``b…`` block, ``c…``
        # char, ``+…`` subsystem tags are irrelevant here).
        if not (entry.name.startswith("n") and entry.name[1:].isdigit()):
            continue
        props, _links = _udev_properties(entry)
        name = props.get("ID_NET_NAME") or props.get("ID_NET_NAME_PATH")
        if name and not _IFACE_SKIP_RE.match(name):
            names.add(name)
    return sorted(names)


def detect_runtime() -> str:
    """Issue #183 Phase 7 — the appliance is k3s-only.

    Pre-Phase-7 this function branched on systemctl-is-active-k3s to
    pick between the docker-compose and k3s lifecycle paths. Phase 7
    retires the compose path entirely; the function survives as a
    pure constant for any caller that still reads the runtime tag
    (heartbeat telemetry, console rendering, etc.).
    """
    return "k3s"


def detect_deployment_kind() -> str:
    """Best-effort introspection of where the agent is running.

    Order matters: appliance signal (role-config bind mount) wins over
    k8s env vars (which can be present on docker-compose hosts that
    happen to ship a kubectl context) which wins over docker. Returns
    one of ``appliance`` / ``docker`` / ``k8s`` / ``unknown``.
    """
    if _HOST_ROLE_CONFIG.exists():
        return "appliance"
    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "k8s"
    # Inside a docker container the kernel exposes /.dockerenv. Also
    # check cgroups as a backup for newer runtimes (podman, rootless)
    # that drop the marker file.
    if Path("/.dockerenv").exists():
        return "docker"
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        # /proc/1/cgroup is optional fallback for runtimes that don't
        # drop /.dockerenv (podman / rootless). When the read fails
        # (cgroups v1 / v2 layout mismatch, namespaced /proc that
        # hides PID 1) treat it as "unknown" — the Fleet UI renders
        # those rows with a Manual upgrade modal instead of an
        # Upgrade button.
        return "unknown"
    if "docker" in cgroup or "containerd" in cgroup:
        return "docker"
    return "unknown"


def read_installed_version() -> str | None:
    """Parse ``APPLIANCE_VERSION=`` out of ``/etc/spatiumddi-host/appliance-release``.

    Only meaningful on appliance deploys; returns None when the file
    isn't mounted (docker / k8s) or doesn't carry the key.
    """
    if not _HOST_RELEASE.exists():
        return None
    try:
        text = _HOST_RELEASE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("APPLIANCE_VERSION="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


# #272 — two installer-role variants: ``control-plane`` (the brain +
# k3s etcd seed) and ``appliance`` (a data-plane node that pairs with
# a remote control plane). The supervisor reports its variant on every
# heartbeat so the Fleet UI can split rows into Control plane vs
# Service agents, and the label reconciler can apply the correct
# per-role labels (control-plane ⇒ control-plane label;
# appliance ⇒ operator-assigned).
_KNOWN_VARIANTS = frozenset({"control-plane", "appliance"})
# Pre-#272 installs wrote one of three variant strings; normalise them
# to the two canonical values so a not-yet-reinstalled box reports a
# clean variant (full-stack / frontend-core were both control planes;
# application was the data-plane node).
_LEGACY_VARIANT_ALIASES = {
    "full-stack": "control-plane",
    "frontend-core": "control-plane",
    "application": "appliance",
}


def detect_architecture() -> str | None:
    """The machine's CPU architecture as ``amd64`` / ``arm64``.

    ``platform.machine()`` is ``uname -m`` without the subprocess. The
    names are normalised to the pair the artifacts already use
    (``fetch-k3s.sh``, ``BAKE_SAVE_PLATFORM``, the release asset names),
    so the control plane never has to map between two spellings —
    see ``app/services/appliance/architecture.py`` for why that matters.

    Returns None for anything unrecognised rather than passing the raw
    string through: the control plane treats None as UNKNOWN and skips
    the comparison, whereas an unrecognised value would compare unequal
    to a real one and refuse every upgrade on, say, a riscv64 port.

    **This reads the CONTAINER's architecture**, which is the host's on
    every appliance — the supervisor image is baked per-arch alongside
    the rootfs, and nothing on an appliance runs under binfmt emulation.
    A deliberately cross-run container (an amd64 supervisor on an arm64
    host under qemu-user) would report the image's arch, not the host's;
    that is not a shape the appliance builds can produce, and the host
    runner re-checks against the real ``uname -m`` before writing.
    """
    import platform  # noqa: PLC0415 - stdlib, kept local to the one caller

    raw = (platform.machine() or "").strip().lower()
    return {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(raw)


def detect_appliance_variant() -> str | None:
    """Parse ``ROLE=`` out of ``/etc/spatiumddi-host/role-config``.

    The installer wizard's role choice is baked into role-config at
    install time (``spatium-install`` writes ``ROLE=<variant>``);
    firstboot leaves the value untouched across slot swaps. Legacy
    pre-#272 strings are normalised to the two canonical variants.
    Returns ``None`` when the file isn't mounted (docker / k8s) or the
    parsed value isn't one we recognise — the heartbeat handler treats
    ``None`` as "supervisor didn't ship the field" and leaves the
    persisted column alone.
    """
    if not _HOST_ROLE_CONFIG.exists():
        return None
    try:
        text = _HOST_ROLE_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("ROLE="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            value = _LEGACY_VARIANT_ALIASES.get(value, value)
            return value if value in _KNOWN_VARIANTS else None
    return None


def _current_slot_from_cmdline() -> str | None:
    """Match /proc/cmdline's ``root=UUID=`` against udev's PARTLABEL.

    Mirror of the api-side ``services/appliance/slot.py`` helper; kept
    independent so the agent doesn't pull in the backend package. The
    PARTLABEL of the booted slot maps to ``slot_a`` or ``slot_b``.

    Reads ``/run/udev/data/b<major>:<minor>`` files directly instead of
    shelling out to lsblk — lsblk inside a container without
    ``/dev/sda*`` bind-mounted can list block topology (from /sys) but
    can't read PARTLABEL / UUID, which it derives from the device
    inode. udev populates the same data into /run/udev/data with
    ``S:`` (symlink) lines like ``S:disk/by-partlabel/root_A`` and
    ``S:disk/by-uuid/aa1311ba-...``; parsing those gives us a
    container-friendly lookup with no extra mounts beyond the
    ``/run/udev`` bind we already have.
    """
    try:
        cmdline = _PROC_CMDLINE.read_text()
    except OSError:
        return None
    m = _UUID_RE.search(cmdline)
    if not m:
        return None
    root_uuid = m.group(1).lower()
    try:
        entries = list(_UDEV_DATA.iterdir())
    except OSError:
        return None
    for entry in entries:
        # udev data files for block devices are named ``b<major>:<minor>``.
        # Other entries (``+acpi:…`` for ACPI tags, ``c…`` for char devs,
        # ``n…`` for net devs) aren't relevant here.
        if not (entry.name.startswith("b") and ":" in entry.name):
            continue
        # ``S:`` lines are symlinks udev creates under /dev/disk/. We
        # pull PARTLABEL + UUID from the matching subdirectory prefix.
        _props, links = _udev_properties(entry)
        partlabel: str | None = None
        matches_uuid = False
        for value in links:
            if value.startswith("disk/by-partlabel/"):
                # Last segment is the PARTLABEL (preserving GPT case
                # would matter for downstream consumers, but we only
                # compare case-insensitively to root_a / root_b).
                partlabel = value.rsplit("/", 1)[-1]
            elif value.startswith("disk/by-uuid/"):
                if value.rsplit("/", 1)[-1].lower() == root_uuid:
                    matches_uuid = True
        if matches_uuid and partlabel:
            lower = partlabel.lower()
            if lower == "root_a":
                return "slot_a"
            if lower == "root_b":
                return "slot_b"
    return None


def _durable_default_from_grubenv() -> str | None:
    """Parse ``saved_entry`` out of grubenv. None if the bind mount
    isn't present or the file is unreadable."""
    if not _HOST_GRUBENV.exists():
        return None
    try:
        text = _HOST_GRUBENV.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.rstrip("\x00").strip()
        if line.startswith("saved_entry="):
            value = line.split("=", 1)[1].strip()
            if value in ("slot_a", "slot_b"):
                return value
    return None


def _last_upgrade_state_from_sidecar() -> tuple[str | None, datetime | None]:
    """Read ``state stamp`` from the .state sidecar the host-side
    runner maintains. Returns (state, when) or (None, None) when no
    upgrade has ever run on this agent.

    Reports ``failed`` honestly (#386). The earlier behaviour flipped a
    stale ``failed`` back to ``ready`` the instant the trigger was
    renamed to ``.failed.<ts>`` — which made a failing upgrade read as
    ``ready`` on the Fleet chip within one heartbeat, hiding the failure
    (and, paired with the silent re-fire loop, hiding it forever). A
    failure now sticks until the operator clears or re-applies: the
    backend's success auto-clear nulls ``desired_*`` once installed
    matches, and ``clear_fleet_upgrade_marker`` resets a stale ``failed``
    to ``ready`` when the control plane reports no upgrade desired (the
    Cancel button / a cleared attempt).

    Fresh appliances that have never run an upgrade have no .state
    file at all — return ``ready`` rather than ``None`` so the Fleet
    view's State column reads as a positive "healthy + no pending
    work" signal instead of an empty cell that visually looks like
    "agent hasn't reported yet". ``None`` is reserved for genuinely-
    unknown rows (docker / k8s / pre-8f-2).
    """
    if not _HOST_SLOT_STATE.exists():
        return "ready", None
    try:
        text = _HOST_SLOT_STATE.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None, None
    parts = text.split(maxsplit=1)
    state = parts[0] if parts else None
    if state not in ("ready", "in-flight", "done", "failed"):
        return None, None
    stamp = None
    if len(parts) > 1:
        try:
            stamp = datetime.fromisoformat(parts[1])
        except ValueError:
            stamp = None
    return state, stamp


# #421 — a slot-upgrade apply that dies mid-flight (SIGKILL, an OOM-killed
# dd, power loss) can't run the host runner's failed-on-exit trap, so the
# .state sidecar stays "in-flight" forever and the Fleet UI shows a
# permanent spinner — observed in the field stuck for two days. The host
# runner re-stamps the in-flight marker every ~60s while it's alive
# (spatiumddi-slot-upgrade INFLIGHT_TICK_SECONDS), so a stamp older than
# this threshold means the runner is gone. Set well above the tick (a few
# missed ticks of jitter is fine) but it never trips on a slow-but-running
# apply because a live runner keeps the stamp fresh regardless of how long
# the apply takes.
_STALE_INFLIGHT_SECONDS = 300  # 5 missed 60s liveness ticks


def _reap_stale_inflight(
    state: str | None, stamp: datetime | None
) -> tuple[str | None, datetime | None]:
    """Detect a dead/stalled slot-upgrade runner and surface it as failed.

    If the sidecar reads ``in-flight`` but the runner's liveness stamp has
    gone stale (older than ``_STALE_INFLIGHT_SECONDS``), the apply died
    without writing a terminal state. Record ``failed`` durably — rewrite
    the sidecar, drop a progress breadcrumb, and rename the lingering
    trigger to ``.failed.<ts>`` so a re-apply / Cancel isn't blocked by
    ``clear_fleet_upgrade_marker``'s "trigger present" guard — and return
    ``("failed", now)`` for this heartbeat. Best-effort: if the durable
    write fails we still report ``failed`` this tick and retry next time.

    A stamp-less ``in-flight`` (old-format sidecar) can't be aged, so it's
    left untouched — conservative beats a false failure on a live apply.
    """
    if state != "in-flight" or stamp is None:
        return state, stamp
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    age = (now - stamp).total_seconds()
    if age <= _STALE_INFLIGHT_SECONDS:
        return state, stamp

    reason = (
        f"runner exited without completing "
        f"(stale in-flight {int(age)}s > {_STALE_INFLIGHT_SECONDS}s threshold)"
    )
    log.warning(
        "supervisor.slot_upgrade.stale_inflight_reaped",
        age_seconds=int(age),
        threshold_seconds=_STALE_INFLIGHT_SECONDS,
    )
    try:
        _HOST_SLOT_STATE.write_text(f"failed {now.isoformat()}\n", encoding="utf-8")
    except OSError:
        # Couldn't persist — report failed for this tick anyway; the next
        # heartbeat re-derives the same stale condition and retries.
        return "failed", now
    try:
        _SLOT_UPGRADE_PROGRESS.write_text(
            json.dumps(
                {"step": "failed", "pct": None, "detail": reason, "at": now.isoformat()}
            ),
            encoding="utf-8",
        )
    except OSError:
        # Cosmetic breadcrumb only — the durable "failed" .state written
        # above is what the UI keys off; a missed progress write just
        # leaves the prior line and is re-derived next tick.
        pass
    try:
        if _TRIGGER_FILE.exists():
            _TRIGGER_FILE.rename(
                _TRIGGER_FILE.with_name(
                    f"{_TRIGGER_FILE.name}.failed.{int(now.timestamp())}"
                )
            )
    except OSError:
        # Best-effort unblock — if the rename misses, the operator's
        # Cancel path still heals failed→ready once the trigger is gone;
        # never fatal to the heartbeat.
        pass
    return "failed", now


_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-upgrade-pending")
# #553 — the FLEET reboot trigger has its own filename, distinct from the
# web-UI local-reboot trigger (``reboot-pending``, handled by
# spatiumddi-reboot.{path,service}). Previously both wrote ``reboot-pending``
# so both .path units fired: the agent runner (5 s) won while the web-UI
# service's un-``-``-prefixed mv failed on the already-renamed file, ending
# ``failed`` on every reboot. Separate filenames = one runner per trigger.
_REBOOT_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/reboot-pending-fleet"
)
# #1446 — the boot a fleet reboot trigger was last written in. The control
# plane keeps delivering ``reboot_requested`` until a heartbeat arrives from
# a different boot, so between writing the trigger and the host going down,
# heartbeats still carry it. Without this marker each of those would
# re-write the trigger the runner had just moved aside, and a trigger left
# behind by the shutdown would make the NEXT request a no-op (the
# ``exists()`` check below), which is the "reboot cleared, nothing happened"
# failure this issue is about.
_REBOOT_FIRED_BOOT_MARKER = Path(
    "/var/lib/spatiumddi-host/release-state/reboot-fleet-fired-boot"
)
# Issue #386 Part B — fire-once marker. Records the last
# ``desired_slot_image_url`` the supervisor wrote a trigger for, so a
# failed apply (which renames the trigger to ``.failed.<ts>`` and would
# otherwise look "no trigger present → fire again") isn't silently
# re-fired every heartbeat. We re-fire only when the desired URL
# differs — the backend appends a per-apply nonce fragment, so a fresh
# "Apply" of the same image re-triggers while a stuck failure does not.
_FIRED_URL_MARKER = Path(
    "/var/lib/spatiumddi-host/release-state/slot-upgrade-fired-url"
)
# Issue #386 Part C — host slot-upgrade log, mounted read-only into the
# supervisor (charts/spatiumddi-appliance/templates/supervisor.yaml) so
# the heartbeat can ship a tail to the Fleet drilldown while an apply is
# in-flight / failed.
_SLOT_UPGRADE_LOG = Path("/var/log/spatiumddi-host/slot-upgrade.log")
# Issue #386 Part C — structured per-phase progress the host runner
# writes (step / pct / detail / at). Lives in release-state (already
# mounted into the supervisor), so it works without the log mount.
_SLOT_UPGRADE_PROGRESS = Path(
    "/var/lib/spatiumddi-host/release-state/slot-upgrade.progress"
)
# Per-slot installed-version sidecar maintained by ``spatium-upgrade-
# slot sync-versions`` (called by spatiumddi-firstboot at every boot
# + at the end of every apply). Shape: ``{"slot_a": "<version>",
# "slot_b": "<version>"}`` — values may be the literal ``"unstamped"``
# / ``"unreadable"`` / ``"unknown"`` for slots that aren't readable
# from the host. We pass values through verbatim; the Fleet UI
# normalises them in ``slotVersion()``.
_SLOT_VERSIONS_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-versions.json")
# Issue #165 — operator-set timezone trigger + applied-hash sidecar.
# Trigger carries a single line (the IANA tz name); host runner
# rewrites the hash sidecar after a successful apply so the
# supervisor short-circuits the next heartbeat's trigger write.
_TZ_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/tz-pending")
_TZ_APPLIED_HASH_FILE = Path("/var/lib/spatiumddi-host/release-state/tz-hash")
# Verbose-boot console toggle. The runner flips a grubenv variable
# (spatium_verbose) the grub.cfg menuentries read; trigger body is a single
# "0" (quiet boot + dashboard), "1" (verbose boot + plain getty, no dashboard)
# or "2" (verbose boot output, then the dashboard) — see
# ``_CONSOLE_MODE_TO_GRUBENV``. It was binary until #393 added mode 2.
_VERBOSE_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/verbose-boot-pending"
)
_VERBOSE_APPLIED_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/verbose-boot-applied"
)
# Per-slot boot-control trigger files. Each carries a single line:
# the target slot name (``slot_a`` / ``slot_b``). The host-side
# ``spatiumddi-slot-set-next-boot.path`` / ``spatiumddi-slot-set-
# default.path`` units fire on close-after-write rename.
_SET_NEXT_BOOT_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/slot-set-next-boot-pending"
)
_SET_DEFAULT_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/slot-set-default-pending"
)
# Issue #153 — SNMP config rollout. The trigger file carries the
# rendered snmpd.conf body so the host runner doesn't need to re-
# render. The hash sidecar lets the agent skip re-firing after an
# unchanged config bundle picks up across an agent restart.
_SNMP_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/snmp-config-pending")
_SNMP_HASH_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/snmp-config-hash")
_SNMP_STATUS_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/snmp-status")
# #989 item 3 — removable (USB) disk mounts. Same shape as SNMP / NTP,
# with one difference that decides the payload: every other host-config
# plane is FLEET-wide (it renders from platform_settings), and this one
# is PER-APPLIANCE — the disk is plugged into exactly one node. So the
# desired set lives on the appliance row, not in platform settings, and
# the trigger's line-3+ payload is the JSON mount list the runner
# reconciles against the units already on disk.
_REMOVABLE_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/removable-config-pending"
)
_REMOVABLE_HASH_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/removable-config-hash"
)
#: The runner's own verdict + reason for the last apply. Read, not just
#: written: ``read_host_config_health`` can only say a plane is
#: unapplied, so without this the operator is told "not applied" and
#: sent to read journalctl, while the concrete cause ("systemd-analyze
#: verify rejected …") sits on disk and is discarded. That is exactly
#: the tz-status / verbose-boot-status gap #882 recorded as deferred;
#: the SNMP plane already reads its own status sidecar.
_REMOVABLE_STATUS_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/removable-status"
)
# Issue #154 — NTP / chrony equivalents. Same shape as SNMP.
_NTP_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/ntp-config-pending")
_NTP_HASH_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/ntp-config-hash")
_NTP_STATUS_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/ntp-status")
# Issue #155 — APT sources / proxy / GPG-key equivalents. Same shape as
# SNMP / NTP; the trigger's line-3+ payload is a JSON blob (multiple
# rendered files + keyrings) parsed by the host runner's python3.
_APT_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/apt-config-pending")
_APT_HASH_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/apt-config-hash")
_APT_STATUS_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/apt-status")
# Issue #343 — LLDP / lldpd equivalents. Same shape as SNMP / NTP.
_LLDP_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/lldp-config-pending")
_LLDP_HASH_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/lldp-config-hash")
_LLDP_STATUS_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/lldp-status")
# Issue #156 — rsyslog forwarding equivalents. Same shape as SNMP / NTP /
# LLDP. The trigger carries the rendered conf body + per-target CA PEMs
# (one JSON header line) so the host runner can stage everything; the
# hash sidecar short-circuits re-firing; the status sidecar carries the
# best-effort ``forwarding`` / ``unreachable`` / ``disabled`` verdict the
# heartbeat ships up.
_SYSLOG_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/syslog-config-pending"
)
_SYSLOG_HASH_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/syslog-config-hash")
_SYSLOG_STATUS_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/syslog-status")
# Issue #157 — SSH authorized_keys + sshd hardening equivalents. Same
# shape as SNMP / NTP / LLDP / syslog. The trigger carries the rendered
# authorized_keys + sshd drop-in + source-scope CIDRs (a JSON header
# line) so the host runner can stage everything; the hash sidecar
# short-circuits re-firing; the count sidecar carries the per-host
# applied authorized_keys count the heartbeat ships up.
_SSH_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/ssh-config-pending")
_SSH_HASH_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/ssh-config-hash")
_SSH_KEY_COUNT_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/ssh-key-count")
# Issue #158 — systemd-resolved equivalents. Same shape as SNMP / NTP /
# LLDP / syslog / SSH. The trigger carries the rendered resolved.conf
# drop-in body (a 2-line header) so the host runner can stage it (or
# remove it on revert-to-automatic); the hash sidecar short-circuits
# re-firing; the status sidecar carries the best-effort ``override`` /
# ``automatic`` / ``failed`` verdict the heartbeat ships up.
_RESOLVER_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/resolver-config-pending"
)
_RESOLVER_HASH_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/resolver-config-hash"
)
_RESOLVER_STATUS_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/resolver-status"
)
# Issue #285 Phase 2b — firewall apply-state sidecars the host-side
# spatium-firewall-reload runner writes after each apply; echoed on the
# heartbeat so the control plane can see drift + drive the apply alarm.
# The runner writes the bare /var/lib/spatiumddi/release-state path; the
# supervisor reads the same dir through the -host bind mount.
_FIREWALL_APPLIED_HASH_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/firewall-applied-hash"
)
_FIREWALL_APPLIED_STATUS_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/firewall-applied-status"
)
_FIREWALL_BASE_MARKER_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/firewall-applied-base-marker"
)
# Issue #285 Phase 2a — the firewall-pending trigger the host-side
# spatium-firewall-reload.path unit watches. Same path heartbeat.py's
# in-pod fallback writes to; maybe_fire_firewall_reload writes the server-
# rendered body here when the control plane has firewall authority.
_FIREWALL_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/firewall-pending")
# #593 — last self-partition refusal, surfaced to the operator on the heartbeat
# (appliance.firewall_state → Fleet chip). Detecting a row/reality divergence
# and only logging it would leave the node silently diverged forever: the
# control plane keeps re-shipping the same wrong body, and nothing tells anyone.
_FIREWALL_REFUSAL_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/firewall-refused"
)

# #272 Phase 7b — control-plane cluster join/leave. The join trigger
# carries the seed's kubeapi URL + join token; the host-side runner
# (spatium-cluster-join) reconfigures k3s to join the seed as a server
# node and writes the .state sidecar (state\treason) the supervisor
# reads back. The leave trigger has no payload. The token sidecar is
# written by the PRIMARY's host runner from /var/lib/rancher/k3s/
# server/token so the supervisor can report it without mounting the
# k3s server dir.
_CLUSTER_JOIN_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/cluster-join-pending"
)
_CLUSTER_LEAVE_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/cluster-leave-pending"
)
# Guardrail confirmation markers (#272). The host-side spatium-cluster-join
# runner does DESTRUCTIVE k3s surgery (full cluster-identity wipe + rejoin),
# fired by a systemd .path unit watching these trigger files. To stop a
# stray / accidental / hand-touched file from triggering a wipe, the
# supervisor stamps a magic first line and the runner refuses to act on any
# trigger whose first line isn't an exact match. Must stay byte-identical to
# the constants in spatium-cluster-join.
_CLUSTER_JOIN_CONFIRM = "SPATIUMDDI-CLUSTER-JOIN-CONFIRM-V1"
_CLUSTER_LEAVE_CONFIRM = "SPATIUMDDI-CLUSTER-LEAVE-CONFIRM-V1"
_CLUSTER_JOIN_STATE_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/cluster-join.state"
)
# #590 — cluster-transition attempt ceiling. ``maybe_fire_cluster_join`` /
# ``maybe_fire_cluster_leave`` used to guard on nothing but "does the trigger
# file exist", and the host runner renames the trigger to ``.failed.<ts>``
# when it gives up — so a transition that could never succeed re-fired a
# DESTRUCTIVE k3s identity wipe on every single heartbeat, forever, while the
# row sat in "joining". The backend now clears the desired-state on a
# reported ``failed`` (which is what actually stops the loop); this ceiling
# is the belt to that pair of braces, bounding the damage even against a
# control plane that never processes the failure.
#
# The ledger itself is the module's existing hash-keyed fire-state sidecar
# (``_fire_state_path`` / ``_read_fire_state`` / ``_write_fire_state``, the
# same one the host-config planes use), keyed by a fingerprint of the
# transition target — so re-driving against a different seed starts with a
# fresh budget. ``reset_cluster_join_attempts()`` clears both ledgers
# whenever the control plane stops asking for a role change.
#
# #1212 — a JOIN's re-fires are spaced too, and its ceiling is high enough
# that its attempts outlast the backend's retry window. The backend keeps a
# transiently failed member's desired role for 15 minutes (#961) so that the
# join is retried once the path to the seed is back. The supervisor used to
# re-fire on every heartbeat, with a ceiling of three and no spacing. An
# attempt against an unreachable seed fails in ~20 s, so all three landed in
# the first ~2.5 minutes of an outage and the rest of the window went unused:
# a member whose path came back four minutes in stayed a standalone node.
#
# The next join against the same target now waits
# ``_cluster_join_retry_delay_s()`` after the last fire, measured from the
# ledger's timestamp: one minute, two, then every four. The first retry
# still comes a minute after the first attempt; that is the retry #961's
# concurrent-promote race needs. Eight attempts take about 23 minutes, past
# the window, so for a transient failure the backend's clear, not this
# ceiling, now ends the retries. The ceiling stays the backstop for a
# control plane that never processes the failure: 8 wipes over ~23 minutes,
# where it used to be 3 in ~2.5.
_CLUSTER_JOIN_MAX_ATTEMPTS = 8
_CLUSTER_JOIN_RETRY_BASE_S = 60.0
_CLUSTER_JOIN_RETRY_MAX_S = 240.0
# The leave is exactly as destructive, but the backend clears a failed
# leave's desired role at once, so there is no window to span: it keeps the
# original ceiling and no spacing.
_CLUSTER_LEAVE_MAX_ATTEMPTS = 3

# #590 — "this terminal verdict has already been delivered" marker.
#
# The .state sidecar is written by the ROOT host runner and lives in a
# sticky dir, so this unprivileged supervisor cannot delete it — it
# would otherwise keep re-reporting a stale ``failed`` from a previous
# episode. Now that the backend CLEARS the desired-state on a reported
# ``failed`` (instead of re-firing the join forever), a stale re-report
# would clear the desired-state of the operator's NEXT promote before the
# join ever fires — turning the old infinite-retry bug into a permanent
# "promote does nothing" deadlock.
#
# So: once the control plane has acknowledged a ``failed`` verdict (it
# drops the desired-state, which is how we know), stamp the sidecar's
# identity here and stop reporting it. The runner rewrites .state — and
# therefore its mtime — at the top of every run, so the next real episode
# reports again. Owned by the supervisor, so rewriting is permitted.
_CLUSTER_JOIN_STATE_CONSUMED = Path(
    "/var/lib/spatiumddi-host/release-state/cluster-join.state.consumed"
)
# ONLY ``failed`` is retired — never ``ready`` / ``left``.
#
# ``ready`` is NOT merely a report: it is this node's local source of truth
# for "I am a promoted control-plane member". service_lifecycle
# .reconcile_node_labels() adds the control-plane node label when it sees
# ``ready`` and STRIPS it otherwise, and heartbeat._is_control_plane_member
# () uses it to pick the in-cluster api Service over the seed's external
# URL. Retiring ``ready`` would deschedule api/frontend/worker/beat/CNPG/
# redis off every promoted member on the first idle heartbeat after a
# SUCCESSFUL promote — the exact HA collapse #590 exists to prevent.
#
# Retiring them is also unnecessary: the backend's clear-on-failed branches
# are gated on ``desired_cluster_role``, so a re-reported ``ready``/``left``
# arriving with no desired-state set is already a no-op there. Only a stale
# ``failed`` can clear the desired-state of the operator's NEXT promote.
_CLUSTER_JOIN_CONSUMABLE_STATES = frozenset({"failed"})
_K3S_JOIN_TOKEN_SIDECAR = Path("/var/lib/spatiumddi-host/release-state/k3s-join-token")

# #272 Phase 9b — guided etcd restore. Same trigger-file + confirm-marker
# shape as join/leave, but for the MOST destructive cluster op: a
# single-node cluster-reset that restores etcd from a snapshot. The
# host-side spatium-cluster-restore runner refuses any trigger whose
# first line isn't this exact marker. The payload is two lines: the
# marker then the snapshot name. The runner writes the same .state sidecar
# shape (``state\treason``) the supervisor reports back.
_CLUSTER_RESTORE_TRIGGER_FILE = Path(
    "/var/lib/spatiumddi-host/release-state/cluster-restore-pending"
)
_CLUSTER_RESTORE_CONFIRM = "SPATIUMDDI-CLUSTER-RESTORE-CONFIRM-V1"
_CLUSTER_RESTORE_STATE_SIDECAR = Path(
    "/var/lib/spatiumddi-host/release-state/cluster-restore.state"
)

# #395 — host-migration reconcile ledger. Written by spatium-host-migrate
# on every reconcile (success or failure). The supervisor reads it via the
# existing read-only /var/lib/spatiumddi-host/release-state bind mount and
# surfaces failing patches on the heartbeat for the Fleet UI.
_HOST_PATCHES_LEDGER = Path(
    "/var/lib/spatiumddi-host/release-state/host-patches-applied.json"
)


def maybe_fire_fleet_upgrade(
    desired_version: str | None,
    desired_url: str | None,
    desired_sha256: str | None = None,
    desired_tls_insecure: bool = False,
) -> bool:
    """Phase 8f-4 — write the slot-upgrade trigger when the control
    plane's desired version doesn't match what's installed.

    Returns True if a trigger was fired (caller should log it), False
    otherwise.

    **Fire-once (#386 Part B).** A failed apply renames the trigger to
    ``.failed.<ts>``, so the old "trigger file absent → fire" guard
    re-fired the SAME desired-state every heartbeat — a silent
    crash-loop that flooded ``.failed.*`` sidecars and never surfaced.
    We now record the fired ``desired_slot_image_url`` (which carries a
    per-apply nonce fragment) in ``_FIRED_URL_MARKER`` and skip when it
    already matches: a stuck failure does NOT re-fire; a fresh Apply
    (new nonce → different URL) does.

    **Download hints (#386 Part A).** ``desired_sha256`` is written into
    the trigger so the host runner verifies the bytes against it;
    ``desired_tls_insecure`` adds an ``insecure-tls`` marker so the
    runner skips cert-verify for the appliance's OWN self-served URL —
    but ONLY when a sha256 is also present (verified bytes are the real
    integrity guarantee).

    Conditions for firing:
      - Not running on an appliance (no /etc/spatiumddi-host) → skip.
      - desired_version / desired_url is None / empty → skip.
      - desired_version equals installed_appliance_version → skip.
      - URL already fired (marker match) → skip (no re-fire loop).
      - Trigger file already present → skip (path unit hasn't picked
        it up yet; don't stack).
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not desired_version or not desired_url:
        return False
    desired_url_str = str(desired_url).strip()
    if not desired_url_str:
        return False
    # Strip the #386 fire-once nonce fragment before any scheme / fetch
    # work — URL fragments are client-side only and must never reach the
    # host runner's ``urllib`` fetch. The UNSTRIPPED URL is the
    # fire-once key (so a new nonce re-fires); the stripped URL is what
    # the runner downloads.
    fetch_url = desired_url_str.split("#", 1)[0]
    # Issue #242 — only accept ``https://`` (preferred) or ``file://``
    # (sneakernet / air-gap). Reject ``http://`` so a misconfigured
    # control plane can't downgrade the OS-image fetch to cleartext
    # over the WAN; reject unknown / unscheme'd URLs entirely.
    allowed_schemes = ("https://", "file://")
    if not any(fetch_url.lower().startswith(s) for s in allowed_schemes):
        log.warning(
            "supervisor.appliance_state.rejected_upgrade_url_scheme",
            url_prefix=fetch_url.split("://", 1)[0][:32],
        )
        return False
    installed = read_installed_version()
    if installed and installed == desired_version:
        return False
    # Fire-once: skip if we already wrote a trigger for this exact
    # desired-state (same URL incl. nonce).
    try:
        if _FIRED_URL_MARKER.read_text(encoding="utf-8").strip() == desired_url_str:
            return False
    except OSError:
        # No marker yet / unreadable → treat as not-yet-fired and fall
        # through to write the trigger. Never fatal.
        pass
    if _TRIGGER_FILE.exists():
        return False
    # Only relax TLS when we also have a hash to verify the bytes.
    insecure = bool(desired_tls_insecure) and bool(desired_sha256)
    # The trigger file's parent should already exist on the appliance
    # (firstboot creates /var/lib/spatiumddi/release-state). Bail
    # silently if it doesn't — host setup is broken; the control plane
    # sees the heartbeat come back without a state change.
    try:
        _TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Trigger format the host runner parses: line 1 = image URL (or
        # path, fragment stripped); optional ``sha256=<hex>`` +
        # ``insecure-tls`` marker lines. Legacy two-line (line 2 = bare
        # checksum URL) is still accepted by the runner for the
        # self-panel apply path.
        lines = [fetch_url]
        if desired_sha256:
            lines.append(f"sha256={desired_sha256.strip().lower()}")
        if insecure:
            lines.append("insecure-tls")
        tmp = _TRIGGER_FILE.with_suffix(".new")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tmp.replace(_TRIGGER_FILE)
        try:
            _FIRED_URL_MARKER.write_text(desired_url_str + "\n", encoding="utf-8")
        except OSError:
            # Best-effort fire-once bookkeeping — a failed marker write at
            # worst costs one extra re-fire next heartbeat, never a crash,
            # so don't abort the (already-written) trigger.
            pass
        _prune_failed_sidecars()
        return True
    except OSError:
        return False


def clear_fleet_upgrade_marker() -> None:
    """#386 Part B — the control plane reports no upgrade desired
    (cleared via the Cancel button, or never set). Drop the fire-once
    marker so a future Apply of the same URL re-fires, and reset a stale
    ``failed`` state back to ``ready`` so a cancelled failure stops
    sticking on the Fleet chip. No-op off-appliance, and never touches
    an in-flight apply (trigger file present)."""
    if detect_deployment_kind() != "appliance":
        return
    try:
        _FIRED_URL_MARKER.unlink(missing_ok=True)
    except OSError:
        # Best-effort cleanup — a stale marker only risks suppressing one
        # re-fire of an identical URL; not worth failing the loop.
        pass
    if _TRIGGER_FILE.exists():
        return
    try:
        if _HOST_SLOT_STATE.exists():
            parts = _HOST_SLOT_STATE.read_text(encoding="utf-8").split(maxsplit=1)
            if parts and parts[0] == "failed":
                _HOST_SLOT_STATE.write_text(
                    f"ready {datetime.now(UTC).isoformat()}\n", encoding="utf-8"
                )
    except OSError:
        # Best-effort heal — if the state sidecar can't be read/rewritten
        # the chip just keeps its last value; the next apply overwrites it.
        pass


def apply_clear_upgrade_command() -> bool:
    """#786 — the operator pressed "Clear failed upgrade"; make the host forget.

    ``clear_fleet_upgrade_marker`` above is the *passive* heal, and it
    deliberately returns early when a trigger file is still on disk so it
    can't disturb an apply that is genuinely running. That guard is also
    what made a wedged appliance unrecoverable: any failure that strands an
    unconsumed ``slot-upgrade-pending`` — the path/service unit failing to
    exec, the runner dying before its EXIT trap is armed, a missed rename
    by the stale-in-flight reaper — blocks both the heal AND
    ``maybe_fire_fleet_upgrade``, so the box could neither clear nor
    re-apply, and no operator action could break the deadlock.

    This is the explicit counterpart: the operator has *asked* for the
    stranded state to go, so the trigger is removed rather than deferred
    to. Returns True when anything was actually reset (for the log line).

    Deliberately does NOT stop a running apply: it only removes the
    trigger + resets the sidecars. A live ``spatiumddi-slot-upgrade``
    process re-stamps its own progress as it goes, so a clear raced
    against a real apply loses to the apply rather than corrupting it.
    """
    if detect_deployment_kind() != "appliance":
        return False

    reset = False
    for path in (_TRIGGER_FILE, _FIRED_URL_MARKER):
        try:
            if path.exists():
                path.unlink(missing_ok=True)
                reset = True
        except OSError as exc:
            # Surfaced rather than swallowed: if the stranded trigger
            # survives, the operator's clear silently didn't take and the
            # box stays wedged — exactly the failure this exists to fix.
            log.warning("supervisor.clear_upgrade.unlink_failed", path=str(path), error=str(exc))

    # Only rewrite a state that is actually stuck. Two reasons: a healthy
    # box would otherwise report "cleared" on every heartbeat inside the
    # flag's lifetime, and clobbering a live ``in-flight`` stamp would blind
    # BOTH crash detectors that key on that literal — the runner's exit trap
    # and the supervisor's stale-in-flight reaper — so a mid-apply Cancel
    # could leave a truncated image with nothing recording the failure.
    try:
        if _HOST_SLOT_STATE.exists():
            current = _HOST_SLOT_STATE.read_text(encoding="utf-8").split(maxsplit=1)
            if current and current[0] == "failed":
                _HOST_SLOT_STATE.write_text(
                    f"ready {datetime.now(UTC).isoformat()}\n", encoding="utf-8"
                )
                reset = True
    except OSError as exc:
        log.warning("supervisor.clear_upgrade.state_reset_failed", error=str(exc))

    # OVERWRITE rather than unlink. release-state is sticky (1770 root:2770)
    # and this file is root-owned (the host runner writes it); a non-owner
    # can never unlink it, but the runner publishes it 0660 to gid 2770,
    # which this process carries, so an in-place write succeeds. An empty object reads as "no progress" to every
    # consumer, which is what a cleared upgrade should show.
    try:
        if _SLOT_UPGRADE_PROGRESS.exists():
            _SLOT_UPGRADE_PROGRESS.write_text("{}\n", encoding="utf-8")
            reset = True
    except OSError as exc:
        log.warning("supervisor.clear_upgrade.progress_reset_failed", error=str(exc))

    _prune_failed_sidecars(keep=0)

    # A trigger we could not remove leaves the box exactly as wedged as it
    # was — it still blocks both the passive heal and maybe_fire_fleet_
    # upgrade. Field-observed: a root-owned trigger (this directory is
    # sticky, so a non-owner can never unlink one) failed here while the
    # state/progress resets succeeded, and the command still reported
    # success. Say so instead, or the operator is told a clear worked when
    # the appliance is still stuck.
    if _TRIGGER_FILE.exists():
        log.error(
            "supervisor.clear_upgrade.trigger_survived",
            path=str(_TRIGGER_FILE),
            hint="not owned by the supervisor; remove it from the host to unwedge",
        )
        return False
    return reset


def _prune_host_config_sidecars(trigger_file: Path, keep: int = 5) -> None:
    """(#387) Keep only the newest ``.failed.<ts>`` / ``.done.<ts>`` /
    ``.invalid.<ts>`` sidecars for ONE trigger family, so a (pre-fix)
    re-fire loop or normal churn can't accumulate thousands of files in
    release-state (2374 ntp + 2021 set-next-boot observed on ddi1, #387).
    Sidecar suffixes are unix timestamps, so a lexicographic sort is
    chronological. Generalises the slot-upgrade-only #386 pruner."""
    try:
        parent = trigger_file.parent
        for suffix in ("failed", "done", "invalid"):
            stale = sorted(parent.glob(f"{trigger_file.name}.{suffix}.*"))
            # ``stale[:-0]`` is the EMPTY slice, not the whole list, so a
            # plain slice would make keep=0 ("remove them all", used by the
            # #786 explicit clear) silently prune nothing.
            for path in stale if keep <= 0 else stale[:-keep]:
                path.unlink(missing_ok=True)
    except OSError:
        # Best-effort housekeeping — leftover sidecars are cosmetic; a
        # prune failure must never block a trigger write.
        pass


def _prune_failed_sidecars(keep: int = 5) -> None:
    """#386 — slot-upgrade sidecar prune. Thin wrapper over the
    generalised #387 pruner, kept as a named entry point for
    ``maybe_fire_fleet_upgrade``."""
    _prune_host_config_sidecars(_TRIGGER_FILE, keep)


# ── #387 — shared bounded-retry fire-guard for the hash-keyed host-
#    config runners (snmp / ntp / lldp / syslog / ssh / resolver /
#    firewall / timezone) ──────────────────────────────────────────────
#
# Each runner applies a control-plane-rendered config and writes its
# applied-hash sidecar ONLY on success. The naive fire test — "desired
# config_hash != applied_hash → write the trigger" — therefore re-fires
# the SAME desired-state every heartbeat whenever an apply persistently
# fails (the sidecar never advances), flooding ``<trigger>.failed.<ts>``
# sidecars (2374 observed on ddi1 for a single bad chrony flag, #387) and
# never surfacing the failure.
#
# The guard caps the RATE of re-fires per distinct config_hash with
# exponential backoff (a fresh hash — operator pushed new config —
# resets the budget). A stuck apply retries at a decreasing cadence
# (60 s → 120 s → … → 15 min ceiling) instead of every ~30 s tick, and
# NEVER permanently gives up, so a fixed runner (e.g. the #387 chrony
# flag fix) auto-recovers on the next backoff window with no operator
# action. ``read_host_config_health()`` surfaces the per-plane
# stuck/failing state on the heartbeat for the Fleet UI.

_HOSTCFG_BACKOFF_BASE_S = 60.0
_HOSTCFG_BACKOFF_MAX_S = 900.0  # 15-min ceiling between retries of a stuck apply
_HOSTCFG_FAILING_ATTEMPTS = 3  # at/after this many fires of one hash → "failing"

# (plane name, trigger file, applied-hash sidecar). The per-plane
# fire-state sidecar is derived as ``<trigger>.fire-state`` so there's
# one source of truth and no extra path consts to keep in sync.
_HOST_CONFIG_PLANES: list[tuple[str, Path, Path]] = [
    ("snmp", _SNMP_TRIGGER_FILE, _SNMP_HASH_SIDECAR),
    ("ntp", _NTP_TRIGGER_FILE, _NTP_HASH_SIDECAR),
    ("apt", _APT_TRIGGER_FILE, _APT_HASH_SIDECAR),
    ("lldp", _LLDP_TRIGGER_FILE, _LLDP_HASH_SIDECAR),
    ("syslog", _SYSLOG_TRIGGER_FILE, _SYSLOG_HASH_SIDECAR),
    ("ssh", _SSH_TRIGGER_FILE, _SSH_HASH_SIDECAR),
    ("resolver", _RESOLVER_TRIGGER_FILE, _RESOLVER_HASH_SIDECAR),
    ("firewall", _FIREWALL_TRIGGER_FILE, _FIREWALL_APPLIED_HASH_SIDECAR),
    ("timezone", _TZ_TRIGGER_FILE, _TZ_APPLIED_HASH_FILE),
    # #882 audit — was absent, so a console-mode apply that kept failing
    # was invisible on the heartbeat while re-firing every tick.
    ("console_mode", _VERBOSE_TRIGGER_FILE, _VERBOSE_APPLIED_FILE),
    # #989 item 3 — registered from the start. A removable mount that
    # keeps failing to apply is exactly the case where the operator sees
    # a configured disk in the UI and a backup that never lands.
    ("removable", _REMOVABLE_TRIGGER_FILE, _REMOVABLE_HASH_SIDECAR),
]


def _fire_state_path(trigger_file: Path) -> Path:
    return trigger_file.with_name(trigger_file.name + ".fire-state")


def _read_fire_state(fire_state_file: Path) -> tuple[str, int, datetime | None]:
    """Read ``<hash>\\t<attempts>\\t<iso>`` → (hash, attempts, when).
    Missing / malformed → ``("", 0, None)``."""
    try:
        text = fire_state_file.read_text(encoding="utf-8").strip()
    except OSError:
        return "", 0, None
    parts = text.split("\t")
    if not parts or not parts[0]:
        return "", 0, None
    try:
        attempts = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        attempts = 0
    when: datetime | None = None
    if len(parts) > 2:
        try:
            when = datetime.fromisoformat(parts[2])
        except ValueError:
            when = None
    return parts[0], attempts, when


def _write_fire_state(
    fire_state_file: Path, config_hash: str, attempts: int, when: datetime
) -> None:
    try:
        # with_name(), not with_suffix(): the latter REPLACES ".fire-state",
        # so "<trigger>.fire-state" would stage through "<trigger>.new" —
        # the very path the trigger writers use for their own atomic temp.
        tmp = fire_state_file.with_name(fire_state_file.name + ".new")
        tmp.write_text(
            f"{config_hash}\t{attempts}\t{when.isoformat()}\n", encoding="utf-8"
        )
        tmp.replace(fire_state_file)
    except OSError:
        # Best-effort bookkeeping — a failed fire-state write at worst
        # costs the backoff its memory for one tick; never fatal.
        pass


def _hostcfg_backoff_seconds(attempts: int) -> float:
    # ``attempts`` = number of prior fires for this hash (>= 1).
    expo = _HOSTCFG_BACKOFF_BASE_S * (2 ** max(0, attempts - 1))
    return min(expo, _HOSTCFG_BACKOFF_MAX_S)


def _hostcfg_should_fire(
    fire_state_file: Path, config_hash: str, *, now: datetime | None = None
) -> tuple[bool, int]:
    """(#387) Decide whether to (re-)fire a hash-keyed host-config
    trigger, applying per-hash exponential backoff. Returns
    ``(should_fire, attempt_to_record)``. The caller has already
    confirmed ``config_hash != applied_hash`` and that the trigger file
    is absent — so reaching here with the SAME hash means the prior
    attempt has not succeeded yet (failed, or still mid-apply)."""
    now = now or datetime.now(UTC)
    prev_hash, attempts, last_at = _read_fire_state(fire_state_file)
    if config_hash != prev_hash:
        return True, 1  # fresh desired-state → reset budget, fire now
    if last_at is not None and (
        now - last_at
    ).total_seconds() < _hostcfg_backoff_seconds(attempts):
        return False, attempts  # still inside the backoff window
    return True, attempts + 1


def _write_owner_only(tmp: Path, payload: str) -> None:
    """Write ``payload`` to ``tmp`` as an owner-only (0o600) file, with the
    restrictive mode set *at creation* rather than after the fact.

    The host-config trigger files can carry decrypted secrets — the SNMP
    community, APT private-mirror passwords + GPG armour (#155), the syslog
    forwarding CA material (#156), the SSH config (#157), and the k3s join
    token (#272) — and they land in the shared ``release-state`` dir, which
    every host account could list while it was 1777 (GHSA-h2j9-qrg7-grfw)
    and the api pod still can. A plain ``write_text`` then
    ``chmod(0o600)`` left a window where the file existed at the umask
    default (typically 0644, world-readable) before the chmod landed, so a
    local user could race-open the ``.new`` temp and read the secret.
    ``os.open`` with ``O_CREAT`` + mode ``0o600`` closes that window;
    ``O_NOFOLLOW`` refuses a symlink an attacker could plant in the
    world-writable dir. The root ``.path`` runner reads as root and is
    unaffected by the tighter mode.

    ``O_EXCL`` (with a best-effort unlink of our own stale temp first)
    is required in addition to ``O_NOFOLLOW``: without it, ``O_CREAT``
    happily opens a pre-planted *regular* file (O_NOFOLLOW only rejects
    symlinks), the mode arg is ignored for an existing inode, and the
    secret would be written into an attacker-owned 0644 file whose fd
    they still hold after ``replace()``. With ``O_EXCL`` the open fails
    closed (EEXIST) if anyone raced a file into the predictable temp
    path; callers wrap this in ``try/except OSError`` and retry on the
    next tick.
    """
    try:
        os.unlink(tmp)  # drop our own stale temp from a crashed prior run
    except FileNotFoundError:
        # No stale temp to remove — the normal case; nothing to clean up.
        pass
    fd = os.open(
        tmp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload)


def _fire_host_config(
    trigger_file: Path,
    applied_hash_sidecar: Path,
    config_hash: str,
    payload: str,
) -> bool:
    """(#387) Shared write path for the hash-keyed host-config runners.

    Replaces the per-function "compare hash → check trigger presence →
    write trigger" boilerplate AND adds the bounded-retry guard + the
    per-plane sidecar prune in one place. Returns True iff a trigger was
    written. The caller owns the appliance-only gate + payload assembly
    (+ any plane-specific guard, e.g. the SSH lockout refusal)."""
    applied_hash = _read_release_state_line(applied_hash_sidecar) or ""
    if config_hash == applied_hash:
        return False  # already applied — idempotent no-op
    if trigger_file.exists():
        return False  # path unit hasn't consumed the last trigger — don't stack
    fire_state = _fire_state_path(trigger_file)
    now = datetime.now(UTC)
    should_fire, attempt = _hostcfg_should_fire(fire_state, config_hash, now=now)
    if not should_fire:
        return False  # backing off a stuck apply (#387) — no silent flood
    try:
        trigger_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = trigger_file.with_suffix(".new")
        # The payload can carry decrypted secrets (SNMP community, APT
        # GPG armour + private-mirror passwords #155, syslog CA #156, the
        # SSH config #157) and lands in the shared, sticky release-state dir.
        # Create it owner-only atomically — see _write_owner_only — so no
        # window exists where another unprivileged host user could read it.
        _write_owner_only(tmp, payload)
        tmp.replace(trigger_file)
    except OSError:
        return False
    _write_fire_state(fire_state, config_hash, attempt, now)
    _prune_host_config_sidecars(trigger_file)
    return True


def read_host_config_health() -> dict[str, dict[str, object]]:
    """(#387) Per-plane apply health for the hash-keyed host-config
    runners, surfaced on the heartbeat so the Fleet UI shows a stuck
    apply honestly instead of leaving the operator with a silent re-fire
    loop. Only planes whose last-fired config has NOT been applied are
    reported::

        {"ntp": {"state": "failing", "attempts": 7, "at": "<iso>"}, ...}

    ``state`` is ``failing`` once the same hash has been fired
    ``_HOSTCFG_FAILING_ATTEMPTS`` times (apply keeps failing), else
    ``retrying``. A plane whose applied-hash matches its last-fired hash
    (success) — or that was never fired — is omitted, so a healthy box
    reports ``{}`` (which clears any stale server-side entry)."""
    out: dict[str, dict[str, object]] = {}
    for name, trigger, applied_sidecar in _HOST_CONFIG_PLANES:
        fhash, attempts, when = _read_fire_state(_fire_state_path(trigger))
        if not fhash:
            continue  # never fired → nothing to report
        applied = _read_release_state_line(applied_sidecar) or ""
        if applied == fhash:
            continue  # last-fired config is applied → healthy, omit
        out[name] = {
            "state": (
                "failing" if attempts >= _HOSTCFG_FAILING_ATTEMPTS else "retrying"
            ),
            "attempts": attempts,
            "at": when.isoformat() if when else None,
        }
    return out


def read_host_migration_health() -> dict[str, dict[str, object]]:
    """(#395) Thin host-migration reconcile rollup, surfaced on the
    heartbeat so the Fleet UI shows a failing patch honestly.

    Reads the per-patch JSON ledger written by ``spatium-host-migrate``
    at ``/var/lib/spatiumddi-host/release-state/host-patches-applied.json``
    and emits an entry for every patch whose ``ok`` field is ``False``::

        {"001-grub-render": {"state": "failing", "at": "<iso>", "error": "…"}}

    A healthy appliance (all patches applied) returns ``{}`` — which
    clears any stale server-side entry, mirroring ``read_host_config_health()``.
    If the ledger is absent (e.g. the box has never booted a #395 slot)
    there is nothing to report, so ``{}`` is returned rather than surfacing
    a spurious failure. ``None`` is never returned; the ``collect()`` caller
    guards with ``if is_appliance else None``.

    Unlike ``host_config_health`` (which uses a continuous bounded-retry
    fire-guard with exponential backoff), host-migration patches are run
    once per boot. They only ever report ``"failing"`` — the next boot
    automatically retries, so there is no ``"retrying"`` transient state.
    The ``state`` value is still in the same ``"retrying" | "failing"``
    union so the Fleet UI chip colours require no extension."""
    try:
        data = json.loads(_HOST_PATCHES_LEDGER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}  # no ledger yet → nothing to report
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict[str, object]] = {}
    patches = data.get("patches", {})
    if not isinstance(patches, dict):
        return {}
    for pid, info in sorted(patches.items()):
        if not isinstance(info, dict):
            continue
        if info.get("ok") is False:
            try:
                attempts = int(info.get("fail_count") or 1)
            except (TypeError, ValueError):
                attempts = 1
            out[pid] = {
                "state": "failing",
                # Real consecutive-boot fail count from the ledger (a box
                # left durable on a slot whose patch keeps failing grows
                # this every boot); floored at 1 so a freshly-failed patch
                # never reports 0.
                "attempts": max(attempts, 1),
                "at": info.get("applied_at"),
                "error": info.get("error"),
            }
    # If the overall reconcile failed but no individual patch is flagged
    # (e.g. the version-stamp write failed after all patches succeeded),
    # surface a synthetic "reconcile" entry so the operator isn't told
    # everything is fine when it isn't.
    if data.get("last_reconcile_ok") is False and not out:
        out["reconcile"] = {
            "state": "failing",
            "attempts": 1,
            "at": data.get("last_reconcile_at"),
        }
    return out


# Trigger families whose host runners rename the consumed trigger to a
# timestamped ``.done`` / ``.failed`` / ``.invalid`` sidecar. The
# collect() sweep prunes each every heartbeat so the existing ddi1
# backlog (2374 ntp + 2021 set-next-boot) is culled on the first
# post-upgrade heartbeat regardless of whether anything fires this tick.
# Globbing a family that never timestamp-renames is a harmless no-op.
_PRUNABLE_TRIGGERS: list[Path] = [
    _TRIGGER_FILE,
    _SET_NEXT_BOOT_TRIGGER_FILE,
    _SET_DEFAULT_TRIGGER_FILE,
    _VERBOSE_TRIGGER_FILE,
    _REBOOT_TRIGGER_FILE,
] + [trigger for _name, trigger, _applied in _HOST_CONFIG_PLANES]


def prune_all_trigger_sidecars(keep: int = 5) -> None:
    """(#387) Sweep every known trigger family's stale timestamped
    sidecars. Called once per ``collect()`` so a pre-fix backlog is
    bounded immediately on upgrade, independent of any fire this tick."""
    for trigger in _PRUNABLE_TRIGGERS:
        _prune_host_config_sidecars(trigger, keep)


def _read_slot_upgrade_log_tail(lines: int = 40, max_chars: int = 8000) -> str:
    """#386 Part C — last ``lines`` of the host slot-upgrade.log, capped
    at ``max_chars``. Empty string when the log is unreadable / absent
    (e.g. the log dir isn't mounted into the supervisor)."""
    try:
        text = _SLOT_UPGRADE_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    tail = "\n".join(text.splitlines()[-lines:])
    return tail[-max_chars:] if len(tail) > max_chars else tail


def _read_slot_upgrade_progress() -> dict[str, object] | None:
    """#386 Part C — structured per-phase progress the host runner
    writes to the progress sidecar (step / pct / detail / at). None when
    absent / unreadable / malformed."""
    try:
        data = json.loads(_SLOT_UPGRADE_PROGRESS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def read_boot_id() -> str | None:
    """This boot's kernel boot id, or None when it cannot be read."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def maybe_fire_reboot(reboot_requested: bool) -> bool:
    """Phase 8f-8 — write the reboot trigger when the control plane
    has stamped ``reboot_requested=True`` on the server row.

    Strict appliance-only gate: a docker / k8s / unknown agent NEVER
    fires the trigger even if the field somehow flips through. The
    host-side ``spatiumddi-reboot-agent.path`` unit + the
    ``/var/lib/spatiumddi-host/release-state`` bind mount only exist
    on a SpatiumDDI appliance — but defence in depth is cheap.

    Returns True if a trigger was fired, False otherwise. Fires at most
    once per boot (#1446): the control plane keeps sending the request
    until a heartbeat comes from a new boot, so every heartbeat between the
    write and the shutdown carries it again.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not reboot_requested:
        return False
    boot_id = read_boot_id()
    try:
        fired_in = _REBOOT_FIRED_BOOT_MARKER.read_text(encoding="utf-8").strip()
    except OSError:
        fired_in = ""
    # #1446 — once per boot. A trigger already written in THIS boot is the
    # host going down; a trigger left over from an EARLIER boot is stale (the
    # runner never consumed it) and is rewritten, so PathChanged fires.
    if boot_id and fired_in == boot_id:
        return False
    if _REBOOT_TRIGGER_FILE.exists() and not boot_id:
        return False
    try:
        _REBOOT_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _REBOOT_TRIGGER_FILE.with_suffix(".new")
        # One-line marker — the host runner doesn't actually need any
        # payload, just the path-changed event. Stamp + UTC time so
        # the operator can debug from /var/log/spatiumddi if needed.
        tmp.write_text(
            datetime.now(UTC).isoformat().replace("+00:00", "Z") + "\n",
            encoding="utf-8",
        )
        tmp.replace(_REBOOT_TRIGGER_FILE)
        if boot_id:
            _REBOOT_FIRED_BOOT_MARKER.write_text(boot_id + "\n", encoding="utf-8")
        return True
    except OSError:
        return False


def maybe_fire_timezone(desired_timezone: str | None) -> bool:
    """Issue #165 — write the tz-reload trigger when the operator's
    desired timezone (from ``platform_settings.timezone``) doesn't
    match the value the host runner last applied.

    Returns True if a trigger was fired, False otherwise. Idempotent
    via the ``tz-hash`` sidecar — the host runner writes the IANA
    name it applied; we compare against the desired value and skip
    the rewrite when they match. Empty / None desired means "no
    override" — the supervisor leaves the host alone.

    Strict appliance-only gate (mirrors ``maybe_fire_reboot``):
    docker / k8s / unknown deploys NEVER fire the trigger even if
    the field somehow flips through.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not desired_timezone or not desired_timezone.strip():
        return False
    desired = desired_timezone.strip()
    # #387 — fire through the shared bounded-retry guard. The "applied
    # IANA name" sidecar plays the role of the applied-hash, and the
    # desired IANA name plays the config_hash, so a tz the host runner
    # can't apply (e.g. a name ``timedatectl`` rejects) backs off
    # instead of re-firing every heartbeat. Payload = the IANA name.
    return _fire_host_config(
        _TZ_TRIGGER_FILE, _TZ_APPLIED_HASH_FILE, desired, desired + "\n"
    )


# #393 — console_mode → grubenv ``spatium_verbose`` numeric. Keeping
# dashboard=0 + text_console=1 preserves the pre-#393 grubenv meaning,
# so an old grubenv (or an unknown mode → ``"0"`` fallback) still
# resolves to the safe dashboard default in grub.cfg (fail-closed).
_CONSOLE_MODE_TO_GRUBENV = {
    "dashboard": "0",
    "text_console": "1",
    "verbose_dashboard": "2",
}


def maybe_fire_console_mode(desired_console_mode: str | None) -> bool:
    """(#393) Write the verbose-boot trigger when the operator's desired
    console mode (``platform_settings.console_mode``) differs from what the
    host runner last applied. The runner flips the grubenv ``spatium_verbose``
    variable the grub.cfg menuentries read, so it takes effect on the NEXT
    reboot.

    Maps the mode to the grubenv numeric the runner + grub.cfg understand:
    ``dashboard``→0 (quiet boot + dashboard), ``text_console``→1 (verbose boot
    + a plain getty login, no dashboard), ``verbose_dashboard``→2 (verbose
    boot output, then the dashboard). An unknown / missing mode falls back to
    ``0`` (dashboard) — fail-closed. Idempotent via the
    ``verbose-boot-applied`` sidecar; a missing sidecar is treated as ``0``
    (the installer seeds ``grub-editenv … spatium_verbose=0``). Strict
    appliance-only gate (mirrors ``maybe_fire_timezone`` / ``maybe_fire_reboot``).
    """
    if detect_deployment_kind() != "appliance":
        return False
    desired = _CONSOLE_MODE_TO_GRUBENV.get(desired_console_mode or "dashboard", "0")
    # #882 audit — fire through the shared bounded-retry guard, like every
    # other host-config plane. This used to write the trigger directly, which
    # meant it had none of the #387 protections: no trigger-presence check, no
    # backoff, and no entry in ``_HOST_CONFIG_PLANES``. A runner that could not
    # apply (no grubenv found, ``grub-editenv`` failing) left ``applied``
    # unchanged, so the very next heartbeat rewrote the trigger, the .path unit
    # fired on the rename, and the failure repeated every ~30 s indefinitely
    # with nothing said upward — the silent re-fire flood the guard exists to
    # prevent, on the one plane that never got it.
    #
    # The applied grubenv numeric plays the role of the applied-hash, exactly
    # as ``maybe_fire_timezone`` uses the applied IANA name.
    #
    # The "already applied" test stays HERE rather than being left to
    # ``_fire_host_config``: a missing sidecar means a fresh box, and a fresh
    # box IS on mode 0 because the installer seeds
    # ``grub-editenv … spatium_verbose=0``. ``_fire_host_config`` reads a
    # missing sidecar as the empty string, which would never equal "0" — so
    # delegating this check would make every fresh appliance fire a
    # console-mode trigger on its first heartbeat to set the value it already
    # has.
    try:
        applied = _VERBOSE_APPLIED_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        applied = "0"
    if applied == desired:
        return False
    return _fire_host_config(
        _VERBOSE_TRIGGER_FILE, _VERBOSE_APPLIED_FILE, desired, desired + "\n"
    )


def read_slot_versions() -> tuple[str | None, str | None]:
    """Read per-slot installed versions from the
    ``slot-versions.json`` sidecar (maintained by ``spatium-upgrade-
    slot sync-versions``).

    Returns ``(slot_a_version, slot_b_version)`` — either or both may
    be ``None`` when the sidecar is missing entirely. ``"unstamped"`` /
    ``"unreadable"`` / ``"unknown"`` sentinel values are passed through
    verbatim; the Fleet UI's ``slotVersion()`` helper normalises them
    to ``"—"``.

    Strict appliance-only — non-appliance deploys don't have the host
    bind mount + the sidecar wouldn't exist anyway. Returns the same
    ``(None, None)`` so the control plane's "only update when not
    None" semantics leaves the columns untouched.
    """
    if detect_deployment_kind() != "appliance":
        return None, None
    if not _SLOT_VERSIONS_FILE.exists():
        return None, None
    try:
        text = _SLOT_VERSIONS_FILE.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    slot_a = data.get("slot_a") if isinstance(data.get("slot_a"), str) else None
    slot_b = data.get("slot_b") if isinstance(data.get("slot_b"), str) else None
    return slot_a, slot_b


def maybe_fire_set_next_boot(
    desired_slot: str | None,
    current_slot: str | None,
) -> bool:
    """Write the slot-set-next-boot trigger when the control plane
    asks for a slot that isn't already running.

    ``desired_slot`` mirrors the heartbeat response's
    ``desired_next_boot_slot`` (``slot_a`` / ``slot_b`` / ``None``).
    ``current_slot`` is the supervisor's last observed running slot —
    if the operator's intent already matches reality we don't fire
    (the heartbeat handler will auto-clear ``desired_*`` on the next
    tick).

    Strict appliance-only gate (mirrors ``maybe_fire_reboot``). Empty
    intent or invalid slot literal → skip. Idempotent via trigger-
    file presence; the host runner renames the trigger to .done /
    .failed on completion.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if desired_slot not in ("slot_a", "slot_b"):
        return False
    if current_slot == desired_slot:
        return False
    if _SET_NEXT_BOOT_TRIGGER_FILE.exists():
        return False
    try:
        _SET_NEXT_BOOT_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _SET_NEXT_BOOT_TRIGGER_FILE.with_suffix(".new")
        # Single-line payload — host runner reads + invokes
        # ``spatium-upgrade-slot set-next-boot <slot>`` with this
        # value. Validated as a slot literal above so no shell
        # metachars reach the runner.
        tmp.write_text(desired_slot + "\n", encoding="utf-8")
        tmp.replace(_SET_NEXT_BOOT_TRIGGER_FILE)
        return True
    except OSError:
        return False


def maybe_fire_set_default(
    desired_slot: str | None,
    durable_default: str | None,
) -> bool:
    """Write the slot-set-default trigger when the control plane asks
    for a durable default different from the current grub
    ``saved_entry``.

    Same shape as ``maybe_fire_set_next_boot`` but for the durable
    (``grub-set-default``) action: commits a trial boot or durably
    reverts. If the durable default already matches the intent we
    skip (the heartbeat handler will auto-clear ``desired_*`` on the
    next tick).
    """
    if detect_deployment_kind() != "appliance":
        return False
    if desired_slot not in ("slot_a", "slot_b"):
        return False
    if durable_default == desired_slot:
        return False
    if _SET_DEFAULT_TRIGGER_FILE.exists():
        return False
    try:
        _SET_DEFAULT_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _SET_DEFAULT_TRIGGER_FILE.with_suffix(".new")
        tmp.write_text(desired_slot + "\n", encoding="utf-8")
        tmp.replace(_SET_DEFAULT_TRIGGER_FILE)
        return True
    except OSError:
        return False


def maybe_fire_snmp_reload(bundle_block: object) -> bool:
    """Issue #153 — write the snmp-config trigger when the control
    plane's rendered snmpd.conf hash differs from the last one this
    agent applied.

    Strict appliance-only gate — same reasoning as
    ``maybe_fire_reboot``: the host-side ``spatiumddi-snmp-reload``
    units don't exist on docker / k8s deploys; firing the trigger
    there would just leave dead files in a directory that may not
    even exist.

    Returns True if a trigger was fired, False otherwise. Idempotent
    via the hash sidecar — multiple long-poll cycles with the same
    config_hash produce zero triggers. The host runner writes the
    sidecar on successful apply so the next agent restart doesn't
    re-fire either.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    snmpd_conf = str(bundle_block.get("snmpd_conf") or "")
    enabled = bool(bundle_block.get("enabled"))
    # Empty hash = SNMP disabled and no config to push. Only fire a
    # disable trigger if the agent previously applied a non-empty
    # config (sidecar present and non-empty) — otherwise this is the
    # default "never configured" state and there's nothing to undo.
    # Three-section payload the host runner reads:
    #   line 1:   ``enabled`` | ``disabled`` marker
    #   line 2:   config_hash (sha256 hex, blank when disabled)
    #   line 3+:  rendered snmpd.conf body (already ends with \n)
    # The hash is on the wire (rather than recomputed by the runner) so
    # the agent and host agree on exactly which body was applied. An
    # empty config_hash (SNMP disabled) only fires a disable trigger if
    # a non-empty config was previously applied — handled by the
    # ``config_hash == applied_hash`` short-circuit inside the guard.
    payload = (
        ("enabled\n" if enabled else "disabled\n") + (config_hash + "\n") + snmpd_conf
    )
    # #387 — fire through the shared bounded-retry guard so a
    # persistently-failing apply backs off instead of re-firing every
    # heartbeat (which flooded thousands of .failed sidecars).
    return _fire_host_config(
        _SNMP_TRIGGER_FILE, _SNMP_HASH_SIDECAR, config_hash, payload
    )


def maybe_fire_removable_reload(bundle_block: object) -> bool:
    """#989 item 3 — write the removable-mount trigger when the control
    plane's desired set differs from the last one this node applied.

    Strict appliance-only gate, same reasoning as every sibling: the
    host-side ``spatiumddi-removable-reload`` units do not exist on
    docker / k8s deploys, so firing there leaves a file in a directory
    that may not exist and nothing to consume it.

    The payload is the three-section shape the other planes use — a
    marker line, the hash, then the body — where the body is the JSON
    mount list. ``enabled`` is ``disabled`` when the desired set is
    EMPTY, which is not the same as "the feature is off": it is what
    tells the runner to tear down every unit it owns, and it is how an
    eject reaches the host at all.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    mounts = bundle_block.get("mounts")
    if not isinstance(mounts, list):
        # NO INSTRUCTION — not "unmount everything". The control plane
        # sends a null mount list when the stored desired set could not
        # be validated, and an empty LIST is this plane's teardown
        # command, so treating the two alike would have one unparseable
        # row silently unmount every backup disk on the node.
        return False
    if not config_hash:
        # Also no instruction: an empty hash is what a MISSING applied
        # sidecar reads as, so acting on it makes an eject a no-op after
        # a failed apply and corrupts the shared fire-state ledger (see
        # ``removable_bundle``). A control plane too old to send a real
        # digest gets nothing rather than something wrong.
        return False
    payload = (
        ("enabled\n" if mounts else "disabled\n")
        + (config_hash + "\n")
        + json.dumps({"mounts": mounts})
        + "\n"
    )
    return _fire_host_config(
        _REMOVABLE_TRIGGER_FILE, _REMOVABLE_HASH_SIDECAR, config_hash, payload
    )


# ── #272 Phase 7b — control-plane cluster join/leave ────────────────


def _join_target_fingerprint(server_url: str, join_token: str) -> str:
    """Stable, non-reversible id for a join target (#590).

    The token is a control-plane-admin-equivalent secret, so the ledger
    stores a digest rather than the value — it only ever needs to answer
    "is this the same target as last time?".
    """
    digest = hashlib.sha256(f"{server_url}\n{join_token}".encode())
    return digest.hexdigest()[:16]


def _cluster_join_retry_delay_s(attempts: int) -> float:
    """#1212 — how long after fire number ``attempts`` (>= 1) the next join
    against the same target may fire: 60 s, 120 s, then 240 s each time."""
    return min(
        _CLUSTER_JOIN_RETRY_BASE_S * (2 ** max(0, attempts - 1)),
        _CLUSTER_JOIN_RETRY_MAX_S,
    )


def _cluster_transition_should_fire(
    trigger_file: Path,
    fingerprint: str,
    *,
    max_attempts: int,
    retry_delay_s: Callable[[int], float] | None = None,
) -> bool:
    """#590 — bound the number of times a DESTRUCTIVE cluster transition
    re-fires against the same target.

    The host runner renames a failed trigger to ``.failed.<ts>``, so
    trigger-file presence alone cannot stop a doomed join/leave from
    re-running a full k3s identity wipe on every heartbeat, forever. The
    backend's clear-on-failed is the primary brake; this is the backstop
    for a control plane that never processes the failure.

    #1212 — with ``retry_delay_s``, a re-fire against the same target also
    waits ``retry_delay_s(attempts)`` after the last fire the ledger
    recorded, so the attempts spread across the backend's retry window
    instead of being spent in its first minutes. A ledger stamped in the
    future (the clock stepped back) never holds a fire back: the ceiling
    still bounds it.

    Reuses the module's hash-keyed fire-state ledger (``_read_fire_state``
    / ``_write_fire_state``), the same one the host-config planes use for
    their re-fire backoff. Budget is per fingerprint: a transition against
    a different target starts over.
    """
    fire_state = _fire_state_path(trigger_file)
    prev_fingerprint, attempts, last_at = _read_fire_state(fire_state)
    if prev_fingerprint != fingerprint:
        attempts, last_at = 0, None
    if attempts >= max_attempts:
        log.error(
            "supervisor.cluster_transition.attempt_ceiling_reached",
            trigger=trigger_file.name,
            attempts=attempts,
            max_attempts=max_attempts,
            detail=(
                "refusing to re-fire the destructive transition; see "
                "/var/log/spatiumddi/cluster-join.log, then re-drive it to retry"
            ),
        )
        return False
    if retry_delay_s is not None and attempts and last_at is not None:
        if last_at.tzinfo is None:
            last_at = last_at.replace(tzinfo=UTC)
        elapsed = (datetime.now(UTC) - last_at).total_seconds()
        wait = retry_delay_s(attempts) - elapsed
        if elapsed >= 0 and wait > 0:
            log.info(
                "supervisor.cluster_transition.retry_deferred",
                trigger=trigger_file.name,
                attempts=attempts,
                max_attempts=max_attempts,
                next_attempt_in_s=round(wait),
            )
            return False
    return True


def _record_cluster_transition_fire(trigger_file: Path, fingerprint: str) -> None:
    """Count an armed transition against its per-fingerprint budget."""
    fire_state = _fire_state_path(trigger_file)
    prev_fingerprint, attempts, _last_at = _read_fire_state(fire_state)
    if prev_fingerprint != fingerprint:
        attempts = 0
    _write_fire_state(fire_state, fingerprint, attempts + 1, datetime.now(UTC))


def _reset_cluster_transition_attempts(trigger_file: Path) -> None:
    try:
        _fire_state_path(trigger_file).unlink()
    except FileNotFoundError:
        # Expected on the overwhelming majority of ticks: no ledger exists
        # until a transition actually fires, and this runs on every idle
        # heartbeat. Not a failure.
        return
    except OSError as exc:
        # A ledger we cannot clear means a later re-drive of the SAME
        # transition could inherit an exhausted budget and silently never
        # fire, so this is worth surfacing rather than swallowing.
        log.warning(
            "supervisor.cluster_transition.ledger_reset_failed",
            trigger=trigger_file.name,
            error=str(exc),
        )


def reset_cluster_join_attempts() -> None:
    """Drop the join + leave attempt ledgers (#590).

    Called whenever the control plane stops asking this node to change its
    cluster role — including after the backend clears the desired-state on
    a reported ``failed``. Without this an operator re-driving the SAME
    transition would inherit the exhausted budget and never fire a retry.
    """
    _reset_cluster_transition_attempts(_CLUSTER_JOIN_TRIGGER_FILE)
    _reset_cluster_transition_attempts(_CLUSTER_LEAVE_TRIGGER_FILE)


def maybe_fire_cluster_join(
    desired_cluster_role: str | None,
    server_url: str | None,
    join_token: str | None,
) -> bool:
    """Write the cluster-join trigger when the control plane asks this
    node to join the k3s control-plane cluster as a server.

    ``desired_cluster_role`` mirrors the heartbeat response field —
    only ``"member"`` fires a join. ``server_url`` + ``join_token`` are
    the seed's coordinates. The host-side runner reconfigures k3s +
    writes the ``.state`` sidecar; the supervisor reports that state on
    subsequent heartbeats so the backend can settle ``cluster_role`` +
    drop the desired-state.

    Strict appliance-only gate (mirrors ``maybe_fire_reboot``).
    Idempotent via trigger-file presence — once written, we don't
    stack writes until the host runner consumes it (renaming to
    ``.done`` / ``.failed``). The trigger payload is three lines: the
    ``_CLUSTER_JOIN_CONFIRM`` guardrail marker, then ``server_url``,
    then ``join_token``. The runner refuses any trigger whose first
    line isn't the marker, so a stray file can't fire a wipe.

    #590 — trigger-file presence is NOT sufficient on its own. The runner
    renames the trigger to ``.done`` the moment it succeeds, but
    ``desired_cluster_role`` stays ``member`` until the backend sees a
    ``ready`` heartbeat and settles it. In that window (trigger gone,
    desired still set) the next heartbeat re-fired the join and wiped the
    node's freshly-joined k3s identity. Observed live: a member reported
    "JOIN ok" at 15:43:31 and re-fired at 15:43:58, and the second attempt
    failed — leaving a node that k3s counted as an etcd member but the
    control plane counted as nothing.

    So also gate on what the runner last wrote. ``.state`` carries the
    target it acted on in its reason field (``ready\\t<server_url>``), which
    is what lets us tell "already joined THIS seed" apart from "promoted to
    a different seed and must re-join".
    """
    if detect_deployment_kind() != "appliance":
        return False
    if desired_cluster_role != "member":
        return False
    if not server_url or not join_token:
        return False
    # #555 — the payload is line-based (marker / server_url / join_token);
    # a newline in either operator-influenced field would shift the lines
    # the host runner parses. Reject control chars outright rather than
    # smuggle a second directive into the trigger.
    if any(c in server_url or c in join_token for c in ("\n", "\r")):
        log.warning("supervisor.cluster_join.rejected_control_char_in_payload")
        return False
    if _CLUSTER_JOIN_TRIGGER_FILE.exists():
        return False
    # #590 — don't re-run a join the runner has already finished (or is still
    # running). The trigger file is gone in both cases, so it cannot tell us.
    state, target = read_cluster_join_state()
    if state == "joining":
        # Runner is mid-flight: it renames the trigger BEFORE it finishes.
        return False
    if state == "ready" and (target or "") == server_url:
        # Already a member of this exact seed. The backend clears the
        # desired-state once it sees the ``ready`` heartbeat; until then,
        # firing again would wipe the identity we just built.
        return False
    # Failure ceiling. The runner renames a failed trigger out of the way, so
    # trigger-file presence alone can't stop a doomed join from re-wiping this
    # node's k3s state on every heartbeat. Budget is per target: a promote
    # against a different seed (or a re-promote after the ledger is reset)
    # starts over. #1212 — re-fires against the same target are spaced
    # (1, 2, then 4 minutes apart), so they cover the backend's retry window.
    fingerprint = _join_target_fingerprint(server_url, join_token)
    if not _cluster_transition_should_fire(
        _CLUSTER_JOIN_TRIGGER_FILE,
        fingerprint,
        max_attempts=_CLUSTER_JOIN_MAX_ATTEMPTS,
        retry_delay_s=_cluster_join_retry_delay_s,
    ):
        return False
    try:
        _CLUSTER_JOIN_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CLUSTER_JOIN_TRIGGER_FILE.with_name(
            _CLUSTER_JOIN_TRIGGER_FILE.name + ".new"
        )
        # The join token is a control-plane-admin-equivalent secret; write
        # it owner-only atomically (see _write_owner_only) so it can't be
        # read by another writer of the shared, sticky release-state dir.
        _write_owner_only(tmp, f"{_CLUSTER_JOIN_CONFIRM}\n{server_url}\n{join_token}\n")
        tmp.replace(_CLUSTER_JOIN_TRIGGER_FILE)
    except OSError:
        return False
    # Count the fire only once it's actually armed. Ledger loss (unwritable
    # dir) must not block the join — the backend's clear-on-failed is the
    # primary brake; this is the backstop.
    _record_cluster_transition_fire(_CLUSTER_JOIN_TRIGGER_FILE, fingerprint)
    return True


def maybe_fire_cluster_leave(desired_cluster_role: str | None) -> bool:
    """Write the cluster-leave trigger when the control plane asks this
    node to leave the cluster (``desired_cluster_role == "none"``).

    Payload is two lines: the ``_CLUSTER_LEAVE_CONFIRM`` guardrail
    marker then a timestamp. The runner refuses any trigger whose first
    line isn't the marker. Strict appliance-only + idempotent via
    trigger-file presence.

    #590 — the leave is exactly as destructive as the join (``do_leave``
    runs the same full ``backup_and_wipe_identity`` + k3s restart) and the
    runner renames a failed leave trigger to ``.failed.<ts>`` just like the
    join. So it gets the same per-target attempt ceiling; without it a
    demote that can never come Ready re-wipes this node's k3s state on
    every heartbeat, forever, whenever the control plane isn't around to
    clear the desired-state.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if desired_cluster_role != "none":
        return False
    if _CLUSTER_LEAVE_TRIGGER_FILE.exists():
        return False
    # #590 — same window as the join: do_leave renames its trigger away, but
    # ``desired_cluster_role`` stays "none" until the backend sees a ``left``
    # heartbeat. Re-firing here would run the destructive identity wipe a
    # second time on a node that has already left.
    state, _target = read_cluster_join_state()
    if state in ("leaving", "left"):
        return False
    # A leave has no target coordinates, so the whole operation is one
    # fingerprint — the budget bounds "this node's demote", period.
    fingerprint = "leave"
    if not _cluster_transition_should_fire(
        _CLUSTER_LEAVE_TRIGGER_FILE, fingerprint, max_attempts=_CLUSTER_LEAVE_MAX_ATTEMPTS
    ):
        return False
    try:
        _CLUSTER_LEAVE_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CLUSTER_LEAVE_TRIGGER_FILE.with_name(
            _CLUSTER_LEAVE_TRIGGER_FILE.name + ".new"
        )
        ts = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        tmp.write_text(f"{_CLUSTER_LEAVE_CONFIRM}\n{ts}\n", encoding="utf-8")
        tmp.replace(_CLUSTER_LEAVE_TRIGGER_FILE)
    except OSError:
        return False
    _record_cluster_transition_fire(_CLUSTER_LEAVE_TRIGGER_FILE, fingerprint)
    return True


def _read_cluster_join_sidecar() -> tuple[str, str | None, int] | None:
    """``(state, reason, mtime_ns)`` for the .state sidecar, or None when
    it's missing / unreadable / empty.

    One stat + one read. Both the reporting path and the consume path go
    through here, so the sidecar is never opened twice per heartbeat.
    """
    try:
        stat = _CLUSTER_JOIN_STATE_SIDECAR.stat()
        raw = _CLUSTER_JOIN_STATE_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not raw:
        return None
    state, _, reason = raw.partition("\t")
    if not state:
        return None
    return state, (reason or None), stat.st_mtime_ns


def _consumed_identity(state: str, mtime_ns: int) -> str:
    """The episode-identity line stored in the consumed marker."""
    return f"{state}\t{mtime_ns}"


def mark_cluster_join_state_consumed() -> None:
    """Record that the control plane has acted on the current ``failed``
    verdict, so we stop re-reporting it (#590).

    Called once the heartbeat response carries no desired cluster role —
    i.e. the backend settled the transition, or gave up on it after the
    failure. Only ``failed`` is marked: see _CLUSTER_JOIN_CONSUMABLE_STATES
    for why retiring ``ready`` would deschedule the control plane off every
    promoted member.
    """
    sidecar = _read_cluster_join_sidecar()
    if sidecar is None:
        return
    state, _reason, mtime_ns = sidecar
    if state not in _CLUSTER_JOIN_CONSUMABLE_STATES:
        return
    identity = _consumed_identity(state, mtime_ns)
    # Idempotent: this runs on every steady-state heartbeat, and rewriting
    # byte-identical content would churn the flash-backed /var partition
    # for the life of the appliance.
    try:
        if _CLUSTER_JOIN_STATE_CONSUMED.read_text(encoding="utf-8").strip() == identity:
            return
    except FileNotFoundError:
        # No marker yet — the common first-consume path. Fall through and
        # write one.
        pass
    except OSError as exc:
        # Marker exists but is unreadable. Fall through and rewrite it: a
        # marker we cannot read is indistinguishable from one that doesn't
        # match, and re-reporting a stale ``failed`` is the failure mode we
        # are here to prevent.
        log.warning(
            "supervisor.cluster_join.consumed_marker_unreadable", error=str(exc)
        )
    try:
        # with_name(), not with_suffix() — the latter would REPLACE the
        # ".consumed" suffix rather than append, landing the temp file on
        # a name that collides with the .state sidecar's namespace.
        tmp = _CLUSTER_JOIN_STATE_CONSUMED.with_name(
            _CLUSTER_JOIN_STATE_CONSUMED.name + ".new"
        )
        _write_owner_only(tmp, f"{identity}\n")
        tmp.replace(_CLUSTER_JOIN_STATE_CONSUMED)
    except OSError:
        # Best-effort. Worst case the stale verdict is reported once more,
        # costing the operator one extra promote click — never a wipe.
        log.warning("supervisor.cluster_join.consumed_marker_write_failed")


def read_cluster_join_state() -> tuple[str | None, str | None]:
    """Return ``(cluster_join_state, cluster_join_reason)`` from the
    ``.state`` sidecar the host runner writes (``state\\treason``).

    Appliance-only; ``(None, None)`` when the sidecar is missing so the
    backend's "only update when not None" semantics leave the columns
    alone on nodes that have never joined/left.

    #590 — also ``(None, None)`` for a ``failed`` verdict the control plane
    has already consumed. Re-reporting one would clear the desired-state of
    the operator's next promote before its join ever fired. The runner
    rewrites .state at the top of each run, so a genuinely new verdict has
    a fresh mtime and reports normally.

    NOTE: this is not a reporting-only accessor. ``ready`` is also the local
    source of truth for control-plane membership (reconcile_node_labels +
    _is_control_plane_member), which is why it is never retired.
    """
    if detect_deployment_kind() != "appliance":
        return None, None
    sidecar = _read_cluster_join_sidecar()
    if sidecar is None:
        return None, None
    state, reason, mtime_ns = sidecar
    if state in _CLUSTER_JOIN_CONSUMABLE_STATES:
        try:
            consumed = _CLUSTER_JOIN_STATE_CONSUMED.read_text(encoding="utf-8").strip()
        except OSError:
            consumed = ""
        if consumed == _consumed_identity(state, mtime_ns):
            return None, None
    return state, reason


def maybe_fire_cluster_restore(desired_restore_snapshot: str | None) -> bool:
    """Write the cluster-restore trigger when the control plane asks this
    seed to restore etcd from a snapshot (#272 Phase 9b).

    ⚠️ The MOST destructive trigger: the host runner stops k3s and runs
    ``k3s server --cluster-reset --cluster-reset-restore-path=…``, which
    collapses the cluster to a 1-member etcd and orphans every other
    control-plane node. The backend already gates this hard (superadmin +
    typed-hostname confirm + snapshot-in-inventory); here we re-assert the
    appliance-only gate and stamp the ``_CLUSTER_RESTORE_CONFIRM`` marker
    so a stray file can't fire a cluster reset.

    Payload is two lines: the marker then the snapshot name. Idempotent
    via trigger-file presence — once written we don't stack until the host
    runner consumes it (rename to ``.done`` / ``.failed``)."""
    if detect_deployment_kind() != "appliance":
        return False
    if not desired_restore_snapshot:
        return False
    # #555 — line-based payload (marker / snapshot name); reject control
    # chars so a newline can't smuggle a second directive to the runner.
    if any(c in desired_restore_snapshot for c in ("\n", "\r")):
        log.warning("supervisor.cluster_restore.rejected_control_char_in_snapshot")
        return False
    if _CLUSTER_RESTORE_TRIGGER_FILE.exists():
        return False
    try:
        _CLUSTER_RESTORE_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _CLUSTER_RESTORE_TRIGGER_FILE.with_suffix(".new")
        tmp.write_text(
            f"{_CLUSTER_RESTORE_CONFIRM}\n{desired_restore_snapshot}\n",
            encoding="utf-8",
        )
        tmp.replace(_CLUSTER_RESTORE_TRIGGER_FILE)
        return True
    except OSError:
        return False


def read_cluster_restore_state() -> tuple[str | None, str | None]:
    """Return ``(restore_state, restore_reason)`` from the ``.state``
    sidecar the host restore runner writes (``state\\treason``).

    Appliance-only; ``(None, None)`` when the sidecar is missing so the
    backend's "only update when not None" semantics leave the columns
    alone on nodes that have never run a restore."""
    if detect_deployment_kind() != "appliance":
        return None, None
    if not _CLUSTER_RESTORE_STATE_SIDECAR.exists():
        return None, None
    try:
        raw = _CLUSTER_RESTORE_STATE_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None, None
    if not raw:
        return None, None
    state, _, reason = raw.partition("\t")
    return (state or None), (reason or None)


def read_k3s_join_token() -> str | None:
    """Return the seed's k3s node-token from the sidecar the PRIMARY's
    host runner copies out of ``/var/lib/rancher/k3s/server/token``.

    Only the seed has this sidecar; ``None`` everywhere else (the
    backend leaves the column untouched). Reading a sidecar rather than
    the k3s server dir keeps the supervisor pod from needing that
    sensitive path mounted.
    """
    if detect_deployment_kind() != "appliance":
        return None
    if not _K3S_JOIN_TOKEN_SIDECAR.exists():
        return None
    try:
        tok = _K3S_JOIN_TOKEN_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return tok or None


def maybe_fire_apt_reload(bundle_block: object) -> bool:
    """Issue #155 — write the apt-config trigger when the control plane's
    rendered APT artifacts hash differs from the last one this agent
    applied.

    Strict appliance-only gate + hash-sidecar idempotency, mirroring
    ``maybe_fire_snmp_reload``. The line-3+ payload is a JSON blob (the
    multiple rendered files + keyring map don't fit the SNMP single-body
    shape) the host runner parses with python3:

        line 1:   ``enabled`` | ``disabled`` marker (SOURCES management)
        line 2:   config_hash (sha256 hex; covers the unattended policy too,
                  so it's non-blank even when apt sources are unmanaged)
        line 3+:  JSON {sources_list, proxy_conf, auth_conf, keyrings,
                  unattended_upgrades_enabled, unattended}

    The ``config_hash == applied_hash`` short-circuit inside the guard means a
    #164 unattended-policy change re-fires the trigger even with apt_managed
    off (the marker stays ``disabled`` for sources; the runner still renders
    the unattended files from the ``unattended`` blob).
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    enabled = bool(bundle_block.get("enabled"))
    blob = json.dumps(
        {
            "sources_list": bundle_block.get("sources_list") or "",
            "proxy_conf": bundle_block.get("proxy_conf") or "",
            "auth_conf": bundle_block.get("auth_conf") or "",
            "keyrings": bundle_block.get("keyrings") or {},
            "unattended_upgrades_enabled": bool(
                bundle_block.get("unattended_upgrades_enabled", True)
            ),
            # #164 — the unattended-upgrades POLICY block (origins / blocklist /
            # automatic-reboot / reboot-time). Always present so the runner can
            # render 50unattended-upgrades even when apt sources are unmanaged.
            "unattended": bundle_block.get("unattended") or {},
        }
    )
    payload = (
        ("enabled\n" if enabled else "disabled\n") + (config_hash + "\n") + blob
    )
    return _fire_host_config(
        _APT_TRIGGER_FILE, _APT_HASH_SIDECAR, config_hash, payload
    )


def read_apt_state() -> str | None:
    """Read the APT host-config state the runner writes to its status
    sidecar after a validate + swap (#155). One of ``synced`` /
    ``proxy-failed`` / ``mirror-unreachable`` / ``signature-mismatch`` /
    ``no-sources`` / ``unmanaged``. ``None`` = unknown (sidecar missing /
    unreadable / non-appliance)."""
    if not _APT_STATUS_SIDECAR.exists():
        return None
    try:
        text = _APT_STATUS_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    valid = {
        "synced",
        "proxy-failed",
        "mirror-unreachable",
        "signature-mismatch",
        "no-sources",
        "unmanaged",
        # The runner writes this on a malformed-blob / unknown-marker apply
        # failure; without it the structural failure is silently dropped.
        "unknown",
    }
    return text if text in valid else None


def read_snmpd_running() -> bool | None:
    """Read snmpd's last-reported status from the sidecar the host-
    side runner writes after each apply. ``True`` = snmpd is running,
    ``False`` = stopped, ``None`` = unknown (sidecar missing /
    unreadable / non-appliance)."""
    if not _SNMP_STATUS_SIDECAR.exists():
        return None
    try:
        text = _SNMP_STATUS_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if text == "running":
        return True
    if text == "stopped":
        return False
    return None


def maybe_fire_syslog_reload(bundle_block: object) -> bool:
    """Issue #156 — write the syslog-config trigger when the control
    plane's rendered rsyslog.conf hash differs from the last one this
    agent applied.

    Strict appliance-only gate + hash-sidecar idempotency, mirroring
    ``maybe_fire_snmp_reload``. The payload is three sections plus a
    JSON CA blob (rsyslog forwarding can carry per-target CA PEMs the
    host runner stages alongside the conf):

        line 1:   ``enabled`` | ``disabled`` marker
        line 2:   config_hash (sha256 hex, blank when disabled)
        line 3:   JSON object of ``{ca_filename: pem}`` (``{}`` when none)
        line 4+:  rendered /etc/rsyslog.d/50-spatium-forward.conf body

    Forwarding is OUTBOUND only, so — unlike SNMP / NTP-serve — there is
    no firewall drop-in; the host runner just stages the conf + CA files,
    validates with ``rsyslogd -N1``, and restarts rsyslog.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    rsyslog_conf = str(bundle_block.get("rsyslog_conf") or "")
    enabled = bool(bundle_block.get("enabled"))
    ca_certs = bundle_block.get("ca_certs")
    if not isinstance(ca_certs, dict):
        ca_certs = {}
    payload = (
        ("enabled\n" if enabled else "disabled\n")
        + (config_hash + "\n")
        + (json.dumps(ca_certs) + "\n")
        + rsyslog_conf
    )
    # #387 — shared bounded-retry guard (see maybe_fire_snmp_reload).
    return _fire_host_config(
        _SYSLOG_TRIGGER_FILE, _SYSLOG_HASH_SIDECAR, config_hash, payload
    )


def read_syslog_forwarding() -> str | None:
    """Read rsyslog's last-reported forwarding status from the sidecar
    the host-side runner writes after each apply. One of ``forwarding``
    (rsyslog active + config applied) / ``unreachable`` (enabled but the
    rsyslog unit failed/inactive) / ``disabled`` (off), or ``None`` on
    docker / k8s (no sidecar mounted) so the backend leaves the column
    alone.

    Fine-grained per-target omfwd reachability is deferred — this is a
    daemon-level health signal derived from ``systemctl is-active
    rsyslog`` + the config-applied state, not a per-destination probe.
    """
    if not _SYSLOG_STATUS_SIDECAR.exists():
        return None
    try:
        text = _SYSLOG_STATUS_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if text in ("forwarding", "unreachable", "disabled"):
        return text
    return None


def maybe_fire_ssh_reload(bundle_block: object) -> bool:
    """Issue #157 — write the ssh-config trigger when the control plane's
    rendered authorized_keys + sshd drop-in hash differs from the last one
    this agent applied.

    Strict appliance-only gate + hash-sidecar idempotency, mirroring
    ``maybe_fire_syslog_reload``. The payload is a 5-line header plus the
    two rendered bodies the host runner stages:

        line 1:   ``enabled`` | ``disabled`` marker
        line 2:   config_hash (sha256 hex, blank when disabled)
        line 3:   ssh_port (int)
        line 4:   JSON list of source-scope CIDRs (``[]`` = open)
        line 5:   ``1`` if password auth enabled else ``0``
        line 6:   byte length of the authorized_keys body (so the runner
                  can split it from the sshd_conf that follows)
        line 7+:  authorized_keys body, then the sshd_conf body
                  (concatenated; split at the line-6 byte offset)

    LOCKOUT SAFETY (host-side mirror of the server PUT guard): refuse to
    write a trigger whose state would leave NO way in — password auth off
    AND zero authorized keys. The server already rejects this on the PUT,
    but we mirror it here so a hand-edited / replayed bundle can't brick
    a box. When we refuse we return False and do NOT write the trigger.

    The host-side ``spatiumddi-ssh-reload`` runner validates the staged
    sshd config with ``sshd -t``, applies a SOURCE-SCOPED nft drop-in for
    the ssh port, and reloads sshd. The port-22 accept floor in the
    firewall renderer always stays open, so a bad port change is never a
    brick.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    enabled = bool(bundle_block.get("enabled"))
    authorized_keys = str(bundle_block.get("authorized_keys") or "")
    sshd_conf = str(bundle_block.get("sshd_conf") or "")
    ssh_port = int(bundle_block.get("ssh_port") or 22)
    allowed = bundle_block.get("allowed_source_networks")
    if not isinstance(allowed, list):
        allowed = []
    password_auth = bool(bundle_block.get("password_auth"))
    key_count = int(bundle_block.get("key_count") or 0)

    # Host-side lockout guard — refuse a payload that would leave no way
    # in (password auth off + zero keys). Only meaningful when enabled;
    # the default/disabled state always has password auth on.
    if enabled and not password_auth and key_count == 0:
        log.warning(
            "supervisor.ssh.lockout_refused",
            reason="password auth off with zero authorized keys",
        )
        return False

    ak_bytes = authorized_keys.encode("utf-8")
    payload = (
        ("enabled\n" if enabled else "disabled\n")
        + (config_hash + "\n")
        + (str(ssh_port) + "\n")
        + (json.dumps(allowed) + "\n")
        + (("1" if password_auth else "0") + "\n")
        + (str(len(ak_bytes)) + "\n")
        + authorized_keys
        + sshd_conf
    )
    # #387 — shared bounded-retry guard (see maybe_fire_snmp_reload).
    return _fire_host_config(_SSH_TRIGGER_FILE, _SSH_HASH_SIDECAR, config_hash, payload)


def read_ssh_key_count() -> int | None:
    """Read the per-host applied authorized_keys count from the sidecar the
    host-side ``spatiumddi-ssh-reload`` runner writes after each apply.

    ``None`` = unknown (sidecar missing / unreadable / non-appliance) so
    the backend leaves the column alone; an int (incl. 0) is the count the
    runner actually wrote to ``~admin/.ssh/authorized_keys`` (#157)."""
    if not _SSH_KEY_COUNT_SIDECAR.exists():
        return None
    try:
        text = _SSH_KEY_COUNT_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def maybe_fire_resolver_reload(bundle_block: object) -> bool:
    """Issue #158 — write the resolver-config trigger when the control
    plane's rendered systemd-resolved drop-in hash differs from the last
    one this agent applied.

    Strict appliance-only gate + hash-sidecar idempotency, mirroring
    ``maybe_fire_syslog_reload``. The payload is a 2-line header plus the
    rendered drop-in body the host runner stages:

        line 1:   ``enabled`` | ``disabled`` marker
        line 2:   config_hash (sha256 hex, blank when disabled/automatic)
        line 3+:  rendered /etc/systemd/resolved.conf.d/spatiumddi.conf body
                  (empty when disabled — the runner then REMOVES the drop-in)

    ``enabled`` (override mode) → the runner writes the drop-in + reloads
    systemd-resolved. ``disabled`` (automatic mode) → the runner removes
    ONLY spatiumddi.conf (leaving the image-shipped no-stub-listener.conf
    intact, which BIND9 relies on to bind host :53) + reloads. The drop-in
    NEVER carries ``DNSStubListener``.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    resolved_conf = str(bundle_block.get("resolved_conf") or "")
    enabled = bool(bundle_block.get("enabled"))
    payload = (
        ("enabled\n" if enabled else "disabled\n")
        + (config_hash + "\n")
        + resolved_conf
    )
    # #387 — shared bounded-retry guard (see maybe_fire_snmp_reload).
    return _fire_host_config(
        _RESOLVER_TRIGGER_FILE, _RESOLVER_HASH_SIDECAR, config_hash, payload
    )


def read_resolver_status() -> str | None:
    """Read systemd-resolved's last-reported state from the sidecar the
    host-side ``spatiumddi-resolved-reload`` runner writes after each apply.

    One of ``override`` (the spatiumddi.conf drop-in is applied) /
    ``automatic`` (no drop-in — per-link DHCP/NetworkManager DNS) /
    ``failed`` (apply error), or ``None`` on docker / k8s (no sidecar
    mounted) so the backend leaves the column alone (#158)."""
    if not _RESOLVER_STATUS_SIDECAR.exists():
        return None
    try:
        text = _RESOLVER_STATUS_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if text in ("override", "automatic", "failed"):
        return text
    return None


def maybe_fire_lldp_reload(bundle_block: object) -> bool:
    """Issue #343 — write the lldp-config trigger when the control plane's
    rendered lldpd config hash differs from the last one this agent applied.

    Identical idempotency + appliance-only gate to ``maybe_fire_snmp_reload``.
    The payload is four sections (LLDP carries an extra ``daemon_args`` line
    for the CDP/EDP/FDP/SONMP reception flags, which live in
    ``/etc/default/lldpd`` rather than the lldpcli conf body):

        line 1:   ``enabled`` | ``disabled`` marker
        line 2:   config_hash (sha256 hex, blank when disabled)
        line 3:   daemon_args (``-c -e`` …, blank when none)
        line 4+:  rendered /etc/lldpd.d/spatium.conf body (ends with \\n)
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    lldpd_conf = str(bundle_block.get("lldpd_conf") or "")
    daemon_args = str(bundle_block.get("daemon_args") or "")
    enabled = bool(bundle_block.get("enabled"))
    payload = (
        ("enabled\n" if enabled else "disabled\n")
        + (config_hash + "\n")
        + (daemon_args + "\n")
        + lldpd_conf
    )
    # #387 — shared bounded-retry guard (see maybe_fire_snmp_reload).
    return _fire_host_config(
        _LLDP_TRIGGER_FILE, _LLDP_HASH_SIDECAR, config_hash, payload
    )


def read_lldpd_running() -> bool | None:
    """Read lldpd's last-reported status from the sidecar the host-side
    runner writes after each apply. ``True`` = running, ``False`` = stopped,
    ``None`` = unknown (sidecar missing / unreadable / non-appliance)."""
    if not _LLDP_STATUS_SIDECAR.exists():
        return None
    try:
        text = _LLDP_STATUS_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if text == "running":
        return True
    if text == "stopped":
        return False
    return None


# ── Firewall apply-state read-back (#285 Phase 2b) ───────────────────


def _read_release_state_line(path: Path) -> str | None:
    """Return the stripped single-line content of a release-state sidecar,
    or None when missing / unreadable / empty."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def read_firewall_applied_hash() -> str | None:
    """sha256 of the drop-in the firewall runner last applied (#285 Phase 2b).
    None when never applied / non-appliance → the control plane leaves the
    column untouched."""
    return _read_release_state_line(_FIREWALL_APPLIED_HASH_SIDECAR)


def read_firewall_applied_status() -> str | None:
    """The firewall runner's last outcome — ``ok`` / ``error:*`` / ``reverted``
    (#285 Phase 2b). None when the sidecar is missing."""
    return _read_release_state_line(_FIREWALL_APPLIED_STATUS_SIDECAR)


def read_firewall_base_marker() -> str | None:
    """sha256 of the base /etc/nftables.conf the firewall runner last applied
    against (#285 Phase 2b) — lets the control plane tell a node still on the
    pre-#285 LAN-wide base apart from a hardened one. None when missing."""
    return _read_release_state_line(_FIREWALL_BASE_MARKER_SIDECAR)


def maybe_fire_firewall_reload(bundle_block: object) -> bool:
    """Issue #285 Phase 2a — pipe the control plane's SERVER-rendered firewall
    drop-in to the host runner.

    When ``firewall_enabled`` is on, the control plane renders the drop-in
    server-side (``firewall_bundle``) and ships ``{enabled, config_hash,
    firewall_conf}`` on the heartbeat. The supervisor is now a pipe: compare
    the bundle's hash to what the host runner last applied (the
    ``firewall-applied-hash`` sidecar) and, on a difference, write the EXACT
    Phase-1 2-line trigger (``<hash>\\n<body>``) so the existing
    spatium-firewall-reload runner consumes it with zero changes. The body
    carries the ``# spatium-bootstrap:`` directive, so sentinel retire/keep
    still works.

    Returns True if a trigger was fired. An empty ``config_hash`` means the
    control plane has no firewall authority (firewall_enabled off / old
    control plane) → return False so the caller falls back to the in-pod
    renderer and we never disturb the last-good drop-in (non-negotiable #5).
    Appliance-only + trigger-presence + hash-short-circuit guards mirror
    ``maybe_fire_snmp_reload``.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    firewall_conf = str(bundle_block.get("firewall_conf") or "")
    if not config_hash or not firewall_conf:
        return False  # no server-side authority → fall back / no-op

    # #593 note: the self-partition guard deliberately does NOT live here.
    #
    # Refusing inside this function can only ever mean "do nothing": its bool
    # return is consumed as "was a trigger fired?", and the caller's in-pod
    # fallback is gated on the ABSENCE of server authority, not on this return
    # value. A refusal here would therefore strand a live etcd member with a
    # stale peer rule — or, on a node that joined while its row was already
    # wrong, with no peer rule at all and no path to recovery.
    #
    # The guard sits in the heartbeat's dispatch instead, where a refusal can
    # fall through to the in-pod renderer and let it re-derive the peer set
    # from live membership. Keeping it out of here also keeps the apiserver
    # probe off the steady-state path, since the hash short-circuit inside
    # _fire_host_config runs first.

    # #387 — shared bounded-retry guard. The short-circuit against the
    # runner's applied-hash sidecar (a body the Phase-1 in-pod path
    # already applied → byte-identical server render → same hash) now
    # lives inside _fire_host_config, along with backoff on a stuck apply
    # (see maybe_fire_snmp_reload).
    return _fire_host_config(
        _FIREWALL_TRIGGER_FILE,
        _FIREWALL_APPLIED_HASH_SIDECAR,
        config_hash,
        f"{config_hash}\n{firewall_conf}",
    )


# ── #593 — surface a self-partition refusal to the operator ──────────
#
# Without this the fix is silent: the guard blocks the bad drop-in, the control
# plane re-renders the same wrong body from the same stale row on every tick,
# and the only trace is a log line on a box nobody is tailing. The refusal is
# persisted here, shipped on the heartbeat as ``firewall_state``, stored on
# ``appliance.firewall_state``, and rendered as a Fleet chip — the same route
# ``port_conflicts`` takes.


def record_firewall_refusal(source: str, reason: str) -> None:
    """Persist the latest refusal. Best-effort: never break the firewall path."""
    payload = {"state": "refused_self_partition", "source": source, "reason": reason}
    try:
        _FIREWALL_REFUSAL_SIDECAR.parent.mkdir(parents=True, exist_ok=True)
        tmp = _FIREWALL_REFUSAL_SIDECAR.with_name(
            _FIREWALL_REFUSAL_SIDECAR.name + ".new"
        )
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(_FIREWALL_REFUSAL_SIDECAR)
    except OSError as exc:
        # A genuine write failure here (read-only fs / ENOSPC / a missing
        # release-state mount) is the one way a self-partition refusal can go
        # silent on the host-side console reader — the #593 "never silent"
        # goal. The in-pod heartbeat still surfaces it (same-container
        # read-back), so this stays best-effort, but warn so the failure is
        # not buried at debug. (#611)
        log.warning(
            "supervisor.firewall.refusal_persist_failed",
            error=str(exc),
            path=str(_FIREWALL_REFUSAL_SIDECAR),
        )


def clear_firewall_refusal() -> None:
    """Drop the refusal marker once a body applies cleanly, so a healed node
    stops reporting a stale divergence."""
    try:
        _FIREWALL_REFUSAL_SIDECAR.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        log.debug("supervisor.firewall.refusal_clear_failed", error=str(exc))


def read_firewall_state() -> dict[str, str] | None:
    """The refusal dict for the heartbeat body, or None when healthy."""
    try:
        raw = _FIREWALL_REFUSAL_SIDECAR.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return {str(k): str(v) for k, v in data.items()}


# ── LLDP neighbour discovery (#347) ──────────────────────────────────


def _lldp_list(x: object) -> list:
    """lldpd's json0 wraps even single items in arrays; tolerate both."""
    if isinstance(x, list):
        return x
    return [x] if x is not None else []


def _lldp_scalar(x: object) -> str:
    """Pull a leaf string from a json0 node — ``[{"value": v}]`` / ``{"value":
    v}`` / a bare scalar all collapse to ``str(v)``."""
    items = _lldp_list(x)
    if not items:
        return ""
    first = items[0]
    if isinstance(first, dict):
        return str(first.get("value", "")).strip()
    return str(first).strip()


def _lldp_chassis(iface: dict) -> dict:
    """Return the chassis object for an interface entry, tolerating both the
    json0 array shape (``"chassis": [{"id": ...}]``) and the name-keyed
    ``json`` shape (``"chassis": {"sw1": {"id": ...}}``)."""
    raw = iface.get("chassis")
    items = _lldp_list(raw)
    if items and isinstance(items[0], dict):
        c = items[0]
        # Name-keyed single-entry dict (no "id" key) → unwrap the inner value.
        # The KEY is the chassis sys-name in this shape, so fold it in as
        # ``name`` (unless the inner dict already carries one) — otherwise
        # remote_sys_name is silently lost for those lldpd builds.
        if "id" not in c and len(c) == 1:
            key, inner = next(iter(c.items()))
            if isinstance(inner, dict):
                return inner if "name" in inner else {**inner, "name": key}
        return c
    return {}


def _parse_lldp_neighbours(doc: object) -> list[dict]:
    """Flatten ``lldpcli show neighbors -f json0`` into neutral neighbour
    dicts the control plane ingests. Defensive — skips malformed entries
    rather than raising, so one weird neighbour can't drop the whole batch.
    """
    out: list[dict] = []
    if not isinstance(doc, dict):
        return out
    for lldp in _lldp_list(doc.get("lldp")):
        if not isinstance(lldp, dict):
            continue
        for iface in _lldp_list(lldp.get("interface")):
            if not isinstance(iface, dict):
                continue
            # ``_lldp_scalar`` handles both a plain ``"eth0"`` and json0's
            # array-wrapped ``[{"value": "eth0"}]`` forms uniformly.
            local = _lldp_scalar(iface.get("name"))
            chassis = _lldp_chassis(iface)
            ports = _lldp_list(iface.get("port"))
            port = ports[0] if ports and isinstance(ports[0], dict) else {}

            chassis_id = _lldp_scalar(chassis.get("id"))
            port_id = _lldp_scalar(port.get("id"))
            if not local or not chassis_id or not port_id:
                continue  # the identity tuple must be complete

            caps = [
                str(c.get("type"))
                for c in _lldp_list(chassis.get("capability"))
                if isinstance(c, dict) and c.get("enabled") and c.get("type")
            ]
            out.append(
                {
                    "local_iface": local[:64],
                    "remote_chassis_id": chassis_id[:255],
                    "remote_port_id": port_id[:255],
                    "remote_port_descr": (_lldp_scalar(port.get("descr")) or None),
                    "remote_sys_name": (_lldp_scalar(chassis.get("name")) or None),
                    "remote_sys_descr": (_lldp_scalar(chassis.get("descr")) or None),
                    "remote_mgmt_ip": (_lldp_scalar(chassis.get("mgmt-ip")) or None),
                    "remote_caps": (",".join(caps) or None),
                }
            )
    return out


def read_lldp_neighbours() -> list[dict] | None:
    """Run ``lldpcli show neighbors -f json0`` + parse it (#347).

    Returns the neighbour list (possibly empty) on a successful run, or
    ``None`` when not on an appliance / lldpcli is unavailable or errors — so
    the control plane leaves the stored set alone rather than wiping it on a
    transient failure. An empty list DOES wipe (lldpd ran, saw nothing)."""
    if detect_deployment_kind() != "appliance":
        return None
    try:
        proc = subprocess.run(
            ["lldpcli", "-f", "json0", "show", "neighbors"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    return _parse_lldp_neighbours(doc)


def maybe_fire_ntp_reload(bundle_block: object) -> bool:
    """Issue #154 — write the ntp-config trigger when the control
    plane's rendered chrony.conf hash differs from the last applied.

    Identical idempotency shape to ``maybe_fire_snmp_reload``:
    appliance-only gate, hash sidecar lookup, single trigger file
    rename, fail silent on OSError. Different paths so the SNMP and
    NTP pipelines never collide.
    """
    if detect_deployment_kind() != "appliance":
        return False
    if not isinstance(bundle_block, dict):
        return False
    config_hash = str(bundle_block.get("config_hash") or "")
    chrony_conf = str(bundle_block.get("chrony_conf") or "")
    allow_clients = bool(bundle_block.get("allow_clients"))
    # Four-line header:
    #   line 1:  marker — ``enabled`` is always the case for chrony
    #            (it's always running on the appliance); kept for
    #            shape-parity with the SNMP runner.
    #   line 2:  ``allow_clients`` — ``true`` / ``false`` so the runner
    #            knows whether to open the UDP 123 nft drop-in.
    #   line 3:  config_hash (sha256 hex)
    #   line 4+: rendered chrony.conf body
    payload = (
        "enabled\n"
        + ("true\n" if allow_clients else "false\n")
        + (config_hash + "\n")
        + chrony_conf
    )
    # #387 — shared bounded-retry guard. Before this, the bad
    # ``chronyd -t -f`` validate flag made every apply fail, and the
    # naive re-fire flooded 2374 .failed sidecars on ddi1. The guard
    # backs off a stuck apply; the chrony runner fix makes it succeed.
    return _fire_host_config(_NTP_TRIGGER_FILE, _NTP_HASH_SIDECAR, config_hash, payload)


def read_ntp_sync_state() -> str | None:
    """Read chrony's last-reported sync state from the sidecar the
    host-side runner refreshes on each apply. One of ``synchronized``
    / ``unsynchronized`` / ``unknown``, or ``None`` on docker / k8s
    (no sidecar mounted)."""
    if not _NTP_STATUS_SIDECAR.exists():
        return None
    try:
        text = _NTP_STATUS_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if text in ("synchronized", "unsynchronized", "unknown"):
        return text
    return None


_HOST_K3S_KUBECONFIG = Path("/etc/spatiumddi-host/rancher/k3s/k3s.yaml")
# Fallback when the bind mount is the supervisor compose's
# ``/etc/rancher/k3s`` path-through instead of the
# ``/etc/spatiumddi-host`` mount. Both layouts exist in the wild.
_DIRECT_K3S_KUBECONFIG = Path("/etc/rancher/k3s/k3s.yaml")
_K3S_VERSION_SIDECAR = Path("/usr/share/doc/k3s/.version")

# Issue #285 Phase 1 — firewall prerequisites. The k3s config files are
# already reachable via the ``/etc/rancher/k3s`` (kubeconfig) bind mount;
# the live base nftables.conf is exposed by a dedicated read-only File
# mount the supervisor DaemonSet adds in #285 (absent on older charts /
# non-appliance, where the reader returns None).
_K3S_CIDRS_DROPIN = Path("/etc/rancher/k3s/config.yaml.d/spatium-cidrs.yaml")
_K3S_MAIN_CONFIG = Path("/etc/rancher/k3s/config.yaml")
_K3S_CONFIG_DIR = Path("/etc/rancher/k3s/config.yaml.d")
_HOST_NFTABLES_CONF = Path("/etc/nftables-host.conf")


def read_k3s_version() -> str | None:
    """Issue #183 Phase 5 — installed k3s version stamped by the
    build-time ``fetch-k3s.sh`` script. Single value per slot; the
    Fleet UI shows it next to the appliance row.

    Returns ``None`` when the sidecar is missing — pre-#183 slots or
    non-appliance deploys.
    """
    if not _K3S_VERSION_SIDECAR.exists():
        return None
    try:
        text = _K3S_VERSION_SIDECAR.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def read_kubeconfig() -> str | None:
    """Issue #183 Phase 5 — operator kubeconfig payload.

    Reads ``k3s.yaml`` straight off the slot's /etc overlay (the
    admin kubeconfig k3s writes on first start). Returns the raw
    YAML text — the backend rewrites the ``server:`` field for
    operator reachability (using the appliance's last-seen IP) and
    Fernet-encrypts before persisting.

    Returns ``None`` when:
      * The supervisor isn't on a k3s appliance (``detect_runtime()
        != "k3s"``)
      * The kubeconfig file doesn't exist yet (k3s.service hasn't
        started, or first-boot is still warming up)

    Shipping the cleartext kubeconfig over the heartbeat is safe —
    the heartbeat channel is already mTLS-encrypted end-to-end with
    the supervisor's cert. At-rest encryption is the backend's job.
    """
    if detect_runtime() != "k3s":
        return None
    for path in (_HOST_K3S_KUBECONFIG, _DIRECT_K3S_KUBECONFIG):
        if path.exists():
            try:
                return path.read_text(encoding="utf-8")
            except OSError:
                continue
    return None


# Issue #183 Phase 6 — k3s server cert expiry probe. The k3s
# default serving cert lives at one of two paths depending on
# whether the supervisor's host bind mount picked up /var/lib/
# rancher (the standard layout) or /var/lib/spatiumddi-host/
# rancher (the bind-mount-everything fallback). Probe both.
_K3S_SERVING_CERT_CANDIDATES = (
    Path("/var/lib/spatiumddi-host/rancher/k3s/server/tls/serving-kube-apiserver.crt"),
    Path("/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt"),
)


def read_k3s_api_cert_expiry() -> str | None:
    """Issue #183 Phase 6 — k3s server-cert ``Not After`` timestamp.

    k3s rotates this cert automatically (1-year default). Surfacing
    the expiry on the heartbeat lets the Fleet UI render an
    "expires in N days" chip + drives the
    ``k3s_api_cert_expiring`` alert rule at 30 / 7 day thresholds.

    Returns the ISO-8601 UTC timestamp string the backend stores in
    ``Appliance.k3s_api_cert_expires_at``. ``None`` when the cert
    isn't readable (not k3s, no bind mount, file missing, parse
    error). The backend's "only update when not None" semantics
    leave the column untouched in those cases.
    """
    if detect_runtime() != "k3s":
        return None
    for path in _K3S_SERVING_CERT_CANDIDATES:
        if not path.exists():
            continue
        try:
            pem = path.read_bytes()
        except OSError:
            continue
        try:
            # cryptography is already a supervisor dep (cert_auth
            # signs heartbeat bodies with the supervisor's Ed25519
            # key). Lazy-import so non-cert-bearing imports stay
            # fast.
            from cryptography import x509  # noqa: PLC0415

            cert = x509.load_pem_x509_certificate(pem)
        except (ValueError, ImportError):
            return None
        # cert.not_valid_after_utc lands in cryptography 42+; the
        # older naïve-datetime accessor is deprecated but still
        # works as a fallback for forks that pin an older version.
        not_after = getattr(cert, "not_valid_after_utc", None) or getattr(
            cert, "not_valid_after", None
        )
        if not_after is None:
            return None
        if not_after.tzinfo is None:
            from datetime import timezone  # noqa: PLC0415

            not_after = not_after.replace(tzinfo=timezone.utc)
        return not_after.isoformat()
    return None


def read_cluster_health() -> dict[str, object] | None:
    """Issue #183 Phase 4 — local k3s health summary for the
    heartbeat's slow drift channel.

    Probes the local kubeapi for:
      * Node count + how many report ``Ready``
      * Pod count in the ``spatium`` namespace + per-phase breakdown
      * Whether the kubeapi itself reports ``/readyz`` ok

    Returns ``None`` when k3s isn't the runtime (no probe attempted)
    or ``{}`` when probes fail (kubeapi unreachable from a
    runtime-claimed-as-k3s appliance, which itself is signal).

    Pure read-only — never mutates cluster state. Sub-2s total probe
    budget so the heartbeat-collect step stays cheap.
    """
    if detect_runtime() != "k3s":
        return None

    # Lazy import — non-appliance / non-k3s deployments don't load
    # the kubeapi client.
    from . import k8s_api  # noqa: PLC0415

    summary: dict[str, object] = {"kubeapi_ready": False}
    if not k8s_api.check_kubeapi_ready(timeout=1.5):
        return summary
    summary["kubeapi_ready"] = True

    # Node count via the kubeapi list. Each node carries a
    # ``conditions`` array; the ``Ready`` condition's ``status`` is
    # ``True`` when the kubelet says so.
    try:
        status_code, body = k8s_api._request("GET", "/api/v1/nodes")
    except (RuntimeError, OSError):
        return summary
    if status_code == 200:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = {}
        nodes = data.get("items") or []
        ready = 0
        for n in nodes:
            for cond in (n.get("status") or {}).get("conditions") or []:
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    ready += 1
                    break
        summary["nodes_total"] = len(nodes)
        summary["nodes_ready"] = ready

    # Pod count in the spatium namespace, grouped by phase.
    try:
        status_code, body = k8s_api._request("GET", "/api/v1/namespaces/spatium/pods")
    except (RuntimeError, OSError):
        return summary
    if status_code == 200:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            data = {}
        pods = data.get("items") or []
        phase_counts: dict[str, int] = {}
        for p in pods:
            phase = (p.get("status") or {}).get("phase") or "Unknown"
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
        summary["pods_total"] = len(pods)
        summary["pods_by_phase"] = phase_counts
    elif status_code == 404:
        # Namespace doesn't exist yet — no role assigned, no pods.
        summary["pods_total"] = 0
        summary["pods_by_phase"] = {}

    return summary


# Issue #402 — host disk partitions for the Cluster → Overview dashboard.
# Reported INSIDE the cluster_health dict (which the backend stores verbatim
# to the appliance.cluster_health JSONB column), so this needs no new
# heartbeat field / column / migration. statvfs the host filesystems the
# supervisor can reach: the active root slot (``/`` via the #402 host-root
# mount), the ``/var`` data partition (via the release-state bind, which
# itself lives on /var), and the ESP (``/boot/efi-host``). Best-effort per
# target — a missing mount (e.g. an older supervisor pod without the
# host-root mount) is skipped, so the list degrades to whatever's reachable.
_DISK_TARGETS = (
    ("/", "OS (root slot)", "/host-root"),
    ("/var", "Data", "/var/lib/spatiumddi-host/release-state"),
    ("/boot/efi", "ESP", "/boot/efi-host"),
)


def read_host_disk_partitions() -> list[dict[str, object]]:
    """statvfs the reachable host partitions → used/total bytes per mount.

    Powers the Cluster → Overview node cards (#402). Each entry:
    ``{"mount", "label", "total_bytes", "used_bytes"}`` — ``df``-style, where
    ``used = (blocks - free) * fragment_size``. Returns the partitions that
    could be statvfs'd (skips any whose mount isn't present in this pod).
    """
    out: list[dict[str, object]] = []
    for mount, label, path in _DISK_TARGETS:
        try:
            st = os.statvfs(path)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            continue
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        out.append(
            {
                "mount": mount,
                "label": label,
                "total_bytes": int(total),
                "used_bytes": int(used),
            }
        )
    return out


# ── Issue #999 Part A — storage redundancy telemetry ──────────────────
#
# Reported INSIDE the cluster_health dict, exactly like the #402 host
# partitions above: the backend stores that dict verbatim to
# appliance.cluster_health (JSONB), so this needs no new heartbeat
# field, no column and no migration.
#
# Why monitoring ships BEFORE the install support (#999 Parts B + C):
# a mirrored root with no degraded-array alarm is a mirror that
# silently becomes a single disk. The operator pays for two disks, the
# array loses a member at 03:00, nothing says so, and the appliance
# keeps serving perfectly until the survivor dies — strictly worse
# than never mirroring, because it displaced the backup discipline
# they would otherwise have kept. So the alarm is a precondition for
# offering the capability, not a follow-on to it.
#
# The reads are the HOST's. /sys is never PID- or mount-namespaced and
# the supervisor DaemonSet runs ``privileged: true`` + ``hostPID:
# true``, so /proc is the host's too — which is not a new assumption
# here: ``_current_slot_from_cmdline()`` has read the host's
# /proc/cmdline through the same window since #170, and
# ``heartbeat.py`` already reads /sys/block/*/queue/rotational.
_PROC_MDSTAT = Path("/proc/mdstat")
_SYS_BLOCK = Path("/sys/block")

# How many members a level can lose and still serve. Used to turn a
# member count into "redundancy remaining", which is what decides the
# alert severity: 2-of-3 in a three-way mirror and 1-of-2 in a pair
# both report "degraded", and only the second one is an emergency.
#
# raid10 is deliberately pessimistic. A 4-disk raid10 survives two
# failures if they land in different mirror pairs and one if they do
# not, and sysfs does not say which member sits in which pair — so the
# GUARANTEED tolerance is 1, and an alarm should be sized to the
# guarantee rather than to the lucky case.
# md ``level`` values that are not a redundancy group at all. A
# ``container`` is the IMSM / DDF metadata holder that real arrays are
# built inside; it is permanently ``inactive`` with ``raid_disks=0``.
_NON_ARRAY_LEVELS = frozenset({"container"})


def _min_working_members(level: str, total: int) -> int:
    """Fewest in-sync members this array can serve on."""
    if level == "raid1":
        return 1
    if level in ("raid4", "raid5"):
        return max(total - 1, 1)
    if level == "raid6":
        return max(total - 2, 1)
    if level == "raid10":
        return max(total - 1, 1)
    # raid0 / linear / anything unrecognised: assume no redundancy, so
    # every member is load-bearing. Guessing generously here would
    # under-report a real emergency.
    return total


def _read_sysfs(path: Path) -> str | None:
    """First line of a sysfs attribute, or None when unreadable."""
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return None


def _read_sysfs_int(path: Path) -> int | None:
    raw = _read_sysfs(path)
    if raw is None:
        return None
    try:
        return int(raw.split()[0])
    except (ValueError, IndexError):
        return None


def _md_members(md_dir: Path) -> list[dict[str, object]]:
    """Per-member state for one array, from ``/sys/block/mdX/md/dev-*``.

    ``state`` is the kernel's own comma-joined member state
    (``in_sync``, ``faulty``, ``spare``, ``write_mostly``, …) —
    reported verbatim rather than collapsed, because "faulty" and
    "spare" call for opposite operator actions.
    """
    members: list[dict[str, object]] = []
    try:
        entries = sorted(md_dir.glob("dev-*"))
    except OSError:
        return members
    for entry in entries:
        state = _read_sysfs(entry / "state") or "unknown"
        slot_raw = _read_sysfs(entry / "slot")
        try:
            slot: int | None = int(slot_raw) if slot_raw not in (None, "none") else None
        except ValueError:
            slot = None
        members.append(
            {
                "device": entry.name[len("dev-") :],
                "state": state,
                "slot": slot,
            }
        )
    # Slot order is the order the operator sees in ``mdadm --detail``;
    # a member with no slot (a spare, or one being removed) sorts last.
    members.sort(
        key=lambda m: (
            m["slot"] is None,
            m["slot"] if isinstance(m["slot"], int) else 0,
            str(m["device"]),
        )
    )
    return members


def _md_sync(md_dir: Path) -> dict[str, object] | None:
    """Rebuild / scrub progress, or None when the array is idle.

    ``sync_completed`` is ``"<done> / <total>"`` in sectors while a sync
    runs and the literal ``"none"`` when it does not. Both numbers come
    from that one file and nothing substitutes for a missing total —
    ``/sys/block/mdX/size`` is the ARRAY's size, which is not the
    per-member extent being synced on anything but a mirror, so using it
    as a denominator would quietly report a wrong percentage on raid5/6.
    No reading beats a plausible wrong one.
    """
    action = _read_sysfs(md_dir / "sync_action")
    if action in (None, "idle"):
        return None
    out: dict[str, object] = {"action": action}
    completed_raw = _read_sysfs(md_dir / "sync_completed")
    done = total = None
    if completed_raw and "/" in completed_raw:
        left, _, right = completed_raw.partition("/")
        try:
            done, total = int(left.strip()), int(right.strip())
        except ValueError:
            done = total = None
    if done is not None and total:
        out["percent"] = round(min(done / total, 1.0) * 100, 1)
    # sync_speed is KB/s; a sector is 512 B, so two sectors per KB.
    speed = _read_sysfs_int(md_dir / "sync_speed")
    if speed and done is not None and total and total > done:
        out["eta_seconds"] = int((total - done) / (speed * 2))
    return out


def _md_arrays() -> list[dict[str, object]]:
    """Every assembled md array, from ``/sys/block/md*/md/``.

    sysfs is the source rather than /proc/mdstat because mdstat is a
    human-readable text format whose per-member and per-progress
    fields have to be regex'd apart, while every one of them is its
    own file here. mdstat is still consulted — by ``read_storage_
    health`` — for whether md is SUPPORTED at all, which sysfs cannot
    answer: no arrays and no md_mod produce an identical empty glob.
    """
    arrays: list[dict[str, object]] = []
    try:
        candidates = sorted(_SYS_BLOCK.glob("md*"))
    except OSError:
        return arrays
    for block in candidates:
        md_dir = block / "md"
        if not md_dir.is_dir():
            continue
        level = _read_sysfs(md_dir / "level") or "unknown"
        if level in _NON_ARRAY_LEVELS:
            # An IMSM / DDF metadata CONTAINER (level ``container``) is
            # not a redundancy group — it holds the vendor metadata that
            # the real arrays inside it are built from, and it reports
            # ``array_state=inactive`` with ``raid_disks=0`` forever, on
            # a perfectly healthy box. Classifying it would open a
            # critical alert nothing can ever clear. The member arrays
            # (md126 and friends) carry the real level and are reported
            # normally.
            continue
        array_state = _read_sysfs(md_dir / "array_state") or "unknown"
        # None, never 0. ``raid_disks`` is how many members the array is
        # SUPPOSED to have, so it is the denominator every degradation
        # test divides by — and a 0 standing in for "could not read it"
        # makes every one of those tests false, dropping an unreadable
        # array through to "clean". Unknown is never clean.
        expected = _read_sysfs_int(md_dir / "raid_disks")
        members = _md_members(md_dir)
        in_sync = sum(1 for m in members if "in_sync" in str(m["state"]).split(","))
        faulty = sum(1 for m in members if "faulty" in str(m["state"]).split(","))
        spares = sum(1 for m in members if "spare" in str(m["state"]).split(","))
        # /sys/block/mdX/size is in 512-byte sectors.
        size_sectors = _read_sysfs_int(block / "size")
        sync = _md_sync(md_dir)
        usable = expected is not None and expected > 0
        minimum = _min_working_members(level, expected) if usable else None

        # State is derived, not copied: array_state says "clean" for a
        # degraded-but-consistent array, which is exactly the reading
        # that must not read as healthy.
        #
        # ``inactive`` is tested FIRST and needs no member count: an
        # array that failed to assemble often reports ``raid_disks=0``
        # too, and deciding on the count would demote a real failure to
        # "unknown". Containers, the other permanently-inactive thing in
        # /sys/block, are already filtered out above.
        if array_state == "inactive":
            state = "failed"
        elif not usable or minimum is None:
            # The array exists (it has an ``md/`` directory) but will not
            # say how many members it is supposed to have, so nothing
            # below can be decided. Reported as its own state rather than
            # folded into any of the others — a green tick here would be
            # a claim we have no basis for.
            state = "unknown"
        elif in_sync < minimum:
            state = "failed"
        elif in_sync < expected:  # type: ignore[operator]
            state = "degraded"
        elif sync is not None:
            state = "syncing"
        else:
            state = "clean"

        entry: dict[str, object] = {
            "name": block.name,
            "level": level,
            "state": state,
            "array_state": array_state,
            "members_expected": expected if usable else None,
            "members_in_sync": in_sync,
            "members_faulty": faulty,
            "spares": spares,
            # How many more members can be lost before the array stops
            # serving. This — not the state string — is what decides
            # alert severity, so it is computed once here rather than
            # re-derived per surface.
            "redundancy_remaining": (
                max(in_sync - minimum, 0) if minimum is not None else None
            ),
            "min_working_members": minimum,
            "size_bytes": size_sectors * 512 if size_sectors else None,
            "members": members,
        }
        if sync is not None:
            entry["sync"] = sync
        arrays.append(entry)
    return arrays


def _multipath_maps() -> list[dict[str, object]]:
    """Every device-mapper multipath map, from ``/sys/block/dm-*``.

    Identified exactly as ``_disk_hazard()`` in the installer does it:
    a ``dm/uuid`` whose first ``-``-separated field is ``mpath``.

    Per-PATH state is reported ``unknown`` on purpose. dm-multipath's
    own verdict for a path lives in the target's status line, reachable
    only through the device-mapper ioctl (``dmsetup status`` /
    ``multipathd show topology``) — Part B tooling, not in this image.
    Fabricating ``active`` here would turn a missing reading into a
    false all-clear, which is the one answer worse than "unknown".

    What IS honestly readable is the SCSI device state of each path
    (``/sys/block/<dev>/device/state``: ``running`` / ``offline`` /
    ``blocked`` / ``transport-offline``), reported alongside as
    ``device_state`` — a different fact from dm's path state, named
    differently so the two are not confused.
    """
    maps: list[dict[str, object]] = []
    try:
        candidates = sorted(_SYS_BLOCK.glob("dm-*"))
    except OSError:
        return maps
    for block in candidates:
        uuid = _read_sysfs(block / "dm" / "uuid")
        if not uuid or uuid.split("-", 1)[0] != "mpath":
            continue
        paths: list[dict[str, object]] = []
        try:
            slaves = sorted((block / "slaves").iterdir())
        except OSError:
            slaves = []
        for slave in slaves:
            paths.append(
                {
                    "device": slave.name,
                    # dm's own path verdict — see the docstring.
                    "state": "unknown",
                    "device_state": _read_sysfs(
                        _SYS_BLOCK / slave.name / "device" / "state"
                    ),
                }
            )
        # Counted the negative way round on purpose: a path whose SCSI
        # state we cannot read (an NVMe path has no ``device/state``)
        # must not be counted as HEALTHY, or an unreadable map would
        # report a clean bill of health. A non-zero ``paths_faulted``
        # is a definite fault; zero is "nothing says otherwise".
        faulted = sum(
            1
            for p in paths
            if p["device_state"] is not None and p["device_state"] != "running"
        )
        size_sectors = _read_sysfs_int(block / "size")
        maps.append(
            {
                "name": _read_sysfs(block / "dm" / "name") or block.name,
                "dm_device": block.name,
                "uuid": uuid,
                "paths_total": len(paths),
                # Paths whose SCSI device reports a definite fault.
                # Not a claim about which paths dm is USING.
                "paths_faulted": faulted,
                "size_bytes": size_sectors * 512 if size_sectors else None,
                "paths": paths,
            }
        )
    return maps


def read_network_state() -> dict[str, object] | None:
    """Effective interface MTU for the fleet-consistency check (#1017).

    Shape::

        {"interface": "eth0", "mode": "static", "mtu": 1400,
         "mtu_requested": 1400, "mtu_applied": "applied"}

    ``None`` when the sidecar is absent — a slot too old to write it, or
    a non-appliance host. That is UNKNOWN and never "this node is at the
    default", because the whole point upstream is comparing nodes
    against each other: an unknown read scored as 1500 would report a
    genuine mismatch as agreement on exactly the nodes whose supervisor
    could not answer.

    **The value is what was APPLIED, not what STATE asked for**, and the
    distinction is load-bearing. ``spatium-etc-render`` drops a
    requested MTU that is out of range, or that would break a pinned
    IPv6 address (RFC 8200), or that has no keyfile to live in (DHCP
    with no pinned port). Reporting the request would have the control
    plane agree that a node running 9000 and a node that asked for 9000
    and had it refused are consistent — which is the mixed-MTU black
    hole the check exists to catch, reported as healthy.

    Read from a sidecar rather than from the kernel because the
    supervisor pod is not ``hostNetwork``: its own ``/sys/class/net``
    shows pod veths, so the host's real MTU is not visible to it. Same
    reason ``host_network_interfaces`` goes via udev.
    """
    try:
        text = _HOST_NETWORK_STATUS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip()

    # The sidecar must have been written by THIS boot.
    #
    # /etc is an overlay whose upperdir lives on /var, so it is shared
    # across the A/B slots. Trial-boot a new slot, have it roll back, and
    # the file written by the new slot's renderer survives into a running
    # slot that never wrote it — and an abort anywhere in that long
    # `set -eu` script leaves the previous boot's claim in place just the
    # same. Either way the reading describes a configuration the running
    # system is not using, and reporting it as fact is the "told it took
    # effect, it did not" failure this whole feature exists to prevent.
    # A stale file is UNKNOWN, which every surface already renders as
    # nothing rather than as a clean bill of health.
    stamped = fields.get("BOOT_ID", "")
    try:
        current = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        current = ""
    if not stamped or not current or stamped != current:
        return None

    def _int(name: str) -> int | None:
        raw = fields.get(name, "")
        return int(raw) if raw.isdigit() else None

    return {
        "interface": fields.get("INTERFACE") or None,
        "mode": fields.get("MODE") or None,
        "mtu": _int("MTU"),
        # Carried as the RAW string, unlike ``mtu`` above, because its
        # whole job is to show the operator what they configured — and
        # the case it exists for is the one where that value was not a
        # number. Parsed with the same digit test, "+1400" and "1400abc"
        # become None precisely when the renderer dropped them for being
        # unparseable, and every surface then reports "MTU None was
        # configured but not applied".
        "mtu_requested": fields.get("MTU_REQUESTED") or None,
        # "applied" / "default" / "dropped" / "n/a" — see the renderer.
        # Absent from a sidecar written by an older slot, which is why
        # this is not defaulted to anything meaningful.
        "mtu_applied": fields.get("MTU_APPLIED") or None,
    }


def read_storage_health() -> dict[str, object]:
    """Storage-redundancy snapshot for the fleet surfaces (#999 Part A).

    Shape::

        {"md_supported": bool, "md_arrays": [...], "multipath_maps": [...]}

    An appliance with neither reports empty lists, which every surface
    renders as nothing at all — an ordinary single-disk box gains no
    clutter. ``md_supported`` distinguishes "the kernel has no md
    support" from "md is loaded and there are no arrays"; without it
    the two are the same empty list, and only the first one means the
    reading is unavailable rather than clean.
    """
    return {
        "md_supported": _PROC_MDSTAT.exists(),
        "md_arrays": _md_arrays(),
        "multipath_maps": _multipath_maps(),
    }


# ── Issue #989 item 3 — removable (USB) disks ────────────────────────
#
# The single-appliance operator with no NAS and no cloud account backs
# up to a USB disk. ``local_volume`` is a path inside the api / worker
# pods, so until this existed there was no supported way to point one at
# a block device: #971 solved the same problem for NFS by speaking the
# protocol in USERSPACE, and a block device has no userspace escape
# hatch. So this is the host mount plane.
#
# THE READ HALF LISTS EVERY USB FILESYSTEM AND MARKS THE UNUSABLE ONES,
# rather than filtering them out. A disk that does not appear at all
# reads as a broken feature — the operator plugged it in and nothing
# happened — and there is no way to tell that from "SpatiumDDI has not
# noticed it yet". The #1026 slot-image picker made the same call: a
# candidate that cannot be used is shown DISABLED with the reason.
#
# The reads are the HOST's — /sys is never mount-namespaced and the
# supervisor DaemonSet is privileged with hostPID, the same window
# ``_md_arrays()`` and ``_current_slot_from_cmdline()`` already use.

_SYS_DEV_BLOCK = Path("/sys/dev/block")

#: Where the host mount plane puts removable filesystems, as the
#: SUPERVISOR sees it (a HostToContainer bind of the host's
#: /var/lib/spatiumddi/removable). Propagation is load-bearing and not a
#: detail: a hostPath volume defaults to private propagation, under
#: which a mount the host makes AFTER the pod started is invisible
#: inside it — the pod sees the empty underlying directory, writes
#: land on the appliance's own /var, and every surface reports success.
_REMOVABLE_ROOT = Path("/host-removable")

#: The SAME directory as seen by the host — which is a different string,
#: and conflating the two is a bug that reads as working code.
#: ``_host_mounted_sources`` parses /proc/1/mountinfo, and under
#: ``hostPID: true`` the kernel renders those paths against host init's
#: root: a disk we mounted ourselves comes back as
#: ``/var/lib/spatiumddi/removable/usb1``, never ``/host-removable/usb1``.
#: Comparing a mountinfo path against ``_REMOVABLE_ROOT`` can therefore
#: NEVER match, which would report every disk this feature successfully
#: mounted as "already mounted" by somebody else — and refuse to
#: re-mount it.
_REMOVABLE_HOST_ROOT = Path("/var/lib/spatiumddi/removable")

#: Filesystems a removable backup disk may carry.
#:
#: vfat is deliberately absent, and not for tidiness: FAT32 caps a
#: single file at 4 GiB, so an estate whose archive grows past that
#: would fail mid-run, at the END of a long backup, on a destination
#: that had worked for months. Refusing up front with the reason is a
#: better answer than a write that returns EFBIG in an hour.
#:
#: ntfs is absent because nothing in the image can fsck it and the issue
#: scoped v1 to ext4 + exFAT; it is reported with that reason rather
#: than hidden, so an operator who brings an NTFS disk is told what to
#: reformat it as instead of wondering why it never appeared.
_SUPPORTED_FSTYPES = frozenset({"ext4", "exfat"})

#: PARTLABELs and filesystem labels the INSTALLER puts on the
#: appliance's own partitions. An appliance that BOOTS from USB reports
#: its own root, ESP, STATE and **var** partitions as removable
#: candidates — every one of them ``ID_BUS=usb`` with a real filesystem —
#: and offering one of those as a backup destination is the worst
#: outcome this feature could produce. Matched case-insensitively
#: against both the GPT name and the filesystem label, because
#: ``spatium-install`` sets the two independently (``sgdisk -c6:var``
#: and ``mkfs.ext4 -L var``).
#:
#: ``var`` is the one that matters most and was missing from the first
#: draft: it is ``-n6:0:0``, the whole remaining disk, and it holds
#: PostgreSQL, the container images and ``/var/lib/spatiumddi`` itself.
#: Mounting it under the removable root binds the same superblock a
#: second time, so archives land on the appliance's own /var while
#: ``ismount`` passes, the 0500 guard passes, and the run reports
#: success — every advertised defence green.
#:
#: ``boot`` was in the first draft and is NOT a label any partition
#: carries (the BIOS one is ``bios_boot``), so it protected nothing.
#: Kept in sync by hand with ``spatium-install``'s ``sgdisk -c…`` /
#: ``mkfs -L…`` calls, and backstopped by the booted-disk check below,
#: which needs no list at all.
_RESERVED_LABELS = frozenset({"root_a", "root_b", "state", "var", "esp", "esp2"})


def _udev_properties(entry: Path) -> tuple[dict[str, str], list[str]]:
    """``E:`` properties + ``S:`` symlinks out of one /run/udev/data record."""
    props: dict[str, str] = {}
    links: list[str] = []
    try:
        text = entry.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return props, links
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("E:"):
            key, _, value = line[2:].partition("=")
            if key:
                props[key] = value
        elif line.startswith("S:"):
            links.append(line[2:].strip())
    return props, links


def _host_mounted_sources() -> dict[str, str]:
    """``{resolved device path: mountpoint}`` for the HOST's own mounts.

    Read from init's mountinfo, which with ``hostPID: true`` is the
    host's. Best-effort by design and never the only guard: it is the
    belt to the reserved-label braces, and its job is to give the
    operator a REASON ("in use at /boot/efi") rather than to be the
    thing standing between a backup and the running root filesystem.
    """
    out: dict[str, str] = {}
    try:
        text = Path("/proc/1/mountinfo").read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        # ``… - <fstype> <source> <superopts>`` — the separator is a
        # lone "-" field, and everything before it is variable-length.
        _, sep, tail = line.partition(" - ")
        if not sep:
            continue
        fields = line.split(" ")
        parts = tail.split(" ")
        if len(parts) < 2 or len(fields) < 5:
            continue
        source = parts[1]
        if not source.startswith("/dev/"):
            continue
        try:
            resolved = str(Path(source).resolve())
        except OSError:
            resolved = source
        # First mount of a device wins; a later bind of the same source
        # would otherwise overwrite the mountpoint the operator knows.
        out.setdefault(resolved, fields[4])
    return out


def _booted_disk_kname() -> str | None:
    """Kernel name of the whole disk this appliance booted from.

    The backstop for ``_RESERVED_LABELS``, and the reason a missing
    label is survivable: a hand-maintained denylist drifts from
    ``spatium-install`` (``var`` was missing from the first draft),
    while "is this on the disk we are running from?" needs no list and
    covers every partition a future installer adds.

    Resolved from the booted slot's own device, which
    ``_current_slot_from_cmdline`` already locates by matching
    /proc/cmdline's ``root=UUID=`` against udev's by-uuid symlinks.
    ``None`` when it cannot be determined, and the refusal then does not
    fire — same call the storage runner's bootloader guard makes: a
    guard that blocks on "I could not tell" is one operators route
    around.
    """
    try:
        cmdline = _PROC_CMDLINE.read_text()
    except OSError:
        return None
    m = _UUID_RE.search(cmdline)
    if not m:
        return None
    root_uuid = m.group(1).lower()
    try:
        entries = list(_UDEV_DATA.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not (entry.name.startswith("b") and ":" in entry.name):
            continue
        _props, links = _udev_properties(entry)
        if not any(
            link.startswith("disk/by-uuid/") and link.rsplit("/", 1)[-1].lower() == root_uuid
            for link in links
        ):
            continue
        kname = _kname_for(entry)
        if not kname:
            return None
        # The PARENT whole disk, so sibling partitions are covered too.
        try:
            return Path("/sys/class/block").joinpath(kname, "..").resolve().name
        except OSError:
            return None
    return None


def _kname_for(entry: Path) -> str:
    """Kernel name for a ``b<major>:<minor>`` udev record, or ``""``."""
    try:
        return _SYS_DEV_BLOCK.joinpath(entry.name[1:]).resolve().name
    except OSError:
        return ""


def _removable_candidate(
    entry: Path,
    mounted: dict[str, str],
    host_root: Path,
    booted_disk: str | None = None,
) -> dict[str, object] | None:
    """One USB filesystem, or None when this udev record is not one.

    ``host_root`` is the removable root **as the host sees it**, because
    ``mounted`` comes from host init's mountinfo — see
    ``_REMOVABLE_HOST_ROOT``.
    """
    props, links = _udev_properties(entry)
    if props.get("ID_BUS") != "usb" and not props.get("ID_USB_DRIVER"):
        return None
    fstype = props.get("ID_FS_TYPE") or ""
    if not fstype:
        # A partition-table parent (``ID_PART_TABLE_TYPE``) or a blank
        # disk. Nothing to mount, and SpatiumDDI does not format disks.
        return None

    kname = _kname_for(entry)
    dev_path = f"/dev/{kname}" if kname else ""

    by_id = next((s for s in links if s.startswith("disk/by-id/")), "")
    fs_uuid = props.get("ID_FS_UUID") or ""
    label = props.get("ID_FS_LABEL") or ""
    partlabel = props.get("ID_PART_ENTRY_NAME") or ""

    size_bytes: int | None = None
    holders: list[str] = []
    parent_disk = ""
    if kname:
        sectors = _read_sysfs_int(Path("/sys/class/block") / kname / "size")
        if sectors is not None:
            # sysfs reports 512-byte sectors regardless of the device's
            # own logical block size.
            size_bytes = sectors * 512
        try:
            holders = sorted(
                p.name for p in (Path("/sys/class/block") / kname / "holders").iterdir()
            )
        except OSError:
            holders = []
        try:
            parent_disk = Path("/sys/class/block").joinpath(kname, "..").resolve().name
        except OSError:
            parent_disk = ""

    mount_point = mounted.get(dev_path) if dev_path else None
    mounted_here = bool(
        mount_point
        and (Path(mount_point) == host_root or host_root in Path(mount_point).parents)
    )

    # ── the refusals, in the order the operator needs to read them ──
    #
    # Ownership FIRST, filesystem second. The ESP is vfat with PARTLABEL
    # ``esp``; asking the fstype question first tells the operator of a
    # USB-booted appliance to "reformat as exfat, ext4" — an instruction
    # to reformat the partition the box boots from, rendered beside a
    # Mount button. Which partition this is matters more than what is on
    # it.
    reason: str | None = None
    if booted_disk and parent_disk and parent_disk == booted_disk:
        reason = "this disk is the one the appliance booted from"
    elif label.lower() in _RESERVED_LABELS or partlabel.lower() in _RESERVED_LABELS:
        reason = "this is one of the appliance's own partitions"
    elif holders:
        reason = f"in use by {', '.join(holders)}"
    elif mount_point and not mounted_here:
        reason = f"already mounted at {mount_point}"
    elif not fs_uuid:
        # Without one there is nothing stable to write into What=; a
        # kernel name is reassigned on the next plug.
        reason = f"{fstype} filesystem has no UUID — nothing stable to mount it by"
    elif fstype not in _SUPPORTED_FSTYPES:
        supported = ", ".join(sorted(_SUPPORTED_FSTYPES))
        extra = (
            " FAT32 caps one file at 4 GiB, which a backup archive can exceed."
            if fstype in ("vfat", "msdos")
            else ""
        )
        reason = f"{fstype} is not supported — reformat as {supported}.{extra}"

    return {
        "device": dev_path,
        "by_id": f"/dev/{by_id}" if by_id else "",
        "fs_uuid": fs_uuid,
        "fstype": fstype,
        "label": label,
        "model": (props.get("ID_MODEL") or "").replace("_", " ").strip(),
        "vendor": (props.get("ID_VENDOR") or "").replace("_", " ").strip(),
        "serial": props.get("ID_SERIAL_SHORT") or "",
        "size_bytes": size_bytes,
        "mounted_at": mount_point if mounted_here else None,
        "usable": reason is None,
        "reason": reason,
    }


def read_removable_apply_status() -> dict[str, str] | None:
    """The host runner's last verdict, or None when it never ran.

    Shape: ``{"state": "applied"|"failed", "at": "<iso>", "error": "…"}``
    — line 1 is ``<state> <iso>``, line 2 the reason (failures only).
    """
    try:
        text = _REMOVABLE_STATUS_SIDECAR.read_text(encoding="utf-8")
    except OSError:
        return None
    lines = text.splitlines()
    if not lines or not lines[0].strip():
        return None
    head = lines[0].split(None, 1)
    out = {"state": head[0]}
    if len(head) > 1:
        out["at"] = head[1].strip()
    if len(lines) > 1 and lines[1].strip():
        out["error"] = lines[1].strip()[:500]
    return out


def read_removable_disks(host_root: Path | None = None) -> list[dict[str, object]]:
    """Every USB filesystem this node can see (#989 item 3).

    ``host_root`` is the removable root **as the HOST sees it**, not as
    this container does — the mountinfo paths it is compared against
    come from host init. See ``_REMOVABLE_HOST_ROOT``.
    """
    root = host_root or _REMOVABLE_HOST_ROOT
    mounted = _host_mounted_sources()
    booted = _booted_disk_kname()
    out: list[dict[str, object]] = []
    try:
        entries = sorted(_UDEV_DATA.iterdir())
    except OSError:
        return out
    for entry in entries:
        # Block records are ``b<major>:<minor>``; ``n…`` are net devices
        # and ``+…`` subsystem tags.
        if not (entry.name.startswith("b") and ":" in entry.name):
            continue
        try:
            row = _removable_candidate(entry, mounted, root, booted)
        except OSError:
            continue
        if row is not None:
            out.append(row)
    out.sort(key=lambda r: (str(r.get("by_id") or ""), str(r.get("device") or "")))
    return out


def read_removable_mounts(removable_root: Path | None = None) -> list[dict[str, object]]:
    """Live state of each configured removable mount (#989 item 3).

    ``mounted`` is decided by comparing st_dev with the parent's, which
    is what ``os.path.ismount`` does and the same test the backup
    driver applies from inside the api / worker pods — so the Fleet UI
    and the destination cannot disagree about whether the disk is there.
    """
    root = removable_root or _REMOVABLE_ROOT
    out: list[dict[str, object]] = []
    try:
        entries = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return out
    for entry in entries:
        mounted = False
        try:
            mounted = os.path.ismount(entry)
        except OSError:
            mounted = False
        # Deliberately NO ``path`` key. The first draft carried one — the
        # mountpoint — while the control plane's ``merge_state`` computes
        # its own ``path`` meaning the ARCHIVE directory inside it. One
        # key, two meanings, and nothing read this one: the "written,
        # never read" class, with a name collision on top.
        row: dict[str, object] = {"name": entry.name, "mounted": mounted}
        if mounted:
            try:
                st = os.statvfs(entry)
                row["total_bytes"] = st.f_blocks * st.f_frsize
                row["free_bytes"] = st.f_bavail * st.f_frsize
            except OSError:
                # Mounted but unstattable — a disk yanked between the
                # ismount and the statvfs. Reported WITHOUT sizes rather
                # than as unmounted: "mounted, size unknown" is the
                # honest reading and the next heartbeat settles it.
                pass
        out.append(row)
    return out


def read_removable_state(
    removable_root: Path | None = None, host_root: Path | None = None
) -> dict[str, object]:
    """The removable-disk block carried inside ``cluster_health``.

    ``supported`` says whether this node can answer at all, which is
    NOT the same as "no disks are plugged in" — without it the Fleet UI
    cannot tell a node with no USB disk from one whose supervisor is too
    old to look, and would render both as an empty, healthy-looking list.
    """
    root = removable_root or _REMOVABLE_ROOT
    return {
        # False = this node cannot look (the /host-removable bind is
        # missing, or its propagation was lost). NOT the same as "no
        # disks": /run/udev is a separate mount, so the disk list can be
        # full while every configured mount reads as absent. Consumed by
        # the control plane, which renders it as its own state.
        "supported": root.exists(),
        # The KUBERNETES node name, which is what a backup target has to
        # record: a removable destination is node-local, and the api /
        # worker pod that runs a backup compares this against its own
        # downward-API NODE_NAME to tell the operator where the disk is.
        # Reported here rather than as a column because it is only ever
        # needed in the context of "which node is this disk plugged
        # into" — and the hostname, which the row already carries, is
        # only USUALLY the node name (k3s defaults it, an operator can
        # override it), and "usually" is not good enough for the field
        # that decides whether a backup lands.
        "node_name": os.environ.get("NODE_NAME")
        or os.environ.get("APPLIANCE_HOSTNAME")
        or "",
        # TWO roots, and they are not interchangeable. The disk scan
        # compares against mountinfo paths, which are the HOST's; the
        # mount-state read stats paths in THIS container. Passing one
        # where the other belongs is silent: every disk we mounted would
        # report "already mounted" by somebody else.
        "disks": read_removable_disks(host_root or _REMOVABLE_HOST_ROOT),
        "mounts": read_removable_mounts(root),
        # The runner's own reason for a failed apply — see
        # ``_REMOVABLE_STATUS_SIDECAR``. Omitted when it never ran.
        "apply_status": read_removable_apply_status(),
    }


def read_node_ip() -> str | None:
    """Return this node's k3s-registered InternalIP (#272 Phase 7b).

    The control-plane promote endpoint needs the SEED's real, routable
    node IP to build the ``--server https://<ip>:6443`` join URL handed
    to joiners. ``last_seen_ip`` can't be used: the supervisor heartbeats
    from inside the cluster, so the control plane sees its POD IP
    (10.42.x.x), which a joiner can't reach. The node's InternalIP is the
    address k3s itself uses for the apiserver + etcd, so it's the correct
    join target.

    Looks the local node up by NODE_NAME (downward-API ``spec.nodeName``,
    set in the supervisor DaemonSet) and returns the first ``InternalIP``
    address. ``None`` when not k3s, NODE_NAME is unset, or the probe
    fails — the backend's "only update when not None" semantics then
    leave the column untouched.
    """
    if detect_runtime() != "k3s":
        return None
    node_name = os.environ.get("NODE_NAME") or os.environ.get("APPLIANCE_HOSTNAME")
    if not node_name:
        return None

    from urllib.parse import quote  # noqa: PLC0415

    from . import k8s_api  # noqa: PLC0415

    try:
        status_code, body = k8s_api._request("GET", f"/api/v1/nodes/{quote(node_name)}")
    except (RuntimeError, OSError):
        return None
    if status_code != 200:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    for addr in (data.get("status") or {}).get("addresses") or []:
        if addr.get("type") == "InternalIP" and addr.get("address"):
            return str(addr["address"])
    return None


def is_control_plane_member() -> bool:
    """True when this node is part of the control-plane k3s cluster: installed
    as a control-plane seed, or an appliance promoted into it whose join the
    host runner has reported ready.

    The one definition, shared by the heartbeat (which switches to the
    in-cluster api Service on a member) and the role chart values (whose agents
    must switch with it, #1281), so the two cannot disagree about a node.
    """
    if detect_appliance_variant() == "control-plane":
        return True
    join_state, _ = read_cluster_join_state()
    return join_state == "ready"


# ── Issue #285 Phase 1 — fleet-firewall prerequisites ────────────────


def read_node_ips() -> list[str] | None:
    """Every k3s-registered InternalIP for this node (#285 Phase 1).

    Unlike ``read_node_ip()`` (the first InternalIP, the join-URL
    source), this returns ALL InternalIPs — both families on a dual-stack
    cluster — so the firewall compiler can derive a family-split peer set
    (``/32`` v4 + ``/128`` v6) instead of fabricating a garbage ``/32``
    from a v6 address. Returns ``None`` when not k3s / NODE_NAME unset /
    probe fails / no InternalIP found, so the backend's "only update when
    not None" semantics leave the column alone.
    """
    if detect_runtime() != "k3s":
        return None
    node_name = os.environ.get("NODE_NAME") or os.environ.get("APPLIANCE_HOSTNAME")
    if not node_name:
        return None

    from urllib.parse import quote  # noqa: PLC0415

    from . import k8s_api  # noqa: PLC0415

    try:
        status_code, body = k8s_api._request("GET", f"/api/v1/nodes/{quote(node_name)}")
    except (RuntimeError, OSError):
        return None
    if status_code != 200:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    ips = [
        str(addr["address"])
        for addr in (data.get("status") or {}).get("addresses") or []
        if addr.get("type") == "InternalIP" and addr.get("address")
    ]
    return ips or None


def _scan_flannel_backend(text: str) -> str | None:
    """Return the ``flannel-backend:`` value from a k3s YAML config body,
    or None when the key isn't present."""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("flannel-backend:"):
            return s.split(":", 1)[1].strip().strip('"').strip("'") or None
    return None


def read_cluster_cidrs() -> tuple[str | None, str | None, str | None]:
    """Parse ``(pod_cidr, service_cidr, dataplane_backend)`` from the k3s
    config (#285 / #302 Phase 1).

    pod/service CIDR come from the ``spatium-cidrs.yaml`` drop-in the
    install wizard writes (``cluster-cidr`` / ``service-cidr``; may be a
    comma-joined dual-stack pair). ``flannel-backend`` is scanned across
    the main ``config.yaml`` + every ``config.yaml.d/*.yaml`` drop-in,
    defaulting to ``vxlan`` (k3s upstream default) when unset.

    Returns ``(None, None, None)`` off k3s. On a k3s appliance the
    backend always resolves (defaults to ``vxlan``); pod/service CIDR may
    still be None on a pre-#302 install with no drop-in, so the backend's
    "only update when not None" semantics leave those columns alone.
    """
    if detect_runtime() != "k3s":
        return None, None, None

    pod_cidr: str | None = None
    service_cidr: str | None = None
    if _K3S_CIDRS_DROPIN.exists():
        try:
            for line in _K3S_CIDRS_DROPIN.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                s = line.strip()
                if s.startswith("cluster-cidr:"):
                    pod_cidr = s.split(":", 1)[1].strip().strip('"').strip("'") or None
                elif s.startswith("service-cidr:"):
                    service_cidr = (
                        s.split(":", 1)[1].strip().strip('"').strip("'") or None
                    )
        except OSError as exc:
            # Drop-in unreadable (perms / mid-write) — fall through with
            # pod/service CIDR as None (the backend leaves those columns
            # alone). Note it so a recurring bind-mount issue isn't silent.
            log.debug("supervisor.cluster_cidrs.dropin_read_failed", error=str(exc))

    # flannel-backend: main config first, then drop-ins in sorted order;
    # first match wins. Default to the k3s upstream ``vxlan`` when nothing
    # set it explicitly.
    backend: str | None = None
    candidates = [_K3S_MAIN_CONFIG]
    try:
        candidates += sorted(_K3S_CONFIG_DIR.glob("*.yaml"))
    except OSError as exc:
        # config.yaml.d enumeration failed — continue with the main
        # config + the vxlan default rather than erroring.
        log.debug("supervisor.cluster_cidrs.dropin_glob_failed", error=str(exc))
    for path in candidates:
        if not path.exists():
            continue
        try:
            found = _scan_flannel_backend(
                path.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            continue
        if found:
            backend = found
            break
    if backend is None:
        backend = "vxlan"

    return pod_cidr, service_cidr, backend


def read_base_conf_marker() -> tuple[str | None, bool | None]:
    """Hash the live base ``/etc/nftables.conf`` + detect the legacy
    LAN-wide k3s accept (#285 Phase 1).

    Returns ``(sha256_hex, lanwide_k3s_present)``. The boolean is the
    self-describing "is this the legacy LAN-wide base or a hardened one"
    signal that gates the UI/compliance claim; the hash is for generic
    change detection. ``(None, None)`` when the file isn't mounted
    (non-appliance / older chart without the read-only mount), so the
    backend leaves both columns untouched.
    """
    if detect_deployment_kind() != "appliance":
        return None, None
    if not _HOST_NFTABLES_CONF.exists():
        return None, None
    try:
        raw = _HOST_NFTABLES_CONF.read_bytes()
    except OSError:
        return None, None
    # An empty / whitespace-only file is the chart's ``hostPath:
    # FileOrCreate`` touching a placeholder when the host has no real
    # base /etc/nftables.conf — NOT a hardened base. Treat it as
    # unavailable (return None,None) so the backend's only-when-not-None
    # semantics don't persist a misleading "hardened" marker (which would
    # otherwise let the Phase-4 all-CP-hardened master-enable gate pass on
    # a node that has no base config at all).
    if not raw.strip():
        return None, None
    marker = hashlib.sha256(raw).hexdigest()
    # The legacy LAN-wide accept carries the literal ``comment "k3s-ha"``
    # tag (see appliance/mkosi.extra/etc/nftables.conf). Its presence ⇒
    # etcd/kubelet are still LAN-wide; its absence ⇒ a hardened base.
    lanwide = 'comment "k3s-ha"' in raw.decode("utf-8", errors="replace")
    return marker, lanwide


def collect() -> dict[str, object]:
    """Snapshot the agent's slot + deployment state for the heartbeat.

    Returns a dict the heartbeat client merges into its outbound body.
    Every value is JSON-serialisable; missing data is represented as
    None so the control plane's "only update when not None" semantics
    leave the DB columns untouched for non-appliance agents.
    """
    deployment_kind = detect_deployment_kind()
    is_appliance = deployment_kind == "appliance"

    # #387 — cull any stale timestamped trigger sidecars every tick so a
    # pre-fix backlog (2374 ntp + 2021 set-next-boot observed on ddi1)
    # is bounded on the first post-upgrade heartbeat, independent of
    # whether any trigger fires this tick. Cheap (a handful of globs).
    if is_appliance:
        prune_all_trigger_sidecars()

    current_slot = _current_slot_from_cmdline() if is_appliance else None
    durable_default = _durable_default_from_grubenv() if is_appliance else None
    is_trial_boot: bool | None = None
    if current_slot and durable_default:
        is_trial_boot = current_slot != durable_default

    last_state, last_state_at = (
        _last_upgrade_state_from_sidecar() if is_appliance else (None, None)
    )
    # #421 — a dead/killed runner leaves the sidecar stuck at in-flight
    # forever (its exit trap never ran). Reap it: report failed and heal
    # the sidecar/trigger so the operator can clear + re-apply.
    if is_appliance:
        last_state, last_state_at = _reap_stale_inflight(last_state, last_state_at)
    # #386 Part C — ship the log tail + structured progress while an
    # upgrade is in-flight / failed / awaiting-reboot (done). For idle
    # appliances ship empty so a stale tail/progress is cleared; None
    # off-appliance so the backend leaves the columns alone.
    _show_progress = is_appliance and last_state in ("in-flight", "failed", "done")
    if not is_appliance:
        last_upgrade_log_tail = None
        last_upgrade_progress: dict[str, object] | None = None
    elif _show_progress:
        last_upgrade_log_tail = _read_slot_upgrade_log_tail()
        last_upgrade_progress = _read_slot_upgrade_progress() or {}
    else:
        last_upgrade_log_tail = ""
        last_upgrade_progress = {}

    slot_a_version, slot_b_version = read_slot_versions()
    cluster_health = read_cluster_health() if is_appliance else None
    # #402 — fold host disk partitions into the cluster_health dict (stored
    # verbatim by the backend; no schema change). Only on appliance hosts;
    # skipped entirely when nothing was reachable so we never ship an empty key.
    if is_appliance:
        _partitions = read_host_disk_partitions()
        if _partitions:
            cluster_health = {
                **(cluster_health or {}),
                "host_disk_partitions": _partitions,
            }
        # #999 Part A — storage redundancy (md arrays + multipath maps),
        # folded into the same dict for the same reason. Shipped
        # unconditionally rather than only when something is present:
        # an empty snapshot is the signal that clears a stale array off
        # every surface after the operator tears one down, and
        # ``md_supported`` is a real reading even with no arrays.
        # #1017 — the effective MTU, folded into the same dict for the
        # same reason (#402: stored verbatim by the backend, no schema
        # change). Shipped only when the sidecar was readable and current:
        # absent means UNKNOWN, and the fleet check upstream must be able
        # to tell that apart from "this node is at the default", or a
        # supervisor that could not answer reads as agreeing.
        #
        # Built in ONE literal with the storage block rather than two
        # adjacent shallow rebuilds of a dict that already carries the
        # node/pod counts and the #402 partition list.
        # #989 item 3 — removable (USB) disks + the state of each
        # configured mount, folded into the same dict for the same
        # reason. Shipped unconditionally like the storage block: an
        # empty reading is what CLEARS a disk off every surface after
        # the operator unplugs it, and ``supported`` distinguishes
        # "nothing plugged in" from "this node cannot look".
        _extra: dict[str, object] = {
            "storage": read_storage_health(),
            "removable": read_removable_state(),
        }
        _network = read_network_state()
        if _network is not None:
            _extra["network"] = _network
        cluster_health = {**(cluster_health or {}), **_extra}
    k3s_version = read_k3s_version() if is_appliance else None
    kubeconfig = read_kubeconfig() if is_appliance else None
    k3s_api_cert_expires_at = read_k3s_api_cert_expiry() if is_appliance else None
    node_ip = read_node_ip() if is_appliance else None

    # Issue #285 Phase 1 — firewall prerequisites.
    node_ips = read_node_ips() if is_appliance else None
    pod_cidr, service_cidr, dataplane_backend = (
        read_cluster_cidrs() if is_appliance else (None, None, None)
    )
    base_conf_marker, base_lanwide_k3s = (
        read_base_conf_marker() if is_appliance else (None, None)
    )

    return {
        "deployment_kind": deployment_kind,
        # #272 Phase 1 — installer-role variant the supervisor is
        # running on. Only meaningful on appliance deploys; None on
        # docker / k8s.
        "appliance_variant": (detect_appliance_variant() if is_appliance else None),
        # #1026 — the node's CPU architecture, one half of the gate that
        # refuses to hand this node an upgrade image built for the other
        # one. Reported on EVERY deployment kind, not just appliance:
        # it is a fact about the machine rather than about the install
        # shape, and gating it on ``is_appliance`` would report None for
        # a docker/k8s supervisor that is perfectly able to say.
        "architecture": detect_architecture(),
        "installed_appliance_version": (
            read_installed_version() if is_appliance else None
        ),
        "current_slot": current_slot,
        "durable_default": durable_default,
        "slot_a_version": slot_a_version,
        "slot_b_version": slot_b_version,
        "is_trial_boot": is_trial_boot,
        # #1446 — which boot this heartbeat comes from. The control plane
        # retires a reboot request when a heartbeat arrives from a
        # different boot, instead of on a 15 s stopwatch that could expire
        # before the request was ever delivered.
        "boot_id": read_boot_id() if is_appliance else None,
        "last_upgrade_state": last_state,
        "last_upgrade_state_at": last_state_at.isoformat() if last_state_at else None,
        # #386 Part C — full upgrade status for the Fleet UI.
        "last_upgrade_log_tail": last_upgrade_log_tail,
        "last_upgrade_progress": last_upgrade_progress,
        # Issue #153 — surfaces in the Fleet view next to deployment
        # kind so operators see at a glance which appliances actually
        # have snmpd running. None on non-appliance deploys.
        "snmpd_running": read_snmpd_running() if is_appliance else None,
        # Issue #154 — chrony sync state from ``chronyc tracking``,
        # captured by the host-side runner on apply. ``synchronized``
        # = leap status OK + reference set; ``unsynchronized`` = no
        # reference / stratum >= 16; ``unknown`` = chronyc unreadable
        # (transient at boot). None on non-appliance deploys.
        "ntp_sync_state": read_ntp_sync_state() if is_appliance else None,
        # Issue #155 — APT host-config state from the runner's status
        # sidecar after validate + swap. None on non-appliance deploys.
        "apt_state": read_apt_state() if is_appliance else None,
        # #387 — per-plane host-config apply health (snmp / ntp / lldp /
        # syslog / ssh / resolver / firewall / timezone). Surfaces a
        # stuck apply (the bounded-retry guard is backing it off) so the
        # Fleet UI shows it honestly instead of a silent re-fire loop.
        # ``{}`` when every plane is applied / unconfigured — clears any
        # stale server-side entry; None off-appliance leaves it untouched.
        "host_config_health": read_host_config_health() if is_appliance else None,
        # #395 — host-migration reconcile health. Surfaces patches whose
        # ``ok`` field in the ``host-patches-applied.json`` ledger is
        # False so the Fleet UI shows a failed grub.cfg re-render (or any
        # future numbered patch) honestly. ``{}`` when all patches are
        # applied — clears any stale server-side entry; None off-appliance
        # leaves the column untouched.
        "host_migration_health": read_host_migration_health() if is_appliance else None,
        # Issue #343 — lldpd running state from the host-side runner's
        # status sidecar. None on non-appliance deploys.
        "lldpd_running": read_lldpd_running() if is_appliance else None,
        # Issue #156 — rsyslog forwarding status from the host-side
        # runner's status sidecar (forwarding / unreachable / disabled).
        # None on non-appliance deploys so the backend leaves the column
        # alone.
        "syslog_forwarding": read_syslog_forwarding() if is_appliance else None,
        # Issue #157 — per-host applied authorized_keys count from the
        # host-side runner's count sidecar. None on non-appliance deploys
        # so the backend leaves the column alone.
        "ssh_key_count": read_ssh_key_count() if is_appliance else None,
        # Issue #158 — systemd-resolved state from the host-side runner's
        # status sidecar (override / automatic / failed). None on
        # non-appliance deploys so the backend leaves the column alone.
        "resolver_status": read_resolver_status() if is_appliance else None,
        # Issue #347 — LLDP neighbours discovered by local lldpd. None when
        # not collected (off-appliance / lldpcli error) so the backend leaves
        # the stored set alone; an empty list means "ran, saw none" (wipe).
        "lldp_neighbours": read_lldp_neighbours() if is_appliance else None,
        # Issue #183 Phase 4 — local k3s health summary. Slow drift
        # signals that ride the heartbeat (fast actions go through
        # the proxy). Empty dict on non-k3s appliances; never None
        # so the backend's "overwrite verbatim" semantics clear stale
        # health when k3s is disabled.
        "cluster_health": cluster_health if cluster_health is not None else {},
        # Issue #183 Phase 5 — operator-facing k3s metadata. The
        # backend rewrites the kubeconfig's ``server:`` field for
        # operator reachability + Fernet-encrypts before persisting.
        # ``None`` when k3s isn't the runtime (backend then leaves
        # the column untouched).
        "k3s_version": k3s_version,
        "kubeconfig": kubeconfig,
        # Issue #183 Phase 6 — k3s server-cert ``Not After``
        # timestamp (ISO-8601 UTC) so the backend can drive expiry
        # alerts. None when not k3s; the backend leaves the column
        # untouched on null.
        "k3s_api_cert_expires_at": k3s_api_cert_expires_at,
        # #272 Phase 7b — control-plane cluster join/leave telemetry.
        # ``k3s_join_token`` only present on the seed; join state from
        # the host runner's .state sidecar. All None on non-appliance.
        "k3s_join_token": read_k3s_join_token() if is_appliance else None,
        "cluster_join_state": (read_cluster_join_state()[0] if is_appliance else None),
        "cluster_join_reason": (read_cluster_join_state()[1] if is_appliance else None),
        # #272 Phase 7b — the node's real routable InternalIP. The
        # promote endpoint builds the k3s join URL from the seed's
        # node_ip; ``last_seen_ip`` is the supervisor POD IP (10.42.x.x),
        # which joiners can't reach. None on non-appliance / non-k3s.
        "node_ip": node_ip,
        # Issue #285 Phase 1 — fleet-firewall prerequisites. All None
        # off-appliance / off-k3s so the backend's "only update when not
        # None" semantics leave the columns alone. Purely additive
        # telemetry — nothing here changes a live firewall yet.
        "node_ips": node_ips,
        "pod_cidr": pod_cidr,
        "service_cidr": service_cidr,
        "dataplane_backend": dataplane_backend,
        "base_conf_marker": base_conf_marker,
        "base_lanwide_k3s": base_lanwide_k3s,
        # Issue #285 Phase 2b — firewall apply-state read-back. None
        # off-appliance so the backend's "only-when-not-None" upsert never
        # blanks the columns. Surfaces what the runner already writes.
        "firewall_applied_hash": read_firewall_applied_hash() if is_appliance else None,
        "firewall_applied_status": (
            read_firewall_applied_status() if is_appliance else None
        ),
        "firewall_base_marker": read_firewall_base_marker() if is_appliance else None,
    }

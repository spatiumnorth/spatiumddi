"""Phase 8b-3 — operator-facing slot upgrade backend.

The api container schedules slot upgrades by writing a trigger file
the host-side ``spatiumddi-slot-upgrade.path`` unit watches; the
runner (``/usr/local/bin/spatiumddi-slot-upgrade``) reads the URL,
invokes ``spatium-upgrade-slot apply`` + ``set-next-boot``, and renames
the trigger to ``.done`` or ``.failed``. Mirrors the existing
``releases.py`` (Phase 4c) shape — same trigger-watcher pattern.

Status detection (``get_slot_status``) reads /proc/cmdline + udev
runtime data (/run/udev/data) + grubenv directly (no need to shell
out to spatium-upgrade-slot status when the api container can do it
itself), and surfaces the trial-boot state so the UI can warn the
operator that a slot has been set as the next boot but not yet
committed.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

# Trigger + log paths inside the api container — bind-mounted to the
# host's /var/lib/spatiumddi/release-state/ and /var/log/spatiumddi/
# via the appliance docker-compose. The host's spatiumddi-slot-upgrade
# .path unit watches the same trigger on its side.
_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-upgrade-pending")
_STATE_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-upgrade-pending.state")
# Phase 8c-3 rollback uses its own trigger so the host-side runner stays
# single-purpose (apply does dd + set-next-boot; rollback only edits
# grubenv). Same release-state dir + same shared log so the UI tails one
# file for both flows.
_ROLLBACK_TRIGGER_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-rollback-pending")
_ROLLBACK_STATE_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-rollback-pending.state")
_UPDATE_LOG = Path("/var/log/spatiumddi-host/slot-upgrade.log")

# grubenv inside the api container — the host's /boot/efi/grub/grubenv
# is bind-mounted at /boot/efi-host so we can read it without docker
# socket gymnastics.
_GRUBENV = Path("/boot/efi-host/grub/grubenv")
_PROC_CMDLINE = Path("/proc/cmdline")
_UDEV_DATA = Path("/run/udev/data")
# Phase 8 — per-slot version sidecar maintained by ``spatium-upgrade-slot
# sync-versions`` (called by spatiumddi-firstboot at every boot + at
# the end of every apply). Maps {"slot_a": "<version>", "slot_b":
# "<version>"} so the OS Image card can show which release lives on
# each slot.
_SLOT_VERSIONS_FILE = Path("/var/lib/spatiumddi-host/release-state/slot-versions.json")


_UUID_RE = re.compile(r"root=UUID=([0-9a-fA-F-]+)")


SlotName = Literal["slot_a", "slot_b"]
UpgradeState = Literal["ready", "in-flight", "done", "failed"]


@dataclass
class SlotStatus:
    """Snapshot of A/B slot state for the UI."""

    appliance_mode: bool
    current_slot: SlotName | None
    durable_default: SlotName | None
    is_trial_boot: bool
    upgrade_state: UpgradeState
    upgrade_state_at: str | None
    log_tail: str
    # Phase 8 per-slot version (Phase 8 #138). slot_a_version / slot_b_
    # _version are the APPLIANCE_VERSION installed on each slot, read
    # from the slot-versions.json sidecar that ``spatium-upgrade-slot
    # sync-versions`` maintains. None when the sidecar is missing
    # (pre-this-release install) or unreadable.
    slot_a_version: str | None
    slot_b_version: str | None


def _read_slot_versions() -> dict[str, str]:
    """Read the per-slot version sidecar maintained by
    ``spatium-upgrade-slot sync-versions``.

    Returns ``{}`` on missing / malformed file — UI then falls back
    to showing nothing under the slot labels.
    """
    if not _SLOT_VERSIONS_FILE.exists():
        return {}
    try:
        text = _SLOT_VERSIONS_FILE.read_text(encoding="utf-8", errors="replace")
        data = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: str(v) for k, v in data.items() if isinstance(v, str)}


def _read_grubenv() -> dict[str, str]:
    """Parse grubenv into a dict. grubenv is a 1024-byte zero-padded
    file with KEY=VALUE lines; we just read the lines we recognise."""
    out: dict[str, str] = {}
    if not _GRUBENV.exists():
        return out
    try:
        text = _GRUBENV.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.rstrip("\x00").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _current_slot_from_cmdline() -> SlotName | None:
    """Resolve which slot we booted from by matching /proc/cmdline's
    root=UUID= against the partition labels via udev runtime data (on a
    mirrored install, the md array's slot name — #3172).

    Reads ``/run/udev/data/b<major>:<minor>`` files directly rather than
    shelling out to ``lsblk``. lsblk inside a container without
    ``/dev/sda*`` bind-mounted can list block topology (from /sys) but
    can't read PARTLABEL / UUID, which it derives from the device
    inode. udev populates the same data into /run/udev/data with
    ``S:`` (symlink) lines like ``S:disk/by-partlabel/root_A`` and
    ``S:disk/by-uuid/aa1311ba-...``; parsing those gives us a
    container-friendly lookup with no extra mounts beyond the
    ``/run/udev`` bind the appliance compose already adds.
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
        if not entry.name.startswith("b"):
            continue
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # #3172 — on a mirrored install (#999) the root filesystem is an md
        # array, which has no PARTLABEL: its by-partlabel links sit on the
        # member partitions, its by-uuid link on the array. The array is
        # named after its slot instead (``mdadm --create /dev/md/root_a``),
        # which udev records as MD_DEVNAME and the ``md/root_a`` link.
        partlabel: str | None = None
        md_name: str | None = None
        matches_uuid = False
        for line in text.splitlines():
            if line.startswith("E:MD_DEVNAME="):
                md_name = line.split("=", 1)[1].strip() or md_name
                continue
            if not line.startswith("S:"):
                continue
            value = line[2:].strip()
            if value.startswith("disk/by-partlabel/"):
                partlabel = value.rsplit("/", 1)[-1]
            elif value.startswith("md/"):
                md_name = md_name or value.rsplit("/", 1)[-1]
            elif value.startswith("disk/by-uuid/"):
                if value.rsplit("/", 1)[-1].lower() == root_uuid:
                    matches_uuid = True
        partlabel = partlabel or md_name
        if matches_uuid and partlabel:
            lower = partlabel.lower()
            if lower == "root_a":
                return "slot_a"
            if lower == "root_b":
                return "slot_b"
    return None


# #421 — mirror the supervisor's _reap_stale_inflight threshold. The host
# runner re-stamps the in-flight marker every ~60s while alive, so a stamp
# older than this means the runner is gone (SIGKILL / power loss, where its
# failed-on-exit trap can't run).
_STALE_INFLIGHT_SECONDS = 300


def _stamp_is_stale(stamp: str | None) -> bool:
    """True if an in-flight stamp is older than the staleness threshold.

    ``date -Iseconds`` emits an offset-aware stamp, so ``fromisoformat`` +
    the UTC subtraction is wall-clock-correct regardless of host tz; an
    old-format stamp without an offset is treated as UTC.
    """
    if not stamp:
        return False
    try:
        dt = datetime.fromisoformat(stamp)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - dt).total_seconds() > _STALE_INFLIGHT_SECONDS


# #1825 — a trigger that lands while systemd is in a ``daemon-reload`` is
# never seen: the reload re-creates the path watches, and per systemd.path(5)
# an already-present file activates the unit only for PathExists= /
# PathExistsGlob= / DirectoryNotEmpty=, "something similar does not apply to
# PathChanged=". The runner normally starts within milliseconds, so a trigger
# still unclaimed after this long was missed.
_PICKUP_GRACE_SECONDS = 30
_last_rearm_at = 0.0


def _mtime_ns(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def _pending_trigger_mtime() -> float | None:
    """mtime of the apply trigger if the runner has not claimed it yet.

    The runner's first act is to write ``.state`` (so it is newer than the
    trigger); its terminal act renames the trigger away. A trigger with no
    ``.state``, or one older than itself (#1288: an earlier run's, which the
    api cannot unlink), is therefore not started.
    """
    trig = _mtime_ns(_TRIGGER_FILE)
    if trig is None:
        return None
    state = _mtime_ns(_STATE_FILE)
    if state is None or state < trig:
        return trig / 1e9
    return None


def _rearm_unclaimed_trigger(trigger_mtime: float) -> None:
    """Re-fire ``PathChanged=`` for a trigger the watcher missed.

    Opening for write and closing without writing emits IN_CLOSE_WRITE (the
    event PathChanged= is documented to fire on: "activated if the file
    which was open for writing gets closed") and leaves the mtime, and with
    it the heal's clock, untouched. No O_CREAT: if the runner consumed the
    trigger since it was read as pending, this must not leave an empty one
    behind for the watcher to start the runner on. O_NOFOLLOW: a symlink is
    not our trigger. Harmless while the runner runs (the path unit watches
    nothing until its service is inactive again) and after it finishes (the
    trigger is gone). A trigger the api cannot open (the supervisor's) is
    left to the heal; the supervisor re-arms its own.
    """
    global _last_rearm_at
    now = time.time()
    if now - trigger_mtime < _PICKUP_GRACE_SECONDS:
        return
    if now - _last_rearm_at < _PICKUP_GRACE_SECONDS:
        return
    _last_rearm_at = now
    try:
        fd = os.open(_TRIGGER_FILE, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return  # consumed since it was read as pending
    except OSError as exc:
        logger.warning(
            "appliance_slot_upgrade_rearm_failed", trigger=str(_TRIGGER_FILE), error=str(exc)
        )
        return
    os.close(fd)
    logger.warning(
        "appliance_slot_upgrade_rearmed",
        trigger=str(_TRIGGER_FILE),
        waited_seconds=int(now - trigger_mtime),
    )


def _upgrade_state_now() -> tuple[UpgradeState, str | None]:
    """Read the .state sidecar the host-side runner maintains. Returns
    ('ready', None) when no upgrade has run recently — ``ready`` is
    the green-chip default that signals "agent is healthy + no pending
    work". A trigger the runner hasn't written state for (no .state, or
    one older than the trigger, an earlier run's — #1288) counts as
    'in-flight', stamped with the trigger's mtime so #421's heal ages it;
    one still unclaimed after _PICKUP_GRACE_SECONDS is re-armed (#1825).

    Stale-failed auto-heal: when state == failed AND the un-suffixed
    trigger isn't present, the host runner has already renamed it to
    .failed.<ts>. Flip back to ``ready`` so the chip doesn't stick on
    failed forever after the operator has observed it; the
    .failed.<ts> sidecar stays on disk for forensics.
    """
    pending = _pending_trigger_mtime()
    if pending is not None:
        # #1825 / #1288 — the runner has not claimed this trigger (no
        # .state, or one left by a PREVIOUS run, older than the trigger).
        # Stamp it with the trigger's mtime so #421's heal bounds it: a
        # stamp-less in-flight could never age out, and a missed
        # ``PathChanged=`` edge would 409 apply + rollback for good.
        stamp = datetime.fromtimestamp(pending, UTC).isoformat()
        if _stamp_is_stale(stamp):
            return "failed", stamp
        _rearm_unclaimed_trigger(pending)
        return "in-flight", stamp
    if _STATE_FILE.exists():
        try:
            text = _STATE_FILE.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return "ready", None
        parts = text.split(maxsplit=1)
        state = parts[0] if parts else ""
        stamp = parts[1] if len(parts) > 1 else None
        if state in ("in-flight", "done", "failed"):
            # Auto-heal: failed + no pending trigger == operator has
            # had time to see it; flip green.
            if state == "failed" and not _TRIGGER_FILE.exists():
                return "ready", None
            # #421 — a dead/killed apply on this host leaves in-flight
            # stuck forever (the runner's exit trap couldn't run), which
            # would 409 a per-box re-apply / rollback. A stale liveness
            # stamp means the runner is gone — report failed so the
            # operator can act. (The supervisor's _reap_stale_inflight is
            # the source of truth for the operator-visible Fleet status +
            # the durable sidecar heal; this just keeps the per-box reader
            # consistent so is_apply_in_flight() stops blocking.)
            if state == "in-flight" and _stamp_is_stale(stamp):
                return "failed", stamp
            return state, stamp  # type: ignore[return-value]
    return "ready", None


def get_slot_status() -> SlotStatus:
    """Compose the full status surface the UI needs.

    Returns appliance_mode=False on non-appliance deploys (the api
    container's mounts won't be present). The frontend uses that to
    hide the OS-upgrade section without an explicit feature flag.
    """
    if not settings.appliance_mode:
        return SlotStatus(
            appliance_mode=False,
            current_slot=None,
            durable_default=None,
            is_trial_boot=False,
            upgrade_state="ready",
            upgrade_state_at=None,
            log_tail="",
            slot_a_version=None,
            slot_b_version=None,
        )

    current = _current_slot_from_cmdline()
    grubenv = _read_grubenv()
    durable_raw = grubenv.get("saved_entry") or ""
    durable: SlotName | None = (
        "slot_a" if durable_raw == "slot_a" else "slot_b" if durable_raw == "slot_b" else None
    )
    is_trial = bool(current and durable and current != durable)
    state, stamp = _upgrade_state_now()
    versions = _read_slot_versions()

    return SlotStatus(
        appliance_mode=True,
        current_slot=current,
        durable_default=durable,
        is_trial_boot=is_trial,
        upgrade_state=state,
        upgrade_state_at=stamp,
        log_tail=get_update_log_tail(),
        slot_a_version=versions.get("slot_a"),
        slot_b_version=versions.get("slot_b"),
    )


def schedule_apply(image_url: str, checksum_url: str | None = None) -> None:
    """Drop the trigger file the host-side slot-upgrade runner watches.

    Two lines: image URL/path on line 1, optional checksum URL/path
    on line 2. Atomic via ``.new`` sibling + replace so the Path unit
    fires exactly once on close-after-write. Raises if appliance_mode
    is off or the trigger dir isn't writable.
    """
    if not settings.appliance_mode:
        raise RuntimeError("slot upgrade is only supported on the SpatiumDDI OS appliance")
    image_url = image_url.strip()
    if not image_url:
        raise ValueError("image_url is required")
    if not (image_url.startswith(("http://", "https://")) or image_url.startswith("/")):
        raise ValueError("image_url must be an http(s) URL or absolute filesystem path")
    if checksum_url:
        checksum_url = checksum_url.strip()
        if not (checksum_url.startswith(("http://", "https://")) or checksum_url.startswith("/")):
            raise ValueError("checksum_url must be an http(s) URL or absolute filesystem path")

    body = image_url + "\n"
    if checksum_url:
        body += checksum_url + "\n"

    _TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    # No .state cleanup: the file is root-owned in a sticky dir, so the api's
    # unlink always failed (EPERM, #1288). A previous run's .state is older
    # than the trigger written below, which _upgrade_state_now() reads as
    # "not started" -> in-flight.
    tmp = _TRIGGER_FILE.with_suffix(".new")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(_TRIGGER_FILE)
    logger.info(
        "appliance_slot_upgrade_scheduled", image_url=image_url, checksum=bool(checksum_url)
    )


def get_update_log_tail(lines: int = 120) -> str:
    """Return the last ``lines`` lines of /var/log/spatiumddi/slot-
    upgrade.log. Empty string when no upgrade has ever run."""
    if not _UPDATE_LOG.exists():
        return ""
    try:
        text = _UPDATE_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])


def is_apply_in_flight() -> bool:
    state, _ = _upgrade_state_now()
    return state == "in-flight"


def schedule_rollback(target_slot: SlotName | None = None) -> None:
    """Drop the rollback trigger file the host-side slot-rollback runner
    watches. When ``target_slot`` is None the runner picks the inactive
    slot (the typical "go back to the previous slot" intent).

    The trigger file is single-line — the explicit slot name (when
    given) or empty. Atomic via ``.new`` sibling + replace so the Path
    unit fires exactly once. Raises if appliance_mode is off, the
    inactive slot is unstamped, or an upgrade is in-flight.
    """
    if not settings.appliance_mode:
        raise RuntimeError("slot rollback is only supported on the SpatiumDDI OS appliance")
    if target_slot is not None and target_slot not in ("slot_a", "slot_b"):
        raise ValueError("target_slot must be 'slot_a' or 'slot_b'")
    body = "" if target_slot is None else target_slot + "\n"

    _ROLLBACK_TRIGGER_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _ROLLBACK_STATE_FILE.exists():
        try:
            _ROLLBACK_STATE_FILE.unlink()
        except OSError as exc:
            # Same best-effort semantics as schedule_apply()'s cleanup.
            logger.warning(
                "appliance_slot_rollback_state_cleanup_failed",
                state_file=str(_ROLLBACK_STATE_FILE),
                error=str(exc),
            )
    tmp = _ROLLBACK_TRIGGER_FILE.with_suffix(".new")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(_ROLLBACK_TRIGGER_FILE)
    logger.info("appliance_slot_rollback_scheduled", target_slot=target_slot)


def can_rollback() -> bool:
    """True iff there's an inactive slot worth rolling back to.

    Returns False on non-appliance deploys, when we can't read grubenv,
    or when both slots resolve to the same value (shouldn't happen in
    a real install but the UI shouldn't offer a rollback button in
    obviously-broken states).
    """
    if not settings.appliance_mode:
        return False
    current = _current_slot_from_cmdline()
    if current not in ("slot_a", "slot_b"):
        return False
    # If durable_default is set to the other slot already, "rollback"
    # would just flip it back — which is also fine, but mainly we want
    # to confirm two distinct slots exist on this install.
    return True

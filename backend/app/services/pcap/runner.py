"""Async packet-capture (tcpdump) runner — issue #59.

Owns the tcpdump subprocess lifecycle for the **server vantage** (the
control-plane worker container). Mirrors :mod:`app.services.nmap.runner`:
it does not own the Celery wrapper (:mod:`app.tasks.pcap`) nor the HTTP
surface (:mod:`app.api.v1.pcap`).

Security model (the headline control is the BPF filter):

* The argv is built as a Python list and spawned with
  ``create_subprocess_exec`` — **never** a shell, **never**
  ``shlex.split`` on operator input. The BPF expression is appended as a
  single trailing argv element; tcpdump parses it internally as BPF with
  zero shell involvement. A charset allowlist is a secondary sanity bound
  (the single-argv-element passing is the primary defense). The exact
  same ``validate_bpf_filter`` / ``validate_interface`` run again on the
  Phase-2 host runner (defence-in-depth — never trust the control plane
  as the sole validator).
* tcpdump runs non-root with ``cap_net_raw`` granted via ``setcap`` on
  the binary in the image. Non-promiscuous by default so ``cap_net_raw``
  alone suffices (no ``cap_net_admin``).
* Hard caps (duration / packets / bytes) are clamped here AND re-enforced
  at the runner, so a tampered row can't run unbounded.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import signal
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.db import task_connect_args
from app.models.pcap import PacketCapture

logger = structlog.get_logger(__name__)


# ── Hard limits + defaults ──────────────────────────────────────────────
# Hard maxima are constants (never operator-raisable beyond these); the
# per-deployment defaults live in PlatformSettings and the API clamps a
# request to min(requested, hard-max).
HARD_MAX_DURATION_S = 1800  # 30 min
HARD_MAX_PACKETS = 1_000_000
HARD_MAX_BYTES = 100 * 1024 * 1024  # 100 MiB

DEFAULT_DURATION_S = 60
DEFAULT_PACKETS = 10_000
DEFAULT_BYTES = 50 * 1024 * 1024  # 50 MiB
DEFAULT_SNAPLEN = 256  # headers-only; full payload is an explicit opt-in
MAX_SNAPLEN = 65535

# Canonical BPF charset — shared byte-identically with the Phase-2 host
# runner. Admits real BPF (byte-offset + bitmask idioms like
# ``tcp[tcpflags] & tcp-syn != 0``, ``ip[6:2] & 0x1fff != 0``,
# ``vlan 100 and host 10.0.0.1``) while excluding shell metacharacters
# (`; $ \` newline { } ' "`). The parens/brackets it admits are safe
# because the filter is a single non-shell argv element.
_BPF_RE = re.compile(r"^[A-Za-z0-9_ .:\[\]()/&|!=<>+*x-]{0,1024}$")

# Interface name: Linux IFNAMSIZ is 16, but VLAN/bridge names + the
# special "any" go a little longer; bound generously, charset-tight.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")

# pcap progress / cancel poll cadence.
_POLL_INTERVAL_S = 1.0
# Grace between SIGTERM (lets tcpdump flush the savefile) and SIGKILL.
_TERM_GRACE_S = 3.0


class PcapArgError(ValueError):
    """Raised when capture parameters fail validation."""


def pcap_dir() -> Path:
    """The on-disk home for ``.pcap`` artifacts (mode 0700, auto-created)."""
    d = Path(os.environ.get("SPATIUM_PCAP_DIR", "/var/lib/spatiumddi/pcaps"))
    d.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        d.chmod(0o700)
    return d


# ── Validation ──────────────────────────────────────────────────────────


def enumerate_interfaces() -> list[str]:
    """List capturable interfaces visible to THIS process (server vantage).

    Read from ``/proc/net/dev`` — the names the worker container can
    actually bind tcpdump to. NOTE for the UI: in a container this is the
    pod/bridge network, NOT the host's physical NICs. ``any`` is always
    offered as the first option (tcpdump's all-interfaces pseudo-device).
    """
    names: list[str] = ["any"]
    try:
        content = Path("/proc/net/dev").read_text()
    except OSError:
        return names
    for line in content.splitlines()[2:]:  # skip the two header rows
        head, _, _ = line.partition(":")
        name = head.strip()
        if name and name != "lo":
            names.append(name)
    return names


def validate_interface(
    iface: str | None,
    *,
    available: list[str] | None = None,
    require_available: bool = True,
) -> str:
    """Validate the requested interface against the vantage's real NICs.

    Charset-tight + membership-checked (422 on an unknown name) so the
    operator can't smuggle an argv token through the interface field and
    can't capture on a non-existent device. Defaults to ``any`` when
    unset, but the API encourages a specific NIC.

    ``require_available=False`` skips the membership check (charset only) —
    used for the appliance-host vantage, where the control plane can't
    enumerate the host's NICs; the host runner does the real membership
    check in the host net namespace and fails the capture cleanly on an
    unknown interface.
    """
    if iface is None or not iface.strip():
        return "any"
    iface = iface.strip()
    if not _IFACE_RE.match(iface):
        raise PcapArgError(f"interface name has invalid characters: {iface!r}")
    if not require_available:
        return iface
    avail = available if available is not None else enumerate_interfaces()
    if iface not in avail:
        raise PcapArgError(
            f"interface {iface!r} is not one of the available interfaces on this vantage"
        )
    return iface


def validate_bpf_filter(bpf: str | None) -> str | None:
    """Validate a BPF expression. Returns the trimmed filter or None.

    This is an *argv-injection* sanity bound, not a target-authorization
    control — it deliberately admits ``host 10.0.0.1`` / ``port 53``. The
    real safety is that the result is passed as tcpdump's single trailing
    argv element, never through a shell.
    """
    if bpf is None:
        return None
    bpf = bpf.strip()
    if not bpf:
        return None
    if not _BPF_RE.match(bpf):
        raise PcapArgError(
            "BPF filter contains characters that aren't valid in a capture "
            "expression (shell metacharacters are rejected)"
        )
    return bpf


def clamp_caps(
    *,
    max_packets: int | None,
    max_duration_s: int | None,
    max_bytes: int | None,
    snaplen: int | None,
) -> tuple[int | None, int | None, int | None, int]:
    """Clamp stop-conditions to the hard maxima; require at least one.

    Returns ``(max_packets, max_duration_s, max_bytes, snaplen)``. An
    unbounded capture (no packet / duration / byte ceiling) is rejected —
    it's a resource leak.
    """
    if max_packets is None and max_duration_s is None and max_bytes is None:
        raise PcapArgError(
            "at least one stop condition is required " "(max_packets, max_duration_s, or max_bytes)"
        )
    mp = None if max_packets is None else max(1, min(int(max_packets), HARD_MAX_PACKETS))
    md = None if max_duration_s is None else max(1, min(int(max_duration_s), HARD_MAX_DURATION_S))
    mb = None if max_bytes is None else max(1, min(int(max_bytes), HARD_MAX_BYTES))
    sl = DEFAULT_SNAPLEN if snaplen is None else max(0, min(int(snaplen), MAX_SNAPLEN))
    return mp, md, mb, sl


def build_pcap_argv(
    *,
    interface: str,
    bpf_filter: str | None,
    snaplen: int,
    promiscuous: bool,
    max_packets: int | None,
    output_path: str,
) -> list[str]:
    """Assemble the tcpdump argv for a write-to-file capture.

    ``-U`` (packet-buffered) so the savefile grows promptly for the
    fstat-based progress poll. ``-p`` disables promiscuous mode (tcpdump's
    default is promiscuous; we opt OUT unless requested). The validated
    BPF filter, if any, is the single trailing element.
    """
    argv = [
        "tcpdump",
        "-n",  # no name resolution (no side DNS, faster)
        "-U",  # packet-buffered writes → live byte progress
        "-i",
        interface,
        "-s",
        str(snaplen),
        "-w",
        output_path,
    ]
    if not promiscuous:
        argv.append("-p")
    if max_packets is not None:
        argv.extend(["-c", str(max_packets)])
    if bpf_filter:
        # SINGLE trailing argv element — tcpdump parses it as BPF. Never
        # shlex.split, never shell.
        argv.append(bpf_filter)
    return argv


# ── Runner ───────────────────────────────────────────────────────────────


def _new_engine_factory() -> tuple[Any, async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(
        settings.database_url, future=True, connect_args=task_connect_args()
    )
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_PKT_RE = re.compile(r"(\d+)\s+packets?\s+captured", re.IGNORECASE)


def _parse_packet_count(stderr_text: str) -> int | None:
    """tcpdump prints ``N packets captured`` to stderr at exit."""
    m = _PKT_RE.search(stderr_text or "")
    return int(m.group(1)) if m else None


async def run_pcap(capture_id: uuid.UUID) -> None:
    """Drive one server-vantage capture to completion.

    Marks the row ``running``, spawns tcpdump writing to a ``.pcap`` under
    ``pcap_dir()``, polls the growing file for ``bytes_captured`` + the
    operator-cancel flag every ~1 s, enforces the duration + byte ceilings
    with a wall-clock kill, then on exit stamps size + sha256 + packet
    count + terminal status. Owns its own engine/session (Celery body via
    ``asyncio.run``).
    """
    engine, factory = _new_engine_factory()
    out_path = pcap_dir() / f"{capture_id}.pcap"
    try:
        async with factory() as db:
            cap = await db.get(PacketCapture, capture_id)
            if cap is None:
                logger.warning("pcap_run_missing", capture_id=str(capture_id))
                return
            if cap.status == "cancelled":
                return

            try:
                interface = validate_interface(cap.interface)
                bpf = validate_bpf_filter(cap.bpf_filter)
                mp, md, mb, sl = clamp_caps(
                    max_packets=cap.max_packets,
                    max_duration_s=cap.max_duration_s,
                    max_bytes=cap.max_bytes,
                    snaplen=cap.snaplen,
                )
                argv = build_pcap_argv(
                    interface=interface,
                    bpf_filter=bpf,
                    snaplen=sl,
                    promiscuous=cap.promiscuous,
                    max_packets=mp,
                    output_path=str(out_path),
                )
            except PcapArgError as exc:
                cap.status = "failed"
                cap.error_message = str(exc)
                cap.finished_at = datetime.now(UTC)
                await db.commit()
                logger.warning("pcap_argv_invalid", capture_id=str(capture_id), error=str(exc))
                return

            cap.status = "running"
            cap.started_at = datetime.now(UTC)
            cap.command_line = " ".join(argv)
            await db.commit()
            logger.info("pcap_starting", capture_id=str(capture_id), argv=argv)

            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                cap.status = "failed"
                cap.error_message = "tcpdump binary not found. Install tcpdump in the worker image."
                cap.finished_at = datetime.now(UTC)
                await db.commit()
                logger.error("pcap_binary_missing", capture_id=str(capture_id))
                return
            except Exception as exc:  # noqa: BLE001 — surface to operator
                cap.status = "failed"
                cap.error_message = f"failed to spawn tcpdump: {exc}"
                cap.finished_at = datetime.now(UTC)
                await db.commit()
                logger.exception("pcap_spawn_failed", capture_id=str(capture_id))
                return

            cap.tcpdump_pid = proc.pid
            await db.commit()

            started = time.monotonic()
            cancelled = False
            hit_byte_cap = False
            timed_out = False

            try:
                while True:
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=_POLL_INTERVAL_S)
                        break  # tcpdump exited on its own (count cap / error)
                    except TimeoutError:
                        # Expected: the poll tick elapsed and tcpdump is
                        # still running — fall through to the progress /
                        # cancel / cap checks below, then loop.
                        pass

                    # Progress: honest byte count from the growing file.
                    size = out_path.stat().st_size if out_path.exists() else 0
                    elapsed = time.monotonic() - started

                    refreshed = await db.get(PacketCapture, capture_id)
                    if refreshed is None:
                        with contextlib.suppress(ProcessLookupError):
                            proc.terminate()
                        return
                    refreshed.bytes_captured = size
                    refreshed.duration_seconds = elapsed
                    await db.commit()

                    if refreshed.status == "cancelled":
                        cancelled = True
                        break
                    if mb is not None and size >= mb:
                        hit_byte_cap = True
                        break
                    if md is not None and elapsed >= md:
                        timed_out = True
                        break
            finally:
                if proc.returncode is None:
                    # SIGTERM lets tcpdump flush + close the savefile; then
                    # SIGKILL as a backstop.
                    with contextlib.suppress(ProcessLookupError):
                        proc.send_signal(signal.SIGTERM)
                    with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
                        await asyncio.wait_for(proc.wait(), timeout=_TERM_GRACE_S)
                    if proc.returncode is None:
                        with contextlib.suppress(ProcessLookupError):
                            proc.kill()
                        await proc.wait()

            stderr_text = ""
            if proc.stderr is not None:
                with contextlib.suppress(Exception):
                    stderr_text = (await proc.stderr.read()).decode("utf-8", errors="replace")

            cap_row = await db.get(PacketCapture, capture_id)
            if cap_row is None:
                return
            cap_row.tcpdump_pid = None
            cap_row.exit_code = proc.returncode
            cap_row.finished_at = datetime.now(UTC)
            cap_row.duration_seconds = time.monotonic() - started

            file_size = out_path.stat().st_size if out_path.exists() else 0
            cap_row.bytes_captured = file_size
            packet_count = _parse_packet_count(stderr_text)
            if packet_count is not None:
                cap_row.packets_captured = packet_count

            truncated = bool(hit_byte_cap or timed_out or (mp is not None and packet_count == mp))

            if file_size > 0:
                cap_row.pcap_path = str(out_path)
                cap_row.artifact_node = (settings.node_name or "").strip() or None
                cap_row.pcap_size_bytes = file_size
                with contextlib.suppress(OSError):
                    cap_row.pcap_sha256 = _sha256_file(out_path)
            cap_row.metadata_json = {
                "packet_count": packet_count,
                "byte_count": file_size,
                "truncated": truncated,
                "stop_reason": (
                    "cancelled"
                    if cancelled
                    else (
                        "max_bytes"
                        if hit_byte_cap
                        else (
                            "max_duration"
                            if timed_out
                            else (
                                "max_packets"
                                if (mp is not None and packet_count == mp)
                                else "completed"
                            )
                        )
                    )
                ),
            }

            if cancelled:
                cap_row.status = "cancelled"
            elif proc.returncode in (0, None) or hit_byte_cap or timed_out:
                # A SIGTERM kill returns non-zero but the savefile is valid;
                # treat a clean stop-condition exit as completed.
                cap_row.status = "completed"
            else:
                cap_row.status = "failed"
                cap_row.error_message = (
                    stderr_text.strip()[-500:] or f"tcpdump exited with code {proc.returncode}"
                )

            await db.commit()
            logger.info(
                "pcap_finished",
                capture_id=str(capture_id),
                status=cap_row.status,
                bytes=file_size,
                packets=packet_count,
            )
    finally:
        await engine.dispose()


__all__ = [
    "DEFAULT_BYTES",
    "DEFAULT_DURATION_S",
    "DEFAULT_PACKETS",
    "DEFAULT_SNAPLEN",
    "HARD_MAX_BYTES",
    "HARD_MAX_DURATION_S",
    "HARD_MAX_PACKETS",
    "MAX_SNAPLEN",
    "PcapArgError",
    "build_pcap_argv",
    "clamp_caps",
    "enumerate_interfaces",
    "pcap_dir",
    "run_pcap",
    "validate_bpf_filter",
    "validate_interface",
]

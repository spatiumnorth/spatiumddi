"""Supervisor-side packet-capture proxy thread (#59 Phase 2).

The appliance-host vantage runs tcpdump on the appliance **host** (real
NICs). The supervisor pod can't (it isn't ``hostNetwork`` — it would only
see the pod veth), so it drives a **host runner** over the existing
trigger-file → systemd ``.path`` pattern (same as snmp / chrony / firewall
reload) and relays progress + the finished ``.pcap`` back to the control
plane.

Flow (one claimed capture, processed serially — one at a time, so no
concurrent-capture lock is needed):

  1. Long-poll ``POST /supervisor/pcap/poll`` (cert-authed). The control
     plane atomically claims the oldest queued appliance-vantage row and
     returns a structured command (never a shell string).
  2. Re-validate the BPF filter + interface name (charset; defence in
     depth — the host runner re-checks the interface against the real
     ``/sys/class/net`` and is the authoritative membership gate).
  3. Atomically write the request trigger
     ``release-state/pcap/<cid>.request.json``. The host ``.path`` unit
     fires ``spatium-pcap-runner``, which writes ``<cid>.pcap`` (grows) +
     ``<cid>.state.json`` ({state, packets, bytes, error}).
  4. Poll the state + pcap size every ~3 s → ``POST /supervisor/pcap/
     progress/<cid>`` (the response carries the operator cancel flag; on
     cancel we ``touch <cid>.cancel`` for the runner to stop).
  5. On ``done`` → stream ``<cid>.pcap`` to ``POST /supervisor/pcap/
     upload/<cid>?packets=N``. On ``failed`` → ``?error=…`` (empty body).
  6. Clean up every ``<cid>.*`` file.

A hard self-timeout (``max_duration_s`` + grace) requests cancel and then
fails the row if the runner never finalizes — backstopped server-side by
the stuck-capture reaper. Daemon thread; self-resilient (no cert /
registration / 404 → sleep + retry), dormant when no capture is queued.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from . import cp_tls
from .cert_auth import build_auth_headers, load_cert
from .config import SupervisorConfig
from .heartbeat import _effective_control_plane_url
from .identity import Identity, load_appliance_id

log = structlog.get_logger(__name__)

_BASE = "/api/v1/appliance/supervisor"
_POLL_PATH = f"{_BASE}/pcap/poll"
_POLL_TIMEOUT_S = 35.0
_BACKOFF_S = 10.0
_REVOKED_BACKOFF_S = 60.0
_PROGRESS_INTERVAL_S = 3.0
_GRACE_S = 20.0

# Trigger dir inside the supervisor pod (bind-mounted host release-state).
# The host .path unit watches the host-side path of this same dir.
_TRIGGER_DIR = Path("/var/lib/spatiumddi-host/release-state/pcap")

# Charset bounds — byte-identical to the backend's
# app/services/pcap/runner.py validators (defence in depth; the host
# runner validates again and is the authoritative interface gate).
import re  # noqa: E402

_BPF_RE = re.compile(r"^[A-Za-z0-9_ .:\[\]()/&|!=<>+*x-]{0,1024}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
# #555 — capture_id becomes filesystem paths under _TRIGGER_DIR
# (``{cid}.request`` / ``.pcap`` / ``.state`` / ``.cancel`` + a cleanup
# glob), so it MUST be charset-validated like interface/bpf are — a value
# with ``/`` or ``..`` would escape _TRIGGER_DIR. Normally a server-side
# UUID, but a compromised/buggy control plane is exactly the threat model
# the other validators already assume.
_CAPTURE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class PcapValidationError(ValueError):
    pass


def _validate(cmd: dict[str, Any]) -> dict[str, Any]:
    capture_id = str(cmd.get("capture_id") or "")
    if not _CAPTURE_ID_RE.match(capture_id):
        raise PcapValidationError(f"invalid capture_id {capture_id!r}")
    iface = (cmd.get("interface") or "any").strip() or "any"
    if not _IFACE_RE.match(iface):
        raise PcapValidationError(f"invalid interface {iface!r}")
    bpf = cmd.get("bpf_filter")
    if bpf is not None:
        bpf = str(bpf).strip()
        if bpf and not _BPF_RE.match(bpf):
            raise PcapValidationError("invalid BPF filter")
        bpf = bpf or None
    return {
        "capture_id": capture_id,
        "interface": iface,
        "bpf_filter": bpf,
        "snaplen": int(cmd.get("snaplen") or 256),
        "promiscuous": bool(cmd.get("promiscuous")),
        "max_packets": cmd.get("max_packets"),
        "max_duration_s": cmd.get("max_duration_s"),
        "max_bytes": cmd.get("max_bytes"),
    }


def _atomic_write_request(path: Path, cmd: dict[str, Any]) -> None:
    """Write the request as a line-based ``key=value`` file (NOT JSON) so
    the bash host runner stays dependency-free. ``bpf`` is the LAST line
    (it may contain spaces; it's validated to have no newlines) so the
    runner can read it as the rest-of-line."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def _v(k: str) -> str:
        v = cmd.get(k)
        return "" if v is None else str(v)

    lines = [
        f"capture_id={cmd['capture_id']}",
        f"interface={cmd['interface']}",
        f"snaplen={cmd['snaplen']}",
        f"promiscuous={'1' if cmd['promiscuous'] else '0'}",
        f"max_packets={_v('max_packets')}",
        f"max_duration_s={_v('max_duration_s')}",
        f"max_bytes={_v('max_bytes')}",
        f"bpf={cmd.get('bpf_filter') or ''}",
    ]
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)


def _read_state(path: Path) -> dict[str, str]:
    """Parse the runner's line-based ``key=value`` state file."""
    out: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            if k:
                out[k.strip()] = v.strip()
    except (OSError, ValueError):
        # Unreadable / half-written state file — treat as "no state yet";
        # the next ~3 s poll re-reads it. Never fatal to the capture.
        pass
    return out


def _cleanup(cid: str) -> None:
    if not _TRIGGER_DIR.exists():
        return
    for f in _TRIGGER_DIR.glob(f"{cid}.*"):
        try:
            f.unlink()
        except OSError:
            # Best-effort cleanup — a file already gone (or briefly locked
            # by the host runner) is harmless; the next capture overwrites.
            pass


def pcap_loop_forever(cfg: SupervisorConfig, identity: Identity) -> None:
    """Run the pcap long-poll loop until the process exits (daemon thread)."""
    # #1219 — a fresh client per poll, verified against the control
    # plane's pinned certificate, so a re-pin by the heartbeat loop is
    # picked up here too. The pin is only ever taken by registration.
    while True:
        try:
            with cp_tls.client(
                cfg.state_dir,
                _effective_control_plane_url(cfg),
                first_contact=False,
                timeout=_POLL_TIMEOUT_S + 5.0,
            ) as client:
                _pcap_once(cfg, identity, client)
        except Exception as exc:  # noqa: BLE001 — never let the thread die
            log.warning("supervisor.pcap.loop_crashed", error=str(exc))
            time.sleep(_BACKOFF_S)


def _pcap_once(cfg: SupervisorConfig, identity: Identity, client: httpx.Client) -> None:
    appliance_id = load_appliance_id(cfg.state_dir)
    cert_pem = load_cert(cfg.state_dir)
    base_url = _effective_control_plane_url(cfg)
    if appliance_id is None or cert_pem is None or not base_url:
        time.sleep(_BACKOFF_S)
        return

    headers = build_auth_headers(
        "POST", _POLL_PATH, cert_pem, identity.private_key, appliance_id
    )
    try:
        resp = client.post(base_url.rstrip("/") + _POLL_PATH, headers=headers)
    except httpx.HTTPError as exc:
        log.warning("supervisor.pcap.poll_failed", error=str(exc))
        time.sleep(_BACKOFF_S)
        return
    if resp.status_code in (403, 404):
        time.sleep(_REVOKED_BACKOFF_S)
        return
    if resp.status_code != 200:
        log.warning("supervisor.pcap.poll_unexpected", status_code=resp.status_code)
        time.sleep(_BACKOFF_S)
        return

    try:
        cmd = resp.json()
    except ValueError:
        time.sleep(_BACKOFF_S)
        return
    if not cmd.get("capture_id"):
        return  # empty long-poll — no queued capture

    _run_capture(cfg, identity, client, appliance_id, cmd)


def _run_capture(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
    appliance_id: str,
    raw_cmd: dict[str, Any],
) -> None:
    cid = str(raw_cmd.get("capture_id") or "")
    try:
        cmd = _validate(raw_cmd)
    except PcapValidationError as exc:
        log.warning("supervisor.pcap.validation_failed", capture_id=cid, error=str(exc))
        _finalize_error(
            cfg, identity, client, appliance_id, cid, f"validation failed: {exc}"
        )
        return

    log.info("supervisor.pcap.starting", capture_id=cid, interface=cmd["interface"])
    _atomic_write_request(_TRIGGER_DIR / f"{cid}.request", cmd)

    pcap_file = _TRIGGER_DIR / f"{cid}.pcap"
    state_file = _TRIGGER_DIR / f"{cid}.state"
    max_dur = int(cmd["max_duration_s"] or 1800)
    deadline = time.monotonic() + max_dur + _GRACE_S
    started = time.monotonic()
    cancel_sent = False

    while True:
        time.sleep(_PROGRESS_INTERVAL_S)
        state = _read_state(state_file) if state_file.exists() else {}
        size = (
            pcap_file.stat().st_size
            if pcap_file.exists()
            else int(state.get("bytes") or 0)
        )
        st = state.get("state") or "starting"

        cancel = _post_progress(
            cfg,
            identity,
            client,
            appliance_id,
            cid,
            packets=state.get("packets"),
            bytes_captured=size,
            elapsed_s=time.monotonic() - started,
        )
        if cancel and not cancel_sent:
            (_TRIGGER_DIR / f"{cid}.cancel").touch()
            cancel_sent = True

        if st == "failed":
            _finalize_error(
                cfg,
                identity,
                client,
                appliance_id,
                cid,
                str(state.get("error") or "host capture failed"),
            )
            _cleanup(cid)
            return
        if st == "done":
            break
        if time.monotonic() > deadline:
            if not cancel_sent:
                (_TRIGGER_DIR / f"{cid}.cancel").touch()
                cancel_sent = True
            # Give the runner a couple of ticks to finalize, then give up.
            if time.monotonic() > deadline + _GRACE_S:
                _finalize_error(
                    cfg,
                    identity,
                    client,
                    appliance_id,
                    cid,
                    "host runner did not finalize before the deadline",
                )
                _cleanup(cid)
                return

    # done → upload the pcap.
    packets = state.get("packets")
    _upload_pcap(cfg, identity, client, appliance_id, cid, pcap_file, packets)
    _cleanup(cid)


def _post_progress(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
    appliance_id: str,
    cid: str,
    *,
    packets: Any,
    bytes_captured: int,
    elapsed_s: float,
) -> bool:
    path = f"{_BASE}/pcap/progress/{cid}"
    base_url = _effective_control_plane_url(cfg)
    cert_pem = load_cert(cfg.state_dir)
    if not base_url or cert_pem is None:
        return False
    headers = build_auth_headers(
        "POST", path, cert_pem, identity.private_key, appliance_id
    )
    try:
        resp = client.post(
            base_url.rstrip("/") + path,
            headers=headers,
            json={
                "packets": int(packets) if packets not in (None, "") else None,
                "bytes_captured": int(bytes_captured),
                "elapsed_s": float(elapsed_s),
            },
        )
        if resp.status_code == 200:
            return bool(resp.json().get("cancel"))
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("supervisor.pcap.progress_failed", capture_id=cid, error=str(exc))
    return False


def _upload_pcap(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
    appliance_id: str,
    cid: str,
    pcap_file: Path,
    packets: Any,
) -> None:
    if not pcap_file.exists() or pcap_file.stat().st_size == 0:
        _finalize_error(
            cfg, identity, client, appliance_id, cid, "capture produced no bytes"
        )
        return
    path = f"{_BASE}/pcap/upload/{cid}"
    base_url = _effective_control_plane_url(cfg)
    cert_pem = load_cert(cfg.state_dir)
    if not base_url or cert_pem is None:
        return
    # Cert signature is over the bare path (query excluded server-side).
    headers = build_auth_headers(
        "POST", path, cert_pem, identity.private_key, appliance_id
    )
    headers["Content-Type"] = "application/octet-stream"
    q = f"?packets={int(packets)}" if packets not in (None, "") else ""

    def _gen() -> Any:
        with open(pcap_file, "rb") as fh:
            while True:
                chunk = fh.read(4 * 1024 * 1024)
                if not chunk:
                    break
                yield chunk

    try:
        resp = client.post(
            base_url.rstrip("/") + path + q,
            headers=headers,
            content=_gen(),
            timeout=120.0,
        )
        log.info(
            "supervisor.pcap.uploaded", capture_id=cid, status_code=resp.status_code
        )
    except httpx.HTTPError as exc:
        log.warning("supervisor.pcap.upload_failed", capture_id=cid, error=str(exc))


def _finalize_error(
    cfg: SupervisorConfig,
    identity: Identity,
    client: httpx.Client,
    appliance_id: str,
    cid: str,
    message: str,
) -> None:
    path = f"{_BASE}/pcap/upload/{cid}"
    base_url = _effective_control_plane_url(cfg)
    cert_pem = load_cert(cfg.state_dir)
    if not base_url or cert_pem is None:
        return
    headers = build_auth_headers(
        "POST", path, cert_pem, identity.private_key, appliance_id
    )
    try:
        client.post(
            base_url.rstrip("/") + path + f"?error={quote(message[:300])}",
            headers=headers,
        )
    except httpx.HTTPError as exc:
        log.warning(
            "supervisor.pcap.finalize_error_failed", capture_id=cid, error=str(exc)
        )


def start_pcap_thread(cfg: SupervisorConfig, identity: Identity) -> threading.Thread:
    """Spawn the pcap proxy loop as a daemon thread."""
    t = threading.Thread(
        target=pcap_loop_forever, args=(cfg, identity), name="pcap-proxy", daemon=True
    )
    t.start()
    return t


__all__ = ["pcap_loop_forever", "start_pcap_thread"]

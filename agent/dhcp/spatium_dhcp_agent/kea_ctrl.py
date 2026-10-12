"""Tiny client for the Kea control unix socket.

Kea speaks line-delimited JSON on the control socket; each request is a single
JSON object with ``command`` + optional ``arguments``, the response is a single
JSON object.
"""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


class KeaCtrlError(RuntimeError):
    pass


def send_command(
    socket_path: Path,
    command: str,
    arguments: dict[str, Any] | None = None,
    *,
    timeout: float = 10.0,
    accept_results: tuple[int, ...] = (0,),
) -> dict[str, Any]:
    """Send a single command over the Kea control unix socket and return the
    decoded JSON response.

    ``accept_results`` lists the Kea result codes returned rather than raised.
    Most commands only succeed on 0, but some answer a legitimate empty result
    with 3 ("empty") — ``lease4-get-page`` past the last lease, for one.
    """
    payload: dict[str, Any] = {"command": command}
    if arguments is not None:
        payload["arguments"] = arguments
    data = json.dumps(payload).encode("utf-8")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(socket_path))
        s.sendall(data)
        # Kea closes after the single response; read until EOF.
        chunks: list[bytes] = []
        while True:
            buf = s.recv(65536)
            if not buf:
                break
            chunks.append(buf)
    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        raise KeaCtrlError(f"empty response for command {command!r}")
    try:
        resp = json.loads(raw)
    except json.JSONDecodeError as e:
        raise KeaCtrlError(f"non-JSON response from kea: {raw[:200]}") from e
    result = resp.get("result")
    if result is not None and result not in accept_results:
        raise KeaCtrlError(
            f"kea command {command!r} failed: result={result} text={resp.get('text')!r}"
        )
    return resp


def config_reload(socket_path: Path) -> None:
    """Ask kea-dhcp4 to reload its config file."""
    log.info("kea_config_reload_send", socket=str(socket_path))
    send_command(socket_path, "config-reload")
    log.info("kea_config_reload_ok")


class KeaConfigRejected(KeaCtrlError):
    """``kea-dhcp4 -t`` / ``kea-dhcp6 -t`` refused the config (exit 1)."""


class KeaCheckUnavailable(RuntimeError):
    """The ``-t`` preflight could not give a verdict at all.

    Binary missing, not executable, timed out, killed by a signal, or an
    exit code other than Kea's documented 0 / 1. Deliberately NOT a
    :class:`KeaCtrlError`: it says nothing about the config, and it must
    never be read as "config OK" either.
    """


# Binaries that check a config file in a separate process. Same PATH lookup
# the entrypoint uses to start the daemons.
CHECK_BINARIES = {"dhcp4": "kea-dhcp4", "dhcp6": "kea-dhcp6"}
CONFIG_CHECK_TIMEOUT = 30.0
# Kea prints the verdict on the last stderr line, prefixed with one of these
# (kea-dhcp4/6 main.cc). Everything else on stderr/stdout is log noise.
_CHECK_REASON_PREFIXES = ("Error encountered:", "Syntax check failed with:")
_MAX_REASON = 500


def _check_reason(stderr: str, stdout: str) -> str:
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    for line in reversed(lines):
        if line.startswith(_CHECK_REASON_PREFIXES):
            return line[:_MAX_REASON]
    if lines:
        return lines[-1][:_MAX_REASON]
    out = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
    return out[-1][:_MAX_REASON] if out else "no output"


def config_check(
    daemon: str, config_path: Path, *, timeout: float = CONFIG_CHECK_TIMEOUT
) -> None:
    """Validate the config file Kea is about to reload, in a separate process.

    Runs ``kea-dhcp4 -t <file>`` (``kea-dhcp6`` for ``daemon="dhcp6"``) —
    the same check-only parse the ``config-test`` command does (#477), but
    without sending anything to the running daemon. Kea 3.0.3's
    ``config-test`` leaves the running server's multi-threading manager in
    test mode, after which the HA hook's dedicated HTTP listener never binds
    again (#1447, fixed upstream in Kea 3.0.4). A ``-t`` process exits and
    takes that state with it.

    ``config_path`` is the file ``config-reload`` reads, so the check and
    the reload see the same bytes.

    Raises :class:`KeaConfigRejected` with Kea's reason on exit 1 (Kea's
    documented "error encountered"), and :class:`KeaCheckUnavailable` when
    no verdict could be had. Returns on exit 0.
    """
    binary = CHECK_BINARIES[daemon]
    log.info("kea_config_check_start", daemon=daemon, path=str(config_path))
    try:
        proc = subprocess.run(
            [binary, "-t", str(config_path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        log.warning("kea_config_check_timeout", daemon=daemon, timeout=timeout)
        raise KeaCheckUnavailable(f"{binary} -t timed out after {timeout:g}s") from e
    except OSError as e:
        log.warning("kea_config_check_not_run", daemon=daemon, error=str(e))
        raise KeaCheckUnavailable(f"{binary} -t could not run: {e}") from e

    if proc.returncode == 0:
        log.info("kea_config_check_ok", daemon=daemon)
        return
    reason = _check_reason(proc.stderr, proc.stdout)
    if proc.returncode == 1:
        log.warning("kea_config_check_rejected", daemon=daemon, reason=reason)
        raise KeaConfigRejected(f"{binary} -t rejected the config: {reason}")
    log.warning(
        "kea_config_check_failed", daemon=daemon, returncode=proc.returncode, reason=reason
    )
    raise KeaCheckUnavailable(f"{binary} -t exited with code {proc.returncode}: {reason}")


def version_get(socket_path: Path) -> str | None:
    """Return the running kea-dhcp4 daemon's version (e.g. ``"3.0.3"``).

    Issue #637. The control plane needs to know which Kea MAJOR each member of
    an HA pair is running, because Kea 3.0's HA hook is wire-incompatible with
    peers older than 2.7.0 (3.0 introduced the "released" lease state, value 3,
    in the lease updates exchanged between partners, and older peers reject
    them). There is therefore no rolling 2.6 → 3.0 HA upgrade: both members must
    cross in the same window. The rolling-upgrade preflight uses this to tell the
    operator *before* they start, instead of after HA has fallen over.

    Reported as ``kea_version`` on the heartbeat. Returns None if the daemon
    isn't up yet or doesn't answer — the caller must treat that as "unknown",
    not as "old".
    """
    try:
        resp = send_command(socket_path, "version-get")
    except (KeaCtrlError, OSError) as e:
        # Socket not ready (cold start) or command refused. Not fatal — the
        # heartbeat simply reports no version this tick and retries next one.
        log.debug("kea_version_get_failed", socket=str(socket_path), error=str(e))
        return None
    text = resp.get("text")
    if not isinstance(text, str) or not text.strip():
        return None
    # ``version-get`` answers with the bare version in ``text`` (e.g. "3.0.3"),
    # sometimes with a trailing build/extended blob after a newline.
    return text.strip().splitlines()[0].strip() or None

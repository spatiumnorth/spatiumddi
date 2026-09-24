"""Tiny client for the Kea control unix socket.

Kea speaks line-delimited JSON on the control socket; each request is a single
JSON object with ``command`` + optional ``arguments``, the response is a single
JSON object.
"""

from __future__ import annotations

import json
import socket
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


def config_test(socket_path: Path, config_doc: dict[str, Any]) -> None:
    """Validate a rendered config WITHOUT applying it (#477).

    Kea's ``config-test`` parses + sanity-checks the config passed in
    ``arguments`` and returns result=0 when valid, or a non-zero result with
    ``text`` describing the exact problem (e.g. a pool outside the subnet).
    ``send_command`` raises :class:`KeaCtrlError` carrying that ``text`` on
    rejection, so a caller can surface Kea's real reason instead of an opaque
    "reload failed" and never reload a config the daemon will reject.

    A daemon too old to know ``config-test`` answers result=2 ("command not
    supported"); we treat that as a soft pass so the preflight degrades to a
    plain reload rather than blocking the apply.
    """
    log.info("kea_config_test_send", socket=str(socket_path))
    try:
        send_command(socket_path, "config-test", arguments=config_doc)
    except KeaCtrlError as e:
        if "result=2" in str(e):  # command unsupported → skip the preflight
            log.info("kea_config_test_unsupported", socket=str(socket_path))
            return
        raise
    log.info("kea_config_test_ok")


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

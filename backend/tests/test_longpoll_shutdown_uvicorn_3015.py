"""#3015 under a REAL uvicorn: SIGTERM ends a parked long-poll with its normal
answer well before ``--timeout-graceful-shutdown`` cancels it.

The in-process tests in ``test_longpoll_shutdown_3015.py`` set the flag by
hand. Nothing there proves the hook is installed by uvicorn's lifespan at
all, or that uvicorn still calls a wrapped handler — which depends on
uvicorn's ``capture_signals`` using ``signal.signal`` and running the
lifespan startup inside it. This starts uvicorn in a subprocess with the
Dockerfile's flag shape (``--workers 1 --timeout-graceful-shutdown N``, with a
shorter cut so the negative control finishes quickly), parks a long-poll,
sends SIGTERM and reads the result off the wire and the server's log.

The negative control neuters ``install_signal_hook`` and asserts the original
failure comes back (the poll is cancelled at the cut), so the harness is shown
to be able to see the bug it guards against.
"""

from __future__ import annotations

import http.client
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

BACKEND = Path(__file__).resolve().parents[1]
CUT_S = 6  # --timeout-graceful-shutdown; production is 20, the hold is 30
PROMPT_S = 2.0  # "well before the cut"
BAD_OUTPUT = ("CancelledError", "Exception in ASGI application", "running task")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _get(port: int, path: str, timeout: float) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


def _redis_reachable() -> bool:
    from urllib.parse import urlparse

    from app.config import settings

    u = urlparse(settings.redis_url)
    if u.scheme not in ("redis", "rediss"):
        return False
    try:
        with socket.create_connection((u.hostname or "localhost", u.port or 6379), timeout=1):
            return True
    except OSError:
        return False


def _run(route: str, *, neuter: bool, cut_s: int = CUT_S) -> dict[str, Any]:
    port = _free_port()
    env = {**os.environ, "PYTHONPATH": str(BACKEND), "PYTHONUNBUFFERED": "1"}
    if neuter:
        env["SPATIUM_TEST_NEUTER_SHUTDOWN_HOOK"] = "1"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "tests._uvicorn_shutdown_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--workers",
            "1",
            "--timeout-graceful-shutdown",
            str(cut_s),
        ],
        cwd=BACKEND,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out: dict[str, Any] = {}
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if _get(port, "/ready", 1)[0] == 200:
                    break
            except OSError:
                pass
            if proc.poll() is not None or time.monotonic() > deadline:
                raise AssertionError(
                    "uvicorn did not start:\n" + proc.communicate(timeout=5)[0].decode()
                )
            time.sleep(0.1)

        def _poll() -> None:
            try:
                status, headers, body = _get(port, route, 60)
                out.update(status=status, headers=headers, body=body)
            except Exception as exc:  # noqa: BLE001 — recorded, asserted on
                out["error"] = repr(exc)
            out["answered_at"] = time.monotonic()

        t = threading.Thread(target=_poll, daemon=True)
        t.start()
        parked_by = time.monotonic() + 10
        while _get(port, "/ready", 1)[2] == b'{"parked":0}':
            assert time.monotonic() < parked_by, "the long-poll never parked"
            time.sleep(0.05)
        time.sleep(0.3)  # into the wait proper

        out["signalled_at"] = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        t.join(cut_s + 15)
        output, _ = proc.communicate(timeout=cut_s + 15)
        out["exited_at"] = time.monotonic()
        out["returncode"] = proc.returncode
        out["log"] = output.decode(errors="replace")
        return out
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _routes() -> list[Any]:
    return [
        pytest.param("/poll/pubsub", 304, id="config-pubsub"),
        pytest.param("/poll/degraded", 304, id="config-degraded"),
        pytest.param("/poll/queue", 200, id="supervisor-queue"),
    ]


@pytest.mark.parametrize(("route", "normal_status"), _routes())
def test_sigterm_answers_the_parked_poll_before_the_cut(route: str, normal_status: int) -> None:
    if route == "/poll/pubsub" and not _redis_reachable():
        pytest.skip("no Redis to subscribe to; the degraded variant covers the fallback")
    r = _run(route, neuter=False)
    log = r["log"]
    assert "error" not in r, f"{r['error']}\n{log}"
    assert r["status"] == normal_status, log
    if route == "/poll/pubsub":
        assert r["headers"]["x-degraded"] == "0", "expected a live pub/sub subscription"
    if route == "/poll/queue":
        assert r["body"] == b'{"request_id":""}'
    took = r["answered_at"] - r["signalled_at"]
    assert took < PROMPT_S, f"answered {took:.2f}s after SIGTERM (cut {CUT_S}s)\n{log}"
    # uvicorn re-raises the captured SIGTERM after a graceful stop.
    assert r["returncode"] in (0, -signal.SIGTERM), log
    assert r["exited_at"] - r["signalled_at"] < CUT_S, log
    assert "Finished server process" in log, log
    for bad in BAD_OUTPUT:
        assert bad not in log, f"{bad!r} in the server log:\n{log}"


def test_negative_control_without_the_hook_the_cut_cancels_the_poll() -> None:
    """The bug #3015 reported, reproduced by this harness: with the hook
    neutered the poll is held to the cut and cancelled there."""
    cut = 3
    r = _run("/poll/degraded", neuter=True, cut_s=cut)
    log = r["log"]
    took = r["answered_at"] - r["signalled_at"]
    assert took >= cut - 0.5, f"answered after {took:.2f}s — the hook was not neutered?\n{log}"
    assert r.get("status") != 304, log
    assert "Cancel 1 running task" in log, log

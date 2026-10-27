"""Celery worker liveness probe that rides out a broker failover (#2815).

Run by the kubelet as ``python -m app.worker_liveness`` in place of
``celery inspect ping``. The ping is a round trip through the broker, so a
Redis master that is gone for two minutes (a split Sentinel vote: ~128 s with
no master, #2815) failed it five times in a row and the kubelet restarted a
worker that was perfectly healthy — the one driving a rolling upgrade, which
died with it. A probe that kills the process coordinating the recovery turns
a two-minute broker blip into a ten-minute one.

So a failed ping is classified first. When this probe cannot reach the broker
either, the failure is the broker's, not the worker's, and it is reported as
alive for up to ``--grace`` seconds (default 300) counted from the first
failed probe since the last successful ping. After that every failure counts
again, and the kubelet's ``failureThreshold`` (5 x 30 s) applies on top, so a
worker is restarted at most grace + 150 s (7.5 min) after its last good ping,
whatever the broker is doing. A worker that does not answer while the broker
is reachable is failed immediately, exactly as before: the grace never covers
a wedged worker on a healthy broker.

The first-failure time lives in a file in the container's own writable layer,
so a restarted container starts with no grace consumed and none carried over.
It is deliberately cleared only by a successful ping: clearing it whenever the
broker answers would let a flapping broker restart the grace forever.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from pathlib import Path

DEFAULT_GRACE_S = 300.0
DEFAULT_STATE_PATH = "/tmp/spatium-worker-liveness"  # noqa: S108 — container-private
_PING_TIMEOUT_S = 5.0


def decide(
    *,
    now: float,
    first_failure: float | None,
    ping_ok: bool,
    broker_reachable: bool,
    grace_s: float,
) -> tuple[bool, float | None]:
    """(alive, first_failure to store) for one probe.

    ``first_failure`` is when the current run of failed probes began, or None
    after a success."""
    if ping_ok:
        return True, None
    started = now if first_failure is None else first_failure
    if not broker_reachable and now - started < grace_s:
        return True, started
    return False, started


def _read_state(path: Path) -> float | None:
    try:
        return float(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _write_state(path: Path, first_failure: float | None) -> None:
    try:
        if first_failure is None:
            path.unlink(missing_ok=True)
            return
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(f"{first_failure}\n")
        tmp.replace(path)
    except OSError as exc:
        # Without the state the grace restarts on every probe; say so, but a
        # probe must still answer.
        print(f"worker-liveness: cannot record state at {path}: {exc}", file=sys.stderr)


def _probe(node_name: str) -> tuple[bool, bool]:
    """(ping_ok, broker_reachable) for this worker."""
    from app.celery_app import celery_app  # noqa: PLC0415 — the probe's one heavy import

    try:
        with celery_app.connection_for_write() as conn:
            # One attempt, no retry loop: the question is whether the broker
            # answers now. A Sentinel with no master raises MasterNotFoundError.
            conn.ensure_connection(max_retries=1, interval_start=0, interval_step=0, timeout=5)
    except Exception as exc:  # noqa: BLE001 — any failure to connect is "unreachable"
        print(f"worker-liveness: broker unreachable: {exc}", file=sys.stderr)
        return False, False
    try:
        replies = celery_app.control.ping(destination=[node_name], timeout=_PING_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 — the broker went away mid-probe
        print(f"worker-liveness: ping failed: {exc}", file=sys.stderr)
        return False, False
    for reply in replies or []:
        if node_name in reply:
            return True, True
    print(f"worker-liveness: {node_name} did not answer the ping", file=sys.stderr)
    return False, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--grace", type=float, default=DEFAULT_GRACE_S)
    parser.add_argument("--state", default=DEFAULT_STATE_PATH)
    parser.add_argument(
        "--node",
        default=f"celery@{os.environ.get('HOSTNAME') or socket.gethostname()}",
    )
    args = parser.parse_args(argv)
    state = Path(args.state)

    ping_ok, broker_reachable = _probe(args.node)
    now = time.time()
    alive, first_failure = decide(
        now=now,
        first_failure=_read_state(state),
        ping_ok=ping_ok,
        broker_reachable=broker_reachable,
        grace_s=args.grace,
    )
    _write_state(state, first_failure)
    if alive and not ping_ok and first_failure is not None:
        print(
            f"worker-liveness: broker down {now - first_failure:.0f}s of "
            f"{args.grace:.0f}s grace; not counting it against the worker",
            file=sys.stderr,
        )
    return 0 if alive else 1


if __name__ == "__main__":
    sys.exit(main())

"""A started Celery worker can run every task this codebase defines.

A worker runs a task only if the task's module was imported when the worker
started. ``celery worker`` imports the Celery app and its ``include`` list,
fires ``worker_init``, and builds the consumer's task table from that
registry. A message naming any other task is logged as "Received unregistered
task" and discarded. A module missing from ``include`` still works in every
process a test can see, because the code that enqueues a task imports its
module to call ``apply_async``, and that registers it in the enqueuing process
only (``bundle_dirty._enqueue_sync`` imports ``app.tasks.agent_bundles``
lazily, in the api).

That is how the DNS agent bundle renders (#1111) left the worker: a merge
resolution dropped ``app.tasks.agent_bundles`` from ``include``, with its
``bundles`` route and the 30 s render-missing sweep, and from then on the
worker discarded every render it was sent. Agents received a change only when
the api's bounded inline fallback built the bundle, two minutes after it.

A registered task can still be stranded. A task whose module has no
``task_routes`` entry, sent without an explicit queue, goes to Celery's
default queue, ``celery``, and no worker consumes that. Five modules were in
that state, including the rolling-upgrade driver and five beat entries (#1200).

The suite imports ``app.main`` (conftest), so these probe the worker's own
startup in a fresh interpreter, as ``tests/test_session_listeners.py`` does.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.tasks.agent_bundles import TASK_RENDER, TASK_SWEEP

_BACKEND = Path(__file__).resolve().parents[1]

# The queues every deploy target starts the worker with (``-Q``):
# charts/spatiumddi/values.yaml ``worker.queues``, k8s/base/worker.yaml and
# docker-compose.yml. A task routed anywhere else is published and never run.
_WORKER_QUEUES = frozenset({"ipam", "dns", "dhcp", "default", "bundles"})

# The worker's startup, exactly as ``celery worker`` does it before its pool
# forks; then every module under ``app/tasks`` is imported, so the tasks that
# appear only then are the ones a started worker cannot run.
_PROBE = """
import importlib, json, pkgutil, sys
from celery.signals import worker_init
from app.celery_app import celery_app

celery_app.loader.import_default_modules()
worker_init.send(sender=None)
assert 'app.main' not in sys.modules, 'probe must not load the api'
started = sorted(n for n in celery_app.tasks if not n.startswith('celery.'))
queues = {n: celery_app.amqp.router.route({}, n)['queue'].name for n in started}
beat = {}
for key, entry in (celery_app.conf.beat_schedule or {}).items():
    every = getattr(entry['schedule'], 'run_every', None)
    beat[key] = {
        'task': entry['task'],
        'every': every.total_seconds() if every is not None else None,
    }
import app.tasks
for mod in pkgutil.iter_modules(app.tasks.__path__):
    importlib.import_module('app.tasks.' + mod.name)
defined = sorted(n for n in celery_app.tasks if not n.startswith('celery.'))
print(json.dumps({'started': started, 'defined': defined, 'queues': queues, 'beat': beat}))
"""


@lru_cache(maxsize=1)
def _worker() -> dict[str, Any]:
    proc = subprocess.run(  # noqa: S603 — fixed argv, our own interpreter
        [sys.executable, "-c", _PROBE],
        cwd=_BACKEND,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    # A probe that could not run is not the negative outcome; say which.
    assert proc.returncode == 0, f"worker probe failed to run:\n{proc.stderr[-2000:]}"
    result: dict[str, Any] = json.loads(proc.stdout.strip().splitlines()[-1])
    return result


def test_a_started_worker_registers_every_task_the_code_defines() -> None:
    worker = _worker()
    assert worker["started"], "the probe found no tasks at all — it is not probing"
    missing = sorted(set(worker["defined"]) - set(worker["started"]))
    assert missing == [], (
        f"{missing} are defined under app/tasks but a started worker does not register "
        "them, so it discards every message for them as an unregistered task: add "
        "their module to the include list in app/celery_app.py"
    )


def test_every_beat_entry_names_a_task_a_started_worker_registers() -> None:
    worker = _worker()
    orphans = sorted(
        f"{key} -> {entry['task']}"
        for key, entry in worker["beat"].items()
        if entry["task"] not in worker["started"]
    )
    assert orphans == [], f"beat sends {orphans}, which a started worker discards"


def test_every_task_a_started_worker_registers_routes_to_a_queue_it_consumes() -> None:
    """#1200: a task with no route goes to Celery's default queue, ``celery``,
    which no worker consumes, so it is published and never run: no error, no
    log line, just a Redis list that grows."""
    worker = _worker()
    stranded = sorted(
        f"{name} -> {queue}"
        for name, queue in worker["queues"].items()
        if queue not in _WORKER_QUEUES
    )
    assert stranded == [], (
        f"{stranded} are published to a queue no worker consumes (the worker runs "
        f"-Q {','.join(sorted(_WORKER_QUEUES))}): add a task_routes entry for their "
        "module in app/celery_app.py"
    )


def test_the_bundle_renders_run_on_the_bundles_queue_and_are_swept() -> None:
    """#1111: renders go to their own ``bundles`` queue (the one the chart lets
    an operator give a worker of its own), and a render-missing sweep runs at
    least every 30 s, the backstop the dirty mark's best-effort enqueue relies
    on for a lost broker message."""
    worker = _worker()
    for name in (TASK_RENDER, TASK_SWEEP):
        assert name in worker["started"], f"a started worker does not register {name}"
        assert (
            worker["queues"][name] == "bundles"
        ), f"{name} is routed to {worker['queues'][name]!r}, not 'bundles'"
    sweeps = [entry["every"] for entry in worker["beat"].values() if entry["task"] == TASK_SWEEP]
    assert sweeps, f"beat never schedules {TASK_SWEEP}"
    assert all(
        every is not None and every <= 30 for every in sweeps
    ), f"{TASK_SWEEP} is scheduled every {sweeps} s; the dirty mark relies on it within 30 s"

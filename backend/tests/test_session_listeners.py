"""Session listeners reach every process that writes rows (#1168).

A module that registers SQLAlchemy session listeners on import only works in
a process that imports it. ``event_publisher`` was imported only by
``app.main``, so the Celery worker never had it and every typed webhook event
for an audit row a task wrote — scheduled backups, rolling upgrades — was
dropped. The suite imports ``app.main`` (conftest), so no ordinary test can
see a worker without a listener; these two can.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from app.services.session_listeners import SESSION_LISTENER_MODULES

_BACKEND = Path(__file__).resolve().parents[1]

# Imported by every process that opens a session (its listener is the
# soft-delete read filter), and the registry module itself.
_EXEMPT = {"app.db", "app.services.session_listeners"}


def _modules_registering_session_listeners() -> set[str]:
    found: set[str] = set()
    for path in (_BACKEND / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "sync_session_class" not in text:
            continue
        if "listens_for(" not in text and "event.listen(" not in text:
            continue
        rel = path.relative_to(_BACKEND).with_suffix("")
        found.add(".".join(rel.parts))
    return found - _EXEMPT


def test_every_module_that_registers_session_listeners_is_installed() -> None:
    """A new listener module has to join the list, or the worker never runs it."""
    found = _modules_registering_session_listeners()
    assert found, "the scan found no listener modules at all — it is not scanning"
    missing = sorted(found - set(SESSION_LISTENER_MODULES))
    assert missing == [], (
        f"{missing} register SQLAlchemy session listeners on import but are not in "
        "app.services.session_listeners.SESSION_LISTENER_MODULES, so the Celery "
        "worker and beat never install them"
    )
    stale = sorted(set(SESSION_LISTENER_MODULES) - found)
    assert stale == [], f"{stale} are listed but no longer register a session listener"


def _probe(code: str) -> str:
    """Run ``code`` in a fresh interpreter and return its last stdout line."""
    proc = subprocess.run(  # noqa: S603 — fixed argv, our own interpreter
        [sys.executable, "-c", code],
        cwd=_BACKEND,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    # A probe that could not run is not the negative outcome; say which.
    assert proc.returncode == 0, f"import probe failed to run:\n{proc.stderr[-2000:]}"
    return proc.stdout.strip().splitlines()[-1]


def test_the_worker_process_installs_every_listener() -> None:
    """Probe the worker's own startup in a fresh interpreter: the Celery app,
    every module in its ``include`` list, then ``worker_init``, exactly as
    ``celery worker`` does before its pool forks."""
    last = _probe(
        "import sys\n"
        "from celery.signals import worker_init\n"
        "from app.celery_app import celery_app\n"
        "celery_app.loader.import_default_modules()\n"
        "worker_init.send(sender=None)\n"
        "assert 'app.main' not in sys.modules, 'probe must not load the api'\n"
        f"wanted = {list(SESSION_LISTENER_MODULES)!r}\n"
        "print('MISSING ' + ' '.join(m for m in wanted if m not in sys.modules))\n"
    )
    assert last == "MISSING", f"the Celery worker does not install: {last[len('MISSING '):]}"


def test_importing_the_celery_app_does_not_install_the_listeners() -> None:
    """#1189: the worker's liveness probe runs ``celery -A app.celery_app inspect
    ping``, which imports the Celery app on every run. The listeners pull in
    the models, the DNS drivers, httpx and jinja2, so they are installed from
    ``worker_init`` / ``beat_init`` and a bare import must not load them."""
    last = _probe(
        "import sys\n"
        "import app.celery_app\n"
        f"wanted = {list(SESSION_LISTENER_MODULES)!r}\n"
        "print('LOADED ' + ' '.join(m for m in wanted if m in sys.modules))\n"
    )
    assert last == "LOADED", f"importing app.celery_app loads: {last[len('LOADED '):]}"

"""Every module that installs SQLAlchemy session listeners on import (#1168).

A module that registers ``event.listens_for(AsyncSession.sync_session_class,
…)`` at import time only takes effect in a process that imports it. These
were imported for their side effect from ``app.main`` — which only the api
imports. The Celery worker and beat import ``app.celery_app`` and their task
modules, never ``app.main``, so a listener reached the worker only if some
task happened to import its module:

* ``audit_forward`` did, by accident of a task import.
* ``event_publisher`` did not — so every typed webhook event for an audit row
  a task writes was dropped: ``system.backup_completed`` /
  ``system.backup_failed`` for SCHEDULED backups, and every
  ``system.upgrade.*`` from the rolling-upgrade orchestrator.

Now both processes install this one list (``app.main`` and ``app.celery_app``
call :func:`install_session_listeners`), and two tests keep it honest:
``tests/test_session_listeners.py`` fails when a module registering session
listeners is missing from the list, and probes the worker's own import graph
in a fresh interpreter — the suite itself imports ``app.main`` (conftest), so
it always has every listener and cannot see a worker without one.

``app.db`` also registers one (the soft-delete read filter) and is not
listed: every process that opens a session imports it.
"""

from __future__ import annotations

import importlib

SESSION_LISTENER_MODULES: tuple[str, ...] = (
    "app.services.audit_forward",
    "app.services.event_publisher",
)


def install_session_listeners() -> None:
    """Import every listener module (idempotent — a module imports once)."""
    for name in SESSION_LISTENER_MODULES:
        importlib.import_module(name)


__all__ = ["SESSION_LISTENER_MODULES", "install_session_listeners"]

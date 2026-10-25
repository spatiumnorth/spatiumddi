"""#2782 — the after-commit dispatch drain runs in prefork children too."""

from __future__ import annotations

from unittest import mock

from app import celery_app


def test_child_hook_drains_and_disposes() -> None:
    fake = mock.Mock()
    with mock.patch("app.celery_app.importlib.import_module", return_value=fake) as im:
        celery_app._close_after_commit_dispatch_in_child()
    im.assert_called_once_with("app.services.after_commit_dispatch")
    fake.shutdown_background.assert_called_once_with()


def test_main_hook_drains_too() -> None:
    fake = mock.Mock()
    with mock.patch("app.celery_app.importlib.import_module", return_value=fake):
        celery_app._close_after_commit_dispatch()
    fake.shutdown_background.assert_called_once_with()


def test_hooks_swallow_exceptions() -> None:
    fake = mock.Mock()
    fake.shutdown_background.side_effect = RuntimeError("boom")
    with mock.patch("app.celery_app.importlib.import_module", return_value=fake):
        celery_app._close_after_commit_dispatch_in_child()
        celery_app._close_after_commit_dispatch()


def test_child_hook_is_connected() -> None:
    from celery.signals import worker_process_shutdown

    names = {getattr(r, "__name__", "") for _, r in worker_process_shutdown.receivers}
    assert "_close_after_commit_dispatch_in_child" in names

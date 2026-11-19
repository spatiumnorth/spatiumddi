"""The release check also runs once when beat starts.

It queues the same task the daily schedule fires (same connection, same
enabled gate inside the task); it opens no connection of its own.
"""

from __future__ import annotations

from unittest.mock import patch

from app import celery_app as ca


def test_beat_start_queues_the_existing_release_check_task() -> None:
    with patch.object(ca.celery_app, "send_task") as send:
        ca._queue_release_check_at_start()
    send.assert_called_once_with("app.tasks.update_check.check_github_release")


def test_beat_start_survives_an_unreachable_broker() -> None:
    with patch.object(ca.celery_app, "send_task", side_effect=OSError("no broker")):
        ca._queue_release_check_at_start()


def test_handler_is_connected_to_beat_init() -> None:
    from celery.signals import beat_init

    assert any(
        getattr(r(), "__name__", "") == "_queue_release_check_at_start"
        for _, r in beat_init.receivers
    )


def test_scheduled_task_name_matches_the_beat_entry() -> None:
    assert (
        ca.celery_app.conf.beat_schedule["check-github-release"]["task"]
        == "app.tasks.update_check.check_github_release"
        if "check-github-release" in ca.celery_app.conf.beat_schedule
        else any(
            e["task"] == "app.tasks.update_check.check_github_release"
            for e in ca.celery_app.conf.beat_schedule.values()
        )
    )

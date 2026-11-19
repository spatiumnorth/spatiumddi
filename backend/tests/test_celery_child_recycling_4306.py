"""#4306 — the worker recycles prefork children, with env-tunable limits."""

import os
import subprocess
import sys

import pytest

import app.celery_app as celery_module
from app.config import Settings


def test_defaults_recycle_children(monkeypatch):
    monkeypatch.delenv("WORKER_MAX_TASKS_PER_CHILD", raising=False)
    monkeypatch.delenv("WORKER_MAX_MEMORY_PER_CHILD_KIB", raising=False)
    s = Settings(_env_file=None)
    assert s.worker_max_tasks_per_child == 1000
    assert s.worker_max_memory_per_child_kib == 409600  # 400 MiB, in KiB


def test_celery_conf_carries_the_settings():
    conf = celery_module.celery_app.conf
    assert conf.worker_max_tasks_per_child == celery_module.settings.worker_max_tasks_per_child
    assert conf.worker_max_memory_per_child == (
        celery_module.settings.worker_max_memory_per_child_kib
    )
    assert conf.worker_max_tasks_per_child
    assert conf.worker_max_memory_per_child


@pytest.mark.parametrize("value, expected", [("7", "7 7"), ("0", "None None")])
def test_env_overrides_reach_celery_conf(value, expected):
    # Celery's conf is built at import, so ask a fresh interpreter.
    code = (
        "from app.celery_app import celery_app as c;"
        "print(c.conf.worker_max_tasks_per_child, c.conf.worker_max_memory_per_child)"
    )
    env = {
        **os.environ,
        "WORKER_MAX_TASKS_PER_CHILD": value,
        "WORKER_MAX_MEMORY_PER_CHILD_KIB": value,
    }
    out = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True
    )
    assert out.stdout.strip().splitlines()[-1] == expected

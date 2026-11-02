"""A failed forced apply is retried on the next heartbeat (#3285).

The forced path (#2808) applies while the stamp already matches the env. When
that apply failed (``kubeapi /readyz not ok``) the matching stamp was left in
place, so every later tick logged ``lifecycle_skipped env_unchanged`` and the
persisted ``failed`` state was reported forever.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import heartbeat, service_lifecycle

ROLE_ENV = "COMPOSE_PROFILES=dns-bind9\nAGENT_GROUP=default\nDNS_ENGINE=bind9\n"
PROFILES = ["dns-bind9"]


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    env_path = tmp_path / "role-compose.env"
    env_path.write_text(ROLE_ENV, encoding="utf-8")
    results: list[service_lifecycle.LifecycleResult] = []
    calls: list[int] = []

    def fake_apply(profiles, env):
        calls.append(1)
        return results.pop(0)

    monkeypatch.setattr(heartbeat, "apply_role_assignment", fake_apply)
    monkeypatch.setattr(heartbeat, "reconcile_node_labels", lambda *a, **k: (True, None))
    _, key = heartbeat._role_apply_due(tmp_path, ROLE_ENV, env_path)
    heartbeat._write_last_apply_hash(tmp_path, key)
    return env_path, results, calls


def _tick(tmp_path: Path, env_path: Path, force: bool = False) -> None:
    heartbeat._run_role_lifecycle(tmp_path, PROFILES, ROLE_ENV, env_path, force=force)


def test_failed_forced_apply_is_retried_then_settles(tmp_path: Path, rig) -> None:
    env_path, results, calls = rig
    failed = service_lifecycle.LifecycleResult(state="failed", reason="kubeapi /readyz not ok")
    ready = service_lifecycle.LifecycleResult(state="ready", started=tuple(PROFILES))
    results.extend([failed, ready])

    _tick(tmp_path, env_path, force=True)
    assert len(calls) == 1

    # Next ordinary tick: the stamp no longer vouches for a failed apply.
    _tick(tmp_path, env_path)
    assert len(calls) == 2

    # The retry settled: stamped, so the following tick skips.
    _tick(tmp_path, env_path)
    assert len(calls) == 2


def test_deferred_forced_apply_keeps_its_stamp(tmp_path: Path, rig) -> None:
    env_path, results, calls = rig
    results.append(service_lifecycle.LifecycleResult(state="idle", deferred=True))
    _tick(tmp_path, env_path, force=True)
    _tick(tmp_path, env_path)
    assert len(calls) == 1

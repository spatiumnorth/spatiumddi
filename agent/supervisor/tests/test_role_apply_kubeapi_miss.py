"""A role apply whose kubeapi misses its ``/readyz`` probe is tried again (#1716).

A role change is applied once, on the supervisor's next due heartbeat. When the
kubeapi missed its 2 s ``/readyz`` probe on that tick, the apply reported
``idle`` and the heartbeat stamped the change as applied, so no later tick tried
it again, even once the kubeapi was back, and the Fleet row read ``idle`` with
no reason until the roles changed again. The apply now reports ``failed`` with
the reason: the heartbeat does not stamp a ``failed`` apply (#1640), so the next
tick applies again, and the row carries the reason. A slot with no chart baked,
which has no k3s path at all, still reports ``idle``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from spatium_supervisor import heartbeat, k8s_api, service_lifecycle

from .test_role_apply_key import ROLE_ENV, slot  # noqa: F401 — the fixture
from .test_role_chart_keeps_other_nodes_agents import (
    MEMBER_1,
    NO_ROLES,
    SEED_ROLES,
    Cluster,
    _apply,
    _member,
    _seed,
)

READYZ_MISS = "kubeapi /readyz not ok"


def test_a_readyz_miss_is_a_kubeapi_miss_not_a_missing_runtime(
    monkeypatch: pytest.MonkeyPatch, slot  # noqa: F811
) -> None:
    monkeypatch.setattr(k8s_api, "check_kubeapi_ready", lambda: False)
    env = service_lifecycle.k3s_available()
    assert env.available is False
    assert env.kubeapi_unready is True
    assert env.reason == READYZ_MISS


def test_a_slot_without_the_chart_is_not_a_kubeapi_miss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(service_lifecycle, "_BAKED_CHART_TARBALL", tmp_path / "absent.tgz")
    monkeypatch.setattr(
        k8s_api, "check_kubeapi_ready", lambda: pytest.fail("probed a slot with no chart")
    )
    env = service_lifecycle.k3s_available()
    assert env.available is False
    assert env.kubeapi_unready is False
    result = service_lifecycle.apply_role_assignment([], tmp_path / "role-compose.env")
    assert result.state == "idle"
    assert result.reason == "chart tarball not baked"
    assert heartbeat._apply_settled(result) is True


def test_an_apply_that_meets_a_readyz_miss_fails_with_its_reason_and_is_tried_again(
    monkeypatch: pytest.MonkeyPatch, slot  # noqa: F811
) -> None:
    """REGRESSION (#1716): the heartbeat's own steps, due -> apply -> stamp
    when settled. The miss is not stamped, so the next tick is due again."""
    monkeypatch.setattr(k8s_api, "check_kubeapi_ready", lambda: False)
    due, key = heartbeat._role_apply_due(slot.state_dir, ROLE_ENV, slot.env_path)
    assert due
    result = service_lifecycle.apply_role_assignment(["dhcp", "dns-bind9"], slot.env_path)
    assert result.state == "failed"
    assert result.reason == READYZ_MISS
    assert heartbeat._apply_settled(result) is False
    if heartbeat._apply_settled(result):
        heartbeat._write_last_apply_hash(slot.state_dir, key)
    due_next, _ = heartbeat._role_apply_due(slot.state_dir, ROLE_ENV, slot.env_path)
    assert due_next is True


def test_a_members_role_change_lands_on_the_tick_after_the_miss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Through the role chart: the apply under the miss writes nothing and
    reports why; once the kubeapi answers, the same change is written."""
    cluster = Cluster()
    _seed(monkeypatch, cluster)
    assert _apply(tmp_path, SEED_ROLES).state == "ready"
    _member(monkeypatch, cluster, name=MEMBER_1)
    writes = len(cluster.writes)
    miss = service_lifecycle.K3sEnvironment(
        available=False, reason=READYZ_MISS, kubeapi_unready=True
    )
    monkeypatch.setattr(service_lifecycle, "k3s_available", lambda: miss)
    missed = _apply(tmp_path, NO_ROLES)
    assert (missed.state, missed.reason) == ("failed", READYZ_MISS)
    assert len(cluster.writes) == writes
    monkeypatch.setattr(
        service_lifecycle,
        "k3s_available",
        lambda: service_lifecycle.K3sEnvironment(available=True),
    )
    assert _apply(tmp_path, NO_ROLES).state == "ready"

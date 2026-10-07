"""The upgrade lease is a compare-and-swap, held per drive (#1512).

* Every task in a worker pod shared the pod's hostname as its lease identity,
  so a second drive of the same run "renewed" the first one's lease and ran a
  second cordon / drain loop beside it.
* ``update_lease`` claimed optimistic concurrency and sent an unconditional
  patch: two takeovers of an expired lease both won, ``renew`` wrote its own
  name back over a legitimate takeover, and Abort's release was renewed away.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.upgrades import mutex


def _lease(holder: str, *, rv: str = "41", renewed: str = "2099-01-01T00:00:00Z") -> dict:
    return {
        "metadata": {"resourceVersion": rv},
        "spec": {
            "holderIdentity": holder,
            "renewTime": renewed,
            "leaseDurationSeconds": 600,
            "leaseTransitions": 3,
        },
    }


@pytest.fixture
def k8s_calls(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    calls: dict[str, Any] = {"update": [], "clear": [], "body": None}
    monkeypatch.setattr(mutex.k8s, "get_lease", lambda *_a, **_kw: (200, calls["body"]))
    monkeypatch.setattr(mutex.k8s, "get_config", lambda: object())

    def _update(name: str, holder: str, **kw: Any) -> tuple[bool, str | None]:
        calls["update"].append({"holder": holder, **kw})
        return True, None

    def _clear(name: str, **kw: Any) -> tuple[bool, str | None]:
        calls["clear"].append(kw)
        return True, None

    monkeypatch.setattr(mutex.k8s, "update_lease", _update)
    monkeypatch.setattr(mutex.k8s, "clear_lease_holder", _clear)
    return calls


def test_drive_identities_are_unique_per_drive() -> None:
    a, b = mutex.drive_identity(), mutex.drive_identity()
    assert a != b
    assert a.startswith(mutex._identity() + "_")


def test_renew_refuses_a_lease_someone_else_now_holds(k8s_calls: dict[str, Any]) -> None:
    k8s_calls["body"] = _lease("pod-a_222")
    ok, err = mutex.renew(holder="pod-a_111")
    assert ok is False
    assert "lost" in (err or "")
    assert k8s_calls["update"] == []  # never wrote its own name back


def test_renew_after_abort_does_not_reclaim(k8s_calls: dict[str, Any]) -> None:
    k8s_calls["body"] = _lease("", renewed="2000-01-01T00:00:00Z")
    ok, _ = mutex.renew(holder="pod-a_111")
    assert ok is False
    assert k8s_calls["update"] == []


def test_renew_of_our_own_lease_is_conditional_on_the_version_read(
    k8s_calls: dict[str, Any],
) -> None:
    k8s_calls["body"] = _lease("pod-a_111", rv="77")
    ok, _ = mutex.renew(holder="pod-a_111")
    assert ok is True
    assert k8s_calls["update"][0]["resource_version"] == "77"


def test_a_second_drive_in_the_same_pod_is_refused(k8s_calls: dict[str, Any]) -> None:
    # The first drive holds it; a second task in the same pod has its own id.
    k8s_calls["body"] = _lease("pod-a_111")
    ok, err = mutex.acquire(holder="pod-a_999")
    assert ok is False
    assert "held by pod-a_111" in (err or "")
    assert k8s_calls["update"] == []


def test_takeover_of_an_expired_lease_is_a_compare_and_swap(k8s_calls: dict[str, Any]) -> None:
    k8s_calls["body"] = _lease("pod-b_dead", rv="90", renewed="2000-01-01T00:00:00Z")
    ok, _ = mutex.acquire(holder="pod-a_111")
    assert ok is True
    call = k8s_calls["update"][0]
    assert call["resource_version"] == "90"
    assert call["bump_transitions"] is True


def test_release_never_clears_a_successors_lease(k8s_calls: dict[str, Any]) -> None:
    k8s_calls["body"] = _lease("pod-b_222")
    ok, _ = mutex.release(holder="pod-a_111")
    assert ok is True
    assert k8s_calls["clear"] == []


def test_release_of_our_own_lease_is_conditional(k8s_calls: dict[str, Any]) -> None:
    k8s_calls["body"] = _lease("pod-a_111", rv="12")
    mutex.release(holder="pod-a_111")
    assert k8s_calls["clear"] == [{"namespace": None, "resource_version": "12"}]


def test_abort_release_clears_whoever_holds_it(k8s_calls: dict[str, Any]) -> None:
    k8s_calls["body"] = _lease("pod-b_222")
    mutex.release()
    assert k8s_calls["clear"] == [{"namespace": None}]

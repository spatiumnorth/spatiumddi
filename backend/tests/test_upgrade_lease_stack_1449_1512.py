"""#1449 and #1512 together: the drive hand-off and the crash-path release,
on a lease held per drive and written as a compare-and-swap.

* Every lease write still sends a six-digit MicroTime (#1445) AND, where the
  caller read a version, carries ``metadata.resourceVersion`` (#1512).
* ``release_if_held`` releases only the given drive's identity, as a CAS on
  the version it read, and retries on an unanswered call or a lost CAS.
* A hand-off releases the departing drive's own identity, after which a
  different drive can take the lease over.
* The task's crash handler releases the identity the drive actually used,
  not the pod's hostname.
"""

from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from typing import Any

import pytest

from app.services.appliance import k8s
from app.services.upgrades import mutex

_MICRO_TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


# ── Wire format: MicroTime + resourceVersion on every lease write ────────────


@pytest.fixture
def captured_requests(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    sent: list[dict[str, Any]] = []

    def _request(method: str, path: str, **kwargs: Any) -> tuple[int, bytes]:
        sent.append({"method": method, "path": path, "body": json.loads(kwargs["body"])})
        return (201 if method == "POST" else 200), b"{}"

    monkeypatch.setattr(k8s, "get_config", lambda: k8s._Config("h", 443, "t", "/ca", "spatium"))
    monkeypatch.setattr(k8s, "_request", _request)
    return sent


def test_cas_lease_writes_keep_micro_time_and_carry_the_version(
    captured_requests: list[dict[str, Any]],
) -> None:
    assert k8s.create_lease("upgrade", "pod_a") == (True, None)
    assert k8s.update_lease(
        "upgrade",
        "pod_a",
        bump_transitions=True,
        expected_transitions=1,
        resource_version="41",
    ) == (True, None)
    assert k8s.update_lease("upgrade", "pod_a", resource_version="42") == (True, None)
    assert k8s.clear_lease_holder("upgrade", resource_version="43") == (True, None)

    create, takeover, renew, clear = captured_requests
    # Every timestamp on every write is a MicroTime.
    for req in captured_requests:
        spec = req["body"]["spec"]
        for key in ("acquireTime", "renewTime"):
            if key in spec:
                assert _MICRO_TIME.match(spec[key]), (req["method"], key, spec[key])
    assert "acquireTime" in takeover["body"]["spec"]
    assert "renewTime" in renew["body"]["spec"]
    assert "renewTime" in clear["body"]["spec"]
    # Every write after a read is conditional on the version read.
    assert takeover["body"]["metadata"] == {"resourceVersion": "41"}
    assert renew["body"]["metadata"] == {"resourceVersion": "42"}
    assert clear["body"]["metadata"] == {"resourceVersion": "43"}
    # A create has no version to be conditional on.
    assert "resourceVersion" not in (create["body"].get("metadata") or {})


def test_mutex_paths_send_micro_time_and_version_end_to_end(
    captured_requests: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive ``mutex`` against the real k8s writers: takeover, renew, release
    and release_if_held each reach the wire with both properties."""
    lease: dict[str, Any] = {
        "metadata": {"resourceVersion": "7"},
        "spec": {
            "holderIdentity": "pod-b_dead",
            "renewTime": "2000-01-01T00:00:00.000000Z",
            "leaseDurationSeconds": 600,
            "leaseTransitions": 2,
        },
    }
    monkeypatch.setattr(k8s, "get_lease", lambda *_a, **_k: (200, lease))

    assert mutex.acquire(holder="pod-a_1") == (True, None)  # expired → CAS takeover
    lease["spec"].update(holderIdentity="pod-a_1", renewTime="2099-01-01T00:00:00Z")
    lease["metadata"]["resourceVersion"] = "8"
    assert mutex.renew(holder="pod-a_1") == (True, None)
    lease["metadata"]["resourceVersion"] = "9"
    assert mutex.release_if_held(holder="pod-a_1") is True

    assert [r["body"]["metadata"]["resourceVersion"] for r in captured_requests] == [
        "7",
        "8",
        "9",
    ]
    for req in captured_requests:
        assert _MICRO_TIME.match(req["body"]["spec"]["renewTime"])


# ── release_if_held: only the drive's own identity, as a CAS ─────────────────


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


class _FakeLease:
    """An in-memory Lease honouring resourceVersion preconditions."""

    def __init__(self, holder: str = "", renewed: str = "2000-01-01T00:00:00Z") -> None:
        self.rv = 1
        self.holder = holder
        self.renewed = renewed
        self.transitions = 0
        self.clears: list[str | None] = []

    def body(self) -> dict:
        return {
            "metadata": {"resourceVersion": str(self.rv)},
            "spec": {
                "holderIdentity": self.holder,
                "renewTime": self.renewed,
                "leaseDurationSeconds": 600,
                "leaseTransitions": self.transitions,
            },
        }

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mutex.k8s, "get_config", lambda: object())
        monkeypatch.setattr(mutex.k8s, "get_lease", lambda *_a, **_k: (200, self.body()))
        monkeypatch.setattr(mutex.k8s, "update_lease", self.update)
        monkeypatch.setattr(mutex.k8s, "clear_lease_holder", self.clear)

    def _stale(self, rv: str | None) -> bool:
        return rv is not None and rv != str(self.rv)

    def update(self, _name: str, holder: str, **kw: Any) -> tuple[bool, str | None]:
        if self._stale(kw.get("resource_version")):
            return False, "409 conflict"
        self.holder, self.renewed = holder, "2099-01-01T00:00:00Z"
        if kw.get("bump_transitions"):
            self.transitions += 1
        self.rv += 1
        return True, None

    def clear(self, _name: str, **kw: Any) -> tuple[bool, str | None]:
        self.clears.append(kw.get("resource_version"))
        if self._stale(kw.get("resource_version")):
            return False, "409 conflict"
        self.holder, self.renewed = "", "2000-01-01T00:00:00Z"
        self.rv += 1
        return True, None


def test_release_if_held_never_clears_another_drives_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = _FakeLease(holder="pod-a_other", renewed="2099-01-01T00:00:00Z")
    lease.install(monkeypatch)
    # Same pod, different drive: not ours.
    assert mutex.release_if_held(holder="pod-a_mine", attempts=3, retry_delay_s=0) is False
    assert lease.clears == []
    assert lease.holder == "pod-a_other"


def test_release_if_held_does_not_fall_back_to_the_pod_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A drive's lease is held under ``<pod>_<random>``, never the bare pod
    name, so a caller passing its holder must not match on the pod."""
    monkeypatch.setattr(mutex, "_identity", lambda: "pod-a")
    lease = _FakeLease(holder="pod-a", renewed="2099-01-01T00:00:00Z")
    lease.install(monkeypatch)
    assert mutex.release_if_held(holder="pod-a_mine") is False
    assert lease.clears == []


def test_release_if_held_loses_the_cas_to_a_takeover_between_read_and_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = _FakeLease(holder="pod-a_mine", renewed="2099-01-01T00:00:00Z")
    lease.install(monkeypatch)
    real_clear = lease.clear

    def _clear_after_takeover(name: str, **kw: Any) -> tuple[bool, str | None]:
        # Another drive takes the lease over between our read and our write.
        lease.holder, lease.rv = "pod-b_new", lease.rv + 1
        monkeypatch.setattr(mutex.k8s, "clear_lease_holder", real_clear)
        return real_clear(name, **kw)

    monkeypatch.setattr(mutex.k8s, "clear_lease_holder", _clear_after_takeover)
    assert mutex.release_if_held(holder="pod-a_mine", attempts=3, retry_delay_s=0) is False
    # The write was refused, and the retry re-read and saw it was no longer ours.
    assert lease.holder == "pod-b_new"
    assert lease.clears == ["1"]


def test_release_if_held_retries_an_unanswered_read(monkeypatch: pytest.MonkeyPatch) -> None:
    lease = _FakeLease(holder="pod-a_mine", renewed="2099-01-01T00:00:00Z")
    lease.install(monkeypatch)
    answers = iter([(503, None), (200, None)])

    def _get(*_a: Any, **_k: Any) -> tuple[int, dict | None]:
        try:
            status, _ = next(answers)
        except StopIteration:
            return 200, lease.body()
        return status, None

    monkeypatch.setattr(mutex.k8s, "get_lease", _get)
    assert mutex.release_if_held(holder="pod-a_mine", attempts=3, retry_delay_s=0) is True
    assert lease.holder == ""
    assert lease.clears == ["1"]


# ── Hand-off: the departing drive releases itself; another drive takes over ───


def test_a_handoff_release_lets_a_different_drive_take_the_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease = _FakeLease()
    lease.install(monkeypatch)
    first, second = mutex.drive_identity(), mutex.drive_identity()

    assert mutex.acquire(holder=first) == (True, None)
    assert lease.holder == first
    # While the first drive holds it, the second is refused.
    ok, err = mutex.acquire(holder=second)
    assert ok is False and first in (err or "")

    # The hand-off: the first drive releases ITS identity, as a CAS.
    assert mutex.release_if_held(holder=first) is True
    assert lease.clears == [str(lease.rv - 1)]

    # The drive enqueued elsewhere takes it over.
    assert mutex.acquire(holder=second) == (True, None)
    assert lease.holder == second
    # And the first drive can neither renew nor release its successor's lease.
    ok, _ = mutex.renew(holder=first)
    assert ok is False
    assert mutex.release_if_held(holder=first) is False
    assert mutex.release(holder=first) == (True, None)
    assert lease.holder == second


# ── The task's crash handler releases the drive's own identity ──────────────


@pytest.mark.asyncio
async def test_the_crash_handler_releases_the_identity_the_drive_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uuid
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from app.tasks import upgrade_orchestrator as task

    used: list[str | None] = []
    released: list[str | None] = []

    async def _drive(_db: Any, _rid: Any, *, holder: str | None = None) -> Any:
        used.append(holder)
        raise RuntimeError("loop crashed")

    db = SimpleNamespace(rollback=AsyncMock(), get=AsyncMock(return_value=None), commit=AsyncMock())

    @asynccontextmanager
    async def _session() -> Any:
        yield db

    monkeypatch.setattr(task, "task_session", _session)
    monkeypatch.setattr(task, "drive_upgrade", _drive)
    monkeypatch.setattr(
        mutex, "release_if_held", lambda **kw: released.append(kw.get("holder")) or True
    )

    out = await task._async_drive(str(uuid.uuid4()))

    assert out["state"] == "failed"
    assert used and used[0] and used[0].startswith(mutex._identity() + "_")
    assert released == used

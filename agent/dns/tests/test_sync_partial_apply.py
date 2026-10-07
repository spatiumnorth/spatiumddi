"""A zone the daemon refuses degrades the apply instead of failing it, and
record ops a failed apply skipped go back to the control plane (#1225).

ddi-pg's gate walk of #1280 on PowerDNS 5.0.7: one zone PowerDNS refused
(six seed names with a manual A record and the identical IPAM-generated one)
kept the WHOLE server ``revert_failed``, because the last-known-good carried
the same refused data. And while it was failing, the bundle's record ops were
never acked, so they sat ``in_flight`` with 0 attempts — a delete among them
kept answering after the server recovered.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent import sync as sync_mod
from spatium_dns_agent.cache import (
    commit_config,
    ensure_layout,
    load_previous_config,
    save_config,
)
from spatium_dns_agent.config_apply import STATUS_OK, STATUS_REVERTED, ApplyStatus
from spatium_dns_agent.drivers.base import DriverBase
from spatium_dns_agent.sync import SyncLoop


class _Driver(DriverBase):
    """Applies every bundle; ``refuse`` names zones the daemon refuses, and
    ``fail`` makes the reload raise outright (a transport failure)."""

    def __init__(self, state_dir: Path):
        super().__init__(state_dir)
        self.refuse: list[str] = []
        self.fail = False
        self.applied: list[str] = []
        self.ops: list[str] = []

    def render(self, bundle: dict[str, Any]) -> None:
        self._bundle_etag = str(bundle.get("etag"))

    def validate(self) -> None:
        return None

    def swap_and_reload(self) -> None:
        if self.fail:
            raise RuntimeError("cannot list PowerDNS zones: connection refused")
        self.applied.append(self._bundle_etag)
        self._refused_zones = tuple(self.refuse)

    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        self.ops.append(op["op_id"])
        return None

    def start_daemon(self) -> None:
        return None

    def daemon_running(self) -> bool:
        return True


class _Heartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.failed_ops_count = 0
        self.config_apply = ApplyStatus()


class _Cfg:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.control_plane_url = "http://cp.invalid"
        self.insecure_skip_tls_verify = False
        self.tls_ca_path = None


REFUSAL = "bad.test. update: HTTP 422 Duplicate record in RRset www.bad.test. IN A"


def _bundle(
    tag: str, structural: str | None = None, ops: list[str] | None = None
) -> dict[str, Any]:
    return {
        "etag": tag,
        "structural_etag": structural or f"s-{tag}",
        "zones": [],
        "pending_record_ops": [
            {"op_id": op_id, "op": "delete", "zone_name": "ok.test.", "dispatch": 0}
            for op_id in ops or []
        ],
    }


class _Resp:
    def __init__(self, body: dict[str, Any]):
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self._body = body
        self.text = ""

    def json(self) -> dict[str, Any]:
        return self._body


class _Client:
    def __init__(self, body: dict[str, Any]):
        self._body = body

    def __enter__(self) -> _Client:  # noqa: PYI034 - a test double, never subclassed
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp(self._body)

    def post(self, *args: Any, **kwargs: Any) -> _Resp:
        return _Resp({})


def _loop(tmp_path: Path, driver: _Driver, monkeypatch: pytest.MonkeyPatch) -> SyncLoop:
    ensure_layout(tmp_path)
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **k: None)
    return SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())


def _poll(loop: SyncLoop, monkeypatch: pytest.MonkeyPatch, bundle: dict[str, Any]) -> None:
    monkeypatch.setattr(loop, "_client", lambda: _Client(bundle))
    loop._poll_once()


# ── a refusal degrades, it does not revert ───────────────────────────────────


def test_a_refused_zone_degrades_the_apply_without_a_revert(tmp_path: Path, monkeypatch) -> None:
    driver = _Driver(tmp_path)
    save_config(tmp_path, _bundle("good"), "good")
    commit_config(tmp_path, "good")
    loop = _loop(tmp_path, driver, monkeypatch)
    driver.applied.clear()

    driver.refuse = [REFUSAL]
    save_config(tmp_path, _bundle("new"), "new")
    assert loop._apply_with_revert(_bundle("new"), "new") is True

    # No rollback: the previous bundle was not re-applied, and the new one —
    # which IS what is served — became the last-known-good.
    assert driver.applied == ["new"]
    assert load_previous_config(tmp_path)[1] == "new"
    assert loop._quarantine.etag is None

    status = loop.apply_status
    assert status.status == STATUS_REVERTED, "the closest warning-level #882 status"
    assert status.etag == "new", "the new bundle is live"
    assert status.failed_etag == "new"
    assert "bad.test." in (status.error or "")
    assert "Duplicate record in RRset" in (status.error or ""), "PowerDNS's own reason"
    # The marker the control plane and UI read to say "zones refused", not
    # "rolled back": there is no partial status in #882's vocabulary.
    assert (status.error or "").startswith(sync_mod.PARTIAL_APPLY_PREFIX)
    assert sync_mod.PARTIAL_APPLY_PREFIX == "partial apply: ", "mirrored by the backend and UI"
    assert loop.heartbeat.config_apply is status
    assert loop.heartbeat.daemon_status["status"] == "degraded"
    assert loop.heartbeat.daemon_status["reason"].startswith("config_apply_reverted: ")


def test_a_refusal_still_drains_record_ops_and_stays_reported(tmp_path: Path, monkeypatch) -> None:
    """The good zones' record ops are applied, and a later record-only poll
    (same structural etag — the refused zone is still refused) must not read
    the degraded verdict as stale and flip it back to ok."""
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    driver.refuse = [REFUSAL]

    _poll(loop, monkeypatch, _bundle("e1", structural="s1", ops=["op-1"]))
    assert driver.ops == ["op-1"]
    assert loop.heartbeat.pending_acks[-1]["result"] == "ok"
    assert loop.apply_status.status == STATUS_REVERTED
    assert (tmp_path / ".ready").exists(), "every other zone is served, so the pod is ready"

    _poll(loop, monkeypatch, _bundle("e2", structural="s1", ops=["op-2"]))
    assert driver.ops == ["op-1", "op-2"]
    assert loop.apply_status.status == STATUS_REVERTED

    # Once a structural apply lands with nothing refused, the verdict clears.
    driver.refuse = []
    _poll(loop, monkeypatch, _bundle("e3", structural="s2"))
    assert loop.apply_status.status == STATUS_OK


# ── ops a failed apply skipped are returned, not stranded ───────────────────


def test_ops_skipped_by_a_failed_apply_are_nacked(tmp_path: Path, monkeypatch) -> None:
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    driver.fail = True

    _poll(loop, monkeypatch, _bundle("e1", ops=["op-del"]))

    assert driver.ops == [], "nothing was applied"
    acks = {a["op_id"]: a for a in loop.heartbeat.pending_acks}
    assert acks["op-del"]["result"] == "error", "returned to the retry path, not left in flight"
    assert acks["op-del"]["dispatch"] == 0, "echoes the dispatch so it is charged once"
    assert "not applied" in acks["op-del"]["message"]


def test_ops_in_a_quarantined_bundle_are_nacked(tmp_path: Path, monkeypatch) -> None:
    driver = _Driver(tmp_path)
    loop = _loop(tmp_path, driver, monkeypatch)
    loop._quarantine.record("e1", "boom")

    _poll(loop, monkeypatch, _bundle("e1", ops=["op-1"]))

    assert driver.applied == [] and driver.ops == []
    assert [a["result"] for a in loop.heartbeat.pending_acks] == ["error"]

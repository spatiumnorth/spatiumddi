"""HA peer-IP re-renders go through the revert path and the apply lock (#1247).

The peer-IP watcher used to call ``SyncLoop._apply_bundle`` directly, from its
own thread, with the bundle it last saw:

* a re-render Kea refused was only logged — no revert, no quarantine, no
  ``config_apply`` verdict — and the refused document stayed at
  ``kea_config_path``, so the next container start booted Kea into it;
* nothing serialised it against the sync loop, so it could re-apply an OLDER
  bundle over a newer one while the agent reported the newer etag.

``reapply_current_bundle`` re-applies the bundle that is live, under the
sync loop's apply lock, through ``_apply_with_revert``.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import pytest

from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import ensure_layout, save_config
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import STATUS_OK, ApplyStatus
from spatium_dhcp_agent.kea_ctrl import KeaCtrlError
from spatium_dhcp_agent.peer_resolve import PeerResolveWatcher
from spatium_dhcp_agent.sync import SyncLoop


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


def _bundle(tag: str, subnet: str) -> dict[str, Any]:
    return {
        "etag": tag,
        "scopes": [
            {
                "subnet_cidr": subnet,
                "lease_time": 3600,
                "address_family": "ipv4",
                "pools": [],
                "statics": [],
            }
        ],
    }


@pytest.fixture
def loop(agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch) -> SyncLoop:
    monkeypatch.setattr(sync_mod, "config_test", lambda s, d: {"result": 0})
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: {"result": 0})
    ensure_layout(agent_cfg.state_dir)
    return SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())


def _poll_apply(loop: SyncLoop, tag: str, subnet: str) -> None:
    """What ``_poll_once`` does for a new bundle: cache, apply, advance."""
    bundle = _bundle(tag, subnet)
    save_config(loop.cfg.state_dir, bundle, tag)
    assert loop._apply_with_revert(bundle, tag)
    loop._current_etag = tag


def _live_config(cfg: AgentConfig) -> str:
    return json.dumps(json.loads(cfg.kea_config_path.read_text()))


def test_a_refused_re_render_is_reverted_and_reported_not_just_logged(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
):
    _poll_apply(loop, "A", "192.0.2.0/24")

    def refuse(sock, doc):  # type: ignore[no-untyped-def]
        raise KeaCtrlError("peer URL refused")

    monkeypatch.setattr(sync_mod, "config_test", refuse)
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is False
    # Before #1247 the status stayed OK and nothing was quarantined.
    assert loop.apply_status.status != STATUS_OK
    assert loop._quarantine.etag == "A"


def test_the_live_bundle_is_re_applied_never_the_callers_older_snapshot(
    loop: SyncLoop, agent_cfg: AgentConfig
):
    _poll_apply(loop, "A", "192.0.2.0/24")
    stale = _bundle("A", "192.0.2.0/24")  # what the watcher saw first
    _poll_apply(loop, "B", "198.51.100.0/24")

    watcher = PeerResolveWatcher()
    watcher.set_apply_fn(
        lambda _bundle, reload_kea=True: loop.reapply_current_bundle(
            "ha_peer_ip_changed"
        )
    )
    assert watcher._apply_fn is not None
    watcher._apply_fn(stale, reload_kea=True)

    live = _live_config(agent_cfg)
    assert "198.51.100.0/24" in live
    assert "192.0.2.0/24" not in live
    assert loop.apply_status.etag == "B"


def test_a_quarantined_bundle_is_not_re_rendered(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
):
    _poll_apply(loop, "A", "192.0.2.0/24")
    loop._quarantine.record("A", "refused earlier")
    calls: list[int] = []
    monkeypatch.setattr(loop, "_apply_bundle", lambda *a, **kw: calls.append(1))
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is None
    assert calls == []


def test_nothing_to_re_apply_before_the_first_bundle(loop: SyncLoop):
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is None


def test_the_watcher_and_the_sync_loop_never_apply_at_once(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
):
    _poll_apply(loop, "A", "192.0.2.0/24")
    inside = 0
    peak = 0
    guard = threading.Lock()
    real_apply = loop._apply_bundle

    def slow_apply(*args: Any, **kwargs: Any) -> None:
        nonlocal inside, peak
        with guard:
            inside += 1
            peak = max(peak, inside)
        time.sleep(0.05)
        try:
            real_apply(*args, **kwargs)
        finally:
            with guard:
                inside -= 1

    monkeypatch.setattr(loop, "_apply_bundle", slow_apply)
    bundle_b = _bundle("B", "198.51.100.0/24")
    save_config(loop.cfg.state_dir, bundle_b, "B")
    threads = [
        threading.Thread(target=loop._apply_with_revert, args=(bundle_b, "B")),
        threading.Thread(
            target=loop.reapply_current_bundle, args=("ha_peer_ip_changed",)
        ),
        threading.Thread(
            target=loop.reapply_current_bundle, args=("ha_peer_ip_changed",)
        ),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak == 1

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
from spatium_dhcp_agent.config_apply import STATUS_REVERTED, ApplyStatus
from spatium_dhcp_agent.kea_ctrl import KeaConfigRejected
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
    monkeypatch.setattr(sync_mod, "config_check", lambda daemon, path: None)
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


def test_a_refused_re_render_restores_the_documents_and_reports_it(
    loop: SyncLoop, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
):
    _poll_apply(loop, "A", "192.0.2.0/24")
    before = agent_cfg.kea_config_path.read_text()

    def refuse(daemon, path):  # type: ignore[no-untyped-def]
        raise KeaConfigRejected("peer URL refused")

    monkeypatch.setattr(sync_mod, "config_check", refuse)
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is False
    # Reported — before #1247 the status stayed OK and it was only logged.
    assert loop.apply_status.status == STATUS_REVERTED
    assert "ha_peer_ip_changed" in (loop.apply_status.error or "")
    # The refused render is not what the next container start boots into.
    assert agent_cfg.kea_config_path.read_text() == before
    # And a known-good control-plane bundle is not poisoned: the control
    # plane changed nothing, so there is nothing to quarantine.
    assert loop._quarantine.etag is None


def test_after_a_revert_a_host_change_re_renders_last_known_good(
    loop: SyncLoop, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
):
    """The regression the first cut had: re-rendering ``_current_etag``
    skipped a quarantined B, so a peer that moved while the agent ran on
    last-known-good A was never followed."""
    _poll_apply(loop, "A", "192.0.2.0/24")

    def refuse_b(daemon, path):  # type: ignore[no-untyped-def]
        if "198.51.100.0/24" in path.read_text():
            raise KeaConfigRejected("bad scope")

    monkeypatch.setattr(sync_mod, "config_check", refuse_b)
    bundle_b = _bundle("B", "198.51.100.0/24")
    save_config(loop.cfg.state_dir, bundle_b, "B")
    assert loop._apply_with_revert(bundle_b, "B") is False
    loop._current_etag = "B"
    assert loop._quarantine.etag == "B"

    rendered: list[str] = []
    real_apply = loop._apply_bundle

    def spy(bundle: dict[str, Any], **kw: Any) -> None:
        rendered.append(bundle["etag"])
        real_apply(bundle, **kw)

    monkeypatch.setattr(loop, "_apply_bundle", spy)
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is True
    assert rendered == ["A"]
    # Still reverted: the control plane's bundle B has not converged.
    assert loop.apply_status.status == STATUS_REVERTED
    assert "192.0.2.0/24" in _live_config(agent_cfg)


def test_only_a_daemon_that_accepted_the_render_is_reloaded_back(
    loop: SyncLoop, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
):
    """The daemons reload independently. When dhcp4 took the re-render and
    dhcp6 refused it, dhcp4 must be put back on the restored document, and
    dhcp6 — still on its old one — must not be reloaded, since a Kea reload
    restarts the HA hook's state machine."""
    _poll_apply(loop, "A", "192.0.2.0/24")
    reloads: list[str] = []

    def v6_refuses(daemon, path):  # type: ignore[no-untyped-def]
        if daemon == "dhcp6":
            raise KeaConfigRejected("v6 refused")

    monkeypatch.setattr(sync_mod, "config_check", v6_refuses)
    monkeypatch.setattr(
        sync_mod, "config_reload", lambda sock: reloads.append(str(sock))
    )
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is False
    v4, v6 = str(agent_cfg.kea_control_socket), str(agent_cfg.kea_control_socket_v6)
    # Once for the re-render, once to put dhcp4 back; never dhcp6.
    assert reloads == [v4, v4]
    assert v6 not in reloads


def test_the_v6_recheck_does_not_retry_the_same_refusal_every_loop(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
):
    _poll_apply(loop, "A", "192.0.2.0/24")
    loop._v6_unicast_applied = (("eth0", "2001:db8::1"),)
    addresses = [("eth0", "2001:db8::2")]
    monkeypatch.setattr(sync_mod, "global_ipv6_addresses", lambda: list(addresses))
    calls: list[str] = []
    monkeypatch.setattr(
        loop, "reapply_current_bundle", lambda reason: calls.append(reason) or False
    )
    loop._recheck_v6_unicast()
    loop._recheck_v6_unicast()
    assert len(calls) == 1  # the same refusal is not asked again
    addresses[:] = [("eth0", "2001:db8::3")]
    loop._recheck_v6_unicast()
    assert len(calls) == 2  # a new address set is a new question


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


def test_nothing_to_re_apply_before_the_first_bundle(loop: SyncLoop):
    assert loop.reapply_current_bundle("ha_peer_ip_changed") is None


def test_the_watcher_and_the_sync_loop_never_apply_at_once(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
):
    _poll_apply(loop, "A", "192.0.2.0/24")
    inside = 0
    peak = 0
    entered = 0
    guard = threading.Lock()
    real_apply = loop._apply_bundle

    def slow_apply(*args: Any, **kwargs: Any) -> None:
        nonlocal inside, peak, entered
        with guard:
            inside += 1
            entered += 1
            peak = max(peak, inside)
        time.sleep(0.05)
        try:
            real_apply(*args, **kwargs)
        finally:
            with guard:
                inside -= 1

    monkeypatch.setattr(loop, "_apply_bundle", slow_apply)
    # Both re-applies render the live bundle, so all three reach
    # ``_apply_bundle`` (``entered == 3``) and ``peak == 1`` is only true with
    # the lock.
    bundle_b = _bundle("B", "198.51.100.0/24")
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
    assert entered == 3
    assert peak == 1

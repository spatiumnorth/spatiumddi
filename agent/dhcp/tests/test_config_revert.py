"""Last-known-good revert + poison-pill quarantine for the DHCP agent (#882).

Before this, ``previous.json`` was written on every fetch and read by
nothing, and a config Kea *refused* still counted as a success: the loop
advanced its etag, called ``_record_success()``, logged
``dhcp_config_applied`` and stamped the K8s readiness marker. The refused
document was also left at ``kea_config_path``, so the next container start
booted Kea straight into it.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import (
    commit_config,
    ensure_layout,
    load_previous_config,
    save_config,
)
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import (
    STATUS_NO_PREVIOUS,
    STATUS_OK,
    STATUS_REVERT_FAILED,
    STATUS_REVERTED,
    ApplyStatus,
    Quarantine,
)
from spatium_dhcp_agent.kea_ctrl import KeaCtrlError
from spatium_dhcp_agent.sync import SyncLoop


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


# The control plane parses the daemon ``reason`` a failed apply leaves behind
# (#1067): ``daemon_state.is_config_apply_verdict`` reads
# ``config_apply_reverted:`` and Kea's own ``dhcp4_config_rejected:`` /
# ``dhcp6_…`` as a failed apply — #882's to report — rather than a daemon that
# is not serving. Reword either and a routine rejection pages critical as "not
# serving" on top of #882's own alarm.
_KEA_REJECTED = re.compile(r"dhcp[46]_config_rejected: ")


def _bundle(tag: str, subnet: str = "192.0.2.0/24") -> dict[str, Any]:
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
    """A SyncLoop whose Kea control socket always answers happily."""
    monkeypatch.setattr(sync_mod, "config_test", lambda s, d: {"result": 0})
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: {"result": 0})
    ensure_layout(agent_cfg.state_dir)
    return SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())


def _apply(loop: SyncLoop, tag: str, subnet: str = "192.0.2.0/24") -> bool:
    """Apply a bundle the way ``_poll_once`` does — cache it, then apply."""
    bundle = _bundle(tag, subnet)
    save_config(loop.cfg.state_dir, bundle, tag)
    return loop._apply_with_revert(bundle, tag)


def _reject(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    """Kea refuses every config from here on — including a revert's."""

    def bad(sock, doc):  # type: ignore[no-untyped-def]
        raise KeaCtrlError(message)

    monkeypatch.setattr(sync_mod, "config_test", bad)


def _reject_containing(monkeypatch: pytest.MonkeyPatch, marker: str, message: str) -> None:
    """Kea refuses only documents mentioning ``marker``.

    The realistic shape: one bad scope is rejected while the previous
    config still loads, which is what makes a revert possible at all.
    """

    def selective(sock, doc):  # type: ignore[no-untyped-def]
        if marker in json.dumps(doc):
            raise KeaCtrlError(message)
        return {"result": 0}

    monkeypatch.setattr(sync_mod, "config_test", selective)


def test_rejected_config_reverts_the_files_on_disk(
    loop: SyncLoop, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The crash-loop-on-restart bug.

    Kea's ``config-test`` rejects without disturbing the running server, so
    the daemon is fine either way — but ``_apply_bundle`` has already written
    the refused document to ``kea_config_path``, and THAT is what Kea reads
    on its next start. The revert has to rewrite the files, not just the
    status.
    """
    assert _apply(loop, "good", "10.0.0.0/24") is True
    good_doc = json.loads(agent_cfg.kea_config_path.read_text())

    _reject_containing(
        monkeypatch, "10.9.9.0/24", "config-test failed: pool not in subnet"
    )
    assert _apply(loop, "bad", "10.9.9.0/24") is False

    # Not merely "status says reverted" — the file Kea would boot from is the
    # good one again.
    assert json.loads(agent_cfg.kea_config_path.read_text()) == good_doc
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.failed_etag == "bad"
    assert loop.apply_status.etag == "good"
    assert loop.heartbeat.daemon_status["reason"].startswith("config_apply_reverted: ")


def test_unreachable_socket_does_not_revert(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable control socket says nothing about the config.

    Kea may simply be restarting. Reverting here would throw away a
    perfectly good bundle because of a timing accident, which is why
    ``_reload_socket`` distinguishes REJECTED from UNREACHABLE.
    """
    assert _apply(loop, "good") is True

    def unreachable(sock, doc):  # type: ignore[no-untyped-def]
        raise OSError("no such control socket")

    monkeypatch.setattr(sync_mod, "config_test", unreachable)
    assert _apply(loop, "next") is True

    assert loop.apply_status.status == STATUS_OK
    assert loop._quarantine.etag is None


def test_rejection_quarantines_the_etag(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _apply(loop, "good") is True
    _reject(monkeypatch, "boom")
    _apply(loop, "bad")

    assert loop._quarantine.blocks("bad")
    assert not loop._quarantine.blocks("good")


def test_success_commits_the_last_known_good(loop: SyncLoop, agent_cfg: AgentConfig) -> None:
    save_config(agent_cfg.state_dir, _bundle("one"), "one")
    assert _apply(loop, "one") is True
    bundle, etag = load_previous_config(agent_cfg.state_dir)
    assert etag == "one"
    assert bundle is not None


def test_failure_with_no_previous_is_reported_distinctly(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    _reject(monkeypatch, "boom")
    assert _apply(loop, "bad") is False
    assert loop.apply_status.status == STATUS_NO_PREVIOUS
    assert loop.apply_status.etag is None
    # Nothing to roll back to: Kea's refusal is what the heartbeat carries.
    assert _KEA_REJECTED.match(loop.heartbeat.daemon_status["reason"])


def test_revert_failure_is_reported_distinctly(
    loop: SyncLoop, agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _apply(loop, "good") is True
    # Every config-test from here on fails, including the revert's.
    _reject(monkeypatch, "boom")
    assert _apply(loop, "bad") is False
    assert loop.apply_status.status == STATUS_REVERT_FAILED
    assert "revert also failed" in (loop.apply_status.error or "")
    assert _KEA_REJECTED.match(loop.heartbeat.daemon_status["reason"])


def test_render_failure_is_tagged_as_such(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _apply(loop, "good") is True

    real_render = sync_mod.render_kea

    def boom(bundle, **kw):  # type: ignore[no-untyped-def]
        if any(s.get("subnet_cidr") == "10.9.9.0/24" for s in bundle.get("scopes") or []):
            raise ValueError("unrenderable scope")
        return real_render(bundle, **kw)

    monkeypatch.setattr(sync_mod, "render_kea", boom)
    assert _apply(loop, "bad", "10.9.9.0/24") is False
    assert loop.apply_status.phase == sync_mod.PHASE_RENDER
    assert loop.apply_status.status == STATUS_REVERTED


def test_bootstrap_skips_a_quarantined_bundle(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A restart must not boot Kea into the config it already refused."""
    monkeypatch.setattr(sync_mod, "config_test", lambda s, d: {"result": 0})
    monkeypatch.setattr(sync_mod, "config_reload", lambda s: {"result": 0})
    ensure_layout(agent_cfg.state_dir)

    save_config(agent_cfg.state_dir, _bundle("good", "10.0.0.0/24"), "good")
    commit_config(agent_cfg.state_dir, "good")
    save_config(agent_cfg.state_dir, _bundle("bad", "10.9.9.0/24"), "bad")
    Quarantine(agent_cfg.state_dir).record("bad", "pool not in subnet")

    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())

    live = json.loads(agent_cfg.kea_config_path.read_text())
    assert "10.0.0.0/24" in json.dumps(live)
    assert loop.apply_status.status == STATUS_REVERTED
    assert loop.apply_status.failed_etag == "bad"


def test_quarantine_clears_when_the_server_moves_on(loop: SyncLoop) -> None:
    """The quarantine names one bundle; a different etag makes it moot.

    Without this the agent would keep dropping If-None-Match on every poll
    for a bundle the control plane no longer serves.
    """
    loop._quarantine.record("bad", "boom")
    assert _apply(loop, "fixed") is True
    assert loop._quarantine.etag is None

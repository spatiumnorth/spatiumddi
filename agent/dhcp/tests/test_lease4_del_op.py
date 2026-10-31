"""``lease4_del`` agent op (#1287).

Re-provisioning a leased device to a static address purges the lease's rows
on the control plane. The lease also has to go from Kea itself — otherwise the
agent's next lease snapshot brings it, its IPAM mirror and its DNS records
back. Before this op existed, every pending op was acked "ok" without being
looked at.
"""

from __future__ import annotations

from typing import Any, Self

import pytest

from spatium_dhcp_agent import kea_ctrl
from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import ensure_layout
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import ApplyStatus
from spatium_dhcp_agent.kea_ctrl import KeaCtrlError
from spatium_dhcp_agent.sync import SyncLoop


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()


class _Resp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakeClient:
    def __init__(
        self, status_code: int, posts: list[tuple[str, dict[str, Any]]]
    ) -> None:
        self._status = status_code
        self._posts = posts

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> _Resp:
        self._posts.append((url, json))
        return _Resp(self._status)


def test_lease4_del_sends_the_address(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    sent: list[tuple[str, dict[str, Any] | None, tuple[int, ...]]] = []

    def fake_send(sock, command, arguments=None, *, timeout=10.0, accept_results=(0,)):
        sent.append((command, arguments, accept_results))
        return {"result": 0}

    monkeypatch.setattr(kea_ctrl, "send_command", fake_send)
    assert kea_ctrl.lease4_del(tmp_path / "sock", "192.0.2.150") is True
    assert sent == [("lease4-del", {"ip-address": "192.0.2.150"}, (0, 3))]


def test_lease4_del_already_gone_is_not_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setattr(kea_ctrl, "send_command", lambda *a, **k: {"result": 3})
    assert kea_ctrl.lease4_del(tmp_path / "sock", "192.0.2.150") is False


def test_lease4_del_refuses_v6(tmp_path) -> None:
    with pytest.raises(ValueError):
        kea_ctrl.lease4_del(tmp_path / "sock", "2001:db8::1")


@pytest.fixture
def loop(agent_cfg: AgentConfig) -> SyncLoop:
    ensure_layout(agent_cfg.state_dir)
    return SyncLoop(agent_cfg, token_ref=["tok"], heartbeat=_FakeHeartbeat())


def test_lease_ops_run_and_ack_directly(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    deleted: list[str] = []
    posts: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        sync_mod, "lease4_del", lambda sock, ip: deleted.append(ip) or True
    )
    monkeypatch.setattr(loop, "_client", lambda: _FakeClient(200, posts))

    handled = loop._run_lease_ops(
        [
            {
                "op_id": "a",
                "op_type": "lease4_del",
                "payload": {"ip_address": "192.0.2.150"},
            },
            {"op_id": "b", "op_type": "apply_config", "payload": {"etag": "x"}},
        ]
    )

    assert handled == {"a"}
    assert deleted == ["192.0.2.150"]
    assert posts == [("/api/v1/dhcp/agents/ops/a/ack", {"op_id": "a", "result": "ok"})]
    # Acked directly, so nothing waits for the heartbeat.
    assert loop.heartbeat.pending_acks == []


def test_lease_op_failure_is_reported_not_swallowed(
    loop: SyncLoop, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(sock, ip):
        raise KeaCtrlError("kea command 'lease4-del' failed: result=1 text='no hook'")

    posts: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(sync_mod, "lease4_del", boom)
    # The direct ack fails too: the heartbeat must carry it.
    monkeypatch.setattr(loop, "_client", lambda: _FakeClient(503, posts))

    handled = loop._run_lease_ops(
        [
            {
                "op_id": "c",
                "op_type": "lease4_del",
                "payload": {"ip_address": "192.0.2.151"},
            }
        ]
    )

    assert handled == {"c"}
    assert loop.heartbeat.pending_acks[0]["result"] == "error"
    assert "no hook" in loop.heartbeat.pending_acks[0]["message"]


def test_memfile_deletion_marker_is_not_an_active_lease() -> None:
    """``lease4-del`` makes Kea append the lease again with lifetime 0.

    Row as Kea 3.0.3 wrote it after a ``lease4-del``. Read as "active", it put
    the lease, its IPAM mirror and its DNS records straight back.
    """
    from spatium_dhcp_agent.leases import _parse_row

    granted = "192.0.2.150,02:12:87:00:00:01,01:02:12:87:00:00:01,3600,1791326810,1,0,0,apc,0,,0"
    deleted = (
        "192.0.2.150,02:12:87:00:00:01,01:02:12:87:00:00:01,0,1791323210,1,0,0,apc,0,,0"
    )
    assert _parse_row(granted.split(","))["state"] == "active"
    assert _parse_row(deleted.split(","))["state"] == "expired"


def test_v6_deletion_marker_is_not_an_active_lease() -> None:
    from spatium_dhcp_agent.leases import _parse_row_v6

    # address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,
    # iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,...
    row = [
        "2001:db8::5",
        "00:01:02",
        "0",
        "1791323210",
        "1",
        "0",
        "0",
        "7",
        "128",
        "0",
        "0",
    ]
    row += ["h", "", "0", "", "", "", "0"]
    assert _parse_row_v6(row)["state"] == "expired"

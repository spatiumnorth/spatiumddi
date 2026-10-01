"""#1232 — an op ack appended while a heartbeat is in flight is not lost.

The sync thread applies ops and appends their acks; the heartbeat thread sent
``pending_acks`` and then ``clear()``-ed it on a 200. An ack appended between
the two was dropped: the op stayed ``in_flight`` on the control plane with no
ack ever coming.
"""

from __future__ import annotations

from typing import Any, Self

import httpx

from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.heartbeat import HeartbeatClient


class _Client:
    """Accepts the heartbeat, and — like the sync thread racing it — appends
    an ack to the live list while the request is in flight."""

    def __init__(self, hb: HeartbeatClient, sent: list[dict[str, Any]], status: int) -> None:
        self.hb = hb
        self.sent = sent
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        self.sent.append({"ops_ack": list(json["ops_ack"])})
        self.hb.pending_acks.append({"op_id": "late", "result": "ok"})
        return httpx.Response(self.status, json={}, request=httpx.Request("POST", url))


def test_an_ack_appended_mid_request_survives_to_the_next_heartbeat(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    hb = HeartbeatClient(agent_cfg, ["tok"])
    hb.pending_acks.append({"op_id": "early", "result": "ok"})
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(hb, sent, 200))

    hb.send_once()
    assert [a["op_id"] for a in sent[0]["ops_ack"]] == ["early"]
    assert [a["op_id"] for a in hb.pending_acks] == ["late"]

    hb.send_once()
    assert [a["op_id"] for a in sent[1]["ops_ack"]] == ["late"]


def test_a_failed_heartbeat_keeps_every_ack(agent_cfg: AgentConfig, monkeypatch) -> None:
    hb = HeartbeatClient(agent_cfg, ["tok"])
    hb.pending_acks.append({"op_id": "early", "result": "ok"})
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(hb, sent, 503))

    hb.send_once()
    assert [a["op_id"] for a in hb.pending_acks] == ["early", "late"]


def test_a_heartbeat_sends_at_most_the_control_planes_ack_bound(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    """The control plane 422s a longer list; with nothing ever removed, every
    later heartbeat would be refused too."""
    from spatium_dns_agent.heartbeat import MAX_ACKS_PER_HEARTBEAT

    class _Plain(_Client):
        def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
            self.sent.append({"ops_ack": list(json["ops_ack"])})
            return httpx.Response(200, json={}, request=httpx.Request("POST", url))

    hb = HeartbeatClient(agent_cfg, ["tok"])
    hb.pending_acks.extend(
        {"op_id": str(i), "result": "ok"} for i in range(MAX_ACKS_PER_HEARTBEAT + 7)
    )
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Plain(hb, sent, 200))
    hb.send_once()
    assert len(sent[0]["ops_ack"]) == MAX_ACKS_PER_HEARTBEAT
    assert len(hb.pending_acks) == 7


def test_an_ack_echoes_the_dispatch_stamp() -> None:
    from spatium_dns_agent.sync import _ack

    assert _ack({"op_id": "a", "dispatch": 3}, "error", "boom") == {
        "op_id": "a",
        "result": "error",
        "message": "boom",
        "dispatch": 3,
    }
    # A page from an older control plane carries no stamp.
    assert _ack({"op_id": "a"}, "ok") == {"op_id": "a", "result": "ok"}

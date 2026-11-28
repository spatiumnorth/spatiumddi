"""#4193 — the agent reports its actual memory use on the heartbeat."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Self

import httpx

from spatium_dhcp_agent import heartbeat as hb_mod
from spatium_dhcp_agent import memory_stats
from spatium_dhcp_agent.heartbeat import HeartbeatClient
from spatium_dhcp_agent.config import AgentConfig

KIB = 1024


def _write(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return str(path)


def _proc(root: Path, pid: int, rss_kb: int | None) -> None:
    body = "Name:\tx\nVmPeak:\t999 kB\n"
    if rss_kb is not None:
        body += f"VmRSS:\t{rss_kb} kB\n"
    _write(root / str(pid) / "status", body)


def test_cgroup_v2_files(tmp_path: Path) -> None:
    used = (_write(tmp_path / "memory.current", "734003200\n"),)
    peak = (_write(tmp_path / "memory.peak", "900000000\n"),)
    rep = memory_stats.memory_report(
        [], used_files=used, peak_files=peak, proc_root=str(tmp_path / "proc"), limit_bytes=1 << 30
    )
    assert rep is not None
    assert rep["used_bytes"] == 734003200
    assert rep["peak_bytes"] == 900000000
    assert rep["limit_bytes"] == 1 << 30


def test_cgroup_v1_files_fall_through_when_v2_is_absent(tmp_path: Path) -> None:
    used = (
        str(tmp_path / "missing-v2-current"),
        _write(tmp_path / "v1" / "memory.usage_in_bytes", "123456\n"),
    )
    peak = (
        str(tmp_path / "missing-v2-peak"),
        _write(tmp_path / "v1" / "memory.max_usage_in_bytes", "223456\n"),
    )
    rep = memory_stats.memory_report(
        [], used_files=used, peak_files=peak, proc_root=str(tmp_path), limit_bytes=None
    )
    assert rep is not None
    assert (rep["used_bytes"], rep["peak_bytes"]) == (123456, 223456)
    assert "limit_bytes" not in rep  # no limit: omitted, not 0


def test_a_kernel_without_memory_peak_omits_only_that_field(tmp_path: Path) -> None:
    used = (_write(tmp_path / "memory.current", "5000\n"),)
    rep = memory_stats.memory_report(
        [],
        used_files=used,
        peak_files=(str(tmp_path / "no-peak"),),
        proc_root=str(tmp_path),
        limit_bytes=None,
    )
    assert rep is not None and rep["used_bytes"] == 5000 and "peak_bytes" not in rep


def test_garbage_and_missing_files_omit_the_field(tmp_path: Path) -> None:
    rep = memory_stats.memory_report(
        [],
        used_files=(_write(tmp_path / "c", "not-a-number\n"),),
        peak_files=(str(tmp_path / "gone"),),
        proc_root=str(tmp_path / "noproc"),
        limit_bytes=None,
    )
    assert rep is None  # nothing readable: the block is not sent at all


def test_process_rss_from_proc_status(tmp_path: Path) -> None:
    _proc(tmp_path, 41, 2048)
    _proc(tmp_path, 42, 1024)
    _proc(tmp_path, 43, None)  # a kernel-thread-like status: no VmRSS
    root = str(tmp_path)
    assert memory_stats.process_rss_bytes(41, root) == 2048 * KIB
    assert memory_stats.process_rss_bytes(43, root) is None
    assert memory_stats.process_rss_bytes(999, root) is None
    assert memory_stats.process_rss_bytes(None, root) is None
    # several daemon processes sum; an unreadable one does not poison the sum
    assert memory_stats.daemon_rss_bytes([41, 42, 999, None], root) == 3072 * KIB
    assert memory_stats.daemon_rss_bytes([999, None], root) is None


def test_report_carries_daemon_and_agent_rss(tmp_path: Path) -> None:
    _proc(tmp_path, 41, 4096)
    _proc(tmp_path, os.getpid(), 512)
    rep = memory_stats.memory_report(
        [41],
        used_files=(),
        peak_files=(),
        proc_root=str(tmp_path),
        limit_bytes=None,
    )
    assert rep == {"daemon_rss_bytes": 4096 * KIB, "agent_rss_bytes": 512 * KIB}


class _Client:
    def __init__(self, sent: list[dict[str, Any]], refuse: bool) -> None:
        self.sent = sent
        self.refuse = refuse

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> httpx.Response:
        self.sent.append(dict(json))
        req = httpx.Request("POST", url)
        if self.refuse and "memory" in json:
            # What an older control plane (extra="forbid") answers; note it
            # names memory_limit_bytes-style fields too on the DNS side.
            return httpx.Response(
                422,
                text='{"detail":[{"type":"extra_forbidden","loc":["body","memory"]}]}',
                request=req,
            )
        return httpx.Response(200, json={}, request=req)


BLOCK = {"used_bytes": 10, "peak_bytes": 20, "daemon_rss_bytes": 5, "agent_rss_bytes": 3}


def test_the_block_rides_on_the_heartbeat(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.setattr(hb_mod, "memory_report", lambda pids: dict(BLOCK))
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse=False))
    hb.send_once()
    assert sent[0]["memory"] == BLOCK


def test_nothing_readable_sends_no_block(agent_cfg: AgentConfig, monkeypatch) -> None:
    monkeypatch.setattr(hb_mod, "memory_report", lambda pids: None)
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse=False))
    hb.send_once()
    assert "memory" not in sent[0]


def test_an_older_control_plane_that_refuses_the_block_still_gets_heartbeats(
    agent_cfg: AgentConfig, monkeypatch
) -> None:
    monkeypatch.setattr(hb_mod, "memory_report", lambda pids: dict(BLOCK))
    hb = HeartbeatClient(agent_cfg, ["tok"])
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(hb, "_client", lambda: _Client(sent, refuse=True))
    hb.send_once()
    assert "memory" in sent[0] and "memory" not in sent[1]
    hb.send_once()
    assert "memory" not in sent[2]

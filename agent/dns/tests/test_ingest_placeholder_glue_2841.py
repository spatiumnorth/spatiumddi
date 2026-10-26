"""The ingest does not mirror the renderer's own placeholder glue (#2841).

A dynamic zone that names no name server is rendered with the placeholder
apex NS ``ns1.<zone>`` and glue ``ns1 A 127.0.0.1``. Reading the live zone
back and shipping that glue made the control plane mirror it as an
external record nobody created.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from spatium_dns_agent import ingest as ingest_mod
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.ingest import IngestWorker


def _zone(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": "example.com",
        "type": "primary",
        "dynamic_update_enabled": True,
        "records": records,
    }


def _render(state_dir: Path, zone: dict[str, Any]) -> None:
    drv = Bind9Driver(state_dir=state_dir)
    drv.render(
        {
            "server": {"name": "s1", "driver": "bind9"},
            "options": {},
            "acls": [],
            "views": [],
            "zones": [zone],
            "blocklists": [],
            "tsig_keys": [],
            "pending_ops": [],
        }
    )
    live = state_dir / "rendered"
    if live.exists():
        shutil.rmtree(live)
    shutil.copytree(state_dir / "rendered.new", live)


def _axfr(ns: str, extra: str = "") -> str:
    return (
        "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 1 1 1 1\n"
        f"example.com. 3600 IN NS {ns}\n"
        + extra
        + "ws1.example.com. 300 IN A 192.0.2.50\n"
    )


def _read(cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, text: str) -> list[dict]:
    monkeypatch.setattr(
        ingest_mod.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=text, stderr=""),
    )
    recs = IngestWorker(cfg, ["tok"])._read_live_zone("example.com", None)
    assert recs is not None
    return recs


def test_placeholder_glue_is_not_shipped(
    agent_cfg: AgentConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _render(tmp_path, _zone([]))
    text = _axfr("ns1.example.com.", "ns1.example.com. 3600 IN A 127.0.0.1\n")
    recs = _read(agent_cfg, monkeypatch, text)
    assert [(r["name"], r["record_type"]) for r in recs] == [("ws1", "A")]


def test_real_ns_with_a_real_a_still_ships_the_a(
    agent_cfg: AgentConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    zone = _zone(
        [
            {"name": "@", "type": "NS", "value": "ns1.example.com.", "ttl": 3600},
            {"name": "ns1", "type": "A", "value": "127.0.0.1", "ttl": 600},
        ]
    )
    _render(tmp_path, zone)
    text = _axfr("ns1.example.com.", "ns1.example.com. 600 IN A 127.0.0.1\n")
    recs = _read(agent_cfg, monkeypatch, text)
    assert ("ns1", "A") in {(r["name"], r["record_type"]) for r in recs}

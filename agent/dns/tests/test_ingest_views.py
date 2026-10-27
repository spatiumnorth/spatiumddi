"""The ingest reads each view's copy of a zone on its own and names the view.

Under split-horizon BIND answers a transfer from the first view whose
``match-clients`` take it. A loopback transfer signed with the group key reads
whichever view admits the loopback address, and the control plane cannot tell
which copy it got. Each view therefore has a transfer key that selects exactly
that view (#920); the ingest signs each view's read with it and puts the view
in the report, so the control plane files it under that view's zone.
"""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest

from spatium_dns_agent import ingest as ingest_mod
from spatium_dns_agent.cache import save_config
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.ingest import IngestWorker, PowerDNSIngestWorker

_SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
GROUP_KEY = {"name": "spatium-grp", "algorithm": "hmac-sha256", "secret": _SECRET}


def _vkey(view: str) -> dict[str, Any]:
    return {"name": f"spatium_xfr_{view}", "algorithm": "hmac-sha256", "secret": _SECRET}


def _zone(name: str, view: str | None, dynamic: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "type": "primary",
        "dynamic_update_enabled": dynamic,
        "view_name": view,
    }


def _bundle(views: list[dict[str, Any]], zones: list[dict[str, Any]]) -> dict[str, Any]:
    return {"views": views, "zones": zones, "tsig_keys": [GROUP_KEY]}


def _save(cfg: AgentConfig, bundle: dict[str, Any]) -> None:
    save_config(cfg.state_dir, bundle, "etag-1")


class _Client:
    """Stands in for the control-plane client; records what is posted."""

    def __init__(self, posted: list[dict[str, Any]]) -> None:
        self.posted = posted

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *a: object) -> None:
        return None

    def post(self, _path: str, json: dict[str, Any], headers: dict[str, str]) -> Any:
        self.posted.append(json)
        return SimpleNamespace(status_code=200)


def test_each_view_copy_is_read_with_its_own_view_key(agent_cfg: AgentConfig) -> None:
    _save(
        agent_cfg,
        _bundle(
            [
                {"name": "inside", "transfer_key": _vkey("inside")},
                {"name": "outside", "transfer_key": _vkey("outside")},
            ],
            [_zone("corp.example", "inside"), _zone("corp.example", "outside")],
        ),
    )
    targets = IngestWorker(agent_cfg, ["tok"])._sweep_inputs()
    assert targets == [
        ("corp.example", "inside", _vkey("inside")),
        ("corp.example", "outside", _vkey("outside")),
    ]


def test_a_view_without_a_transfer_key_is_read_once_without_naming_a_view(
    agent_cfg: AgentConfig,
) -> None:
    """A control plane that ships no view keys: the read cannot select a view,
    so it is one read per name, reported without a view (the control plane
    files that only when the name is unambiguous)."""
    _save(
        agent_cfg,
        _bundle(
            [{"name": "inside"}, {"name": "outside"}],
            [_zone("corp.example", "inside"), _zone("corp.example", "outside")],
        ),
    )
    targets = IngestWorker(agent_cfg, ["tok"])._sweep_inputs()
    assert targets == [("corp.example", None, GROUP_KEY)]


def test_an_unrenderable_view_key_is_not_used(agent_cfg: AgentConfig) -> None:
    """The renderer leaves a key it cannot write out of ``match-clients``, so
    named would not know it; the read falls back to an unaddressed one."""
    bad = {**_vkey("inside"), "secret": 'x"; };'}
    _save(
        agent_cfg,
        _bundle([{"name": "inside", "transfer_key": bad}], [_zone("corp.example", "inside")]),
    )
    targets = IngestWorker(agent_cfg, ["tok"])._sweep_inputs()
    assert targets == [("corp.example", None, GROUP_KEY)]


def test_a_flat_bundle_reads_each_name_once_with_the_group_key(
    agent_cfg: AgentConfig,
) -> None:
    _save(
        agent_cfg,
        _bundle(
            [],
            [
                _zone("a.example", None),
                _zone("a.example", None),
                _zone("off.example", None, dynamic=False),
            ],
        ),
    )
    targets = IngestWorker(agent_cfg, ["tok"])._sweep_inputs()
    assert targets == [("a.example", None, GROUP_KEY)]


def test_powerdns_never_names_a_view(agent_cfg: AgentConfig) -> None:
    _save(
        agent_cfg,
        _bundle(
            [{"name": "inside", "transfer_key": _vkey("inside")}],
            [_zone("corp.example", "inside")],
        ),
    )
    targets = PowerDNSIngestWorker(agent_cfg, ["tok"])._sweep_inputs()
    assert targets == [("corp.example", None, GROUP_KEY)]


def test_the_transfer_is_signed_with_the_view_key_and_the_report_names_the_view(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    _save(
        agent_cfg,
        _bundle(
            [
                {"name": "inside", "transfer_key": _vkey("inside")},
                {"name": "outside", "transfer_key": _vkey("outside")},
            ],
            [_zone("corp.example", "inside"), _zone("corp.example", "outside")],
        ),
    )
    signed_with: list[str] = []

    def fake_run(cmd: list[str], **_kw: Any) -> Any:
        keyfile = Path(cmd[cmd.index("-k") + 1])
        signed_with.append(keyfile.read_text().split('"')[1])
        view = signed_with[-1].removeprefix("spatium_xfr_")
        out = (
            "corp.example. 3600 IN SOA ns1.corp.example. a.corp.example. 1 1 1 1 1\n"
            f"only-{view}.corp.example. 300 IN A 192.0.2.1\n"
        )
        return SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(ingest_mod.subprocess, "run", fake_run)

    posted: list[dict[str, Any]] = []

    worker = IngestWorker(agent_cfg, ["tok"])
    monkeypatch.setattr(worker, "_cp_client", lambda: _Client(posted))
    worker._sweep()

    assert signed_with == ["spatium_xfr_inside", "spatium_xfr_outside"]
    sent = [(p["zone_name"], p["view_name"], [r["name"] for r in p["records"]]) for p in posted]
    assert sent == [
        ("corp.example", "inside", ["only-inside"]),
        ("corp.example", "outside", ["only-outside"]),
    ]


def test_an_unaddressed_report_carries_no_view_field(
    agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted: list[dict[str, Any]] = []

    worker = IngestWorker(agent_cfg, ["tok"])
    monkeypatch.setattr(worker, "_cp_client", lambda: _Client(posted))
    worker._ship("a.example.", [])
    assert posted == [{"zone_name": "a.example", "records": []}]

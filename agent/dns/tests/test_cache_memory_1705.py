"""The config cache is written and promoted without whole-file copies (#1705).

``save_config`` built the bundle as one string then encoded it again, and
``commit_config`` read ``current.json`` and wrote it back through memory: with
a catalog-sized blocklist each added ~2x the config to the agent. The ingest
sweep re-parsed the whole file every 180 s with nothing changed.
"""

from __future__ import annotations

import json
import tracemalloc
from pathlib import Path
from typing import Any

from spatium_dns_agent import ingest as ingest_mod
from spatium_dns_agent.cache import commit_config, load_config, save_config
from spatium_dns_agent.config import AgentConfig
from spatium_dns_agent.ingest import IngestWorker


def _big_bundle(n: int = 120_000) -> dict[str, Any]:
    return {
        "tsig_keys": [{"name": "k"}],
        "zones": [],
        "blocklists": [
            {
                "rpz_zone_name": "z.rpz.",
                "entries": [
                    {"domain": f"host{i}.blocked.example.test", "action": "block"}
                    for i in range(n)
                ],
            }
        ],
    }


def _peak(fn: Any) -> int:
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_save_config_does_not_hold_the_serialised_bundle(tmp_path: Path) -> None:
    bundle = _big_bundle()
    peak = _peak(lambda: save_config(tmp_path, bundle, "e1"))
    size = (tmp_path / "config" / "current.json").stat().st_size
    assert size > 5_000_000
    # Before: the whole text plus its encoded bytes (>= 2x the file).
    assert peak < size / 2
    assert load_config(tmp_path) == (bundle, "e1")


def test_commit_config_copies_bytes_without_passing_them_through_memory(
    tmp_path: Path,
) -> None:
    save_config(tmp_path, _big_bundle(), "e1")
    cfg = tmp_path / "config"
    size = (cfg / "current.json").stat().st_size
    peak = _peak(lambda: commit_config(tmp_path, "e1"))
    assert peak < size / 4
    assert (cfg / "previous.json").read_bytes() == (cfg / "current.json").read_bytes()
    assert (cfg / "previous.etag").read_text().strip() == "e1"


def test_ingest_sweep_does_not_reparse_an_unchanged_cache(
    agent_cfg: AgentConfig, monkeypatch: Any
) -> None:
    tmp_path = agent_cfg.state_dir
    bundle = {
        "tsig_keys": [{"name": "k"}],
        "zones": [
            {"name": "a.example.", "type": "primary", "dynamic_update_enabled": True},
            {"name": "a.example.", "type": "primary", "dynamic_update_enabled": True},
            {"name": "off.example.", "type": "primary"},
        ],
    }
    save_config(tmp_path, bundle, "e1")
    loads: list[int] = []
    real = ingest_mod.load_config
    monkeypatch.setattr(
        ingest_mod, "load_config", lambda sd, **kw: (loads.append(1), real(sd, **kw))[1]
    )
    w = IngestWorker(agent_cfg, ["tok"])
    read: list[str] = []
    monkeypatch.setattr(w, "_read_live_zone", lambda z, k: read.append(z) or None)

    w._sweep()
    w._sweep()
    assert loads == [1]
    assert read == ["a.example", "a.example"]

    # A new bundle (new etag) is picked up.
    bundle["zones"].append(
        {"name": "b.example.", "type": "primary", "dynamic_update_enabled": True}
    )
    save_config(tmp_path, bundle, "e2")
    read.clear()
    w._sweep()
    assert loads == [1, 1]
    assert read == ["a.example", "b.example"]
    assert json.loads((tmp_path / "config" / "current.json").read_text())["zones"]


def test_a_dump_that_fails_midway_leaves_the_cache_as_it_was(tmp_path: Path) -> None:
    """Streaming writes the temp file as it goes, so a failure partway must not
    reach ``current.json`` (non-negotiable #5: the agent serves from it), nor
    leave a half-written temp file behind."""
    save_config(tmp_path, {"zones": [], "n": 1}, "e1")
    cfg = tmp_path / "config"
    before = (cfg / "current.json").read_bytes()

    # ``sort_keys`` puts "z" last, so the dump has written the rest first.
    bad = {"a": ["x" * 10_000], "z": object()}
    try:
        save_config(tmp_path, bad, "e2")
    except TypeError:
        pass
    else:  # pragma: no cover - the object is not serialisable
        raise AssertionError("save_config accepted an unserialisable bundle")

    assert (cfg / "current.json").read_bytes() == before
    assert (cfg / "current.etag").read_text() == "e1"
    assert not (cfg / "current.json.tmp").exists()
    assert load_config(tmp_path) == ({"zones": [], "n": 1}, "e1")

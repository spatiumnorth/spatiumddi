"""#2309: key files of zones no longer signed are removed after a good apply."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9 as b9
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.sync import SyncLoop


def _keys(d: Path, zone: str, tag: int = 1) -> None:
    for ext in ("key", "private", "state"):
        (d / f"K{zone.rstrip('.')}.+013+{tag:05d}.{ext}").write_text("x")


def _driver(monkeypatch: pytest.MonkeyPatch, d: Path) -> Bind9Driver:
    monkeypatch.setattr(b9, "DNSSEC_KEY_DIR", str(d))
    return Bind9Driver.__new__(Bind9Driver)


def _z(name: str, signed: bool = True, **kw: Any) -> dict[str, Any]:
    return {"name": name, "dnssec_enabled": signed, "type": "primary", **kw}


def test_removed_and_unsigned_zones_lose_keys(tmp_path, monkeypatch):
    _keys(tmp_path, "gone.test.")
    _keys(tmp_path, "unsigned.test.")
    _keys(tmp_path, "kept.test.")
    drv = _driver(monkeypatch, tmp_path)
    removed = drv.prune_dnssec_keys({"zones": [_z("kept.test."), _z("unsigned.test.", False)]})
    assert len(removed) == 6
    left = {p.name for p in tmp_path.iterdir()}
    assert left == {f"Kkept.test.+013+00001.{e}" for e in ("key", "private", "state")}


def test_name_prefix_collision_is_safe(tmp_path, monkeypatch):
    _keys(tmp_path, "sub.example.com.")
    _keys(tmp_path, "example.com.")
    drv = _driver(monkeypatch, tmp_path)
    drv.prune_dnssec_keys({"zones": [_z("sub.example.com")]})
    assert len(list(tmp_path.iterdir())) == 3
    assert all(p.name.startswith("Ksub.example.com.") for p in tmp_path.iterdir())
    _keys(tmp_path, "example.com.")
    drv.prune_dnssec_keys({"zones": [_z("Example.COM.")]})
    assert len(list(tmp_path.iterdir())) == 3
    assert not any(p.name.startswith("Ksub.") for p in tmp_path.iterdir())


def test_zone_signed_in_either_view_keeps_keys(tmp_path, monkeypatch):
    _keys(tmp_path, "split.test.")
    drv = _driver(monkeypatch, tmp_path)
    drv.prune_dnssec_keys(
        {"zones": [_z("split.test.", True, view="a"), _z("split.test.", False, view="b")]}
    )
    assert len(list(tmp_path.iterdir())) == 3


def test_recreated_zone_starts_clean(tmp_path, monkeypatch):
    _keys(tmp_path, "back.test.", tag=7)
    drv = _driver(monkeypatch, tmp_path)
    drv.prune_dnssec_keys({"zones": []})
    assert list(tmp_path.iterdir()) == []


def test_sync_prunes_only_after_successful_apply():
    calls: list[Any] = []

    class _Drv:
        def prune_dnssec_keys(self, bundle):
            calls.append(bundle)

    loop = SyncLoop.__new__(SyncLoop)
    loop.driver = _Drv()
    loop._prune_dnssec_keys({"zones": []})
    assert calls == [{"zones": []}]
    # every failure path returns before the prune
    src = inspect.getsource(SyncLoop._apply_with_revert)
    assert src.rindex("return False") < src.index("_prune_dnssec_keys")

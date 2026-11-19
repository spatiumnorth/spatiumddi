"""#2648 — TSIG key files are staged with the render, never written live early.

A bundle ``named-checkconf`` rejects used to leave ``tsig/ddns.key`` rewritten
(wrong signing key for record ops) and ``view-transfer.key`` unlinked (a
missing include on the next named start) while the running config was
untouched.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver

from .test_views_render import _keyed_bundle, _split_horizon_bundle


def _swap(drv: Bind9Driver) -> None:
    cur = drv.state_dir / "rendered"
    drv._swap_in(drv.state_dir / "rendered.new", cur, drv.state_dir / "rendered.prev")


def _rekeyed(secret: str, views: bool = True) -> dict[str, Any]:
    b = _keyed_bundle() if views else _split_horizon_bundle()
    b["tsig_keys"] = [
        {"name": "spatium-grp", "secret": secret, "algorithm": "hmac-sha256"}
    ]
    if not views:
        b["views"] = []
        b["zones"] = [z for z in b["zones"] if not z.get("view_name")][:0]
    return b


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _fail_checkconf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 1, stdout="named.conf:1: bad", stderr=""
        ),
    )


def test_rrender_touches_nothing_outside_rendered_new(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_keyed_bundle())
    assert not (tmp_path / "tsig" / "ddns.key").exists()
    assert not (tmp_path / "tsig" / "view-transfer.key").exists()
    assert (tmp_path / "rendered.new" / "tsig" / "ddns.key").exists()
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert f'include "{tmp_path / "rendered" / "tsig" / "ddns.key"}";' in conf


def test_rejected_bundle_leaves_live_key_files_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_keyed_bundle())
    _swap(drv)
    before = _snapshot(tmp_path / "rendered")
    assert "tsig/view-transfer.key" in before

    # Rotate the group key AND drop the views, in a bundle validation refuses.
    drv.render(_rekeyed("bmV3c2VjcmV0", views=False))
    _fail_checkconf(monkeypatch)
    with pytest.raises(RuntimeError):
        drv.validate()

    assert _snapshot(tmp_path / "rendered") == before
    assert not (tmp_path / "tsig").exists() or not any((tmp_path / "tsig").iterdir())


def test_record_ops_sign_with_the_live_key_until_the_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_keyed_bundle())
    _swap(drv)
    drv.render(_rekeyed("bmV3c2VjcmV0"))
    # staged, not live
    live = (tmp_path / "rendered" / "tsig" / "ddns.key").read_text()
    assert "Z3JvdXBrZXk=" in live and "bmV3c2VjcmV0" not in live
    _swap(drv)
    assert "bmV3c2VjcmV0" in (tmp_path / "rendered" / "tsig" / "ddns.key").read_text()
    # revert path: previous tree back, keys consistent with its named.conf
    shutil_rev = tmp_path / "rendered.prev"
    assert "Z3JvdXBrZXk=" in (shutil_rev / "tsig" / "ddns.key").read_text()


def test_validate_checks_staged_keys_not_live_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(_keyed_bundle())
    seen: dict[str, str] = {}

    def fake_run(argv: list[str], **k: Any) -> subprocess.CompletedProcess[str]:
        seen["text"] = Path(argv[1]).read_text()
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(drv, "_check_zone_files", lambda d: None)
    drv.validate()
    assert str(tmp_path / "rendered.new" / "tsig" / "ddns.key") in seen["text"]
    assert not (tmp_path / "rendered.new" / "named.check.conf").exists()

"""A kept single-node etcd whose address changed is reset, never an HA one (#4591).

``spatium-etcd-peer-reset`` (k3s.service ExecStartPre) reads k3s's own refusal
from the journal and runs ``k3s server --cluster-reset`` once when the member
list holds exactly this node. Run against stub k3s / journalctl binaries.

    python3 -m pytest appliance/tests/test_etcd_peer_reset.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

EXTRA = Path(__file__).resolve().parents[1] / "mkosi.extra"
SCRIPT = EXTRA / "usr" / "local" / "bin" / "spatium-etcd-peer-reset"

REFUSAL = (
    "Failed to test etcd connection: this server is not a member of the etcd cluster. "
    "Found [{found}], expect: n1-abc=https://10.0.0.9:2380"
)


def _run(tmp_path: Path, found: str | None, *, join: bool = False, config: bool = True):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    (tmp_path / "journal").write_text(REFUSAL.format(found=found) + "\n" if found else "")
    jc = bindir / "journalctl"
    jc.write_text(f'#!/bin/sh\ncat "{tmp_path}/journal"\n')
    k3s = bindir / "k3s"
    k3s.write_text(f'#!/bin/sh\necho "$@" >>"{tmp_path}/k3s.calls"\n')
    for f in (jc, k3s):
        f.chmod(0o755)
    cfg = tmp_path / "etcd-config"
    if config:
        cfg.write_text("name: n1-abc\n")
    dropin = tmp_path / "spatium-cluster.yaml"
    if join:
        dropin.write_text("server: https://10.0.0.1:6443\n")
    env = {
        **os.environ,
        "SPATIUM_K3S_BIN": str(k3s),
        "SPATIUM_JOURNALCTL": str(jc),
        "SPATIUM_K3S_JOIN_DROPIN": str(dropin),
        "SPATIUM_ETCD_CONFIG_FILE": str(cfg),
        "SPATIUM_ETCD_PEER_RESET_STAMP": str(tmp_path / "stamp"),
        "SPATIUM_ETCD_PEER_RESET_LOG": str(tmp_path / "log"),
        "SPATIUM_CONSOLE": str(tmp_path / "console"),
    }
    proc = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    calls = tmp_path / "k3s.calls"
    return proc, (calls.read_text().split() if calls.exists() else [])


def test_single_member_at_old_address_is_reset(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380")
    assert calls == ["server", "--cluster-reset"]
    assert (tmp_path / "stamp").read_text().strip().isdigit()
    assert "cluster-reset" in (tmp_path / "console").read_text()


def test_stamped_reset_is_not_repeated_for_old_lines(tmp_path: Path) -> None:
    # journalctl is stubbed to ignore --since, so prove the stamp is passed.
    _run(tmp_path, "n1-abc=https://10.0.0.5:2380")
    assert (tmp_path / "stamp").exists()
    text = SCRIPT.read_text()
    assert '--since "@$since"' in text


def test_multi_member_is_left_alone(tmp_path: Path) -> None:
    proc, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380 n2-def=https://10.0.0.6:2380")
    assert calls == []
    assert "NOT resetting" in proc.stderr
    assert not (tmp_path / "stamp").exists()


def test_no_refusal_does_nothing(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, None)
    assert calls == []


def test_joined_member_is_left_alone(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380", join=True)
    assert calls == []


def test_other_nodes_member_is_left_alone(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "zzz=https://10.0.0.5:2380")
    assert calls == []


def test_no_kept_datastore_does_nothing(tmp_path: Path) -> None:
    _, calls = _run(tmp_path, "n1-abc=https://10.0.0.5:2380", config=False)
    assert calls == []


def test_unit_runs_it_before_k3s() -> None:
    unit = (EXTRA / "etc" / "systemd" / "system" / "k3s.service").read_text()
    assert "ExecStartPre=-/usr/local/bin/spatium-etcd-peer-reset" in unit

"""#1934: the control plane's DNSSEC keys follow the keys BIND serves.

BIND changes a zone's keys without a structural reload (a pod replacement
that re-keys the zone, a dnssec-policy rollover). The agent must report the
new keys, and soon: not after a quiet-zone interval, and never by wiping the
control plane's rows because named was not answering yet.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers import bind9 as b9
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.sync import DNSSEC_REFRESH_SECONDS, SyncLoop
from tests.test_ds_from_keyfile import _Cfg, _Heartbeat

BUNDLE = {"zones": [{"name": "probe.test.", "dnssec_enabled": True, "type": "primary"}]}


def _status(tag: int) -> str:
    return (
        "dnssec-policy: default\ncurrent time: Thu Oct 15 13:36:00 2026\n\n"
        f"key: {tag} (ECDSAP256SHA256), CSK\n"
        "  published:      yes - since Thu Oct 15 13:35:45 2026\n"
        "  key signing:    yes - since Thu Oct 15 13:35:45 2026\n"
        "  zone signing:   yes - since Thu Oct 15 13:35:45 2026\n"
    )


def _keyfile(d: Path, tag: int, fill: int) -> None:
    pub = base64.b64encode(bytes([fill]) * 64).decode()
    base = f"Kprobe.test.+013+{tag:05d}"
    (d / f"{base}.key").write_text(f"probe.test. 3600 IN DNSKEY 257 3 13 {pub}\n")
    (d / f"{base}.state").write_text("DSState: omnipresent\n")


class _Bind:
    """Stands in for named: what ``rndc dnssec -status`` answers."""

    def __init__(self) -> None:
        self.rc = 0
        self.tag = 6244

    def run(self, *a: Any, **kw: Any) -> Any:
        outer = self

        class R:
            returncode = outer.rc
            stdout = _status(outer.tag) if outer.rc == 0 else ""
            stderr = "rndc: 'dnssec' failed: not found"

        return R()


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    keys = tmp_path / "keys"
    keys.mkdir()
    bind = _Bind()
    monkeypatch.setattr(b9, "DNSSEC_KEY_DIR", str(keys), raising=False)
    # main hardcodes the directory inside the method; point the DS reader at
    # the test directory either way.
    real = b9._ds_from_key_dir
    monkeypatch.setattr(b9, "_ds_from_key_dir", lambda zone, kd: real(zone, str(keys)))
    monkeypatch.setattr(b9.shutil, "which", lambda n: "/usr/sbin/rndc")
    monkeypatch.setattr(b9.subprocess, "run", bind.run)
    drv = Bind9Driver.__new__(Bind9Driver)
    monkeypatch.setattr(drv, "_rndc_base", lambda: ["rndc"], raising=False)
    loop = SyncLoop(_Cfg(tmp_path), ["tok"], drv, _Heartbeat())  # type: ignore[arg-type]
    posted: list[list[dict[str, Any]]] = []
    loop._report_dnssec_state = lambda s: posted.append(s) or True  # type: ignore[method-assign]
    loop._dnssec_bundle = BUNDLE
    return loop, bind, keys, posted


def _due_in(loop: SyncLoop) -> float:
    return loop._dnssec_refresh_at - time.monotonic()


def test_new_keys_after_rekey_are_reported_without_a_structural_reload(rig) -> None:
    loop, bind, keys, posted = rig
    _keyfile(keys, 6244, 1)
    loop._refresh_dnssec_state(force=True)
    assert posted[-1][0]["keys"][0]["key_tag"] == 6244

    # BIND re-keys the zone (pod replaced, #1855): same bundle, new key.
    for f in keys.iterdir():
        f.unlink()
    _keyfile(keys, 26803, 2)
    bind.tag = 26803
    loop._refresh_dnssec_state()
    entry = posted[-1][0]
    assert [k["key_tag"] for k in entry["keys"]] == [26803]
    assert len(entry["ds_records"]) == 1


def test_named_not_answering_is_not_reported_as_no_keys(rig) -> None:
    loop, bind, _keys, posted = rig
    bind.rc = 1
    loop._refresh_dnssec_state()
    # Wiping the control plane's key rows on a guess is wrong...
    assert posted == []
    # ...and so is waiting a quiet-zone interval to ask again.
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4


def test_recheck_soon_after_a_report_so_a_settling_key_set_is_caught(rig) -> None:
    loop, _bind, keys, _posted = rig
    _keyfile(keys, 6244, 1)
    loop._refresh_dnssec_state(force=True)
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4


def test_quiet_zone_backs_off_to_the_slow_interval(rig) -> None:
    loop, _bind, keys, posted = rig
    _keyfile(keys, 6244, 1)
    loop._refresh_dnssec_state(force=True)
    loop._refresh_dnssec_state()  # unchanged
    assert len(posted) == 1
    assert _due_in(loop) > DNSSEC_REFRESH_SECONDS / 2


def test_refused_report_is_retried_soon(rig) -> None:
    loop, _bind, keys, _posted = rig
    loop._report_dnssec_state = lambda s: False  # type: ignore[method-assign]
    _keyfile(keys, 6244, 1)
    loop._refresh_dnssec_state()
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4


def test_zone_not_keyed_yet_is_retried_soon(rig, monkeypatch: pytest.MonkeyPatch) -> None:
    loop, _bind, _keys, posted = rig
    # rndc answers (exit 0) but BIND has not generated the zone's key yet.
    monkeypatch.setattr(
        b9.subprocess,
        "run",
        lambda *a, **kw: type(
            "R", (), {"returncode": 0, "stdout": "dnssec-policy: default\n", "stderr": ""}
        )(),
    )
    loop._refresh_dnssec_state(force=True)
    assert posted[-1][0]["keys"] == []  # what BIND serves right now: no key
    loop._refresh_dnssec_state()  # unchanged, but incomplete: still settling
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4


def test_unreadable_zone_backs_off_instead_of_polling_every_20s(rig) -> None:
    # A zone named cannot answer for until the next structural apply (held
    # back by the zone check): one rndc per signed zone every 20 s for as
    # long as that lasts is too much on an estate with many signed zones.
    loop, bind, keys, posted = rig
    bind.rc = 1
    delays = []
    for _ in range(8):
        loop._refresh_dnssec_state()
        delays.append(round(_due_in(loop)))
    assert delays[0] < DNSSEC_REFRESH_SECONDS / 4
    assert delays == sorted(delays)
    assert delays[-1] > DNSSEC_REFRESH_SECONDS - 5
    # Once it answers and the read settles, the next change is caught soon.
    bind.rc = 0
    _keyfile(keys, 6244, 1)
    loop._refresh_dnssec_state()
    assert [k["key_tag"] for k in posted[-1][0]["keys"]] == [6244]
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4  # a report starts afresh
    loop._refresh_dnssec_state()  # unchanged, complete: settled
    assert _due_in(loop) > DNSSEC_REFRESH_SECONDS - 5
    bind.tag = 26803
    for f in keys.iterdir():
        f.unlink()
    _keyfile(keys, 26803, 2)
    loop._refresh_dnssec_state()
    assert [k["key_tag"] for k in posted[-1][0]["keys"]] == [26803]
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4


def test_pod_restart_on_a_cached_bundle_reports_the_new_key(
    rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The live #1934 sequence: the pod is replaced, the agent boots from its
    cached bundle (same structural etag, so no structural reload and no forced
    report), and BIND has re-keyed the zone. The first loop turn must report
    the new key. Before #1886 nothing on this path read the keys at all."""
    from spatium_dns_agent import sync as sync_mod
    from spatium_dns_agent.cache import save_config

    _, bind, keys, _ = rig
    drv = Bind9Driver.__new__(Bind9Driver)
    monkeypatch.setattr(drv, "_rndc_base", lambda: ["rndc"], raising=False)
    drv.held_back = []  # type: ignore[misc]
    monkeypatch.setattr(drv, "apply_config", lambda bundle: None, raising=False)
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **kw: None)
    state = tmp_path / "state"
    state.mkdir()
    save_config(state, {**BUNDLE, "structural_etag": "s1"}, "e1")

    bind.tag = 26803
    _keyfile(keys, 26803, 2)
    loop = SyncLoop(_Cfg(state), ["tok"], drv, _Heartbeat())  # type: ignore[arg-type]
    posted: list[list[dict[str, Any]]] = []
    loop._report_dnssec_state = lambda s: posted.append(s) or True  # type: ignore[method-assign]
    loop._poll_once = loop.stop  # type: ignore[method-assign]  # one turn, no new bundle
    loop.run()
    assert [k["key_tag"] for k in posted[-1][0]["keys"]] == [26803]
    assert len(posted[-1][0]["ds_records"]) == 1



def test_manual_rollover_op_is_followed_by_a_prompt_reread(
    rig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``rndc dnssec -rollover`` returns before BIND generates the successor
    key, so the state the op reports is the pre-rollover set. With no config
    change behind it, the next periodic read must come soon, not after the
    quiet-zone interval."""
    from spatium_dns_agent import sync as sync_mod
    from spatium_dns_agent.cache import ensure_layout
    from tests.test_sync_partial_apply import _Client

    loop, bind, keys, posted = rig
    ensure_layout(tmp_path)
    monkeypatch.setattr(sync_mod, "push_rendered_config", lambda *a, **kw: None)
    _keyfile(keys, 6244, 1)
    loop._refresh_dnssec_state(force=True)
    loop._refresh_dnssec_state()  # settled: slow cadence
    assert _due_in(loop) > DNSSEC_REFRESH_SECONDS - 5

    drv = loop.driver
    monkeypatch.setattr(
        drv,
        "apply_record_op",
        lambda op: {"dnssec_state": drv._zone_dnssec_state("probe.test")},
        raising=False,
    )
    monkeypatch.setattr(loop, "_report_reached_serials", lambda *a, **kw: None)
    loop._current_structural_etag = "s1"
    bundle = {
        **BUNDLE,
        "etag": "e2",
        "structural_etag": "s1",  # no structural change: ops only
        "pending_record_ops": [
            {"op_id": "1", "op": "dnssec_rollover", "zone_name": "probe.test.", "record": {}}
        ],
    }
    monkeypatch.setattr(loop, "_client", lambda: _Client(bundle))
    loop._poll_once()
    assert _due_in(loop) < DNSSEC_REFRESH_SECONDS / 4

    # BIND then generates the successor; the prompt read reports it.
    bind.tag = 31000
    _keyfile(keys, 31000, 3)
    loop._refresh_dnssec_state()
    assert 31000 in [k["key_tag"] for k in posted[-1][0]["keys"]]

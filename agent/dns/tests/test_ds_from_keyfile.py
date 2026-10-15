"""DS computed in-process from a KSK .key file (#1854): no dnssec-dsfromkey.

Only keys BIND itself would put in its CDS get a DS: ``DSState`` rumoured or
omnipresent in the key's ``.state`` file (``syncpublish`` in BIND's
lib/dns/dnssec.c).
"""

from __future__ import annotations

import base64
import hashlib
import struct
from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _ds_from_key_dir
from spatium_dns_agent.sync import SyncLoop

PUB = base64.b64encode(bytes(range(64))).decode()


def _write(
    d: Path, zone: str, flags: int, tag: int = 12345, ds_state: str | None = None, pub: str = PUB
) -> None:
    base = f"K{zone}.+013+{tag:05d}"
    (d / f"{base}.key").write_text(
        f"; This is a key-signing key\n{zone}. 3600 IN DNSKEY {flags} 3 13 {pub}\n"
    )
    if ds_state is not None:
        (d / f"{base}.state").write_text(
            f"; This is the state of key {tag}, for {zone}.\n"
            "Algorithm: 13\nKSK: yes\nZSK: yes\n"
            f"DNSKEYState: omnipresent\nKRRSIGState: omnipresent\nDSState: {ds_state}\n"
            "GoalState: omnipresent\n"
        )


def _digest(pub: str = PUB) -> str:
    wire_name = b"\x07example\x04test\x00"
    rdata = struct.pack("!HBB", 257, 3, 13) + base64.b64decode(pub)
    return hashlib.sha256(wire_name + rdata).hexdigest().upper()


def test_ds_for_ksk_matches_rfc4034_digest(tmp_path: Path) -> None:
    _write(tmp_path, "example.test", 257)
    _write(tmp_path, "example.test", 256, tag=999)  # ZSK ignored
    out = _ds_from_key_dir("example.test", str(tmp_path))
    assert len(out) == 1
    owner, cls, typ, tag, alg, dt, digest = out[0].split()
    assert (owner, cls, typ, alg, dt) == ("example.test.", "IN", "DS", "13", "2")
    assert digest == _digest()
    assert int(tag) > 0


def test_ds_follows_bind_ds_state(tmp_path: Path) -> None:
    """A KSK BIND has not made submittable, or is withdrawing, gets no DS."""
    pubs = {
        s: base64.b64encode(bytes([i + 1]) * 64).decode()
        for i, s in enumerate(["hidden", "rumoured", "omnipresent", "unretentive"])
    }
    for i, (state, pub) in enumerate(pubs.items()):
        _write(tmp_path, "example.test", 257, tag=100 + i, ds_state=state, pub=pub)
    out = _ds_from_key_dir("example.test", str(tmp_path))
    digests = {line.split()[-1] for line in out}
    assert digests == {_digest(pubs["rumoured"]), _digest(pubs["omnipresent"])}


def test_only_unsubmittable_ksk_logs_pending(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "example.test", 257, ds_state="hidden")
    assert _ds_from_key_dir("example.test", str(tmp_path)) == []
    cap = capsys.readouterr()
    assert "dnssec_ds_pending" in cap.out + cap.err
    assert "dnssec_ds_unavailable" not in cap.out + cap.err


def test_missing_ksk_is_logged_not_silent(tmp_path: Path, capsys) -> None:
    _write(tmp_path, "example.test", 256)
    assert _ds_from_key_dir("example.test", str(tmp_path)) == []
    cap = capsys.readouterr()
    assert "dnssec_ds_unavailable" in cap.out + cap.err


def test_missing_dir_is_logged(tmp_path: Path, capsys) -> None:
    assert _ds_from_key_dir("example.test", str(tmp_path / "nope")) == []
    cap = capsys.readouterr()
    assert "key_dir_missing" in cap.out + cap.err


def test_each_key_gets_its_own_ds(monkeypatch) -> None:
    """A per-key DS is the DS of THAT key, not every KSK's DS."""
    ds_a = "example.test. IN DS 100 13 2 AA"
    ds_b = "example.test. IN DS 200 13 2 BB"
    keys = [
        {"key_tag": 100, "key_type": "csk"},
        {"key_tag": 200, "key_type": "ksk"},
        {"key_tag": 300, "key_type": "ksk"},
        {"key_tag": 400, "key_type": "zsk"},
    ]

    class _Res:
        returncode = 0
        stdout = ""

    monkeypatch.setattr("spatium_dns_agent.drivers.bind9._ds_from_key_dir", lambda zone, key_dir: [ds_a, ds_b])
    monkeypatch.setattr("spatium_dns_agent.drivers.bind9.shutil.which", lambda name: "/usr/sbin/rndc")
    monkeypatch.setattr("spatium_dns_agent.drivers.bind9._parse_dnssec_status", lambda text: [dict(k) for k in keys])
    monkeypatch.setattr("spatium_dns_agent.drivers.bind9.subprocess.run", lambda *a, **kw: _Res())
    d = Bind9Driver.__new__(Bind9Driver)
    monkeypatch.setattr(d, "_rndc_base", lambda: ["rndc"], raising=False)

    state = d._zone_dnssec_state("example.test")
    assert state["ds_records"] == [ds_a, ds_b]
    by_tag = {k["key_tag"]: k for k in state["keys"]}
    assert by_tag[100]["ds_records"] == [ds_a]
    assert by_tag[200]["ds_records"] == [ds_b]
    assert by_tag[300]["ds_records"] == []
    assert "ds_records" not in by_tag[400]


# ── periodic refresh in the sync loop ─────────────────────────────────────


class _Heartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.failed_ops_count = 0
        self.config_apply = None


class _Cfg:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.control_plane_url = "http://cp.invalid"
        self.insecure_skip_tls_verify = False
        self.tls_ca_path = None


class _Driver:
    def __init__(self) -> None:
        self.states: list[dict[str, Any]] = []
        self.calls = 0

    def collect_dnssec_state(self, bundle: dict[str, Any]) -> list[dict[str, Any]]:
        self.calls += 1
        return [dict(s) for s in self.states]


def _loop(tmp_path: Path, driver: _Driver, posted: list[Any], results: list[bool]) -> SyncLoop:
    loop = SyncLoop(_Cfg(tmp_path), ["tok"], driver, _Heartbeat())  # type: ignore[arg-type]
    it = iter(results)

    def _post(states: list[dict[str, Any]]) -> bool:
        posted.append(states)
        return next(it, True)

    loop._report_dnssec_state = _post  # type: ignore[method-assign]
    return loop


def test_refresh_posts_a_ds_that_becomes_submittable_later(tmp_path: Path) -> None:
    """BIND makes a KSK's DS submittable hours after signing, with no config
    change in between; the refresh must report it, and only when it moved."""
    driver = _Driver()
    posted: list[Any] = []
    loop = _loop(tmp_path, driver, posted, [])

    loop._refresh_dnssec_state()  # no bundle applied yet → nothing to collect
    assert driver.calls == 0

    loop._dnssec_bundle = {"zones": [{"name": "example.test.", "dnssec_enabled": True}]}
    driver.states = [{"zone_name": "example.test.", "ds_records": [], "keys": []}]
    loop._refresh_dnssec_state(force=True)  # after a structural reload
    assert len(posted) == 1

    loop._refresh_dnssec_state()  # unchanged → no POST
    assert len(posted) == 1

    ds = "example.test. IN DS 1 13 2 AA"
    driver.states = [{"zone_name": "example.test.", "ds_records": [ds], "keys": []}]
    loop._refresh_dnssec_state()
    assert len(posted) == 2
    assert posted[-1][0]["ds_records"] == [ds]


def test_failed_post_is_retried_on_next_refresh(tmp_path: Path) -> None:
    driver = _Driver()
    posted: list[Any] = []
    loop = _loop(tmp_path, driver, posted, [False, True])
    loop._dnssec_bundle = {"zones": []}
    driver.states = [{"zone_name": "example.test.", "ds_records": ["x"], "keys": []}]
    loop._refresh_dnssec_state()
    loop._refresh_dnssec_state()
    loop._refresh_dnssec_state()
    assert len(posted) == 2
